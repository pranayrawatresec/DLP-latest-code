//! M4 decrypt-path tests (encrypt-on-write spec §5.3 + §9/M4 acceptance).
//!
//! Library-path coverage — no server, no hardware, no real state dir needed
//! except for the keyring-at-rest round-trip:
//! * seal → decrypt round trip with the audit incident recorded BEFORE the
//!   plaintext write (order machine-verified via an injected sink + writer);
//! * "machine B" opens with a fresh ring parsed from the SAME dev keyfile
//!   bytes (the M4 acceptance shape);
//! * unknown key ⇒ typed `UnknownKeyId` error + `DecryptDenied` incident,
//!   writer never called;
//! * destroyed key ⇒ `KeyDestroyed`, distinct from unknown, same denial path;
//! * audit sink failure ⇒ `AuditFailed`, writer never called (fail secure:
//!   no un-audited decrypt);
//! * `Storage::store_keyring`/`load_keyring` round-trip (DPAPI-sealed on
//!   Windows — asserted not-plaintext-at-rest there).

use std::cell::RefCell;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use dlp_agent::crypto::{self, EnvelopeError, Keyring};
use dlp_agent::decrypt::{decrypt_envelope, DecryptError};
use dlp_agent::storage::Storage;
use dlp_agent::usb::{ActionTaken, IncidentKind, UsbIncident};

const KEY_ID: &str = "class-internal/v1";
const SEALER: &str = "agent-sealer-A";
const OPENER: &str = "agent-opener-B";
const NOW: u64 = 1_700_000_000;

/// Dev keyfile JSON holding one 32-byte key under `key_id` (test material).
fn dev_json(key_id: &str) -> String {
    let b64 = B64.encode([0x42u8; 32]);
    format!(r#"{{"activeKeyId":"{key_id}","keys":{{"{key_id}":"{b64}"}}}}"#)
}

fn ring_with(key_id: &str) -> Keyring {
    Keyring::from_dev_json(dev_json(key_id).as_bytes()).expect("dev keyring parses")
}

fn seal_with(ring: &Keyring, plaintext: &[u8], name: &str) -> Vec<u8> {
    crypto::seal(plaintext, name, ring.active().expect("active kek"), SEALER, NOW)
        .expect("seal succeeds")
}

/// A unique temp dir per (test, process) so scenarios don't collide.
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join(format!("dlp-agent-decrypt-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("creating temp dir");
    dir
}

#[test]
fn round_trip_audits_before_write_with_full_incident_shape() {
    let ring = ring_with(KEY_ID);
    let plaintext = b"the plan: hold the line";
    let envelope = seal_with(&ring, plaintext, "plan.docx");

    // "Machine B": a FRESH ring parsed from the same dev keyfile bytes —
    // the spec's M4 acceptance shape (seal on A, open on B, same keyfile).
    let ring_b = ring_with(KEY_ID);

    let events: RefCell<Vec<&'static str>> = RefCell::new(Vec::new());
    let incidents: RefCell<Vec<UsbIncident>> = RefCell::new(Vec::new());
    let got: RefCell<Vec<u8>> = RefCell::new(Vec::new());

    let summary = decrypt_envelope(
        &envelope,
        "plan.docx.dlpenc",
        &ring_b,
        OPENER,
        |inc| {
            events.borrow_mut().push("audit");
            incidents.borrow_mut().push(inc.clone());
            Ok(())
        },
        |header, pt| {
            events.borrow_mut().push("write");
            assert_eq!(header.orig_name, "plan.docx");
            *got.borrow_mut() = pt.to_vec();
            Ok(())
        },
    )
    .expect("round-trip decrypt succeeds");

    // THE M4 invariant: the incident is queued strictly BEFORE the write.
    assert_eq!(
        *events.borrow(),
        vec!["audit", "write"],
        "audit incident must be recorded before the plaintext write"
    );
    assert_eq!(got.borrow().as_slice(), plaintext);

    let incidents = incidents.borrow();
    assert_eq!(incidents.len(), 1);
    let inc = &incidents[0];
    assert_eq!(inc.kind, IncidentKind::Decrypted);
    assert_eq!(inc.channel, "decrypt");
    assert_eq!(inc.action_taken, ActionTaken::Audited);
    assert_eq!(inc.key_id.as_deref(), Some(KEY_ID), "incident carries the key id");
    assert_eq!(
        inc.file_sha256, summary.plaintext_sha256,
        "incident carries the plaintext hash"
    );
    let note = inc.note.as_deref().expect("note present");
    assert!(note.contains(OPENER), "incident note carries the decrypting agent id");
    assert!(note.contains(SEALER), "incident note carries the sealing origin agent");
    assert!(inc.verdict.is_some(), "wire verdict present so the incident can post");

    // Summary is authenticated header truth.
    assert_eq!(summary.header.orig_name, "plan.docx");
    assert_eq!(summary.header.key_id, KEY_ID);
    assert_eq!(summary.header.origin_agent, SEALER);
    assert_eq!(summary.plaintext_len, plaintext.len());
    assert_eq!(
        summary.header.plaintext_sha256, summary.plaintext_sha256,
        "computed plaintext hash matches the authenticated header claim"
    );
}

#[test]
fn unknown_key_denies_with_incident_and_writes_nothing() {
    // Sealed under a key this endpoint's ring has never seen (foreign media).
    let foreign = ring_with("class-foreign/v9");
    let envelope = seal_with(&foreign, b"foreign secrets", "foreign.txt");
    let ring = ring_with(KEY_ID);

    let incidents: RefCell<Vec<UsbIncident>> = RefCell::new(Vec::new());
    let write_called = RefCell::new(false);

    let err = decrypt_envelope(
        &envelope,
        "foreign.txt.dlpenc",
        &ring,
        OPENER,
        |inc| {
            incidents.borrow_mut().push(inc.clone());
            Ok(())
        },
        |_h, _pt| {
            *write_called.borrow_mut() = true;
            Ok(())
        },
    )
    .expect_err("unknown key must deny");

    match err {
        DecryptError::Envelope(EnvelopeError::UnknownKeyId(id)) => {
            assert_eq!(id, "class-foreign/v9")
        }
        other => panic!("expected UnknownKeyId, got {other:?}"),
    }
    assert!(!*write_called.borrow(), "nothing may be written on a denial");

    let incidents = incidents.borrow();
    assert_eq!(incidents.len(), 1, "the denial itself is an incident (signal)");
    let inc = &incidents[0];
    assert_eq!(inc.kind, IncidentKind::DecryptDenied);
    assert_eq!(inc.channel, "decrypt");
    assert_eq!(inc.action_taken, ActionTaken::Blocked);
    assert_eq!(
        inc.key_id.as_deref(),
        Some("class-foreign/v9"),
        "the claimed key id is the reviewer's lead"
    );
    assert_eq!(inc.file_sha256, "", "no authenticated plaintext hash on a denial");
    assert!(inc.note.as_deref().unwrap().contains("unknown-key-id"));
}

#[test]
fn destroyed_key_denies_distinctly_from_unknown() {
    let mut ring = ring_with(KEY_ID);
    let envelope = seal_with(&ring, b"sealed before the shred", "old.txt");

    // Crypto-shred AFTER sealing — previously sealed media becomes unopenable
    // (definition-of-done #4; single-person v1 destroy is the caller's audit
    // duty, exercised here only as the keyring state change).
    assert!(ring.destroy(KEY_ID), "the key was held and is now shredded");

    let incidents: RefCell<Vec<UsbIncident>> = RefCell::new(Vec::new());
    let write_called = RefCell::new(false);

    let err = decrypt_envelope(
        &envelope,
        "old.txt.dlpenc",
        &ring,
        OPENER,
        |inc| {
            incidents.borrow_mut().push(inc.clone());
            Ok(())
        },
        |_h, _pt| {
            *write_called.borrow_mut() = true;
            Ok(())
        },
    )
    .expect_err("destroyed key must deny");

    match err {
        DecryptError::Envelope(EnvelopeError::KeyDestroyed(id)) => assert_eq!(id, KEY_ID),
        other => panic!("expected KeyDestroyed, got {other:?}"),
    }
    assert!(!*write_called.borrow());
    let incidents = incidents.borrow();
    assert_eq!(incidents[0].kind, IncidentKind::DecryptDenied);
    assert!(
        incidents[0].note.as_deref().unwrap().contains("key-destroyed"),
        "shredded is distinct from unknown in the record"
    );
}

#[test]
fn audit_failure_blocks_the_plaintext_write() {
    let ring = ring_with(KEY_ID);
    let envelope = seal_with(&ring, b"never without a record", "x.txt");
    let write_called = RefCell::new(false);

    let err = decrypt_envelope(
        &envelope,
        "x.txt.dlpenc",
        &ring,
        OPENER,
        |_inc| anyhow::bail!("post failed AND local queue full"),
        |_h, _pt| {
            *write_called.borrow_mut() = true;
            Ok(())
        },
    )
    .expect_err("no audit record ⇒ no decrypt");

    assert!(
        matches!(err, DecryptError::AuditFailed(_)),
        "expected AuditFailed, got {err:?}"
    );
    assert!(
        !*write_called.borrow(),
        "fail secure: an un-audited decrypt must never write plaintext"
    );
}

#[test]
fn keyring_persists_at_rest_and_round_trips() {
    let dir = temp_dir("keyring-rest");
    let storage = Storage::new(dir.clone());
    let json = dev_json(KEY_ID);

    storage.store_keyring(json.as_bytes()).expect("store keyring");
    let loaded = storage
        .load_keyring()
        .expect("load keyring")
        .expect("a stored keyring is present");
    let ring = Keyring::from_dev_json(&loaded).expect("restored ring parses");
    assert_eq!(ring.active_key_id(), KEY_ID);
    assert!(ring.active().is_ok(), "active KEK usable after the at-rest round trip");

    // On the product platform the blob at rest must be DPAPI-sealed —
    // never the plaintext keyring JSON.
    #[cfg(windows)]
    {
        let raw = std::fs::read(dir.join("keyring.sealed")).expect("sealed blob on disk");
        assert_ne!(
            raw.as_slice(),
            json.as_bytes(),
            "keyring at rest is DPAPI-sealed, not plaintext"
        );
    }

    // Never-stored ⇒ Ok(None), not an error.
    let empty = Storage::new(dir.join("nothing-here"));
    assert!(empty.load_keyring().expect("absent ring is not an error").is_none());

    let _ = std::fs::remove_dir_all(&dir);
}
