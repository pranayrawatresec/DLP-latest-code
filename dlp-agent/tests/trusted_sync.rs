//! M6 trusted-config sync — the AT-REST persistence path, exercised through the
//! library surface only (no live server, no network). Covers:
//!
//! * `Storage::store_trusted_destinations` / `load_trusted_destinations` round
//!   trip (metadata only — the file must never carry key bytes), and
//! * the synced keyring going to rest via `store_keyring` and coming back
//!   usable: seal on the synced KEK, open on a ring restored from rest.
//!
//! The pure merge/parse/keyring logic is unit-tested inside `src/trustsync.rs`;
//! this file gates the storage wiring that the binary depends on.

use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use dlp_agent::crypto::{self, Keyring};
use dlp_agent::storage::Storage;
use dlp_agent::trustdest::{BlockBandPolicy, EncryptMode};
use dlp_agent::trustsync::{
    self, SyncedDestination, SyncedKey, SyncedMatcher, TrustedConfig,
};

const SEALER: &str = "agent-under-test";
const NOW: u64 = 1_700_000_000;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("dlp-agent-trustsync-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("creating temp dir");
    dir
}

fn sample_dests() -> Vec<SyncedDestination> {
    vec![
        SyncedDestination {
            channel: "usb".into(),
            matcher: SyncedMatcher::Serial { serial: "0401396FBBF0C89E".into() },
            mode: EncryptMode::EncryptAll,
            key_id: "class-internal/v1".into(),
            on_block_band: BlockBandPolicy::Block,
        },
        SyncedDestination {
            channel: "usb".into(),
            matcher: SyncedMatcher::VidPid { vid: "0951".into(), pid: "1666".into() },
            mode: EncryptMode::EncryptSensitive,
            key_id: "class-secret/v2".into(),
            on_block_band: BlockBandPolicy::Seal,
        },
    ]
}

#[test]
fn destinations_persist_at_rest_metadata_only() {
    let dir = temp_dir("dests");
    let storage = Storage::new(dir.clone());
    let dests = sample_dests();

    storage
        .store_trusted_destinations(&trustsync::serialize_destinations(&dests))
        .expect("store destinations");

    // The at-rest file carries key IDS (by design, audited) but NEVER key bytes.
    let raw = std::fs::read(dir.join("trusted-destinations.json")).expect("file on disk");
    let text = String::from_utf8(raw).expect("utf8");
    assert!(text.contains("class-internal/v1"), "key id is expected metadata");
    assert!(text.contains("encrypt_all"));
    assert!(text.contains("onBlockBand"));

    let loaded = storage.load_trusted_destinations().expect("a stored file is present");
    let back = trustsync::parse_destinations(&loaded).expect("round-trips");
    assert_eq!(back, dests);
}

#[test]
fn absent_destinations_file_is_none() {
    let dir = temp_dir("absent");
    let storage = Storage::new(dir.join("nothing-here"));
    assert!(storage.load_trusted_destinations().is_none());
}

#[test]
fn synced_keyring_persists_at_rest_and_seals_then_opens() {
    let dir = temp_dir("keyring");
    let storage = Storage::new(dir.clone());

    // A trusted-config whose destination references the second key → that key is
    // the active seal key (see TrustedConfig::active_key_id).
    let tc = TrustedConfig {
        destinations: vec![SyncedDestination {
            channel: "usb".into(),
            matcher: SyncedMatcher::Serial { serial: "COURIER".into() },
            mode: EncryptMode::EncryptAll,
            key_id: "class-secret/v2".into(),
            on_block_band: BlockBandPolicy::Block,
        }],
        keys: vec![
            SyncedKey { id: "class-internal/v1".into(), key_b64: B64.encode([0x11u8; 32]) },
            SyncedKey { id: "class-secret/v2".into(), key_b64: B64.encode([0x22u8; 32]) },
        ],
    };

    // Persist the synced keyring exactly as sync_trusted_config does.
    let json = tc.to_keyring_json().expect("keys present");
    storage.store_keyring(&json).expect("store synced keyring at rest");

    // On the product platform the blob at rest must be DPAPI-sealed, never the
    // plaintext keyring JSON that carries KEK material.
    #[cfg(windows)]
    {
        let raw = std::fs::read(dir.join("keyring.sealed")).expect("sealed blob on disk");
        assert_ne!(raw.as_slice(), json.as_slice(), "keyring at rest is DPAPI-sealed");
    }

    // Restore from rest and seal with the synced active KEK…
    let restored = storage.load_keyring().expect("load").expect("present");
    let ring = Keyring::from_dev_json(&restored).expect("restored ring parses");
    assert_eq!(ring.active_key_id(), "class-secret/v2");

    let plaintext = b"the plan holds the line";
    let envelope = crypto::seal(
        plaintext,
        "plan.docx",
        ring.active().expect("active kek"),
        SEALER,
        NOW,
    )
    .expect("seal with synced key");

    // …and open with a fresh ring restored from the same at-rest blob.
    let restored2 = storage.load_keyring().expect("load").expect("present");
    let ring2 = Keyring::from_dev_json(&restored2).expect("second ring parses");
    let (header, opened) = crypto::open(&envelope, &ring2).expect("open with synced key");
    assert_eq!(opened, plaintext);
    assert_eq!(header.key_id, "class-secret/v2");
    assert_eq!(header.orig_name, "plan.docx");
}
