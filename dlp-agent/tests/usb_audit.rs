//! Integration test for the USB copy auditor (spec §8): a temp directory acts
//! as a simulated removable volume. The verdict source is INJECTED (a plain
//! `Fn(&Path) -> Result<Verdict>`) so the settle / dedup / incident logic is
//! validated deterministically without depending on live fingerprint math
//! (which is already golden-tested in bundle_loader.rs).
//!
//! The clock is injected too (`poll(now_ms)`), so settle timing is exact rather
//! than wall-clock-flaky. No `ReadDirectoryChangesW`, no message loop — the
//! polling path is the tested mechanism (spec §3.2 / §7).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use dlp_agent::crypto::{envelope, Kek, Keyring};
use dlp_agent::detect::{Extraction, IdmMatch, Verdict};
use dlp_agent::trustdest::{BlockBandPolicy, EncryptBands, EncryptMode};
use dlp_agent::usb::{
    scan_and_seal_to_incident, scan_to_incident, seal_file_in_place, ActionTaken, CopyAuditor,
    DeviceIdentity, IncidentKind, SealOutcome,
};

const SETTLE_MS: u64 = 1500;
const SETTLE_TIMEOUT_MS: u64 = 30_000;
const MAX_BYTES: u64 = 100 * 1024 * 1024;

/// A unique temp dir per (test, process) so scenarios don't collide.
fn temp_volume(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join(format!("dlp-agent-usb-audit-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("creating simulated volume");
    dir
}

fn device() -> DeviceIdentity {
    DeviceIdentity {
        drive_letter: "E:".into(),
        vendor_id: "Kingston".into(),
        product_id: "DataTraveler".into(),
        serial: "0123456789AB".into(),
        product_name: "Kingston DataTraveler".into(),
        bus_type: "usb".into(),
        removable: true,
    }
}

fn innocent_verdict(name: &str) -> Verdict {
    Verdict {
        file_name: name.to_string(),
        file_sha256: "deadbeef".into(),
        extraction: Extraction::Ok { format: "text".into() },
        idm: vec![],
        edm: vec![],
    }
}

fn matching_verdict(name: &str) -> Verdict {
    let mut v = innocent_verdict(name);
    v.idm.push(IdmMatch {
        version_id: "33333333-3333-4333-8333-333333333333".into(),
        document_id: "doc".into(),
        collection_id: "col".into(),
        title: "Fixture Plan Alpha".into(),
        containment: 1.0,
        coverage: 1.0,
        matched_count: 64,
        total_count: 64,
        matched_hashes: vec!["1".into()],
    });
    v
}

fn basename(p: &Path) -> String {
    p.file_name().unwrap().to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------

#[test]
fn dropped_file_settles_scans_once_and_produces_match_incident() {
    let vol = temp_volume("match");
    let path = vol.join("opord-secret.txt");
    std::fs::write(&path, b"the operations order body").expect("write file");

    let mut auditor = CopyAuditor::new(&vol, SETTLE_MS, SETTLE_TIMEOUT_MS);

    // First sight: not settled yet (quiet window hasn't elapsed).
    assert!(auditor.poll(0).is_empty(), "a file must not be scanned on first sight");

    // After the settle window with no changes → settled exactly once.
    let settled = auditor.poll(2000);
    assert_eq!(settled.len(), 1, "file must settle exactly once");
    assert_eq!(basename(&settled[0].path), "opord-secret.txt");

    // Scan the settled file through the injected verdict source (a match).
    let calls = AtomicUsize::new(0);
    let src = |p: &Path| -> anyhow::Result<Verdict> {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(matching_verdict(&basename(p)))
    };
    let incident = scan_to_incident(&settled[0], MAX_BYTES, &src, &device(), ActionTaken::Audited, "usb")
        .expect("a matching verdict must raise an incident");

    assert_eq!(calls.load(Ordering::SeqCst), 1, "settled file scanned exactly once");
    assert_eq!(incident.kind, IncidentKind::Match);
    assert_eq!(incident.channel, "usb", "channel label from config");
    assert_eq!(incident.file_name, "opord-secret.txt");
    assert_eq!(incident.file_sha256, "deadbeef");
    assert_eq!(incident.device.serial, "0123456789AB", "device context recorded locally");
    assert!(incident.verdict.is_some(), "match incident carries the verdict verbatim");

    let _ = std::fs::remove_dir_all(&vol);
}

#[test]
fn innocent_file_produces_no_incident() {
    let vol = temp_volume("innocent");
    let path = vol.join("shopping-list.txt");
    std::fs::write(&path, b"milk, eggs").expect("write file");

    let mut auditor = CopyAuditor::new(&vol, SETTLE_MS, SETTLE_TIMEOUT_MS);
    auditor.poll(0);
    let settled = auditor.poll(2000);
    assert_eq!(settled.len(), 1);

    let src = |p: &Path| -> anyhow::Result<Verdict> { Ok(innocent_verdict(&basename(p))) };
    let incident = scan_to_incident(&settled[0], MAX_BYTES, &src, &device(), ActionTaken::Audited, "usb");
    assert!(incident.is_none(), "a non-matching, readable file must not raise an incident");

    let _ = std::fs::remove_dir_all(&vol);
}

#[test]
fn same_file_across_two_poll_cycles_is_not_rescanned() {
    let vol = temp_volume("dedup");
    let path = vol.join("stable.txt");
    std::fs::write(&path, b"unchanged content").expect("write file");

    let mut auditor = CopyAuditor::new(&vol, SETTLE_MS, SETTLE_TIMEOUT_MS);
    auditor.poll(0);
    let first = auditor.poll(2000);
    assert_eq!(first.len(), 1, "settles once");

    // Subsequent polls with the file unchanged must yield nothing (dedup on
    // (path, size, mtime)). This is what stops a bulk copy re-scanning forever.
    assert!(auditor.poll(4000).is_empty(), "dedup: unchanged file not settled again");
    assert!(auditor.poll(9999).is_empty(), "dedup holds across many cycles");

    let _ = std::fs::remove_dir_all(&vol);
}

#[test]
fn still_growing_file_is_not_scanned_until_it_settles() {
    let vol = temp_volume("growing");
    let path = vol.join("bigcopy.bin");
    std::fs::write(&path, vec![0u8; 1024]).expect("write initial chunk");

    let mut auditor = CopyAuditor::new(&vol, SETTLE_MS, SETTLE_TIMEOUT_MS);
    assert!(auditor.poll(0).is_empty(), "first sight");

    // Simulate mid-copy growth: the size changes → settle timer resets.
    std::fs::write(&path, vec![0u8; 4096]).expect("grow file");
    assert!(auditor.poll(1000).is_empty(), "a growing file must not settle");

    // Only 500ms of stability so far — still not settled.
    assert!(auditor.poll(1500).is_empty(), "quiet window not yet elapsed after last change");

    // No further growth; now past the settle window relative to the last change.
    let settled = auditor.poll(3000);
    assert_eq!(settled.len(), 1, "settles once growth stops and the window elapses");
    assert_eq!(settled[0].size, 4096, "settled at the final size");

    let _ = std::fs::remove_dir_all(&vol);
}

#[test]
fn vanished_temp_file_is_never_scanned() {
    // Edge 9: a file created then deleted before it settles is dropped
    // naturally by the settle delay.
    let vol = temp_volume("vanish");
    let path = vol.join("~tmp.part");
    std::fs::write(&path, b"partial").expect("write temp");

    let mut auditor = CopyAuditor::new(&vol, SETTLE_MS, SETTLE_TIMEOUT_MS);
    assert!(auditor.poll(0).is_empty(), "seen but not settled");
    std::fs::remove_file(&path).expect("delete temp before settle");
    assert!(auditor.poll(2000).is_empty(), "a vanished file must never be scanned");

    let _ = std::fs::remove_dir_all(&vol);
}

#[test]
fn oversized_file_is_skipped_with_a_metadata_incident() {
    // Edge 3: the size gate raises a metadata incident WITHOUT reading the file.
    let vol = temp_volume("toobig");
    let path = vol.join("huge.iso");
    std::fs::write(&path, vec![0u8; 2048]).expect("write file");

    let mut auditor = CopyAuditor::new(&vol, SETTLE_MS, SETTLE_TIMEOUT_MS);
    auditor.poll(0);
    let settled = auditor.poll(2000);
    assert_eq!(settled.len(), 1);

    // Cap below the file size → skip-with-note; verdict source must NOT run.
    let src = |_: &Path| -> anyhow::Result<Verdict> { panic!("oversized file must not be read") };
    let incident = scan_to_incident(&settled[0], 1024, &src, &device(), ActionTaken::Audited, "usb")
        .expect("too-large must raise a metadata incident");
    assert_eq!(incident.kind, IncidentKind::SkippedTooLarge);
    assert!(incident.verdict.is_none());

    let _ = std::fs::remove_dir_all(&vol);
}

// ---------------------------------------------------------------------------
// USB seal-in-place (encrypt-on-write M3, spec §5.1): the temp dir acts as an
// `Action::Encrypt` volume. The REAL sealer (`seal_file_in_place` + the real
// AES-256-GCM envelope) runs against it — no hardware, no driver.

const KEY_ID: &str = "class-internal/v1";

fn test_kek() -> Kek {
    Kek::new(KEY_ID, [7u8; 32])
}

fn test_keyring() -> Keyring {
    let mut ring = Keyring::new(KEY_ID);
    ring.insert(test_kek());
    ring
}

/// The production-shaped sealer closure the monitor wires in main.rs.
fn real_sealer(path: &Path, key_id: &str) -> anyhow::Result<SealOutcome> {
    let ring = test_keyring();
    let kek = ring.lookup(key_id).map_err(anyhow::Error::new)?;
    seal_file_in_place(path, kek, "agent-under-test", 1_754_000_000)
}

/// Verdict inside the seal band (0.05 ≤ containment < 0.30) — sealed, not blocked.
fn seal_band_verdict(name: &str) -> Verdict {
    let mut v = innocent_verdict(name);
    v.idm.push(IdmMatch {
        version_id: "33333333-3333-4333-8333-333333333333".into(),
        document_id: "doc".into(),
        collection_id: "col".into(),
        title: "Fixture Plan Alpha".into(),
        containment: 0.10,
        coverage: 0.10,
        matched_count: 4,
        total_count: 64,
        matched_hashes: vec!["1".into()],
    });
    v
}

#[test]
fn sensitive_file_on_encrypt_volume_is_sealed_in_place() {
    let vol = temp_volume("seal");
    let path = vol.join("plan.docx");
    let secret_body = b"the operations order body (sensitive)";
    std::fs::write(&path, secret_body).expect("write file");

    let mut auditor = CopyAuditor::new(&vol, SETTLE_MS, SETTLE_TIMEOUT_MS);
    auditor.poll(0);
    let settled = auditor.poll(2000);
    assert_eq!(settled.len(), 1, "file must settle exactly once");

    let src = |p: &Path| -> anyhow::Result<Verdict> { Ok(seal_band_verdict(&basename(p))) };
    let incident = scan_and_seal_to_incident(
        &settled[0],
        MAX_BYTES,
        &src,
        &device(),
        "usb",
        EncryptMode::EncryptSensitive,
        &EncryptBands::default(),
        BlockBandPolicy::Block,
        KEY_ID,
        &real_sealer,
    )
    .expect("a sealed file must raise an incident");

    // On-disk shape: sealed sibling present, plaintext + temp gone.
    let sealed_path = vol.join("plan.docx.dlpenc");
    assert!(sealed_path.exists(), ".dlpenc sibling must exist");
    assert!(!path.exists(), "plaintext original must be gone");
    assert!(!vol.join("plan.docx.dlpenc.tmp").exists(), "no temp file left behind");

    // The envelope round-trips with the org keyring (offline, no server).
    let sealed_bytes = std::fs::read(&sealed_path).expect("read envelope");
    let (header, plaintext) =
        envelope::open(&sealed_bytes, &test_keyring()).expect("envelope must open with the KEK");
    assert_eq!(plaintext, secret_body, "seal→open is identity");
    assert_eq!(header.key_id, KEY_ID);
    assert_eq!(header.orig_name, "plan.docx", "original name survives inside the header");

    // Incident shape: Encrypted + key id + BOTH hashes + the v1 limitation note.
    assert_eq!(incident.kind, IncidentKind::Match);
    assert_eq!(incident.action_taken, ActionTaken::Encrypted);
    assert_eq!(incident.key_id.as_deref(), Some(KEY_ID));
    assert_eq!(incident.file_sha256, "deadbeef", "plaintext hash from the verdict");
    let sealed_sha = incident.sealed_sha256.as_deref().expect("sealed hash present");
    assert_eq!(sealed_sha.len(), 64, "hex sha-256 of the envelope");
    assert_eq!(header.plaintext_sha256.len(), 64);
    assert_eq!(incident.note.as_deref(), Some("sealed-post-write"));

    let _ = std::fs::remove_dir_all(&vol);
}

#[test]
fn failing_sealer_keeps_plaintext_and_raises_enforcement_failed() {
    let vol = temp_volume("sealfail");
    let path = vol.join("plan.docx");
    std::fs::write(&path, b"sensitive body").expect("write file");

    let mut auditor = CopyAuditor::new(&vol, SETTLE_MS, SETTLE_TIMEOUT_MS);
    auditor.poll(0);
    let settled = auditor.poll(2000);
    assert_eq!(settled.len(), 1);

    // A sealer whose keyring does not hold the requested key — the same
    // failure mode as an unsynced/unset [crypto] keyfile.
    let bad_sealer = |p: &Path, _k: &str| -> anyhow::Result<SealOutcome> {
        let ring = Keyring::new("other/v1");
        let kek = ring.lookup("other/v1").map_err(anyhow::Error::new)?;
        seal_file_in_place(p, kek, "agent-under-test", 0)
    };
    let src = |p: &Path| -> anyhow::Result<Verdict> { Ok(seal_band_verdict(&basename(p))) };
    let incident = scan_and_seal_to_incident(
        &settled[0],
        MAX_BYTES,
        &src,
        &device(),
        "usb",
        EncryptMode::EncryptSensitive,
        &EncryptBands::default(),
        BlockBandPolicy::Block,
        KEY_ID,
        &bad_sealer,
    )
    .expect("a failed seal must be flagged");

    // Fail secure: plaintext untouched, nothing sealed, copy flagged.
    assert!(path.exists(), "plaintext must be KEPT on seal failure");
    assert!(!vol.join("plan.docx.dlpenc").exists(), "no sealed sibling on failure");
    assert_eq!(incident.kind, IncidentKind::EnforcementFailed);
    assert_eq!(incident.action_taken, ActionTaken::Audited, "never claim Encrypted on failure");
    assert!(incident.key_id.is_none());
    assert!(incident.sealed_sha256.is_none());
    assert!(incident.note.as_deref().unwrap().contains("seal-failed(plaintext-kept)"));

    let _ = std::fs::remove_dir_all(&vol);
}

#[test]
fn clean_file_on_encrypt_sensitive_volume_stays_plaintext() {
    let vol = temp_volume("sealclean");
    let path = vol.join("shopping-list.txt");
    std::fs::write(&path, b"milk, eggs").expect("write file");

    let mut auditor = CopyAuditor::new(&vol, SETTLE_MS, SETTLE_TIMEOUT_MS);
    auditor.poll(0);
    let settled = auditor.poll(2000);
    assert_eq!(settled.len(), 1);

    let calls = AtomicUsize::new(0);
    let counting_sealer = |p: &Path, k: &str| -> anyhow::Result<SealOutcome> {
        calls.fetch_add(1, Ordering::SeqCst);
        real_sealer(p, k)
    };
    let src = |p: &Path| -> anyhow::Result<Verdict> { Ok(innocent_verdict(&basename(p))) };
    let incident = scan_and_seal_to_incident(
        &settled[0],
        MAX_BYTES,
        &src,
        &device(),
        "usb",
        EncryptMode::EncryptSensitive,
        &EncryptBands::default(),
        BlockBandPolicy::Block,
        KEY_ID,
        &counting_sealer,
    );

    // decide-not-to-seal: today's behaviour exactly — plaintext, no incident.
    assert!(incident.is_none(), "clean file on encrypt_sensitive raises nothing");
    assert_eq!(calls.load(Ordering::SeqCst), 0, "the sealer must not be called");
    assert!(path.exists(), "the file stays plaintext");
    assert!(!vol.join("shopping-list.txt.dlpenc").exists());

    let _ = std::fs::remove_dir_all(&vol);
}

#[test]
fn sealed_envelopes_are_never_re_processed() {
    // Regression: the sealer writes <name>.dlpenc, which must not be picked up
    // as a new file and sealed again (recursing to .dlpenc.dlpenc...).
    let vol = temp_volume("noresealenv");
    std::fs::write(vol.join("plan.docx.dlpenc"), b"DLPE...pretend envelope").unwrap();
    std::fs::write(vol.join("plan.docx.dlpenc.tmp"), b"in-flight").unwrap();
    std::fs::write(vol.join("real.pdf"), b"a genuine new copy").unwrap();

    let mut auditor = CopyAuditor::new(&vol, SETTLE_MS, SETTLE_TIMEOUT_MS);
    auditor.poll(0);
    let settled = auditor.poll(SETTLE_TIMEOUT_MS + 1);
    let names: Vec<String> = settled
        .iter()
        .filter_map(|s| s.path.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    assert_eq!(names, vec!["real.pdf"], "envelopes (.dlpenc / .dlpenc.tmp) are skipped");

    let _ = std::fs::remove_dir_all(&vol);
}

#[test]
fn baseline_existing_suppresses_pre_existing_files_only() {
    // A stick that already has content when it is plugged in: baseline it, then
    // only files copied AFTERWARD should settle and surface for sealing.
    let vol = temp_volume("baseline");
    std::fs::write(vol.join("already-there-1.pdf"), b"pre-existing sensitive body").unwrap();
    std::fs::write(vol.join("already-there-2.txt"), b"pre-existing notes").unwrap();

    let mut auditor = CopyAuditor::new(&vol, SETTLE_MS, SETTLE_TIMEOUT_MS);
    let n = auditor.baseline_existing();
    assert_eq!(n, 2, "both pre-existing files are baselined");

    // Poll past the settle window: the baselined files must NOT surface.
    auditor.poll(0);
    let settled = auditor.poll(SETTLE_TIMEOUT_MS + 1);
    assert!(settled.is_empty(), "pre-existing content is never re-processed after baseline");

    // Now a genuine copy-to-stick AFTER mount.
    std::fs::write(vol.join("freshly-copied.pdf"), b"the file the user just copied").unwrap();
    auditor.poll(SETTLE_TIMEOUT_MS + 2);
    let settled = auditor.poll(2 * SETTLE_TIMEOUT_MS + 4);
    let names: Vec<String> = settled
        .iter()
        .filter_map(|s| s.path.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    assert_eq!(names, vec!["freshly-copied.pdf"], "only the new copy surfaces");

    let _ = std::fs::remove_dir_all(&vol);
}
