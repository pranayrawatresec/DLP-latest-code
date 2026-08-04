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

use dlp_agent::detect::{Extraction, IdmMatch, Verdict};
use dlp_agent::usb::{scan_to_incident, ActionTaken, CopyAuditor, DeviceIdentity, IncidentKind};

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
