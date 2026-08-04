//! Clipboard detection gate (spec §1.5): `detect::verdict_text` must reproduce
//! `verdict(path)`'s matching on the SAME text — proving the behavior-preserving
//! refactor — and fire on protected material copied to the clipboard, while
//! staying quiet on innocent text.
//!
//! Reuses the server-produced golden bundle fixture in
//! dlp-management-server/test/fixtures/bundle-sample/ (the same one
//! tests/bundle_loader.rs gates), so no new fixture is introduced.

use dlp_agent::clipboard::formats::ClipboardPayload;
use dlp_agent::clipboard::{inspect, verdict_blocks};
use dlp_agent::config::{ClipboardAction, ClipboardConfig};
use dlp_agent::detect::bundle::Bundle;
use dlp_agent::detect::{verdict, verdict_text, Extraction};
use dlp_agent::usb::IncidentKind;
use std::path::{Path, PathBuf};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../dlp-management-server/test/fixtures/bundle-sample")
}

fn load_bundle() -> Bundle {
    let dir = fixture_dir();
    let bytes = std::fs::read(dir.join("sample.bundle")).expect("sample.bundle");
    let ca = std::fs::read(dir.join("ca-cert.pem")).expect("ca-cert.pem");
    Bundle::load(&bytes, &ca).expect("golden bundle must load")
}

/// DOC_A_TEXT from scripts/gen-bundle-fixture.js, reproduced verbatim (same as
/// tests/bundle_loader.rs).
fn doc_a_text() -> String {
    let sentences: Vec<String> = (1..=12)
        .map(|i| {
            format!(
                "Unit {i} advances to grid reference alpha {i} and holds the \
                 river crossing until the fuel convoy has cleared checkpoint delta {i}."
            )
        })
        .collect();
    format!("Operation fixture alpha. {}", sentences.join(" "))
}

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("dlp-clip-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

#[test]
fn verdict_text_matches_protected_document() {
    let bundle = load_bundle();
    let v = verdict_text(&doc_a_text(), &bundle);
    assert_eq!(v.extraction, Extraction::Ok { format: "text".into() });
    let top = v.idm.first().expect("doc A must match on clipboard text");
    assert_eq!(top.title, "Fixture Plan Alpha");
    assert_eq!(top.containment, 1.0, "verbatim copy contains 100% of doc A");
    // No path/file name on a clipboard-text verdict.
    assert!(v.file_name.is_empty());
}

#[test]
fn verdict_text_is_quiet_on_innocent_text() {
    let bundle = load_bundle();
    let v = verdict_text("Let us meet for coffee at ten and discuss the picnic.", &bundle);
    assert!(v.idm.is_empty(), "innocent text must not match any document");
    assert!(v.edm.is_empty());
}

#[test]
fn verdict_text_reproduces_verdict_path_matching() {
    // The refactor must be behavior-preserving: verdict_text on the extracted
    // text of a file must yield the SAME idm/edm as verdict(path) on that file.
    let bundle = load_bundle();
    let text = doc_a_text();

    let path = temp_dir().join("alpha.txt");
    std::fs::write(&path, &text).expect("write scan file");
    let from_path = verdict(&path, &bundle).expect("verdict(path)");
    let from_text = verdict_text(&text, &bundle);

    assert_eq!(from_path.idm, from_text.idm, "idm must be byte-identical");
    assert_eq!(from_path.edm, from_text.edm, "edm must be byte-identical");
    // Same content hash too (sha256 of the identical bytes).
    assert_eq!(from_path.file_sha256, from_text.file_sha256);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn verdict_text_fires_edm_on_a_copied_row() {
    // A copied identity row (two primary fields + dob within proximity) fires
    // EDM even though it carries no document fingerprints — the clipboard case
    // the spec calls out (low containment, EDM signal).
    let bundle = load_bundle();
    let v = verdict_text(
        "Duty roster update: Jane Doe (service number CD-5678) reported to the depot on 1990-07-02.",
        &bundle,
    );
    assert_eq!(v.edm.len(), 1, "one EDM source must hit on the copied row");
    assert!(v.idm.is_empty(), "no document fingerprints in this snippet");
}

#[test]
fn clipboard_inspect_blocks_a_matching_text_copy_when_action_is_block() {
    // End-to-end pure decision: under default_action=block, a protected copy
    // blocks and raises a Match incident (metadata only — verdict, never text).
    let bundle = load_bundle();
    let mut cfg = ClipboardConfig::default();
    cfg.default_action = ClipboardAction::Block;
    let payload = ClipboardPayload::Text(doc_a_text());
    let decision = inspect(&payload, Some(&bundle), &cfg);
    assert!(decision.block, "a verbatim protected copy must block under block policy");
    assert_eq!(decision.incidents.len(), 1);
    assert_eq!(decision.incidents[0].kind, IncidentKind::Match);
    assert_eq!(decision.incidents[0].channel, "clipboard");
    // The incident carries the verdict metadata, NOT the copied text.
    assert!(decision.incidents[0].verdict.is_some());
    assert_eq!(decision.incidents[0].file_name, "(clipboard text)");
}

#[test]
fn clipboard_inspect_audits_but_does_not_block_under_audit_default() {
    // Default is audit-only: a match still raises an incident, but the clipboard
    // is not blocked (the incident's action is Audited, not Blocked).
    use dlp_agent::usb::ActionTaken;
    let bundle = load_bundle();
    let cfg = ClipboardConfig::default(); // default_action = allow_audited
    let payload = ClipboardPayload::Text(doc_a_text());
    let decision = inspect(&payload, Some(&bundle), &cfg);
    assert!(!decision.block, "audit-only default must not block");
    assert_eq!(decision.incidents.len(), 1, "detection still audits the copy");
    assert_eq!(decision.incidents[0].kind, IncidentKind::Match);
    assert_eq!(decision.incidents[0].action_taken, ActionTaken::Audited);
}

#[test]
fn clipboard_inspect_allows_innocent_text() {
    let bundle = load_bundle();
    let cfg = ClipboardConfig::default();
    let payload = ClipboardPayload::Text("nothing sensitive here at all".into());
    let decision = inspect(&payload, Some(&bundle), &cfg);
    assert!(!decision.block);
    assert!(decision.incidents.is_empty());
}

#[test]
fn clipboard_inspect_edm_row_blocks_under_block_policy() {
    // A copied identity row (EDM proximity hit) is a block-worthy signal; under
    // default_action=block it blocks the paste and raises a Match incident.
    let bundle = load_bundle();
    let mut cfg = ClipboardConfig::default();
    cfg.default_action = ClipboardAction::Block;
    let payload = ClipboardPayload::Text(
        "Duty roster update: Jane Doe (service number CD-5678) reported to the depot on 1990-07-02."
            .into(),
    );
    let decision = inspect(&payload, Some(&bundle), &cfg);
    assert!(decision.block, "a copied identity row must block under block policy");
    assert_eq!(decision.incidents.len(), 1);
    assert_eq!(decision.incidents[0].kind, IncidentKind::Match);
}

#[test]
fn verdict_blocks_helper_thresholds() {
    // Direct check of the shared policy signal used by the clipboard decision.
    let bundle = load_bundle();
    let v = verdict_text(&doc_a_text(), &bundle);
    assert!(verdict_blocks(&v, 0.30, 0.60));
    // An impossibly high threshold with no EDM must NOT block.
    let innocent = verdict_text("coffee and biscuits", &bundle);
    assert!(!verdict_blocks(&innocent, 0.30, 0.60));
}
