//! `detect::verdict_bytes` gate (content-over-port, kguard v2): the kernel
//! minifilter now reads the file IN-KERNEL and ships the bytes inline, so the
//! agent scores content in memory and NEVER re-opens the file. This proves
//! `verdict_bytes` fires on protected material (same matching core as
//! `verdict(path)`/`verdict_text`) and stays quiet on innocent bytes.
//!
//! Reuses the server-produced golden bundle fixture in
//! dlp-management-server/test/fixtures/bundle-sample/ (the same one
//! tests/bundle_loader.rs and tests/clipboard_verdict.rs gate) — no new fixture.

use dlp_agent::detect::bundle::Bundle;
use dlp_agent::detect::{verdict, verdict_bytes, Extraction};
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
/// tests/bundle_loader.rs / tests/clipboard_verdict.rs).
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

#[test]
fn verdict_bytes_matches_protected_document() {
    let bundle = load_bundle();
    let content = doc_a_text().into_bytes();
    let v = verdict_bytes(&content, "alpha.txt", &bundle);

    assert_eq!(v.extraction, Extraction::Ok { format: "text".into() });
    assert_eq!(v.file_name, "alpha.txt", "filename comes from the caller, not a re-opened path");
    let top = v.idm.first().expect("doc A must match on protected content bytes");
    assert_eq!(top.title, "Fixture Plan Alpha");
    assert_eq!(top.containment, 1.0, "verbatim content contains 100% of doc A");
}

#[test]
fn verdict_bytes_is_quiet_on_innocent_bytes() {
    let bundle = load_bundle();
    let content = b"Let us meet for coffee at ten and discuss the picnic.";
    let v = verdict_bytes(content, "note.txt", &bundle);
    assert!(v.idm.is_empty(), "innocent content must not match any document");
    assert!(v.edm.is_empty());
}

#[test]
fn verdict_bytes_reproduces_verdict_path() {
    // Behavior-preserving refactor: verdict_bytes on a file's bytes must yield
    // the SAME verdict as verdict(path) reading that file (golden-vector safe).
    let bundle = load_bundle();
    let text = doc_a_text();

    let dir = std::env::temp_dir().join(format!("dlp-vbytes-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("alpha.txt");
    std::fs::write(&path, &text).expect("write scan file");

    let from_path = verdict(&path, &bundle).expect("verdict(path)");
    let from_bytes = verdict_bytes(text.as_bytes(), "alpha.txt", &bundle);

    assert_eq!(from_path.idm, from_bytes.idm, "idm must be byte-identical");
    assert_eq!(from_path.edm, from_bytes.edm, "edm must be byte-identical");
    assert_eq!(from_path.file_sha256, from_bytes.file_sha256, "same content hash");
    assert_eq!(from_path.file_name, from_bytes.file_name, "same basename");
    let _ = std::fs::remove_file(&path);
}
