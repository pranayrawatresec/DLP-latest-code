//! Golden gate for the bundle loader (src/detect/bundle.rs) against the
//! server-produced fixture in
//! dlp-management-server/test/fixtures/bundle-sample/ — the byte-exact
//! contract of docs/index-bundle-format.md. Every assertion in expected.json
//! must reproduce, and any tampered byte must fail verification. A failure
//! here is a breaking protocol change, not a flaky test.
//!
//! Also gates the EDM port (src/detect/edm.rs): the salted cell hashes of
//! every fixture CSV cell must land on the exact bundle entries the server
//! stored, and a verdict() end-to-end scan must match the fixture documents
//! and rows.

use dlp_agent::detect::bundle::Bundle;
use dlp_agent::detect::edm::{hash_field, normalize_field};
use dlp_agent::detect::{verdict, Extraction};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../dlp-management-server/test/fixtures/bundle-sample")
}

fn load_fixture() -> (Vec<u8>, Vec<u8>, Value) {
    let dir = fixture_dir();
    let bundle = std::fs::read(dir.join("sample.bundle"))
        .unwrap_or_else(|e| panic!("cannot read sample.bundle in {}: {e}", dir.display()));
    let ca = std::fs::read(dir.join("ca-cert.pem")).expect("reading ca-cert.pem");
    let expected: Value =
        serde_json::from_slice(&std::fs::read(dir.join("expected.json")).expect("expected.json"))
            .expect("parsing expected.json");
    (bundle, ca, expected)
}

fn as_i64(v: &Value) -> i64 {
    v.as_str().expect("hash string").parse().expect("signed i64 decimal")
}

// =====================================================================
// 1. Header + bloom parameters reproduce expected.json exactly.
// =====================================================================

#[test]
fn golden_header_and_bloom_reproduced() {
    let (bytes, ca, expected) = load_fixture();
    let bundle = Bundle::load(&bytes, &ca).expect("golden bundle must load");
    let eh = &expected["header"];

    assert_eq!(bundle.format_version, 1);
    assert_eq!(bundle.version(), eh["bundleVersion"].as_u64().unwrap());
    assert_eq!(bundle.header.params.k as u64, eh["params"]["k"].as_u64().unwrap());
    assert_eq!(bundle.header.params.w as u64, eh["params"]["w"].as_u64().unwrap());
    assert_eq!(u64::from(bundle.header.params.hash_bits), eh["params"]["hashBits"].as_u64().unwrap());

    assert_eq!(bundle.header.counts.idm as u64, eh["counts"]["idm"].as_u64().unwrap());
    assert_eq!(bundle.header.counts.edm as u64, eh["counts"]["edm"].as_u64().unwrap());
    assert_eq!(bundle.header.counts.docs as u64, eh["counts"]["docs"].as_u64().unwrap());
    assert_eq!(bundle.idm_entries().len(), bundle.header.counts.idm);
    assert_eq!(bundle.edm_entries().len(), bundle.header.counts.edm);

    let escope: Vec<&str> = eh["scope"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(bundle.header.scope, escope);

    let edocs = eh["docs"].as_array().unwrap();
    assert_eq!(bundle.header.docs.len(), edocs.len());
    for (doc, ed) in bundle.header.docs.iter().zip(edocs) {
        assert_eq!(doc.version_id, ed["versionId"].as_str().unwrap());
        assert_eq!(doc.document_id, ed["documentId"].as_str().unwrap());
        assert_eq!(doc.collection_id, ed["collectionId"].as_str().unwrap());
        assert_eq!(doc.title, ed["title"].as_str().unwrap());
        assert_eq!(doc.fp_count as u64, ed["fpCount"].as_u64().unwrap());
    }

    let esources = eh["edmSources"].as_array().unwrap();
    assert_eq!(bundle.header.edm_sources.len(), esources.len());
    for (src, es) in bundle.header.edm_sources.iter().zip(esources) {
        assert_eq!(src.source_id, es["sourceId"].as_str().unwrap());
        assert_eq!(src.name, es["name"].as_str().unwrap());
        let efields = es["fields"].as_array().unwrap();
        assert_eq!(src.fields.len(), efields.len());
        for (f, ef) in src.fields.iter().zip(efields) {
            assert_eq!(u64::from(f.field_id), ef["fieldId"].as_u64().unwrap());
            assert_eq!(f.name, ef["name"].as_str().unwrap());
            assert_eq!(f.field_type, ef["type"].as_str().unwrap());
            assert_eq!(f.primary, ef["primary"].as_bool().unwrap());
        }
    }
    for (source_id, salt_hex) in eh["edmSalts"].as_object().unwrap() {
        assert_eq!(bundle.header.edm_salts.get(source_id).map(String::as_str),
                   salt_hex.as_str());
    }

    let (m_bits, k_hashes) = bundle.bloom_params();
    assert_eq!(u64::from(m_bits), expected["bloom"]["mBits"].as_u64().unwrap());
    assert_eq!(u64::from(k_hashes), expected["bloom"]["kHashes"].as_u64().unwrap());
}

// =====================================================================
// 2. Every expected lookup — present, bloom-negative, bloom-positive.
// =====================================================================

#[test]
fn golden_lookups_present_and_absent() {
    let (bytes, ca, expected) = load_fixture();
    let bundle = Bundle::load(&bytes, &ca).expect("golden bundle must load");

    for p in expected["present"].as_array().unwrap() {
        let hash = as_i64(&p["hash"]);
        assert!(bundle.bloom_has(hash), "present hash {hash} must be bloom-positive");
        let matches = p["matches"].as_array().unwrap();
        match p["section"].as_str().unwrap() {
            "idm" => {
                let found = bundle.lookup_idm(hash);
                assert_eq!(found.len(), matches.len(), "idm lookup count for {hash}");
                for (entry, em) in found.iter().zip(matches) {
                    assert_eq!(u64::from(entry.doc_index), em["docIndex"].as_u64().unwrap());
                    let doc = &bundle.header.docs[entry.doc_index as usize];
                    assert_eq!(doc.version_id, em["versionId"].as_str().unwrap());
                    assert_eq!(doc.title, em["title"].as_str().unwrap());
                }
            }
            "edm" => {
                let found = bundle.lookup_edm(hash);
                assert_eq!(found.len(), matches.len(), "edm lookup count for {hash}");
                for (entry, em) in found.iter().zip(matches) {
                    assert_eq!(u64::from(entry.source_index), em["sourceIndex"].as_u64().unwrap());
                    let src = &bundle.header.edm_sources[entry.source_index as usize];
                    assert_eq!(src.source_id, em["sourceId"].as_str().unwrap());
                    assert_eq!(u64::from(entry.row_id), em["rowId"].as_u64().unwrap());
                    assert_eq!(u64::from(entry.field_id), em["fieldId"].as_u64().unwrap());
                }
            }
            other => panic!("unknown section {other}"),
        }
    }

    for v in expected["absentBloomNegative"].as_array().unwrap() {
        let hash = as_i64(v);
        assert!(!bundle.bloom_has(hash), "hash {hash} must be bloom-NEGATIVE");
        assert!(bundle.lookup_idm(hash).is_empty());
        assert!(bundle.lookup_edm(hash).is_empty());
    }
    for v in expected["absentBloomPositive"].as_array().unwrap() {
        let hash = as_i64(v);
        // Bloom false positive: filter says maybe, sections must say no.
        assert!(bundle.bloom_has(hash), "hash {hash} must be a bloom false-positive");
        assert!(bundle.lookup_idm(hash).is_empty());
        assert!(bundle.lookup_edm(hash).is_empty());
    }
}

// =====================================================================
// 3. Any tampered byte must fail verification (fail closed).
// =====================================================================

#[test]
fn tampered_bundle_fails_verification() {
    let (bytes, ca, _) = load_fixture();
    assert!(Bundle::load(&bytes, &ca).is_ok(), "pristine bundle must load");

    // Flip one byte in: magic, header JSON, IDM section, and the signature.
    for offset in [0usize, 100, 2000, bytes.len() - 1] {
        let mut tampered = bytes.clone();
        tampered[offset] ^= 0x01;
        assert!(
            Bundle::load(&tampered, &ca).is_err(),
            "byte flip at offset {offset} must be rejected"
        );
    }
    // Truncation and trailing garbage are structural failures.
    assert!(Bundle::load(&bytes[..bytes.len() - 10], &ca).is_err(), "truncated must fail");
    let mut extended = bytes.clone();
    extended.push(0);
    assert!(Bundle::load(&extended, &ca).is_err(), "trailing bytes must fail");
    // An empty/garbage CA can never verify anything.
    assert!(Bundle::load(&bytes, b"not a pem").is_err(), "garbage CA must fail");
}

// =====================================================================
// 4. EDM port gate: every fixture CSV cell hash lands on the exact bundle
//    entry the server stored (salt + typed normalization + SHA-256/8-byte
//    truncation all byte-identical).
// =====================================================================

#[test]
fn edm_cell_hashes_match_golden_bundle() {
    let (bytes, ca, _) = load_fixture();
    let bundle = Bundle::load(&bytes, &ca).expect("golden bundle must load");
    let source = &bundle.header.edm_sources[0];
    let salt_hex = bundle.header.edm_salts.get(&source.source_id).expect("fixture salt");
    let salt: Vec<u8> = (0..salt_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&salt_hex[i..i + 2], 16).unwrap())
        .collect();

    // The fixture CSV from scripts/gen-bundle-fixture.js (rowId, raw cells).
    let rows: [(u32, [&str; 3]); 3] = [
        (1, ["Smith, John", "AB-1234", "14/03/1988"]),
        (2, ["Jane Doe", "CD-5678", "1990-07-02"]),
        (3, ["O'Brien, Pat", "EF-9012", "5 Mar 1979"]),
    ];
    for (row_id, cells) in rows {
        for (field, raw) in source.fields.iter().zip(cells) {
            let normalized = normalize_field(raw, &field.field_type)
                .unwrap_or_else(|| panic!("cell {raw:?} must normalize as {}", field.field_type));
            let hash = hash_field(&salt, field.field_id, &normalized);
            assert!(bundle.bloom_has(hash), "cell {raw:?}: hash must be bloom-positive");
            let found = bundle.lookup_edm(hash);
            assert_eq!(found.len(), 1, "cell {raw:?}: exactly one bundle entry");
            assert_eq!(found[0].row_id, row_id, "cell {raw:?}: rowId");
            assert_eq!(found[0].field_id, field.field_id, "cell {raw:?}: fieldId");
            assert_eq!(found[0].source_index, 0);
        }
    }

    // Spot-check the typed normalization forms themselves.
    assert_eq!(normalize_field("Smith, John", "text").as_deref(), Some("smith john"));
    assert_eq!(normalize_field("AB-1234", "id").as_deref(), Some("AB1234"));
    assert_eq!(normalize_field("14/03/1988", "date").as_deref(), Some("1988-03-14"));
    assert_eq!(normalize_field("1990-07-02", "date").as_deref(), Some("1990-07-02"));
    assert_eq!(normalize_field("5 Mar 1979", "date").as_deref(), Some("1979-03-05"));
    assert_eq!(normalize_field("31/02/1988", "date"), None, "impossible day must be rejected");
    assert_eq!(normalize_field("007", "number").as_deref(), Some("7"));
    assert_eq!(normalize_field("1,234.50", "number").as_deref(), Some("1234.5"));
    assert_eq!(normalize_field("-0", "number").as_deref(), Some("0"));
}

// =====================================================================
// 5. verdict() end-to-end on the fixture texts.
// =====================================================================

/// DOC_A_TEXT from scripts/gen-bundle-fixture.js, reproduced verbatim.
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

fn temp_scan_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("dlp-agent-bundle-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("creating temp scan dir");
    dir
}

#[test]
fn verdict_full_copy_of_fixture_doc_scores_containment_1() {
    let (bytes, ca, _) = load_fixture();
    let bundle = Bundle::load(&bytes, &ca).expect("golden bundle must load");

    let path = temp_scan_dir().join("alpha-copy.txt");
    std::fs::write(&path, doc_a_text()).expect("writing scan file");
    let v = verdict(&path, &bundle).expect("verdict");

    assert_eq!(v.extraction, Extraction::Ok { format: "text".into() });
    let top = v.idm.first().expect("doc A must match");
    assert_eq!(top.version_id, "33333333-3333-4333-8333-333333333333");
    assert_eq!(top.title, "Fixture Plan Alpha");
    assert_eq!(top.containment, 1.0, "verbatim copy must contain 100% of doc A");
    assert_eq!((top.matched_count, top.total_count), (64, 64));
    assert_eq!(top.matched_hashes.len(), 64);
    // Every reported hash must be resolvable in the bundle (server contract).
    for h in &top.matched_hashes {
        assert!(!bundle.lookup_idm(h.parse().unwrap()).is_empty());
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn verdict_edm_row_fires_on_proximity_and_stays_quiet_on_one_field() {
    let (bytes, ca, _) = load_fixture();
    let bundle = Bundle::load(&bytes, &ca).expect("golden bundle must load");
    let dir = temp_scan_dir();

    // Two primary fields + the dob of fixture row 2 in one sentence → hit.
    let hit_path = dir.join("roster.txt");
    std::fs::write(
        &hit_path,
        "Duty roster update: Jane Doe (service number CD-5678) reported to the depot on 1990-07-02.",
    )
    .expect("writing scan file");
    let v = verdict(&hit_path, &bundle).expect("verdict");
    assert_eq!(v.edm.len(), 1, "one source must hit");
    assert_eq!(v.edm[0].source_id, "66666666-6666-4666-8666-666666666666");
    let row = v.edm[0].rows_hit.iter().find(|r| r.row_id == 2).expect("row 2 must hit");
    assert!(row.fields.contains(&"full_name".to_string()));
    assert!(row.fields.contains(&"service_no".to_string()));
    assert!(row.fields.contains(&"dob".to_string()));
    assert!(v.idm.is_empty(), "no document fingerprints in this snippet");

    // A single matched field must NOT report a row (proximity rule).
    let quiet_path = dir.join("mention.txt");
    std::fs::write(&quiet_path, "Jane Doe attended the morning briefing as scheduled.")
        .expect("writing scan file");
    let v = verdict(&quiet_path, &bundle).expect("verdict");
    assert!(v.edm.is_empty(), "one field alone must not fire: {:?}", v.edm);

    let _ = std::fs::remove_file(&hit_path);
    let _ = std::fs::remove_file(&quiet_path);
}

#[test]
fn verdict_unreadable_is_a_verdict_not_an_error() {
    let (bytes, ca, _) = load_fixture();
    let bundle = Bundle::load(&bytes, &ca).expect("golden bundle must load");

    let path = temp_scan_dir().join("blob.bin");
    std::fs::write(&path, [0u8, 159, 146, 150, 7, 1]).expect("writing scan file");
    let v = verdict(&path, &bundle).expect("unreadable must still be Ok(verdict)");
    assert_eq!(v.extraction, Extraction::Unreadable { reason: "unsupported-format".into() });
    assert!(v.idm.is_empty() && v.edm.is_empty());
    let _ = std::fs::remove_file(&path);
}
