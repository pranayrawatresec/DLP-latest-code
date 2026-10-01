use dlp_agent::bluetooth::{decide, Decision, Mode};
use dlp_agent::detect::{Bands, EdmRowHit, EdmSourceHit, Extraction, IdmMatch, MlResult, Verdict};
use dlp_agent::readdenypolicy::ReadDenyPolicy;

fn clean() -> Verdict {
    Verdict {
        file_name: "example.txt".into(),
        file_sha256: "hash".into(),
        extraction: Extraction::Ok {
            format: "text".into(),
        },
        idm: vec![],
        edm: vec![],
        ml: None,
    }
}
fn bands() -> Bands {
    Bands::new(0.3, 0.6)
}
fn model(sensitive: bool) -> MlResult {
    MlResult::classified("test", "FIN", "Financial", 0.99, sensitive, 1, 20)
}

#[test]
fn either_detector_blocks_independently() {
    let mut v = clean();
    v.idm.push(IdmMatch {
        version_id: "v".into(),
        document_id: "d".into(),
        collection_id: "c".into(),
        title: "Registered".into(),
        containment: 0.9,
        coverage: 0.9,
        matched_count: 9,
        total_count: 10,
        matched_hashes: vec![],
    });
    // ML missing, non-sensitive, sensitive: none may downgrade a fingerprint.
    for ml in [None, Some(model(false)), Some(model(true))] {
        v.ml = ml;
        assert_eq!(decide(Some(&v), &bands(), true, false), Decision::Sensitive);
    }
    v.idm.clear();
    assert_eq!(decide(Some(&v), &bands(), true, false), Decision::Sensitive);
    v.ml = None;
    v.edm.push(EdmSourceHit {
        source_id: "s".into(),
        name: "Records".into(),
        rows_hit: vec![EdmRowHit {
            row_id: 1,
            fields: vec!["id".into()],
        }],
    });
    assert_eq!(decide(Some(&v), &bands(), true, false), Decision::Sensitive);
}

#[test]
fn pending_can_become_clean_or_sensitive_on_retry() {
    let mut v = clean();
    assert!(matches!(
        decide(Some(&v), &bands(), true, false),
        Decision::Unknown(_)
    ));
    v.ml = Some(model(false));
    assert_eq!(decide(Some(&v), &bands(), true, false), Decision::Clean);
    v.ml = Some(model(true));
    assert_eq!(decide(Some(&v), &bands(), true, false), Decision::Sensitive);
}

#[test]
fn unknown_and_partial_content_never_become_clean() {
    let mut v = clean();
    v.ml = Some(model(false));
    assert!(matches!(
        decide(None, &bands(), false, false),
        Decision::Unknown(_)
    ));
    assert!(matches!(
        decide(Some(&v), &bands(), true, true),
        Decision::Unknown(_)
    ));
    v.extraction = Extraction::Unreadable {
        reason: "encrypted-container".into(),
    };
    assert!(matches!(
        decide(Some(&v), &bands(), true, false),
        Decision::Unknown(_)
    ));
    // A positive signal still blocks even if the other detector has incomplete input.
    v.ml = Some(model(true));
    assert_eq!(decide(Some(&v), &bands(), true, true), Decision::Sensitive);
}

#[test]
fn inactive_ml_does_not_require_a_model() {
    assert_eq!(
        decide(Some(&clean()), &bands(), false, false),
        Decision::Clean
    );
}

#[test]
fn bluetooth_policy_is_independent_and_backwards_compatible() {
    let p: ReadDenyPolicy =
        serde_json::from_str(r#"{"mode":"off","bluetoothMode":"enforce"}"#).unwrap();
    assert!(!p.read_block());
    assert_eq!(p.bluetooth_mode, Mode::Enforce);
    let legacy: ReadDenyPolicy = serde_json::from_str(r#"{"mode":"enforce"}"#).unwrap();
    assert_eq!(legacy.bluetooth_mode, Mode::Off);
    assert!(serde_json::from_str::<ReadDenyPolicy>(r#"{"bluetoothMode":"invalid"}"#).is_err());
    assert_eq!(Mode::Off.wire(), 0);
    assert_eq!(Mode::Enforce.wire(), 1);
    assert_eq!(Mode::Monitor.wire(), 2);
}
