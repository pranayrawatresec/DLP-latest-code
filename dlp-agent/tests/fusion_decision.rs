//! FUSION gate — the unified detection decision (`detect::decide`) and the
//! fail-secure rules the channels wrap around it.
//!
//! WHY this test exists as its own binary: the fusion is the one place that says
//! "sensitive or not" for every channel, so a regression here silently changes
//! what leaves an employee's PC on USB, clipboard and web upload at once. The
//! matrix below is deliberately exhaustive over the four states (fingerprint
//! only / ML only / both / neither) plus every way the ML half can fail to fire:
//! below threshold, on a label the admin did not select, with the policy
//! disabled, and with the model unavailable under both `failBlock` settings.
//!
//! The claims being gated, from the contract:
//!   * `sensitive = fingerprint_sensitive OR ml_sensitive` — OR, never AND.
//!     Fingerprinting cannot see an unregistered document; the model cannot name
//!     which document leaked. Each covers the other's blind spot.
//!   * ML can only ADD sensitivity. It never downgrades a fingerprint hit.
//!   * severity: both ⇒ critical, fingerprint only ⇒ high, ML only ⇒ medium.
//!   * EGRESS paths honour `failBlock` when the model is unavailable; the kernel
//!     READ path NEVER runs the model and NEVER fail-blocks.
//!
//! NOTE ON THE POLICY STORE: `mlpolicy::ACTIVE` is process-wide, and cargo runs
//! the tests in one process on many threads. Every test that publishes a policy
//! takes `POLICY_LOCK` first, so the egress-rule tests cannot race each other.
//! The pure `decide()` tests need no lock at all — that is the point of keeping
//! it policy-free.

use std::sync::{Mutex, MutexGuard, OnceLock};

use dlp_agent::detect::decide::{ml_blocks_egress, ml_blocks_read, ml_fail_blocks};
use dlp_agent::detect::{
    decide, Bands, EdmRowHit, EdmSourceHit, Extraction, IdmMatch, MlResult, Severity, Verdict,
};
use dlp_agent::mlpolicy::{self, MlAction, MlLabelRule, MlPolicy};

// --------------------------------------------------------------------------
// Fixtures — all hand-built. The fusion is pure, so it needs no bundle, no
// model and no server.
// --------------------------------------------------------------------------

/// The kguard read-deny band (`block_at` 0.30 / `coverage_block_at` 0.60).
fn read_bands() -> Bands {
    Bands::new(0.30, 0.60)
}

/// The tighter removable-WRITE band (`removable_write_block_at` 0.15).
fn write_bands() -> Bands {
    Bands::new(0.15, 0.60)
}

fn clean() -> Verdict {
    Verdict {
        file_name: "f.docx".into(),
        file_sha256: "sha".into(),
        extraction: Extraction::Ok { format: "docx".into() },
        idm: Vec::new(),
        edm: Vec::new(),
        ml: None,
    }
}

fn with_idm(containment: f64, coverage: f64) -> Verdict {
    let mut v = clean();
    v.idm.push(IdmMatch {
        version_id: "v1".into(),
        document_id: "d1".into(),
        collection_id: "c1".into(),
        title: "Himalayan Shield OPORD".into(),
        containment,
        coverage,
        matched_count: 9,
        total_count: 10,
        matched_hashes: vec!["1".into()],
    });
    v
}

fn with_edm(mut v: Verdict) -> Verdict {
    v.edm.push(EdmSourceHit {
        source_id: "s1".into(),
        name: "Personnel roster".into(),
        rows_hit: vec![EdmRowHit { row_id: 7, fields: vec!["full_name".into(), "svc_no".into()] }],
    });
    v
}

/// An `ok` classification. `sensitive` is the POLICY answer the classify site
/// already computed — exactly what the verdict carries in production.
fn ml_ok(label: &str, confidence: f64, sensitive: bool) -> MlResult {
    MlResult::classified("V6.2.01", label, "Nuclear & Strategic Systems", confidence, sensitive, 2, 700)
}

fn attach(mut v: Verdict, ml: MlResult) -> Verdict {
    v.ml = Some(ml);
    v
}

// --------------------------------------------------------------------------
// THE MATRIX — pure fusion.
// --------------------------------------------------------------------------

#[test]
fn fusion_matrix() {
    // (name, verdict, bands, expect sensitive, expect signal, expect severity)
    let cases: Vec<(&str, Verdict, Bands, bool, Option<&str>, Option<Severity>)> = vec![
        // ---- neither ----------------------------------------------------
        ("clean, no ml at all", clean(), read_bands(), false, None, None),
        (
            "clean, model answered but the label is not selected",
            attach(clean(), ml_ok("PUB", 0.99, false)),
            read_bands(),
            false,
            None,
            None,
        ),
        (
            "clean, selected label but BELOW its threshold",
            // The classify site already applied `label_is_sensitive`, so a
            // below-threshold hit arrives as `sensitive: false`.
            attach(clean(), ml_ok("NUC", 0.55, false)),
            read_bands(),
            false,
            None,
            None,
        ),
        (
            "clean, policy disabled ⇒ no ml field at all",
            clean(),
            read_bands(),
            false,
            None,
            None,
        ),
        (
            "IDM match BELOW the band, no ml",
            with_idm(0.10, 0.10),
            read_bands(),
            false,
            None,
            None,
        ),
        // ---- fingerprint only -------------------------------------------
        (
            "IDM over the read band",
            with_idm(0.90, 0.0),
            read_bands(),
            true,
            Some("idm"),
            Some(Severity::High),
        ),
        (
            "IDM over the coverage band only",
            with_idm(0.01, 0.75),
            read_bands(),
            true,
            Some("idm"),
            Some(Severity::High),
        ),
        (
            "EDM row hit, unbanded",
            with_edm(clean()),
            read_bands(),
            true,
            Some("edm"),
            Some(Severity::High),
        ),
        (
            "IDM + EDM, no ml",
            with_edm(with_idm(0.90, 0.90)),
            read_bands(),
            true,
            Some("idm+edm"),
            Some(Severity::High),
        ),
        (
            "IDM under the READ band but over the tighter WRITE band",
            with_idm(0.20, 0.0),
            write_bands(),
            true,
            Some("idm"),
            Some(Severity::High),
        ),
        // ---- ML only ------------------------------------------------------
        (
            "unregistered document the model puts in a marked class",
            attach(clean(), ml_ok("NUC", 0.98, true)),
            read_bands(),
            true,
            Some("ml"),
            Some(Severity::Medium),
        ),
        (
            "ML hit alongside an IDM match too weak to fire",
            attach(with_idm(0.05, 0.05), ml_ok("NUC", 0.98, true)),
            read_bands(),
            true,
            Some("ml"),
            Some(Severity::Medium),
        ),
        // ---- both ---------------------------------------------------------
        (
            "IDM + ML",
            attach(with_idm(0.90, 0.0), ml_ok("NUC", 0.98, true)),
            read_bands(),
            true,
            Some("idm+ml"),
            Some(Severity::Critical),
        ),
        (
            "EDM + ML",
            attach(with_edm(clean()), ml_ok("NUC", 0.98, true)),
            read_bands(),
            true,
            Some("edm+ml"),
            Some(Severity::Critical),
        ),
        (
            "IDM + EDM + ML",
            attach(with_edm(with_idm(0.90, 0.90)), ml_ok("NUC", 0.98, true)),
            read_bands(),
            true,
            Some("idm+edm+ml"),
            Some(Severity::Critical),
        ),
        // ---- the model failed --------------------------------------------
        (
            "model unavailable, nothing else ⇒ the fusion detects NOTHING",
            // `failBlock` is a CHANNEL rule (egress only), never a detection.
            attach(clean(), MlResult::unavailable("V6.2.01", "model_not_loaded")),
            read_bands(),
            false,
            None,
            None,
        ),
        (
            "model unavailable does not weaken a fingerprint hit",
            attach(with_idm(0.90, 0.0), MlResult::unavailable("V6.2.01", "load_failed")),
            read_bands(),
            true,
            Some("idm"),
            Some(Severity::High),
        ),
        (
            "read path: model deliberately skipped, fingerprints still decide",
            attach(with_idm(0.90, 0.0), MlResult::skipped("V6.2.01", "read_path_skip")),
            read_bands(),
            true,
            Some("idm"),
            Some(Severity::High),
        ),
        (
            "read path: skipped ml on a clean file is still clean",
            attach(clean(), MlResult::skipped("V6.2.01", "read_path_skip")),
            read_bands(),
            false,
            None,
            None,
        ),
        (
            "nothing to classify (empty) is an outcome, not a detection",
            attach(clean(), MlResult::empty("V6.2.01")),
            read_bands(),
            false,
            None,
            None,
        ),
    ];

    for (name, verdict, bands, want_sensitive, want_signal, want_severity) in cases {
        let d = decide(&verdict, &bands);
        assert_eq!(d.sensitive, want_sensitive, "sensitive [{name}]");
        assert_eq!(d.signal.as_deref(), want_signal, "signal [{name}]");
        assert_eq!(d.severity, want_severity, "severity [{name}]");
        // Internal consistency: `sensitive` is exactly the OR of the two halves.
        assert_eq!(d.sensitive, d.fingerprint || d.ml, "OR invariant [{name}]");
        // And severity is a function of which halves fired, nothing else.
        assert_eq!(
            d.severity,
            match (d.fingerprint, d.ml) {
                (true, true) => Some(Severity::Critical),
                (true, false) => Some(Severity::High),
                (false, true) => Some(Severity::Medium),
                (false, false) => None,
            },
            "severity derivation [{name}]"
        );
    }
}

#[test]
fn ml_never_downgrades_a_fingerprint_hit() {
    // The strongest possible statement of "OR, never AND": the model is 100%
    // confident this is PUBLIC information and the policy agrees it is not
    // sensitive — and the document is still 95% of a registered plan.
    let v = attach(with_idm(0.95, 0.95), ml_ok("PUB", 1.0, false));
    let d = decide(&v, &read_bands());
    assert!(d.sensitive, "a fingerprint hit cannot be argued away by the model");
    assert!(d.fingerprint && !d.ml);
    assert_eq!(d.severity, Some(Severity::High));
}

#[test]
fn bands_come_from_the_caller_so_one_fusion_serves_every_channel() {
    // The SAME verdict is clean on the read band and sensitive on the tighter
    // removable-write band. That is the whole reason `Bands` is a parameter.
    let v = with_idm(0.20, 0.0);
    assert!(!decide(&v, &read_bands()).sensitive, "read band 0.30");
    assert!(decide(&v, &write_bands()).sensitive, "removable-write band 0.15");
}

#[test]
fn a_forged_sensitive_flag_on_a_failed_status_is_not_believed() {
    // Defence in depth: `sensitive` is only meaningful on `status == "ok"`.
    let mut bogus = MlResult::unavailable("V6.2.01", "load_failed");
    bogus.sensitive = true;
    assert!(!decide(&attach(clean(), bogus), &read_bands()).ml);
}

// --------------------------------------------------------------------------
// THE CHANNEL RULES — fail-secure, per path. These read the process-wide
// policy, so they serialise on POLICY_LOCK.
// --------------------------------------------------------------------------

fn policy_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let m = LOCK.get_or_init(|| Mutex::new(()));
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn live_policy(action: MlAction, fail_block: bool) -> MlPolicy {
    MlPolicy {
        enabled: true,
        action,
        fail_block,
        labels: vec![MlLabelRule { id: "NUC".into(), min_confidence: None }],
        ..MlPolicy::default()
    }
}

#[test]
fn egress_fail_block_true_blocks_an_unavailable_model() {
    let _g = policy_lock();
    mlpolicy::set_active(live_policy(MlAction::Audit, true));

    let unavailable = MlResult::unavailable("V6.2.01", "model_not_loaded");
    assert!(ml_fail_blocks(Some(&unavailable)), "failBlock=true ⇒ egress blocks");
    assert!(ml_blocks_egress(Some(&unavailable)));

    // The other statuses are NOT the model failing and must never fail-block.
    assert!(!ml_fail_blocks(Some(&MlResult::skipped("V6.2.01", "read_path_skip"))));
    assert!(!ml_fail_blocks(Some(&MlResult::empty("V6.2.01"))));
    assert!(!ml_fail_blocks(Some(&ml_ok("NUC", 0.99, true))));
    assert!(!ml_fail_blocks(None), "no ml result at all ⇒ nothing to fail on");

    mlpolicy::set_active(MlPolicy::default());
}

#[test]
fn egress_fail_block_false_lets_an_unavailable_model_through() {
    let _g = policy_lock();
    mlpolicy::set_active(live_policy(MlAction::Block, false));

    let unavailable = MlResult::unavailable("V6.2.01", "load_failed");
    assert!(!ml_fail_blocks(Some(&unavailable)), "failBlock=false ⇒ audit only");
    assert!(!ml_blocks_egress(Some(&unavailable)));

    mlpolicy::set_active(MlPolicy::default());
}

#[test]
fn egress_ml_hit_blocks_only_under_the_block_action() {
    let _g = policy_lock();
    let hit = ml_ok("NUC", 0.99, true);

    mlpolicy::set_active(live_policy(MlAction::Audit, true));
    assert!(
        !ml_blocks_egress(Some(&hit)),
        "action=audit records the incident but must not stop the copy"
    );

    mlpolicy::set_active(live_policy(MlAction::Block, true));
    assert!(ml_blocks_egress(Some(&hit)), "action=block stops it");

    mlpolicy::set_active(MlPolicy::default());
}

#[test]
fn an_inert_policy_makes_the_whole_signal_disappear() {
    let _g = policy_lock();
    // The shipped default: disabled, no labels. Nothing the model could say
    // reaches an egress decision, and the classify bridge attaches no `ml` field
    // at all — so a verdict is byte-identical to a pre-model one.
    mlpolicy::set_active(MlPolicy::default());
    assert!(
        !ml_blocks_egress(Some(&ml_ok("NUC", 1.0, true))),
        "a stale hit cannot block once the console switches the feature off"
    );
    assert!(
        !ml_fail_blocks(Some(&MlResult::unavailable("V6.2.01", "model_not_loaded"))),
        "failBlock defaults to true — an unarmed policy must still not block"
    );
    assert!(dlp_agent::detect::decide::ml_for_text("anything at all").is_none());
    assert!(dlp_agent::detect::decide::ml_read_path_skip().is_none());
    assert!(dlp_agent::detect::decide::ml_for_bytes(b"anything", "x.txt").is_none());

    // "enabled with no label selected" is a real console state and must be just
    // as inert — an admin who switched the feature on before choosing categories
    // has not armed anything.
    mlpolicy::set_active(MlPolicy { enabled: true, ..MlPolicy::default() });
    assert!(dlp_agent::detect::decide::ml_for_text("anything at all").is_none());
    assert!(dlp_agent::detect::decide::ml_read_path_skip().is_none());

    mlpolicy::set_active(MlPolicy::default());
}

#[test]
fn read_path_records_a_skip_and_never_a_model_hit() {
    let _g = policy_lock();
    mlpolicy::set_active(live_policy(MlAction::Block, true));

    let skip = dlp_agent::detect::decide::ml_read_path_skip().expect("policy is live");
    assert_eq!(skip.status, "skipped");
    assert_eq!(skip.reason.as_deref(), Some("read_path_skip"));
    assert_eq!(skip.model_version, "V6.2.01");
    assert!(!skip.sensitive);
    assert!(skip.label_id.is_none() && skip.label_name.is_none());
    // The synchronous kernel up-call has no budget for a forward pass, and a
    // skip must never be able to block — not even with failBlock set.
    assert!(!ml_fail_blocks(Some(&skip)));
    assert!(!ml_blocks_egress(Some(&skip)));
    // And it changes no decision: fingerprints alone decide the read.
    assert!(!decide(&attach(clean(), skip), &read_bands()).sensitive);

    mlpolicy::set_active(MlPolicy::default());
}

#[test]
fn model_not_loaded_maps_to_unavailable_on_a_live_policy() {
    let _g = policy_lock();
    mlpolicy::set_active(live_policy(MlAction::Block, true));

    // No engine is published in this test binary, so the classify bridge must
    // report the fail-secure `unavailable / model_not_loaded` — never a silent
    // "clean".
    let r = dlp_agent::detect::decide::ml_for_text("some text").expect("policy is live");
    assert_eq!(r.status, "unavailable");
    assert_eq!(r.reason.as_deref(), Some("model_not_loaded"));
    assert!(!r.sensitive);
    assert!(ml_fail_blocks(Some(&r)), "egress fails secure");

    // Bytes that cannot be extracted are `empty`, NOT `unavailable`: there is
    // nothing to read, the model is not at fault, and it must not fail-block.
    let e = dlp_agent::detect::decide::ml_for_bytes(&[0xff, 0xd8, 0xff, 0xe0], "photo.jpg")
        .expect("policy is live");
    assert_eq!(e.status, "empty");
    assert_eq!(e.reason.as_deref(), Some("no_text"));
    assert!(!ml_fail_blocks(Some(&e)));

    mlpolicy::set_active(MlPolicy::default());
}

// --------------------------------------------------------------------------
// The wire shape (contract §C) — this is a protocol the server parses.
// --------------------------------------------------------------------------

#[test]
fn verdict_without_ml_serializes_byte_identically() {
    // The whole reason `ml` is `skip_serializing_if = "Option::is_none"`: a
    // fingerprint-only verdict must be indistinguishable from a pre-model one,
    // because the golden vectors and the server's incident parser both see it.
    let json = serde_json::to_string(&clean()).unwrap();
    assert!(!json.contains("\"ml\""), "no ml key at all: {json}");
    assert_eq!(
        json,
        r#"{"fileName":"f.docx","fileSha256":"sha","extraction":{"status":"ok","format":"docx"},"idm":[],"edm":[]}"#
    );
}

#[test]
fn ml_result_serializes_in_the_contract_shape() {
    let v = attach(clean(), ml_ok("FIN", 0.9981, true));
    let json: serde_json::Value = serde_json::to_value(&v).unwrap();
    let ml = &json["ml"];
    assert_eq!(ml["status"], "ok");
    assert_eq!(ml["modelVersion"], "V6.2.01");
    assert_eq!(ml["labelId"], "FIN");
    assert_eq!(ml["confidence"], 0.9981);
    assert_eq!(ml["sensitive"], true);
    assert_eq!(ml["chunks"], 2);
    assert_eq!(ml["tokens"], 700);
    assert!(ml["reason"].is_null(), "reason is null on an answered classification");

    // A failed one carries the reason and no label.
    let bad = attach(clean(), MlResult::unavailable("V6.2.01", "load_failed"));
    let json: serde_json::Value = serde_json::to_value(&bad).unwrap();
    assert_eq!(json["ml"]["status"], "unavailable");
    assert_eq!(json["ml"]["reason"], "load_failed");
    assert!(json["ml"]["labelId"].is_null());
    assert!(json["ml"]["labelName"].is_null());
    assert_eq!(json["ml"]["sensitive"], false);

    // No content, ever — the incident report and the audit log carry this.
    let raw = serde_json::to_string(&bad).unwrap();
    assert!(!raw.contains("text"), "the ml result must never carry content: {raw}");
}


// =====================================================================
// THE READ PATH MUST ACT ON A POSITIVE MODEL HIT
//
// This is the regression guard for the defect that made the entire
// at-rest / at-creation / on-demand pipeline inert: the read branch used to
// compute `reason != DLP_REASON_READ && ml_blocks_egress(..)`, which suppressed
// the fail-block arm by throwing the POSITIVE answer away with it. Every cache
// hit — a document the walker had classified NUC at 0.99 — replied ALLOW, and
// RustDesk/AnyDesk/RDP read it straight out with no block and no incident.
//
// The asymmetry between the two paths is deliberate and both halves matter:
//   READ  blocks on a hit, NEVER on `unavailable`
//   WRITE blocks on a hit, AND on `unavailable` per failBlock
// =====================================================================

#[test]
fn a_positive_model_hit_denies_a_read() {
    let _g = policy_lock();
    mlpolicy::set_active(live_policy(MlAction::Block, true));

    let hit = ml_ok("NUC", 0.99, true);
    assert!(
        ml_blocks_read(Some(&hit)),
        "a cache hit the policy calls sensitive MUST deny the read — this is the \
         entire purpose of the verdict cache"
    );
}

#[test]
fn an_unavailable_model_never_denies_a_read() {
    let _g = policy_lock();
    mlpolicy::set_active(live_policy(MlAction::Block, true));

    // failBlock is TRUE and still must not apply here: a model that will not load
    // must never turn every file read on the endpoint into a denial.
    for r in [
        MlResult::unavailable("V6.2.01", "model_not_loaded"),
        MlResult::unavailable("V6.2.01", "load_failed"),
    ] {
        assert!(!ml_blocks_read(Some(&r)), "unavailable must not deny reads: {r:?}");
        assert!(ml_blocks_egress(Some(&r)), "...but it DOES block egress under failBlock");
    }
}

#[test]
fn read_denial_still_respects_the_audit_action() {
    let _g = policy_lock();
    mlpolicy::set_active(live_policy(MlAction::Audit, true));

    let hit = ml_ok("NUC", 0.99, true);
    assert!(
        !ml_blocks_read(Some(&hit)),
        "under action=audit a hit is recorded and fused, but does not deny"
    );
}

#[test]
fn an_inert_policy_denies_no_read_whatever_the_verdict_says() {
    let _g = policy_lock();
    mlpolicy::set_active(MlPolicy::default());

    assert!(!ml_blocks_read(Some(&ml_ok("NUC", 0.99, true))));
    assert!(!ml_blocks_read(Some(&MlResult::unavailable("V6.2.01", "load_failed"))));
    assert!(!ml_blocks_read(None));
}

#[test]
fn skipped_and_empty_never_deny_a_read() {
    let _g = policy_lock();
    mlpolicy::set_active(live_policy(MlAction::Block, true));

    // "not classified yet" is denyUnclassified's business (read_path_reply), not
    // this function's — it must not smuggle a denial in here.
    assert!(!ml_blocks_read(Some(&MlResult::skipped("V6.2.01", "not_classified"))));
    assert!(!ml_blocks_read(Some(&MlResult::empty("V6.2.01"))));
    assert!(!ml_blocks_read(None));
}
