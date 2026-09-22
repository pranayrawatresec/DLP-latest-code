//! END-TO-END GATE for the at-rest / at-creation / on-demand ML pipeline, run
//! against the REAL ONNX engine and the REAL on-disk verdict cache.
//!
//! WHY THIS BINARY EXISTS, AND WHY IT IS SEPARATE FROM `tests/ml_readpath.rs`
//! ------------------------------------------------------------------------
//! `ml_readpath.rs` proves the read-path RULES with hand-seeded cache entries and
//! no engine at all. That is the right way to gate rules — it is fast, it is
//! deterministic, and it can assert "no inference happened" absolutely. But it
//! can also stay green while the feature is entirely broken in the field, because
//! everything it asserts is downstream of two things it never exercises:
//!
//!   * that a real inference result, produced by the background worker, actually
//!     lands in the cache under the key the read path will later compute; and
//!   * that the key an OFF-PATH producer mints from a file on disk is the SAME
//!     key the read path mints from the ≤4 MiB prefix the driver ships up.
//!
//! The second is the bug the whole feature dies on and dies QUIETLY: hash a whole
//! 9 MB PDF in the walker and the cache fills up, reports healthy stats, and hits
//! zero times for ever. Nothing in a rules test can see that. So this file wires
//! the actual pieces together — engine → queue worker → `VerdictCache` on disk →
//! `decide::read_path_ml` — and asserts the properties the contract says the
//! product depends on:
//!
//!   (a) ON-DEMAND SELF-HEAL   miss → enqueue → real classification → hit.
//!   (b) KEY EQUIVALENCE       `cache::read_prefix_for_hashing` (walker/watcher)
//!                             == `VerdictCache::key_for` (read path) for a file
//!                             LARGER than the driver's cap.
//!   (c) POLICY AT LOOKUP      a console change flips an already-cached file with
//!                             ZERO reclassification (worker counter unchanged).
//!   (d) FAIL-SECURE           a miss is never "clean": `denyUnclassified` on ⇒
//!                             NOVERDICT (`None`), off ⇒ today's fingerprint-only
//!                             answer.
//!   (e) INERT                 an inert policy is byte-identical to an agent with
//!                             no pipeline at all (invariant F3).
//!
//! ENVIRONMENT GATE — read this before trusting a green run
//! --------------------------------------------------------
//! The 256 MB `Document_classification/model/model.onnx` and the ONNX Runtime
//! shared library are not carried in the build, so the engine-dependent tests
//! SKIP when either is absent — and a skipped test prints `ok`. `DLP_ML_STRICT=1`
//! turns that skip into a hard failure that names what to install, exactly as
//! `tests/ml_golden.rs` does, so a release is never verified by a suite that
//! silently opted out of every test that touches the model.
//!
//!   set ORT_DYLIB_PATH=%USERPROFILE%\.dlp-onnxruntime\onnxruntime.dll
//!   cargo test --test ml_pipeline_e2e -- --nocapture
//!
//! PROCESS-WIDE STATE: the engine, the ML policy, the `denyUnclassified` flag,
//! the cache handle and the worker are all process-wide singletons and cargo runs
//! these tests on many threads in ONE process. Every test that touches any of
//! them holds `ENV_LOCK` for its whole body and restores the shipped inert
//! defaults on the way out.
//!
//! Never log or assert on document TEXT here — labels, scores and counts only,
//! the same rule the rest of `ml/` obeys.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use dlp_agent::detect::decide::{
    self, deny_unclassified, ml_from_cache, ml_read_path_skip, read_path_ml, read_path_reply,
    CacheOutcome,
};
use dlp_agent::detect::{decide as fuse, Bands, Extraction, IdmMatch, Verdict};
use dlp_agent::ml::cache::{read_prefix_for_hashing, VerdictCache, MAX_HASHED_BYTES};
use dlp_agent::ml::{engine, queue, MlConfig, MlEngine};
use dlp_agent::mlpolicy::{self, MlLabelRule, MlPolicy};

/// The kguard read-deny band (`block_at` 0.30 / `coverage_block_at` 0.60), the
/// same numbers `tests/ml_readpath.rs` fuses against.
fn read_bands() -> Bands {
    Bands::new(0.30, 0.60)
}

/// How long a single background classification may take before this test calls
/// it a failure. The model card's worst case is ~640 ms at eight chunks; the
/// documents here are one or two chunks. Generous by two orders of magnitude so
/// a loaded CI box cannot flake, but still BOUNDED — never a bare sleep.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(60);

// ==========================================================================
// Harness
// ==========================================================================

fn env_lock() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

fn classifier_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../Document_classification")
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "dlp-ml-e2e-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Turn a skip into a FAILURE when the caller demands the real thing.
///
/// `cargo test` hides an `eprintln` unless `--nocapture` is passed, so a suite in
/// which every ONNX test opted out reads exactly like a suite in which every one
/// of them passed. CI sets `DLP_ML_STRICT=1` and then a missing artifact is a
/// hard failure naming what to install. Same contract, same variable, same
/// wording as `tests/ml_golden.rs` — deliberately, so there is one switch.
fn require_runtime_or_skip(what: &str) {
    if std::env::var_os("DLP_ML_STRICT").is_some_and(|v| v == "1") {
        panic!(
            "DLP_ML_STRICT=1 but {what}. This build cannot verify the ML classification \
             pipeline end to end. Stage the model under Document_classification/ and put \
             onnxruntime.dll at Document_classification/runtime/ (see scripts/stage-ml-model.ps1 \
             and the build recipe at the top of src/ml/engine.rs)."
        );
    }
}

/// Load the engine ONCE for this binary and publish it as the process's active
/// one, or explain why this box cannot and skip.
///
/// Loading costs hundreds of milliseconds and ~300 MB resident, and the worker
/// resolves the engine through `engine::active()`, so a single shared load is
/// both the cheap and the faithful arrangement: it is exactly what
/// `main.rs::activate_ml` does on an endpoint.
fn engine_or_skip() -> Option<Arc<MlEngine>> {
    static ENGINE: OnceLock<Option<Arc<MlEngine>>> = OnceLock::new();
    ENGINE
        .get_or_init(|| {
            let root = classifier_root();
            let config = MlConfig::under(&root);

            if !config.artifacts_present() {
                require_runtime_or_skip("the classifier artifacts are absent");
                eprintln!(
                    "SKIPPING ml_pipeline_e2e: the classifier artifacts are not under {}. \
                     The 256 MB model/model.onnx is not carried in the build.",
                    root.display()
                );
                return None;
            }
            let has_runtime = config.dylib.is_some()
                || std::env::var_os("ORT_DYLIB_PATH").is_some_and(|v| !v.is_empty());
            if !has_runtime {
                require_runtime_or_skip("no ONNX Runtime shared library is locatable");
                eprintln!(
                    "SKIPPING ml_pipeline_e2e: no ONNX Runtime shared library located. Set \
                     ORT_DYLIB_PATH, or place it at {}/runtime/.",
                    root.display()
                );
                return None;
            }

            let engine = engine::load(&config)
                .expect("the model and a runtime are both present; loading must work");
            engine::set_active(engine.clone());
            Some(engine)
        })
        .clone()
}

/// Put the process back into the shipped, fully-inert state. The ENGINE stays
/// loaded on purpose (it is expensive and it is not policy): inertness is a
/// property of the POLICY, and proving that an inert policy changes nothing
/// *while a working engine sits right there* is a strictly stronger claim.
fn reset_env() {
    queue::stop_worker();
    queue::set_verdict_cache(None);
    decide::set_deny_unclassified(false);
    mlpolicy::set_active(MlPolicy::default());
}

/// A live policy selecting `labels`, with the shipped 0.70 floor.
fn live_policy(labels: &[&str]) -> MlPolicy {
    MlPolicy {
        enabled: true,
        min_confidence: 0.70,
        labels: labels
            .iter()
            .map(|id| MlLabelRule {
                id: (*id).to_string(),
                // 0.0 so the assertion is about the LABEL selection, not about
                // whether this particular document cleared a floor. Confidence
                // thresholds are already table-tested in ml_readpath.rs.
                min_confidence: Some(0.0),
            })
            .collect(),
        ..MlPolicy::default()
    }
}

/// Open a real on-disk cache in a fresh directory and start the real background
/// worker on it — the whole production wiring, minus the driver.
fn start_pipeline(tag: &str) -> Arc<VerdictCache> {
    let cache = queue::open_and_start(&temp_dir(tag), 1024, 16, None)
        .expect("opening the verdict cache and starting the worker");
    assert!(queue::running(), "the background classifier must be running");
    cache
}

/// A verdict shaped exactly as `kguard::decide` builds one before it attaches
/// `ml`. `containment`/`coverage` are the fingerprint half.
fn verdict_with_idm(containment: f64, coverage: f64) -> Verdict {
    let mut v = Verdict {
        file_name: "plan.docx".into(),
        file_sha256: "sha".into(),
        extraction: Extraction::Ok { format: "docx".into() },
        idm: Vec::new(),
        edm: Vec::new(),
        ml: None,
    };
    if containment > 0.0 || coverage > 0.0 {
        v.idm.push(IdmMatch {
            version_id: "v1".into(),
            document_id: "d1".into(),
            collection_id: "c1".into(),
            title: "OPORD".into(),
            containment,
            coverage,
            matched_count: 1,
            total_count: 1,
            matched_hashes: vec!["1".into()],
        });
    }
    v
}

/// A document with enough real prose to tokenize into a stable classification.
/// `tag` keeps every test's bytes distinct so no test can accidentally hit an
/// entry another test deposited.
fn document(tag: &str) -> Vec<u8> {
    format!(
        "Reactor Core Safety Assessment — Fuel Assembly Integrity Review ({tag})\n\n\
         This assessment records the periodic evaluation of fuel assembly integrity for the \
         pressurised water reactor at the naval propulsion test facility. Coolant loop pressure, \
         primary circuit temperature margins and neutron flux distribution were measured across \
         three consecutive fuel cycles. Cladding oxidation was within the acceptance envelope \
         for all sampled assemblies. Control rod drive mechanism response times remained inside \
         the qualified band. The criticality safety analysis was re-run against the revised \
         burnup credit method, and the shielding survey of the primary containment boundary \
         confirmed dose rates below the administrative limit. Reactor protection system \
         channel trip setpoints were verified against the technical specification, and the \
         emergency core cooling injection path was proved by full-flow test. Spent fuel pool \
         boron concentration and decay heat removal capacity were both re-baselined for the \
         next operating cycle.\n"
    )
    .into_bytes()
}

/// Any label the model did NOT predict, so a "policy selects something else"
/// phase is genuinely a non-selection rather than an accident.
fn a_different_label(than: &str) -> &'static str {
    dlp_agent::ml::LABELS
        .iter()
        .map(|l| l.id)
        .find(|id| !id.eq_ignore_ascii_case(than))
        .expect("the taxonomy has more than one label")
}

// ==========================================================================
// (a) ON-DEMAND SELF-HEAL — miss, enqueue, real inference, hit
// ==========================================================================

/// The guarantee the whole feature exists to provide: a document nobody
/// registered and nothing pre-scanned is UNKNOWN on its first read and KNOWN on
/// its next one, with no file re-open (the driver already handed us the bytes)
/// and no inference on the message loop.
///
/// The expected label is not hard-coded. It is taken from a direct
/// `engine.classify()` — the ground truth for these exact bytes — and the cached
/// answer is asserted to reproduce it field for field. That way the test gates
/// "the pipeline carried the model's answer through intact", which is the claim,
/// rather than "the model still says NUC", which is `ml_golden.rs`'s job.
#[test]
fn on_demand_self_heal_miss_then_hit() {
    let _g = env_lock();
    let Some(engine) = engine_or_skip() else { return };
    reset_env();
    let cache = start_pipeline("selfheal");

    let content = document("selfheal");
    let key = VerdictCache::key_for(&content);

    // Ground truth for these bytes, straight from the graph.
    let text = String::from_utf8(content.clone()).unwrap();
    let truth = engine.classify(&text).expect("the document must classify");
    mlpolicy::set_active(live_policy(&[truth.label_id]));

    // --- first read: MISS. Not "clean" — explicitly unclassified.
    assert_eq!(
        ml_from_cache(&content, "assessment.txt"),
        CacheOutcome::Miss,
        "a document nothing has scanned must be a MISS, never a clean answer"
    );
    let (ml, miss) = read_path_ml(&content, "assessment.txt");
    assert!(miss, "the first read of unknown bytes is a cache miss");
    let ml = ml.expect("a live policy always attaches an ml field");
    assert_eq!(ml.status, "skipped");
    assert_eq!(ml.reason.as_deref(), Some("not_classified"));
    assert!(!ml.sensitive, "an unclassified read must never claim sensitivity");
    assert_eq!(cache.len(), 0, "a miss writes nothing by itself");

    // --- the worker heals it. Bounded wait on the queue's own drain signal.
    assert!(
        queue::drain_for_test(DRAIN_TIMEOUT),
        "the background classifier did not drain within {DRAIN_TIMEOUT:?}"
    );
    let stats = queue::stats();
    assert_eq!(stats.queued, 1, "the read path enqueued exactly one job");
    assert_eq!(stats.classified, 1, "the worker classified it");
    assert_eq!(stats.failed, 0, "no classification may fail here");
    assert_eq!(stats.dropped, 0);
    assert_eq!(cache.len(), 1, "a successful classification writes exactly one entry");

    // --- second read: HIT, and it is the MODEL's answer, intact.
    let (ml, miss) = read_path_ml(&content, "assessment.txt");
    assert!(!miss, "the second read of the same bytes must HIT");
    let ml = ml.expect("a live policy always attaches an ml field");
    assert_eq!(ml.status, "ok", "a hit is an answer, not a skip");
    assert_eq!(ml.reason, None, "an answer carries no `why not`");
    assert_eq!(ml.label_id.as_deref(), Some(truth.label_id));
    assert_eq!(ml.label_name.as_deref(), Some(truth.label_name));
    assert_eq!(ml.model_version, engine.model_version());
    assert_eq!(ml.chunks, truth.chunks);
    assert_eq!(ml.tokens, truth.tokens);
    assert!(
        (ml.confidence - truth.confidence).abs() < 1e-9,
        "the cache must round-trip the model's confidence exactly: {} vs {}",
        ml.confidence,
        truth.confidence
    );
    assert!(
        ml.sensitive,
        "the policy selects {}, so the hit must be sensitive",
        truth.label_id
    );

    // ...and the fusion acts on it. No fingerprint hit at all here, so the model
    // is the ONLY thing that can make this read sensitive — which is precisely
    // the gap (an unregistered document read by RustDesk) the feature closes.
    let mut v = verdict_with_idm(0.0, 0.0);
    v.ml = Some(ml);
    let d = fuse(&v, &read_bands());
    assert!(d.ml, "the ML half must fire");
    assert!(d.sensitive, "an unregistered but classified document is sensitive");
    assert!(!d.fingerprint, "no fingerprint was involved — that is the point");

    // The key the read path used is the key the entry lives under.
    assert!(
        cache.get(&key, engine.model_version()).is_some(),
        "the entry must be reachable under the read path's own key"
    );

    reset_env();
}

// ==========================================================================
// (b) CACHE-KEY EQUIVALENCE ACROSS TRIGGERS
// ==========================================================================

/// The silent killer: the walker/watcher hash a file from DISK, the read path
/// hashes the ≤4 MiB prefix the DRIVER shipped. If those two ever disagree the
/// cache fills, reports healthy stats, and hits zero times — for ever, with no
/// error anywhere.
///
/// Needs no engine: this is arithmetic over bytes, and it must be gated even on
/// a box that cannot run the model.
#[test]
fn cache_key_is_identical_across_every_trigger_even_past_the_drivers_cap() {
    let dir = temp_dir("keyeq");
    let path = dir.join("big.bin");

    // A file comfortably LARGER than DLP_MAX_CONTENT, with a distinguishable
    // tail so a whole-file hash cannot coincide with a prefix hash.
    let mut whole = Vec::with_capacity(MAX_HASHED_BYTES + 4096);
    let mut n: u64 = 0;
    while whole.len() < MAX_HASHED_BYTES + 4096 {
        whole.extend_from_slice(&n.to_le_bytes());
        n = n.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    }
    whole.truncate(MAX_HASHED_BYTES + 4096);
    std::fs::write(&path, &whole).unwrap();

    // The off-path producers' route: watcher and walker both go through this.
    let (prefix, truncated) = read_prefix_for_hashing(&path).expect("reading the hash prefix");
    assert_eq!(
        prefix.len(),
        MAX_HASHED_BYTES,
        "a producer must take EXACTLY the driver's cap, no more"
    );
    assert!(truncated, "a file past the cap must report itself truncated (C2 reporting)");

    // The read path's route: hash what the driver would have shipped up.
    let as_the_driver_ships = &whole[..MAX_HASHED_BYTES];
    assert_eq!(
        VerdictCache::key_for(&prefix),
        VerdictCache::key_for(as_the_driver_ships),
        "the producer's key and the read path's key MUST be the same key (contract C1)"
    );

    // And the mistake this exists to catch really would break it, so the
    // assertion above is load-bearing rather than trivially true.
    assert_ne!(
        VerdictCache::key_for(&whole),
        VerdictCache::key_for(as_the_driver_ships),
        "hashing the WHOLE file must mint a different key — that is the bug C1 forbids"
    );

    // A file at or under the cap is not truncated and hashes whole.
    let small = dir.join("small.bin");
    std::fs::write(&small, &whole[..1024]).unwrap();
    let (sp, st) = read_prefix_for_hashing(&small).unwrap();
    assert_eq!(sp.len(), 1024);
    assert!(!st, "a file inside the cap is not truncated");
    assert_eq!(VerdictCache::key_for(&sp), VerdictCache::key_for(&whole[..1024]));

    let _ = std::fs::remove_dir_all(&dir);
}

// ==========================================================================
// (c) POLICY CHANGE WITHOUT RECLASSIFICATION
// ==========================================================================

/// C2, proved against the real pipeline: the entry stores what the MODEL said,
/// so an admin marking a new label sensitive changes the answer for every
/// already-cached file on the estate on the NEXT READ — no reclassification, no
/// invalidation, no re-walk.
///
/// The proof that nothing reclassified is the worker's own `classified` counter,
/// which must be unchanged across the policy flip.
#[test]
fn a_policy_change_flips_a_cached_file_with_no_reclassification() {
    let _g = env_lock();
    let Some(engine) = engine_or_skip() else { return };
    reset_env();
    let _cache = start_pipeline("policyflip");

    let content = document("policyflip");
    let text = String::from_utf8(content.clone()).unwrap();
    let truth = engine.classify(&text).expect("the document must classify");
    let decoy = a_different_label(truth.label_id);

    // Phase 0 — get it into the cache the ordinary way.
    mlpolicy::set_active(live_policy(&[decoy]));
    let (_, miss) = read_path_ml(&content, "assessment.txt");
    assert!(miss);
    assert!(queue::drain_for_test(DRAIN_TIMEOUT), "the classifier did not drain");
    let classified_after_seed = queue::stats().classified;
    assert_eq!(classified_after_seed, 1);

    // Phase 1 — the admin has NOT selected the predicted label. Cached, hit,
    // answered, not sensitive.
    let before = read_path_ml(&content, "assessment.txt");
    assert!(!before.1, "must be a HIT");
    let before = before.0.expect("live policy attaches ml");
    assert_eq!(before.status, "ok");
    assert_eq!(before.label_id.as_deref(), Some(truth.label_id));
    assert!(
        !before.sensitive,
        "{} is not a selected label, so the hit is not sensitive",
        truth.label_id
    );

    // Phase 2 — the admin marks the predicted label sensitive. Nothing else
    // changes: same bytes, same entry, same model.
    mlpolicy::set_active(live_policy(&[truth.label_id]));
    let after = read_path_ml(&content, "assessment.txt");
    assert!(!after.1, "must still be a HIT");
    let after = after.0.expect("live policy attaches ml");
    assert_eq!(after.status, "ok");
    assert_eq!(after.label_id.as_deref(), Some(truth.label_id));
    assert_eq!(after.confidence, before.confidence, "the model's answer did not move");
    assert!(after.sensitive, "the console change must take effect on the next read");

    // THE claim: nothing was reclassified to make that happen.
    let stats = queue::stats();
    assert_eq!(
        stats.classified, classified_after_seed,
        "a policy change must reclassify NOTHING (contract C2)"
    );
    assert_eq!(stats.depth, 0, "a hit never enqueues");
    assert_eq!(stats.queued, 1, "only the original miss was ever queued");

    reset_env();
}

// ==========================================================================
// (d) FAIL-SECURE — a miss is never "not sensitive"
// ==========================================================================

/// F1/P2 against the real worker: with `denyUnclassified` OFF (the shipped, and
/// non-negotiable, default) a miss is exactly today's fingerprint-only answer;
/// with it ON the reply is `None` — `DLP_VERDICT_NOVERDICT`, which makes the
/// driver deny per `ExfilReadFailBlock` and cache NOTHING, so the retry after the
/// queue drains is authoritative.
///
/// The self-heal half matters as much as the deny half: a denial nothing can
/// ever clear is an outage, not a control.
#[test]
fn a_miss_is_never_clean_and_deny_unclassified_heals() {
    let _g = env_lock();
    let Some(engine) = engine_or_skip() else { return };
    reset_env();
    let _cache = start_pipeline("failsecure");

    let content = document("failsecure");
    let text = String::from_utf8(content.clone()).unwrap();
    let truth = engine.classify(&text).expect("the document must classify");
    mlpolicy::set_active(live_policy(&[truth.label_id]));

    // ---- flag OFF (the default): today's behaviour, byte for byte.
    assert!(!deny_unclassified(), "denyUnclassified must default to OFF");
    let clean = document("failsecure-off");
    let (ml, miss) = read_path_ml(&clean, "assessment.txt");
    assert!(miss);
    let ml = ml.expect("live policy attaches ml");
    assert_eq!(ml.status, "skipped");
    assert_eq!(ml.reason.as_deref(), Some("not_classified"));
    assert!(!ml.sensitive);
    // The fingerprint half is the whole decision, and it is passed through
    // unchanged in BOTH directions.
    assert_eq!(
        read_path_reply(false, miss, deny_unclassified()),
        Some(false),
        "flag off + fingerprint-clean ⇒ allow, exactly as before the cache existed"
    );
    assert_eq!(
        read_path_reply(true, miss, deny_unclassified()),
        Some(true),
        "flag off + fingerprint-block ⇒ block"
    );

    // ---- flag ON but this endpoint has NOT been swept: the LOCAL INTERLOCK holds.
    // `denyUnclassified` is one console switch over a whole fleet, while "has this
    // machine been classified yet" is a per-endpoint fact the console cannot know.
    // A laptop enrolled an hour ago has an almost empty cache; honouring the switch
    // there would deny the first read of nearly every document on it.
    decide::set_deny_unclassified(true);
    decide::set_sweep_completed(false);
    assert!(
        !deny_unclassified(),
        "the console switch must NOT arm an endpoint that has not completed a          discovery sweep"
    );
    let (_, miss_pre) = read_path_ml(&content, "assessment.txt");
    assert_eq!(
        read_path_reply(false, miss_pre, deny_unclassified()),
        Some(false),
        "un-swept endpoint keeps its previous behaviour — the interlock can only          ever make the feature less aggressive, never fail open"
    );

    // ---- flag ON and the sweep has completed: a miss becomes NOVERDICT.
    decide::set_sweep_completed(true);
    assert!(
        deny_unclassified(),
        "live policy + running worker + flag + completed sweep ⇒ the deny is armed"
    );
    let (ml, miss) = read_path_ml(&content, "assessment.txt");
    assert!(miss, "these bytes are not cached yet");
    assert_eq!(ml.expect("live policy attaches ml").status, "skipped");
    assert_eq!(
        read_path_reply(false, miss, deny_unclassified()),
        None,
        "an unknown document must reply NOVERDICT, not allow (contract P2/F1)"
    );
    // A BLOCK still wins over NOVERDICT: Some(true) lets the driver cache the
    // decision and seed its bad-hash list, which NOVERDICT deliberately does not.
    assert_eq!(
        read_path_reply(true, miss, deny_unclassified()),
        Some(true),
        "an already-decided block must not be downgraded to NOVERDICT"
    );

    // ---- and the denial HEALS: the retry after the worker runs is a real answer.
    assert!(queue::drain_for_test(DRAIN_TIMEOUT), "the classifier did not drain");
    let (ml, miss) = read_path_ml(&content, "assessment.txt");
    assert!(!miss, "the retry must hit");
    let ml = ml.expect("live policy attaches ml");
    assert_eq!(ml.status, "ok");
    assert!(ml.sensitive, "and it is the sensitive answer the deny was protecting");
    let mut v = verdict_with_idm(0.0, 0.0);
    v.ml = Some(ml);
    let block = fuse(&v, &read_bands()).sensitive;
    assert_eq!(
        read_path_reply(block, miss, deny_unclassified()),
        Some(true),
        "the retry is authoritative: a real block, with a real incident behind it"
    );

    // ---- the deny is GATED, not merely flagged. An inert policy disarms it even
    // with the flag still set, which is what makes the feature safe to ship on.
    mlpolicy::set_active(MlPolicy::default());
    assert!(
        !deny_unclassified(),
        "an inert policy can never deny a read, whatever the flag says"
    );
    // ...and so does a stopped worker: a denial nothing can clear is an outage.
    mlpolicy::set_active(live_policy(&[truth.label_id]));
    queue::stop_worker();
    assert!(
        !deny_unclassified(),
        "no background classifier ⇒ no deny, because the denial could never heal"
    );

    reset_env();
}

// ==========================================================================
// (e) INERT — invariant F3
// ==========================================================================

/// F3, the deployability property, asserted against the real pipeline with a
/// POPULATED cache and a LOADED engine sitting right there: an inert policy
/// produces a verdict byte-identical to one produced by an agent that has no
/// cache, no worker and no ML at all.
///
/// Byte-identical is asserted literally — the serialized JSON, which is what
/// reaches the management server, the incident record and the audit log.
#[test]
fn an_inert_policy_is_byte_identical_to_an_agent_with_no_pipeline() {
    let _g = env_lock();
    let Some(engine) = engine_or_skip() else { return };
    reset_env();

    let content = document("inert");

    // --- (1) The pre-pipeline agent: no cache, no worker, inert policy.
    assert!(MlPolicy::default().is_inert());
    assert!(queue::verdict_cache().is_none());
    assert!(!queue::running());
    let (ml_nopipeline, miss_nopipeline) = read_path_ml(&content, "assessment.txt");
    let mut v_nopipeline = verdict_with_idm(0.42, 0.0);
    v_nopipeline.ml = ml_nopipeline;
    let json_nopipeline = serde_json::to_string(&v_nopipeline).unwrap();
    let decision_nopipeline = fuse(&v_nopipeline, &read_bands());

    // --- (2) The full pipeline, with a cache that WOULD hit — so this proves
    // inertness BEATS a populated cache rather than coinciding with an empty one.
    let cache = start_pipeline("inert");
    mlpolicy::set_active(live_policy(&["OOD"])); // live, only to fill the cache
    let (_, miss) = read_path_ml(&content, "assessment.txt");
    assert!(miss);
    assert!(queue::drain_for_test(DRAIN_TIMEOUT), "the classifier did not drain");
    assert_eq!(cache.len(), 1, "the cache is populated for these exact bytes");
    assert!(
        cache
            .get(&VerdictCache::key_for(&content), engine.model_version())
            .is_some(),
        "and it would hit"
    );

    // Now the console turns ML off. Everything else stays exactly where it is:
    // engine loaded, worker running, entry present.
    mlpolicy::set_active(MlPolicy::default());
    decide::set_deny_unclassified(true); // even with the deny flag left on

    let (ml_inert, miss_inert) = read_path_ml(&content, "assessment.txt");
    assert!(ml_inert.is_none(), "an inert policy attaches no ml field at all");
    assert!(!miss_inert, "an inert policy never reports a cache miss");
    assert_eq!(
        ml_read_path_skip(),
        None,
        "and the pre-cache helper says the same thing"
    );
    assert_eq!(ml_from_cache(&content, "assessment.txt"), CacheOutcome::Inert);
    assert!(!deny_unclassified(), "inert beats the deny flag");

    let mut v_inert = verdict_with_idm(0.42, 0.0);
    v_inert.ml = ml_inert;
    let json_inert = serde_json::to_string(&v_inert).unwrap();

    // THE assertion: identical on the wire, and identical after fusion.
    assert_eq!(
        json_inert, json_nopipeline,
        "an inert policy must serialize byte-identically to a pre-pipeline agent (F3)"
    );
    assert!(
        !json_inert.contains("\"ml\""),
        "an inert verdict must be a pre-model verdict: {json_inert}"
    );
    assert_eq!(miss_inert, miss_nopipeline);
    assert_eq!(decision_nopipeline, fuse(&v_inert, &read_bands()));

    reset_env();
}
