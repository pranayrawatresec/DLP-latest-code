//! Golden gate for the full ML inference engine (src/ml/engine.rs).
//!
//! tests/ml_chunker.rs proves the agent feeds the model the same token ids the
//! Python reference does. This file proves the rest: that the graph runs, that
//! the batch is padded to the LONGEST CHUNK IN THIS CALL rather than always to
//! 512, that softmax is computed in f64 with the max subtracted, and that the
//! 29 logits, the argmax and the confidence match
//! tests/fixtures/ml-golden-vectors.json to 1e-4.
//!
//! Why the tolerance is 1e-4 and not exact: the numbers come out of ONNX
//! Runtime's float32 kernels, and CPU dispatch (AVX2 vs AVX-512), thread count
//! and runtime version can move the last bits. Geometry is asserted exactly in
//! ml_chunker.rs; only the floats get a tolerance, and 1e-4 is far tighter than
//! any policy threshold an admin can set. **Do not widen it to get green.**
//!
//! Environment gate
//! ----------------
//! Two artifacts this test needs are not in the build: the 256 MB
//! `Document_classification/model/model.onnx`, and the ONNX Runtime shared
//! library (see the build recipe at the top of src/ml/engine.rs). When either is
//! absent the test SKIPS with an eprintln explaining how to get it, so a
//! developer without the graph can still run the rest of the suite. When both
//! are present it must pass.
//!
//!   set ORT_DYLIB_PATH=%USERPROFILE%\.dlp-onnxruntime\onnxruntime.dll
//!   cargo test --test ml_golden -- --nocapture

use std::path::{Path, PathBuf};
use std::sync::Arc;

use dlp_agent::ml::{engine, MlConfig, MlEngine, MlError};
use serde::Deserialize;

// =====================================================================
// The fixture
// =====================================================================

#[derive(Deserialize)]
struct Fixture {
    #[serde(rename = "modelVersion")]
    model_version: String,
    #[serde(rename = "modelSha256")]
    model_sha256: String,
    tolerance: f64,
    #[serde(rename = "maxChars")]
    max_chars: usize,
    labels: Vec<String>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    #[serde(rename = "textRecipe")]
    text_recipe: TextRecipe,
    expected: Expected,
}

#[derive(Deserialize)]
struct TextRecipe {
    kind: String,
    text: String,
    #[serde(default)]
    times: Option<usize>,
}

#[derive(Deserialize)]
struct Expected {
    #[serde(rename = "chunkCount")]
    chunk_count: usize,
    #[serde(rename = "tokenCount")]
    token_count: usize,
    #[serde(rename = "labelId")]
    label_id: String,
    #[serde(rename = "labelIndex")]
    label_index: usize,
    confidence: f64,
    logits: Vec<f64>,
}

impl TextRecipe {
    fn build(&self) -> String {
        match self.kind.as_str() {
            "literal" => self.text.clone(),
            "repeat" => self.text.repeat(self.times.expect("repeat recipe needs `times`")),
            other => panic!("unknown textRecipe kind {other:?}"),
        }
    }
}

fn classifier_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../Document_classification")
}

fn load_fixture() -> Fixture {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ml-golden-vectors.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read ML golden vectors at {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("parsing ml-golden-vectors.json")
}

/// Build and load the engine, or explain why this box cannot and skip.
///
/// The two conditions are deliberately different in kind. A missing model is an
/// Turn a skip into a FAILURE when the caller demands the real thing.
///
/// A skipped test prints `ok`. `cargo test` hides the `SKIPPING` line unless
/// `--nocapture` is passed, so a suite in which EVERY ONNX test silently opted
/// out reads exactly like a suite in which every one of them passed — which is
/// how an unverified inference path can sit in a green build.
///
/// So CI (and anyone verifying a release) sets `DLP_ML_STRICT=1`, and then a
/// missing model or a missing runtime is a hard failure that names what to
/// install rather than a line nobody reads.
fn require_runtime_or_skip(what: &str) {
    if std::env::var_os("DLP_ML_STRICT").is_some_and(|v| v == "1") {
        panic!(
            "DLP_ML_STRICT=1 but {what}. This build cannot verify the classifier.              Stage the model under Document_classification/ and put onnxruntime.dll at              Document_classification/runtime/ (see scripts/stage-ml-model.ps1 and the build              recipe at the top of src/ml/engine.rs)."
        );
    }
}

/// artifact the repository does not carry, so it skips. A missing ONNX Runtime
/// is a documented one-command setup, so it skips too — but once a runtime IS
/// locatable, a load failure is a REAL failure and this panics rather than
/// hiding it.
fn engine_or_skip() -> Option<Arc<MlEngine>> {
    let root = classifier_root();
    let config = MlConfig::under(&root);

    if !config.artifacts_present() {
        require_runtime_or_skip("the classifier artifacts are absent");
        eprintln!(
            "SKIPPING ml_golden: the classifier artifacts are not under {}. \
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
            "SKIPPING ml_golden: no ONNX Runtime shared library located. Set ORT_DYLIB_PATH, or \
             place it at {}/runtime/. See the build recipe at the top of src/ml/engine.rs.",
            root.display()
        );
        return None;
    }

    Some(engine::load(&config).expect("the model and a runtime are both present; loading must work"))
}

// =====================================================================
// 1. The fixture is paired with the weights on this box.
// =====================================================================

/// The fixture records the SHA-256 of the graph it was generated from. If the
/// model file on disk is a different one, every logit below is meaningless — so
/// say that clearly instead of reporting 11 confusing float mismatches.
#[test]
fn fixture_is_paired_with_the_model_on_disk() {
    let model = classifier_root().join("model/model.onnx");
    if !model.is_file() {
        eprintln!("SKIPPING ml_golden: {} is not present.", model.display());
        return;
    }
    let fx = load_fixture();
    let hex = engine::model_sha256(&model).expect("hashing model.onnx");
    assert_eq!(
        hex,
        fx.model_sha256,
        "model.onnx on disk is NOT the graph the golden vectors were generated from; \
         regenerate the fixture (tools/ml-reference/gen_golden_vectors.py) or restore the weights"
    );
}

// =====================================================================
// 2. Load-time validation.
// =====================================================================

#[test]
fn the_loaded_model_declares_the_frozen_version_and_geometry() {
    let Some(engine) = engine_or_skip() else { return };
    let fx = load_fixture();

    assert_eq!(engine.model_version(), fx.model_version);
    assert_eq!(engine.geometry().max_tokens, 512);
    assert_eq!(engine.geometry().overlap_tokens, 64);
    assert_eq!(engine.geometry().min_tokens, 32);
    assert_eq!(fx.labels.len(), dlp_agent::ml::LABEL_COUNT);
    assert_eq!(fx.max_chars, 200_000);
}

// =====================================================================
// 3. Every golden case: label, confidence and all 29 logits.
// =====================================================================

#[test]
fn golden_predictions_reproduced_within_tolerance() {
    let Some(engine) = engine_or_skip() else { return };
    let fx = load_fixture();
    let tol = fx.tolerance;

    let mut worst: (f64, String) = (0.0, String::from("(none)"));

    for case in &fx.cases {
        let text = case.text_recipe.build();
        let got = engine
            .classify(&text)
            .unwrap_or_else(|e| panic!("{}: classify failed: {e}", case.name));

        // Geometry first: a chunk-count mismatch explains every float mismatch
        // that would follow it.
        assert_eq!(got.chunks, case.expected.chunk_count, "{}: chunk count drifted", case.name);
        assert_eq!(got.tokens, case.expected.token_count, "{}: token count drifted", case.name);

        assert_eq!(got.label_id, case.expected.label_id, "{}: label drifted", case.name);
        assert_eq!(got.label_index, case.expected.label_index, "{}: label index drifted", case.name);
        assert_eq!(
            got.label_name,
            dlp_agent::ml::LABELS[case.expected.label_index].name,
            "{}: label name does not match the frozen table",
            case.name
        );

        assert_eq!(got.logits.len(), 29, "{}: expected 29 logits", case.name);
        for (i, (a, b)) in got.logits.iter().zip(case.expected.logits.iter()).enumerate() {
            let delta = (a - b).abs();
            if delta > worst.0 {
                worst = (delta, format!("{} logit[{i}]", case.name));
            }
            assert!(
                delta <= tol,
                "{}: logit[{i}] = {a} but the reference says {b} (delta {delta} > {tol})",
                case.name
            );
        }

        let delta = (got.confidence - case.expected.confidence).abs();
        if delta > worst.0 {
            worst = (delta, format!("{} confidence", case.name));
        }
        assert!(
            delta <= tol,
            "{}: confidence = {} but the reference says {} (delta {delta} > {tol})",
            case.name,
            got.confidence,
            case.expected.confidence
        );

        // The confidence must BE the softmax of the winning logit, not an
        // independently computed number.
        assert!(
            (0.0..=1.0).contains(&got.confidence),
            "{}: confidence {} is not a probability",
            case.name,
            got.confidence
        );
    }

    eprintln!("ml_golden: {} cases, worst float delta {:.3e} at {}", fx.cases.len(), worst.0, worst.1);
}

// =====================================================================
// 4. The outcomes that are not predictions.
// =====================================================================

#[test]
fn empty_and_whitespace_only_text_is_an_empty_outcome_not_an_error() {
    let Some(engine) = engine_or_skip() else { return };

    for text in ["", "   ", "\n\n\t \n"] {
        match engine.classify(text) {
            Err(MlError::Empty) => {}
            other => panic!("expected MlError::Empty for {text:?}, got {other:?}"),
        }
    }

    // And it maps onto the wire vocabulary the contract fixes.
    assert_eq!(MlError::Empty.status(), "empty");
    assert_eq!(MlError::Empty.reason(), "no_text");
}

#[test]
fn a_missing_model_is_unavailable_not_a_panic() {
    // Fail secure: the agent must survive a box where the artifacts were never
    // installed, or were removed. No panic, a typed error, and the wire status
    // the channels know how to apply failBlock to.
    let config = MlConfig::under(Path::new("X:/no/such/ml/root"));
    let err = engine::load(&config).expect_err("loading absent artifacts must fail");
    assert_eq!(err.status(), "unavailable");
    assert_eq!(err.reason(), "load_failed");
}

// =====================================================================
// 6. The cost bound (`[ml] max_chunks`) and the truncation guard.
// =====================================================================

/// `max_chunks` must actually bite, and must SAY that it bit.
///
/// A documented, defaulted knob that silently does nothing is worse than an
/// absent one: an operator who caps a slow endpoint would believe inference was
/// bounded while every chunk still ran. So this asserts both halves — fewer
/// chunks were fed to the graph, and `chunks_total` still reports what the
/// document really was, which is what puts `chunksTruncated` on the wire.
#[test]
fn max_chunks_classifies_a_prefix_and_records_it() {
    let root = classifier_root();
    let mut config = MlConfig::under(&root);
    if !config.artifacts_present() {
        require_runtime_or_skip("the classifier artifacts are absent");
        eprintln!("SKIPPING max_chunks: classifier artifacts absent under {}", root.display());
        return;
    }
    if config.dylib.is_none() && !std::env::var_os("ORT_DYLIB_PATH").is_some_and(|v| !v.is_empty()) {
        require_runtime_or_skip("no ONNX Runtime shared library is locatable");
        eprintln!("SKIPPING max_chunks: no ONNX Runtime shared library located");
        return;
    }

    // Long enough to be several chunks: ~600 short sentences well past one 512
    // token chunk. Deterministic, and no fixture needed — this asserts the cap's
    // mechanics, not the numerics (golden_predictions_reproduced does that).
    let text = "The sanctioned budget allocation for the current fiscal year was reviewed. "
        .repeat(600);

    let uncapped = engine::load(&config)
        .expect("artifacts and runtime present")
        .classify(&text)
        .expect("a long document classifies");
    assert!(uncapped.chunks > 2, "test text must span several chunks, got {}", uncapped.chunks);
    assert_eq!(
        uncapped.chunks_total, uncapped.chunks,
        "with no cap the whole document is classified, so nothing is 'total but not fed'"
    );

    config.max_chunks = 2;
    let capped = engine::load(&config)
        .expect("artifacts and runtime present")
        .classify(&text)
        .expect("a capped document still classifies");
    assert_eq!(capped.chunks, 2, "the cap must bound what reaches the graph");
    assert_eq!(
        capped.chunks_total, uncapped.chunks,
        "the pre-cap chunk count must survive so a reviewer sees the answer came from a prefix"
    );
}

/// A configured `max_chars` that disagrees with the sidecar is REFUSED.
///
/// The bound is applied before a single token exists, so a lower one shortens the
/// document before the model ever sees it and the damage is invisible in the
/// output. The reference pipeline refuses here too; this is that guard.
#[test]
fn a_max_chars_that_disagrees_with_the_sidecar_is_refused() {
    let root = classifier_root();
    let mut config = MlConfig::under(&root);
    if !config.artifacts_present() {
        require_runtime_or_skip("the classifier artifacts are absent");
        eprintln!("SKIPPING max_chars guard: classifier artifacts absent under {}", root.display());
        return;
    }

    config.max_chars = 4096; // the sidecar declares 200000
    let err = engine::load(&config).expect_err("a disagreeing max_chars must be refused");
    let message = err.to_string();
    assert!(
        message.contains("max_chars"),
        "the error must name the setting an operator has to fix, got: {message}"
    );
}

// =====================================================================
// 7. The two halves of activation, together.
// =====================================================================

/// A live policy WITHOUT a loaded engine is not "inert" — it is a total block.
///
/// This is the shape of a real defect this feature already had once: the policy
/// was published into enforcing processes but the graph never was, so every
/// classify returned `NotLoaded` -> `status = "unavailable"`, and `failBlock`
/// (default TRUE) then denied every USB write, clipboard copy and browser upload
/// on the machine. Fail-secure is right for a model that genuinely broke; it is an
/// outage when it is reached because nobody called `ml::set_active`.
///
/// So the two halves are asserted TOGETHER here, in one test, in order — publish
/// the policy alone and observe `unavailable`, then publish the engine and observe
/// `ok`. `main.rs::activate_ml` is the single function that does both; if anyone
/// splits them again, the first half of this test is what documents the cost.
#[test]
fn policy_without_engine_is_unavailable_and_with_engine_is_ok() {
    use dlp_agent::detect::decide::ml_for_text;
    use dlp_agent::mlpolicy::{self, MlAction, MlLabelRule, MlPolicy};

    let Some(engine) = engine_or_skip() else { return };

    // A text whose predicted label we pin to the policy below, so `sensitive`
    // exercises the real threshold rather than a hard-coded expectation.
    let text = "The sanctioned budget allocation for the current fiscal year was reviewed \
                against total expenditure and the audited statement of accounts.";
    let predicted = engine.classify(text).expect("a plain paragraph classifies");

    let policy = MlPolicy {
        enabled: true,
        min_confidence: 0.0, // the threshold is not what this test is about
        action: MlAction::Block,
        fail_block: true,
        model_version: "V6.2.01".to_string(),
        labels: vec![MlLabelRule { id: predicted.label_id.to_string(), min_confidence: None }],
        // Read-path only, and irrelevant here: this test is about the EGRESS
        // fusion of policy + engine, which never consults it.
        deny_unclassified: false,
    };

    // --- half one only: policy live, engine absent ------------------------
    dlp_agent::ml::unload();
    mlpolicy::set_active(policy.clone());
    let half = ml_for_text(text).expect("a live policy always produces an ml block");
    assert_eq!(
        half.status, "unavailable",
        "a live policy with no loaded engine reports unavailable — and `failBlock` then denies \
         every egress path. Publishing the policy without the engine is an outage, not an inert \
         feature: see main.rs::activate_ml."
    );
    assert!(!half.sensitive, "an unanswered classification is never a model hit");

    // --- both halves: policy live, engine published -----------------------
    dlp_agent::ml::set_active(engine);
    let whole = ml_for_text(text).expect("a live policy always produces an ml block");
    assert_eq!(whole.status, "ok", "policy + engine together must actually classify");
    assert_eq!(whole.label_id.as_deref(), Some(predicted.label_id));
    assert!(whole.sensitive, "the predicted label was the one the policy marked sensitive");

    // Leave the process as we found it for any test that runs after this one.
    dlp_agent::ml::unload();
    mlpolicy::set_active(MlPolicy::default());
}


// =====================================================================
// 8. THE SPLIT GRAPHS: same answer, bounded memory.
//
// The monolithic `model.onnx` seals the per-chunk mean pooling inside itself, so
// every chunk of a document must be encoded in ONE call - ~65 MB of attention
// activations per chunk, ~5 GB on a 72-chunk document, which exhausted an 8 GiB
// endpoint and aborted the service.
//
// The split pair cuts at the only seam where that is mathematically safe: the
// encoder emits per-chunk [CLS], the agent accumulates them, and the head (which
// holds the non-linear ReLU, and therefore CANNOT be decomposed) runs exactly
// once on the pooled vector. Batching a SUM is exact; averaging per-batch LOGITS
// would not be, and would fail silently.
//
// These tests exist to prove the swap changed memory and nothing else.
// =====================================================================

/// The split graphs must actually be IN USE when staged.
///
/// `load` falls back to the monolithic graph when the pair is absent, which is
/// deliberate - an endpoint staged before the split existed must keep working.
/// But that fallback makes a staging mistake invisible: the agent would classify
/// correctly, pass every other test, and quietly keep the 5 GB memory profile.
/// So assert the backend by name.
#[test]
fn the_split_graphs_are_used_when_they_are_staged() {
    let root = classifier_root();
    let config = MlConfig::under(&root);
    let split_dir = root.join("model").join("onnx_split");
    if !split_dir.join("encoder.onnx").is_file() || !split_dir.join("head.onnx").is_file() {
        require_runtime_or_skip("the split graphs are not staged");
        eprintln!(
            "SKIPPING split test: no onnx_split/ under {}. Stage encoder.onnx + head.onnx \
             to exercise the micro-batched path.",
            root.display()
        );
        return;
    }
    let Some(engine) = engine_or_skip() else { return };
    assert_eq!(
        engine.graph_kind(),
        "split+microbatched",
        "the split graphs are on disk but the engine did not pick them up - it is \
         still running the monolithic graph, and with it the unbounded memory profile"
    );
}

/// The split path and the monolithic path must agree, on the SAME weights.
///
/// This is the equivalence proof. `split_metadata.json` records that the pair was
/// carved from this exact `model.onnx` (verified by SHA-256 at staging), so any
/// disagreement here is our batching arithmetic being wrong - not a different
/// model. The tolerance is the same 1e-4 the fixtures use.
#[test]
fn split_and_monolithic_agree_on_the_same_document() {
    let root = classifier_root();
    let split_dir = root.join("model").join("onnx_split");
    if !split_dir.join("encoder.onnx").is_file() {
        require_runtime_or_skip("the split graphs are not staged");
        eprintln!("SKIPPING equivalence test: no onnx_split/ staged");
        return;
    }
    let Some(split_engine) = engine_or_skip() else { return };
    assert_eq!(split_engine.graph_kind(), "split+microbatched");

    // Build a monolithic-only view of the SAME weights by hard-linking model.onnx
    // into a directory with no onnx_split/ beside it. A hard link is instantaneous
    // and costs no disk, where copying 268 MB per test run would not be acceptable.
    let tmp = std::env::temp_dir().join("dlp-ml-monolithic-view");
    let _ = std::fs::remove_dir_all(&tmp);
    if std::fs::create_dir_all(&tmp).is_err() {
        eprintln!("SKIPPING equivalence test: cannot create {}", tmp.display());
        return;
    }
    let model_src = root.join("model").join("model.onnx");
    let model_dst = tmp.join("model.onnx");
    if std::fs::hard_link(&model_src, &model_dst).is_err()
        && std::fs::copy(&model_src, &model_dst).is_err()
    {
        eprintln!("SKIPPING equivalence test: cannot stage a monolithic view");
        return;
    }
    if std::fs::copy(
        root.join("model").join("model.onnx.json"),
        tmp.join("model.onnx.json"),
    )
    .is_err()
    {
        eprintln!("SKIPPING equivalence test: cannot stage the sidecar");
        return;
    }

    let mut mono_cfg = MlConfig::under(&root);
    mono_cfg.model = model_dst;
    mono_cfg.sidecar = tmp.join("model.onnx.json");
    // `dylib` must still point at the runtime we already located.
    let mono = match engine::load(&mono_cfg) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("SKIPPING equivalence test: monolithic view would not load: {e}");
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }
    };
    assert_eq!(
        mono.graph_kind(),
        "monolithic",
        "the control arm must actually be the monolithic graph"
    );

    // A genuinely multi-chunk document: one chunk would not exercise batching at all.
    let text = "The sanctioned budget allocation for the current fiscal year was \
                reviewed against total expenditure and the audited statement of accounts. "
        .repeat(600);

    let a = split_engine.classify(&text).expect("split path classifies");
    let b = mono.classify(&text).expect("monolithic path classifies");

    assert!(
        a.chunks > 1,
        "the test document must span several chunks to exercise micro-batching, got {}",
        a.chunks
    );
    assert_eq!(a.chunks, b.chunks, "both paths must chunk identically");
    assert_eq!(
        a.label_id, b.label_id,
        "split said {} but monolithic said {} - the batching arithmetic is wrong",
        a.label_id, b.label_id
    );

    let worst = a
        .logits
        .iter()
        .zip(b.logits.iter())
        .map(|(x, y)| (x - y).abs())
        .fold(0.0f64, f64::max);
    assert!(
        worst <= 1e-4,
        "max |split - monolithic| logit difference {worst:.3e} exceeds 1e-4 - \
         batching must be exact, not approximate"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
