//! Gate for the at-rest discovery walker (`src/ml/walk.rs`).
//!
//! The walker is the component `denyUnclassified` waits on: an operator is told
//! to enable that flag once a full sweep has completed, so every claim this
//! module makes has to be true or the fleet denies the first read of every
//! legacy file on every endpoint. The properties pinned here are the ones whose
//! failure is SILENT:
//!
//! * **Coverage.** Documents are enqueued; machinery (unsupported formats, temp
//!   artefacts, `node_modules`, the agent's own state directory) is not — and the
//!   skip is counted, not swallowed.
//! * **Idempotence.** A second sweep over an already-classified tree enqueues
//!   NOTHING. A walker that re-offers every file each pass would keep the queue
//!   permanently full, which drops the on-demand read-path work that actually
//!   matters.
//! * **The key.** What the walker enqueues must be keyed on the first ≤4 MiB of
//!   the file and nothing more (contract C1) — otherwise the cache fills, reports
//!   healthy stats, and the read path never hits it.
//! * **Resumability.** A cursor round-trips; a TRUNCATED cursor is discarded, not
//!   fatal — a walker that refuses to start because of a torn bookmark is a
//!   walker that never covers the estate.
//! * **The throttle.** The rate limiter actually limits. Asserted against an
//!   injected clock: no test in this file sleeps.
//! * **Inert means inert** (F3).
//!
//! NOTE ON THE FILTER CONFIG: these trees are built under the OS temp directory,
//! whose own path contains the excluded component `Temp`, so the fixture removes
//! the temp/cache names from the exclusion list. The real table is pinned by
//! `tests/ml_filter.rs`; what is exercised here is the walker's use of it
//! (`node_modules` pruning, the state-directory prefix, unsupported extensions).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use dlp_agent::ml::cache::{CacheKey, CachedVerdict, VerdictCache, MAX_HASHED_BYTES};
use dlp_agent::ml::walk::{
    load_checkpoint, load_completion, save_checkpoint, RateLimiter, StepStatus, WalkConfig,
    WalkCheckpoint, Walker, CHECKPOINT_FILE, CHECKPOINT_VERSION,
};
use dlp_agent::ml::watch::{ClassifyJob, ClassifySink, SweepFlags, WatchOutcome};
use dlp_agent::mlpolicy::{self, MlLabelRule, MlPolicy};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// The active ML policy is process-wide, so every test in this binary takes this
/// lock: one of them deliberately makes the policy inert, and a parallel test
/// that expected a live policy would fail for the wrong reason.
fn policy_guard() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

fn live_policy() {
    mlpolicy::set_active(MlPolicy {
        enabled: true,
        labels: vec![MlLabelRule {
            id: "FIN".to_string(),
            min_confidence: None,
        }],
        ..MlPolicy::default()
    });
}

fn model_version() -> String {
    mlpolicy::active().model_version
}

fn temp_root(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "dlp-ml-walk-{tag}-{}-{}",
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

fn write(root: &Path, rel: &str, bytes: &[u8]) -> PathBuf {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, bytes).unwrap();
    p
}

/// Walk config for a test tree. See the module note about the temp directory.
fn cfg(root: &Path, state: &Path) -> WalkConfig {
    let mut c = WalkConfig::new(state, vec![root.to_path_buf()]);
    c.files_per_minute = 0; // unlimited unless a test says otherwise
    c.filter
        .excluded_components
        .retain(|n| !matches!(n.as_str(), "temp" | "tmp" | "cache" | "caches"));
    c
}

/// A sink that records what it was handed and, optionally, deposits the verdict
/// into the cache the way the real background worker would — which is what makes
/// "a second sweep enqueues nothing" testable without a model.
struct RecordingSink {
    cache: Arc<VerdictCache>,
    deposit: bool,
    accept: bool,
    jobs: Mutex<Vec<(CacheKey, String, bool)>>,
}

impl RecordingSink {
    fn new(cache: Arc<VerdictCache>, deposit: bool) -> Arc<Self> {
        Arc::new(RecordingSink {
            cache,
            deposit,
            accept: true,
            jobs: Mutex::new(Vec::new()),
        })
    }

    fn names(&self) -> BTreeSet<String> {
        self.jobs
            .lock()
            .unwrap()
            .iter()
            .map(|(_, n, _)| n.clone())
            .collect()
    }

    fn len(&self) -> usize {
        self.jobs.lock().unwrap().len()
    }

    fn keys(&self) -> Vec<(CacheKey, String, bool)> {
        self.jobs.lock().unwrap().clone()
    }
}

impl ClassifySink for RecordingSink {
    fn submit(&self, job: ClassifyJob) -> bool {
        self.jobs
            .lock()
            .unwrap()
            .push((job.key, job.file_name, job.truncated));
        if self.deposit {
            let _ = self.cache.put(
                job.key,
                CachedVerdict {
                    model_version: model_version(),
                    label_id: "FIN".to_string(),
                    label_index: 3,
                    confidence: 0.87,
                    chunks: 1,
                    tokens: 120,
                    truncated: job.truncated,
                    classified_at: 1_700_000_000,
                },
            );
        }
        self.accept
    }
}

/// The standard tree: four documents, and one of every reason to be skipped.
fn build_tree(root: &Path, state: &Path) {
    write(root, "a.txt", b"alpha document about quarterly finance");
    write(root, "docs/b.md", b"# beta\nsome prose");
    write(root, "docs/notes.csv", b"col1,col2\n1,2\n");
    write(root, "docs/deep/nested/plan.json", b"{\"plan\":\"gamma\"}");

    // ...and the machinery, one per skip reason.
    write(root, "docs/image.png", b"\x89PNG not a document"); // unsupported extension
    write(root, "docs/~$b.md", b"owner file"); // temp artefact
    write(root, "docs/empty.txt", b""); // zero bytes
    write(root, "node_modules/pkg/index.js", b"module.exports = 1"); // pruned tree
    std::fs::create_dir_all(state).unwrap();
    write(state, "decoy.txt", b"the agent's own state: never classify this");
}

fn documents() -> BTreeSet<String> {
    ["a.txt", "b.md", "notes.csv", "plan.json"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Drive a sweep to completion with a monotonic fake clock.
fn drive(w: &Walker) -> StepStatus {
    let mut t = 0u64;
    w.drive(
        || {
            t += 10;
            t
        },
        5_000,
    )
}

// ===========================================================================
// Coverage
// ===========================================================================

#[test]
fn a_sweep_enqueues_the_documents_and_skips_the_machinery() {
    let _g = policy_guard();
    live_policy();
    let root = temp_root("coverage");
    let state = root.join("agent-state");
    build_tree(&root, &state);

    let cache = Arc::new(VerdictCache::open(&state, 1024).unwrap());
    let sink = RecordingSink::new(Arc::clone(&cache), false);
    let w = Walker::new(cfg(&root, &state), cache, sink.clone());

    w.begin_full_sweep();
    assert_eq!(drive(&w), StepStatus::Completed, "the sweep must finish");

    assert_eq!(
        sink.names(),
        documents(),
        "exactly the documents must reach the classifier"
    );
    let c = w.counts();
    assert_eq!(c.candidates, 4, "four files were looked at");
    assert_eq!(c.enqueued, 4);
    assert_eq!(c.already_known, 0);
    assert!(
        c.skipped >= 5,
        "png, ~$ artefact, empty file, node_modules and the state dir must be counted as skipped, got {}",
        c.skipped
    );
    assert_eq!(c.errors, 0, "nothing in this tree is unreadable");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_agents_own_state_directory_is_never_swept() {
    let _g = policy_guard();
    live_policy();
    let root = temp_root("selfexclude");
    let state = root.join("agent-state");
    build_tree(&root, &state);

    let cache = Arc::new(VerdictCache::open(&state, 1024).unwrap());
    let sink = RecordingSink::new(Arc::clone(&cache), false);
    let w = Walker::new(cfg(&root, &state), cache, sink.clone());
    w.begin_full_sweep();
    drive(&w);

    assert!(
        !sink.names().contains("decoy.txt"),
        "classifying the state directory is the livelock: put → write → notify → put"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// ===========================================================================
// Idempotence — the property that keeps the queue free for the read path
// ===========================================================================

#[test]
fn a_second_sweep_over_a_classified_tree_enqueues_nothing_new() {
    let _g = policy_guard();
    live_policy();
    let root = temp_root("second");
    let state = root.join("agent-state");
    build_tree(&root, &state);

    let cache = Arc::new(VerdictCache::open(&state, 1024).unwrap());
    // deposit = true: this sink stands in for the background worker.
    let sink = RecordingSink::new(Arc::clone(&cache), true);
    let w = Walker::new(cfg(&root, &state), Arc::clone(&cache), sink.clone());

    w.begin_full_sweep();
    assert_eq!(drive(&w), StepStatus::Completed);
    assert_eq!(sink.len(), 4, "first sweep classifies everything");

    // Second sweep, same tree, same cache.
    w.begin_full_sweep();
    assert_eq!(drive(&w), StepStatus::Completed);
    assert_eq!(
        sink.len(),
        4,
        "a second sweep must enqueue nothing — every key is already cached"
    );

    let c = w.counts();
    assert_eq!(c.candidates, 4);
    assert_eq!(c.already_known, 4, "all four must be recognised as known");
    assert_eq!(c.enqueued, 0);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_stale_model_version_makes_every_entry_a_miss_again() {
    let _g = policy_guard();
    live_policy();
    let root = temp_root("stale");
    let state = root.join("agent-state");
    write(&root, "a.txt", b"alpha");

    let cache = Arc::new(VerdictCache::open(&state, 1024).unwrap());
    // An entry written under ANOTHER model version (C3) is not coverage.
    let bytes = std::fs::read(root.join("a.txt")).unwrap();
    let key = VerdictCache::key_for(&bytes);
    cache
        .put(
            key,
            CachedVerdict {
                model_version: "V0.0.00-previous".to_string(),
                label_id: "FIN".to_string(),
                label_index: 3,
                confidence: 0.99,
                chunks: 1,
                tokens: 10,
                truncated: false,
                classified_at: 1,
            },
        )
        .unwrap();

    let sink = RecordingSink::new(Arc::clone(&cache), false);
    let w = Walker::new(cfg(&root, &state), cache, sink.clone());
    w.begin_full_sweep();
    drive(&w);

    assert_eq!(
        sink.len(),
        1,
        "a verdict from a superseded model must be re-classified, not trusted"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// ===========================================================================
// The key (contract C1)
// ===========================================================================

#[test]
fn the_enqueued_key_is_the_read_paths_key_even_for_a_big_file() {
    let _g = policy_guard();
    live_policy();
    let root = temp_root("key");
    let state = root.join("agent-state");

    // 5 MiB: longer than the prefix the driver ships.
    let mut big = vec![0u8; MAX_HASHED_BYTES + 1024 * 1024];
    for (i, b) in big.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    write(&root, "big.txt", &big);

    let cache = Arc::new(VerdictCache::open(&state, 1024).unwrap());
    let sink = RecordingSink::new(Arc::clone(&cache), false);
    let w = Walker::new(cfg(&root, &state), cache, sink.clone());
    w.begin_full_sweep();
    drive(&w);

    let jobs = sink.keys();
    assert_eq!(jobs.len(), 1);
    let (key, name, truncated) = &jobs[0];
    assert_eq!(name, "big.txt");
    assert!(truncated, "a file past the cap must be reported truncated");
    assert_eq!(
        *key,
        VerdictCache::key_for(&big[..MAX_HASHED_BYTES]),
        "the walker must key on the first 4 MiB — hashing the whole file yields a \
         key the read path can never produce, and the cache would never hit"
    );

    let _ = std::fs::remove_dir_all(&root);
}

// ===========================================================================
// Inert (F3)
// ===========================================================================

#[test]
fn an_inert_policy_makes_the_walker_do_nothing_at_all() {
    let _g = policy_guard();
    mlpolicy::set_active(MlPolicy::default()); // disabled ⇒ inert
    let root = temp_root("inert");
    let state = root.join("agent-state");
    build_tree(&root, &state);

    let cache = Arc::new(VerdictCache::open(&state, 1024).unwrap());
    let sink = RecordingSink::new(Arc::clone(&cache), false);
    let w = Walker::new(cfg(&root, &state), cache, sink.clone());

    w.begin_full_sweep();
    assert_eq!(w.step(0), StepStatus::Inert);
    assert_eq!(drive(&w), StepStatus::Inert);
    assert_eq!(sink.len(), 0, "an inert policy reads nothing");
    assert_eq!(w.counts().candidates, 0);
    assert!(
        load_completion(&state).is_none(),
        "an inert walker must not claim coverage"
    );

    live_policy();
    let _ = std::fs::remove_dir_all(&root);
}

// ===========================================================================
// Checkpointing
// ===========================================================================

fn sample_checkpoint(root: &Path) -> WalkCheckpoint {
    WalkCheckpoint {
        version: CHECKPOINT_VERSION,
        sweep_seq: 7,
        started_at: 1_700_000_000,
        full: true,
        model_version: model_version(),
        scopes_all: vec![root.to_path_buf()],
        scopes_pending: vec![],
        current_scope: Some(root.to_path_buf()),
        pending_dirs: vec![root.join("docs"), root.join("docs/deep")],
        spill: Default::default(),
        pending_truncated: false,
        last_dir: Some(root.join("docs")),
        counts: Default::default(),
    }
}

#[test]
fn a_checkpoint_round_trips() {
    let root = temp_root("cpround");
    let state = root.join("agent-state");
    std::fs::create_dir_all(&state).unwrap();

    let cp = sample_checkpoint(&root);
    save_checkpoint(&state, &cp).unwrap();
    assert_eq!(
        load_checkpoint(&state).expect("a saved checkpoint must load"),
        cp
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_truncated_checkpoint_is_discarded_rather_than_fatal() {
    let _g = policy_guard();
    live_policy();
    let root = temp_root("cptorn");
    let state = root.join("agent-state");
    build_tree(&root, &state);

    save_checkpoint(&state, &sample_checkpoint(&root)).unwrap();
    // Tear the file in half, the way an unclean shutdown would.
    let path = state.join(CHECKPOINT_FILE);
    let whole = std::fs::read(&path).unwrap();
    std::fs::write(&path, &whole[..whole.len() / 2]).unwrap();

    assert!(
        load_checkpoint(&state).is_none(),
        "a torn checkpoint must read as 'no checkpoint', not as an error"
    );

    // ...and the walker must still sweep the whole tree from the start.
    let cache = Arc::new(VerdictCache::open(&state, 1024).unwrap());
    let sink = RecordingSink::new(Arc::clone(&cache), false);
    let w = Walker::new(cfg(&root, &state), cache, sink.clone());
    w.begin_full_sweep();
    assert_eq!(
        w.stats().checkpoints_discarded.load(Ordering::Relaxed),
        1,
        "the discard must be COUNTED — a silently restarted sweep is a coverage lie"
    );
    assert_eq!(drive(&w), StepStatus::Completed);
    assert_eq!(sink.names(), documents());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_interrupted_sweep_resumes_from_its_checkpoint() {
    let _g = policy_guard();
    live_policy();
    let root = temp_root("resume");
    let state = root.join("agent-state");
    build_tree(&root, &state);

    let cache = Arc::new(VerdictCache::open(&state, 1024).unwrap());
    let sink1 = RecordingSink::new(Arc::clone(&cache), true);
    let w1 = Walker::new(cfg(&root, &state), Arc::clone(&cache), sink1.clone());
    w1.begin_full_sweep();

    // Stop part-way, the way a reboot would, and persist the cursor.
    let mut t = 0u64;
    for _ in 0..4 {
        t += 10;
        w1.step(t);
    }
    let done_before = sink1.len();
    assert!(done_before < 4, "the interruption must be a real one");
    assert!(w1.checkpoint_now(), "a clean stop persists the cursor");
    assert!(
        load_checkpoint(&state).is_some(),
        "the cursor must be on disk"
    );

    // A fresh process: same state directory, same cache.
    let sink2 = RecordingSink::new(Arc::clone(&cache), true);
    let w2 = Walker::new(cfg(&root, &state), cache, sink2.clone());
    w2.begin_full_sweep();
    assert_eq!(drive(&w2), StepStatus::Completed);

    let all: BTreeSet<String> = sink1.names().union(&sink2.names()).cloned().collect();
    assert_eq!(all, documents(), "the two halves must cover the whole tree");
    assert!(
        load_checkpoint(&state).is_none(),
        "a finished sweep leaves no cursor behind"
    );

    let _ = std::fs::remove_dir_all(&root);
}

// ===========================================================================
// Completion — the fact the denyUnclassified rollout is gated on
// ===========================================================================

#[test]
fn a_full_sweep_publishes_a_completion_record() {
    let _g = policy_guard();
    live_policy();
    let root = temp_root("completion");
    let state = root.join("agent-state");
    build_tree(&root, &state);

    let cache = Arc::new(VerdictCache::open(&state, 1024).unwrap());
    let sink = RecordingSink::new(Arc::clone(&cache), true);
    let w = Walker::new(cfg(&root, &state), cache, sink);
    w.begin_full_sweep();
    assert_eq!(drive(&w), StepStatus::Completed);

    let c = w.last_completion().expect("completion must be persisted");
    assert_eq!(c.files_covered(), 4, "covering N files");
    assert!(c.completed_at > 0, "completed at T");
    assert!(
        c.covers_model(&model_version()),
        "coverage is a claim about ONE model version"
    );
    assert!(
        !c.covers_model("V9.9.99-other"),
        "coverage under another model version is not coverage"
    );
    assert_eq!(w.stats().sweeps_completed.load(Ordering::Relaxed), 1);

    // The same record must be readable by anyone holding the state directory —
    // that is how the runbook and the health surface consume it.
    assert_eq!(load_completion(&state).unwrap(), c);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_scope_resweep_does_not_renew_the_estate_wide_claim() {
    let _g = policy_guard();
    live_policy();
    let root = temp_root("overflow");
    let state = root.join("agent-state");
    build_tree(&root, &state);

    let cache = Arc::new(VerdictCache::open(&state, 1024).unwrap());
    let sink = RecordingSink::new(Arc::clone(&cache), false);
    let flags = Arc::new(SweepFlags::new());
    let w = Walker::new(cfg(&root, &state), cache, sink.clone())
        .with_sweep_flags(Arc::clone(&flags));

    // The watcher lost notifications for this scope.
    flags.mark(&root.join("docs"));
    let flagged = w.take_flagged_scopes();
    assert_eq!(flagged, vec![root.join("docs")]);
    assert!(flags.is_empty(), "taking the flags must clear them");

    w.begin_scope_sweep(&flagged);
    assert_eq!(drive(&w), StepStatus::Completed);

    assert_eq!(
        sink.names(),
        ["b.md", "notes.csv", "plan.json"]
            .iter()
            .map(|s| s.to_string())
            .collect::<BTreeSet<String>>(),
        "only the flagged scope is re-swept"
    );
    assert!(
        load_completion(&state).is_none(),
        "a targeted re-sweep must not claim estate-wide coverage"
    );
    assert_eq!(w.stats().overflow_sweeps.load(Ordering::Relaxed), 1);

    let _ = std::fs::remove_dir_all(&root);
}

// ===========================================================================
// The throttle — injected clock, no sleeping
// ===========================================================================

#[test]
fn the_rate_limiter_actually_limits_the_sweep() {
    let _g = policy_guard();
    live_policy();
    let root = temp_root("rate");
    let state = root.join("agent-state");
    write(&root, "one.txt", b"first document");
    write(&root, "two.txt", b"second document");
    write(&root, "three.txt", b"third document");
    std::fs::create_dir_all(&state).unwrap();

    let mut c = cfg(&root, &state);
    c.files_per_minute = 60; // one per second...
    c.burst = 1; // ...and no burst to hide behind
    // This test isolates the FILE throttle; the directory-descent throttle has
    // its own dedicated test below and would otherwise eat into the same
    // one-token burst just to list `root`.
    c.dir_listing_cost = 0.0;
    let cache = Arc::new(VerdictCache::open(&state, 1024).unwrap());
    let sink = RecordingSink::new(Arc::clone(&cache), false);
    let w = Walker::new(c, cache, sink.clone());
    w.begin_full_sweep();

    // The clock is FROZEN at t=0: after the listing and one file, the budget is
    // spent and every further step must pause.
    let mut processed = 0usize;
    let mut paused = 0usize;
    for _ in 0..20 {
        match w.step(0) {
            StepStatus::Processed(_) => processed += 1,
            StepStatus::Paused { wait_ms } => {
                assert!(wait_ms > 0, "a pause must say how long to wait");
                paused += 1;
            }
            StepStatus::Descended => {}
            other => panic!("unexpected {other:?} while throttled"),
        }
    }
    assert_eq!(processed, 1, "one token, one file");
    assert!(paused > 10, "every later step must be throttled");
    assert_eq!(sink.len(), 1);
    assert!(w.stats().rate_limited.load(Ordering::Relaxed) >= 10);

    // Advance the injected clock by one second: exactly one more file.
    assert!(matches!(w.step(1_000), StepStatus::Processed(_)));
    assert!(matches!(w.step(1_000), StepStatus::Paused { .. }));
    assert_eq!(sink.len(), 2);

    // ...and with time enough for everything, the sweep completes.
    let mut t = 2_000u64;
    let last = w.drive(
        || {
            t += 1_000;
            t
        },
        200,
    );
    assert_eq!(last, StepStatus::Completed);
    assert_eq!(sink.len(), 3);

    let _ = std::fs::remove_dir_all(&root);
}

/// A re-sweep must not re-spend rate-limiter budget on files that turn out to
/// already be cached: the token was taken in `pick_next` before the outcome
/// was known, and `RateLimiter::refund` gives it back on `AlreadyClassified`.
/// Without the refund, this test's second sweep would need `rate_limited`
/// pauses (and a real clock) to get through four already-known files on a
/// one-token burst; with it, the frozen clock alone is enough.
#[test]
fn a_resweep_of_already_classified_files_costs_no_rate_limiter_budget() {
    let _g = policy_guard();
    live_policy();
    let root = temp_root("refund");
    let state = root.join("agent-state");
    build_tree(&root, &state);

    let cache = Arc::new(VerdictCache::open(&state, 1024).unwrap());
    let sink = RecordingSink::new(Arc::clone(&cache), true); // deposit
    let w = Walker::new(cfg(&root, &state), Arc::clone(&cache), sink.clone());
    w.begin_full_sweep();
    assert_eq!(drive(&w), StepStatus::Completed);
    assert_eq!(sink.len(), 4, "first sweep classifies and caches everything");

    // A SECOND sweep, tightly rate-limited and with the clock frozen at t=0:
    // if hits are truly free, every already-known file still gets through.
    let mut c = cfg(&root, &state);
    c.files_per_minute = 60;
    c.burst = 1;
    c.dir_listing_cost = 0.0; // isolate the file-token refund from dir descent
    let w2 = Walker::new(c, Arc::clone(&cache), sink.clone());
    w2.begin_full_sweep();

    let mut t = 0u64;
    let last = w2.drive(
        || {
            t += 1; // barely moves — refills essentially nothing
            t
        },
        5_000,
    );
    assert_eq!(last, StepStatus::Completed, "a frozen clock must still finish");
    let c2 = w2.counts();
    assert_eq!(c2.candidates, 4);
    assert_eq!(c2.already_known, 4, "every file must be recognised as known");
    assert_eq!(
        w2.stats().rate_limited.load(Ordering::Relaxed),
        0,
        "a cache hit must never draw down the rate limiter"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// Directory descent must cost something: before this throttle existed, a
/// subtree with no eligible file in it was free — no token, no pause — so the
/// walker could `read_dir` its way through an unbounded number of empty
/// directories at whatever rate the disk allowed. This builds a tree of nested
/// directories holding no documents at all and confirms listing them alone,
/// on a tight budget, produces throttled pauses.
#[test]
fn directory_descent_is_throttled_when_a_subtree_has_no_eligible_files() {
    let _g = policy_guard();
    live_policy();
    let root = temp_root("dirthrottle");
    let state = root.join("agent-state");
    // Ten nested directories, no documents anywhere in them.
    for i in 0..10 {
        write(
            &root,
            &format!("empty{i}/marker.png", i = i), // unsupported extension
            b"\x89PNG not a document",
        );
    }
    std::fs::create_dir_all(&state).unwrap();

    let mut c = cfg(&root, &state);
    c.files_per_minute = 60; // 1 token/sec
    c.burst = 1; // one directory listing's worth, then nothing
    c.dir_listing_cost = 0.25; // the shipped default
    let cache = Arc::new(VerdictCache::open(&state, 1024).unwrap());
    let sink = RecordingSink::new(Arc::clone(&cache), false);
    let w = Walker::new(c, cache, sink.clone());
    w.begin_full_sweep();

    // Frozen clock: the budget never refills, so descent must eventually pause
    // rather than list all eleven directories (root + 10 subdirs) back to back.
    let mut descended = 0usize;
    let mut paused = 0usize;
    for _ in 0..100 {
        match w.step(0) {
            StepStatus::Descended => descended += 1,
            StepStatus::Paused { wait_ms } => {
                assert!(wait_ms > 0);
                paused += 1;
            }
            StepStatus::Completed => break,
            other => panic!("unexpected {other:?} — this tree has no files to process"),
        }
    }
    assert!(
        paused > 0,
        "an unthrottled walker would list all 11 directories with zero pauses; got {descended} descents, {paused} pauses"
    );
    assert!(
        w.stats().rate_limited.load(Ordering::Relaxed) > 0,
        "the throttled descents must be visible on the health surface, not silent"
    );
    // No documents anywhere — sink must never have been called at all.
    assert_eq!(sink.len(), 0);

    let _ = std::fs::remove_dir_all(&root);
}

/// The service loop (`ml::walk::run`) reads this to decide whether a
/// completion may push the full-sweep backstop timer out — a targeted
/// overflow re-sweep must not. Pinning the primitive directly since `run`
/// itself spawns a real thread and isn't exercised by this injected-clock
/// suite.
#[test]
fn is_full_sweep_distinguishes_full_from_targeted_scope_sweeps() {
    let _g = policy_guard();
    live_policy();
    let root = temp_root("fullflag");
    let state = root.join("agent-state");
    build_tree(&root, &state);

    let cache = Arc::new(VerdictCache::open(&state, 1024).unwrap());
    let sink = RecordingSink::new(Arc::clone(&cache), false);
    let w = Walker::new(cfg(&root, &state), cache, sink);

    w.begin_full_sweep();
    assert!(w.is_full_sweep(), "begin_full_sweep must report full");
    assert_eq!(drive(&w), StepStatus::Completed);

    w.begin_scope_sweep(&[root.clone()]);
    assert!(
        !w.is_full_sweep(),
        "a targeted overflow re-sweep must report NOT full"
    );
    assert_eq!(drive(&w), StepStatus::Completed);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_limiter_is_a_token_bucket_over_the_injected_clock() {
    let mut l = RateLimiter::new(120, 2); // two per second, burst 2
    assert!(l.try_take(0));
    assert!(l.try_take(0));
    assert!(!l.try_take(0), "the burst is two, not three");
    assert_eq!(l.wait_ms(0), 500);
    assert!(!l.try_take(499));
    assert!(l.try_take(500));

    // Idling does not mint an unbounded burst.
    assert!(l.try_take(1_000_000));
    assert!(l.try_take(1_000_000));
    assert!(
        !l.try_take(1_000_000),
        "a bucket that saved up all day would defeat the throttle entirely"
    );
}

// ===========================================================================
// Errors are counted, never fatal
// ===========================================================================

#[test]
fn a_refused_queue_is_counted_and_the_sweep_continues() {
    let _g = policy_guard();
    live_policy();
    let root = temp_root("refused");
    let state = root.join("agent-state");
    build_tree(&root, &state);

    struct RefusingSink;
    impl ClassifySink for RefusingSink {
        fn submit(&self, _job: ClassifyJob) -> bool {
            false // full, in flight, or known-barren
        }
    }

    let cache = Arc::new(VerdictCache::open(&state, 1024).unwrap());
    let w = Walker::new(cfg(&root, &state), cache, Arc::new(RefusingSink));
    w.begin_full_sweep();
    assert_eq!(drive(&w), StepStatus::Completed);

    let c = w.counts();
    assert_eq!(c.candidates, 4);
    assert_eq!(c.refused, 4, "a refusal is coverage lost, and must be visible");
    assert_eq!(c.enqueued, 0);

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_file_that_vanishes_between_listing_and_reading_is_counted_not_fatal() {
    let _g = policy_guard();
    live_policy();
    let root = temp_root("vanish");
    let state = root.join("agent-state");
    let doomed = write(&root, "gone.txt", b"about to be deleted");
    write(&root, "stays.txt", b"still here");
    std::fs::create_dir_all(&state).unwrap();

    let cache = Arc::new(VerdictCache::open(&state, 1024).unwrap());
    let sink = RecordingSink::new(Arc::clone(&cache), false);
    let w = Walker::new(cfg(&root, &state), cache, sink.clone());
    w.begin_full_sweep();

    // First step lists the root; delete one of the listed files before it is
    // reached — exactly what a throttled walker races with.
    assert_eq!(w.step(10), StepStatus::Descended);
    std::fs::remove_file(&doomed).unwrap();

    assert_eq!(drive(&w), StepStatus::Completed);
    assert_eq!(w.counts().vanished, 1);
    assert_eq!(
        sink.names(),
        ["stays.txt"].iter().map(|s| s.to_string()).collect()
    );

    let _ = std::fs::remove_dir_all(&root);
}

// Sanity: the outcome vocabulary the walker reports is the watcher's, so the two
// producers cannot drift into reporting the same thing under different names.
#[test]
fn outcomes_are_the_watchers_vocabulary() {
    let inert: WatchOutcome = WatchOutcome::Inert;
    assert_eq!(inert, WatchOutcome::Inert);
    assert_ne!(WatchOutcome::Enqueued, WatchOutcome::Refused);
}

// ===========================================================================
// A queue wider than memory
// ===========================================================================

/// `n` sibling directories, each holding one document. Breadth-first, the whole
/// level sits in the pending queue at once — which is the shape that used to
/// overflow the checkpoint on a real profile (`C:\Users` peaks at ~12 600
/// pending directories against a cap of 4 096).
fn build_wide_tree(root: &Path, state: &Path, n: usize) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for i in 0..n {
        let name = format!("doc{i:04}.txt");
        write(
            root,
            &format!("wide/dir{i:04}/{name}"),
            format!("quarterly finance report number {i}").as_bytes(),
        );
        names.insert(name);
    }
    std::fs::create_dir_all(state).unwrap();
    names
}

#[test]
fn a_queue_wider_than_the_memory_cap_still_covers_every_file() {
    let _g = policy_guard();
    live_policy();
    let root = temp_root("widecover");
    let state = root.join("agent-state");
    let expected = build_wide_tree(&root, &state, 120);

    let cache = Arc::new(VerdictCache::open(&state, 4096).unwrap());
    let sink = RecordingSink::new(Arc::clone(&cache), false);
    let mut c = cfg(&root, &state);
    c.max_pending_dirs = 4; // force the queue onto disk almost immediately
    let w = Walker::new(c, cache, sink.clone());

    w.begin_full_sweep();
    assert_eq!(drive(&w), StepStatus::Completed, "the sweep must finish");

    assert_eq!(
        sink.names(),
        expected,
        "spilling the queue to disk must not lose a single directory"
    );
    let stats = w.stats().snapshot();
    assert!(
        stats.dirs_spilled > 0,
        "a 120-wide level against a cap of 4 must have spilled"
    );
    assert!(
        stats.dirs_pending_max > 4,
        "the queue really did grow past the memory cap (max was {})",
        stats.dirs_pending_max
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_restart_resumes_a_wide_sweep_instead_of_starting_it_over() {
    let _g = policy_guard();
    live_policy();
    let root = temp_root("wideresume");
    let state = root.join("agent-state");
    let expected = build_wide_tree(&root, &state, 120);

    // Depositing the verdict is what the background worker does; it makes a
    // re-listed file a cache hit, so "enqueued twice" is observable.
    let cache = Arc::new(VerdictCache::open(&state, 4096).unwrap());
    let sink_a = RecordingSink::new(Arc::clone(&cache), true);
    let mut c = cfg(&root, &state);
    c.max_pending_dirs = 4;
    let w1 = Walker::new(c.clone(), Arc::clone(&cache), sink_a.clone());

    // Interrupt part-way: enough steps to be deep into the wide level.
    w1.begin_full_sweep();
    let mut t = 0u64;
    for _ in 0..80 {
        t += 10;
        if w1.step(t) == StepStatus::Completed {
            panic!("the tree must be big enough to interrupt");
        }
    }
    assert!(w1.checkpoint_now(), "a running sweep must checkpoint");
    let dirs_before = w1.counts().dirs;
    drop(w1);

    // THE REGRESSION: the pending queue has to survive the restart. Before the
    // sidecar, a queue this wide was written away empty with `truncated`, and
    // the resume below would re-walk the scope from zero.
    let cp = load_checkpoint(&state).expect("a checkpoint must be on disk");
    assert!(
        !cp.pending_truncated,
        "the pending queue must be persisted, not discarded"
    );
    assert!(
        cp.spill.count > 0,
        "the part of the queue that did not fit in memory must be on disk"
    );
    assert!(
        cp.pending_dirs.len() <= 5,
        "only the in-memory head belongs in the checkpoint file, got {}",
        cp.pending_dirs.len()
    );

    // Restart the agent over the same state directory.
    let sink_b = RecordingSink::new(Arc::clone(&cache), true);
    let w2 = Walker::new(c, cache, sink_b.clone());
    w2.begin_full_sweep();
    assert!(
        w2.counts().dirs >= dirs_before,
        "the resumed sweep must carry the earlier sweep's progress, not reset it"
    );
    assert_eq!(drive(&w2), StepStatus::Completed, "the sweep must finish");

    let mut covered = sink_a.names();
    covered.extend(sink_b.names());
    assert_eq!(covered, expected, "every document must be classified once");
    assert_eq!(
        sink_a.len() + sink_b.len(),
        expected.len(),
        "a resumed sweep must not re-offer work the interrupted one finished"
    );
    assert!(
        w2.stats().snapshot().dirs < 120,
        "the resume re-listed the whole tree: {} directories",
        w2.stats().snapshot().dirs
    );

    let _ = std::fs::remove_dir_all(&root);
}
