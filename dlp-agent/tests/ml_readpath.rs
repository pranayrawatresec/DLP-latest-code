//! Gate for the KERNEL READ path's ML step (`detect::decide::read_path_ml` /
//! `read_path_reply`, `ml_from_cache`, the `ml::queue` bounded worker).
//!
//! WHY THIS TEST BINARY EXISTS, IN ONE SENTENCE: a mistake on this path is not a
//! false positive on one file, it is a fleet outage — every read of every file
//! on every endpoint goes through it, inside a 500 ms kernel budget, on a
//! single-threaded message loop.
//!
//! The claims being gated, from the contract:
//!   * **F3, the deployability property.** An inert policy produces BYTE-IDENTICAL
//!     behaviour to the pre-cache agent: `ml` is absent from the verdict entirely,
//!     exactly as `ml_read_path_skip()` produced, and the block decision is the
//!     fingerprint-only one.
//!   * **C2, the policy-at-lookup property.** The cache stores what the MODEL
//!     said, never what the POLICY concluded. Marking a label sensitive — or
//!     moving a threshold — flips an ALREADY-CACHED file from allowed to blocked
//!     with no reclassification. This is asserted with no engine loaded at all,
//!     which is the strongest possible proof no inference happened.
//!   * **F1, a miss is never "clean".** A miss yields today's fingerprint-only
//!     answer with `ml = skipped/not_classified` (`denyUnclassified` off), or a
//!     `None` reply — `DLP_VERDICT_NOVERDICT`, deny-and-cache-nothing — when the
//!     admin opted in.
//!   * **P2, default off, and gated.** `denyUnclassified` cannot deny while the
//!     policy is inert, and cannot deny while no background classifier is running
//!     to clear the denial — a deny nothing can heal is an outage, not a control.
//!   * **P3, the enqueue never blocks.** A full queue drops its OLDEST job and
//!     counts the drop.
//!
//! NOTE ON PROCESS-WIDE STATE: the ML policy, the `denyUnclassified` flag, the
//! verdict-cache handle and the classify worker are all process-wide, and cargo
//! runs these tests on many threads in ONE process. Every test therefore takes
//! `ENV_LOCK` for its whole body and restores the inert defaults on the way out.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use dlp_agent::detect::decide::{
    self, deny_unclassified, ml_from_cache, ml_read_path_skip, ml_unclassified_result,
    read_path_ml, read_path_reply, CacheOutcome,
};
use dlp_agent::detect::{decide as fuse, Bands, Extraction, IdmMatch, Verdict};
use dlp_agent::ml::cache::{CachedVerdict, VerdictCache};
use dlp_agent::ml::queue;
use dlp_agent::mlpolicy::{self, MlLabelRule, MlPolicy};

/// The model version every fixture uses. It is also `MlPolicy::default()`'s, so
/// `queue::model_version_for_cache()` (no engine loaded ⇒ the policy's) matches.
const MV: &str = "V6.2.01";

/// The kguard read-deny band (`block_at` 0.30 / `coverage_block_at` 0.60).
fn read_bands() -> Bands {
    Bands::new(0.30, 0.60)
}

// --------------------------------------------------------------------------
// Harness
// --------------------------------------------------------------------------

fn env_lock() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "dlp-ml-readpath-{tag}-{}-{}",
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

/// Put the process back into the shipped, fully-inert state.
fn reset_env() {
    queue::stop_worker();
    queue::set_verdict_cache(None);
    decide::set_deny_unclassified(false);
    decide::set_sweep_completed(false);
    mlpolicy::set_active(MlPolicy::default());
}

fn live_policy(labels: &[(&str, Option<f64>)]) -> MlPolicy {
    MlPolicy {
        enabled: true,
        min_confidence: 0.70,
        labels: labels
            .iter()
            .map(|(id, min)| MlLabelRule { id: (*id).to_string(), min_confidence: *min })
            .collect(),
        ..MlPolicy::default()
    }
}

fn cached(label: &str, confidence: f64) -> CachedVerdict {
    CachedVerdict {
        model_version: MV.to_string(),
        label_id: label.to_string(),
        label_index: 3,
        confidence,
        chunks: 2,
        tokens: 512,
        truncated: false,
        classified_at: 1_700_000_000,
    }
}

/// A verdict shaped exactly as `kguard::decide` builds one before attaching
/// `ml`: `idm`/`edm` are the fingerprint half.
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

/// Install a cache in a fresh directory, with no worker (so nothing drains and
/// nothing classifies — every hit in these tests is one this test seeded).
fn install_cache(tag: &str) -> Arc<VerdictCache> {
    let c = Arc::new(VerdictCache::open(&temp_dir(tag), 1024).unwrap());
    queue::set_verdict_cache(Some(c.clone()));
    c
}

// ==========================================================================
// F3 — an inert policy is byte-identical to the pre-cache read path
// ==========================================================================

#[test]
fn inert_policy_is_byte_identical_to_the_pre_cache_read_path() {
    let _g = env_lock();
    reset_env();

    // A cache that WOULD hit, so this proves inertness beats a populated cache
    // rather than merely coinciding with an empty one.
    let content = b"a paragraph of a drafted plan".to_vec();
    let cache = install_cache("inert");
    cache
        .put(VerdictCache::key_for(&content), cached("NUC", 0.99))
        .unwrap();

    // The policy is the shipped default: disabled, no labels.
    assert!(MlPolicy::default().is_inert());

    assert_eq!(ml_from_cache(&content, "plan.docx"), CacheOutcome::Inert);
    let (ml, miss) = read_path_ml(&content, "plan.docx");
    assert!(ml.is_none(), "an inert policy attaches no ml field at all");
    assert!(!miss, "an inert policy never reports a cache miss");
    // The pre-cache helper said exactly the same thing.
    assert!(ml_read_path_skip().is_none());
    assert!(ml_unclassified_result().is_none());

    // The verdict serializes with NO `ml` key — the wire-compat claim.
    let mut v = verdict_with_idm(0.0, 0.0);
    v.ml = ml;
    let json = serde_json::to_string(&v).unwrap();
    assert!(!json.contains("\"ml\""), "inert verdict must be a pre-model verdict: {json}");

    // And the fused decision is the fingerprint-only one, both ways.
    assert_eq!(fuse(&v, &read_bands()), fuse(&verdict_with_idm(0.0, 0.0), &read_bands()));
    let mut hit = verdict_with_idm(0.9, 0.0);
    hit.ml = read_path_ml(&content, "plan.docx").0;
    assert!(fuse(&hit, &read_bands()).fingerprint);
    assert!(!fuse(&hit, &read_bands()).ml);

    // With the flag on it STILL cannot deny: inert beats everything (F3).
    decide::set_deny_unclassified(true);
    assert!(!deny_unclassified(), "an inert policy can never deny a read");

    reset_env();
}

// ==========================================================================
// Cache HIT — sensitivity is the CURRENT policy's answer, not the entry's
// ==========================================================================

#[test]
fn cache_hit_sensitivity_table() {
    let _g = env_lock();
    reset_env();
    let cache = install_cache("hit-table");

    // (case, cached label, cached confidence, policy labels, expect sensitive)
    let cases: Vec<(&str, &str, f64, Vec<(&str, Option<f64>)>, bool)> = vec![
        (
            "selected label, comfortably over the floor ⇒ blocks",
            "NUC",
            0.93,
            vec![("NUC", None)],
            true,
        ),
        (
            "label the admin did NOT select ⇒ no model hit, however confident",
            "PUB",
            1.00,
            vec![("NUC", None)],
            false,
        ),
        (
            "selected label BELOW its own threshold ⇒ not sensitive",
            "NUC",
            0.62,
            vec![("NUC", Some(0.80))],
            false,
        ),
        (
            "selected label exactly AT its threshold ⇒ sensitive (>= is inclusive)",
            "NUC",
            0.80,
            vec![("NUC", Some(0.80))],
            true,
        ),
    ];

    for (name, label, confidence, labels, expect_sensitive) in cases {
        let content = format!("content for {name}").into_bytes();
        cache
            .put(VerdictCache::key_for(&content), cached(label, confidence))
            .unwrap();
        mlpolicy::set_active(live_policy(&labels));

        let (ml, miss) = read_path_ml(&content, "doc.docx");
        assert!(!miss, "{name}: a seeded entry must HIT");
        let ml = ml.expect("a live policy always attaches an ml field");
        assert_eq!(ml.status, "ok", "{name}: a hit is an answer, not a skip");
        assert_eq!(ml.reason, None, "{name}: an answer carries no `why not`");
        assert_eq!(ml.label_id.as_deref(), Some(label), "{name}");
        assert_eq!(ml.model_version, MV, "{name}");
        assert_eq!(ml.sensitive, expect_sensitive, "{name}");

        // ...and the fusion acts on it. No fingerprint hit here, so the ML half
        // is the only thing that can make the read sensitive.
        let mut v = verdict_with_idm(0.0, 0.0);
        v.ml = Some(ml);
        let d = fuse(&v, &read_bands());
        assert_eq!(d.ml, expect_sensitive, "{name}");
        assert_eq!(d.sensitive, expect_sensitive, "{name}");
    }

    reset_env();
}

// ==========================================================================
// C2 — a policy change flips a HIT with NO reclassification
// ==========================================================================

#[test]
fn policy_change_flips_a_cached_hit_with_no_reclassification() {
    let _g = env_lock();
    reset_env();
    let cache = install_cache("c2");

    let content = b"a nuclear systems appendix nobody registered".to_vec();
    let key = VerdictCache::key_for(&content);
    cache.put(key, cached("NUC", 0.91)).unwrap();
    let entries_after_seed = cache.stats().entries;

    // No engine is loaded in this test binary, so ANY reclassification would be
    // impossible — which is exactly why this asserts the property so strongly.
    assert!(dlp_agent::ml::active().is_none(), "no engine may be loaded here");

    // Phase 1: the admin has marked only FIN. Same bytes, same entry, no hit.
    mlpolicy::set_active(live_policy(&[("FIN", None)]));
    let before = read_path_ml(&content, "appendix.docx").0.unwrap();
    assert_eq!(before.status, "ok");
    assert!(!before.sensitive, "NUC is not a selected label yet");
    let mut v = verdict_with_idm(0.0, 0.0);
    v.ml = Some(before);
    assert!(!fuse(&v, &read_bands()).sensitive);

    // Phase 2: the admin adds NUC in the console. Nothing is reclassified,
    // nothing is invalidated, no entry is written.
    mlpolicy::set_active(live_policy(&[("FIN", None), ("NUC", None)]));
    let after = read_path_ml(&content, "appendix.docx").0.unwrap();
    assert_eq!(after.status, "ok");
    assert!(after.sensitive, "the SAME cached label is now sensitive");
    let mut v = verdict_with_idm(0.0, 0.0);
    v.ml = Some(after);
    let d = fuse(&v, &read_bands());
    assert!(d.sensitive && d.ml && !d.fingerprint);

    // Phase 3: the same trick with a THRESHOLD move rather than a label add.
    mlpolicy::set_active(live_policy(&[("NUC", Some(0.95))]));
    assert!(!read_path_ml(&content, "appendix.docx").0.unwrap().sensitive);

    assert_eq!(
        cache.stats().entries,
        entries_after_seed,
        "no entry was written, rewritten or invalidated by a policy change"
    );
    assert_eq!(cache.stats().hits, 3, "all three answers above came from the cache");

    reset_env();
}

// ==========================================================================
// C3 — a stale model version is a MISS, not a reinterpreted label
// ==========================================================================

#[test]
fn an_entry_from_another_model_version_is_a_miss() {
    let _g = env_lock();
    reset_env();
    let cache = install_cache("stale");

    let content = b"classified by an older graph".to_vec();
    cache
        .put(
            VerdictCache::key_for(&content),
            CachedVerdict { model_version: "V5.0.00".into(), ..cached("NUC", 0.99) },
        )
        .unwrap();
    mlpolicy::set_active(live_policy(&[("NUC", None)]));

    assert_eq!(ml_from_cache(&content, "f.docx"), CacheOutcome::Miss);
    let (ml, miss) = read_path_ml(&content, "f.docx");
    assert!(miss);
    let ml = ml.unwrap();
    assert_eq!(ml.status, "skipped");
    assert_eq!(ml.reason.as_deref(), Some("not_classified"));
    assert!(!ml.sensitive, "a stale entry can never make a file sensitive");

    reset_env();
}

// ==========================================================================
// F1 / P2 — what a MISS costs, with the flag off and on
// ==========================================================================

#[test]
fn miss_with_deny_off_is_exactly_the_fingerprint_only_answer() {
    let _g = env_lock();
    reset_env();
    install_cache("miss-off"); // empty
    mlpolicy::set_active(live_policy(&[("NUC", None)]));
    assert!(!deny_unclassified(), "the flag ships OFF");

    // (case, containment, coverage, fingerprint blocks?)
    let cases: [(&str, f64, f64, bool); 3] = [
        ("clean file", 0.0, 0.0, false),
        ("under the read band", 0.10, 0.10, false),
        ("over the read band", 0.90, 0.0, true),
    ];

    for (name, containment, coverage, expect_block) in cases {
        let content = format!("uncached bytes for {name}").into_bytes();
        let (ml, miss) = read_path_ml(&content, "f.docx");
        assert!(miss, "{name}: nothing is cached");
        let ml = ml.expect("a live policy records the coverage gap explicitly");
        assert_eq!(ml.status, "skipped", "{name}");
        assert_eq!(ml.reason.as_deref(), Some("not_classified"), "{name}");
        assert!(!ml.sensitive, "{name}: F1 — a miss is never `not sensitive` by fiat");

        let mut v = verdict_with_idm(containment, coverage);
        v.ml = Some(ml);
        let d = fuse(&v, &read_bands());
        // Identical to the same verdict with no ml field at all.
        let bare = fuse(&verdict_with_idm(containment, coverage), &read_bands());
        assert_eq!(d, bare, "{name}: a miss changes no decision");
        assert_eq!(d.sensitive, expect_block, "{name}");

        // ...and the reply is the ordinary one.
        assert_eq!(
            read_path_reply(d.sensitive, miss, deny_unclassified()),
            Some(expect_block),
            "{name}"
        );
    }

    reset_env();
}

#[test]
fn miss_with_deny_on_replies_noverdict() {
    let _g = env_lock();
    reset_env();
    let cache = install_cache("miss-on");
    // A RUNNING worker is one of the three gates, so start one (nothing to
    // classify: the queue stays empty and the engine is not loaded).
    queue::start(cache, 8, None);
    mlpolicy::set_active(live_policy(&[("NUC", None)]));
    decide::set_deny_unclassified(true);
    // The endpoint interlock: the console switch is only honoured once THIS machine
    // has completed a discovery sweep (see decide::deny_unclassified).
    decide::set_sweep_completed(true);
    assert!(deny_unclassified(), "live policy + flag + running worker + swept");

    let content = b"a file the walker has not reached yet".to_vec();
    let (ml, miss) = read_path_ml(&content, "f.docx");
    assert!(miss);
    assert_eq!(ml.unwrap().reason.as_deref(), Some("not_classified"));

    // The unknown case ⇒ NOVERDICT: the driver denies per ExfilReadFailBlock and
    // caches NOTHING, so the retry after the queue drains is authoritative.
    assert_eq!(read_path_reply(false, true, true), None);
    // A real block beats NOVERDICT — the driver should cache it and seed the bad
    // hash, and the caller's incident names the document.
    assert_eq!(read_path_reply(true, true, true), Some(true));
    // A HIT is never denied for being unclassified; it IS classified.
    assert_eq!(read_path_reply(false, false, true), Some(false));
    // And with the flag off, the rule is the identity.
    assert_eq!(read_path_reply(false, true, false), Some(false));

    reset_env();
}

#[test]
fn deny_unclassified_is_gated_on_policy_and_on_a_running_worker() {
    let _g = env_lock();
    reset_env();
    let cache = install_cache("gates");
    decide::set_deny_unclassified(true);
    decide::set_sweep_completed(true);

    // Gate 1: no worker ⇒ a denial could never heal, so it must not happen.
    mlpolicy::set_active(live_policy(&[("NUC", None)]));
    assert!(!queue::running());
    assert!(!deny_unclassified(), "no classifier ⇒ no deny (an outage, not a control)");

    // Gate 2: worker running + live policy ⇒ the flag is honoured.
    queue::start(cache.clone(), 8, None);
    assert!(queue::running());
    assert!(deny_unclassified());

    // Gate 2b: THIS ENDPOINT must have been swept. The console applies the switch to
    // a fleet; whether a given machine has been classified yet is a local fact, and
    // arming an un-swept machine denies the first read of nearly every file on it.
    decide::set_sweep_completed(false);
    assert!(
        !deny_unclassified(),
        "an endpoint with no completed discovery sweep must not honour the switch"
    );
    decide::set_sweep_completed(true);
    assert!(deny_unclassified());

    // Gate 3: the policy going inert switches it straight back off.
    mlpolicy::set_active(MlPolicy::default());
    assert!(!deny_unclassified());

    // Gate 1 again, from the other direction: stopping the worker disarms it.
    mlpolicy::set_active(live_policy(&[("NUC", None)]));
    assert!(deny_unclassified());
    queue::stop_worker();
    assert!(!deny_unclassified());

    reset_env();
}

// ==========================================================================
// P3 — the enqueue never blocks, and drops are counted
// ==========================================================================

#[test]
fn enqueue_never_blocks_when_full_and_drops_are_counted() {
    let _g = env_lock();
    reset_env();
    let cache = install_cache("full");

    // A worker whose stop flag is ALREADY set exits on its first iteration, so
    // nothing drains the queue and it genuinely fills — which is the state this
    // test is about. (`deny_unclassified` correctly reports false meanwhile.)
    let stop = Arc::new(AtomicBool::new(true));
    queue::start(cache, 4, Some(stop));
    mlpolicy::set_active(live_policy(&[("NUC", None)]));

    let started = Instant::now();
    for i in 0..64u32 {
        // ~64 KiB per job, so a blocking implementation would be obvious.
        let content = {
            let mut c = vec![0u8; 64 * 1024];
            c[..4].copy_from_slice(&i.to_le_bytes());
            c
        };
        queue::enqueue(content, format!("f{i}.txt"));
    }
    let elapsed = started.elapsed();

    let s = queue::stats();
    assert_eq!(s.capacity, 4);
    assert_eq!(s.depth, 4, "capacity is a HARD bound on the queue");
    assert_eq!(s.queued, 64);
    assert_eq!(s.dropped, 60, "the oldest job is dropped, and every drop is counted");
    assert!(
        elapsed < Duration::from_secs(2),
        "enqueue must never wait for the worker (took {elapsed:?})"
    );

    // Duplicate bytes are not queued twice — a file read in a tight loop is
    // classified once.
    let before = queue::stats();
    let dup = vec![7u8; 1024];
    assert!(queue::enqueue(dup.clone(), "dup.txt".into()));
    assert!(!queue::enqueue(dup, "dup.txt".into()));
    assert_eq!(queue::stats().deduped, before.deduped + 1);

    reset_env();
}

// ==========================================================================
// Key equivalence — the one mistake that makes the whole feature silently inert
// ==========================================================================

#[test]
fn the_read_path_key_is_the_drivers_prefix() {
    let _g = env_lock();
    reset_env();
    let cache = install_cache("key");
    mlpolicy::set_active(live_policy(&[("NUC", None)]));

    // A 5 MiB file: the driver ships the first 4 MiB and sets `truncated`.
    let whole: Vec<u8> = (0..5 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let prefix = &whole[..dlp_agent::ml::cache::MAX_HASHED_BYTES];

    // A producer that hashed the WHOLE file would mint this key...
    cache
        .put(VerdictCache::key_for(&whole), cached("NUC", 0.99))
        .unwrap();
    assert_eq!(
        ml_from_cache(prefix, "big.pdf"),
        CacheOutcome::Miss,
        "hashing the whole file produces a key the read path can never make"
    );

    // ...whereas the prefix key is the one the read path actually looks up.
    cache
        .put(VerdictCache::key_for(prefix), cached("NUC", 0.99))
        .unwrap();
    match ml_from_cache(prefix, "big.pdf") {
        CacheOutcome::Hit(r) => assert!(r.sensitive),
        other => panic!("expected a hit on the prefix key, got {other:?}"),
    }

    reset_env();
}

// =====================================================================
// THE QUEUE'S MEMORY BOUND
//
// `capacity` bounds the job COUNT, not memory — and a job carries the file's
// bytes. That was harmless while every job was the driver's ≤4 MiB prefix, but
// the watcher and walker now read a WHOLE container file (a >4 MiB .docx or .pdf
// cannot be parsed from a prefix: its central directory / xref lives at the end).
// One job became tens of MiB, 256 of them became gigabytes, and on a real 8 GiB
// endpoint the agent reached 4.5 GiB and pushed the machine into commit
// exhaustion — where a failed allocation aborts the process outright, with no
// panic and no log line.
//
// So the queue carries TWO bounds and both must hold.
// =====================================================================

#[test]
fn the_queue_bounds_bytes_as_well_as_job_count() {
    let _g = env_lock();
    reset_env();
    let cache = install_cache("bytes-budget");
    // Plenty of job slots, so only the BYTE bound can do the limiting here.
    queue::start(cache, 4096, None);

    let before = queue::stats();
    assert!(
        before.max_queued_bytes > 0,
        "a byte budget must exist — without it the job count is the only bound \
         and whole-file reads grow the process without limit"
    );

    // Offer far more content than the budget allows.
    let chunk = vec![b'x'; 1 << 20]; // 1 MiB each
    let offers = (before.max_queued_bytes / chunk.len()) + 32;
    for i in 0..offers {
        let mut c = chunk.clone();
        // Distinct bytes ⇒ distinct keys, so the in-flight dedupe cannot absorb them.
        c[0] = (i % 251) as u8;
        c[1] = (i / 251) as u8;
        queue::enqueue(c, format!("f{i}.txt"));
    }

    let after = queue::stats();
    assert!(
        after.queued_bytes <= after.max_queued_bytes,
        "queued bytes {} exceeded the budget {} — this is the growth that \
         exhausted an 8 GiB endpoint",
        after.queued_bytes,
        after.max_queued_bytes
    );
}

#[test]
fn a_job_larger_than_the_whole_budget_is_refused_not_admitted() {
    let _g = env_lock();
    reset_env();
    let cache = install_cache("oversize");
    queue::start(cache, 256, None);

    let budget = queue::stats().max_queued_bytes;
    // One job bigger than the entire budget. Admitting it would mean evicting the
    // whole queue AND still blowing the bound.
    let huge = vec![b'z'; budget + (1 << 20)];
    let accepted = queue::enqueue(huge, "enormous.docx".into());
    assert!(!accepted, "an over-budget job must be refused");

    let st = queue::stats();
    assert!(st.oversized >= 1, "the refusal must be counted, not silent");
    assert!(
        st.queued_bytes <= st.max_queued_bytes,
        "refusing must not leave the budget breached"
    );
    // Refusing costs COVERAGE (the file stays unclassified — a MISS), which can
    // never read as "not sensitive". That is the safe direction.
}

// =====================================================================
// THE WRITE PATH MUST CONSULT THE CACHE BEFORE CLASSIFYING
//
// The driver blocks a write by DELETING the file it has already written to the
// media (detect-and-quarantine). The file therefore exists on the stick for
// exactly as long as the verdict takes. Fingerprinting answers in milliseconds
// and the file vanishes before Explorer redraws; a COLD ML answer takes long
// enough that Explorer caches the entry, leaving a "ghost file" the user can see
// but not open. Same block, but it reads as a product defect.
//
// A cache hit collapses the ML path to a hash plus a map lookup, back in the same
// latency class as fingerprinting. This test pins that the lookup happens.
// =====================================================================

#[test]
fn the_write_path_uses_a_cached_verdict_instead_of_reclassifying() {
    let _g = env_lock();
    reset_env();
    let cache = install_cache("write-lookup");
    queue::start(cache.clone(), 16, None);
    mlpolicy::set_active(live_policy(&[("NUC", None)]));

    // Seed the cache exactly as the walker would, for these bytes.
    let content = b"reactor core safety assessment and criticality margins".to_vec();
    let key = VerdictCache::key_for(&content);
    cache
        .put(
            key,
            CachedVerdict {
                model_version: queue::model_version_for_cache(),
                label_id: "NUC".into(),
                label_index: 28,
                confidence: 0.97,
                chunks: 1,
                tokens: 12,
                truncated: false,
                classified_at: 1_700_000_000,
            },
        )
        .expect("seed the cache");

    let before = queue::stats();

    // The write path. With no engine loaded in this test process, a MISS would
    // have to report `unavailable` - so an `ok` answer can only have come from
    // the cache.
    let ml = dlp_agent::detect::decide::ml_for_bytes_caching(&content, "reactor.txt", false)
        .expect("a live policy always produces an ml block");

    assert_eq!(
        ml.status, "ok",
        "the write path must answer from the cache; it reported {:?} ({:?}), which \
         means it tried to classify from scratch inside the driver's up-call",
        ml.status, ml.reason
    );
    assert_eq!(ml.label_id.as_deref(), Some("NUC"));
    assert!(ml.sensitive, "NUC is selected in the policy at this confidence");

    // And it must not have queued any background work for content it already knows.
    let after = queue::stats();
    assert_eq!(
        after.queued, before.queued,
        "a cache hit must not enqueue a reclassification"
    );
}
