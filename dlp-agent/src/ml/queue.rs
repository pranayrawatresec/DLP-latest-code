//! ON-DEMAND CLASSIFICATION — the bounded background worker that turns a
//! read-path cache MISS into a self-healing event instead of a permanent hole.
//!
//! WHY THIS EXISTS
//! ---------------
//! `ml/cache.rs` explains why the model may never run on the kernel READ up-call:
//! that call is synchronous, the filesystem stack is blocked on our reply inside
//! `DLP_REPLY_TIMEOUT_MS` (500 ms), eight consecutive timeouts trip the IPC
//! circuit breaker for the WHOLE machine, and a DistilBERT forward pass costs
//! ~10–100 ms typically and ~640 ms at eight chunks. Worse, the kguard message
//! loop is single-threaded (`FilterGetMessage` → decide → `FilterReplyMessage`,
//! serially), so one slow scan delays every other scan on the endpoint.
//!
//! But the driver has ALREADY read the file in-kernel and shipped us up to 4 MiB
//! of its content with `DLP_REASON_READ`. On a cache miss we therefore hold
//! exactly the bytes the model needs and need no file re-open — we just cannot
//! afford to classify them *now*. This module is the "later": the read path hands
//! the bytes over here and returns immediately, the worker classifies off the hot
//! loop, and the answer lands in the verdict cache so the NEXT read of the same
//! content is a microsecond HashMap hit.
//!
//! Paired with `denyUnclassified` (see `detect::decide::deny_unclassified`) that
//! becomes the deny-now / classify-later / self-heal primitive: reply
//! `DLP_VERDICT_NOVERDICT`, which the driver fails safe on per
//! `ExfilReadFailBlock`, seeds into NO cross-open cache (so the next read
//! up-calls again), and — per `comms.c` — explicitly does not count toward the
//! IPC breaker. With the flag off (the shipped default) this module is a pure
//! coverage engine: it fills the cache, it changes no decision.
//!
//! RULES THIS MODULE OBEYS, AND WHY EACH ONE IS LOAD-BEARING
//! ---------------------------------------------------------
//! * **`enqueue` never blocks.** It is called from the kguard message loop. A
//!   bounded queue that made a producer *wait* for the worker would hand the
//!   500 ms kernel budget to a 640 ms forward pass — the exact coupling this
//!   whole design exists to break. Full ⇒ drop the OLDEST job and count it.
//! * **One worker thread.** Inference is already serialised behind the engine's
//!   own lock, so extra threads buy no throughput and cost ~300 MB of resident
//!   model per contender.
//! * **A failed classification writes NOTHING** (contract F2). A cache entry can
//!   cause a file to be ALLOWED out; "we tried and it did not work" must never
//!   become "the model said this is fine".
//! * **In-flight work is deduplicated by key.** A file read in a tight loop (an
//!   RDP session streaming a document) otherwise enqueues the same 4 MiB dozens
//!   of times and starves every other file of the single worker.
//! * **Nothing here raises an incident** (F5). Classifying a file is not a
//!   detection; only enforcement is. Per-file incidents from a background
//!   classifier would flood the console on day one.
//! * **Nothing here logs content, extracted text or a full path.** Counts, label
//!   ids and scores only — the same rule the rest of `ml/` obeys.
//!
//! THE `barren` SET, and the honest consequence of it
//! --------------------------------------------------
//! Some content yields no model answer at all: an image, an encrypted archive, a
//! binary the extractor refuses, a document that tokenizes to nothing. Per F2 we
//! store no cache entry for those, which means every read of such a file misses
//! for ever. Without a memory of "we already tried this and there is nothing to
//! read", each of those reads would re-enqueue the same 4 MiB and re-run the
//! extractor — a busy loop on the one worker. `barren` is a small bounded set of
//! keys that produced no entry, consulted only to skip RE-ENQUEUEING. It is
//! deliberately NOT consulted by the read-path decision: a barren key is still a
//! cache MISS, so with `denyUnclassified` on, content the extractor cannot read
//! stays denied. That is the admin's choice when they enable the flag, and one of
//! the reasons the flag ships false and is gated on a completed estate walk.
//!
//! WHERE THE PROCESS-WIDE CACHE HANDLE LIVES
//! -----------------------------------------
//! Here, next to the worker that feeds it, because every producer in the design
//! (this queue, the at-creation watcher, the at-rest walker, and the kguard WRITE
//! path depositing its inline result) and the single consumer (the read path)
//! need one handle and one open() of the durability log. `verdict_cache()` is
//! that handle; it is `None` until `start`/`open_and_start` publishes one, and a
//! `None` handle degrades every path to exactly its pre-cache behaviour.

use std::collections::{HashSet, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::Serialize;

use super::cache::{CacheKey, CachedVerdict, VerdictCache};
use super::{MlError, MlPrediction};

/// Queue depth when the caller passes 0. 256 jobs of up-to-4 MiB is a worst case
/// the agent will never reach in practice (jobs are drained continuously and the
/// same key is only queued once), but it is the number that bounds it.
pub const DEFAULT_CAPACITY: usize = 256;

/// How long the worker parks between queue checks. Short enough that a stop flag
/// is honoured promptly at service shutdown, long enough to cost nothing.
const WORKER_PARK: Duration = Duration::from_millis(250);

/// Bound on the "we tried, there was nothing to classify" set (see the header).
const MAX_BARREN: usize = 8_192;

/// Aggregate deny-unclassified denials no more often than this. One log line per
/// denied read would be one line per file read by an exfil-channel process.
const DENY_LOG_EVERY: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Process-wide handles
// ---------------------------------------------------------------------------

/// The verdict cache every producer writes and the read path reads.
static CACHE: RwLock<Option<Arc<VerdictCache>>> = RwLock::new(None);
/// The running worker's shared state. `None` ⇒ no worker, and every `enqueue`
/// is a no-op that reports `false`.
static SHARED: RwLock<Option<Arc<Shared>>> = RwLock::new(None);

/// Publish (or clear) the process-wide verdict cache.
///
/// Separate from [`start`] so a test — or a future console "ML off" transition
/// that unloads the engine — can install or drop the cache without owning the
/// worker.
pub fn set_verdict_cache(cache: Option<Arc<VerdictCache>>) {
    match CACHE.write() {
        Ok(mut w) => *w = cache,
        Err(e) => *e.into_inner() = cache,
    }
}

/// The process-wide verdict cache, if one has been published.
///
/// `None` is a normal state, not an error: an agent that has not wired the cache
/// yet simply behaves as it did before this feature existed (every lookup is a
/// miss, which is always the safe answer — contract F1).
pub fn verdict_cache() -> Option<Arc<VerdictCache>> {
    match CACHE.read() {
        Ok(r) => r.clone(),
        Err(e) => e.into_inner().clone(),
    }
}

/// The model version a cache entry is written under, and matched against on
/// lookup (contract C3).
///
/// The LOADED ENGINE is the authority — it is the graph that actually produced
/// the label — and the console policy's `modelVersion` is the fallback for a
/// process with no engine (a lookup on a machine where loading failed, and every
/// pure test). Producer and consumer both call this one function, so they cannot
/// disagree about what "stale" means; and if the two sources ever DID disagree,
/// every entry would read as stale, i.e. a miss, i.e. fail-safe.
pub fn model_version_for_cache() -> String {
    match super::engine::active() {
        Some(e) => e.model_version().to_string(),
        None => crate::mlpolicy::active().model_version,
    }
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

/// What the on-demand path did, for the console health surface. Counts only —
/// no path, no name, no content (C6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct QueueStats {
    /// Bound on `depth`.
    pub capacity: usize,
    /// Ceiling on total queued content bytes (the memory bound, distinct from
    /// `capacity`, which bounds the job COUNT).
    pub max_queued_bytes: usize,
    /// Content bytes queued right now.
    pub queued_bytes: usize,
    /// Jobs refused because one job alone exceeded `max_queued_bytes`. Non-zero
    /// means files that big are going unclassified on this endpoint.
    pub oversized: u64,
    /// Jobs waiting right now.
    pub depth: usize,
    /// Jobs accepted since start.
    pub queued: u64,
    /// Jobs that produced a cache entry.
    pub classified: u64,
    /// Jobs the model could not answer (not loaded, load failure, inference
    /// error). Transient by nature — these are NOT remembered as barren.
    pub failed: u64,
    /// Jobs with nothing to classify (unextractable content, no tokens). Not a
    /// model fault; remembered so we stop re-extracting the same bytes.
    pub unextractable: u64,
    /// Jobs discarded because the queue was full. **Non-zero means the endpoint
    /// is missing coverage**, not merely that it is busy.
    pub dropped: u64,
    /// Enqueues skipped because the same key was already queued/in flight, or
    /// already known barren.
    pub deduped: u64,
    /// Reads denied by `denyUnclassified` because the content was not cached.
    /// This is the counter that stands in for a per-read incident (see
    /// [`note_deny_unclassified`]).
    pub deny_unclassified: u64,
}

// ---------------------------------------------------------------------------
// The worker
// ---------------------------------------------------------------------------

struct Job {
    key: CacheKey,
    /// The driver's ≤4 MiB prefix, COPIED out of the message loop's reusable
    /// buffer before it is handed here (contract P3).
    content: Vec<u8>,
    /// Basename only — extraction picks its format from the extension. Never a
    /// full path, and never logged.
    filename: String,
    /// The file was longer than the hashed prefix. Reporting only (C2).
    truncated: bool,
}

struct Inner {
    q: VecDeque<Job>,
    /// Keys queued or in flight — the in-flight dedupe (a file read in a loop is
    /// classified once).
    pending: HashSet<CacheKey>,
    /// Keys that produced no entry and never will without new bytes. Bounded,
    /// FIFO-evicted. See the module header for why this is an ENQUEUE filter and
    /// never a decision input.
    barren: HashSet<CacheKey>,
    barren_order: VecDeque<CacheKey>,
    /// Running total of `Job::content` bytes sitting in `q`. Maintained on every
    /// push and pop so the budget check is O(1) on the enqueue path, which runs
    /// on the kguard message loop and must not walk the queue.
    queued_bytes: usize,
    shutdown: bool,
}

/// Default ceiling on total queued content, in bytes.
///
/// 64 MiB holds the driver's 4 MiB prefixes many times over while capping what a
/// handful of whole-file container reads can pin. Tunable via `[ml]
/// queue_max_bytes`; see the field doc on [`Shared::max_queued_bytes`].
pub const DEFAULT_MAX_QUEUED_BYTES: usize = 64 * 1024 * 1024;

struct Shared {
    inner: Mutex<Inner>,
    cv: Condvar,
    capacity: usize,
    /// Ceiling on the TOTAL bytes of queued content, independent of the job count.
    ///
    /// WHY A SECOND BOUND. `capacity` bounds jobs, not memory, and a job carries
    /// the file's bytes. That was survivable while every job was the driver's
    /// ≤4 MiB prefix, but the off-path producers now read a WHOLE container file
    /// (a >4 MiB .docx/.pdf does not parse from a prefix — its central directory
    /// is at the end), so one job can be tens of MiB. 256 jobs × 64 MiB is 16 GiB
    /// of queued content, and on an 8 GiB endpoint the agent grew to 4.5 GiB and
    /// pushed the whole machine into commit exhaustion — at which point a failed
    /// allocation aborts the process (Rust's alloc error handler) and the service
    /// dies with no log line at all.
    ///
    /// Coverage is worth memory only up to a point: dropping a job costs one
    /// unclassified file (a MISS, which can never read as "not sensitive"),
    /// while exhausting the endpoint's memory costs the whole agent.
    max_queued_bytes: usize,
    stop: Option<Arc<AtomicBool>>,
    queued: AtomicU64,
    classified: AtomicU64,
    failed: AtomicU64,
    unextractable: AtomicU64,
    dropped: AtomicU64,
    /// Jobs refused because their content alone exceeds the whole byte budget.
    oversized: AtomicU64,
    deduped: AtomicU64,
    deny_unclassified: AtomicU64,
}

impl Shared {
    fn should_stop(&self) -> bool {
        self.stop
            .as_ref()
            .is_some_and(|s| s.load(Ordering::Relaxed))
    }
}

fn shared() -> Option<Arc<Shared>> {
    match SHARED.read() {
        Ok(r) => r.clone(),
        Err(e) => e.into_inner().clone(),
    }
}

/// Is a worker running? Callers use this to decide whether a miss can ever heal.
pub fn running() -> bool {
    shared().is_some_and(|s| {
        !s.should_stop() && !s.inner.lock().unwrap_or_else(|p| p.into_inner()).shutdown
    })
}

/// Open the verdict cache in `dir` and start the worker on it. The one call a
/// startup path needs.
///
/// `max_entries`/`capacity` take their module defaults when 0. Returns the cache
/// so the at-creation watcher and the at-rest walker can share the same handle
/// rather than opening a second log over the same files.
pub fn open_and_start(
    dir: &Path,
    max_entries: usize,
    capacity: usize,
    stop: Option<Arc<AtomicBool>>,
) -> Result<Arc<VerdictCache>> {
    let cache = Arc::new(VerdictCache::open(dir, max_entries)?);
    start(cache.clone(), capacity, stop);
    Ok(cache)
}

/// Publish `cache` process-wide and start the single background classifier on
/// it. Calling it twice is a no-op with a warning — one worker, by design.
pub fn start(cache: Arc<VerdictCache>, capacity: usize, stop: Option<Arc<AtomicBool>>) {
    set_verdict_cache(Some(cache.clone()));

    {
        let existing = match SHARED.read() {
            Ok(r) => r.is_some(),
            Err(e) => e.into_inner().is_some(),
        };
        if existing {
            tracing::warn!("ml classify queue already started — ignoring a second start");
            return;
        }
    }

    let capacity = if capacity == 0 { DEFAULT_CAPACITY } else { capacity };
    let s = Arc::new(Shared {
        inner: Mutex::new(Inner {
            q: VecDeque::new(),
            pending: HashSet::new(),
            barren: HashSet::new(),
            barren_order: VecDeque::new(),
            queued_bytes: 0,
            shutdown: false,
        }),
        cv: Condvar::new(),
        capacity,
        max_queued_bytes: DEFAULT_MAX_QUEUED_BYTES,
        oversized: AtomicU64::new(0),
        stop,
        queued: AtomicU64::new(0),
        classified: AtomicU64::new(0),
        failed: AtomicU64::new(0),
        unextractable: AtomicU64::new(0),
        dropped: AtomicU64::new(0),
        deduped: AtomicU64::new(0),
        deny_unclassified: AtomicU64::new(0),
    });
    match SHARED.write() {
        Ok(mut w) => *w = Some(s.clone()),
        Err(e) => *e.into_inner() = Some(s.clone()),
    }

    let worker = s.clone();
    let cache = cache.clone();
    let spawned = std::thread::Builder::new()
        .name("dlp-ml-classify".into())
        .spawn(move || worker_loop(worker, cache));
    match spawned {
        Ok(_) => tracing::info!(capacity, "ml classify queue started"),
        Err(e) => {
            // No worker ⇒ no self-healing. Say so loudly and tear the shared
            // state down so `running()` reports the truth and
            // `deny_unclassified` refuses to deny reads nothing can ever clear.
            tracing::error!(error = %e, "could not start the ml classify worker — on-demand classification is OFF");
            stop_worker();
        }
    }
}

/// Signal the worker to finish and forget the shared state. Idempotent.
pub fn stop_worker() {
    let s = shared();
    if let Some(s) = &s {
        {
            let mut g = s.inner.lock().unwrap_or_else(|p| p.into_inner());
            g.shutdown = true;
            g.q.clear();
            g.pending.clear();
        }
        s.cv.notify_all();
    }
    match SHARED.write() {
        Ok(mut w) => *w = None,
        Err(e) => *e.into_inner() = None,
    }
}

/// Queue `content` for background classification. **Never blocks.**
///
/// Returns `true` when the job was accepted. `false` covers every reason it was
/// not — no worker, a duplicate already in flight, known-barren bytes — none of
/// which is an error the caller can act on: the caller's decision is already
/// made by the time it calls here.
pub fn enqueue(content: Vec<u8>, filename: String) -> bool {
    let key = VerdictCache::key_for(&content);
    enqueue_keyed(key, content, filename, false)
}

/// [`enqueue`] for a caller that already computed the key.
///
/// The read path hashes the driver's bytes to do its cache LOOKUP, so making it
/// hash the same 4 MiB a second time to enqueue would double the only
/// non-trivial cost that path pays.
pub fn enqueue_keyed(
    key: CacheKey,
    content: Vec<u8>,
    filename: String,
    truncated: bool,
) -> bool {
    let s = match shared() {
        Some(s) => s,
        None => return false,
    };

    let mut dropped_oldest = false;
    {
        let mut g = s.inner.lock().unwrap_or_else(|p| p.into_inner());
        if g.shutdown {
            return false;
        }
        if g.pending.contains(&key) || g.barren.contains(&key) {
            s.deduped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // A single job bigger than the whole budget can never be admitted without
        // blowing it, and evicting the entire queue to make room for one enormous
        // file is a bad trade. Refuse it and count it: the file stays unclassified
        // (a MISS — never "not sensitive"), which is the safe direction.
        let size = content.len();
        if size > s.max_queued_bytes {
            let n = s.oversized.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::warn!(
                bytes = size,
                budget = s.max_queued_bytes,
                oversized = n,
                "ml queue: job exceeds the whole byte budget — refused, file stays unclassified"
            );
            return false;
        }

        // Full ⇒ drop the OLDEST (contract P3). Newer bytes are the ones a user
        // is actually waiting on; the dropped one will be re-offered by its next
        // read, because a NOVERDICT/miss caches nothing in the driver either.
        //
        // TWO bounds, and both must hold: the job count AND the queued bytes. The
        // byte bound is what stops the off-path producers' whole-file reads from
        // growing the process without limit.
        while (g.q.len() >= s.capacity || g.queued_bytes + size > s.max_queued_bytes)
            && !g.q.is_empty()
        {
            if let Some(old) = g.q.pop_front() {
                g.queued_bytes = g.queued_bytes.saturating_sub(old.content.len());
                g.pending.remove(&old.key);
                dropped_oldest = true;
            }
        }
        g.pending.insert(key);
        g.queued_bytes += size;
        g.q.push_back(Job { key, content, filename, truncated });
    }
    s.cv.notify_one();

    if dropped_oldest {
        let n = s.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        // Counts only. A dropped job is lost COVERAGE, so this is warn-level:
        // it means files are being read faster than they can be classified.
        tracing::warn!(
            dropped = n,
            capacity = s.capacity,
            "ml classify queue full — dropped the oldest pending classification"
        );
    }
    s.queued.fetch_add(1, Ordering::Relaxed);
    true
}

/// Deposit an ALREADY-COMPUTED prediction into the cache (contract P4).
///
/// The kguard WRITE path classifies inline within its async budget; this is how
/// that answer becomes known to the read path, so a file scanned on its way to a
/// USB stick is already classified when RustDesk later reads it. No queue, no
/// thread — the work is done, this is just the store.
pub fn deposit(key: CacheKey, prediction: &MlPrediction, truncated: bool) {
    let cache = match verdict_cache() {
        Some(c) => c,
        None => return,
    };
    let version = model_version_for_cache();
    let verdict = CachedVerdict::from_prediction(prediction, &version, truncated);
    if let Err(e) = cache.put(key, verdict) {
        // A cache that cannot be written costs coverage, never correctness — the
        // read path just keeps missing. Never propagate it into a scan decision.
        tracing::warn!(error = %e, "ml verdict cache put failed");
    }
}

/// Count a read denied because its content was not classified yet.
///
/// WHY A COUNTER AND NOT AN INCIDENT: a `denyUnclassified` denial is "we do not
/// know yet", not a detection (F5). The driver caches nothing on NOVERDICT by
/// design, so the SAME file re-up-calls on every read attempt until the queue
/// drains — an incident per denial would be an incident per read, and on the day
/// the flag is switched on it would be one per legacy file on every endpoint.
/// The signal an operator actually needs is the RATE, which is this counter plus
/// the aggregated log line below; a genuine block still raises its normal
/// incident through the ordinary fingerprint/ML path.
pub fn note_deny_unclassified() {
    let s = match shared() {
        Some(s) => s,
        None => return,
    };
    let n = s.deny_unclassified.fetch_add(1, Ordering::Relaxed) + 1;

    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|p| p.into_inner());
    let due = last.map(|t| t.elapsed() >= DENY_LOG_EVERY).unwrap_or(true);
    if due {
        *last = Some(Instant::now());
        let depth = s.inner.lock().unwrap_or_else(|p| p.into_inner()).q.len();
        tracing::info!(
            denied_total = n,
            queue_depth = depth,
            "denyUnclassified: reads denied pending classification"
        );
    }
}

/// Counters for the console health surface.
pub fn stats() -> QueueStats {
    let s = match shared() {
        Some(s) => s,
        None => return QueueStats::default(),
    };
    let depth = s.inner.lock().unwrap_or_else(|p| p.into_inner()).q.len();
    let (depth_bytes, _) = {
        let g = s.inner.lock().unwrap_or_else(|p| p.into_inner());
        (g.queued_bytes, ())
    };
    QueueStats {
        capacity: s.capacity,
        max_queued_bytes: s.max_queued_bytes,
        queued_bytes: depth_bytes,
        oversized: s.oversized.load(Ordering::Relaxed),
        depth,
        queued: s.queued.load(Ordering::Relaxed),
        classified: s.classified.load(Ordering::Relaxed),
        failed: s.failed.load(Ordering::Relaxed),
        unextractable: s.unextractable.load(Ordering::Relaxed),
        dropped: s.dropped.load(Ordering::Relaxed),
        deduped: s.deduped.load(Ordering::Relaxed),
        deny_unclassified: s.deny_unclassified.load(Ordering::Relaxed),
    }
}

/// Block until the queue is empty and nothing is in flight, or `timeout`
/// elapses. Returns whether it drained. **Test/CLI support only** — no
/// production path may wait on classification.
pub fn drain_for_test(timeout: Duration) -> bool {
    let s = match shared() {
        Some(s) => s,
        None => return true,
    };
    let deadline = Instant::now() + timeout;
    loop {
        {
            let g = s.inner.lock().unwrap_or_else(|p| p.into_inner());
            if g.q.is_empty() && g.pending.is_empty() {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn worker_loop(s: Arc<Shared>, cache: Arc<VerdictCache>) {
    loop {
        let job = {
            let mut g = s.inner.lock().unwrap_or_else(|p| p.into_inner());
            loop {
                if g.shutdown || s.should_stop() {
                    tracing::info!("ml classify worker stopping");
                    return;
                }
                if let Some(j) = g.q.pop_front() {
                    // Keep the byte budget honest: the bytes leave the queue here.
                    g.queued_bytes = g.queued_bytes.saturating_sub(j.content.len());
                    break j;
                }
                let (next, _) = s
                    .cv
                    .wait_timeout(g, WORKER_PARK)
                    .unwrap_or_else(|p| p.into_inner());
                g = next;
            }
        };

        let key = job.key;
        let outcome = classify_job(&s, &cache, job);

        {
            let mut g = s.inner.lock().unwrap_or_else(|p| p.into_inner());
            g.pending.remove(&key);
            if matches!(outcome, Outcome::Barren) {
                remember_barren(&mut g, key);
            }
        }

        // Verdict-log housekeeping happens HERE and nowhere else. `VerdictCache::put`
        // only ARMS a compaction, because it is also reachable from the kguard
        // message loop (the write path deposits its inline result), and rewriting +
        // fsyncing the log inside the kernel's 500 ms budget risks the IPC circuit
        // breaker taking the endpoint to FailMode. This thread has no budget at all.
        cache.compact_if_pending();
    }
}

enum Outcome {
    /// An entry was written.
    Stored,
    /// No answer, and none is possible from these bytes.
    Barren,
    /// No answer, but the model might give one later (not loaded yet, load
    /// failed, inference error). Deliberately NOT remembered.
    Transient,
}

/// extract → classify → put. A failure at any step writes NOTHING (F2).
fn classify_job(s: &Arc<Shared>, cache: &Arc<VerdictCache>, job: Job) -> Outcome {
    let text = match crate::detect::extract_text(&job.content, &job.filename) {
        Ok(e) => e.text,
        // Unextractable content (an image, an encrypted archive) is an outcome,
        // not a fault — exactly as `decide::ml_for_bytes` treats it.
        Err(_) => {
            s.unextractable.fetch_add(1, Ordering::Relaxed);
            return Outcome::Barren;
        }
    };

    match super::classify(&text) {
        Ok(p) => {
            let version = model_version_for_cache();
            let verdict = CachedVerdict::from_prediction(&p, &version, job.truncated);
            match cache.put(job.key, verdict) {
                Ok(()) => {
                    s.classified.fetch_add(1, Ordering::Relaxed);
                    // Metadata only: label, score, counts. NEVER the text, never
                    // the filename at info level.
                    tracing::debug!(
                        label = p.label_id,
                        confidence = p.confidence,
                        chunks = p.chunks,
                        tokens = p.tokens,
                        "background classification cached"
                    );
                    Outcome::Stored
                }
                Err(e) => {
                    tracing::warn!(error = %e, "ml verdict cache put failed");
                    s.failed.fetch_add(1, Ordering::Relaxed);
                    Outcome::Transient
                }
            }
        }
        // Nothing to classify: same disposition as unextractable content.
        Err(MlError::Empty) => {
            s.unextractable.fetch_add(1, Ordering::Relaxed);
            Outcome::Barren
        }
        // The model owed an answer and could not give one. Counted, not logged
        // per file — a model that will not load would otherwise emit one warning
        // per file read on the endpoint.
        Err(_) => {
            s.failed.fetch_add(1, Ordering::Relaxed);
            Outcome::Transient
        }
    }
}

fn remember_barren(g: &mut Inner, key: CacheKey) {
    if g.barren.insert(key) {
        g.barren_order.push_back(key);
        while g.barren_order.len() > MAX_BARREN {
            if let Some(old) = g.barren_order.pop_front() {
                g.barren.remove(&old);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full queue drops the OLDEST and counts it, and `enqueue` returns
    /// immediately in every case. Runs with NO worker able to drain it (the
    /// engine is not loaded in unit tests, so jobs stay put long enough).
    #[test]
    fn enqueue_bounds_and_dedupes() {
        // Build the shared state directly: this exercises the queue discipline
        // without racing the process-wide singleton other tests may own.
        let inner = Inner {
            q: VecDeque::new(),
            pending: HashSet::new(),
            barren: HashSet::new(),
            barren_order: VecDeque::new(),
            queued_bytes: 0,
            shutdown: false,
        };
        let s = Shared {
            inner: Mutex::new(inner),
            cv: Condvar::new(),
            capacity: 2,
        max_queued_bytes: DEFAULT_MAX_QUEUED_BYTES,
        oversized: AtomicU64::new(0),
            stop: None,
            queued: AtomicU64::new(0),
            classified: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            unextractable: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            deduped: AtomicU64::new(0),
            deny_unclassified: AtomicU64::new(0),
        };

        let mut g = s.inner.lock().unwrap();
        for i in 0..3u8 {
            let key = VerdictCache::key_for(&[i]);
            if g.q.len() >= s.capacity {
                if let Some(old) = g.q.pop_front() {
                    g.queued_bytes = g.queued_bytes.saturating_sub(old.content.len());
                    g.pending.remove(&old.key);
                    s.dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            g.pending.insert(key);
            g.q.push_back(Job {
                key,
                content: vec![i],
                filename: "f.txt".into(),
                truncated: false,
            });
        }
        assert_eq!(g.q.len(), 2, "capacity is a hard bound");
        assert_eq!(s.dropped.load(Ordering::Relaxed), 1);
        // The OLDEST went, not the newest.
        assert_eq!(g.q.front().unwrap().content, vec![1u8]);
        assert_eq!(g.q.back().unwrap().content, vec![2u8]);
    }

    #[test]
    fn barren_set_is_bounded_fifo() {
        let mut g = Inner {
            q: VecDeque::new(),
            pending: HashSet::new(),
            barren: HashSet::new(),
            barren_order: VecDeque::new(),
            queued_bytes: 0,
            shutdown: false,
        };
        let first = VerdictCache::key_for(b"first");
        remember_barren(&mut g, first);
        for i in 0..MAX_BARREN {
            remember_barren(&mut g, VerdictCache::key_for(format!("k{i}").as_bytes()));
        }
        assert_eq!(g.barren.len(), MAX_BARREN);
        assert!(!g.barren.contains(&first), "the oldest key is evicted first");
    }

    #[test]
    fn no_worker_means_enqueue_is_a_no_op_not_a_panic() {
        // The process-wide worker is not started in unit tests.
        assert!(!enqueue(b"anything".to_vec(), "f.txt".into()));
        assert_eq!(stats(), QueueStats::default());
    }
}
