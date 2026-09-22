//! AT CREATION — classify a document the moment it is finished being written.
//!
//! Why this exists
//! ---------------
//! The read path can only ever consult what somebody already classified. Trigger
//! (3) — classify-on-miss, deny, retry — makes the guarantee hold, but it pays
//! for it with a denied read and a user-visible stall the first time a file is
//! opened. This watcher is what makes that the exception instead of the rule: a
//! file written to `C:\` meets the model within seconds of the writer closing it,
//! so by the time RustDesk/AnyDesk/RDP reaches for it the answer is already a
//! HashMap lookup away. The write path deliberately skips fixed volumes (copying
//! C:→C: is not exfiltration), which is exactly why nothing classified these
//! files before this module existed.
//!
//! Settle, do not react
//! --------------------
//! `ReadDirectoryChangesW` fires DURING the write, many times per file: Word
//! writes a temp file, flushes, renames; a download grows for a minute. Reacting
//! to the first notification classifies half a document, burns a forward pass and
//! caches a key that will never be looked up again (the finished file has
//! different bytes, so a different key). So every path goes into a debounce map
//! and is only acted on after `settle_ms` of quiet, with a hard cap
//! (`settle_timeout_ms`) so a file that is appended to forever is still seen once.
//! That is the same shape as the USB copy auditor's settle logic
//! (`src/usb/audit.rs`) — including the injected `now_ms` clock, which is what
//! makes the bookkeeping unit-testable without a real directory — so the two
//! channels behave alike.
//!
//! What it must never do
//! ---------------------
//! * **Never hash the whole file.** The cache key is the SHA-256 of the first
//!   `MAX_HASHED_BYTES` only (contract C1) — the exact bytes the driver ships on
//!   the read path. Hashing more produces a key the read path can never match,
//!   and the cache would look healthy while hitting zero times. Hence
//!   [`cache::read_prefix_for_hashing`], never `fs::read`.
//! * **Never raise an incident** (F5). Classifying a file is not a detection.
//!   Per-file incidents from a background sweep would flood the console and
//!   train reviewers to ignore it.
//! * **Never log a path or any content at info level.** Counters, extensions and
//!   reasons only.
//! * **Never do inference here.** The watcher hands bytes to the bounded
//!   background classifier (`ml::queue`) and moves on; a queue that is full drops
//!   work and increments a counter rather than blocking the watcher thread.
//!
//! Missed events are admitted, not hidden
//! --------------------------------------
//! Under heavy churn the kernel's notification buffer overflows and Windows tells
//! us so (a completion with zero bytes). The changes are gone — there is no way
//! to recover them from the API. The honest response is to mark the scope for the
//! at-rest walker to sweep ([`SweepFlags`]), because pretending nothing was
//! missed is how a file quietly ends up unclassified forever.
//!
//! Cross-platform: everything below the `#[cfg(windows)]` line is pure and
//! builds anywhere; the watcher loop itself is an inert stub off Windows.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;

use super::cache::{self, CacheKey, VerdictCache};
use super::filter::{self, FilterConfig, SkipReason};

/// Quiet period a path must observe before it is considered finished (ms).
pub const DEFAULT_SETTLE_MS: u64 = 2_000;
/// Hard cap on the settle wait: a file still changing at this point is taken
/// once anyway, so an endlessly-appended log is not invisible forever (ms).
pub const DEFAULT_SETTLE_TIMEOUT_MS: u64 = 30_000;
/// Debounce map cap. Bounded like every other endpoint-side structure: a
/// `node_modules` unpack must not be able to grow the agent's heap.
pub const DEFAULT_PENDING_CAP: usize = 4_096;
/// Sharing-violation retries before a path is given up on. A file held open by
/// its writer will be seen again on its next close notification anyway, and the
/// at-rest walker is the backstop.
pub const DEFAULT_MAX_RETRIES: u32 = 5;
/// Notification buffer handed to `ReadDirectoryChangesW`, in bytes. Bigger means
/// fewer overflows under churn; 64 KiB is the practical ceiling for a network
/// path and comfortable for a local one.
pub const NOTIFY_BUFFER_BYTES: usize = 64 * 1024;
/// How long a scope thread blocks before servicing the debounce map. Bounds both
/// settle latency and shutdown latency.
pub const WAIT_SLICE_MS: u32 = 250;

// ---------------------------------------------------------------------------
// The hand-off to the background classifier
// ---------------------------------------------------------------------------

/// One unit of work for the background classifier.
///
/// The bytes are the PREFIX the cache key was computed from, so the consumer
/// must not re-read the file: re-reading could see different content and would
/// store an answer under a key nothing looks up.
///
/// `file_name` is the bare NAME, never the path — the extractor needs the
/// extension to choose a decoder, and a name is the least that discloses. It
/// exists only in memory and on the queue; it is never stored in the cache (C6)
/// and never logged.
pub struct ClassifyJob {
    pub key: CacheKey,
    pub content: Vec<u8>,
    /// The file was longer than [`cache::MAX_HASHED_BYTES`]; the answer will
    /// describe a prefix.
    pub truncated: bool,
    pub file_name: String,
}

/// Where settled files go to be classified.
///
/// A trait rather than a direct call into [`super::queue`] so the enqueue
/// decisions can be unit-tested with no model, no worker thread and no
/// filesystem. [`QueueSink`] is the production implementation and is what
/// callers should pass.
pub trait ClassifySink: Send + Sync {
    /// Hand off one job. Returns `false` when the queue would not take it. MUST
    /// NOT block: this is called from the watcher thread.
    fn submit(&self, job: ClassifyJob) -> bool;
}

/// The production sink: the bounded background classifier in [`super::queue`].
///
/// The key is passed through rather than recomputed — the watcher already
/// hashed this prefix to do its cache lookup, and hashing 4 MiB twice per file
/// is the one avoidable cost on this path.
///
/// `false` from the queue is not necessarily "full": it also covers a duplicate
/// already in flight, bytes already known to yield no text, and "no worker
/// running". None of those is actionable here — the outcome is the same, this
/// watcher does not classify the file itself.
pub struct QueueSink;

impl ClassifySink for QueueSink {
    fn submit(&self, job: ClassifyJob) -> bool {
        super::queue::enqueue_keyed(job.key, job.content, job.file_name, job.truncated)
    }
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

/// Live counters. Monotonic; reported as agent health/coverage. No paths.
#[derive(Debug, Default)]
pub struct WatchStats {
    /// Change notifications accepted into the debounce map.
    pub events: AtomicU64,
    /// Paths that reached the quiet threshold and were acted on.
    pub settled: AtomicU64,
    /// Rejected by [`filter::should_classify`].
    pub skipped: AtomicU64,
    /// Gone by the time we looked (temp files, the common case).
    pub vanished: AtomicU64,
    /// Open/read failed — locked by the writer, or an ACL we do not hold.
    pub unreadable: AtomicU64,
    /// Already in the cache under the loaded model version: nothing to do. This
    /// rising while `enqueued` stays flat is the steady state, not a fault.
    pub already_classified: AtomicU64,
    /// Handed to the background classifier.
    pub enqueued: AtomicU64,
    /// The classifier queue would not take it — full, already in flight, or
    /// known-barren bytes. A rising count against a flat `enqueued` means the
    /// endpoint is producing documents faster than it can classify them; the
    /// at-rest walker backfills what is lost.
    pub refused: AtomicU64,
    /// Pending entries dropped because the debounce map hit its cap.
    pub pending_dropped: AtomicU64,
    /// `ReadDirectoryChangesW` buffer overflows. **Each one means changes were
    /// permanently lost** and the scope needs a walker sweep.
    pub overflows: AtomicU64,
    /// Notifications ignored because the ML policy is inert.
    pub inert: AtomicU64,
}

/// Point-in-time copy of [`WatchStats`], for reporting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct WatchStatsSnapshot {
    pub events: u64,
    pub settled: u64,
    pub skipped: u64,
    pub vanished: u64,
    pub unreadable: u64,
    pub already_classified: u64,
    pub enqueued: u64,
    pub refused: u64,
    pub pending_dropped: u64,
    pub overflows: u64,
    pub inert: u64,
}

impl WatchStats {
    pub fn snapshot(&self) -> WatchStatsSnapshot {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        WatchStatsSnapshot {
            events: g(&self.events),
            settled: g(&self.settled),
            skipped: g(&self.skipped),
            vanished: g(&self.vanished),
            unreadable: g(&self.unreadable),
            already_classified: g(&self.already_classified),
            enqueued: g(&self.enqueued),
            refused: g(&self.refused),
            pending_dropped: g(&self.pending_dropped),
            overflows: g(&self.overflows),
            inert: g(&self.inert),
        }
    }
}

// ---------------------------------------------------------------------------
// Scopes that need a walker sweep
// ---------------------------------------------------------------------------

/// Scopes whose notification stream lost changes, for the at-rest walker to pick
/// up. Set by the watcher, drained by the walker — a shared `Arc`, no channel,
/// because the state is idempotent: "this scope needs a sweep" cannot be marked
/// twice in a way that matters.
#[derive(Debug, Default)]
pub struct SweepFlags {
    inner: Mutex<Vec<PathBuf>>,
}

impl SweepFlags {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a scope as needing a full sweep. Idempotent.
    pub fn mark(&self, scope: &Path) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if !g.iter().any(|p| p == scope) {
            g.push(scope.to_path_buf());
        }
    }

    /// Is this scope currently marked?
    pub fn is_marked(&self, scope: &Path) -> bool {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.iter().any(|p| p == scope)
    }

    /// Take (and clear) every marked scope. The walker calls this.
    pub fn take(&self) -> Vec<PathBuf> {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        std::mem::take(&mut *g)
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// Settle bookkeeping (pure)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Pending {
    first_seen_ms: u64,
    last_event_ms: u64,
    retries: u32,
}

/// A path that has gone quiet and is ready to be looked at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Due {
    pub path: PathBuf,
    /// Forced out by `settle_timeout_ms` while still changing. Reported so a
    /// perpetually-appended file is distinguishable from a finished one.
    pub by_timeout: bool,
    /// How many times this path has already been re-queued after an
    /// unreadable/locked attempt.
    pub retries: u32,
}

/// Debounce map: notifications in, settled paths out, driven by an INJECTED
/// clock so every timing rule is unit-testable.
#[derive(Debug)]
pub struct SettleTracker {
    settle_ms: u64,
    timeout_ms: u64,
    cap: usize,
    pending: HashMap<PathBuf, Pending>,
    dropped: u64,
}

impl SettleTracker {
    pub fn new(settle_ms: u64, timeout_ms: u64, cap: usize) -> Self {
        SettleTracker {
            settle_ms,
            timeout_ms,
            cap: cap.max(1),
            pending: HashMap::new(),
            dropped: 0,
        }
    }

    /// Record a change notification for `path`. An existing entry keeps its
    /// `first_seen_ms` (so the timeout measures the whole write, not the last
    /// buffer) and its retry count.
    ///
    /// At capacity the OLDEST-first-seen entry is dropped and counted, matching
    /// the read path's bounded-queue rule: shed the stalest work, never block
    /// and never grow.
    pub fn note(&mut self, path: PathBuf, now_ms: u64) {
        if let Some(p) = self.pending.get_mut(&path) {
            p.last_event_ms = now_ms;
            return;
        }
        if self.pending.len() >= self.cap {
            if let Some(victim) = self
                .pending
                .iter()
                .min_by_key(|(_, p)| p.first_seen_ms)
                .map(|(k, _)| k.clone())
            {
                self.pending.remove(&victim);
                self.dropped += 1;
            }
        }
        self.pending.insert(
            path,
            Pending {
                first_seen_ms: now_ms,
                last_event_ms: now_ms,
                retries: 0,
            },
        );
    }

    /// Put a path back after an unreadable attempt, if it has retries left.
    /// Returns `false` when the budget is exhausted (the caller then gives up
    /// and leaves the file to the walker).
    pub fn requeue(&mut self, path: PathBuf, retries: u32, now_ms: u64, max_retries: u32) -> bool {
        if retries >= max_retries {
            return false;
        }
        self.pending.insert(
            path,
            Pending {
                first_seen_ms: now_ms,
                last_event_ms: now_ms,
                retries,
            },
        );
        true
    }

    /// Forget a path (it was deleted or renamed away).
    pub fn forget(&mut self, path: &Path) {
        self.pending.remove(path);
    }

    /// Remove and return every path that has been quiet for `settle_ms`, plus
    /// any that has been waiting longer than `timeout_ms`.
    pub fn due(&mut self, now_ms: u64) -> Vec<Due> {
        let mut out = Vec::new();
        let settle_ms = self.settle_ms;
        let timeout_ms = self.timeout_ms;
        let mut ready: Vec<(PathBuf, bool, u32)> = Vec::new();
        for (path, p) in self.pending.iter() {
            let quiet_for = now_ms.saturating_sub(p.last_event_ms);
            let waited = now_ms.saturating_sub(p.first_seen_ms);
            let by_timeout = waited >= timeout_ms && quiet_for < settle_ms;
            if quiet_for >= settle_ms || by_timeout {
                ready.push((path.clone(), by_timeout, p.retries));
            }
        }
        for (path, by_timeout, retries) in ready {
            self.pending.remove(&path);
            out.push(Due {
                path,
                by_timeout,
                retries,
            });
        }
        // Deterministic order so tests and logs are reproducible.
        out.sort_by(|a, b| a.path.cmp(&b.path));
        out
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Entries shed because the map was at capacity.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Drop everything (used when the policy goes inert).
    pub fn clear(&mut self) {
        self.pending.clear();
    }
}

// ---------------------------------------------------------------------------
// What happened to one settled path
// ---------------------------------------------------------------------------

/// Outcome of processing one settled path. Every variant is a counter label;
/// none of them is an incident (F5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchOutcome {
    /// ML policy is inert — the watcher does nothing at all (F3).
    Inert,
    /// The filter said no.
    Skipped(SkipReason),
    /// Gone before we looked (the common case for editor temp files).
    Vanished,
    /// Could not be opened/read. Retried, then abandoned to the walker.
    Unreadable,
    /// Already in the cache under the loaded model version.
    AlreadyClassified,
    /// Handed to the background classifier.
    Enqueued,
    /// The classifier queue would not take it (full, duplicate in flight, or
    /// bytes already known to yield no text).
    Refused,
}

/// The part of the decision that needs no bytes: policy, then the pure filter.
///
/// `meta` is `None` when the path could not be stat'ed (vanished), and
/// `Some((is_file, size))` otherwise. Returns `Some(outcome)` when the answer is
/// already final, and `None` when the caller must go and read the prefix.
///
/// Pure — this is the half of the watcher that a unit test can drive.
pub fn pre_read_decision(
    policy_inert: bool,
    path: &Path,
    meta: Option<(bool, u64)>,
    fcfg: &FilterConfig,
) -> Option<WatchOutcome> {
    if policy_inert {
        return Some(WatchOutcome::Inert);
    }
    let Some((is_file, size)) = meta else {
        return Some(WatchOutcome::Vanished);
    };
    if !is_file {
        // A directory notification is not a document. Not "skipped" — there was
        // never a file here to classify.
        return Some(WatchOutcome::Vanished);
    }
    match filter::should_classify(path, size, fcfg) {
        filter::Decision::Skip(reason) => Some(WatchOutcome::Skipped(reason)),
        filter::Decision::Classify => None,
    }
}

/// The other pure half: what to do once the prefix is in hand and the cache has
/// been consulted. `submitted` is the sink's answer.
pub fn post_read_outcome(cache_hit: bool, submitted: bool) -> WatchOutcome {
    if cache_hit {
        WatchOutcome::AlreadyClassified
    } else if submitted {
        WatchOutcome::Enqueued
    } else {
        WatchOutcome::Refused
    }
}

// ---------------------------------------------------------------------------
// The watcher
// ---------------------------------------------------------------------------

/// Everything the watcher needs that is not global state.
#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// Directory trees to watch, recursively. Typically the user profile root
    /// and any data volumes — never `C:\` whole, which would drown the debounce
    /// map in OS churn the filter would only throw away again.
    pub scopes: Vec<PathBuf>,
    pub settle_ms: u64,
    pub settle_timeout_ms: u64,
    pub pending_cap: usize,
    pub max_retries: u32,
    pub filter: FilterConfig,
}

impl Default for WatchConfig {
    fn default() -> Self {
        WatchConfig {
            scopes: Vec::new(),
            settle_ms: DEFAULT_SETTLE_MS,
            settle_timeout_ms: DEFAULT_SETTLE_TIMEOUT_MS,
            pending_cap: DEFAULT_PENDING_CAP,
            max_retries: DEFAULT_MAX_RETRIES,
            filter: FilterConfig::default(),
        }
    }
}

/// The at-creation watcher: debounce map, cache, sink and counters.
///
/// Shared by every scope thread behind an `Arc`; the only mutable state is the
/// tracker, behind a `Mutex` held for the length of a map operation and never
/// across I/O.
pub struct CreationWatcher {
    cfg: WatchConfig,
    cache: Arc<VerdictCache>,
    sink: Arc<dyn ClassifySink>,
    tracker: Mutex<SettleTracker>,
    stats: Arc<WatchStats>,
    sweep: Arc<SweepFlags>,
}

impl CreationWatcher {
    pub fn new(cfg: WatchConfig, cache: Arc<VerdictCache>, sink: Arc<dyn ClassifySink>) -> Self {
        let tracker = SettleTracker::new(cfg.settle_ms, cfg.settle_timeout_ms, cfg.pending_cap);
        CreationWatcher {
            cfg,
            cache,
            sink,
            tracker: Mutex::new(tracker),
            stats: Arc::new(WatchStats::default()),
            sweep: Arc::new(SweepFlags::new()),
        }
    }

    /// Construction for the service: the process-wide verdict cache published by
    /// `queue::open_and_start`, plus the real queue sink.
    ///
    /// `None` when no cache has been published — with no cache there is nothing
    /// for a producer to fill and every path already behaves exactly as the
    /// pre-cache agent did (F3), so the right answer is not to start the threads.
    pub fn with_shared_queue(cfg: WatchConfig) -> Option<Self> {
        let cache = super::queue::verdict_cache()?;
        Some(Self::new(cfg, cache, Arc::new(QueueSink)))
    }

    pub fn stats(&self) -> Arc<WatchStats> {
        Arc::clone(&self.stats)
    }

    /// Scopes that lost notifications and need a walker sweep.
    pub fn sweep_flags(&self) -> Arc<SweepFlags> {
        Arc::clone(&self.sweep)
    }

    pub fn config(&self) -> &WatchConfig {
        &self.cfg
    }

    /// Record one change notification.
    pub fn notice(&self, path: PathBuf, now_ms: u64) {
        self.stats.events.fetch_add(1, Ordering::Relaxed);
        let mut t = self.tracker.lock().unwrap_or_else(|p| p.into_inner());
        let before = t.dropped();
        t.note(path, now_ms);
        let dropped = t.dropped() - before;
        if dropped > 0 {
            self.stats
                .pending_dropped
                .fetch_add(dropped, Ordering::Relaxed);
        }
    }

    /// A path went away (deleted, or renamed to something else).
    pub fn forget(&self, path: &Path) {
        let mut t = self.tracker.lock().unwrap_or_else(|p| p.into_inner());
        t.forget(path);
    }

    /// Process everything that has settled by `now_ms`. Returns the outcomes so
    /// the caller (and the tests) can see what happened; production callers
    /// ignore the vector and read the counters.
    pub fn pump(&self, now_ms: u64) -> Vec<(PathBuf, WatchOutcome)> {
        let policy = crate::mlpolicy::active();
        if policy.is_inert() {
            // F3: an inert policy produces byte-identical behaviour to the
            // pre-cache agent — nothing is read, nothing is classified, nothing
            // is remembered.
            let mut t = self.tracker.lock().unwrap_or_else(|p| p.into_inner());
            if !t.is_empty() {
                self.stats
                    .inert
                    .fetch_add(t.len() as u64, Ordering::Relaxed);
                t.clear();
            }
            return Vec::new();
        }

        let due = {
            let mut t = self.tracker.lock().unwrap_or_else(|p| p.into_inner());
            t.due(now_ms)
        };

        // ONE definition of "which model's answers count" for every producer and
        // the read path alike (contract C3). Asking the policy directly here
        // would make this watcher's lookups miss every entry the queue deposited
        // under the loaded ENGINE's version, and it would re-enqueue the same
        // file after every write, forever.
        let model_version = super::queue::model_version_for_cache();

        let mut out = Vec::with_capacity(due.len());
        for item in due {
            self.stats.settled.fetch_add(1, Ordering::Relaxed);
            let outcome = self.process(&item.path, &model_version);
            if outcome == WatchOutcome::Unreadable {
                // Locked by its writer: give it another settle window rather
                // than losing it. Exhausted budgets fall through to the walker.
                let mut t = self.tracker.lock().unwrap_or_else(|p| p.into_inner());
                t.requeue(
                    item.path.clone(),
                    item.retries + 1,
                    now_ms,
                    self.cfg.max_retries,
                );
            }
            out.push((item.path, outcome));
        }
        out
    }

    /// One settled path, start to finish. This is the only method that touches
    /// the disk.
    fn process(&self, path: &Path, model_version: &str) -> WatchOutcome {
        let meta = std::fs::metadata(path)
            .ok()
            .map(|m| (m.is_file(), m.len()));

        if let Some(outcome) = pre_read_decision(false, path, meta, &self.cfg.filter) {
            match outcome {
                WatchOutcome::Skipped(_) => {
                    self.stats.skipped.fetch_add(1, Ordering::Relaxed);
                }
                WatchOutcome::Vanished => {
                    self.stats.vanished.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
            return outcome;
        }

        // CONTRACT C1: the KEY is always the first min(size, 4 MiB) bytes and not
        // one more — the exact prefix the driver hashes and ships on the read path.
        // The bytes we EXTRACT from may reach further: a >4 MiB .docx or .pdf has
        // its central directory / xref at the end, so a prefix does not parse at
        // all and the file would be permanently unclassifiable. `read_for_classification`
        // keeps the key on the prefix and escalates only those formats.
        let prepared = match cache::read_for_classification(path, self.cfg.filter.max_file_bytes as usize) {
            Ok(v) => v,
            Err(_) => {
                self.stats.unreadable.fetch_add(1, Ordering::Relaxed);
                return WatchOutcome::Unreadable;
            }
        };
        let (content, truncated) = (prepared.content, prepared.truncated);
        if content.is_empty() {
            // Raced with a truncation between stat and open.
            self.stats.skipped.fetch_add(1, Ordering::Relaxed);
            return WatchOutcome::Skipped(SkipReason::Empty);
        }

        let key = prepared.key;
        if self.cache.get(&key, model_version).is_some() {
            self.stats
                .already_classified
                .fetch_add(1, Ordering::Relaxed);
            return post_read_outcome(true, false);
        }

        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let submitted = self.sink.submit(ClassifyJob {
            key,
            content,
            truncated,
            file_name,
        });
        if submitted {
            self.stats.enqueued.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.refused.fetch_add(1, Ordering::Relaxed);
        }
        post_read_outcome(false, submitted)
    }

    /// Record a lost-notification event for `scope` and mark it for the walker.
    pub fn note_overflow(&self, scope: &Path) {
        self.stats.overflows.fetch_add(1, Ordering::Relaxed);
        self.sweep.mark(scope);
        tracing::warn!(
            scope_depth = scope.components().count(),
            "ml watcher: change-notification buffer overflowed — scope marked for at-rest sweep"
        );
    }
}

/// Monotonic milliseconds since the first call. Immune to wall-clock changes,
/// which matters because every settle rule is a difference of two of these.
pub fn now_ms() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

// ---------------------------------------------------------------------------
// Windows: the ReadDirectoryChangesW loop
// ---------------------------------------------------------------------------

/// Spawn one watcher thread per configured scope. Threads exit when `stop` is
/// set; join the handles for a clean shutdown.
///
/// Nothing is spawned when the scope list is empty, and a scope that cannot be
/// opened is logged and skipped — one unreachable drive must not take the other
/// scopes down with it.
pub fn spawn(
    watcher: Arc<CreationWatcher>,
    stop: Arc<AtomicBool>,
) -> Vec<std::thread::JoinHandle<()>> {
    let mut handles = Vec::new();
    for scope in watcher.config().scopes.clone() {
        let w = Arc::clone(&watcher);
        let s = Arc::clone(&stop);
        let name = format!("ml-watch-{}", handles.len());
        match std::thread::Builder::new()
            .name(name)
            .spawn(move || run_scope(&w, &scope, &s))
        {
            Ok(h) => handles.push(h),
            Err(e) => tracing::warn!(error = %e, "ml watcher: could not spawn scope thread"),
        }
    }
    handles
}

#[cfg(windows)]
pub fn run_scope(watcher: &CreationWatcher, scope: &Path, stop: &AtomicBool) {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadDirectoryChangesW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED,
        FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
    use windows::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};

    let wide: Vec<u16> = scope
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // FILE_LIST_DIRECTORY + BACKUP_SEMANTICS is the only way to get a handle to
    // a DIRECTORY; OVERLAPPED is what lets the wait be interruptible, which is
    // what makes shutdown prompt instead of "whenever the next file changes".
    // Full sharing: we must never be the reason another process cannot rename or
    // delete a directory.
    let dir: HANDLE = match unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_LIST_DIRECTORY.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            None,
        )
    } {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = %e, "ml watcher: cannot open watch scope — skipping it");
            return;
        }
    };

    let event: HANDLE = match unsafe { CreateEventW(None, true, false, PCWSTR::null()) } {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = %e, "ml watcher: cannot create wait event — scope not watched");
            unsafe { let _ = CloseHandle(dir); };
            return;
        }
    };

    // DWORD-aligned buffer: FILE_NOTIFY_INFORMATION records must be, and a
    // Vec<u32> guarantees it where a Vec<u8> does not.
    let mut buf: Vec<u32> = vec![0; NOTIFY_BUFFER_BYTES / 4];
    let filter = FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME;

    tracing::info!(
        settle_ms = watcher.config().settle_ms,
        "ml watcher: watching a scope for at-creation classification"
    );

    // The OVERLAPPED lives OUTSIDE the loop, in a Box, so its address is stable
    // for the whole life of this thread.
    //
    // WHY THIS MATTERS (this was a crash): `ReadDirectoryChangesW` hands the
    // kernel a pointer to this structure and to `buf`, and the kernel writes into
    // BOTH when the I/O completes — which may be long after the call returns. A
    // per-iteration stack `OVERLAPPED` that is abandoned while its I/O is still
    // pending therefore gets written by the kernel after the frame is gone,
    // corrupting the stack. Windows traps that as STATUS_STACK_BUFFER_OVERRUN
    // (0xC0000409) and the whole service dies — with no panic, no log line, and a
    // WER bucket that just says BEX64. Under heavy churn (a scope covering a whole
    // volume) it took about half an hour to hit.
    //
    // Two rules keep it safe, and every path below obeys them:
    //   1. one stable OVERLAPPED and one stable buffer for the thread's lifetime;
    //   2. NEVER re-issue or return while an I/O is pending — cancel it and WAIT
    //      for the completion first (`drain_pending`).
    let mut ovl = Box::new(OVERLAPPED { hEvent: event, ..Default::default() });

    'outer: while !stop.load(Ordering::Relaxed) {
        // Re-arm the same allocation rather than making a new one.
        *ovl = OVERLAPPED { hEvent: event, ..Default::default() };

        let issued = unsafe {
            ReadDirectoryChangesW(
                dir,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                (buf.len() * 4) as u32,
                true, // recursive
                filter,
                None,
                Some(&mut *ovl),
                None,
            )
        };
        if let Err(e) = issued {
            // ERROR_NOTIFY_ENUM_DIR and friends: the stream is not usable right
            // now and changes are being missed. Say so, and let the walker cover
            // the gap rather than looping hot.
            tracing::warn!(error = %e, "ml watcher: ReadDirectoryChangesW failed");
            watcher.note_overflow(scope);
            std::thread::sleep(std::time::Duration::from_millis(1_000));
            continue;
        }

        // Interruptible wait: service the debounce map on every slice so settle
        // latency does not depend on the next notification arriving.
        let bytes = loop {
            if stop.load(Ordering::Relaxed) {
                drain_pending(dir, &ovl);
                break 'outer;
            }
            match unsafe { WaitForSingleObject(event, WAIT_SLICE_MS) } {
                WAIT_OBJECT_0 => {
                    let mut n = 0u32;
                    match unsafe { GetOverlappedResult(dir, &*ovl, &mut n, false) } {
                        Ok(()) => break n,
                        Err(e) => {
                            // Changes were lost. Fall through with zero bytes so
                            // the single overflow path below marks the scope —
                            // marking it here too would double-count it.
                            //
                            // CANCEL FIRST. This arm is also reached with
                            // ERROR_IO_INCOMPLETE (a signalled event does not
                            // prove the read finished), and re-issuing while the
                            // old I/O is live is what corrupted the stack. Drain
                            // it before touching the buffer or the OVERLAPPED
                            // again — see the note above the declaration.
                            tracing::warn!(error = %e, "ml watcher: overlapped result failed");
                            drain_pending(dir, &ovl);
                            break 0;
                        }
                    }
                }
                WAIT_TIMEOUT => {
                    watcher.pump(now_ms());
                }
                other => {
                    tracing::warn!(code = other.0, "ml watcher: wait failed — restarting scope");
                    drain_pending(dir, &ovl);
                    break 'outer;
                }
            }
        };

        if bytes == 0 {
            // Zero bytes with a successful completion is how Windows reports
            // that its internal buffer overflowed: the changes are GONE. Do not
            // pretend otherwise (see the module header).
            watcher.note_overflow(scope);
        } else {
            let raw = unsafe {
                std::slice::from_raw_parts(buf.as_ptr() as *const u8, bytes as usize)
            };
            for (rel, action) in parse_notifications(raw) {
                let full = scope.join(&rel);
                match action {
                    // Deleted / renamed away: stop tracking it.
                    2 | 4 => watcher.forget(&full),
                    _ => watcher.notice(full, now_ms()),
                }
            }
        }
        watcher.pump(now_ms());
    }

    unsafe {
        let _ = CloseHandle(event);
        let _ = CloseHandle(dir);
    }
    tracing::info!("ml watcher: scope thread stopped");
}

/// Non-Windows: an inert stub so the crate keeps cross-compiling (the pure
/// settle/filter logic above is what the tests exercise anyway).
#[cfg(not(windows))]
pub fn run_scope(_watcher: &CreationWatcher, _scope: &Path, _stop: &AtomicBool) {}

/// Cancel a possibly-pending directory-change read and BLOCK until the kernel is
/// finished with the buffer and the `OVERLAPPED`.
///
/// The blocking wait is the entire point: `CancelIoEx` only *requests*
/// cancellation, and until the completion is collected the kernel may still write
/// into both. Returning or re-issuing before that is a use-after-scope that
/// presents as a 0xC0000409 process abort with nothing in the log.
#[cfg(windows)]
fn drain_pending(
    dir: windows::Win32::Foundation::HANDLE,
    ovl: &windows::Win32::System::IO::OVERLAPPED,
) {
    use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult};
    unsafe {
        let _ = CancelIoEx(dir, Some(ovl));
        let mut n = 0u32;
        // bWait = true: wait for the cancellation to actually land.
        let _ = GetOverlappedResult(dir, ovl, &mut n, true);
    }
}

/// Walk a `ReadDirectoryChangesW` buffer into `(relative path, action)` pairs.
///
/// Pure and platform-independent so the framing — variable-length records, a
/// byte (not character) length, `NextEntryOffset == 0` terminating the chain —
/// is unit-tested rather than trusted. A malformed or truncated chain stops the
/// walk instead of walking off the end of the buffer.
pub fn parse_notifications(raw: &[u8]) -> Vec<(PathBuf, u32)> {
    const HEADER: usize = 12; // NextEntryOffset + Action + FileNameLength
    let mut out = Vec::new();
    let mut off = 0usize;
    loop {
        if off + HEADER > raw.len() {
            break;
        }
        let next = u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]) as usize;
        let action =
            u32::from_le_bytes([raw[off + 4], raw[off + 5], raw[off + 6], raw[off + 7]]);
        let name_len =
            u32::from_le_bytes([raw[off + 8], raw[off + 9], raw[off + 10], raw[off + 11]]) as usize;

        let start = off + HEADER;
        let end = start.saturating_add(name_len);
        if name_len % 2 != 0 || end > raw.len() {
            break; // truncated / malformed: stop, never over-read
        }
        let units: Vec<u16> = raw[start..end]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let name = String::from_utf16_lossy(&units);
        if !name.is_empty() {
            out.push((PathBuf::from(name), action));
        }

        if next == 0 || off + next <= off {
            break;
        }
        off += next;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    // --- settle bookkeeping ---------------------------------------------

    fn tracker() -> SettleTracker {
        SettleTracker::new(2_000, 30_000, 4)
    }

    #[test]
    fn a_path_is_not_due_until_it_has_been_quiet() {
        let mut t = tracker();
        t.note(PathBuf::from(r"C:\d\a.docx"), 1_000);
        assert!(t.due(2_000).is_empty(), "still inside the quiet window");
        assert!(t.due(2_999).is_empty());
        let due = t.due(3_000);
        assert_eq!(due.len(), 1);
        assert!(!due[0].by_timeout);
        assert!(t.is_empty(), "a settled path leaves the map");
    }

    #[test]
    fn each_notification_restarts_the_quiet_window() {
        let mut t = tracker();
        let p = PathBuf::from(r"C:\d\big.pdf");
        t.note(p.clone(), 0);
        t.note(p.clone(), 1_500); // still being written
        assert!(t.due(2_000).is_empty(), "window restarted at 1500");
        assert_eq!(t.due(3_500).len(), 1);
    }

    #[test]
    fn a_file_written_forever_is_force_settled_by_the_timeout() {
        let mut t = tracker();
        let p = PathBuf::from(r"C:\d\growing.log");
        t.note(p.clone(), 0);
        for ms in (1_000..=30_000).step_by(1_000) {
            t.note(p.clone(), ms);
            if ms < 30_000 {
                assert!(t.due(ms).is_empty(), "never quiet, not yet timed out at {ms}");
            }
        }
        let due = t.due(30_000);
        assert_eq!(due.len(), 1);
        assert!(due[0].by_timeout, "forced out by the settle timeout");
    }

    #[test]
    fn the_pending_map_is_bounded_and_sheds_the_oldest() {
        let mut t = SettleTracker::new(2_000, 30_000, 2);
        t.note(PathBuf::from("a.txt"), 100);
        t.note(PathBuf::from("b.txt"), 200);
        t.note(PathBuf::from("c.txt"), 300); // evicts a.txt (oldest first-seen)
        assert_eq!(t.len(), 2);
        assert_eq!(t.dropped(), 1);
        let due: Vec<_> = t.due(10_000).into_iter().map(|d| d.path).collect();
        assert_eq!(due, vec![PathBuf::from("b.txt"), PathBuf::from("c.txt")]);
    }

    #[test]
    fn deleted_paths_are_forgotten() {
        let mut t = tracker();
        t.note(PathBuf::from("gone.docx"), 0);
        t.forget(Path::new("gone.docx"));
        assert!(t.due(10_000).is_empty());
    }

    #[test]
    fn requeue_is_bounded_by_the_retry_budget() {
        let mut t = tracker();
        let p = PathBuf::from("locked.docx");
        assert!(t.requeue(p.clone(), 1, 0, 5));
        assert_eq!(t.due(5_000)[0].retries, 1);
        assert!(!t.requeue(p, 5, 0, 5), "budget exhausted");
        assert!(t.is_empty());
    }

    // --- the pure decision -----------------------------------------------

    #[test]
    fn an_inert_policy_stops_everything_before_any_io() {
        let cfg = FilterConfig::default();
        let d = pre_read_decision(true, Path::new(r"C:\Users\a\x.docx"), Some((true, 10)), &cfg);
        assert_eq!(d, Some(WatchOutcome::Inert));
    }

    #[test]
    fn a_vanished_or_non_file_path_needs_no_read() {
        let cfg = FilterConfig::default();
        assert_eq!(
            pre_read_decision(false, Path::new(r"C:\Users\a\x.docx"), None, &cfg),
            Some(WatchOutcome::Vanished)
        );
        assert_eq!(
            pre_read_decision(false, Path::new(r"C:\Users\a\sub"), Some((false, 0)), &cfg),
            Some(WatchOutcome::Vanished)
        );
    }

    #[test]
    fn a_filtered_path_needs_no_read_and_carries_its_reason() {
        let cfg = FilterConfig::default();
        assert_eq!(
            pre_read_decision(false, Path::new(r"C:\Users\a\app.exe"), Some((true, 10)), &cfg),
            Some(WatchOutcome::Skipped(SkipReason::UnsupportedExtension))
        );
        assert_eq!(
            pre_read_decision(false, Path::new(r"C:\Users\a\x.docx"), Some((true, 0)), &cfg),
            Some(WatchOutcome::Skipped(SkipReason::Empty))
        );
    }

    #[test]
    fn a_classifiable_path_falls_through_to_the_read() {
        let cfg = FilterConfig::default();
        assert_eq!(
            pre_read_decision(
                false,
                Path::new(r"C:\Users\a\Docs\plan.docx"),
                Some((true, 4_096)),
                &cfg
            ),
            None
        );
    }

    #[test]
    fn post_read_outcomes_cover_hit_enqueue_and_full() {
        assert_eq!(post_read_outcome(true, false), WatchOutcome::AlreadyClassified);
        assert_eq!(post_read_outcome(false, true), WatchOutcome::Enqueued);
        assert_eq!(post_read_outcome(false, false), WatchOutcome::Refused);
    }

    // --- sweep flags ------------------------------------------------------

    #[test]
    fn sweep_flags_are_idempotent_and_drainable() {
        let f = SweepFlags::new();
        f.mark(Path::new(r"C:\Users"));
        f.mark(Path::new(r"C:\Users"));
        f.mark(Path::new(r"D:\Data"));
        assert_eq!(f.len(), 2);
        assert!(f.is_marked(Path::new(r"D:\Data")));
        let taken = f.take();
        assert_eq!(taken.len(), 2);
        assert!(f.is_empty(), "taking clears the marks for the walker");
    }

    // --- notification framing ---------------------------------------------

    fn notify_record(next: u32, action: u32, name: &str) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut v = Vec::new();
        v.extend_from_slice(&next.to_le_bytes());
        v.extend_from_slice(&action.to_le_bytes());
        v.extend_from_slice(&((units.len() * 2) as u32).to_le_bytes());
        for u in units {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v
    }

    #[test]
    fn notification_chain_is_walked_to_its_terminator() {
        let first = notify_record(0, 1, r"Docs\a.docx");
        let len = first.len() as u32;
        let mut raw = notify_record(len, 1, r"Docs\a.docx");
        raw.extend(notify_record(0, 3, "b.pdf"));
        let parsed = parse_notifications(&raw);
        assert_eq!(
            parsed,
            vec![
                (PathBuf::from(r"Docs\a.docx"), 1u32),
                (PathBuf::from("b.pdf"), 3u32)
            ]
        );
    }

    #[test]
    fn a_truncated_notification_buffer_stops_the_walk() {
        let full = notify_record(0, 1, "report.docx");
        let parsed = parse_notifications(&full[..full.len() - 4]);
        assert!(parsed.is_empty(), "never over-read a torn record");
        assert!(parse_notifications(&[]).is_empty());
        assert!(parse_notifications(&[0, 0, 0]).is_empty());
    }

    // --- the sink contract -------------------------------------------------

    struct CountingSink {
        accepted: AtomicUsize,
        refused: AtomicUsize,
        accept: bool,
    }

    impl ClassifySink for CountingSink {
        fn submit(&self, job: ClassifyJob) -> bool {
            assert!(!job.content.is_empty(), "never enqueue an empty job");
            if self.accept {
                self.accepted.fetch_add(1, Ordering::Relaxed);
                true
            } else {
                self.refused.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    // --- one settled file, end to end, over a real directory ---------------
    //
    // `process()` is called directly rather than through `pump()` so this test
    // never touches the process-wide ML policy (which the other tests in this
    // binary share). What it exercises is the part that needs a filesystem: the
    // prefix read, the key, the cache consultation and the hand-off.

    struct CapturingSink(Mutex<Vec<(CacheKey, usize, bool, String)>>);

    impl ClassifySink for CapturingSink {
        fn submit(&self, job: ClassifyJob) -> bool {
            self.0.lock().unwrap().push((
                job.key,
                job.content.len(),
                job.truncated,
                job.file_name,
            ));
            true
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dlp-ml-watch-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_settled_file_is_hashed_on_its_prefix_enqueued_once_and_then_known() {
        const MV: &str = "test-model/v1";
        let root = temp_dir("e2e");
        let cache = Arc::new(VerdictCache::open(&root.join("cache"), 64).unwrap());
        let sink = Arc::new(CapturingSink(Mutex::new(Vec::new())));

        let doc = root.join("plan.txt");
        let body = b"quarterly reactor maintenance plan".to_vec();
        std::fs::write(&doc, &body).unwrap();

        let mut cfg = WatchConfig::default();
        cfg.filter = FilterConfig::with_state_dir(root.join("cache"));
        // The fixture lives under the OS temp tree, which the default filter
        // (correctly) excludes. Drop just that rule so the rest of the pipeline
        // is what this test measures — the exclusion itself is pinned by
        // tests/ml_filter.rs.
        cfg.filter
            .excluded_components
            .retain(|c| c != "temp" && c != "tmp");
        let w = CreationWatcher::new(cfg, Arc::clone(&cache), sink.clone());

        // 1. First sight: enqueued, with the key taken from the file's bytes.
        assert_eq!(w.process(&doc, MV), WatchOutcome::Enqueued);
        let jobs = sink.0.lock().unwrap().clone();
        assert_eq!(jobs.len(), 1);
        let (key, len, truncated, name) = jobs[0].clone();
        assert_eq!(
            key,
            VerdictCache::key_for(&body),
            "C1: the key is the SHA-256 of the bytes the driver would ship"
        );
        assert_eq!(len, body.len());
        assert!(!truncated);
        assert_eq!(name, "plan.txt", "the NAME travels, never the path");

        // 2. Once the classifier has deposited an answer, the same file is known
        //    and no second job is produced.
        cache
            .put(
                key,
                cache::CachedVerdict {
                    model_version: MV.to_string(),
                    label_id: "NUC".into(),
                    label_index: 7,
                    confidence: 0.97,
                    chunks: 1,
                    tokens: 12,
                    truncated: false,
                    classified_at: 1_700_000_000,
                },
            )
            .unwrap();
        assert_eq!(w.process(&doc, MV), WatchOutcome::AlreadyClassified);
        assert_eq!(sink.0.lock().unwrap().len(), 1, "no duplicate job");

        // 3. A DIFFERENT model version makes the same entry stale ⇒ re-queued.
        assert_eq!(w.process(&doc, "test-model/v2"), WatchOutcome::Enqueued);

        // 4. The cache's own log lives under the excluded state dir.
        let log = root.join("cache").join("ml-verdicts.log");
        if log.exists() {
            assert!(
                matches!(w.process(&log, MV), WatchOutcome::Skipped(_)),
                "the watcher must never classify its own verdict log"
            );
        }

        // 5. Filtered and vanished paths need no bytes.
        let exe = root.join("setup.exe");
        std::fs::write(&exe, b"MZ").unwrap();
        assert_eq!(
            w.process(&exe, MV),
            WatchOutcome::Skipped(SkipReason::UnsupportedExtension)
        );
        assert_eq!(
            w.process(&root.join("never-existed.docx"), MV),
            WatchOutcome::Vanished
        );

        let s = w.stats().snapshot();
        assert_eq!(s.enqueued, 2);
        assert_eq!(s.already_classified, 1);
        assert_eq!(s.vanished, 1);
        assert!(s.skipped >= 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// LIVE test: a real `ReadDirectoryChangesW` thread over a real directory.
    ///
    /// `#[ignore]` by design, for two reasons: it takes seconds (it must wait out
    /// a settle window), and it publishes a non-inert ML policy into the
    /// process-wide store that every other test in this binary shares. Run it on
    /// its own:
    ///
    /// ```text
    /// cargo test --lib ml::watch::tests::live -- --ignored --test-threads=1
    /// ```
    #[test]
    #[ignore = "spawns a live directory-watch thread; run explicitly"]
    fn live_watcher_notices_a_created_file_and_enqueues_it_once_settled() {
        use crate::mlpolicy::{MlLabelRule, MlPolicy};
        use std::sync::atomic::AtomicBool;

        const MV: &str = "test-model/v1";
        let root = temp_dir("live");
        let cache = Arc::new(VerdictCache::open(&root.join("cache"), 64).unwrap());
        let sink = Arc::new(CapturingSink(Mutex::new(Vec::new())));

        // The watcher does nothing while the policy is inert (F3), so a live run
        // has to publish one.
        let previous = crate::mlpolicy::active();
        crate::mlpolicy::set_active(MlPolicy {
            enabled: true,
            model_version: MV.to_string(),
            labels: vec![MlLabelRule {
                id: "NUC".into(),
                min_confidence: None,
            }],
            ..MlPolicy::default()
        });

        let mut cfg = WatchConfig::default();
        cfg.scopes = vec![root.clone()];
        cfg.settle_ms = 300;
        cfg.settle_timeout_ms = 2_000;
        cfg.filter = FilterConfig::with_state_dir(root.join("cache"));
        cfg.filter
            .excluded_components
            .retain(|c| c != "temp" && c != "tmp");

        let watcher = Arc::new(CreationWatcher::new(cfg, cache, sink.clone()));
        let stop = Arc::new(AtomicBool::new(false));
        let handles = spawn(Arc::clone(&watcher), Arc::clone(&stop));
        assert_eq!(handles.len(), 1, "one thread per scope");

        std::thread::sleep(std::time::Duration::from_millis(300));
        std::fs::write(root.join("sub_created.txt"), b"a document written live").unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while std::time::Instant::now() < deadline
            && watcher.stats().snapshot().enqueued == 0
        {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        stop.store(true, Ordering::Relaxed);
        for h in handles {
            let _ = h.join();
        }
        crate::mlpolicy::set_active(previous);

        let s = watcher.stats().snapshot();
        let _ = std::fs::remove_dir_all(&root);
        assert!(s.events > 0, "no change notifications arrived at all");
        assert_eq!(s.enqueued, 1, "the created file should be classified once");
        assert_eq!(sink.0.lock().unwrap()[0].3, "sub_created.txt");
    }

    #[test]
    fn a_full_queue_is_counted_not_blocked_on() {
        let sink = CountingSink {
            accepted: AtomicUsize::new(0),
            refused: AtomicUsize::new(0),
            accept: false,
        };
        let refused = sink.submit(ClassifyJob {
            key: VerdictCache::key_for(b"x"),
            content: b"x".to_vec(),
            truncated: false,
            file_name: "x.txt".into(),
        });
        assert!(!refused);
        assert_eq!(sink.refused.load(Ordering::Relaxed), 1);
        assert_eq!(post_read_outcome(false, refused), WatchOutcome::Refused);
    }
}
