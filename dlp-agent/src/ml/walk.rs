//! AT REST — the discovery walker that backfills everything the watcher never saw.
//!
//! Why this exists
//! ---------------
//! The at-creation watcher ([`super::watch`]) only ever sees files written while
//! the agent is running and while the notification stream keeps up. That leaves
//! three holes, and every one of them is a document that would be adjudicated on
//! fingerprints alone if an exfil tool reached for it:
//!
//! * files that PREDATE the agent — on a machine enrolled today, that is every
//!   document the employee has ever had;
//! * files that arrived while the service was STOPPED (update, reboot, crash);
//! * files lost to a `ReadDirectoryChangesW` BUFFER OVERFLOW — the changes are
//!   gone from the API, and the watcher admits it by marking the scope in
//!   [`SweepFlags`] rather than pretending nothing was missed.
//!
//! This walker is therefore the component that makes `denyUnclassified` SAFE TO
//! ENABLE. Turning that flag on before the estate has been swept would deny the
//! first read of every legacy file on every endpoint. The rollout is: deploy →
//! walker completes → verify coverage → enable, which is why "a full sweep
//! finished at T covering N files" is persisted as a first-class fact
//! ([`SweepCompletion`]) and not merely logged.
//!
//! It runs on somebody's work PC
//! -----------------------------
//! A background process that reads every document on a laptop is how a security
//! product gets uninstalled. Three throttles, in order of how much they matter,
//! and deliberately no more than three — a real idle-detection scheme (CPU
//! counters, input-idle time, power source) would need OS APIs this crate does
//! not enable and would still be guessing:
//!
//! 1. **A files-per-minute budget** ([`RateLimiter`], default
//!    [`DEFAULT_FILES_PER_MINUTE`]). A hard ceiling on the only expensive thing
//!    the walker does — reading a ≤4 MiB prefix off disk. It is a token bucket
//!    with a small burst so a sparse directory tree still moves, and it is fed an
//!    INJECTED clock, so the limiter is unit-tested without a single sleep.
//! 2. **Queue backpressure**. If the background classifier's queue is already
//!    deep ([`WalkConfig::queue_pause_depth`]) the machine is busy doing OUR
//!    inference; adding files to the pile only makes the user's fans louder and
//!    risks evicting newer work. Pause until it drains. This is the closest
//!    thing to an honest "is the machine busy?" signal that costs nothing.
//! 3. **I/O contention, measured by our own reads**. If reading one prefix took
//!    longer than [`WalkConfig::slow_read_ms`], the disk is serving somebody else
//!    — the user. Charge the bucket extra tokens so the walker naturally yields
//!    to a busy disk and speeds back up when it goes quiet. A proxy, not a
//!    measurement, and labelled as one.
//!
//! Resumable, idempotent, honest about coverage
//! --------------------------------------------
//! A sweep of a laptop takes hours at a modest rate, so it must survive a reboot:
//! the cursor (scope, pending directories, counts) is checkpointed to the state
//! directory with a temp-file + rename swap, so a crash can lose progress but can
//! never leave a half-written checkpoint. A resumed or repeated sweep is cheap by
//! construction: an already-cached, non-stale key costs one ≤4 MiB hash and
//! nothing else — no extraction, no forward pass.
//!
//! What it must never do
//! ---------------------
//! * **Never hash the whole file** — the key is the SHA-256 of the first
//!   [`cache::MAX_HASHED_BYTES`] bytes and not one byte more (contract C1), so
//!   this module goes through [`cache::read_prefix_for_hashing`] exactly like the
//!   watcher does. A key built from a whole file can never match the key the read
//!   path builds from the driver's prefix, and the cache would look healthy while
//!   hitting zero times.
//! * **Never raise an incident** (F5). A sweep classifies; it does not detect.
//!   Per-file incidents from a background walk would flood the console on day one.
//! * **Never run inference here.** The walker hands bytes to [`super::queue`] and
//!   moves on; the queue is bounded and drops work rather than growing.
//! * **Never do anything at all when the policy is inert** (F3).
//! * **Never log a path or content at info level.** Counters and reasons only.
//!   The checkpoint necessarily holds DIRECTORY paths (that is what resuming is),
//!   never file names, never content, and it lives in the agent's state directory
//!   — which [`FilterConfig::with_state_dir`] excludes from classification.
//!
//! Everything here is portable: the walker is `std::fs` only, so the whole
//! traversal, throttle and checkpoint story is exercised by `tests/ml_walk.rs` on
//! any host.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::cache::{self, VerdictCache};
use super::filter::{self, FilterConfig};
use super::queue;
use super::watch::{
    now_ms, post_read_outcome, pre_read_decision, ClassifyJob, ClassifySink, QueueSink, SweepFlags,
    WatchOutcome,
};

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/// Candidate files per minute, the walker's headline throttle.
///
/// 120/min ≈ 2/s. At that rate a 60 000-document profile is fully swept in about
/// eight hours of uptime — one working day, which is the right order for "the
/// estate is covered, you may enable denyUnclassified" — while costing at most a
/// couple of 4 MiB reads per second, i.e. below the noise floor of an ordinary
/// desktop's own I/O. It is a config knob because a file server and a laptop
/// deserve different answers.
pub const DEFAULT_FILES_PER_MINUTE: u32 = 120;

/// Token-bucket burst. Lets the walker cross a directory of a few documents
/// without stalling on the very next file, while still averaging the budget.
pub const DEFAULT_BURST: u32 = 20;

/// Persist the cursor every this many processed candidates. Small enough that a
/// crash loses minutes of work, large enough that the checkpoint write is not
/// itself a workload.
pub const DEFAULT_CHECKPOINT_EVERY: u64 = 200;

/// Cap on the number of pending directories written into a checkpoint. Beyond
/// this the checkpoint records "restart this scope" instead of a partial list —
/// a truncated list would silently drop directories from the sweep, and a sweep
/// that claims completion it did not achieve is the one failure mode this whole
/// module exists to prevent. Re-walking a scope is cheap (a hash per known file).
pub const DEFAULT_MAX_PENDING_DIRS: usize = 4_096;

/// Pause the sweep while the classifier queue is at least this deep.
pub const DEFAULT_QUEUE_PAUSE_DEPTH: usize = 32;

/// How long to wait before re-testing queue depth.
pub const DEFAULT_BACKPRESSURE_PAUSE_MS: u64 = 2_000;

/// A prefix read slower than this says the disk is busy with the user's work.
pub const DEFAULT_SLOW_READ_MS: u64 = 250;

/// Tokens charged to the bucket after a slow read — i.e. "skip the next N files'
/// worth of budget". Four is enough to be felt within seconds and small enough
/// that a single unlucky read does not stall a sweep.
pub const DEFAULT_SLOW_READ_PENALTY: f64 = 4.0;

/// Fraction of a file-token charged for listing ONE directory. Directory
/// descent has no cost of its own otherwise — no token was ever taken for it —
/// so a subtree with no eligible file in it (which is most of them: package
/// managers, browser profiles, per-app AppData trees) could run unthrottled at
/// whatever rate the disk allowed. A quarter-token lets a normal directory
/// crossing pass through near-instantly (the burst absorbs it) while a long,
/// file-free run still spends real, visible budget from the SAME bucket a file
/// would draw from, so `rate_limited` — not a silent, invisible core pin — is
/// what shows up on the health surface.
pub const DEFAULT_DIR_LISTING_COST: f64 = 0.25;

/// Idle gap between full sweeps in the service loop (seconds). The watcher is
/// the primary coverage mechanism; this is the backstop that catches whatever it
/// missed, so it is measured in hours, not minutes.
pub const DEFAULT_RESCAN_INTERVAL_SECS: u64 = 6 * 3_600;

/// Longest the service loop blocks before re-checking the stop flag.
pub const WALK_SLICE_MS: u64 = 250;

/// On-disk cursor. Bumped only if the shape changes incompatibly; an unknown
/// version is discarded like any other unreadable checkpoint.
pub const CHECKPOINT_VERSION: u32 = 1;

/// Cursor file name, inside the agent's state directory.
pub const CHECKPOINT_FILE: &str = "ml-walk.checkpoint.json";

/// Completion-fact file name, beside the cursor.
pub const COMPLETION_FILE: &str = "ml-walk.completed.json";

// ---------------------------------------------------------------------------
// Throttle
// ---------------------------------------------------------------------------

/// Token bucket over an INJECTED clock.
///
/// Injected rather than internal because "does the throttle actually throttle?"
/// is a property a test must be able to assert in microseconds. Every method
/// takes `now_ms`; the walker feeds it [`super::watch::now_ms`] (monotonic, so a
/// wall-clock change cannot hand the walker a free burst) and the tests feed it a
/// counter.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// 0 ⇒ unlimited (tests, and a deliberate "sweep flat out" configuration).
    per_minute: u32,
    burst: f64,
    tokens: f64,
    last_ms: u64,
    primed: bool,
}

impl RateLimiter {
    pub fn new(files_per_minute: u32, burst: u32) -> Self {
        let burst = if burst == 0 { 1 } else { burst } as f64;
        RateLimiter {
            per_minute: files_per_minute,
            burst,
            tokens: burst,
            last_ms: 0,
            primed: false,
        }
    }

    /// Unlimited: no throttle at all.
    pub fn unlimited() -> Self {
        RateLimiter::new(0, 1)
    }

    fn rate_per_ms(&self) -> f64 {
        self.per_minute as f64 / 60_000.0
    }

    fn refill(&mut self, now_ms: u64) {
        if !self.primed {
            self.primed = true;
            self.last_ms = now_ms;
            return;
        }
        // saturating: the clock is monotonic, but a caller passing a stale value
        // must never mint tokens.
        let elapsed = now_ms.saturating_sub(self.last_ms) as f64;
        self.last_ms = now_ms.max(self.last_ms);
        self.tokens = (self.tokens + elapsed * self.rate_per_ms()).min(self.burst);
    }

    /// Take one token if one is available. `false` ⇒ the caller must wait
    /// [`wait_ms`](Self::wait_ms).
    pub fn try_take(&mut self, now_ms: u64) -> bool {
        self.try_take_cost(now_ms, 1.0)
    }

    /// Take `cost` tokens (fractional) if that many are available. Used to
    /// charge less than a full token for cheap work — a directory listing
    /// costing a quarter of a file, say — while sharing the SAME bucket a full
    /// file would draw from, so the two throttles cannot be played off each
    /// other (a subtree with no eligible files still spends real budget).
    pub fn try_take_cost(&mut self, now_ms: u64, cost: f64) -> bool {
        if self.per_minute == 0 || cost <= 0.0 {
            return true;
        }
        self.refill(now_ms);
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }

    /// Milliseconds until one full token is available, 0 if one already is.
    pub fn wait_ms(&self, now_ms: u64) -> u64 {
        self.wait_ms_for(now_ms, 1.0)
    }

    /// Milliseconds until `need` tokens are available, 0 if they already are.
    pub fn wait_ms_for(&self, now_ms: u64, need: f64) -> u64 {
        if self.per_minute == 0 {
            return 0;
        }
        let mut tokens = self.tokens;
        if self.primed {
            tokens =
                (tokens + now_ms.saturating_sub(self.last_ms) as f64 * self.rate_per_ms()).min(self.burst);
        }
        if tokens >= need {
            return 0;
        }
        ((need - tokens) / self.rate_per_ms()).ceil() as u64
    }

    /// Charge extra tokens — the slow-read penalty. Never drives the bucket below
    /// a one-file debt floor, so one pathological file cannot stall a sweep for
    /// minutes.
    pub fn charge(&mut self, tokens: f64) {
        if self.per_minute == 0 {
            return;
        }
        self.tokens = (self.tokens - tokens).max(-self.burst);
    }

    /// Give back tokens previously taken for work that turned out to be free.
    /// An already-classified file costs a hash and a HashMap lookup, not a
    /// rate-limited inference slot — without this, a re-sweep over an already-
    /// covered estate costs the same wall clock as the first sweep ever did,
    /// which defeats the point of a "cheap repeat" backstop. Clamped to the
    /// burst ceiling exactly like a normal refill, so a long run of hits cannot
    /// mint an unbounded surplus that then blows through backpressure.
    pub fn refund(&mut self, tokens: f64) {
        if self.per_minute == 0 {
            return;
        }
        self.tokens = (self.tokens + tokens).min(self.burst);
    }

    /// Current token balance. Reporting/tests only.
    pub fn tokens(&self) -> f64 {
        self.tokens
    }
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

/// What one sweep saw. Persisted in the checkpoint and in the completion record,
/// so an operator can answer "is this endpoint covered?" from a file.
///
/// These are counts of WORK DONE, not of distinct files: a resumed sweep re-lists
/// the directory it was interrupted in, so a handful of files can be counted
/// twice (as `already_known` the second time, which is exactly what a cheap
/// second pass looks like).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepCounts {
    /// Directories listed.
    pub dirs: u64,
    /// Files that passed the filter and were actually looked at.
    pub candidates: u64,
    /// Candidates already in the cache under the loaded model version.
    pub already_known: u64,
    /// Candidates handed to the background classifier.
    pub enqueued: u64,
    /// Candidates the classifier queue would not take (full, in flight, barren).
    pub refused: u64,
    /// Entries rejected by [`filter::should_classify`], plus directory symlinks
    /// and pruned trees.
    pub skipped: u64,
    /// Gone between listing and processing.
    pub vanished: u64,
    /// Unreadable directories and files — locked, or an ACL we do not hold.
    pub errors: u64,
}

/// Live process counters. Monotonic across sweeps; reported as agent health.
#[derive(Debug, Default)]
pub struct WalkStats {
    pub dirs: AtomicU64,
    pub candidates: AtomicU64,
    pub already_known: AtomicU64,
    pub enqueued: AtomicU64,
    pub refused: AtomicU64,
    pub skipped: AtomicU64,
    pub vanished: AtomicU64,
    pub errors: AtomicU64,
    /// Steps that returned early because the files-per-minute budget was spent.
    pub rate_limited: AtomicU64,
    /// Steps that returned early because the classifier queue was deep.
    pub backpressured: AtomicU64,
    /// Prefix reads slower than `slow_read_ms` — the I/O-contention proxy.
    pub slow_reads: AtomicU64,
    /// Full sweeps finished. **This, and the completion record, is the coverage
    /// signal `denyUnclassified` waits on.**
    pub sweeps_completed: AtomicU64,
    /// Targeted re-sweeps run because the watcher lost notifications.
    pub overflow_sweeps: AtomicU64,
    /// Cursor writes.
    pub checkpoints: AtomicU64,
    /// Cursors discarded as unreadable/stale — a sweep restarted from zero.
    pub checkpoints_discarded: AtomicU64,
}

/// Point-in-time copy of [`WalkStats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct WalkStatsSnapshot {
    pub dirs: u64,
    pub candidates: u64,
    pub already_known: u64,
    pub enqueued: u64,
    pub refused: u64,
    pub skipped: u64,
    pub vanished: u64,
    pub errors: u64,
    pub rate_limited: u64,
    pub backpressured: u64,
    pub slow_reads: u64,
    pub sweeps_completed: u64,
    pub overflow_sweeps: u64,
    pub checkpoints: u64,
    pub checkpoints_discarded: u64,
}

impl WalkStats {
    pub fn snapshot(&self) -> WalkStatsSnapshot {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        WalkStatsSnapshot {
            dirs: g(&self.dirs),
            candidates: g(&self.candidates),
            already_known: g(&self.already_known),
            enqueued: g(&self.enqueued),
            refused: g(&self.refused),
            skipped: g(&self.skipped),
            vanished: g(&self.vanished),
            errors: g(&self.errors),
            rate_limited: g(&self.rate_limited),
            backpressured: g(&self.backpressured),
            slow_reads: g(&self.slow_reads),
            sweeps_completed: g(&self.sweeps_completed),
            overflow_sweeps: g(&self.overflow_sweeps),
            checkpoints: g(&self.checkpoints),
            checkpoints_discarded: g(&self.checkpoints_discarded),
        }
    }
}

// ---------------------------------------------------------------------------
// Persisted facts
// ---------------------------------------------------------------------------

/// The resumable cursor.
///
/// Holds DIRECTORY paths — that is what resuming a tree walk is — and nothing
/// else: no file names, no content, no verdicts (C6 governs the verdict cache;
/// this file is the walker's own bookmark and lives in the same protected state
/// directory).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalkCheckpoint {
    pub version: u32,
    /// Monotonic sweep number, for correlating logs.
    pub sweep_seq: u64,
    /// Unix seconds the sweep began.
    pub started_at: u64,
    /// A sweep of every configured scope (as opposed to a targeted re-sweep).
    /// Only a full sweep can produce a [`SweepCompletion`].
    pub full: bool,
    /// The engine version the sweep is being conducted under. A checkpoint from
    /// another model version is DISCARDED: entries written under it are stale
    /// (C3), so resuming would let a sweep claim coverage it does not have.
    pub model_version: String,
    /// The configured scope list at the time the sweep started. If the
    /// configuration has since changed the cursor is meaningless — discarded.
    pub scopes_all: Vec<PathBuf>,
    /// Scopes not yet started.
    pub scopes_pending: Vec<PathBuf>,
    /// The scope being walked.
    pub current_scope: Option<PathBuf>,
    /// Directories still to visit in the current scope. Empty together with
    /// `pending_truncated` ⇒ restart the current scope.
    pub pending_dirs: Vec<PathBuf>,
    /// The pending list exceeded [`WalkConfig::max_pending_dirs`] and was NOT
    /// persisted; resume restarts the current scope instead of silently
    /// dropping directories.
    pub pending_truncated: bool,
    /// Last directory listed. Reporting/diagnostics.
    pub last_dir: Option<PathBuf>,
    pub counts: SweepCounts,
}

/// **A full sweep completed at T, covering N files.**
///
/// The one fact an operator needs before enabling `denyUnclassified`, which is
/// why it is a persisted record rather than a log line: the runbook says to read
/// this file (or the health surface that serialises it), and a fleet tool can
/// gate the rollout on it.
///
/// `model_version` is part of the claim. Coverage under a superseded model is
/// not coverage: every entry that sweep wrote reads as stale (C3), i.e. a miss.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SweepCompletion {
    pub version: u32,
    pub sweep_seq: u64,
    /// Unix seconds.
    pub started_at: u64,
    /// Unix seconds.
    pub completed_at: u64,
    pub duration_secs: u64,
    pub model_version: String,
    pub scopes: Vec<PathBuf>,
    pub counts: SweepCounts,
}

impl SweepCompletion {
    /// Does this completion establish coverage for `model_version`?
    pub fn covers_model(&self, model_version: &str) -> bool {
        self.model_version == model_version
    }

    /// Files actually looked at by the sweep — the "covering N files" number.
    pub fn files_covered(&self) -> u64 {
        self.counts.candidates
    }
}

/// Write `value` to `dir/name` crash-safely and durably, via
/// [`crate::atomicfile::write_atomic`]: at every instant the file is the
/// complete previous record or the complete new one. That matters most for the
/// COMPLETION record — it is the coverage evidence `denyUnclassified` arms on,
/// and the old "remove the destination, then rename" sequence left a window in
/// which a crash deleted it outright (a reader polling a file replaced 300
/// times under that sequence found no file 950 times; under a rename-over, 0).
fn write_json_atomic<T: Serialize>(dir: &Path, name: &str, value: &T) -> Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating ml walk state dir {}", dir.display()))?;
    let bytes = serde_json::to_vec_pretty(value).context("serialising ml walk state")?;
    crate::atomicfile::write_atomic(&dir.join(name), &bytes).context("replacing ml walk state")?;
    Ok(())
}

/// Read `dir/name`, or `None` for missing, truncated, corrupt or
/// wrong-version content. **Never an error**: a damaged bookmark must cost a
/// restarted sweep, never a failed startup.
fn read_json<T: for<'de> Deserialize<'de>>(dir: &Path, name: &str) -> Option<T> {
    let path = dir.join(name);
    let bytes = std::fs::read(&path).ok()?;
    match serde_json::from_slice::<T>(&bytes) {
        Ok(v) => Some(v),
        Err(_) => {
            tracing::warn!(
                file = name,
                bytes = bytes.len(),
                "ml walker: unreadable state file discarded"
            );
            None
        }
    }
}

/// Load the persisted cursor, if there is a usable one.
pub fn load_checkpoint(state_dir: &Path) -> Option<WalkCheckpoint> {
    let cp: WalkCheckpoint = read_json(state_dir, CHECKPOINT_FILE)?;
    if cp.version != CHECKPOINT_VERSION {
        tracing::warn!(
            found = cp.version,
            expected = CHECKPOINT_VERSION,
            "ml walker: checkpoint version mismatch — restarting the sweep"
        );
        return None;
    }
    Some(cp)
}

/// Persist the cursor.
pub fn save_checkpoint(state_dir: &Path, cp: &WalkCheckpoint) -> Result<()> {
    write_json_atomic(state_dir, CHECKPOINT_FILE, cp)
}

/// Remove the cursor (a sweep finished; there is nothing to resume).
pub fn clear_checkpoint(state_dir: &Path) {
    let _ = std::fs::remove_file(state_dir.join(CHECKPOINT_FILE));
    let _ = std::fs::remove_file(state_dir.join(format!("{CHECKPOINT_FILE}.tmp")));
}

/// The last completed full sweep, if any.
pub fn load_completion(state_dir: &Path) -> Option<SweepCompletion> {
    let c: SweepCompletion = read_json(state_dir, COMPLETION_FILE)?;
    if c.version != CHECKPOINT_VERSION {
        return None;
    }
    Some(c)
}

/// Record a completed full sweep.
pub fn save_completion(state_dir: &Path, c: &SweepCompletion) -> Result<()> {
    write_json_atomic(state_dir, COMPLETION_FILE, c)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Is this a cloud-storage placeholder (OneDrive/SharePoint "Files On-Demand",
/// or anything else that marks a file this way) whose content is not actually
/// on local disk yet?
///
/// `std::fs::FileType::is_symlink()` does not catch these: a placeholder is a
/// reparse point, but under `IO_REPARSE_TAG_CLOUD*`, a different tag family
/// from the mount-point/symlink tags that method recognises — so a placeholder
/// sails through the walker's existing symlink check as an ordinary file, and
/// reading it to classify it forces Windows to download it. We check the
/// attribute bits Windows sets on exactly this class of file instead —
/// `FILE_ATTRIBUTE_RECALL_ON_OPEN` / `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`
/// (opening or reading triggers a recall from the cloud) and the older
/// `FILE_ATTRIBUTE_OFFLINE` bit OneDrive also sets — off the SAME metadata
/// call `list_dir` already made for the file's size, so this costs no extra
/// syscall.
#[cfg(windows)]
fn is_cloud_placeholder(meta: Option<&std::fs::Metadata>) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
    const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
    const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
    const CLOUD_BITS: u32 =
        FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
    meta.is_some_and(|m| m.file_attributes() & CLOUD_BITS != 0)
}

#[cfg(not(windows))]
fn is_cloud_placeholder(_meta: Option<&std::fs::Metadata>) -> bool {
    false
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Everything the walker needs that is not global state.
#[derive(Debug, Clone)]
pub struct WalkConfig {
    /// Trees to sweep, recursively. The same scopes the watcher watches: the two
    /// producers must agree, or the walker's "complete" would be a claim about a
    /// different estate than the one the watcher keeps fresh.
    pub scopes: Vec<PathBuf>,
    /// Where the cursor and the completion record live.
    pub state_dir: PathBuf,
    pub files_per_minute: u32,
    pub burst: u32,
    pub checkpoint_every: u64,
    pub max_pending_dirs: usize,
    pub queue_pause_depth: usize,
    pub backpressure_pause_ms: u64,
    pub slow_read_ms: u64,
    pub slow_read_penalty: f64,
    /// Fractional token charged per directory listed. See
    /// [`DEFAULT_DIR_LISTING_COST`]; `0.0` disables the throttle entirely
    /// (unthrottled descent), which is deliberately NOT the default.
    pub dir_listing_cost: f64,
    pub rescan_interval_secs: u64,
    pub filter: FilterConfig,
}

impl WalkConfig {
    /// Defaults, with the mandatory self-exclusion of the agent's own state
    /// directory (the verdict log lives there and has a supported extension).
    pub fn new(state_dir: impl AsRef<Path>, scopes: Vec<PathBuf>) -> Self {
        let state_dir = state_dir.as_ref().to_path_buf();
        WalkConfig {
            scopes,
            filter: FilterConfig::with_state_dir(&state_dir),
            state_dir,
            files_per_minute: DEFAULT_FILES_PER_MINUTE,
            burst: DEFAULT_BURST,
            checkpoint_every: DEFAULT_CHECKPOINT_EVERY,
            max_pending_dirs: DEFAULT_MAX_PENDING_DIRS,
            queue_pause_depth: DEFAULT_QUEUE_PAUSE_DEPTH,
            backpressure_pause_ms: DEFAULT_BACKPRESSURE_PAUSE_MS,
            slow_read_ms: DEFAULT_SLOW_READ_MS,
            slow_read_penalty: DEFAULT_SLOW_READ_PENALTY,
            dir_listing_cost: DEFAULT_DIR_LISTING_COST,
            rescan_interval_secs: DEFAULT_RESCAN_INTERVAL_SECS,
        }
    }
}

// ---------------------------------------------------------------------------
// One step of the sweep
// ---------------------------------------------------------------------------

/// What one call to [`Walker::step`] did. Every variant is a counter label; none
/// of them is an incident (F5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepStatus {
    /// The ML policy is inert — the walker does nothing at all (F3).
    Inert,
    /// No sweep is running (call [`Walker::begin_full_sweep`]).
    Idle,
    /// A directory was listed. Cheap; costs no rate-limit budget.
    Descended,
    /// One candidate file was processed.
    Processed(WatchOutcome),
    /// Throttled — the budget is spent or the classifier queue is deep. Come back
    /// in `wait_ms`.
    Paused { wait_ms: u64 },
    /// Every scope has been walked. A full sweep also wrote its completion
    /// record before returning this.
    Completed,
}

/// Internal: what `pick_next` decided, computed under the state lock and acted
/// on outside it (no I/O ever happens with the lock held).
enum Next {
    Idle,
    Paused(u64),
    Dir(PathBuf),
    File(PathBuf),
    Done,
}

#[derive(Debug, Default)]
struct Cursor {
    active: bool,
    full: bool,
    sweep_seq: u64,
    started_at: u64,
    scopes_all: Vec<PathBuf>,
    scopes_pending: VecDeque<PathBuf>,
    current_scope: Option<PathBuf>,
    dirs: VecDeque<PathBuf>,
    files: VecDeque<PathBuf>,
    last_dir: Option<PathBuf>,
    counts: SweepCounts,
    since_checkpoint: u64,
}

struct WalkState {
    cursor: Cursor,
    limiter: RateLimiter,
}

/// Result of listing one directory.
#[derive(Debug, Default)]
struct Listing {
    dirs: Vec<PathBuf>,
    files: Vec<PathBuf>,
    skipped: u64,
    errors: u64,
}

// ---------------------------------------------------------------------------
// The walker
// ---------------------------------------------------------------------------

/// The at-rest discovery walker.
///
/// One cursor, one rate limiter, one sink — shared behind an `Arc` by the service
/// thread. The only mutable state is behind a `Mutex` that is never held across
/// I/O, so `stats()` and `checkpoint_now()` stay responsive while a 4 MiB read is
/// in flight.
pub struct Walker {
    cfg: WalkConfig,
    cache: Arc<VerdictCache>,
    sink: Arc<dyn ClassifySink>,
    stats: Arc<WalkStats>,
    state: Mutex<WalkState>,
    /// Scopes the watcher lost notifications for. Shared with the watcher; the
    /// walker drains it and re-sweeps.
    sweep_flags: Option<Arc<SweepFlags>>,
}

impl Walker {
    pub fn new(cfg: WalkConfig, cache: Arc<VerdictCache>, sink: Arc<dyn ClassifySink>) -> Self {
        let limiter = RateLimiter::new(cfg.files_per_minute, cfg.burst);
        Walker {
            cfg,
            cache,
            sink,
            stats: Arc::new(WalkStats::default()),
            state: Mutex::new(WalkState {
                cursor: Cursor::default(),
                limiter,
            }),
            sweep_flags: None,
        }
    }

    /// Construction for the service: the process-wide verdict cache published by
    /// `queue::open_and_start`, plus the real queue sink.
    ///
    /// `None` when no cache has been published — with no cache there is nothing
    /// for a producer to fill, and every path already behaves exactly as the
    /// pre-cache agent did (F3), so the right answer is not to start a sweep.
    pub fn with_shared_queue(cfg: WalkConfig) -> Option<Self> {
        let cache = queue::verdict_cache()?;
        Some(Self::new(cfg, cache, Arc::new(QueueSink)))
    }

    /// Share the watcher's overflow flags, so a lost-notification scope gets
    /// re-swept (see [`Walker::take_flagged_scopes`]).
    pub fn with_sweep_flags(mut self, flags: Arc<SweepFlags>) -> Self {
        self.sweep_flags = Some(flags);
        self
    }

    pub fn stats(&self) -> Arc<WalkStats> {
        Arc::clone(&self.stats)
    }

    pub fn config(&self) -> &WalkConfig {
        &self.cfg
    }

    /// Is a sweep in progress?
    pub fn is_sweeping(&self) -> bool {
        self.lock().cursor.active
    }

    /// Is the sweep in progress (or last recorded) a FULL, estate-wide sweep —
    /// as opposed to a targeted overflow re-sweep of one flagged scope? The
    /// service loop uses this to decide whether a completion is allowed to
    /// push the full-sweep backstop timer out; see [`run`].
    pub fn is_full_sweep(&self) -> bool {
        self.lock().cursor.full
    }

    /// Counts for the sweep in progress (or the last one).
    pub fn counts(&self) -> SweepCounts {
        self.lock().cursor.counts
    }

    /// The last completed FULL sweep — the coverage fact.
    pub fn last_completion(&self) -> Option<SweepCompletion> {
        load_completion(&self.cfg.state_dir)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, WalkState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    // -----------------------------------------------------------------------
    // Starting a sweep
    // -----------------------------------------------------------------------

    /// Begin (or RESUME) a sweep of every configured scope.
    ///
    /// A persisted cursor is honoured only when it describes the same estate and
    /// the same model version; anything else is discarded and the sweep starts
    /// from the beginning, because resuming across either change would let the
    /// sweep claim coverage it never achieved.
    pub fn begin_full_sweep(&self) {
        let model_version = queue::model_version_for_cache();
        let resumed = load_checkpoint(&self.cfg.state_dir).and_then(|cp| {
            if !cp.full {
                return None;
            }
            if cp.scopes_all != self.cfg.scopes {
                tracing::warn!("ml walker: scope configuration changed — restarting the sweep");
                return None;
            }
            if cp.model_version != model_version {
                tracing::warn!("ml walker: model version changed — restarting the sweep");
                return None;
            }
            Some(cp)
        });

        let mut st = self.lock();
        match resumed {
            Some(cp) => {
                let dirs: VecDeque<PathBuf> = if cp.pending_truncated {
                    // The list was too long to persist: restart the current
                    // scope rather than silently dropping directories.
                    cp.current_scope.clone().into_iter().collect()
                } else {
                    cp.pending_dirs.iter().cloned().collect()
                };
                st.cursor = Cursor {
                    active: true,
                    full: true,
                    sweep_seq: cp.sweep_seq,
                    started_at: cp.started_at,
                    scopes_all: cp.scopes_all,
                    scopes_pending: cp.scopes_pending.into_iter().collect(),
                    current_scope: cp.current_scope,
                    dirs,
                    files: VecDeque::new(),
                    last_dir: cp.last_dir,
                    counts: cp.counts,
                    since_checkpoint: 0,
                };
                tracing::info!(
                    sweep = st.cursor.sweep_seq,
                    candidates = st.cursor.counts.candidates,
                    dirs_pending = st.cursor.dirs.len(),
                    "ml walker: resumed at-rest sweep from checkpoint"
                );
            }
            None => {
                if std::fs::metadata(self.cfg.state_dir.join(CHECKPOINT_FILE)).is_ok() {
                    self.stats
                        .checkpoints_discarded
                        .fetch_add(1, Ordering::Relaxed);
                }
                let seq = st.cursor.sweep_seq + 1;
                st.cursor = Cursor {
                    active: true,
                    full: true,
                    sweep_seq: seq,
                    started_at: unix_now(),
                    scopes_all: self.cfg.scopes.clone(),
                    scopes_pending: self.cfg.scopes.iter().cloned().collect(),
                    ..Cursor::default()
                };
                tracing::info!(
                    sweep = seq,
                    scopes = st.cursor.scopes_pending.len(),
                    "ml walker: starting at-rest sweep"
                );
            }
        }
    }

    /// Begin a TARGETED sweep of specific scopes — what an overflow flag asks
    /// for. Deliberately does not produce a [`SweepCompletion`]: completion is a
    /// claim about the whole configured estate, and re-walking one tree does not
    /// establish it.
    pub fn begin_scope_sweep(&self, scopes: &[PathBuf]) {
        let scopes: Vec<PathBuf> = scopes.iter().filter(|p| !p.as_os_str().is_empty()).cloned().collect();
        if scopes.is_empty() {
            return;
        }
        let mut st = self.lock();
        let seq = st.cursor.sweep_seq + 1;
        st.cursor = Cursor {
            active: true,
            full: false,
            sweep_seq: seq,
            started_at: unix_now(),
            scopes_all: self.cfg.scopes.clone(),
            scopes_pending: scopes.iter().cloned().collect(),
            ..Cursor::default()
        };
        self.stats.overflow_sweeps.fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            sweep = seq,
            scopes = scopes.len(),
            "ml walker: re-sweeping scopes whose change notifications overflowed"
        );
    }

    /// Drain the watcher's overflow flags.
    pub fn take_flagged_scopes(&self) -> Vec<PathBuf> {
        match &self.sweep_flags {
            Some(f) => f.take(),
            None => Vec::new(),
        }
    }

    // -----------------------------------------------------------------------
    // The step
    // -----------------------------------------------------------------------

    /// Advance the sweep by at most one directory listing or one candidate file.
    ///
    /// `now_ms` is the injected monotonic clock (production passes
    /// [`super::watch::now_ms`]). Never blocks on anything but its own I/O, and
    /// never runs inference.
    pub fn step(&self, now_ms: u64) -> StepStatus {
        // F3: an inert policy behaves exactly like the pre-cache agent — no
        // reads, no hashes, no state.
        if crate::mlpolicy::active().is_inert() {
            return StepStatus::Inert;
        }

        let next = {
            let mut st = self.lock();
            self.pick_next(&mut st, now_ms)
        };

        match next {
            Next::Idle => StepStatus::Idle,
            Next::Paused(wait) => StepStatus::Paused { wait_ms: wait },
            Next::Done => {
                self.finish_sweep();
                StepStatus::Completed
            }
            Next::Dir(dir) => {
                // I/O outside the lock.
                let listing = self.list_dir(&dir);
                let mut st = self.lock();
                st.cursor.counts.dirs += 1;
                st.cursor.counts.skipped += listing.skipped;
                st.cursor.counts.errors += listing.errors;
                st.cursor.last_dir = Some(dir);
                for d in listing.dirs {
                    st.cursor.dirs.push_back(d);
                }
                for f in listing.files {
                    st.cursor.files.push_back(f);
                }
                drop(st);
                self.stats.dirs.fetch_add(1, Ordering::Relaxed);
                self.stats.skipped.fetch_add(listing.skipped, Ordering::Relaxed);
                self.stats.errors.fetch_add(listing.errors, Ordering::Relaxed);
                self.maybe_checkpoint(false);
                StepStatus::Descended
            }
            Next::File(path) => {
                let model_version = queue::model_version_for_cache();
                let (outcome, read_ms) = self.process(&path, &model_version);
                let mut st = self.lock();
                st.cursor.counts.candidates += 1;
                self.stats.candidates.fetch_add(1, Ordering::Relaxed);
                let counter = match outcome {
                    WatchOutcome::AlreadyClassified => {
                        st.cursor.counts.already_known += 1;
                        // The token for this file was taken in `pick_next`
                        // before `process` could know it was a cache hit — a
                        // hash and a lookup, not an inference slot. Refund it
                        // so a re-sweep over an already-covered estate is
                        // actually cheap, matching the module's own claim.
                        st.limiter.refund(1.0);
                        Some(&self.stats.already_known)
                    }
                    WatchOutcome::Enqueued => {
                        st.cursor.counts.enqueued += 1;
                        Some(&self.stats.enqueued)
                    }
                    WatchOutcome::Refused => {
                        st.cursor.counts.refused += 1;
                        Some(&self.stats.refused)
                    }
                    WatchOutcome::Skipped(_) => {
                        st.cursor.counts.skipped += 1;
                        Some(&self.stats.skipped)
                    }
                    WatchOutcome::Vanished => {
                        st.cursor.counts.vanished += 1;
                        Some(&self.stats.vanished)
                    }
                    WatchOutcome::Unreadable => {
                        st.cursor.counts.errors += 1;
                        Some(&self.stats.errors)
                    }
                    WatchOutcome::Inert => None,
                };
                if let Some(c) = counter {
                    c.fetch_add(1, Ordering::Relaxed);
                }
                // Throttle 3: a slow read means the disk is busy with the user's
                // work, so yield budget to them.
                if self.cfg.slow_read_ms > 0 && read_ms >= self.cfg.slow_read_ms {
                    st.limiter.charge(self.cfg.slow_read_penalty);
                    self.stats.slow_reads.fetch_add(1, Ordering::Relaxed);
                }
                st.cursor.since_checkpoint += 1;
                let due = st.cursor.since_checkpoint >= self.cfg.checkpoint_every;
                drop(st);
                if due {
                    self.maybe_checkpoint(true);
                }
                StepStatus::Processed(outcome)
            }
        }
    }

    /// Decide the next unit of work. Pure bookkeeping under the lock — no I/O.
    fn pick_next(&self, st: &mut WalkState, now_ms: u64) -> Next {
        if !st.cursor.active {
            return Next::Idle;
        }
        loop {
            if !st.cursor.files.is_empty() {
                // Throttle 2: the classifier is already the busiest thing on the
                // machine — do not feed it.
                if self.backpressured() {
                    self.stats.backpressured.fetch_add(1, Ordering::Relaxed);
                    return Next::Paused(self.cfg.backpressure_pause_ms);
                }
                // Throttle 1: the files-per-minute budget.
                if !st.limiter.try_take(now_ms) {
                    self.stats.rate_limited.fetch_add(1, Ordering::Relaxed);
                    return Next::Paused(st.limiter.wait_ms(now_ms).max(1));
                }
                let f = st.cursor.files.pop_front().expect("checked non-empty");
                return Next::File(f);
            }
            if let Some(d) = st.cursor.dirs.pop_front() {
                // Throttle 4: directory descent. A subtree with no eligible
                // file in it (an AppData package tree, a browser profile) used
                // to cost NOTHING — no token, no sleep, no budget — so the
                // walker could `read_dir` its way through tens of thousands of
                // directories at whatever rate the disk and the MFT allowed,
                // pinning a core and saturating metadata I/O while the user
                // was working. Charging a fraction of the SAME bucket a file
                // draws from means a long run of empty directories throttles
                // exactly like a long run of files would.
                if self.cfg.dir_listing_cost > 0.0
                    && !st.limiter.try_take_cost(now_ms, self.cfg.dir_listing_cost)
                {
                    st.cursor.dirs.push_front(d); // must not lose it
                    self.stats.rate_limited.fetch_add(1, Ordering::Relaxed);
                    return Next::Paused(
                        st.limiter
                            .wait_ms_for(now_ms, self.cfg.dir_listing_cost)
                            .max(1),
                    );
                }
                return Next::Dir(d);
            }
            match st.cursor.scopes_pending.pop_front() {
                Some(scope) => {
                    st.cursor.current_scope = Some(scope.clone());
                    st.cursor.dirs.push_back(scope);
                }
                None => return Next::Done,
            }
        }
    }

    /// Queue depth backpressure. `queue::stats()` reports zeros when no worker is
    /// running, which is the correct answer for a test or a CLI sweep: no worker,
    /// no backpressure.
    fn backpressured(&self) -> bool {
        if self.cfg.queue_pause_depth == 0 {
            return false;
        }
        queue::stats().depth >= self.cfg.queue_pause_depth
    }

    /// List one directory. Prunes excluded trees and never follows a symlink or
    /// reparse point — a junction pointing at a parent would otherwise walk
    /// forever, and one pointing at `C:\` would turn a scoped sweep into a
    /// whole-volume one.
    fn list_dir(&self, dir: &Path) -> Listing {
        let mut out = Listing::default();
        let rd = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(_) => {
                // Access denied / gone. Counted, never logged with the path.
                out.errors += 1;
                return out;
            }
        };
        for entry in rd {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    out.errors += 1;
                    continue;
                }
            };
            let path = entry.path();
            let ft = match entry.file_type() {
                Ok(t) => t,
                Err(_) => {
                    out.errors += 1;
                    continue;
                }
            };
            if ft.is_symlink() {
                out.skipped += 1;
                continue;
            }
            if ft.is_dir() {
                if self.prune(&path) {
                    out.skipped += 1;
                } else {
                    out.dirs.push(path);
                }
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            let meta = entry.metadata().ok();
            if is_cloud_placeholder(meta.as_ref()) {
                // A OneDrive/SharePoint "Files On-Demand" placeholder: the
                // directory entry reports the file's real logical size, but
                // the content is not on disk. Reading it to classify it would
                // force Windows to download it from the cloud just to decide
                // whether a background sweep cares — expensive, surprising to
                // the user (their free space drops), and on a metered or
                // otherwise-air-gapped link outright wrong for this product.
                // Not a coverage hole: the on-demand path still classifies it
                // from the real bytes the moment it is genuinely opened.
                out.skipped += 1;
                continue;
            }
            let size = meta.map(|m| m.len()).unwrap_or(0);
            match filter::should_classify(&path, size, &self.cfg.filter) {
                filter::Decision::Classify => out.files.push(path),
                filter::Decision::Skip(_) => out.skipped += 1,
            }
        }
        // Deterministic order, so a resumed sweep behaves like an uninterrupted
        // one and a test can reason about what happens first.
        out.dirs.sort();
        out.files.sort();
        out
    }

    /// Should this DIRECTORY be descended into?
    ///
    /// `filter::is_excluded_directory` treats the last segment as a file name, so
    /// the directory is probed with a dummy child — that also gives
    /// `is_excluded_prefix` the "strictly under" shape it wants, which is what
    /// stops the walker from descending into the agent's own state directory.
    fn prune(&self, dir: &Path) -> bool {
        let probe = dir.join("_");
        let raw = probe.to_string_lossy().to_string();
        let segs = filter::split_segments(&raw);
        filter::is_excluded_prefix(&segs, &self.cfg.filter)
            || filter::is_excluded_directory(&raw, &segs, &self.cfg.filter)
    }

    /// One candidate file, start to finish. Returns the outcome and how long the
    /// prefix read took (the I/O-contention proxy).
    ///
    /// Re-stats the file rather than trusting the listing: the rate limiter can
    /// put minutes between listing a directory and reaching a file in it, so it
    /// may well be gone or truncated by now. The policy/filter half is
    /// [`pre_read_decision`] — the SAME function the at-creation watcher uses, so
    /// the two producers cannot drift.
    fn process(&self, path: &Path, model_version: &str) -> (WatchOutcome, u64) {
        let meta = std::fs::metadata(path).ok().map(|m| (m.is_file(), m.len()));
        if let Some(outcome) = pre_read_decision(false, path, meta, &self.cfg.filter) {
            return (outcome, 0);
        }

        // CONTRACT C1: the first min(size, 4 MiB) bytes and not one more — the
        // exact prefix the driver hashes and ships on the read path. Hashing the
        // whole file would produce keys the read path can never match.
        // The KEY stays on the prefix; the bytes handed to the extractor may reach
        // further for a container format whose parser needs the file's tail (see
        // `cache::read_for_classification`) — without that, no .docx or .pdf over
        // 4 MiB could ever be classified, on any trigger.
        let started = Instant::now();
        let read = cache::read_for_classification(path, self.cfg.filter.max_file_bytes as usize);
        let read_ms = started.elapsed().as_millis() as u64;
        let prepared = match read {
            Ok(v) => v,
            Err(_) => return (WatchOutcome::Unreadable, read_ms),
        };
        let (content, truncated) = (prepared.content, prepared.truncated);
        if content.is_empty() {
            return (
                WatchOutcome::Skipped(filter::SkipReason::Empty),
                read_ms,
            );
        }

        let key = prepared.key;
        if self.cache.get(&key, model_version).is_some() {
            // The cheap second pass: one hash, no extraction, no forward pass.
            return (post_read_outcome(true, false), read_ms);
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
        (post_read_outcome(false, submitted), read_ms)
    }

    /// Persist the cursor. `force` distinguishes a scheduled checkpoint from the
    /// opportunistic one after a directory listing.
    fn maybe_checkpoint(&self, force: bool) {
        let cp = {
            let mut st = self.lock();
            if !st.cursor.active {
                return;
            }
            if !force && st.cursor.since_checkpoint < self.cfg.checkpoint_every {
                return;
            }
            st.cursor.since_checkpoint = 0;
            self.checkpoint_of(&st.cursor)
        };
        self.write_checkpoint(&cp);
    }

    /// Persist the cursor NOW — used on a clean stop.
    pub fn checkpoint_now(&self) -> bool {
        let cp = {
            let mut st = self.lock();
            if !st.cursor.active {
                return false;
            }
            st.cursor.since_checkpoint = 0;
            self.checkpoint_of(&st.cursor)
        };
        self.write_checkpoint(&cp)
    }

    fn write_checkpoint(&self, cp: &WalkCheckpoint) -> bool {
        match save_checkpoint(&self.cfg.state_dir, cp) {
            Ok(()) => {
                self.stats.checkpoints.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(e) => {
                // Losing a bookmark costs a restarted sweep, never correctness.
                tracing::warn!(error = %e, "ml walker: could not persist sweep checkpoint");
                false
            }
        }
    }

    fn checkpoint_of(&self, c: &Cursor) -> WalkCheckpoint {
        // Files still pending in the directory we are inside are NOT persisted;
        // instead that directory goes back on the front of the queue, so a resume
        // re-lists it. The files already done cost one hash each the second time
        // (they are cached), which is the cheap direction.
        let mut dirs: Vec<PathBuf> = Vec::with_capacity(c.dirs.len() + 1);
        if !c.files.is_empty() {
            if let Some(d) = c.last_dir.clone() {
                dirs.push(d);
            }
        }
        dirs.extend(c.dirs.iter().cloned());

        let truncated = dirs.len() > self.cfg.max_pending_dirs;
        WalkCheckpoint {
            version: CHECKPOINT_VERSION,
            sweep_seq: c.sweep_seq,
            started_at: c.started_at,
            full: c.full,
            model_version: queue::model_version_for_cache(),
            scopes_all: c.scopes_all.clone(),
            scopes_pending: c.scopes_pending.iter().cloned().collect(),
            current_scope: c.current_scope.clone(),
            pending_dirs: if truncated { Vec::new() } else { dirs },
            pending_truncated: truncated,
            last_dir: c.last_dir.clone(),
            counts: c.counts,
        }
    }

    /// End of the sweep: publish the coverage fact, drop the cursor.
    fn finish_sweep(&self) {
        let (full, completion) = {
            let mut st = self.lock();
            st.cursor.active = false;
            let c = &st.cursor;
            let completed_at = unix_now();
            let completion = SweepCompletion {
                version: CHECKPOINT_VERSION,
                sweep_seq: c.sweep_seq,
                started_at: c.started_at,
                completed_at,
                duration_secs: completed_at.saturating_sub(c.started_at),
                model_version: queue::model_version_for_cache(),
                scopes: c.scopes_all.clone(),
                counts: c.counts,
            };
            (c.full, completion)
        };

        clear_checkpoint(&self.cfg.state_dir);
        if !full {
            // A targeted re-sweep does not renew the estate-wide claim.
            tracing::info!(
                sweep = completion.sweep_seq,
                candidates = completion.counts.candidates,
                "ml walker: scope re-sweep finished"
            );
            return;
        }
        self.stats.sweeps_completed.fetch_add(1, Ordering::Relaxed);
        // Arm the local interlock: `denyUnclassified` is only honoured on an
        // endpoint that has actually been covered (see
        // `detect::decide::deny_unclassified`). A console switch cannot know
        // whether THIS machine has been swept; this is how it finds out.
        crate::detect::decide::set_sweep_completed(true);
        if let Err(e) = save_completion(&self.cfg.state_dir, &completion) {
            tracing::warn!(error = %e, "ml walker: could not persist sweep completion record");
        }
        // THE line an operator greps for before enabling denyUnclassified.
        tracing::info!(
            sweep = completion.sweep_seq,
            files = completion.counts.candidates,
            already_known = completion.counts.already_known,
            enqueued = completion.counts.enqueued,
            skipped = completion.counts.skipped,
            errors = completion.counts.errors,
            duration_secs = completion.duration_secs,
            "ml walker: FULL at-rest sweep complete"
        );
    }

    /// Drive the sweep with an injected clock until it completes, goes idle, or
    /// `max_steps` is spent. Returns the last status.
    ///
    /// **Test/CLI support.** The service loop ([`run`]) has its own loop because
    /// it must sleep on `Paused` and honour a stop flag; this one simply asks the
    /// caller's clock again, which is what makes a whole sweep a microsecond-long
    /// unit test.
    pub fn drive(&self, mut clock: impl FnMut() -> u64, max_steps: usize) -> StepStatus {
        let mut last = StepStatus::Idle;
        for _ in 0..max_steps {
            last = self.step(clock());
            match last {
                StepStatus::Completed | StepStatus::Idle | StepStatus::Inert => return last,
                _ => {}
            }
        }
        last
    }
}

// ---------------------------------------------------------------------------
// The service loop
// ---------------------------------------------------------------------------

/// Run sweeps until `stop` is set. One thread for the whole estate — the walker
/// is throttled by design, so parallelism would only defeat the throttle.
///
/// Order of business, forever:
/// 1. inert policy ⇒ do nothing at all (F3);
/// 2. a scope the watcher lost notifications for ⇒ targeted re-sweep;
/// 3. otherwise a full sweep (resumed from the checkpoint if there is one);
/// 4. then idle until `rescan_interval_secs`.
///
/// A clean stop persists the cursor and returns; it never leaves a half-written
/// checkpoint (temp + rename), and never abandons progress it could have kept.
pub fn run(walker: Arc<Walker>, stop: Arc<AtomicBool>) {
    let slice = Duration::from_millis(WALK_SLICE_MS);
    let mut next_full_sweep_at: u64 = 0; // unix seconds; 0 ⇒ sweep now

    while !stop.load(Ordering::Relaxed) {
        if crate::mlpolicy::active().is_inert() {
            std::thread::sleep(slice);
            continue;
        }

        if !walker.is_sweeping() {
            let flagged = walker.take_flagged_scopes();
            if !flagged.is_empty() {
                walker.begin_scope_sweep(&flagged);
            } else if unix_now() >= next_full_sweep_at {
                walker.begin_full_sweep();
            } else {
                std::thread::sleep(slice);
                continue;
            }
        }

        // Which KIND of sweep is now in flight — asked fresh rather than
        // inferred from which branch above just ran, so a sweep resumed
        // mid-flight (already active on loop entry, e.g. across a policy
        // toggle) is answered correctly too.
        //
        // This is what a targeted overflow re-sweep completing must NOT be
        // allowed to do: push the full-sweep backstop timer further out. Before
        // this check, `StepStatus::Completed` advanced `next_full_sweep_at` by
        // a full `rescan_interval_secs` regardless of which kind of sweep had
        // just finished, so an endpoint whose watcher keeps overflowing (one
        // flagged scope after another) could starve `begin_full_sweep`
        // indefinitely — and with it the completion record `denyUnclassified`
        // depends on.
        let is_full = walker.is_full_sweep();

        // Drive the current sweep.
        while !stop.load(Ordering::Relaxed) {
            match walker.step(now_ms()) {
                StepStatus::Paused { wait_ms } => {
                    // Sleep in slices so the stop flag is honoured promptly.
                    let mut left = wait_ms;
                    while left > 0 && !stop.load(Ordering::Relaxed) {
                        let n = left.min(WALK_SLICE_MS);
                        std::thread::sleep(Duration::from_millis(n));
                        left -= n;
                    }
                }
                StepStatus::Completed => {
                    if is_full {
                        next_full_sweep_at = unix_now() + walker.config().rescan_interval_secs;
                    }
                    break;
                }
                StepStatus::Inert | StepStatus::Idle => break,
                StepStatus::Descended | StepStatus::Processed(_) => {}
            }
        }
    }

    // Clean stop: keep what we learned.
    walker.checkpoint_now();
}

/// Spawn [`run`] on its own thread. `None` when the thread cannot be created —
/// logged, never fatal: the agent without a walker is the agent as it is today.
pub fn spawn(walker: Arc<Walker>, stop: Arc<AtomicBool>) -> Option<std::thread::JoinHandle<()>> {
    match std::thread::Builder::new()
        .name("ml-walk".to_string())
        .spawn(move || run(walker, stop))
    {
        Ok(h) => Some(h),
        Err(e) => {
            tracing::warn!(error = %e, "ml walker: could not spawn the at-rest sweep thread");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_hands_out_one_token_per_period() {
        // 60/min = one per second, burst 1.
        let mut l = RateLimiter::new(60, 1);
        assert!(l.try_take(0), "the burst token is available immediately");
        assert!(!l.try_take(0), "a second take at the same instant must fail");
        assert_eq!(l.wait_ms(0), 1_000);
        assert!(!l.try_take(999));
        assert!(l.try_take(1_000), "one second later a token exists");
    }

    #[test]
    fn unlimited_never_throttles() {
        let mut l = RateLimiter::unlimited();
        for _ in 0..1_000 {
            assert!(l.try_take(0));
        }
        assert_eq!(l.wait_ms(0), 0);
    }

    #[test]
    fn charge_pushes_the_next_token_further_out() {
        let mut l = RateLimiter::new(60, 4);
        assert!(l.try_take(0));
        l.charge(2.0);
        // 3 tokens were left, 2 charged ⇒ 1 left, still takeable...
        assert!(l.try_take(0));
        // ...and now empty.
        assert!(!l.try_take(0));
    }

    #[test]
    fn try_take_cost_charges_a_fraction_and_can_still_deplete_the_bucket() {
        // burst 1, no refill within the window: four quarter-tokens exhaust it.
        let mut l = RateLimiter::new(60, 1);
        assert!(l.try_take_cost(0, 0.25));
        assert!(l.try_take_cost(0, 0.25));
        assert!(l.try_take_cost(0, 0.25));
        assert!(l.try_take_cost(0, 0.25));
        assert!(
            !l.try_take_cost(0, 0.25),
            "the fifth quarter-token must fail — the bucket held exactly one"
        );
        // ...and the SAME bucket a full file-token draws from is now empty too.
        assert!(!l.try_take(0));
    }

    #[test]
    fn wait_ms_for_reports_time_until_a_fractional_amount_is_available() {
        let mut l = RateLimiter::new(60, 1); // 1 token/sec
        assert!(l.try_take(0)); // bucket now empty
        // Need a quarter-token back: at 1 tok/sec that is 250ms, rounded up.
        assert_eq!(l.wait_ms_for(0, 0.25), 250);
        assert_eq!(l.wait_ms_for(0, 1.0), 1_000);
    }

    #[test]
    fn refund_gives_back_a_token_but_never_past_the_burst_ceiling() {
        let mut l = RateLimiter::new(60, 2);
        assert!(l.try_take(0));
        assert!(l.try_take(0));
        assert!(!l.try_take(0), "bucket is empty");
        l.refund(1.0);
        assert!(l.try_take(0), "the refunded token is spendable");
        assert!(!l.try_take(0));
        // Refunding past a full bucket must not mint a surplus above burst.
        l.refund(10.0);
        assert_eq!(l.tokens(), 2.0, "refund clamps to the burst ceiling");
    }

    #[test]
    fn unlimited_ignores_cost_and_refund_too() {
        let mut l = RateLimiter::unlimited();
        assert!(l.try_take_cost(0, 0.01));
        assert_eq!(l.wait_ms_for(0, 999.0), 0);
        l.refund(5.0); // must not panic or do anything observable
    }
}
