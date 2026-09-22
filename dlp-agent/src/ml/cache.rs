//! CONTENT-HASH VERDICT CACHE — what lets the classifier guard the kernel READ
//! path without ever running on it.
//!
//! THE PROBLEM THIS EXISTS TO SOLVE
//! --------------------------------
//! `DlpPreRead` is a SYNCHRONOUS kernel up-call: the driver blocks the reading
//! thread, ships us up to `DLP_MAX_CONTENT` (4 MiB) of the file, and expects a
//! verdict inside `DLP_REPLY_TIMEOUT_MS` (500 ms). Eight consecutive timeouts
//! trip the IPC circuit breaker and every up-call on the machine short-circuits
//! to the fail mode. A DistilBERT forward pass costs ~10–100 ms typically and
//! ~640 ms at eight chunks — and the kguard message loop is single-threaded, so
//! one slow scan delays every other scan on the endpoint. Inference therefore
//! MUST NOT happen on that loop, ever. That is why `ml/mod.rs` documents the read
//! path as "never".
//!
//! But "never classify on read" used to mean "never classify a file at all"
//! unless it was on its way out through a write/copy/clipboard/upload channel. A
//! document authored on `C:\` this morning was adjudicated on fingerprints
//! alone, and fingerprinting cannot see a document nobody registered — so
//! RustDesk/AnyDesk/RDP could read it out.
//!
//! This module is the resolution: the model runs OFF the hot loop (a directory
//! watcher at creation, a throttled walker at rest, a bounded background queue on
//! a read-path miss) and deposits its answer here, keyed by content. The read
//! path then does a HashMap LOOKUP — microseconds — instead of an inference.
//!
//! FIVE PROPERTIES THAT ARE NOT OPTIONAL, AND WHY
//! ----------------------------------------------
//! 1. **The key is the driver's bytes, not the file.** [`MAX_HASHED_BYTES`] is
//!    `DLP_MAX_CONTENT`. The read path can only ever hash the prefix the kernel
//!    handed it, so the watcher and the walker must hash *exactly* that prefix
//!    too. Hash a whole 9 MB PDF and you mint a key the read path can never
//!    produce: the cache would fill up, report healthy stats, and never hit once.
//!    [`read_prefix_for_hashing`] is the single function both off-path producers
//!    use, so their key cannot diverge from the consumer's.
//! 2. **We store what the MODEL said, never what the POLICY concluded.** No
//!    `sensitive` field exists on [`CachedVerdict`] — deliberately. Sensitivity is
//!    `mlpolicy::active().label_is_sensitive(label_id, confidence)` evaluated at
//!    LOOKUP time. An admin who marks NUC sensitive, or drops a threshold from
//!    0.80 to 0.60, changes the whole estate's behaviour on the next read instead
//!    of invalidating every cached entry and waiting for a re-walk.
//! 3. **A stale model version is a MISS.** A different graph is a different
//!    opinion; label indices and calibration move. Content change needs no logic
//!    at all — different bytes are a different key.
//! 4. **Every entry is HMAC'd.** This cache can cause a file to be ALLOWED out. An
//!    attacker who can write to the agent state directory and relabel NUC content
//!    as OOD has an exfiltration path, so each record carries HMAC-SHA256 over its
//!    own bytes under a per-machine key sealed with DPAPI (machine scope), exactly
//!    like `src/storage.rs` seals the agent identity. A record that fails
//!    verification is DISCARDED — treated as a miss, counted, warned about once —
//!    never trusted and never panicked on.
//! 5. **It is a fast path, never an authority.** A miss NEVER means "not
//!    sensitive"; it means the caller falls back to whatever it did before this
//!    module existed. Nothing here can downgrade a fingerprint hit, and nothing
//!    here raises an incident: classifying a file is not a detection.
//!
//! PRIVACY (same rule as the rest of `ml/`, applied to a component that persists)
//! -----------------------------------------------------------------------------
//! A record holds a hash, a label id, an index, a score and three counts. **No
//! path, no file name, no directory, no content, not one extracted token.** The
//! on-disk log is readable by an incident responder and must be boring.
//!
//! CONCURRENCY — two independent locks, on purpose
//! -----------------------------------------------
//! Producers (watcher, walker, background queue, and the write path, which now
//! deposits its inline result here) all write; the consumer is the kguard message
//! loop, which must never wait. So:
//!
//! * `map: RwLock<HashMap<..>>` — the read path takes a READ lock and nothing
//!   else. Recency is an `AtomicU64` INSIDE the entry, so a hit updates LRU
//!   through the read lock and concurrent readers never serialise.
//! * `log: Mutex<LogState>` — the append handle. The read path never touches it,
//!   so a producer writing (or compacting) a multi-megabyte log cannot stall a
//!   lookup. Order is log-then-map, and `put` and `compact` both hold the log
//!   mutex while they touch the map: that is what guarantees a compaction's
//!   snapshot contains every record already in the log it is replacing. No
//!   path ever takes the map lock first, so the nesting cannot deadlock.
//!
//! There is **no fsync on the write path**. Losing the tail of a best-effort
//! cache costs one re-classification; an fsync per file on a walker would cost
//! the endpoint's disk.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::MlPrediction;

/// The number of leading bytes of a file that form its cache key.
///
/// This is `DLP_MAX_CONTENT` from `dlp-minifilter/src/dlpflt.h` and it is a
/// CONTRACT, not a tuning knob: the driver reads at most this much of a file
/// in-kernel and ships exactly those bytes up with `DLP_REASON_READ`. If the two
/// numbers ever diverge the cache goes 100% miss, silently.
pub const MAX_HASHED_BYTES: usize = 4 * 1024 * 1024;

/// Entry cap when the caller passes 0. ~200k entries is tens of MB resident.
pub const DEFAULT_MAX_ENTRIES: usize = 200_000;

/// The append-only durability log. Name is stable; responders will see it.
const LOG_FILE: &str = "ml-verdicts.log";
/// DPAPI-sealed (machine scope) HMAC key. Never leaves this machine.
const MAC_KEY_FILE: &str = "ml-cache.key";

/// Framing/HMAC domain tag. Bumped if the record layout ever changes, which
/// makes every old record fail verification and the cache rebuild itself.
const RECORD_MAGIC: &[u8] = b"dlpvc1\0";
/// A record is a hash plus a handful of numbers; anything larger is a corrupt
/// length prefix, not a record. Bounds how far a torn/garbled log can walk us.
const MAX_RECORD_BYTES: usize = 64 * 1024;

/// Compact once the log holds this many times more records than there are live
/// entries (and at least [`MIN_COMPACT_RECORDS`], so a small cache is not
/// rewritten constantly).
const LOG_BLOAT_FACTOR: u64 = 4;
const MIN_COMPACT_RECORDS: u64 = 4_096;

/// When the map is full, evict down to this fraction of the cap in ONE pass
/// rather than evicting a single entry per insert. Amortises the O(n) victim
/// selection to roughly once per `cap/20` insertions.
const EVICT_DOWN_TO: f64 = 0.95;

// ---------------------------------------------------------------------------
// Key
// ---------------------------------------------------------------------------

/// SHA-256 of the first `min(file_size, `[`MAX_HASHED_BYTES`]`)` bytes of a file.
///
/// Stored as the raw 32 bytes rather than the 64-char hex string, because the
/// consumer is the kguard message loop: hashing a `[u8; 32]` into a `HashMap` is
/// a fixed, allocation-free operation, whereas a `String` key costs an
/// allocation and a formatting pass per lookup on the one path that has a 500 ms
/// kernel budget. Hex is the CANONICAL RENDERING (contract C1, and what any log
/// line or console field shows) and round-trips through [`CacheKey::to_hex`] /
/// [`CacheKey::from_hex`] — lower-case, exactly as the driver's `file_sha256`
/// strings are formatted elsewhere in the agent.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CacheKey([u8; 32]);

impl CacheKey {
    /// Wrap raw digest bytes (e.g. a hash the driver already computed).
    pub fn from_bytes(b: [u8; 32]) -> Self {
        CacheKey(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lower-case hex — the canonical rendering (C1).
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0.iter() {
            // No `hex` crate in the tree and no reason to add one for 4 lines.
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
        }
        s
    }

    /// Parse the canonical rendering back. Accepts either case; returns `None`
    /// for anything that is not 64 hex digits.
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        let b = s.as_bytes();
        for (i, slot) in out.iter_mut().enumerate() {
            let hi = (b[2 * i] as char).to_digit(16)?;
            let lo = (b[2 * i + 1] as char).to_digit(16)?;
            *slot = ((hi << 4) | lo) as u8;
        }
        Some(CacheKey(out))
    }
}

impl std::fmt::Debug for CacheKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Debug-printing a key is safe (it is a hash, not content) but a full
        // 64 chars in a log line is noise: show the prefix responders quote.
        write!(f, "CacheKey({}…)", &self.to_hex()[..16])
    }
}

impl std::fmt::Display for CacheKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

// ---------------------------------------------------------------------------
// Value
// ---------------------------------------------------------------------------

/// What the MODEL said about one blob of content.
///
/// Note what is absent: `sensitive`. See property 2 in the module header — the
/// policy answers that at lookup time, not the cache at store time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CachedVerdict {
    /// Which graph produced this. A mismatch against the loaded engine is a MISS
    /// (C3), because label indices and calibration move between models.
    pub model_version: String,
    /// Frozen taxonomy id, e.g. `"NUC"`.
    pub label_id: String,
    /// Index into the model's 29-wide output layer.
    pub label_index: usize,
    /// Softmax probability of the winning label, in `[0, 1]`.
    pub confidence: f64,
    /// Chunks actually fed to the graph.
    pub chunks: usize,
    /// Content tokens before chunking.
    pub tokens: usize,
    /// `true` when the file was larger than [`MAX_HASHED_BYTES`], i.e. this
    /// answer describes a PREFIX. Reporting only — the key is the prefix either
    /// way, so a truncated entry is still a correct key for the read path (which
    /// is fed the same prefix).
    pub truncated: bool,
    /// Unix seconds at classification. Reporting and coverage metrics; never an
    /// expiry (content change already invalidates via the key).
    pub classified_at: u64,
}

impl CachedVerdict {
    /// Shape an engine answer for storage. `model_version` comes from the loaded
    /// engine/policy, not from the prediction, because the prediction does not
    /// carry one and the cache's staleness rule (C3) is defined against it.
    pub fn from_prediction(p: &MlPrediction, model_version: &str, truncated: bool) -> Self {
        CachedVerdict {
            model_version: model_version.to_string(),
            label_id: p.label_id.to_string(),
            label_index: p.label_index,
            confidence: p.confidence,
            chunks: p.chunks,
            tokens: p.tokens,
            truncated,
            classified_at: now_unix(),
        }
    }
}

/// Counters. Every field is monotonic except `entries`/`bytes_on_disk`, which are
/// instantaneous. Reported to the console as coverage/health; carries no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct CacheStats {
    pub entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    /// Records rejected by HMAC verification — on load or on lookup. **Any
    /// non-zero value is a tamper signal**, not a performance note.
    pub hmac_failures: u64,
    pub bytes_on_disk: u64,
}

// ---------------------------------------------------------------------------
// The cache
// ---------------------------------------------------------------------------

struct Entry {
    verdict: CachedVerdict,
    /// LRU recency. An atomic so a HIT can update it while holding only the
    /// READ lock — the whole reason lookups do not serialise (see header).
    used: AtomicU64,
}

struct LogState {
    /// `None` only between the close and reopen inside [`VerdictCache::compact`],
    /// or after a reopen failed. `put` retries the open itself, so a closed
    /// handle heals on the next write instead of switching persistence off.
    file: Option<File>,
    /// Records physically in the log, live or superseded. Drives compaction.
    records: u64,
}

pub struct VerdictCache {
    dir: PathBuf,
    max_entries: usize,
    map: RwLock<HashMap<CacheKey, Entry>>,
    log: Mutex<LogState>,
    /// Per-machine HMAC key, DPAPI-sealed at rest. Zeroized on drop.
    mac_key: Zeroizing<[u8; 32]>,
    tick: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    /// C4: a tampered log is summarised in ONE warning at `open` (see below),
    /// never one line per record — a poisoned log would otherwise bury every
    /// other message in the agent log.
    hmac_failures: AtomicU64,
    /// Armed by [`VerdictCache::put`], drained by [`VerdictCache::compact_if_pending`]
    /// on the background worker. `put` is reachable from the kguard message loop,
    /// which must never rewrite-and-fsync a log inside the kernel's 500 ms budget.
    compact_pending: std::sync::atomic::AtomicBool,
}

impl VerdictCache {
    /// Open (or create) the cache in `dir`, replaying the durability log.
    ///
    /// Never fails because of a damaged log: a torn tail is truncated away, a
    /// record that fails HMAC is dropped and counted. It fails only when the
    /// directory or the sealed key genuinely cannot be used — states in which
    /// silently running an unverified cache would be the wrong answer.
    pub fn open(dir: &Path, max_entries: usize) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating ml cache dir {}", dir.display()))?;
        let max_entries = if max_entries == 0 {
            DEFAULT_MAX_ENTRIES
        } else {
            max_entries
        };

        let (mac_key, key_is_new) = load_or_create_mac_key(dir)?;

        let log_path = dir.join(LOG_FILE);
        if key_is_new && log_path.exists() {
            // A fresh key cannot verify anything written under the old one (the
            // machine changed, or the sealed key was lost). Every record would
            // count as a tamper failure, so discard the log instead of alarming.
            tracing::warn!("ml cache: HMAC key regenerated — discarding unverifiable verdict log");
            let _ = std::fs::remove_file(&log_path);
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&log_path)
            .with_context(|| format!("opening ml verdict log {}", log_path.display()))?;

        let replay = replay_log(&mut file, &mac_key)?;
        if replay.torn_tail {
            // Truncate, or every future append sits behind unparseable bytes and
            // the log never replays again.
            file.set_len(replay.good_len)
                .context("truncating torn ml verdict log tail")?;
            tracing::warn!(
                good_len = replay.good_len,
                "ml cache: dropped a torn tail record from the verdict log"
            );
        }
        if replay.hmac_failures > 0 {
            tracing::warn!(
                failures = replay.hmac_failures,
                "ml cache: verdict records failed HMAC verification and were discarded (tamper signal)"
            );
        }
        file.seek(SeekFrom::End(0))
            .context("seeking ml verdict log to end")?;

        let mut map: HashMap<CacheKey, Entry> = HashMap::with_capacity(replay.entries.len());
        let mut tick = 0u64;
        for (k, v) in replay.entries {
            tick += 1;
            map.insert(
                k,
                Entry {
                    verdict: v,
                    used: AtomicU64::new(tick),
                },
            );
        }

        let cache = VerdictCache {
            dir: dir.to_path_buf(),
            max_entries,
            map: RwLock::new(map),
            log: Mutex::new(LogState {
                file: Some(file),
                records: replay.records,
            }),
            mac_key,
            tick: AtomicU64::new(tick),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            hmac_failures: AtomicU64::new(replay.hmac_failures),
            compact_pending: std::sync::atomic::AtomicBool::new(false),
        };

        // A log written under a larger cap (or bloated by superseded records)
        // can replay past the current cap. Trim before anyone can look us up.
        cache.evict_if_needed();
        Ok(cache)
    }

    /// SHA-256 of the bytes **as given**. The caller is responsible for giving it
    /// the right bytes; [`read_prefix_for_hashing`] is how a caller holding a
    /// path gets them, and the read path already holds them from the driver.
    pub fn key_for(bytes: &[u8]) -> CacheKey {
        let mut h = Sha256::new();
        h.update(bytes);
        CacheKey(h.finalize().into())
    }

    /// Look up a verdict produced by `model_version`.
    ///
    /// A stale entry (C3) is a MISS and is counted as one — it is not evicted
    /// here, because eviction would need the write lock and this runs on the
    /// kernel up-call path. Compaction and LRU retire it in due course.
    pub fn get(&self, key: &CacheKey, model_version: &str) -> Option<CachedVerdict> {
        let map = match self.map.read() {
            Ok(m) => m,
            // A poisoned lock means a producer panicked mid-insert. Fail the
            // LOOKUP, not the process: a miss is always safe (F1).
            Err(p) => p.into_inner(),
        };
        match map.get(key) {
            Some(e) if e.verdict.model_version == model_version => {
                e.used
                    .store(self.tick.fetch_add(1, Ordering::Relaxed) + 1, Ordering::Relaxed);
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(e.verdict.clone())
            }
            _ => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Store a model answer. Appends to the durability log FIRST (so a crash
    /// loses nothing that the map claims to hold), then inserts into the map.
    ///
    /// No fsync — see the module header.
    pub fn put(&self, key: CacheKey, verdict: CachedVerdict) -> Result<()> {
        let record = encode_record(&key, &verdict, &self.mac_key)?;

        let (appended, should_compact) = {
            let mut st = self.log.lock().unwrap_or_else(|p| p.into_inner());
            // Self-heal: a compaction whose reopen failed leaves the handle
            // closed. Retry the open here rather than refusing every write
            // until the service restarts.
            if st.file.is_none() {
                if let Ok(f) = open_log_for_append(&self.dir.join(LOG_FILE)) {
                    st.file = Some(f);
                }
            }
            let appended = match st.file.as_mut() {
                Some(f) => f.write_all(&record).context("appending ml verdict record"),
                None => Err(anyhow::anyhow!("ml verdict log is not open")),
            };
            if appended.is_ok() {
                st.records += 1;
            }

            // Insert into the map WHILE STILL HOLDING the log mutex. Lock order
            // in this type is always log -> map (`compact` snapshots the map
            // under the same mutex), so a compaction either sees this entry or
            // runs before its record exists: a record can never sit in the old
            // log, be missing from the snapshot, and be thrown away by the swap.
            //
            // The in-memory answer is kept even when the disk append failed —
            // the verdict itself is valid; only its survival across a restart
            // was lost, and the caller still sees the error below.
            {
                let mut map = self.map.write().unwrap_or_else(|p| p.into_inner());
                let tick = self.tick.fetch_add(1, Ordering::Relaxed) + 1;
                map.insert(
                    key,
                    Entry {
                        verdict,
                        used: AtomicU64::new(tick),
                    },
                );
            }
            (appended, st.records)
        };

        self.evict_if_needed();

        // Compaction is decided against the LIVE count, so a cache that is mostly
        // re-classifications of the same files does not grow without bound — but
        // it is only ARMED here, never RUN here.
        //
        // WHY: `put` is reachable from the kguard message loop. The WRITE branch
        // classifies inline and deposits its answer (contract P4), and that loop is
        // single-threaded with a 500 ms kernel budget behind it
        // (DLP_REPLY_TIMEOUT_MS) and a circuit breaker that short-circuits EVERY
        // up-call to FailMode after 8 consecutive timeouts. Compaction rewrites the
        // whole log and `sync_all`s it — tens of milliseconds on a small cache and
        // far more on a large one, on whatever the endpoint's disk is doing at the
        // time. Running that under the loop risks taking the machine to FailMode to
        // tidy a log file. The background worker calls
        // [`compact_if_pending`] instead.
        let live = self.len() as u64;
        if should_compact >= MIN_COMPACT_RECORDS && should_compact > live * LOG_BLOAT_FACTOR {
            self.compact_pending.store(true, Ordering::Relaxed);
        }
        appended
    }

    /// Run a compaction previously armed by [`put`], if one is due.
    ///
    /// Called by the background classify worker — never by a scan path. Cheap when
    /// nothing is armed (one relaxed load), so the worker can call it freely.
    pub fn compact_if_pending(&self) {
        if !self.compact_pending.swap(false, Ordering::Relaxed) {
            return;
        }
        if let Err(e) = self.compact() {
            // Housekeeping: a failure must never affect a verdict. Re-arm so the
            // next pass tries again rather than letting the log grow forever.
            self.compact_pending.store(true, Ordering::Relaxed);
            tracing::warn!(error = %e, "ml cache: verdict log compaction failed");
        }
    }

    /// Live entry count.
    pub fn len(&self) -> usize {
        self.map
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            entries: self.len(),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            hmac_failures: self.hmac_failures.load(Ordering::Relaxed),
            bytes_on_disk: std::fs::metadata(self.dir.join(LOG_FILE))
                .map(|m| m.len())
                .unwrap_or(0),
        }
    }

    /// Rewrite the log as exactly one record per live entry.
    ///
    /// Holds the log mutex for the whole operation and snapshots the map UNDER
    /// it; `put` appends and inserts under the same mutex (log -> map, the one
    /// lock order in this type), so no record can reach the old log after the
    /// snapshot and then be discarded by the swap.
    ///
    /// The swap is [`crate::atomicfile`]'s flushed rename-over: at every instant
    /// the log on disk is the complete old file or the complete compacted one.
    /// The previous sequence deleted the old log first, so a crash between the
    /// delete and the rename destroyed the whole cache even though a complete
    /// compacted copy was sitting beside it.
    ///
    /// Whatever happens, the append handle is REOPENED before returning — onto
    /// the compacted log on success, onto the untouched old log on failure.
    /// Leaving it closed after a failed swap (an antivirus scanner holding the
    /// file, say) made every later `put` fail and skip the in-memory insert too,
    /// silently switching the verdict cache off until the service restarted.
    pub fn compact(&self) -> Result<()> {
        let mut st = self.log.lock().unwrap_or_else(|p| p.into_inner());
        let snapshot: Vec<(CacheKey, CachedVerdict)> = {
            let map = self.map.read().unwrap_or_else(|p| p.into_inner());
            map.iter().map(|(k, e)| (*k, e.verdict.clone())).collect()
        };
        let log_path = self.dir.join(LOG_FILE);

        // Close the append handle before the swap. The replace itself would
        // succeed with it open (Rust opens files with delete-sharing), but a
        // handle kept across the swap would go on appending to the file that
        // was just replaced — every later record lost.
        st.file = None;
        let swapped = crate::atomicfile::write_atomic_with(
            &log_path,
            // Short: `put` from the kguard message loop waits on this mutex.
            crate::atomicfile::SHORT_RETRY_BUDGET,
            |f| {
                for (k, v) in &snapshot {
                    let rec = encode_record(k, v, &self.mac_key).map_err(std::io::Error::other)?;
                    f.write_all(&rec)?;
                }
                Ok(())
            },
        );

        match open_log_for_append(&log_path) {
            Ok(f) => st.file = Some(f),
            // `put` retries the open on its next call.
            Err(e) => tracing::warn!(error = %e, "ml cache: could not reopen the verdict log after compaction"),
        }

        match swapped {
            Ok(()) => {
                st.records = snapshot.len() as u64;
                Ok(())
            }
            Err(e) => Err(anyhow::Error::from(e).context("swapping compacted ml verdict log")),
        }
    }

    /// Drop the least recently used entries when the map is over its cap.
    ///
    /// Victim SELECTION runs under the read lock (blocks no reader) and the
    /// REMOVAL under the write lock is a bounded set of hash removals — that is
    /// what keeps the guarantee "a write never blocks the read path for longer
    /// than a map insert" true even at the 200k cap.
    fn evict_if_needed(&self) {
        let target = ((self.max_entries as f64) * EVICT_DOWN_TO) as usize;
        let victims: Vec<CacheKey> = {
            let map = self.map.read().unwrap_or_else(|p| p.into_inner());
            if map.len() <= self.max_entries {
                return;
            }
            let over = map.len() - target;
            let mut ages: Vec<(u64, CacheKey)> = map
                .iter()
                .map(|(k, e)| (e.used.load(Ordering::Relaxed), *k))
                .collect();
            let n = over.min(ages.len());
            if n == 0 {
                return;
            }
            // Partial selection: we only need the n oldest, not a sorted log.
            ages.select_nth_unstable(n - 1);
            ages[..n].iter().map(|(_, k)| *k).collect()
        };

        let mut removed = 0u64;
        {
            let mut map = self.map.write().unwrap_or_else(|p| p.into_inner());
            for k in victims {
                if map.remove(&k).is_some() {
                    removed += 1;
                }
            }
        }
        self.evictions.fetch_add(removed, Ordering::Relaxed);
    }

}

// ---------------------------------------------------------------------------
// The 4 MiB prefix rule (C1) — one function, so no caller can get it wrong
// ---------------------------------------------------------------------------

/// Read the first `min(file_size, `[`MAX_HASHED_BYTES`]`)` bytes of `path` and
/// report whether the file is longer than that.
///
/// This is THE way a producer that holds a path (the at-creation watcher, the
/// at-rest walker) obtains bytes to hash and to classify. It exists so nobody
/// can accidentally hash a whole file: a key built from 9 MB of PDF can never
/// equal the key the read path builds from the 4 MiB the driver shipped, and the
/// resulting cache would appear healthy while hitting zero times.
///
/// `truncated` is decided by attempting one byte PAST the cap rather than by
/// consulting metadata, so a file being appended to while we read still reports
/// the truth about the bytes we actually took.
pub fn read_prefix_for_hashing(path: &Path) -> std::io::Result<(Vec<u8>, bool)> {
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    while buf.len() < MAX_HASHED_BYTES {
        let want = (MAX_HASHED_BYTES - buf.len()).min(chunk.len());
        let n = f.read(&mut chunk[..want])?;
        if n == 0 {
            return Ok((buf, false)); // EOF before the cap: nothing was cut off
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    // Exactly at the cap. One more byte decides whether we truncated.
    let mut probe = [0u8; 1];
    let truncated = f.read(&mut probe)? > 0;
    Ok((buf, truncated))
}

/// One file, prepared for classification: the C1 key, and the bytes to extract from.
///
/// These are NOT always the same bytes, and that is the point.
pub struct PreparedRead {
    /// Always `sha256` of the first ≤ [`MAX_HASHED_BYTES`] — identical to what the
    /// read path computes from the driver's inline content.
    pub key: CacheKey,
    /// What the extractor should parse. Equal to the keyed prefix for an ordinary
    /// file; the WHOLE file (bounded) for a container format bigger than the cap.
    pub content: Vec<u8>,
    /// The file is longer than the keyed prefix.
    pub truncated: bool,
    /// `content` reaches past the keyed prefix because the format needed its tail.
    pub extended: bool,
}

/// Prepare a file a path-holding producer (the watcher, the walker) is about to
/// classify.
///
/// WHY THIS IS NOT JUST [`read_prefix_for_hashing`]
/// -----------------------------------------------
/// A ZIP-family container (`.docx`, `.xlsx`, `.pptx`, `.zip`) stores its central
/// directory at the END of the file, and a PDF its xref table. Hand a parser the
/// first 4 MiB of a 9 MB report and it does not return partial text — it fails
/// outright. Under the naive rule every Office document and every PDF over 4 MiB
/// was therefore permanently unclassifiable: extraction failed, the key was
/// remembered as barren, and the file was adjudicated on fingerprints forever
/// while the discovery sweep still counted it as covered. That is a silent
/// fail-open on exactly the large documents a defence site cares most about.
///
/// The watcher and the walker hold a path and run off any latency budget, so they
/// can read the whole file. The KEY still comes from the first 4 MiB, so it
/// matches what the read path derives from the driver's inline bytes — the cache
/// entry is found by the enforcement path, but its verdict was formed by reading
/// the entire document. `max_bytes` bounds the escalation (`[ml] max_file_bytes`).
///
/// Escalation is deliberately narrow: formats whose parser needs the tail. A
/// 40 MB log file classifies fine from its first 4 MiB and is not worth the read.
pub fn read_for_classification(path: &Path, max_bytes: usize) -> std::io::Result<PreparedRead> {
    let (prefix, truncated) = read_prefix_for_hashing(path)?;
    let key = VerdictCache::key_for(&prefix);

    if !truncated || !needs_whole_file(path) || max_bytes <= MAX_HASHED_BYTES {
        return Ok(PreparedRead { key, content: prefix, truncated, extended: false });
    }

    let mut f = File::open(path)?;
    let mut buf = Vec::with_capacity(MAX_HASHED_BYTES);
    let mut chunk = [0u8; 64 * 1024];
    while buf.len() < max_bytes {
        let want = (max_bytes - buf.len()).min(chunk.len());
        let n = f.read(&mut chunk[..want])?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    // Past `max_bytes` the tail is still missing, so the escalation bought nothing
    // and we keep the cheap prefix rather than carrying tens of MB through the
    // queue for a parse that will fail anyway.
    if buf.len() >= max_bytes {
        return Ok(PreparedRead { key, content: prefix, truncated, extended: false });
    }
    debug_assert_eq!(key, VerdictCache::key_for(&buf[..MAX_HASHED_BYTES.min(buf.len())]));
    Ok(PreparedRead { key, content: buf, truncated, extended: true })
}

/// Whether this file's extractor needs bytes from the END of the file.
///
/// ZIP-family containers keep the central directory at the end; PDF keeps its
/// xref there. Everything else this deployment extracts (plain text, CSV, RTF,
/// HTML) parses fine from a prefix. Derived from the format set in
/// `detect::extract` — the two must not drift.
fn needs_whole_file(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    matches!(ext.as_str(), "docx" | "xlsx" | "pptx" | "zip" | "pdf")
}

// ---------------------------------------------------------------------------
// Record framing + HMAC-SHA256
// ---------------------------------------------------------------------------

/// On-disk shape of one record's payload. Hash as hex (canonical, C1); no path,
/// no name, no content (C6).
#[derive(Serialize, Deserialize)]
struct LogRecord {
    k: String,
    v: CachedVerdict,
}

/// `[u32 LE payload_len][payload][32-byte HMAC]`
///
/// The MAC covers `RECORD_MAGIC || len_le || payload`, so the framing itself is
/// authenticated: an attacker cannot re-length a record to splice two entries
/// together without invalidating the tag.
/// Open the verdict log for appending, creating it if absent — the same options
/// `open` uses, shared so `compact` and `put` can reopen it identically.
fn open_log_for_append(path: &Path) -> std::io::Result<File> {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    f.seek(SeekFrom::End(0))?;
    Ok(f)
}

fn encode_record(key: &CacheKey, v: &CachedVerdict, mac_key: &[u8; 32]) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(&LogRecord {
        k: key.to_hex(),
        v: v.clone(),
    })
    .context("serialising ml verdict record")?;
    anyhow::ensure!(
        payload.len() <= MAX_RECORD_BYTES,
        "ml verdict record too large ({} bytes)",
        payload.len()
    );
    let len = (payload.len() as u32).to_le_bytes();
    let tag = hmac_sha256(mac_key, &[RECORD_MAGIC, &len, &payload]);

    let mut out = Vec::with_capacity(4 + payload.len() + 32);
    out.extend_from_slice(&len);
    out.extend_from_slice(&payload);
    out.extend_from_slice(&tag);
    Ok(out)
}

struct Replay {
    entries: Vec<(CacheKey, CachedVerdict)>,
    records: u64,
    hmac_failures: u64,
    torn_tail: bool,
    /// Byte offset of the end of the last INTACT record.
    good_len: u64,
}

/// Replay the whole log from offset 0.
///
/// Failure taxonomy, and it matters:
/// * a record whose framing cannot be completed (short read, absurd length) is a
///   TORN TAIL — the process died mid-append. Stop, truncate, carry on (C5).
/// * a record that frames fine but fails its MAC is TAMPERING. Skip it, count
///   it, keep replaying — one poisoned entry must not cost the whole cache.
fn replay_log(file: &mut File, mac_key: &[u8; 32]) -> Result<Replay> {
    file.seek(SeekFrom::Start(0))?;
    let mut all = Vec::new();
    file.read_to_end(&mut all).context("reading ml verdict log")?;

    let mut entries = Vec::new();
    let mut records = 0u64;
    let mut hmac_failures = 0u64;
    let mut off = 0usize;
    let mut torn_tail = false;

    while off < all.len() {
        if all.len() - off < 4 {
            torn_tail = true;
            break;
        }
        let len =
            u32::from_le_bytes([all[off], all[off + 1], all[off + 2], all[off + 3]]) as usize;
        if len == 0 || len > MAX_RECORD_BYTES {
            torn_tail = true;
            break;
        }
        let payload_start = off + 4;
        let payload_end = payload_start + len;
        let tag_end = payload_end + 32;
        if tag_end > all.len() {
            torn_tail = true;
            break;
        }
        let payload = &all[payload_start..payload_end];
        let tag = &all[payload_end..tag_end];
        let want = hmac_sha256(
            mac_key,
            &[RECORD_MAGIC, &all[off..off + 4], payload],
        );
        if ct_eq(&want, tag) {
            match serde_json::from_slice::<LogRecord>(payload) {
                Ok(rec) => match CacheKey::from_hex(&rec.k) {
                    // Later records supersede earlier ones for the same key; the
                    // map insert below preserves that because we replay in order.
                    Some(k) => entries.push((k, rec.v)),
                    None => hmac_failures += 1, // authenticated but malformed: same disposition
                },
                Err(_) => hmac_failures += 1,
            }
        } else {
            hmac_failures += 1;
        }
        records += 1;
        off = tag_end;
    }

    Ok(Replay {
        entries,
        records,
        hmac_failures,
        torn_tail,
        good_len: off as u64,
    })
}

/// HMAC-SHA256, RFC 2104, built on the `sha2` already in the tree.
///
/// Written by hand rather than adding the `hmac` crate: this repo ships to
/// air-gapped defence sites and every npm/crates dependency is supply-chain
/// surface we have to justify (CLAUDE.md). HMAC is twelve lines of well-specified
/// padding around a hash we already depend on and already trust — the construction
/// is:
///
/// ```text
/// K'   = K padded with zeros to the 64-byte SHA-256 block size (our K is 32 bytes,
///        so the "hash the key if it is longer than a block" branch cannot trigger
///        — asserted below rather than left implicit)
/// HMAC = H( (K' XOR opad) || H( (K' XOR ipad) || message ) )
/// ipad = 0x36 repeated, opad = 0x5c repeated
/// ```
///
/// `parts` is hashed in order, so callers can bind framing fields into the tag
/// without concatenating buffers.
fn hmac_sha256(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    const BLOCK: usize = 64;
    // Our key is exactly 32 bytes by construction, i.e. shorter than the block:
    // the RFC's "if len(K) > B: K = H(K)" branch is unreachable here.
    debug_assert!(key.len() <= BLOCK);

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..key.len() {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    for p in parts {
        inner.update(p);
    }
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

/// Constant-time comparison. A tag check that short-circuits on the first
/// differing byte leaks how much of a forged tag was right, which is exactly the
/// oracle a local attacker needs to build a valid one.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Per-machine MAC key, sealed at rest
// ---------------------------------------------------------------------------

/// Load the sealed HMAC key, or mint one on first run.
///
/// Returns `(key, is_new)`; `is_new` tells [`VerdictCache::open`] to discard a
/// log it can no longer verify instead of reporting every record as tampered.
///
/// Sealing mirrors `src/storage.rs`: DPAPI **machine scope** on Windows, so the
/// key file is useless on any other PC, and a plain file elsewhere.
fn load_or_create_mac_key(dir: &Path) -> Result<(Zeroizing<[u8; 32]>, bool)> {
    let path = dir.join(MAC_KEY_FILE);
    if path.exists() {
        match std::fs::read(&path).map_err(anyhow::Error::from).and_then(|sealed| unseal(&sealed)) {
            Ok(plain) if plain.len() == 32 => {
                let mut k = Zeroizing::new([0u8; 32]);
                k.copy_from_slice(&plain);
                return Ok((k, false));
            }
            Ok(_) => {
                tracing::warn!("ml cache: sealed HMAC key has the wrong length — regenerating");
            }
            Err(e) => {
                // Unsealable = the machine changed or the blob was corrupted.
                // Regenerating is the fail-safe answer: every cached entry
                // becomes unverifiable and therefore a MISS, which costs
                // re-classification and never a wrong "allow".
                tracing::warn!(error = %e, "ml cache: could not unseal HMAC key — regenerating");
            }
        }
    }

    let mut k = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut k[..]);
    let sealed = seal(&k[..]).context("sealing ml cache HMAC key")?;
    // Atomic: a key file torn by a crash would be unsealable on the next start,
    // which regenerates the key and discards every cached verdict.
    crate::atomicfile::write_atomic_with(&path, crate::atomicfile::DEFAULT_RETRY_BUDGET, |f| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(&sealed)
    })
    .with_context(|| format!("writing {}", path.display()))?;
    Ok((k, true))
}

// DPAPI, machine scope — byte-for-byte the same two calls `storage.rs` makes for
// the agent identity and the KEK keyring, with the same flag
// (`CRYPTPROTECT_LOCAL_MACHINE`), so the sealed key opens on this PC and nowhere
// else.
//
// WHY IT IS SPELLED OUT AGAIN HERE RATHER THAN CALLED: `storage::seal`/`unseal`
// and their `dpapi` submodule are PRIVATE to `storage.rs`, and this task's file
// ownership does not include that file (several agents are editing this repo
// concurrently). No new cryptography is introduced — this is the identical
// Win32 pair. FOLLOW-UP for whoever owns `storage.rs` next: make
// `storage::{seal, unseal}` `pub(crate)` and delete this block.
#[cfg(windows)]
fn seal(plain: &[u8]) -> Result<Vec<u8>> {
    win_dpapi::protect(plain)
}
#[cfg(windows)]
fn unseal(sealed: &[u8]) -> Result<Vec<u8>> {
    win_dpapi::unprotect(sealed)
}

#[cfg(windows)]
mod win_dpapi {
    use anyhow::{bail, Result};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
    };

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        }
    }

    fn take_and_free(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
        unsafe {
            let _ = LocalFree(HLOCAL(out.pbData as *mut core::ffi::c_void));
        }
        v
    }

    pub fn protect(plain: &[u8]) -> Result<Vec<u8>> {
        let mut input = blob(plain);
        let mut output = CRYPT_INTEGER_BLOB::default();
        let ok = unsafe {
            CryptProtectData(
                &mut input,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_LOCAL_MACHINE,
                &mut output,
            )
        };
        if ok.is_err() {
            bail!("CryptProtectData failed: {ok:?}");
        }
        Ok(take_and_free(output))
    }

    pub fn unprotect(sealed: &[u8]) -> Result<Vec<u8>> {
        let mut input = blob(sealed);
        let mut output = CRYPT_INTEGER_BLOB::default();
        let ok = unsafe {
            CryptUnprotectData(
                &mut input,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_LOCAL_MACHINE,
                &mut output,
            )
        };
        if ok.is_err() {
            bail!("CryptUnprotectData failed: {ok:?}");
        }
        Ok(take_and_free(output))
    }
}

// NON-WINDOWS / DEV BUILDS ONLY. There is no DPAPI here, so the key file holds
// RAW key material — exactly the same compromise `storage.rs::seal` already
// makes for the agent identity and the KEK keyring, and for the same reason:
// the product target is Windows and the cross-compile has to keep building so
// the pure-logic tests can run anywhere. Never ship this configuration.
#[cfg(not(windows))]
fn seal(plain: &[u8]) -> Result<Vec<u8>> {
    Ok(plain.to_vec())
}
#[cfg(not(windows))]
fn unseal(sealed: &[u8]) -> Result<Vec<u8>> {
    Ok(sealed.to_vec())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
