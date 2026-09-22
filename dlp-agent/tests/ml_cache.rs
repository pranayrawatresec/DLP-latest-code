//! Gate for the content-hash verdict cache (src/ml/cache.rs).
//!
//! This cache can cause a file to be ALLOWED past the kernel read-deny path, so
//! the interesting assertions here are not "does put/get work" but the four
//! properties a mistake in which is silent:
//!
//! * **Key equivalence.** `read_prefix_for_hashing` on a 5 MiB file MUST produce
//!   the same key as `key_for` on the first 4 MiB — because the read path can
//!   only ever hash the prefix the driver shipped. Get this wrong and the cache
//!   fills, reports healthy stats, and hits zero times forever.
//! * **Staleness.** A verdict from another model version is a MISS, never a
//!   silently-reinterpreted label index.
//! * **Tamper.** One flipped byte in the persisted log makes an entry disappear
//!   (a miss, counted) rather than relabel content or panic the agent.
//! * **Crash tolerance.** A log torn mid-record loses only the torn record.

use std::path::PathBuf;
use std::sync::Arc;

use dlp_agent::ml::cache::{
    read_prefix_for_hashing, CachedVerdict, VerdictCache, MAX_HASHED_BYTES,
};

const MV: &str = "V6.2.01";

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "dlp-ml-cache-{tag}-{}-{:?}",
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

fn verdict(label: &str, model_version: &str) -> CachedVerdict {
    CachedVerdict {
        model_version: model_version.to_string(),
        label_id: label.to_string(),
        label_index: 7,
        confidence: 0.9137,
        chunks: 2,
        tokens: 640,
        truncated: false,
        classified_at: 1_700_000_000,
    }
}

// =====================================================================
// Round trip
// =====================================================================

#[test]
fn put_then_get_round_trips_and_unknown_key_misses() {
    let dir = temp_dir("roundtrip");
    let c = VerdictCache::open(&dir, 128).unwrap();

    let k = VerdictCache::key_for(b"a classified paragraph");
    assert!(c.get(&k, MV).is_none(), "empty cache must miss");

    c.put(k, verdict("NUC", MV)).unwrap();
    let got = c.get(&k, MV).expect("stored verdict must come back");
    assert_eq!(got, verdict("NUC", MV));

    let other = VerdictCache::key_for(b"something else entirely");
    assert!(c.get(&other, MV).is_none(), "unknown key must miss");

    let s = c.stats();
    assert_eq!(s.entries, 1);
    assert_eq!(s.hits, 1);
    assert_eq!(s.misses, 2);
    assert_eq!(s.hmac_failures, 0);
    assert!(s.bytes_on_disk > 0, "the put must have been journalled");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn no_sensitive_field_is_persisted() {
    // C2: the cache stores the MODEL's answer, never the POLICY's conclusion.
    // If a `sensitive` flag ever creeps into the record, an admin changing a
    // threshold would stop taking effect on cached files — a silent protection
    // regression. Assert against the on-disk bytes, which is where it would show.
    let dir = temp_dir("nosensitive");
    let c = VerdictCache::open(&dir, 16).unwrap();
    c.put(VerdictCache::key_for(b"x"), verdict("NUC", MV)).unwrap();
    drop(c);

    let raw = std::fs::read(dir.join("ml-verdicts.log")).unwrap();
    let text = String::from_utf8_lossy(&raw);
    assert!(
        !text.contains("sensitive"),
        "cache record must not carry a policy conclusion: {text}"
    );
    // C6: and it must carry no path or file name either.
    assert!(!text.contains(".docx") && !text.contains("C:\\"));

    let _ = std::fs::remove_dir_all(&dir);
}

// =====================================================================
// C1 — the 4 MiB prefix rule. THE assertion the whole feature rests on.
// =====================================================================

#[test]
fn prefix_hashing_matches_the_read_paths_key_on_a_large_file() {
    let dir = temp_dir("prefix");
    let path = dir.join("big.bin");

    // 5 MiB of non-repeating bytes, so hashing 4 MiB and hashing 5 MiB cannot
    // collide by accident.
    let mut content = Vec::with_capacity(5 * 1024 * 1024);
    let mut x: u32 = 0x1234_5678;
    while content.len() < 5 * 1024 * 1024 {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        content.extend_from_slice(&x.to_le_bytes());
    }
    content.truncate(5 * 1024 * 1024);
    std::fs::write(&path, &content).unwrap();

    let (prefix, truncated) = read_prefix_for_hashing(&path).unwrap();
    assert_eq!(prefix.len(), MAX_HASHED_BYTES, "must stop at DLP_MAX_CONTENT");
    assert!(truncated, "a 5 MiB file must report truncated");
    assert_eq!(prefix, &content[..MAX_HASHED_BYTES], "must be the LEADING prefix");

    // The equivalence: what the walker/watcher computes == what the read path,
    // holding the driver's 4 MiB buffer, computes.
    let from_file = VerdictCache::key_for(&prefix);
    let from_driver_buffer = VerdictCache::key_for(&content[..MAX_HASHED_BYTES]);
    assert_eq!(from_file, from_driver_buffer);

    // And it must NOT equal the whole-file hash — the bug this test exists for.
    assert_ne!(from_file, VerdictCache::key_for(&content));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn prefix_hashing_on_a_small_file_reads_all_of_it_and_is_not_truncated() {
    let dir = temp_dir("small");
    let path = dir.join("small.txt");
    std::fs::write(&path, b"short document").unwrap();

    let (bytes, truncated) = read_prefix_for_hashing(&path).unwrap();
    assert_eq!(bytes, b"short document");
    assert!(!truncated);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn prefix_hashing_at_exactly_the_cap_is_not_truncated() {
    // Boundary: a file of exactly DLP_MAX_CONTENT bytes was fully seen, so
    // `truncated` must be false. Getting this off-by-one wrong would mis-report
    // coverage on every 4 MiB file.
    let dir = temp_dir("exact");
    let path = dir.join("exact.bin");
    std::fs::write(&path, vec![0xABu8; MAX_HASHED_BYTES]).unwrap();

    let (bytes, truncated) = read_prefix_for_hashing(&path).unwrap();
    assert_eq!(bytes.len(), MAX_HASHED_BYTES);
    assert!(!truncated);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn key_hex_round_trips() {
    let k = VerdictCache::key_for(b"abc");
    let hex = k.to_hex();
    assert_eq!(hex.len(), 64);
    assert_eq!(hex, hex.to_lowercase(), "canonical rendering is lower-case");
    // SHA-256("abc"), the standard vector — proves key_for really is plain
    // SHA-256 over the bytes as given, with no salt or domain tag mixed in
    // (the driver's hash has none either).
    assert_eq!(
        hex,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        dlp_agent::ml::cache::CacheKey::from_hex(&hex).unwrap(),
        k
    );
    assert!(dlp_agent::ml::cache::CacheKey::from_hex("nope").is_none());
}

// =====================================================================
// C3 — staleness
// =====================================================================

#[test]
fn an_entry_from_another_model_version_is_a_miss() {
    let dir = temp_dir("stale");
    let c = VerdictCache::open(&dir, 32).unwrap();
    let k = VerdictCache::key_for(b"doc");
    c.put(k, verdict("NUC", "V6.2.01")).unwrap();

    assert!(c.get(&k, "V6.2.01").is_some());
    assert!(
        c.get(&k, "V7").is_none(),
        "a different graph's label space must not be reused"
    );
    assert_eq!(c.stats().misses, 1);

    let _ = std::fs::remove_dir_all(&dir);
}

// =====================================================================
// C4 — tamper
// =====================================================================

#[test]
fn flipping_one_byte_of_a_persisted_entry_makes_it_a_miss_and_counts_it() {
    let dir = temp_dir("tamper");
    let k_good = VerdictCache::key_for(b"innocuous");
    let k_bad = VerdictCache::key_for(b"classified");
    {
        let c = VerdictCache::open(&dir, 32).unwrap();
        c.put(k_bad, verdict("NUC", MV)).unwrap();
        c.put(k_good, verdict("OOD", MV)).unwrap();
    }

    // Relabel NUC -> OOD in the first record: the exfiltration path C4 exists
    // to close. Same length, so the framing still parses — only the MAC objects.
    let log = dir.join("ml-verdicts.log");
    let mut raw = std::fs::read(&log).unwrap();
    let at = raw
        .windows(3)
        .position(|w| w == b"NUC")
        .expect("record must contain the label id");
    raw[at..at + 3].copy_from_slice(b"OOD");
    std::fs::write(&log, &raw).unwrap();

    let c = VerdictCache::open(&dir, 32).unwrap();
    assert!(
        c.get(&k_bad, MV).is_none(),
        "a tampered record must be discarded, not trusted"
    );
    assert!(
        c.get(&k_good, MV).is_some(),
        "one poisoned record must not cost the whole cache"
    );
    let s = c.stats();
    assert_eq!(s.hmac_failures, 1, "the tamper must be counted");
    assert_eq!(s.entries, 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_foreign_hmac_key_invalidates_the_whole_log_without_erroring() {
    // Copying a state directory to another machine (where DPAPI cannot unseal)
    // must degrade to an empty cache, never to a cache of unverified verdicts.
    let dir = temp_dir("foreignkey");
    {
        let c = VerdictCache::open(&dir, 32).unwrap();
        c.put(VerdictCache::key_for(b"doc"), verdict("NUC", MV)).unwrap();
    }
    // Simulate "the sealed key no longer opens": destroy it.
    std::fs::write(dir.join("ml-cache.key"), b"not a sealed key").unwrap();

    let c = VerdictCache::open(&dir, 32).unwrap();
    assert_eq!(c.len(), 0, "unverifiable entries must not be loaded");
    assert!(c.get(&VerdictCache::key_for(b"doc"), MV).is_none());

    // And the cache is usable again immediately under the new key.
    let k = VerdictCache::key_for(b"doc2");
    c.put(k, verdict("FIN", MV)).unwrap();
    assert!(c.get(&k, MV).is_some());

    let _ = std::fs::remove_dir_all(&dir);
}

// =====================================================================
// C5 — bounded + crash safe
// =====================================================================

#[test]
fn reopening_after_a_crash_truncated_log_keeps_every_intact_record() {
    let dir = temp_dir("torn");
    let keys: Vec<_> = (0..5)
        .map(|i| VerdictCache::key_for(format!("doc-{i}").as_bytes()))
        .collect();
    {
        let c = VerdictCache::open(&dir, 64).unwrap();
        for k in &keys {
            c.put(*k, verdict("NUC", MV)).unwrap();
        }
    }

    // Cut the file mid-record: 20 bytes past the last record boundary is well
    // inside the fifth record's payload.
    let log = dir.join("ml-verdicts.log");
    let full = std::fs::metadata(&log).unwrap().len();
    let record_len = full / 5;
    let torn_at = record_len * 4 + 20;
    assert!(torn_at < full && torn_at > record_len * 4);
    let raw = std::fs::read(&log).unwrap();
    std::fs::write(&log, &raw[..torn_at as usize]).unwrap();

    let c = VerdictCache::open(&dir, 64).unwrap();
    for k in &keys[..4] {
        assert!(c.get(k, MV).is_some(), "intact records must survive");
    }
    assert!(c.get(&keys[4], MV).is_none(), "the torn record is gone");
    assert_eq!(c.stats().hmac_failures, 0, "a torn tail is not tampering");

    // The tail must have been truncated away, or the next append is unreadable.
    assert_eq!(std::fs::metadata(&log).unwrap().len(), record_len * 4);

    // Prove it: append after the repair and reopen once more.
    let k_new = VerdictCache::key_for(b"after-repair");
    c.put(k_new, verdict("FIN", MV)).unwrap();
    drop(c);
    let c = VerdictCache::open(&dir, 64).unwrap();
    assert!(c.get(&k_new, MV).is_some());
    assert_eq!(c.len(), 5);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn lru_eviction_holds_the_cap_and_keeps_the_recently_used() {
    let cap = 40;
    let dir = temp_dir("lru");
    let c = VerdictCache::open(&dir, cap).unwrap();

    let keys: Vec<_> = (0..cap)
        .map(|i| VerdictCache::key_for(format!("k{i}").as_bytes()))
        .collect();
    for k in &keys {
        c.put(*k, verdict("NUC", MV)).unwrap();
    }
    assert_eq!(c.len(), cap);

    // Touch the last 10 so they are the most recently USED, not merely the most
    // recently inserted — that is the difference between LRU and FIFO.
    for k in &keys[cap - 10..] {
        assert!(c.get(k, MV).is_some());
    }

    // Overflow by 10 fresh keys.
    for i in cap..cap + 10 {
        c.put(
            VerdictCache::key_for(format!("k{i}").as_bytes()),
            verdict("NUC", MV),
        )
        .unwrap();
    }

    assert!(c.len() <= cap, "the cap must hold, got {}", c.len());
    assert!(c.stats().evictions > 0, "eviction must have been counted");
    for k in &keys[cap - 10..] {
        assert!(c.get(k, MV).is_some(), "recently used entries must survive");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn compaction_preserves_live_entries_and_shrinks_the_log() {
    let dir = temp_dir("compact");
    let c = VerdictCache::open(&dir, 64).unwrap();
    let k = VerdictCache::key_for(b"rewritten-many-times");

    // 200 supersedes of ONE key: 200 records, one live entry.
    for i in 0..200 {
        let mut v = verdict("NUC", MV);
        v.classified_at = 1_700_000_000 + i;
        c.put(k, v).unwrap();
    }
    let k2 = VerdictCache::key_for(b"other");
    c.put(k2, verdict("FIN", MV)).unwrap();

    let before = c.stats().bytes_on_disk;
    c.compact().unwrap();
    let after = c.stats().bytes_on_disk;
    assert!(after < before, "compaction must shrink the log ({before} -> {after})");

    assert_eq!(c.get(&k, MV).unwrap().classified_at, 1_700_000_199);
    assert_eq!(c.get(&k2, MV).unwrap().label_id, "FIN");

    // And the compacted log must still replay.
    drop(c);
    let c = VerdictCache::open(&dir, 64).unwrap();
    assert_eq!(c.len(), 2);
    assert_eq!(c.get(&k, MV).unwrap().classified_at, 1_700_000_199);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn automatic_compaction_is_armed_by_put_and_run_off_the_hot_path() {
    // The self-healing property: a machine that reclassifies the same handful of
    // files forever must not grow an unbounded log. MIN_COMPACT_RECORDS is 4096.
    //
    // But `put` must never RUN the compaction. It is reachable from the kguard
    // message loop (the write path deposits its inline result there), and that
    // loop is single-threaded behind the kernel's 500 ms DLP_REPLY_TIMEOUT_MS with
    // a breaker that sends every up-call on the machine to FailMode after eight
    // consecutive timeouts. Rewriting and fsyncing a multi-megabyte log inside
    // that budget would risk the endpoint to tidy a file. So `put` ARMS it and
    // the background classify worker drains it via `compact_if_pending`.
    let dir = temp_dir("autocompact");
    let c = VerdictCache::open(&dir, 1_000).unwrap();
    let keys: Vec<_> = (0..4)
        .map(|i| VerdictCache::key_for(format!("hot-{i}").as_bytes()))
        .collect();
    for i in 0..6_000 {
        c.put(keys[i % 4], verdict("NUC", MV)).unwrap();
    }
    assert_eq!(c.len(), 4);

    // Still bloated: no put rewrote the log.
    let armed = c.stats().bytes_on_disk;
    assert!(
        armed > 4_096 * 20,
        "put must NOT compact inline; log is only {armed} bytes, so something          rewrote it on the hot path"
    );

    // The worker's housekeeping call is what reclaims it.
    c.compact_if_pending();
    let after = c.stats().bytes_on_disk;
    assert!(
        after < armed / 4,
        "compact_if_pending should have reclaimed the log: {armed} -> {after} bytes"
    );
    assert_eq!(c.len(), 4, "compaction preserves every live entry");

    // Idempotent: nothing is armed now, so a second call is a no-op.
    c.compact_if_pending();
    assert_eq!(c.stats().bytes_on_disk, after);

    // And the compacted log still replays.
    drop(c);
    let c = VerdictCache::open(&dir, 1_000).unwrap();
    assert_eq!(c.len(), 4);

    let _ = std::fs::remove_dir_all(&dir);
}

// =====================================================================
// Concurrency smoke
// =====================================================================

#[test]
fn concurrent_writers_and_a_reader_do_not_deadlock() {
    let dir = temp_dir("threads");
    let c = Arc::new(VerdictCache::open(&dir, 500).unwrap());

    let mut handles = Vec::new();
    for t in 0..6 {
        let c = Arc::clone(&c);
        handles.push(std::thread::spawn(move || {
            for i in 0..200 {
                let k = VerdictCache::key_for(format!("t{t}-i{i}").as_bytes());
                c.put(k, verdict("NUC", MV)).unwrap();
            }
        }));
    }
    // The read path, running throughout: it must never block for long and must
    // never observe a torn value.
    {
        let c = Arc::clone(&c);
        handles.push(std::thread::spawn(move || {
            for i in 0..3_000 {
                let k = VerdictCache::key_for(format!("t0-i{}", i % 200).as_bytes());
                if let Some(v) = c.get(&k, MV) {
                    assert_eq!(v.label_id, "NUC");
                    assert_eq!(v.model_version, MV);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    assert!(c.len() <= 500);
    // Everything written is still verifiable after a reopen.
    let entries = c.len();
    drop(c);
    let c = VerdictCache::open(&dir, 500).unwrap();
    assert_eq!(c.stats().hmac_failures, 0);
    assert!(c.len() >= entries.min(500).saturating_sub(500));

    let _ = std::fs::remove_dir_all(&dir);
}

// =====================================================================
// Compaction must never cost the cache — the two defects fixed alongside
// the atomic-write helper
// =====================================================================

/// A compaction whose swap FAILS (an antivirus scanner holding the log without
/// delete-sharing) used to leave the append handle closed. Every later `put`
/// then returned "log is not open" before its in-memory insert, silently
/// switching the verdict cache off until the service restarted.
#[cfg(windows)]
#[test]
fn a_failed_compaction_leaves_the_cache_fully_working() {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;

    let dir = temp_dir("compact-fail");
    let c = VerdictCache::open(&dir, 1024).unwrap();
    let before = VerdictCache::key_for(b"written before the failed compaction");
    c.put(before, verdict("FIN", MV)).unwrap();

    // Hold the log the way a scanner does: read/write sharing, NOT delete.
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(dir.join("ml-verdicts.log"))
        .unwrap();
    assert!(c.compact().is_err(), "the swap cannot succeed while the log is held");

    // The cache must keep working — in memory AND on disk.
    let after = VerdictCache::key_for(b"written after the failed compaction");
    c.put(after, verdict("NUC", MV)).expect("a put after a failed compaction must succeed");
    assert!(c.get(&after, MV).is_some(), "and be visible in memory");
    drop(holder);
    drop(c);

    let reopened = VerdictCache::open(&dir, 1024).unwrap();
    assert_eq!(reopened.get(&before, MV).map(|v| v.label_id), Some("FIN".to_string()));
    assert_eq!(
        reopened.get(&after, MV).map(|v| v.label_id),
        Some("NUC".to_string()),
        "the post-failure record must have been persisted, not just held in memory"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Writers racing compactions. The invariant: the moment a compaction returns,
/// EVERY record whose `put` has already returned Ok is on disk.
///
/// Checked after every single compaction against a copy of what is on disk —
/// not just at the end, because a record a compaction drops is silently
/// restored by the NEXT one (it rewrites from memory), so an end-of-run check
/// only catches a loss in the last window and passes by luck. Before the fix
/// both halves of the race were open: `compact` snapshotted the map before
/// taking the log mutex, and `put` inserted into the map after releasing it —
/// either way a record could sit in the old log, be missing from the snapshot,
/// and be thrown away by the swap, surviving a crash only if another compaction
/// happened to run first.
#[test]
fn every_acknowledged_record_is_on_disk_the_moment_a_compaction_returns() {
    // Well above anything the writers can produce, so LRU EVICTION (which
    // legitimately drops entries from the next compacted log) can never be
    // mistaken for a durability loss.
    const CAP: usize = 10_000_000;
    const PER_WRITER: u32 = 1_500;
    let dir = temp_dir("compact-race");
    let c = Arc::new(VerdictCache::open(&dir, CAP).unwrap());
    let acked: Arc<std::sync::Mutex<Vec<dlp_agent::ml::cache::CacheKey>>> = Arc::default();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let compactor = {
        let (c, acked, stop, dir) = (Arc::clone(&c), Arc::clone(&acked), Arc::clone(&stop), dir.clone());
        std::thread::spawn(move || {
            // A fixed number of rounds, with writers running throughout, so the
            // race is exercised however fast this machine is.
            let mut rounds = 0;
            while rounds < 30 {
                c.compact().expect("an uncontended compaction must succeed");
                // Every put acknowledged BEFORE this point must be durable now.
                let must_have = acked.lock().unwrap().clone();
                // Inspect a COPY of the on-disk state: opening the live log a
                // second time could truncate a record a writer is mid-append.
                let copy = dir.join(format!("inspect-{rounds}"));
                std::fs::create_dir_all(&copy).unwrap();
                for f in ["ml-verdicts.log", "ml-cache.key"] {
                    std::fs::write(copy.join(f), std::fs::read(dir.join(f)).unwrap()).unwrap();
                }
                let on_disk = VerdictCache::open(&copy, CAP).unwrap();
                let lost = must_have.iter().filter(|k| on_disk.get(k, MV).is_none()).count();
                assert_eq!(lost, 0, "compaction {rounds}: {lost} acknowledged record(s) are not on disk");
                drop(on_disk);
                let _ = std::fs::remove_dir_all(&copy);
                rounds += 1;
                // Production compacts once per 4x log bloat, never back to
                // back; re-taking the (unfair) mutex in a tight loop would
                // starve the writers and test the scheduler, not the invariant.
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            rounds
        })
    };
    let writers: Vec<_> = (0..4u32)
        .map(|w| {
            let (c, acked, stop) = (Arc::clone(&c), Arc::clone(&acked), Arc::clone(&stop));
            std::thread::spawn(move || {
                let mut i = 0u32;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) && i < PER_WRITER {
                    let k = dlp_agent::ml::cache::VerdictCache::key_for(format!("writer {w} record {i}").as_bytes());
                    c.put(k, verdict("GOV", MV)).expect("put must succeed");
                    acked.lock().unwrap().push(k);
                    i += 1;
                }
            })
        })
        .collect();
    let rounds = compactor.join().expect("the compactor's durability check failed");
    for w in writers {
        w.join().expect("a writer panicked");
    }
    assert_eq!(rounds, 30);
    let written = acked.lock().unwrap().len();
    assert!(written > 100, "writers must actually have raced the compactions ({written} records)");
    let _ = std::fs::remove_dir_all(&dir);
}
