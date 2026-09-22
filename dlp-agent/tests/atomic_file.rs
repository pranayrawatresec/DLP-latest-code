//! Gate for `src/atomicfile.rs` — the one way the agent persists state.
//!
//! The property every test here defends: at every instant a reader sees EITHER
//! the complete old file OR the complete new one — never no file, never a
//! half-written one — and a failed write leaves the old file untouched.
//!
//! The race tests are the regression tests for the defect that motivated the
//! module. Measured on Windows 10 and 11 with the previous "delete the
//! destination, then rename" sequence, a reader polling a file replaced 300
//! times found NO file 950 times; with a rename-over, 0.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use dlp_agent::atomicfile::{remove_stale_temps, write_atomic, write_atomic_with, STALE_TEMP_AGE};

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "dlp-atomic-{tag}-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// A payload whose every byte is the same, so a torn or interleaved read is
/// detectable from its content alone.
fn payload(tag: u8, len: usize) -> Vec<u8> {
    vec![tag; len]
}

// ===========================================================================
// Basics
// ===========================================================================

#[test]
fn it_creates_then_replaces_and_leaves_no_temp_behind() {
    let d = temp_dir("basic");
    let dest = d.join("state.json");
    write_atomic(&dest, b"first").unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"first");
    write_atomic(&dest, b"second, and longer").unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"second, and longer");
    write_atomic(&dest, b"3").unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"3", "a shorter write must not keep a stale tail");
    assert_eq!(names_in(&d), vec!["state.json".to_string()], "no temp file may survive a write");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_writer_that_fails_midway_leaves_the_old_file_untouched() {
    let d = temp_dir("failing");
    let dest = d.join("policy.json");
    write_atomic(&dest, b"{\"good\":true}").unwrap();

    let err = write_atomic_with(&dest, Duration::from_millis(50), |f| {
        f.write_all(b"{\"half\":")?; // a partial write...
        Err(std::io::Error::other("simulated failure")) // ...then the writer dies
    })
    .unwrap_err();
    assert_eq!(err.to_string(), "simulated failure", "the writer's own error is returned");
    assert_eq!(std::fs::read(&dest).unwrap(), b"{\"good\":true}", "the old file is intact");
    assert_eq!(names_in(&d), vec!["policy.json".to_string()], "the partial temp is removed");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_missing_directory_is_an_error_not_a_panic_and_creates_nothing() {
    let d = temp_dir("nodir");
    let dest = d.join("does").join("not").join("exist.json");
    assert!(write_atomic(&dest, b"x").is_err());
    assert!(!d.join("does").exists());
    let _ = std::fs::remove_dir_all(&d);
}

// ===========================================================================
// The gap — a reader must never find the file missing or torn
// ===========================================================================

#[test]
fn a_reader_never_finds_the_file_missing_or_torn_while_it_is_replaced() {
    const LEN: usize = 64 * 1024;
    const WRITES: u8 = 200;
    let d = temp_dir("reader-race");
    let dest = d.join("ml-walk.completed.json");
    write_atomic(&dest, &payload(0, LEN)).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let (missing, torn, reads) = (
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
    );
    let reader = {
        let (stop, missing, torn, reads, dest) =
            (stop.clone(), missing.clone(), torn.clone(), reads.clone(), dest.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                // Rust's default open shares read/write/delete — like `ml-status`.
                match std::fs::File::open(&dest) {
                    Ok(mut f) => {
                        let mut buf = Vec::new();
                        let _ = f.read_to_end(&mut buf);
                        reads.fetch_add(1, Ordering::Relaxed);
                        let whole = buf.len() == LEN && buf.iter().all(|&b| b == buf[0]);
                        if !whole {
                            torn.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        missing.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {}
                }
            }
        })
    };

    for i in 1..=WRITES {
        write_atomic(&dest, &payload(i, LEN)).unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    reader.join().unwrap();

    assert!(reads.load(Ordering::Relaxed) > 0, "the reader must actually have raced the writer");
    assert_eq!(missing.load(Ordering::Relaxed), 0, "the file must never be absent");
    assert_eq!(torn.load(Ordering::Relaxed), 0, "a read must never see a partial file");
    assert_eq!(std::fs::read(&dest).unwrap(), payload(WRITES, LEN));
    let _ = std::fs::remove_dir_all(&d);
}

/// Two processes (the service and an operator's debug `usb-guard`) writing the
/// same file: each write lands whole; they can never write through each other's
/// temp file — which a fixed temp name allowed.
#[test]
fn concurrent_writers_never_interleave_their_content() {
    const LEN: usize = 256 * 1024;
    let d = temp_dir("writers");
    let dest = d.join("index.dlpx");
    write_atomic(&dest, &payload(b'0', LEN)).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let torn = Arc::new(AtomicU64::new(0));
    let checker = {
        let (stop, torn, dest) = (stop.clone(), torn.clone(), dest.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Ok(buf) = std::fs::read(&dest) {
                    if !(buf.len() == LEN && buf.iter().all(|&b| b == buf[0])) {
                        torn.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        })
    };
    let writers: Vec<_> = (b'a'..=b'd')
        .map(|tag| {
            let dest = dest.clone();
            std::thread::spawn(move || {
                let mut ok = 0;
                for _ in 0..25 {
                    // A lost race to a concurrent replace may surface as a
                    // transient error after the budget; it must never corrupt.
                    if write_atomic(&dest, &payload(tag, LEN)).is_ok() {
                        ok += 1;
                    }
                }
                ok
            })
        })
        .collect();
    let succeeded: i32 = writers.into_iter().map(|w| w.join().unwrap()).sum();
    stop.store(true, Ordering::Relaxed);
    checker.join().unwrap();

    assert!(succeeded > 0);
    assert_eq!(torn.load(Ordering::Relaxed), 0, "no reader may ever see mixed content");
    let last = std::fs::read(&dest).unwrap();
    assert!(last.len() == LEN && last.iter().all(|&b| b == last[0]), "the final file is one writer's whole payload");
    assert_eq!(names_in(&d), vec!["index.dlpx".to_string()], "no temp file survives");
    let _ = std::fs::remove_dir_all(&d);
}

// ===========================================================================
// Another process holding the destination (antivirus, backup agent)
// ===========================================================================

#[cfg(windows)]
fn hold_without_delete_sharing(path: &Path) -> std::fs::File {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    // Read/write sharing but NOT delete — what a scanner holding the file looks
    // like. Measured: this makes rename-over AND delete fail (5 / 32).
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(path)
        .unwrap()
}

/// A scanner that lets go within the retry budget: the write waits for it and
/// then succeeds, instead of giving up on the first sharing violation.
#[cfg(windows)]
#[test]
fn a_briefly_held_destination_is_retried_until_it_is_released() {
    let d = temp_dir("held-brief");
    let dest = d.join("read-deny-policy.json");
    write_atomic(&dest, b"old").unwrap();

    let holder = hold_without_delete_sharing(&dest);
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        drop(holder);
    });
    let t = Instant::now();
    write_atomic(&dest, b"new").expect("must succeed once the holder lets go");
    let waited = t.elapsed();
    release.join().unwrap();

    assert!(waited >= Duration::from_millis(250), "it really waited for the holder ({waited:?})");
    assert_eq!(std::fs::read(&dest).unwrap(), b"new");
    assert_eq!(names_in(&d), vec!["read-deny-policy.json".to_string()]);
    let _ = std::fs::remove_dir_all(&d);
}

/// A holder that never lets go: the write fails within its budget — no hang —
/// and changes nothing.
#[cfg(windows)]
#[test]
fn a_destination_held_past_the_budget_fails_fast_and_changes_nothing() {
    let d = temp_dir("held-long");
    let dest = d.join("ml-policy.json");
    write_atomic(&dest, b"old").unwrap();
    let _holder = hold_without_delete_sharing(&dest);

    let t = Instant::now();
    let err = write_atomic_with(&dest, Duration::from_millis(200), |f| f.write_all(b"new")).unwrap_err();
    let took = t.elapsed();

    assert_eq!(err.raw_os_error(), Some(5), "the lock surfaces as access-denied: {err}");
    assert!(took < Duration::from_secs(1), "bounded by the budget, not a hang ({took:?})");
    assert_eq!(std::fs::read(&dest).unwrap(), b"old");
    assert_eq!(names_in(&d), vec!["ml-policy.json".to_string()], "the temp is cleaned up");
    let _ = std::fs::remove_dir_all(&d);
}

// ===========================================================================
// Orphaned temps from a crashed writer
// ===========================================================================

#[test]
fn orphaned_temps_from_a_crashed_writer_are_cleaned_up_and_live_ones_are_not() {
    let d = temp_dir("orphans");
    let dest = d.join("index.dlpx");
    let orphan_new_style = d.join("index.dlpx.4242.7.tmp");
    let orphan_legacy = d.join("index.dlpx.tmp"); // the name older builds used
    let live_temp = d.join("index.dlpx.9999.0.tmp"); // another writer, mid-write
    let unrelated = d.join("ml-policy.json.4242.7.tmp");
    for p in [&orphan_new_style, &orphan_legacy, &live_temp, &unrelated] {
        std::fs::write(p, b"leftover").unwrap();
    }
    let old = SystemTime::now() - (STALE_TEMP_AGE + Duration::from_secs(60));
    for p in [&orphan_new_style, &orphan_legacy, &unrelated] {
        OpenOptions::new().write(true).open(p).unwrap().set_modified(old).unwrap();
    }

    write_atomic(&dest, b"bundle").unwrap();

    assert!(!orphan_new_style.exists(), "a crashed writer's temp is removed");
    assert!(!orphan_legacy.exists(), "the legacy fixed-name temp is removed");
    assert!(live_temp.exists(), "a YOUNG temp may be a live writer's — never touched");
    assert!(unrelated.exists(), "another file's temps are not this write's business");
    assert_eq!(std::fs::read(&dest).unwrap(), b"bundle");

    // And the helper on its own, for the same rule.
    remove_stale_temps(&d, "ml-policy.json", STALE_TEMP_AGE);
    assert!(!unrelated.exists());
    let _ = std::fs::remove_dir_all(&d);
}
