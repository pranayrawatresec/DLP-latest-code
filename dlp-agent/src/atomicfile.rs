//! Crash-safe "replace this file" — the one way the agent persists state.
//!
//! Why this module exists
//! ----------------------
//! Before it, the agent persisted state three different ways, and two of them
//! were wrong:
//!
//! * `std::fs::write` straight onto the live file. That TRUNCATES first and
//!   writes second, so a crash or power cut mid-write leaves a half-empty
//!   policy file. Several of those (ML, read-deny, clipboard policy, trusted
//!   readers) are rewritten on every resync, every few minutes — and an
//!   offline endpoint that boots with an unreadable cached policy has lost the
//!   thing "keep enforcing cached policy" depends on.
//! * temp file → `remove_file(dest)` → `rename(tmp, dest)`, justified by a
//!   comment saying "Windows rename does not overwrite". That is not true of
//!   `std::fs::rename`, and the delete is what OPENS a window in which the file
//!   does not exist at all. Measured on Windows 10 and 11: a reader polling
//!   the file while it was replaced 300 times found NO file 950 times, and got
//!   83 further "access denied" errors from the delete-pending state; with a
//!   plain rename-over it found no file 0 times.
//! * neither path flushed. NTFS journals metadata (names, renames) but not
//!   file contents, so after a power cut the rename can be on disk while the
//!   bytes it points at were still in cache — a file that exists and is empty.
//!
//! The sequence here closes all three:
//!
//! 1. write the new content to a UNIQUE sibling temp file (pid + sequence, so
//!    two processes — the service and an operator's debug `usb-guard` — can
//!    never write through each other's temp);
//! 2. `sync_all` it: the bytes are on disk before any name points at them;
//! 3. replace the destination in ONE step, never deleting it first, with
//!    `std::fs::rename`. On Windows 10+ that is a POSIX-semantics rename, which
//!    replaces the destination EVEN WHILE another process has it open with
//!    delete-sharing (as Rust's own `File::open` and `ml-status` do). The
//!    classic `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` does NOT: the old file
//!    goes delete-pending and blocks the name, so a reader polling the file
//!    starved the writer into "access denied" for the whole retry budget — the
//!    first version of this module used it, and its own race test caught it;
//! 4. retry that step, within a bounded budget, on a sharing/lock violation —
//!    an antivirus scanner or backup agent holding the old file open WITHOUT
//!    delete-sharing makes both rename and delete fail, so retrying is the only
//!    remedy, not a property of any one API.
//!
//! At every instant a reader therefore sees either the complete old file or the
//! complete new one. On any failure the destination is untouched and the temp
//! file is removed.
//!
//! What a power cut can and cannot do. The new file's bytes are flushed before
//! the rename, and NTFS journals the rename as one metadata transaction, so
//! after a cut the name points at the complete old file or the complete new
//! one — never at nothing and never at a partial file. What is NOT promised is
//! that a write completed in the last moments before the cut survives: NTFS
//! flushes its journal lazily, so the rename can roll back to the old version.
//! For state that is re-synced from the server (policies, the index) or
//! re-derived (checkpoints, coverage), old-but-whole is the right failure.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// How long a replace keeps retrying while another process holds the old file.
/// Long enough to ride out an antivirus scan of a small file, short enough that
/// a permanently-held file surfaces as an error rather than a hang.
pub const DEFAULT_RETRY_BUDGET: Duration = Duration::from_millis(1_500);

/// For callers that hold a lock something latency-critical waits on (the
/// verdict-cache compaction holds the log mutex that the kernel message loop's
/// `put` needs). Failing fast and trying again next time is the right trade.
pub const SHORT_RETRY_BUDGET: Duration = Duration::from_millis(200);

/// A sibling temp file older than this belongs to a writer that crashed
/// between creating it and replacing the destination. No legitimate write
/// takes ten minutes, so this can never delete a live writer's temp.
pub const STALE_TEMP_AGE: Duration = Duration::from_secs(600);

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Replace `dest` with `bytes`, crash-safely. See the module header.
pub fn write_atomic(dest: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic_with(dest, DEFAULT_RETRY_BUDGET, |f| f.write_all(bytes))
}

/// [`write_atomic`] with a caller-supplied writer and retry budget — for
/// content produced incrementally (the verdict-log compaction streams records
/// rather than building the whole log in memory first).
///
/// `fill` writes the complete new content into the temp file. It may also set
/// metadata on the handle (permissions on Unix). Whatever it returns as an
/// error is returned unchanged, with the destination untouched.
pub fn write_atomic_with<F>(dest: &Path, retry_budget: Duration, fill: F) -> io::Result<()>
where
    F: FnOnce(&mut File) -> io::Result<()>,
{
    let dir = parent_dir(dest);
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "destination has no file name"))?;
    let tmp = dir.join(format!(
        "{name}.{}.{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));

    let result = (|| -> io::Result<()> {
        // create_new: never adopt a file somebody else is writing.
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        fill(&mut f)?;
        f.flush()?;
        // The bytes must be durable BEFORE any name points at them.
        f.sync_all()?;
        // Closed before the replace: an open handle on the SOURCE of a rename
        // makes the rename fail with a sharing violation.
        drop(f);
        replace_with_retry(&tmp, dest, retry_budget)
    })();

    match result {
        Ok(()) => {
            remove_stale_temps(&dir, &name, STALE_TEMP_AGE);
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// `Path::parent` treats a bare file name as having the parent `""`, which is
/// not a directory `read_dir` or `join` handle usefully; normalise it to `.`.
fn parent_dir(dest: &Path) -> PathBuf {
    match dest.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Is this error the kind a retry can cure — the destination (or a directory
/// entry) is transiently held by another process?
fn is_transient(e: &io::Error) -> bool {
    // ERROR_ACCESS_DENIED (5) is what a rename reports for a destination held
    // open without delete-sharing (measured on Windows 10 and 11);
    // ERROR_SHARING_VIOLATION (32) and ERROR_LOCK_VIOLATION (33) are the other
    // two faces of the same thing.
    matches!(e.raw_os_error(), Some(5) | Some(32) | Some(33))
}

fn replace_with_retry(tmp: &Path, dest: &Path, budget: Duration) -> io::Result<()> {
    let started = Instant::now();
    let mut backoff = Duration::from_millis(5);
    loop {
        match replace(tmp, dest) {
            Ok(()) => return Ok(()),
            Err(e) if is_transient(&e) && started.elapsed() + backoff <= budget => {
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_millis(100));
            }
            Err(e) => return Err(e),
        }
    }
}

/// Replace `dest` with `tmp` in one step. Never deletes `dest` first.
///
/// `std::fs::rename` on every platform: POSIX rename is atomic by definition,
/// and on Windows 10+ std uses a POSIX-semantics rename that replaces an open
/// destination (see the module header for why `MoveFileExW` is not used). On
/// Unix the directory is fsynced so the rename itself survives a power cut;
/// Windows offers no supported equivalent for a directory, and relies on the
/// NTFS journal described in the header.
fn replace(tmp: &Path, dest: &Path) -> io::Result<()> {
    std::fs::rename(tmp, dest)?;
    #[cfg(not(windows))]
    if let Ok(d) = File::open(parent_dir(dest)) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Remove temp siblings of `name` left behind by a writer that crashed, and
/// the fixed-name `<name>.tmp` earlier versions of the agent used.
///
/// Only files that match `<name>.*.tmp` / `<name>.tmp` exactly AND are older
/// than `older_than` are touched, so a concurrent writer's live temp is never
/// removed. Best-effort: a failure here costs a stray file, never the write.
pub fn remove_stale_temps(dir: &Path, name: &str, older_than: Duration) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let prefix = format!("{name}.");
    let now = SystemTime::now();
    for entry in rd.flatten() {
        let fname = entry.file_name();
        let fname = fname.to_string_lossy();
        if !(fname.starts_with(&prefix) && fname.ends_with(".tmp")) {
            continue;
        }
        let old_enough = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| now.duration_since(m).ok())
            .is_some_and(|age| age >= older_than);
        if old_enough {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "dlp-atomicfile-unit-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn transient_codes_are_exactly_the_lock_family() {
        for c in [5, 32, 33] {
            assert!(is_transient(&io::Error::from_raw_os_error(c)), "{c} must retry");
        }
        for c in [2, 3, 112, 1] {
            assert!(!is_transient(&io::Error::from_raw_os_error(c)), "{c} must not retry");
        }
    }

    #[test]
    fn a_bare_file_name_resolves_to_the_current_directory() {
        assert_eq!(parent_dir(Path::new("state.json")), PathBuf::from("."));
        assert_eq!(parent_dir(Path::new("a/b.json")), PathBuf::from("a"));
    }

    #[test]
    fn stale_temp_matching_is_exact_and_age_gated() {
        let d = dir("stale");
        let keep_young = d.join("state.json.1.0.tmp");
        let keep_other = d.join("other.json.1.0.tmp");
        let keep_real = d.join("state.json");
        for p in [&keep_young, &keep_other, &keep_real] {
            std::fs::write(p, b"x").unwrap();
        }
        // Age 0 would delete a young temp — so "older than 1 hour" must keep all.
        remove_stale_temps(&d, "state.json", Duration::from_secs(3600));
        assert!(keep_young.exists() && keep_other.exists() && keep_real.exists());
        // With age 0, only the matching temp goes; the real file and another
        // file's temp stay.
        remove_stale_temps(&d, "state.json", Duration::ZERO);
        assert!(!keep_young.exists(), "matching temp removed");
        assert!(keep_other.exists(), "another file's temp is never touched");
        assert!(keep_real.exists(), "the destination itself is never touched");
        let _ = std::fs::remove_dir_all(&d);
    }
}
