//! The sweep's pending-directory queue, bounded in memory.
//!
//! A tree walk is a queue of directories still to visit. Breadth-first is the
//! order we want — the shallow directories are where the user's documents are,
//! and a sweep that reaches `Documents` in its first minute is worth more than
//! one that spends an hour inside `AppData` first — but breadth-first is also
//! the order that holds the most at once: the queue grows to the width of the
//! widest level of the tree. Measured on a real profile (`C:\Users`, 22 469
//! directories) the queue peaks at **12 629 entries**, three times the cap the
//! checkpoint was willing to persist.
//!
//! That had two consequences, both fixed here:
//!
//! 1. Nothing bounded the queue in memory. 2 MB on that profile, but the bound
//!    was the estate's, not ours.
//! 2. Worse: because the list did not fit, every checkpoint wrote it away
//!    EMPTY with a `truncated` flag, so every agent restart threw the sweep
//!    away and began the scope again. On any real machine the resume path was
//!    dead code.
//!
//! So the queue keeps its first `cap` entries in memory and appends the rest to
//! a sidecar file, reading them back as the head drains. Order is exactly the
//! order of a plain `VecDeque`; what changes is that the tail lives on disk,
//! where the checkpoint can point at it instead of dropping it.
//!
//! **Crash safety.** The sidecar is append-only for the life of one sweep (it
//! is named after the sweep sequence, so a new sweep never inherits an old
//! one's bytes). A checkpoint records the byte offset of the next entry to read
//! and the number of bytes that were on disk when it was written, and
//! [`Frontier::flush`] makes those bytes durable BEFORE the checkpoint that
//! references them is written. On resume the file must be at least that long —
//! a shorter one means the tail was lost, and the caller restarts the scope
//! rather than silently skipping directories.
//!
//! **Degraded mode.** If the sidecar cannot be written (full disk, an ACL we do
//! not hold) entries stay in memory. That is exactly the behaviour this module
//! replaced, so the failure costs the memory bound and nothing else: no
//! directory is ever dropped on the floor.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Sidecar file name: `ml-walk.frontier.<sweep_seq>.spill`.
pub const SPILL_PREFIX: &str = "ml-walk.frontier.";
pub const SPILL_SUFFIX: &str = ".spill";

/// Where one sweep's overflow tail lives.
pub fn spill_path(state_dir: &Path, sweep_seq: u64) -> PathBuf {
    state_dir.join(format!("{SPILL_PREFIX}{sweep_seq}{SPILL_SUFFIX}"))
}

/// Delete every sweep sidecar except the one in use. Called when a sweep
/// starts: an abandoned sweep's tail is not evidence of anything.
pub fn remove_other_spills(state_dir: &Path, keep: &Path) {
    let Ok(rd) = std::fs::read_dir(state_dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path == keep {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with(SPILL_PREFIX) && name.ends_with(SPILL_SUFFIX) {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// The part of the queue that lives on disk, as the checkpoint records it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpillState {
    /// Byte offset of the next entry to read back.
    pub head: u64,
    /// Bytes written and made durable. The file must be at least this long.
    pub len: u64,
    /// Entries between `head` and `len`.
    pub count: u64,
}

impl SpillState {
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// A FIFO of directory paths: `cap` entries in memory, the rest on disk.
#[derive(Debug)]
pub struct Frontier {
    /// The head of the queue. Never exceeds `cap` except by [`Self::push_front`]
    /// putting back the entry it just took, or in degraded mode.
    mem: VecDeque<PathBuf>,
    cap: usize,
    path: PathBuf,
    /// Append handle, opened on the first spill.
    writer: Option<File>,
    state: SpillState,
    /// Deepest the queue ever got, memory and disk together.
    high_water: usize,
    /// Entries written to disk over the life of this sweep.
    spilled: u64,
    /// The sidecar failed and we are holding everything in memory.
    degraded: bool,
}

impl Default for Frontier {
    /// A memory-only queue, for a cursor that is not walking anything.
    fn default() -> Self {
        Frontier {
            mem: VecDeque::new(),
            cap: usize::MAX,
            path: PathBuf::new(),
            writer: None,
            state: SpillState::default(),
            high_water: 0,
            spilled: 0,
            degraded: true,
        }
    }
}

impl Frontier {
    /// A queue that holds `cap` entries in memory and spills the rest to `path`.
    /// Any file already at `path` is removed: a sweep starts with an empty tail.
    pub fn new(cap: usize, path: PathBuf) -> Self {
        let _ = std::fs::remove_file(&path);
        Frontier {
            mem: VecDeque::new(),
            cap: cap.max(1),
            path,
            writer: None,
            state: SpillState::default(),
            high_water: 0,
            spilled: 0,
            degraded: false,
        }
    }

    /// Rebuild the queue a checkpoint described.
    ///
    /// Fails if the sidecar is missing or shorter than the checkpoint says it
    /// was, which is the one case where continuing would skip directories. The
    /// caller restarts the scope instead.
    pub fn restore(
        cap: usize,
        path: PathBuf,
        mem: Vec<PathBuf>,
        state: SpillState,
    ) -> io::Result<Self> {
        if !state.is_empty() {
            let on_disk = std::fs::metadata(&path)?.len();
            if on_disk < state.len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "frontier sidecar is {on_disk} bytes, checkpoint recorded {}",
                        state.len
                    ),
                ));
            }
        }
        let mem: VecDeque<PathBuf> = mem.into();
        Ok(Frontier {
            high_water: mem.len() + state.count as usize,
            mem,
            cap: cap.max(1),
            path,
            writer: None,
            state,
            spilled: 0,
            degraded: false,
        })
    }

    /// Total entries waiting, in memory and on disk.
    pub fn len(&self) -> usize {
        self.mem.len() + self.state.count as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The in-memory head — what a checkpoint persists inline.
    pub fn memory(&self) -> impl Iterator<Item = &PathBuf> {
        self.mem.iter()
    }

    pub fn memory_len(&self) -> usize {
        self.mem.len()
    }

    /// Where the tail is, for the checkpoint. Call [`Self::flush`] first.
    pub fn spill_state(&self) -> SpillState {
        self.state
    }

    pub fn high_water(&self) -> usize {
        self.high_water
    }

    pub fn spilled(&self) -> u64 {
        self.spilled
    }

    /// True once the sidecar has failed and the queue is memory-only again.
    pub fn is_degraded(&self) -> bool {
        self.degraded
    }

    /// Queue a directory at the back. Goes to disk once memory is full — and
    /// once anything is on disk, everything does, or the order would break.
    pub fn push_back(&mut self, dir: PathBuf) {
        if self.state.is_empty() && self.mem.len() < self.cap {
            self.mem.push_back(dir);
        } else {
            match self.spill(&dir) {
                Ok(()) => {}
                Err(e) => {
                    self.degrade(e);
                    self.mem.push_back(dir);
                }
            }
        }
        self.note_high_water();
    }

    /// Put back the entry we just took (the descent throttle does this). It
    /// belongs at the head, so it goes to memory even if that is one over cap.
    pub fn push_front(&mut self, dir: PathBuf) {
        self.mem.push_front(dir);
        self.note_high_water();
    }

    /// Take the next directory, reading the tail back if the head has drained.
    pub fn pop_front(&mut self) -> Option<PathBuf> {
        if self.mem.is_empty() && !self.state.is_empty() {
            self.refill();
        }
        self.mem.pop_front()
    }

    /// Make every spilled byte durable. **A checkpoint that records
    /// [`Self::spill_state`] must call this first**, or a power cut can leave
    /// the checkpoint pointing past the end of the file.
    pub fn flush(&mut self) -> io::Result<()> {
        match self.writer.as_mut() {
            Some(f) => {
                f.flush()?;
                f.sync_data()
            }
            None => Ok(()),
        }
    }

    /// Drop the queue and its sidecar — the sweep is over.
    pub fn clear(&mut self) {
        self.mem.clear();
        self.state = SpillState::default();
        self.writer = None;
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    // -- internals ----------------------------------------------------------

    fn note_high_water(&mut self) {
        let now = self.len();
        if now > self.high_water {
            self.high_water = now;
        }
    }

    /// Append one entry. A path that is not valid UTF-8 cannot be written as a
    /// line (and could not go in the JSON checkpoint either), so it stays in
    /// memory rather than being mangled.
    fn spill(&mut self, dir: &Path) -> io::Result<()> {
        if self.degraded {
            return Err(io::Error::other("sidecar disabled"));
        }
        let text = dir.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "path is not valid UTF-8")
        })?;
        if text.contains(['\n', '\r']) {
            // Impossible in an NTFS name; refuse rather than corrupt the file.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "path contains a line break",
            ));
        }
        if self.writer.is_none() {
            self.writer = Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.path)?,
            );
        }
        let line = format!("{text}\n");
        let f = self.writer.as_mut().expect("just opened");
        f.write_all(line.as_bytes())?;
        self.state.len += line.len() as u64;
        self.state.count += 1;
        self.spilled += 1;
        Ok(())
    }

    /// Read the next batch back into memory.
    fn refill(&mut self) {
        match self.read_batch(self.cap) {
            Ok((batch, new_head)) if !batch.is_empty() => {
                self.state.count = self.state.count.saturating_sub(batch.len() as u64);
                self.state.head = new_head;
                for p in batch {
                    self.mem.push_back(p);
                }
            }
            Ok(_) => {
                // The file says it holds entries but yielded none: treat the
                // tail as lost rather than spinning on it forever.
                tracing::warn!(
                    path = %self.path.display(),
                    pending = self.state.count,
                    "ml walker: pending-directory sidecar yielded nothing; dropping its tail"
                );
                self.state.count = 0;
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %self.path.display(),
                    pending = self.state.count,
                    "ml walker: could not read back pending directories"
                );
                self.state.count = 0;
            }
        }
    }

    /// Entries from `head`, stopping at `want` or at the durable end.
    fn read_batch(&self, want: usize) -> io::Result<(Vec<PathBuf>, u64)> {
        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(self.state.head))?;

        let mut out = Vec::with_capacity(want.min(1_024));
        let mut pos = self.state.head;
        let mut line = String::new();
        while out.len() < want && pos < self.state.len {
            line.clear();
            let read = reader.read_line(&mut line)?;
            if read == 0 {
                break;
            }
            pos += read as u64;
            let text = line.trim_end_matches(['\n', '\r']);
            if !text.is_empty() {
                out.push(PathBuf::from(text));
            }
        }
        Ok((out, pos))
    }

    fn degrade(&mut self, e: io::Error) {
        if !self.degraded {
            self.degraded = true;
            tracing::warn!(
                error = %e,
                path = %self.path.display(),
                "ml walker: cannot spill pending directories to disk — holding them in memory"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "dlp-frontier-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::create_dir_all(&p);
        p
    }

    #[test]
    fn order_is_exactly_a_queue_even_across_the_spill() {
        let dir = tmp();
        let mut f = Frontier::new(4, spill_path(&dir, 1));
        for i in 0..20 {
            f.push_back(PathBuf::from(format!("d{i}")));
        }
        assert_eq!(f.len(), 20);
        let mut seen = Vec::new();
        while let Some(p) = f.pop_front() {
            seen.push(p.to_string_lossy().into_owned());
        }
        let want: Vec<String> = (0..20).map(|i| format!("d{i}")).collect();
        assert_eq!(seen, want);
        f.clear();
    }

    #[test]
    fn memory_is_bounded_by_the_cap() {
        let dir = tmp();
        let mut f = Frontier::new(8, spill_path(&dir, 2));
        for i in 0..5_000 {
            f.push_back(PathBuf::from(format!("d{i}")));
        }
        assert!(f.memory_len() <= 8, "held {} in memory", f.memory_len());
        assert_eq!(f.len(), 5_000);
        assert_eq!(f.spilled(), 5_000 - 8);
        f.clear();
    }

    #[test]
    fn a_restored_queue_continues_where_the_checkpoint_stopped() {
        let dir = tmp();
        let path = spill_path(&dir, 3);
        let mut f = Frontier::new(4, path.clone());
        for i in 0..30 {
            f.push_back(PathBuf::from(format!("d{i}")));
        }
        // Drain a few, then checkpoint.
        let mut seen = Vec::new();
        for _ in 0..6 {
            seen.push(f.pop_front().unwrap());
        }
        f.flush().unwrap();
        let mem: Vec<PathBuf> = f.memory().cloned().collect();
        let state = f.spill_state();
        drop(f);

        let mut f2 = Frontier::restore(4, path, mem, state).unwrap();
        while let Some(p) = f2.pop_front() {
            seen.push(p);
        }
        let want: Vec<PathBuf> = (0..30).map(|i| PathBuf::from(format!("d{i}"))).collect();
        assert_eq!(seen, want);
        f2.clear();
    }

    #[test]
    fn a_truncated_sidecar_is_refused_rather_than_silently_short() {
        let dir = tmp();
        let path = spill_path(&dir, 4);
        let mut f = Frontier::new(2, path.clone());
        for i in 0..50 {
            f.push_back(PathBuf::from(format!("d{i}")));
        }
        f.flush().unwrap();
        let mem: Vec<PathBuf> = f.memory().cloned().collect();
        let state = f.spill_state();
        drop(f);

        // A power cut that lost the tail.
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(state.len / 2).unwrap();
        drop(file);

        assert!(Frontier::restore(2, path.clone(), mem, state).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn put_back_keeps_its_place_at_the_head() {
        let dir = tmp();
        let mut f = Frontier::new(2, spill_path(&dir, 5));
        for i in 0..10 {
            f.push_back(PathBuf::from(format!("d{i}")));
        }
        let first = f.pop_front().unwrap();
        f.push_front(first.clone());
        assert_eq!(f.pop_front().unwrap(), first);
        assert_eq!(f.len(), 9);
        f.clear();
    }

    #[test]
    fn a_sweep_that_ends_takes_its_sidecar_with_it() {
        let dir = tmp();
        let path = spill_path(&dir, 6);
        let mut f = Frontier::new(1, path.clone());
        for i in 0..10 {
            f.push_back(PathBuf::from(format!("d{i}")));
        }
        assert!(path.exists());
        f.clear();
        assert!(!path.exists());
        assert!(f.is_empty());
    }

    #[test]
    fn a_new_sweep_removes_the_sidecars_of_the_old_ones() {
        let dir = tmp();
        let old = spill_path(&dir, 70);
        std::fs::write(&old, b"C:\\stale\n").unwrap();
        let keep = spill_path(&dir, 71);
        std::fs::write(&keep, b"C:\\live\n").unwrap();
        remove_other_spills(&dir, &keep);
        assert!(!old.exists());
        assert!(keep.exists());
        let _ = std::fs::remove_file(keep);
    }

    #[test]
    fn a_queue_that_cannot_spill_keeps_every_entry_in_memory() {
        let dir = tmp();
        // A directory where the sidecar should be makes opening it fail.
        let path = spill_path(&dir, 8);
        let _ = std::fs::remove_file(&path);
        std::fs::create_dir_all(&path).unwrap();

        let mut f = Frontier::new(2, path.clone());
        for i in 0..100 {
            f.push_back(PathBuf::from(format!("d{i}")));
        }
        assert!(f.is_degraded());
        assert_eq!(f.len(), 100, "no directory may be dropped");
        let mut seen = Vec::new();
        while let Some(p) = f.pop_front() {
            seen.push(p.to_string_lossy().into_owned());
        }
        let want: Vec<String> = (0..100).map(|i| format!("d{i}")).collect();
        assert_eq!(seen, want, "order survives degraded mode");
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn the_high_water_mark_reports_the_deepest_the_queue_got() {
        let dir = tmp();
        let mut f = Frontier::new(4, spill_path(&dir, 9));
        for i in 0..100 {
            f.push_back(PathBuf::from(format!("d{i}")));
        }
        for _ in 0..100 {
            f.pop_front();
        }
        assert_eq!(f.high_water(), 100);
        f.clear();
    }
}
