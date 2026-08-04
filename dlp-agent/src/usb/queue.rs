//! Bounded local incident queue (spec §3.6 edge 11).
//!
//! When the server is unreachable or the agent is unenrolled, incidents must
//! not be lost silently: they are queued on disk under `state_dir` and flushed
//! on the next successful check-in. The queue is **bounded** — once it reaches
//! its cap the oldest entry is dropped and the drop is logged (fail-secure:
//! never grow without limit, never drop silently beyond the bound).
//!
//! Each entry stores the exact JSON POST body (spec §4 wire shape). We persist
//! the serialized body rather than a typed struct because `detect::Verdict` is
//! serialize-only; storing the ready-to-POST bytes also means a flush re-sends
//! byte-for-byte what would have been sent live. Writes use the temp-file→rename
//! pattern (mirroring `Storage::store_index_bundle`) so a crash mid-write can't
//! corrupt the queue.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

const QUEUE_DIR: &str = "usb-incident-queue";
const DEFAULT_CAP: usize = 1000;

/// A disk-backed, bounded FIFO of pending incident POST bodies.
pub struct IncidentQueue {
    dir: PathBuf,
    cap: usize,
}

impl IncidentQueue {
    /// Queue rooted at `<state_dir>/usb-incident-queue`.
    pub fn new(state_dir: &Path) -> Self {
        IncidentQueue { dir: state_dir.join(QUEUE_DIR), cap: DEFAULT_CAP }
    }

    #[cfg(test)]
    fn with_cap(state_dir: &Path, cap: usize) -> Self {
        IncidentQueue { dir: state_dir.join(QUEUE_DIR), cap }
    }

    /// Ordered list of queued entry files (oldest first). Names are
    /// zero-padded monotonic so lexical order == chronological order.
    fn entries(&self) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
                .collect(),
            Err(_) => Vec::new(),
        };
        files.sort();
        files
    }

    /// Number of queued incidents.
    pub fn len(&self) -> usize {
        self.entries().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Enqueue a ready-to-POST JSON body. If the queue is at capacity, the
    /// oldest entry is dropped (and logged) before the new one is written.
    pub fn enqueue(&self, json_body: &str) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating incident queue {}", self.dir.display()))?;

        // Enforce the bound: drop oldest while at/over cap.
        let mut existing = self.entries();
        while existing.len() >= self.cap {
            let oldest = existing.remove(0);
            let _ = std::fs::remove_file(&oldest);
            tracing::warn!(
                dropped = %oldest.display(),
                cap = self.cap,
                "usb incident queue full — dropped oldest incident (fail-secure bound)"
            );
        }

        // Monotonic name: nanos + pid keeps ordering stable and unique.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let stem = format!("{now:039}-{}", std::process::id());
        let tmp = self.dir.join(format!("{stem}.tmp"));
        let dest = self.dir.join(format!("{stem}.json"));
        std::fs::write(&tmp, json_body).context("writing queued incident (temp)")?;
        std::fs::rename(&tmp, &dest).context("committing queued incident")?;
        Ok(())
    }

    /// Attempt to flush the queue: for each entry (oldest first) call `send`
    /// with the stored JSON body; on success delete the entry. Stops at the
    /// first failure (server still unreachable) and leaves the rest queued.
    /// Returns the number of incidents successfully flushed.
    pub fn flush<F>(&self, mut send: F) -> usize
    where
        F: FnMut(&str) -> Result<()>,
    {
        let mut flushed = 0;
        for path in self.entries() {
            let body = match std::fs::read_to_string(&path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            match send(&body) {
                Ok(()) => {
                    let _ = std::fs::remove_file(&path);
                    flushed += 1;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "incident flush stopped; leaving remainder queued");
                    break;
                }
            }
        }
        flushed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("dlp-agent-queue-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn enqueue_then_flush_sends_in_order_and_clears() {
        let base = temp_dir("flush");
        let q = IncidentQueue::new(&base);
        q.enqueue("{\"n\":1}").unwrap();
        q.enqueue("{\"n\":2}").unwrap();
        assert_eq!(q.len(), 2);

        let mut sent = Vec::new();
        let flushed = q.flush(|body| {
            sent.push(body.to_string());
            Ok(())
        });
        assert_eq!(flushed, 2);
        assert!(q.is_empty(), "successful flush must clear the queue");
        assert_eq!(sent, vec!["{\"n\":1}".to_string(), "{\"n\":2}".to_string()]);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn flush_stops_and_retains_on_failure() {
        let base = temp_dir("retain");
        let q = IncidentQueue::new(&base);
        q.enqueue("a").unwrap();
        q.enqueue("b").unwrap();
        // Fail on the first send: nothing should be removed.
        let flushed = q.flush(|_| anyhow::bail!("server down"));
        assert_eq!(flushed, 0);
        assert_eq!(q.len(), 2, "a failed flush must retain every entry");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn bound_drops_oldest_when_full() {
        let base = temp_dir("bound");
        let q = IncidentQueue::with_cap(&base, 2);
        q.enqueue("one").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        q.enqueue("two").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        q.enqueue("three").unwrap(); // drops "one"
        assert_eq!(q.len(), 2, "queue must stay bounded at cap");

        let mut sent = Vec::new();
        q.flush(|b| {
            sent.push(b.to_string());
            Ok(())
        });
        assert_eq!(sent, vec!["two".to_string(), "three".to_string()]);
        let _ = std::fs::remove_dir_all(&base);
    }
}
