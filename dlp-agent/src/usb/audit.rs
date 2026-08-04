//! Copy auditor (spec §3.5) — the heart of the user-mode channel's value.
//!
//! Given a volume root, detect files written to it and scan them with the
//! existing `detect::verdict()`. This is *detect + audit*, not pre-write block:
//! the file may briefly exist on the stick, then we flag it (a later minifilter
//! would block/quarantine). The design here is built to be deterministically
//! testable:
//!
//! * The watched root is an **injectable directory path** — an integration test
//!   points it at a temp dir (spec §3.5). The v0 detection mechanism is a
//!   recursive poll-scan (name+size+mtime diff); `ReadDirectoryChangesW` is an
//!   allowed future enhancement behind the same interface.
//! * The **clock is injected** (`poll(now_ms)`), so settle timing is exact in
//!   tests rather than wall-clock-flaky.
//! * The **verdict source is injectable** (`Fn(&Path) -> Result<Verdict>`), so
//!   the settle/dedup/incident logic is validated without depending on live
//!   fingerprint math (already golden-tested).
//!
//! Never logs file contents or extracted text (spec §7): incidents carry only
//! hashes, scores, and metadata, exactly like the existing incident path.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use crate::detect::{Extraction, Verdict};

use super::device::DeviceIdentity;
use super::policy::Action;

/// What enforcement disposition accompanied this file's audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionTaken {
    Audited,
    ReadOnly,
    Blocked,
}

impl From<Action> for ActionTaken {
    fn from(a: Action) -> Self {
        match a {
            Action::AllowAudited => ActionTaken::Audited,
            Action::ReadOnly => ActionTaken::ReadOnly,
            Action::Block => ActionTaken::Blocked,
        }
    }
}

/// Category of a raised incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentKind {
    /// IDM/EDM matched — sensitive material copied to removable media.
    Match,
    /// Content could not be read on a removable target (fail-secure hook,
    /// spec §3.5): a later minifilter in enforce-mode would block this.
    UnreadableOnRemovable,
    /// File exceeded `max_file_bytes` and was not scanned (spec §5 edge 3).
    SkippedTooLarge,
    /// A live enforcement operation failed (spec §3.4 / §5 edge 13).
    EnforcementFailed,
    /// An MTP/phone device was present (informational only — content is NOT
    /// inspected in this build, spec §5 edge 10).
    MtpDevicePresent,
    /// A clipboard image (CF_DIB/CF_BITMAP) was copied. It cannot be inspected
    /// without OCR (out of scope, clipboard spec §1.4 edge 6) — recorded as a
    /// metadata-only note; `[clipboard] block_images` decides allow vs block.
    ClipboardImageUninspected,
}

/// A locally-recorded incident. The server wire contract (spec §4) is a subset
/// (`channel`, `fileName`, `fileSha256`, `verdict`); the device identity and the
/// action taken are recorded locally so a reviewer can see *which stick*.
#[derive(Debug, Clone)]
pub struct UsbIncident {
    pub kind: IncidentKind,
    pub channel: String,
    pub file_name: String,
    pub file_sha256: String,
    /// Present for scanned files (Match / UnreadableOnRemovable); None for
    /// metadata-only incidents (skipped-too-large, enforcement-failed, mtp).
    pub verdict: Option<Verdict>,
    pub device: DeviceIdentity,
    pub action_taken: ActionTaken,
    /// Short machine note, e.g. "settled-by-timeout", "unreadable-on-removable",
    /// "skipped-too-large". Never contains file contents.
    pub note: Option<String>,
}

/// A file that has settled and is ready to scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settled {
    pub path: PathBuf,
    pub size: u64,
    /// True if it was force-settled by the timeout while still changing
    /// (spec §3.5: "settled-by-timeout").
    pub by_timeout: bool,
}

// Per-file tracking for settle detection. All times are injected `now_ms`.
#[derive(Debug, Clone)]
struct FileState {
    size: u64,
    mtime_ms: u64,
    first_seen_ms: u64,
    last_change_ms: u64,
    // Sharing-violation retries before we give up and skip-with-note.
    lock_retries: u32,
}

/// Bounded dedup set keyed by `(path, size, mtime)` so an unchanged file is not
/// re-scanned every poll (spec §5 edge 7). LRU-evicts at `cap` (default 10k) so
/// it cannot grow without bound (spec §3.5).
struct BoundedSeen {
    cap: usize,
    order: VecDeque<(PathBuf, u64, u64)>,
    set: HashSet<(PathBuf, u64, u64)>,
}

impl BoundedSeen {
    fn new(cap: usize) -> Self {
        BoundedSeen { cap, order: VecDeque::new(), set: HashSet::new() }
    }
    fn contains(&self, key: &(PathBuf, u64, u64)) -> bool {
        self.set.contains(key)
    }
    fn insert(&mut self, key: (PathBuf, u64, u64)) {
        if self.set.insert(key.clone()) {
            self.order.push_back(key);
            while self.order.len() > self.cap {
                if let Some(old) = self.order.pop_front() {
                    self.set.remove(&old);
                }
            }
        }
    }
}

/// Max sharing-violation retries before a locked file is skipped (edge 4).
const MAX_LOCK_RETRIES: u32 = 5;
/// Dedup set cap (spec §3.5).
const SEEN_CAP: usize = 10_000;

/// Watches one volume root for settled new/changed files. Stateful across
/// polls; the caller supplies a monotonic `now_ms` each poll.
pub struct CopyAuditor {
    root: PathBuf,
    settle_ms: u64,
    settle_timeout_ms: u64,
    tracked: HashMap<PathBuf, FileState>,
    seen: BoundedSeen,
}

impl CopyAuditor {
    pub fn new(root: impl Into<PathBuf>, settle_ms: u64, settle_timeout_ms: u64) -> Self {
        CopyAuditor {
            root: root.into(),
            settle_ms,
            settle_timeout_ms,
            tracked: HashMap::new(),
            seen: BoundedSeen::new(SEEN_CAP),
        }
    }

    /// Recursively list regular files under the root with their (size, mtime).
    /// A volume removed mid-scan makes this return an empty/partial list rather
    /// than panicking (spec §5 edge 8).
    fn scan_tree(&self) -> Vec<(PathBuf, u64, u64)> {
        let mut out = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => continue, // vanished / unreadable dir → skip
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if meta.is_dir() {
                    stack.push(path);
                } else if meta.is_file() {
                    let size = meta.len();
                    let mtime_ms = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    out.push((path, size, mtime_ms));
                }
            }
        }
        out
    }

    /// One poll at logical time `now_ms`. Returns the files that have newly
    /// settled AND passed dedup, ready to scan. A file counts as settled when
    /// its (size, mtime) has been unchanged for `settle_ms`, or force-settled
    /// once at `settle_timeout_ms` if still changing. Vanished files are dropped
    /// naturally (spec §5 edge 9).
    pub fn poll(&mut self, now_ms: u64) -> Vec<Settled> {
        let current = self.scan_tree();
        let present: HashSet<PathBuf> = current.iter().map(|(p, _, _)| p.clone()).collect();

        // Drop tracking for files that vanished (temp files, removed volume).
        self.tracked.retain(|p, _| present.contains(p));

        let mut settled = Vec::new();
        for (path, size, mtime_ms) in current {
            let entry = self.tracked.entry(path.clone()).or_insert(FileState {
                size,
                mtime_ms,
                first_seen_ms: now_ms,
                last_change_ms: now_ms,
                lock_retries: 0,
            });

            let changed = entry.size != size || entry.mtime_ms != mtime_ms;
            if changed {
                entry.size = size;
                entry.mtime_ms = mtime_ms;
                entry.last_change_ms = now_ms;
                // Still growing → not settled this poll.
                if now_ms.saturating_sub(entry.first_seen_ms) < self.settle_timeout_ms {
                    continue;
                }
            }

            let stable_for = now_ms.saturating_sub(entry.last_change_ms);
            let waited_total = now_ms.saturating_sub(entry.first_seen_ms);
            let by_timeout = waited_total >= self.settle_timeout_ms && stable_for < self.settle_ms;
            let is_settled = stable_for >= self.settle_ms || by_timeout;
            if !is_settled {
                continue;
            }

            let key = (path.clone(), size, mtime_ms);
            if self.seen.contains(&key) {
                continue; // already scanned this exact (path,size,mtime)
            }

            // Openability / sharing check: a locked file (still being written)
            // is retried a bounded number of times, then skipped (edge 4).
            if std::fs::File::open(&path).is_err() {
                entry.lock_retries += 1;
                if entry.lock_retries < MAX_LOCK_RETRIES {
                    continue; // retry next poll
                }
                // Give up: mark seen so we don't spin, and surface it as settled
                // (the scan step will note the sharing problem).
            }

            self.seen.insert(key);
            settled.push(Settled { path, size, by_timeout });
        }
        settled
    }
}

/// Build an incident (if any) for a settled file, using an injectable verdict
/// source (spec §3.5). Returns:
/// * `Some(Match)` when IDM/EDM matched,
/// * `Some(UnreadableOnRemovable)` when content couldn't be read (fail-secure),
/// * `Some(SkippedTooLarge)` when the file exceeds `max_file_bytes`,
/// * `None` for an innocent, readable, non-matching file.
///
/// The verdict source (`|p| detect::verdict(p, &bundle)`) is the ONLY place the
/// file is read; large files are size-gated *before* calling it.
pub fn scan_to_incident<F>(
    settled: &Settled,
    max_file_bytes: u64,
    verdict_src: &F,
    device: &DeviceIdentity,
    action: ActionTaken,
    channel: &str,
) -> Option<UsbIncident>
where
    F: Fn(&Path) -> anyhow::Result<Verdict>,
{
    let base = settled
        .path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| settled.path.display().to_string());

    // Size cap: never read an oversized file — skip with a metadata incident.
    if settled.size > max_file_bytes {
        return Some(UsbIncident {
            kind: IncidentKind::SkippedTooLarge,
            channel: channel.to_string(),
            file_name: base,
            file_sha256: String::new(),
            verdict: None,
            device: device.clone(),
            action_taken: action,
            note: Some(format!("skipped-too-large:{}>{}", settled.size, max_file_bytes)),
        });
    }

    let verdict = match verdict_src(&settled.path) {
        Ok(v) => v,
        Err(e) => {
            // Could not even produce a verdict (e.g. no bundle / read error).
            // Surface as unreadable-on-removable, fail-secure, without content.
            tracing::warn!(file = %base, error = %e, "verdict failed on removable file");
            return Some(UsbIncident {
                kind: IncidentKind::UnreadableOnRemovable,
                channel: channel.to_string(),
                file_name: base,
                file_sha256: String::new(),
                verdict: None,
                device: device.clone(),
                action_taken: action,
                note: Some("verdict-error".into()),
            });
        }
    };

    let has_match = !verdict.idm.is_empty() || !verdict.edm.is_empty();
    if has_match {
        let mut note = None;
        if settled.by_timeout {
            note = Some("settled-by-timeout".into());
        }
        return Some(UsbIncident {
            kind: IncidentKind::Match,
            channel: channel.to_string(),
            file_name: verdict.file_name.clone(),
            file_sha256: verdict.file_sha256.clone(),
            verdict: Some(verdict),
            device: device.clone(),
            action_taken: action,
            note,
        });
    }

    if matches!(verdict.extraction, Extraction::Unreadable { .. }) {
        return Some(UsbIncident {
            kind: IncidentKind::UnreadableOnRemovable,
            channel: channel.to_string(),
            file_name: verdict.file_name.clone(),
            file_sha256: verdict.file_sha256.clone(),
            verdict: Some(verdict),
            device: device.clone(),
            action_taken: action,
            note: Some("unreadable-on-removable".into()),
        });
    }

    // Innocent, readable, no match → no incident.
    None
}

/// A bounded worker pool that scans settled files concurrently WITHOUT spawning
/// one thread per file (spec §3.5 / §7): a fixed set of `workers` threads drain
/// a queue. Used by `run_monitor` for bulk copies; the deterministic settle
/// logic above is what the integration test exercises.
pub fn scan_batch<F>(
    settled: Vec<Settled>,
    workers: usize,
    max_file_bytes: u64,
    verdict_src: F,
    device: DeviceIdentity,
    action: ActionTaken,
    channel: String,
) -> Vec<UsbIncident>
where
    F: Fn(&Path) -> anyhow::Result<Verdict> + Send + Sync + 'static,
{
    let workers = workers.clamp(1, 4);
    if settled.is_empty() {
        return Vec::new();
    }
    let verdict_src = std::sync::Arc::new(verdict_src);
    let (job_tx, job_rx) = mpsc::channel::<Settled>();
    let job_rx = std::sync::Arc::new(std::sync::Mutex::new(job_rx));
    let (out_tx, out_rx) = mpsc::channel::<UsbIncident>();

    let mut handles = Vec::new();
    for _ in 0..workers {
        let job_rx = job_rx.clone();
        let out_tx = out_tx.clone();
        let verdict_src = verdict_src.clone();
        let device = device.clone();
        let channel = channel.clone();
        handles.push(std::thread::spawn(move || loop {
            let job = {
                let rx = job_rx.lock().unwrap();
                rx.recv()
            };
            let Ok(job) = job else { break };
            if let Some(inc) = scan_to_incident(
                &job,
                max_file_bytes,
                verdict_src.as_ref(),
                &device,
                action,
                &channel,
            ) {
                let _ = out_tx.send(inc);
            }
        }));
    }
    for s in settled {
        let _ = job_tx.send(s);
    }
    drop(job_tx);
    drop(out_tx);

    let mut incidents = Vec::new();
    while let Ok(inc) = out_rx.recv() {
        incidents.push(inc);
    }
    for h in handles {
        let _ = h.join();
    }
    incidents
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::Extraction;

    fn dev() -> DeviceIdentity {
        DeviceIdentity {
            drive_letter: "E:".into(),
            vendor_id: "V".into(),
            product_id: "P".into(),
            serial: "S".into(),
            product_name: "V P".into(),
            bus_type: "usb".into(),
            removable: true,
        }
    }

    fn empty_verdict(name: &str) -> Verdict {
        Verdict {
            file_name: name.into(),
            file_sha256: "sha".into(),
            extraction: Extraction::Ok { format: "text".into() },
            idm: vec![],
            edm: vec![],
        }
    }

    #[test]
    fn dedup_evicts_at_cap() {
        let mut seen = BoundedSeen::new(2);
        seen.insert((PathBuf::from("a"), 1, 1));
        seen.insert((PathBuf::from("b"), 1, 1));
        seen.insert((PathBuf::from("c"), 1, 1)); // evicts "a"
        assert!(!seen.contains(&(PathBuf::from("a"), 1, 1)));
        assert!(seen.contains(&(PathBuf::from("b"), 1, 1)));
        assert!(seen.contains(&(PathBuf::from("c"), 1, 1)));
    }

    #[test]
    fn skipped_too_large_produces_metadata_incident_without_reading() {
        let settled = Settled { path: PathBuf::from("/x/big.bin"), size: 999, by_timeout: false };
        // verdict_src panics if called — proving we do NOT read oversized files.
        let src = |_: &Path| -> anyhow::Result<Verdict> { panic!("must not read a too-large file") };
        let inc = scan_to_incident(&settled, 100, &src, &dev(), ActionTaken::Audited, "usb")
            .expect("too-large must yield an incident");
        assert_eq!(inc.kind, IncidentKind::SkippedTooLarge);
        assert!(inc.verdict.is_none());
    }

    #[test]
    fn innocent_file_yields_no_incident() {
        let settled = Settled { path: PathBuf::from("/x/note.txt"), size: 10, by_timeout: false };
        let src = |_: &Path| Ok(empty_verdict("note.txt"));
        assert!(scan_to_incident(&settled, 1000, &src, &dev(), ActionTaken::Audited, "usb").is_none());
    }

    #[test]
    fn matching_file_yields_match_incident() {
        let settled = Settled { path: PathBuf::from("/x/plan.txt"), size: 10, by_timeout: false };
        let src = |_: &Path| {
            let mut v = empty_verdict("plan.txt");
            v.idm.push(crate::detect::IdmMatch {
                version_id: "vid".into(),
                document_id: "did".into(),
                collection_id: "cid".into(),
                title: "Plan".into(),
                containment: 1.0,
                coverage: 1.0,
                matched_count: 1,
                total_count: 1,
                matched_hashes: vec!["1".into()],
            });
            Ok(v)
        };
        let inc = scan_to_incident(&settled, 1000, &src, &dev(), ActionTaken::ReadOnly, "usb")
            .expect("match must yield incident");
        assert_eq!(inc.kind, IncidentKind::Match);
        assert_eq!(inc.channel, "usb");
        assert_eq!(inc.file_name, "plan.txt");
        assert_eq!(inc.action_taken, ActionTaken::ReadOnly);
        assert!(inc.verdict.is_some());
    }

    #[test]
    fn unreadable_file_yields_fail_secure_incident() {
        let settled = Settled { path: PathBuf::from("/x/enc.zip"), size: 10, by_timeout: false };
        let src = |_: &Path| {
            let mut v = empty_verdict("enc.zip");
            v.extraction = Extraction::Unreadable { reason: "encrypted-archive".into() };
            Ok(v)
        };
        let inc = scan_to_incident(&settled, 1000, &src, &dev(), ActionTaken::Audited, "usb")
            .expect("unreadable must yield incident");
        assert_eq!(inc.kind, IncidentKind::UnreadableOnRemovable);
        assert_eq!(inc.note.as_deref(), Some("unreadable-on-removable"));
    }

    #[test]
    fn scan_batch_is_bounded_and_processes_all() {
        let files: Vec<Settled> = (0..20)
            .map(|i| Settled { path: PathBuf::from(format!("/x/f{i}.txt")), size: 5, by_timeout: false })
            .collect();
        let incidents = scan_batch(
            files,
            4,
            1000,
            |p: &Path| {
                // Odd-numbered files "match", even ones are innocent.
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                let mut v = empty_verdict(&name);
                let n: u32 = name.trim_start_matches('f').trim_end_matches(".txt").parse().unwrap();
                if n % 2 == 1 {
                    v.idm.push(crate::detect::IdmMatch {
                        version_id: "v".into(), document_id: "d".into(), collection_id: "c".into(),
                        title: "t".into(), containment: 1.0, coverage: 1.0,
                        matched_count: 1, total_count: 1, matched_hashes: vec!["1".into()],
                    });
                }
                Ok(v)
            },
            dev(),
            ActionTaken::Audited,
            "usb".into(),
        );
        assert_eq!(incidents.len(), 10, "the ten odd-numbered files must each incident");
        assert!(incidents.iter().all(|i| i.kind == IncidentKind::Match));
    }
}
