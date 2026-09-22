//! The fingerprint index a long-running channel scores against — kept current
//! WITHOUT a restart.
//!
//! Why this module exists
//! ----------------------
//! Every enforcing channel (kguard's USB write + read-deny scan, the USB audit
//! monitor, the clipboard monitor, the browser-upload host) used to load
//! `index.dlpx` ONCE, when it started, and score against that copy for the
//! rest of its life. The check-in worker downloads and stores a newer index
//! whenever the console registers a document — but nothing ever told the
//! channels. So:
//!
//! * a document an admin registered today was not enforced on USB until the
//!   service next restarted;
//! * an endpoint that started with NO index (fresh install, or one lost to a
//!   crash mid-save) stayed blind even after the index was re-downloaded,
//!   and on the kguard write path "no index" skips the ML classifier too.
//!
//! A `LiveBundle` holds the current VERIFIED bundle behind an `Arc` and a
//! detached watcher thread re-checks the file every few seconds. Readers call
//! [`LiveBundle::current`] once per event — an `RwLock` read and an `Arc`
//! clone, so the 500 ms kernel path never pays for signature verification.
//!
//! What it refuses to do (all fail-secure, all logged, none silent):
//!
//! * replace a good in-memory bundle with nothing, because the file vanished;
//! * replace it with bytes that fail signature or parse verification;
//! * roll back to a LOWER version — the same monotonic rule the downloader
//!   (`update_index_bundle`) applies, so an older-but-validly-signed bundle
//!   dropped on disk cannot quietly un-register documents.
//!
//! Content, file names and hashes are never logged — versions and counts only.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, SystemTime};

use crate::detect::Bundle;
use crate::storage::Storage;

/// How often the watcher re-checks the index file. A `stat` every few seconds
/// is free; the delay is the longest a newly downloaded index waits before it
/// is enforced.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// What one [`LiveBundle::refresh`] did. Reporting and tests only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refresh {
    /// The file is the same one already considered.
    Unchanged,
    /// A newer verified bundle is now live.
    Loaded { from: Option<u64>, to: u64 },
    /// The file changed but holds the same version already live.
    SameVersion(u64),
    /// The file holds an OLDER validly-signed version; the newer in-memory one
    /// was kept.
    KeptNewer { on_disk: u64, live: u64 },
    /// The file changed and failed verification; whatever was live is kept.
    Rejected,
    /// The file is absent; whatever was live is kept.
    Missing,
    /// The file or the CA could not be read right now (a scanner holding it,
    /// say). Retried on the next poll rather than remembered as bad.
    Transient,
}

/// Identity of the file on disk — enough to notice a replacement. An atomic
/// replace always produces a new modification time (the temp file is written
/// fresh), and length alone would miss a same-size re-sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    len: u64,
    modified: Option<SystemTime>,
}

fn stamp(path: &Path) -> Option<Stamp> {
    let m = std::fs::metadata(path).ok()?;
    Some(Stamp { len: m.len(), modified: m.modified().ok() })
}

struct Inner {
    channel: &'static str,
    index_path: PathBuf,
    state_dir: PathBuf,
    ca_cert_path: PathBuf,
    current: RwLock<Option<Arc<Bundle>>>,
    /// The stamp of the file last CONSIDERED — loaded, rejected, or found to be
    /// the same. `None` inside means "the file was absent last time".
    considered: Mutex<Option<Option<Stamp>>>,
    reloads: AtomicU64,
    rejections: AtomicU64,
    /// Set once `open` has made its first attempt, so a later first-ever load
    /// (recovery from "no index") is logged by `refresh` rather than silently.
    opened: std::sync::atomic::AtomicBool,
}

/// A channel's live view of the verified fingerprint index. Cheap to clone.
#[derive(Clone)]
pub struct LiveBundle {
    inner: Arc<Inner>,
}

impl LiveBundle {
    /// Load whatever verified bundle is on disk now, WITHOUT a watcher. Tests
    /// and one-shot commands use this and call [`refresh`](Self::refresh)
    /// themselves.
    pub fn open(state_dir: &Path, ca_cert_path: &Path, channel: &'static str) -> Self {
        let storage = Storage::new(state_dir.to_path_buf());
        let lb = LiveBundle {
            inner: Arc::new(Inner {
                channel,
                index_path: storage.index_bundle_path(),
                state_dir: state_dir.to_path_buf(),
                ca_cert_path: ca_cert_path.to_path_buf(),
                current: RwLock::new(None),
                considered: Mutex::new(None),
                reloads: AtomicU64::new(0),
                rejections: AtomicU64::new(0),
                opened: std::sync::atomic::AtomicBool::new(false),
            }),
        };
        match lb.refresh() {
            Refresh::Loaded { to, .. } => {
                tracing::info!(channel, version = to, "verified index bundle loaded")
            }
            _ => tracing::warn!(
                channel,
                "no verified index bundle on disk yet — this channel scores without \
                 fingerprints until one is downloaded, and picks it up automatically \
                 (no restart needed)"
            ),
        }
        lb.inner.opened.store(true, Ordering::Relaxed);
        lb
    }

    /// [`open`](Self::open) plus a detached watcher that re-checks the file
    /// every `interval`. The watcher holds only a weak reference, so it exits
    /// on its own once every clone of this `LiveBundle` has been dropped —
    /// there is nothing to join, and a restarted channel simply builds a new
    /// one.
    pub fn start(state_dir: &Path, ca_cert_path: &Path, channel: &'static str, interval: Duration) -> Self {
        let lb = Self::open(state_dir, ca_cert_path, channel);
        lb.spawn_watcher(interval);
        lb
    }

    fn spawn_watcher(&self, interval: Duration) {
        let weak: Weak<Inner> = Arc::downgrade(&self.inner);
        let spawned = std::thread::Builder::new()
            .name(format!("bundle-watch-{}", self.inner.channel))
            .spawn(move || loop {
                std::thread::sleep(interval);
                let Some(inner) = weak.upgrade() else { return };
                // A panic in one refresh must not end the watching for good;
                // it is logged and the next tick tries again.
                let lb = LiveBundle { inner };
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| lb.refresh())).is_err() {
                    tracing::error!(channel = lb.inner.channel, "index bundle refresh panicked — will retry");
                }
            });
        if let Err(e) = spawned {
            // Without the watcher the channel keeps its startup bundle — exactly
            // the pre-fix behaviour, so this degrades, it does not break.
            tracing::warn!(channel = self.inner.channel, error = %e, "could not start the index bundle watcher");
        }
    }

    /// The bundle to score THIS event against. `None` = no verified index yet.
    /// Take it once per event and use that one value throughout the event.
    pub fn current(&self) -> Option<Arc<Bundle>> {
        self.inner.current.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Version of the live bundle, if any.
    pub fn version(&self) -> Option<u64> {
        self.current().map(|b| b.version())
    }

    /// How many times a newer bundle has gone live since construction
    /// (the initial load included).
    pub fn reloads(&self) -> u64 {
        self.inner.reloads.load(Ordering::Relaxed)
    }

    /// How many changed files were rejected (bad signature, older version).
    pub fn rejections(&self) -> u64 {
        self.inner.rejections.load(Ordering::Relaxed)
    }

    /// Look at the file once and swap in a newer verified bundle if there is
    /// one. The watcher calls this; so can a test or a one-shot command.
    pub fn refresh(&self) -> Refresh {
        let inner = &*self.inner;
        let channel = inner.channel;
        let now = stamp(&inner.index_path);

        let mut considered = inner.considered.lock().unwrap_or_else(|p| p.into_inner());
        if *considered == Some(now) {
            return Refresh::Unchanged;
        }

        let Some(_) = now else {
            *considered = Some(None);
            if let Some(v) = self.version() {
                tracing::warn!(
                    channel,
                    version = v,
                    "index bundle file is missing on disk — keeping the verified bundle already in memory"
                );
            }
            return Refresh::Missing;
        };

        // Transient failures are NOT remembered: a scanner holding the file, or
        // an unreadable CA, is retried on the next tick.
        let Ok(bytes) = std::fs::read(&inner.index_path) else {
            return Refresh::Transient;
        };
        let Some(ca) = resolve_ca(&inner.state_dir, &inner.ca_cert_path) else {
            return Refresh::Transient;
        };

        // From here the outcome is a property of THIS file, so remember it and
        // do not re-verify the same bytes every tick.
        *considered = Some(now);
        drop(considered);

        let candidate = match Bundle::load(&bytes, &ca) {
            Ok(b) => b,
            Err(_) => {
                inner.rejections.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    channel,
                    bytes = bytes.len(),
                    live = ?self.version(),
                    "index bundle on disk failed verification — keeping the bundle already in memory"
                );
                return Refresh::Rejected;
            }
        };

        let mut cur = inner.current.write().unwrap_or_else(|p| p.into_inner());
        let live = cur.as_ref().map(|b| b.version());
        let to = candidate.version();
        match live {
            Some(l) if to == l => Refresh::SameVersion(l),
            Some(l) if to < l => {
                inner.rejections.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    channel,
                    on_disk = to,
                    live = l,
                    "index bundle on disk is OLDER than the one in memory — refusing to roll back"
                );
                Refresh::KeptNewer { on_disk: to, live: l }
            }
            _ => {
                *cur = Some(Arc::new(candidate));
                inner.reloads.fetch_add(1, Ordering::Relaxed);
                if live.is_some() {
                    tracing::info!(channel, from = ?live, to, "index bundle hot-reloaded — new documents are enforced now");
                } else if inner.opened.load(Ordering::Relaxed) {
                    // The recovery case: this channel has been running with NO
                    // index (fresh install, or one lost) and now has one.
                    tracing::info!(channel, version = to, "index bundle now available — this channel is enforcing fingerprints again, without a restart");
                }
                Refresh::Loaded { from: live, to }
            }
        }
    }
}

/// The CA that signs bundles: the one pinned at enrollment when enrolled, else
/// the installer-provisioned file — the same rule every channel applied in its
/// own copy of this function before this module replaced them.
fn resolve_ca(state_dir: &Path, ca_cert_path: &Path) -> Option<Vec<u8>> {
    let storage = Storage::new(state_dir.to_path_buf());
    if storage.has_identity() {
        storage.load_identity().ok().map(|(_, ca)| ca)
    } else {
        std::fs::read(ca_cert_path).ok()
    }
}
