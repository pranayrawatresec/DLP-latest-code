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
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::envelope;
use crate::crypto::keyring::Kek;
use crate::detect::{Extraction, Verdict};
use crate::trustdest::{decide_seal, BlockBandPolicy, EncryptBands, EncryptMode, SealDecision};

use super::device::DeviceIdentity;
use super::policy::Action;

/// What enforcement disposition accompanied this file's audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionTaken {
    Audited,
    ReadOnly,
    Blocked,
    /// A `.dlpenc` seal-in-place SUCCEEDED on an `Action::Encrypt` destination
    /// (encrypt-on-write spec §5.1): the sealed sibling is on the volume and
    /// the plaintext original is gone. Recorded ONLY after that success — a
    /// planned-but-failed seal stays `Audited` with
    /// `IncidentKind::EnforcementFailed` (planned vs taken stay distinct).
    Encrypted,
}

impl From<Action> for ActionTaken {
    fn from(a: Action) -> Self {
        match a {
            Action::AllowAudited => ActionTaken::Audited,
            // Planned vs taken (encrypt-on-write spec §5.1): an `Encrypt`
            // destination's copies are AUDITED until a seal actually succeeds.
            // `ActionTaken::Encrypted` is set only by the seal pipeline
            // (`scan_and_seal_to_incident`) after a successful seal — NEVER
            // from the plan, so this mapping deliberately stays `Audited`.
            Action::Encrypt => ActionTaken::Audited,
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
    /// A file was sealed into a `.dlpenc` envelope on an `Action::Encrypt`
    /// destination WITHOUT an IDM/EDM match of its own (encrypt_all courier
    /// mode, or the fail-secure seal when no verdict could be produced —
    /// encrypt-on-write spec §3.1/§5.1). Files that DID match stay `Match`
    /// (with `action_taken: Encrypted`); unreadable ones stay
    /// `UnreadableOnRemovable`. Every successful seal raises an incident so
    /// the key id and both hashes are on record.
    Sealed,
    /// A `.dlpenc` open was refused — unknown or crypto-shredded key id, or a
    /// policy deny (encrypt-on-write spec §5.3, raised by the decrypt path,
    /// M4). Someone holding old/foreign sealed media is signal, not noise.
    DecryptDenied,
    /// A `.dlpenc` open SUCCEEDED on this endpoint (decrypt path, spec §5.3,
    /// M4). Every decrypt is audited — and the incident is recorded BEFORE
    /// the plaintext is written (no un-audited decrypt, ever).
    Decrypted,
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
    /// "skipped-too-large", "sealed-post-write". Never contains file contents.
    pub note: Option<String>,
    /// KEK id a SUCCESSFUL seal used (`action_taken == Encrypted` only), or —
    /// on the decrypt path (M4) — the key id the open used (`Decrypted`) or
    /// the envelope header CLAIMED (`DecryptDenied`; a peeked header is not
    /// yet authenticated). FREE-FORM opaque string, never parsed anywhere.
    /// `None` for every other incident, including failed seals. Additive wire
    /// field (encrypt-on-write spec §5.1/§5.3).
    pub key_id: Option<String>,
    /// hex SHA-256 of the sealed `.dlpenc` envelope: as written to the
    /// destination (successful seals) or as presented for decrypt (M4 —
    /// identifies the exact envelope even when the open is denied).
    /// `file_sha256` remains the PLAINTEXT hash so it keeps correlating with
    /// the envelope header's `plaintextSha256`. Additive wire field.
    pub sealed_sha256: Option<String>,
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

/// True for the sealer's own output: `<name>.dlpenc` and its in-flight
/// `<name>.dlpenc.tmp`. The copy auditor skips these so sealing is idempotent
/// and can never recurse on its own envelopes (pure, tested).
fn is_sealed_envelope_path(path: &Path) -> bool {
    match path.file_name().and_then(|s| s.to_str()) {
        Some(name) => {
            let lower = name.to_ascii_lowercase();
            lower.ends_with(".dlpenc") || lower.ends_with(".dlpenc.tmp")
        }
        None => false,
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

    /// Seed the dedup set with the files ALREADY present under the root, so a
    /// freshly-mounted volume's pre-existing content is treated as a baseline
    /// and never re-scanned or re-sealed. Only files WRITTEN AFTER this call
    /// (a genuine copy-to-stick) settle and surface from `poll`. A pre-existing
    /// file that is later modified still surfaces — its changed `(size, mtime)`
    /// key differs from the baselined one, so it is not falsely suppressed.
    ///
    /// Returns the number of files baselined. Bounded by the dedup cap
    /// (`SEEN_CAP`): on a volume with more than `SEEN_CAP` files the oldest
    /// baseline entries LRU-evict, so a few pre-existing files may still be
    /// processed — acceptable degradation, never a panic.
    pub fn baseline_existing(&mut self) -> usize {
        let current = self.scan_tree();
        let n = current.len();
        for key in current {
            self.seen.insert(key);
        }
        n
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
                    // Never track our own sealed output. The sealer writes
                    // `<name>.dlpenc` (via a `.dlpenc.tmp`), which would otherwise
                    // reappear as a "new" file and be sealed again — recursing to
                    // `<name>.dlpenc.dlpenc...`. An envelope is already the
                    // strongest protected state (mirrors the kernel guard's DLPE
                    // passthrough); skip it on every volume.
                    if is_sealed_envelope_path(&path) {
                        continue;
                    }
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
            key_id: None,
            sealed_sha256: None,
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
                key_id: None,
                sealed_sha256: None,
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
            key_id: None,
            sealed_sha256: None,
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
            key_id: None,
            sealed_sha256: None,
        });
    }

    // Innocent, readable, no match → no incident.
    None
}

/// What a SUCCESSFUL seal-in-place produced (encrypt-on-write spec §5.1).
/// Hashes and the key id only — never key material, never content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealOutcome {
    /// The KEK id actually used — FREE-FORM opaque string, never parsed.
    pub key_id: String,
    /// hex SHA-256 of the plaintext that was sealed (correlates with the
    /// envelope header's `plaintextSha256` and `UsbIncident.file_sha256`).
    pub plaintext_sha256: String,
    /// hex SHA-256 of the `.dlpenc` envelope as written to the destination.
    pub sealed_sha256: String,
}

/// Scan + seal decision for ONE settled file on an `Action::Encrypt`
/// destination (encrypt-on-write spec §5.1, milestone M3).
///
/// Pipeline: size gate → injected verdict fn → `trustdest::decide_seal` →
/// * `Plain` → today's behaviour exactly (audit incident on a match, else none),
/// * `Seal`  → the injected SEALER fn (`sealer(path, key_id)`) performs the
///   seal-in-place; success ⇒ incident with `ActionTaken::Encrypted`, the key
///   id and both hashes; ANY failure ⇒ the plaintext is KEPT (the sealer must
///   guarantee that) and an `EnforcementFailed` incident carries the error
///   note — fail secure: nothing is silently lost or silently unprotected,
/// * `Block` → the existing block path: in this user-mode audit channel that
///   is a `Match` incident (the kernel guard is the enforcing layer);
///   whitelisting a destination never weakens the block band (spec §10).
///
/// The sealer is injected (like the verdict fn) so tests assert call/no-call
/// and incident shape without real crypto or hardware; production wires
/// [`seal_file_in_place`] (see `main.rs`).
///
/// Known, documented v1 limitation: plaintext exists on the volume between the
/// OS write and our seal (the settle window) — every seal incident carries the
/// `"sealed-post-write"` note. Closing the window is kernel milestone M8.
#[allow(clippy::too_many_arguments)]
pub fn scan_and_seal_to_incident<F, S>(
    settled: &Settled,
    max_file_bytes: u64,
    verdict_src: &F,
    device: &DeviceIdentity,
    channel: &str,
    mode: EncryptMode,
    bands: &EncryptBands,
    on_block_band: BlockBandPolicy,
    key_id: &str,
    sealer: &S,
) -> Option<UsbIncident>
where
    F: Fn(&Path) -> anyhow::Result<Verdict>,
    S: Fn(&Path, &str) -> anyhow::Result<SealOutcome>,
{
    let base = settled
        .path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| settled.path.display().to_string());

    // Size gate: an oversized file is neither read nor sealed (sealing needs a
    // full in-memory read — unbounded above the cap that exists precisely to
    // bound reads). Deliberate, FLAGGED limitation: the metadata incident
    // keeps the plaintext copy visible to a reviewer, nothing is silent.
    if settled.size > max_file_bytes {
        return Some(UsbIncident {
            kind: IncidentKind::SkippedTooLarge,
            channel: channel.to_string(),
            file_name: base,
            file_sha256: String::new(),
            verdict: None,
            device: device.clone(),
            action_taken: ActionTaken::Audited,
            note: Some(format!(
                "skipped-too-large:{}>{};not-sealed",
                settled.size, max_file_bytes
            )),
            key_id: None,
            sealed_sha256: None,
        });
    }

    // Injected verdict fn; a failure means "no verdict available", which
    // decide_seal fails secure to Seal on BOTH encrypt modes.
    let verdict = match verdict_src(&settled.path) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(file = %base, error = %e, "verdict failed on encrypt destination — sealing fail-secure");
            None
        }
    };

    let has_match = verdict
        .as_ref()
        .map(|v| !v.idm.is_empty() || !v.edm.is_empty())
        .unwrap_or(false);
    let unreadable = verdict
        .as_ref()
        .map(|v| matches!(v.extraction, Extraction::Unreadable { .. }))
        .unwrap_or(false);
    let file_name = verdict.as_ref().map(|v| v.file_name.clone()).unwrap_or_else(|| base.clone());
    let verdict_sha = verdict.as_ref().map(|v| v.file_sha256.clone()).unwrap_or_default();

    match decide_seal(mode, bands, on_block_band, verdict.as_ref()) {
        // Clean file on encrypt_sensitive → today's behaviour. Plain implies a
        // readable verdict exists (None/Unreadable fail secure to Seal), so
        // only the match/no-match split remains — identical to
        // `scan_to_incident`'s shape.
        SealDecision::Plain => {
            if has_match {
                Some(UsbIncident {
                    kind: IncidentKind::Match,
                    channel: channel.to_string(),
                    file_name,
                    file_sha256: verdict_sha,
                    verdict,
                    device: device.clone(),
                    action_taken: ActionTaken::Audited,
                    note: settled.by_timeout.then(|| "settled-by-timeout".to_string()),
                    key_id: None,
                    sealed_sha256: None,
                })
            } else {
                None
            }
        }
        // Block band reached — the whitelist never weakens the block
        // threshold. In this user-mode channel the existing "block path" is
        // the audit record (kguard/minifilter is the enforcing layer); the
        // file is deliberately NOT sealed so the planned/taken distinction and
        // the kernel path's quarantine semantics stay untouched.
        SealDecision::Block => Some(UsbIncident {
            kind: IncidentKind::Match,
            channel: channel.to_string(),
            file_name,
            file_sha256: verdict_sha,
            verdict,
            device: device.clone(),
            action_taken: ActionTaken::Audited,
            note: Some("block-band-on-encrypt-destination".into()),
            key_id: None,
            sealed_sha256: None,
        }),
        SealDecision::Seal => match sealer(&settled.path, key_id) {
            Ok(out) => {
                // Success: the sealed sibling is on the volume, plaintext gone.
                // Kind reflects WHAT was sealed; Encrypted records the taken
                // action; note documents the v1 settle-window limitation.
                let kind = if has_match {
                    IncidentKind::Match
                } else if unreadable {
                    IncidentKind::UnreadableOnRemovable
                } else {
                    IncidentKind::Sealed
                };
                let file_sha256 =
                    if verdict_sha.is_empty() { out.plaintext_sha256.clone() } else { verdict_sha };
                Some(UsbIncident {
                    kind,
                    channel: channel.to_string(),
                    file_name,
                    file_sha256,
                    verdict,
                    device: device.clone(),
                    action_taken: ActionTaken::Encrypted,
                    note: Some("sealed-post-write".into()),
                    key_id: Some(out.key_id),
                    sealed_sha256: Some(out.sealed_sha256),
                })
            }
            Err(e) => {
                // Fail secure: the sealer keeps the plaintext on ANY failure;
                // the copy is flagged, never silently left unprotected. The
                // planned action was Encrypt but nothing was enforced → the
                // TAKEN action stays Audited (never claim a seal that didn't
                // happen). The note carries the error only — no content.
                tracing::warn!(file = %base, error = %e, "seal-in-place failed — plaintext kept, raising EnforcementFailed");
                Some(UsbIncident {
                    kind: IncidentKind::EnforcementFailed,
                    channel: channel.to_string(),
                    file_name,
                    file_sha256: verdict_sha,
                    verdict,
                    device: device.clone(),
                    action_taken: ActionTaken::Audited,
                    note: Some(format!("seal-failed(plaintext-kept): {e}")),
                    key_id: None,
                    sealed_sha256: None,
                })
            }
        },
    }
}

/// The PRODUCTION sealer (encrypt-on-write spec §5.1 steps 1–4): seal one file
/// in place on the destination volume.
///
/// 1. read the plaintext fully (the settle machinery guarantees the writer is
///    done; the buffer is zeroized on drop),
/// 2. write `<name>.dlpenc.tmp` beside it and fsync,
/// 3. atomically rename to `<name>.dlpenc` (same volume ⇒ atomic),
/// 4. delete the plaintext original — ONLY after the rename succeeded.
///
/// Any failure returns `Err` with the plaintext untouched on the volume (a
/// leftover `.tmp` is removed best-effort); the caller raises
/// `EnforcementFailed`. Never logs content or key material.
pub fn seal_file_in_place(
    path: &Path,
    kek: &Kek,
    agent_id: &str,
    now_unix: u64,
) -> anyhow::Result<SealOutcome> {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .ok_or_else(|| anyhow::anyhow!("path has no file name"))?;

    let plaintext = Zeroizing::new(std::fs::read(path)?);
    let envelope_bytes = envelope::seal(&plaintext, &name, kek, agent_id, now_unix)
        .map_err(|e| anyhow::anyhow!("envelope seal failed: {e}"))?;
    let plaintext_sha256 = hex(&Sha256::digest(plaintext.as_slice()));
    let sealed_sha256 = hex(&Sha256::digest(&envelope_bytes));

    let tmp_path = path.with_file_name(format!("{name}.dlpenc.tmp"));
    let final_path = path.with_file_name(format!("{name}.dlpenc"));

    // Write + fsync the sibling; on any failure remove the temp (best-effort)
    // and leave the plaintext alone.
    let write_result = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(&envelope_bytes)?;
        f.sync_all()?; // fsync BEFORE the rename — the envelope must be durable
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(anyhow::anyhow!("writing sealed sibling failed: {e}"));
    }
    if let Err(e) = std::fs::rename(&tmp_path, &final_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(anyhow::anyhow!("renaming sealed sibling failed: {e}"));
    }
    // Only now is the plaintext removed. A failure here still leaves the data
    // protected AND present — surfaced as EnforcementFailed by the caller.
    std::fs::remove_file(path)
        .map_err(|e| anyhow::anyhow!("sealed ok but plaintext delete failed: {e}"))?;

    Ok(SealOutcome {
        key_id: kek.id().to_string(),
        plaintext_sha256,
        sealed_sha256,
    })
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
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

    // --- scan_and_seal_to_incident (encrypt-on-write M3, spec §5.1) ---------
    // Fake sealer + injected verdict fn: assert call/no-call and incident
    // shape without real crypto or hardware.

    use std::sync::atomic::{AtomicUsize, Ordering};

    const KEY: &str = "class-internal/v1";

    fn seal_band_verdict(name: &str) -> Verdict {
        let mut v = empty_verdict(name);
        v.idm.push(crate::detect::IdmMatch {
            version_id: "v".into(),
            document_id: "d".into(),
            collection_id: "c".into(),
            title: "t".into(),
            containment: 0.10, // inside the seal band (0.05 ≤ c < 0.30)
            coverage: 0.10,
            matched_count: 1,
            total_count: 10,
            matched_hashes: vec![],
        });
        v
    }

    fn block_band_verdict(name: &str) -> Verdict {
        let mut v = seal_band_verdict(name);
        v.idm[0].containment = 0.90; // ≥ block_at
        v.idm[0].coverage = 0.90;
        v
    }

    fn ok_sealer(calls: &AtomicUsize) -> impl Fn(&Path, &str) -> anyhow::Result<SealOutcome> + '_ {
        move |_p: &Path, key_id: &str| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(SealOutcome {
                key_id: key_id.to_string(),
                plaintext_sha256: "aa".repeat(32),
                sealed_sha256: "bb".repeat(32),
            })
        }
    }

    fn panicking_sealer(_p: &Path, _k: &str) -> anyhow::Result<SealOutcome> {
        panic!("sealer must not be called for this decision");
    }

    #[test]
    fn seal_band_file_is_sealed_with_key_id_and_both_hashes() {
        let settled = Settled { path: PathBuf::from("/x/plan.txt"), size: 10, by_timeout: false };
        let src = |_: &Path| Ok(seal_band_verdict("plan.txt"));
        let calls = AtomicUsize::new(0);
        let sealer = ok_sealer(&calls);
        let inc = scan_and_seal_to_incident(
            &settled, 1000, &src, &dev(), "usb",
            EncryptMode::EncryptSensitive, &EncryptBands::default(), BlockBandPolicy::Block, KEY, &sealer,
        )
        .expect("a sealed file must raise an incident");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "sealer called exactly once");
        assert_eq!(inc.kind, IncidentKind::Match, "a matched file stays a Match incident");
        assert_eq!(inc.action_taken, ActionTaken::Encrypted);
        assert_eq!(inc.key_id.as_deref(), Some(KEY));
        assert_eq!(inc.sealed_sha256.as_deref(), Some("bb".repeat(32).as_str()));
        assert_eq!(inc.file_sha256, "sha", "plaintext hash from the verdict is kept");
        assert_eq!(inc.note.as_deref(), Some("sealed-post-write"), "v1 limitation documented");
        assert!(inc.verdict.is_some());
    }

    #[test]
    fn clean_file_on_encrypt_sensitive_is_not_sealed_and_no_incident() {
        let settled = Settled { path: PathBuf::from("/x/note.txt"), size: 10, by_timeout: false };
        let src = |_: &Path| Ok(empty_verdict("note.txt"));
        let inc = scan_and_seal_to_incident(
            &settled, 1000, &src, &dev(), "usb",
            EncryptMode::EncryptSensitive, &EncryptBands::default(), BlockBandPolicy::Block, KEY, &panicking_sealer,
        );
        assert!(inc.is_none(), "clean file on encrypt_sensitive: today's behaviour (no incident)");
    }

    #[test]
    fn encrypt_all_seals_clean_files_as_sealed_kind() {
        let settled = Settled { path: PathBuf::from("/x/note.txt"), size: 10, by_timeout: false };
        let src = |_: &Path| Ok(empty_verdict("note.txt"));
        let calls = AtomicUsize::new(0);
        let sealer = ok_sealer(&calls);
        let inc = scan_and_seal_to_incident(
            &settled, 1000, &src, &dev(), "usb",
            EncryptMode::EncryptAll, &EncryptBands::default(), BlockBandPolicy::Block, KEY, &sealer,
        )
        .expect("courier-stick mode records every seal");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(inc.kind, IncidentKind::Sealed, "clean-but-sealed gets its own kind, not Match");
        assert_eq!(inc.action_taken, ActionTaken::Encrypted);
        assert_eq!(inc.key_id.as_deref(), Some(KEY));
        assert!(inc.sealed_sha256.is_some());
    }

    #[test]
    fn sealer_failure_raises_enforcement_failed_without_encrypted_claim() {
        let settled = Settled { path: PathBuf::from("/x/plan.txt"), size: 10, by_timeout: false };
        let src = |_: &Path| Ok(seal_band_verdict("plan.txt"));
        let sealer =
            |_p: &Path, _k: &str| -> anyhow::Result<SealOutcome> { anyhow::bail!("disk full") };
        let inc = scan_and_seal_to_incident(
            &settled, 1000, &src, &dev(), "usb",
            EncryptMode::EncryptSensitive, &EncryptBands::default(), BlockBandPolicy::Block, KEY, &sealer,
        )
        .expect("a failed seal must be flagged");
        assert_eq!(inc.kind, IncidentKind::EnforcementFailed);
        assert_eq!(inc.action_taken, ActionTaken::Audited, "planned Encrypt, taken Audited on failure");
        assert!(inc.key_id.is_none(), "no key id claim without a successful seal");
        assert!(inc.sealed_sha256.is_none());
        assert!(inc.note.as_deref().unwrap().contains("seal-failed(plaintext-kept)"));
        assert!(inc.verdict.is_some(), "the verdict is still on record");
    }

    #[test]
    fn block_band_on_encrypt_destination_is_not_sealed() {
        // Whitelisting must never weaken the block threshold (spec §10): the
        // block band keeps the existing (audit-channel) block path, unsealed.
        let settled = Settled { path: PathBuf::from("/x/opord.txt"), size: 10, by_timeout: false };
        let src = |_: &Path| Ok(block_band_verdict("opord.txt"));
        let inc = scan_and_seal_to_incident(
            &settled, 1000, &src, &dev(), "usb",
            EncryptMode::EncryptSensitive, &EncryptBands::default(), BlockBandPolicy::Block, KEY, &panicking_sealer,
        )
        .expect("block band must raise an incident");
        assert_eq!(inc.kind, IncidentKind::Match);
        assert_eq!(inc.action_taken, ActionTaken::Audited);
        assert_eq!(inc.note.as_deref(), Some("block-band-on-encrypt-destination"));
        assert!(inc.key_id.is_none());
    }

    #[test]
    fn block_band_with_seal_opt_in_is_sealed() {
        // Owner opt-in (`on_block_band = "seal"`): a block-band file on this
        // destination leaves armoured instead of blocked — sealer IS called,
        // incident stays a Match (what was sealed) with the Encrypted action.
        let settled = Settled { path: PathBuf::from("/x/opord.txt"), size: 10, by_timeout: false };
        let src = |_: &Path| Ok(block_band_verdict("opord.txt"));
        let calls = AtomicUsize::new(0);
        let sealer = ok_sealer(&calls);
        let inc = scan_and_seal_to_incident(
            &settled, 1000, &src, &dev(), "usb",
            EncryptMode::EncryptSensitive, &EncryptBands::default(), BlockBandPolicy::Seal, KEY,
            &sealer,
        )
        .expect("sealed block-band file must raise an incident");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "sealer called for the opted-in block band");
        assert_eq!(inc.kind, IncidentKind::Match, "the full verdict stays on record");
        assert_eq!(inc.action_taken, ActionTaken::Encrypted);
        assert_eq!(inc.key_id.as_deref(), Some(KEY));
        assert_eq!(inc.note.as_deref(), Some("sealed-post-write"));
    }

    #[test]
    fn unreadable_on_encrypt_sensitive_is_sealed_fail_secure() {
        let settled = Settled { path: PathBuf::from("/x/enc.zip"), size: 10, by_timeout: false };
        let src = |_: &Path| {
            let mut v = empty_verdict("enc.zip");
            v.extraction = Extraction::Unreadable { reason: "encrypted-archive".into() };
            Ok(v)
        };
        let calls = AtomicUsize::new(0);
        let sealer = ok_sealer(&calls);
        let inc = scan_and_seal_to_incident(
            &settled, 1000, &src, &dev(), "usb",
            EncryptMode::EncryptSensitive, &EncryptBands::default(), BlockBandPolicy::Block, KEY, &sealer,
        )
        .expect("unreadable must incident");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "pre-encrypted blind spot is sealed, not waved through");
        assert_eq!(inc.kind, IncidentKind::UnreadableOnRemovable);
        assert_eq!(inc.action_taken, ActionTaken::Encrypted);
    }

    #[test]
    fn verdict_error_fails_secure_to_seal_with_sealer_hash() {
        // No verdict at all (no bundle / scan I/O error) ⇒ seal on both modes;
        // the plaintext hash comes from the sealer's outcome.
        let settled = Settled { path: PathBuf::from("/x/mystery.bin"), size: 10, by_timeout: false };
        let src = |_: &Path| -> anyhow::Result<Verdict> { anyhow::bail!("no-bundle") };
        let calls = AtomicUsize::new(0);
        let sealer = ok_sealer(&calls);
        let inc = scan_and_seal_to_incident(
            &settled, 1000, &src, &dev(), "usb",
            EncryptMode::EncryptSensitive, &EncryptBands::default(), BlockBandPolicy::Block, KEY, &sealer,
        )
        .expect("no-verdict seal must incident");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(inc.kind, IncidentKind::Sealed);
        assert_eq!(inc.action_taken, ActionTaken::Encrypted);
        assert_eq!(inc.file_sha256, "aa".repeat(32), "plaintext hash from the seal outcome");
        assert!(inc.verdict.is_none());
    }

    #[test]
    fn oversized_file_on_encrypt_destination_is_skipped_not_sealed() {
        let settled = Settled { path: PathBuf::from("/x/huge.iso"), size: 999, by_timeout: false };
        let src = |_: &Path| -> anyhow::Result<Verdict> { panic!("must not read oversized") };
        let inc = scan_and_seal_to_incident(
            &settled, 100, &src, &dev(), "usb",
            EncryptMode::EncryptAll, &EncryptBands::default(), BlockBandPolicy::Block, KEY, &panicking_sealer,
        )
        .expect("too-large must yield a metadata incident");
        assert_eq!(inc.kind, IncidentKind::SkippedTooLarge);
        assert!(inc.note.as_deref().unwrap().contains("not-sealed"), "the unsealed state is flagged");
        assert!(inc.key_id.is_none());
    }
}
