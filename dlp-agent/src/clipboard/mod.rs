//! User-mode clipboard channel (spec §1). Watches clipboard changes, inspects
//! the copied content against the cached, signature-verified index bundle, and
//! (under `--enforce`) blocks a sensitive copy by clearing the clipboard.
//!
//! Structure mirrors the USB channel so the two share one incident/queue path:
//! * `formats` — pure bytes → `ClipboardPayload` parsing (unit-tested).
//! * `watch`   — the `#[cfg(windows)]` message-only window + live clipboard read
//!   (operator-manual; NO message loop ever reaches a test).
//! * `enforce` — dry-run-first block planning + the loop guard.
//! * this file — the PURE decision (`inspect`) the tests drive directly, plus
//!   `run_monitor`, the live loop.
//!
//! NEVER logs clipboard text or file contents (spec §1.3 / DO-NOT): incidents
//! carry only hashes, scores, and metadata — exactly like the USB path.

pub mod enforce;
pub mod formats;
pub mod watch;

pub use formats::ClipboardPayload;

use crate::config::{ClipboardAction, ClipboardConfig, Config};
use crate::detect::{self, Bundle, Verdict};
use crate::storage::Storage;
use crate::usb::{ActionTaken, DeviceIdentity, IncidentKind, UsbIncident};

/// The outcome of inspecting one clipboard snapshot: whether it should be
/// blocked (under `--enforce`) and the incidents to report (metadata only).
#[derive(Debug, Clone, Default)]
pub struct ClipboardDecision {
    pub block: bool,
    pub incidents: Vec<UsbIncident>,
}

/// Shared policy signal (spec §Shared, mirrors `kguard::should_block`): BLOCK if
/// any EDM row hit, or any matched document reaches the containment or coverage
/// threshold. Clipboard snippets score low containment / high coverage, and EDM
/// fires on a copied row — either signal blocks.
pub fn verdict_blocks(v: &Verdict, block_at: f64, coverage_block_at: f64) -> bool {
    if !v.edm.is_empty() {
        return true;
    }
    v.idm
        .iter()
        .any(|m| m.containment >= block_at || m.coverage >= coverage_block_at)
}

/// Synthesize the placeholder device identity for a clipboard incident. The
/// clipboard is not a device; other fields are empty and `bus_type` marks the
/// origin so a reviewer can tell clipboard incidents from USB ones.
fn clipboard_device() -> DeviceIdentity {
    DeviceIdentity {
        drive_letter: String::new(),
        vendor_id: String::new(),
        product_id: String::new(),
        serial: String::new(),
        product_name: String::new(),
        bus_type: "clipboard".into(),
        removable: false,
    }
}

/// Build the incident (if any) for a scored clipboard item. `label` names the
/// item on the wire (e.g. "(clipboard text)" or a file's basename) — never the
/// content itself.
fn verdict_incident(label: &str, verdict: Verdict, block: bool, channel: &str) -> Option<UsbIncident> {
    let has_match = !verdict.idm.is_empty() || !verdict.edm.is_empty();
    let action = if block { ActionTaken::Blocked } else { ActionTaken::Audited };
    let file_sha256 = verdict.file_sha256.clone();

    if has_match {
        return Some(UsbIncident {
            kind: IncidentKind::Match,
            channel: channel.to_string(),
            file_name: label.to_string(),
            file_sha256,
            verdict: Some(verdict),
            device: clipboard_device(),
            action_taken: action,
            note: Some(if block { "clipboard-blocked" } else { "clipboard-audited" }.into()),
        });
    }

    if matches!(verdict.extraction, detect::Extraction::Unreadable { .. }) {
        return Some(UsbIncident {
            kind: IncidentKind::UnreadableOnRemovable,
            channel: channel.to_string(),
            file_name: label.to_string(),
            file_sha256,
            verdict: Some(verdict),
            device: clipboard_device(),
            action_taken: action,
            note: Some("clipboard-unreadable".into()),
        });
    }

    None
}

/// Metadata-only incident for an uninspectable image copy (spec §1.4 edge 6).
fn image_incident(block: bool, channel: &str) -> UsbIncident {
    UsbIncident {
        kind: IncidentKind::ClipboardImageUninspected,
        channel: channel.to_string(),
        file_name: "(clipboard image)".into(),
        file_sha256: String::new(),
        verdict: None,
        device: clipboard_device(),
        action_taken: if block { ActionTaken::Blocked } else { ActionTaken::Audited },
        note: Some(if block { "image-clipboard-blocked" } else { "image-clipboard-uninspected" }.into()),
    }
}

/// The PURE clipboard decision (spec §1.5): given a parsed payload, the cached
/// bundle (or None), and config, return the block disposition + incidents. No
/// I/O, no Win32 — the tests drive this directly with synthetic payloads.
///
/// * `Text` → `detect::verdict_text`; block on the shared signal.
/// * `Files` → each path via `detect::verdict`; block if any file matches.
/// * `Image` → uninspectable; block iff `block_images`, else audit-only note.
/// * `Uninspected`/empty → no incident.
/// * No bundle cached → "no-policy": nothing to match; block follows `fail_block`
///   (only acted on under `--enforce`).
pub fn inspect(
    payload: &ClipboardPayload,
    bundle: Option<&Bundle>,
    cfg: &ClipboardConfig,
) -> ClipboardDecision {
    let channel = &cfg.channel_label;

    match payload {
        ClipboardPayload::Text(text) => {
            // Size cap: skip huge payloads with no incident (spec §1.4 edge 5).
            if text.len() as u64 > cfg.max_bytes {
                tracing::info!(bytes = text.len(), "clipboard text over max_bytes — skipped");
                return ClipboardDecision::default();
            }
            let Some(bundle) = bundle else {
                // No policy: cannot score. Fail per config (only under enforce).
                return ClipboardDecision { block: cfg.fail_block, incidents: Vec::new() };
            };
            let verdict = detect::verdict_text(text, bundle);
            // The signal decides IF the copy is sensitive; default_action decides
            // what to DO about it. `allow_audited` (default) records the incident
            // but never blocks; `block` clears the clipboard on a signal.
            let signal = verdict_blocks(&verdict, cfg.block_at, cfg.coverage_block_at);
            let block = signal && cfg.default_action == ClipboardAction::Block;
            let mut incidents = Vec::new();
            if let Some(inc) = verdict_incident("(clipboard text)", verdict, block, channel) {
                incidents.push(inc);
            }
            ClipboardDecision { block, incidents }
        }
        ClipboardPayload::Files(paths) => {
            let Some(bundle) = bundle else {
                return ClipboardDecision { block: cfg.fail_block, incidents: Vec::new() };
            };
            let mut incidents = Vec::new();
            let mut block = false;
            for path in paths {
                let label = path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string());
                match detect::verdict(path, bundle) {
                    Ok(v) => {
                        let signal = verdict_blocks(&v, cfg.block_at, cfg.coverage_block_at);
                        let b = signal && cfg.default_action == ClipboardAction::Block;
                        block = block || b;
                        if let Some(inc) = verdict_incident(&label, v, b, channel) {
                            incidents.push(inc);
                        }
                    }
                    Err(e) => {
                        // Could not read a dropped file → fail-secure visibility.
                        tracing::warn!(file = %label, error = %e, "clipboard file verdict failed");
                        block = block || cfg.fail_block;
                        incidents.push(UsbIncident {
                            kind: IncidentKind::UnreadableOnRemovable,
                            channel: channel.to_string(),
                            file_name: label,
                            file_sha256: String::new(),
                            verdict: None,
                            device: clipboard_device(),
                            action_taken: if cfg.fail_block { ActionTaken::Blocked } else { ActionTaken::Audited },
                            note: Some("clipboard-file-unreadable".into()),
                        });
                    }
                }
            }
            ClipboardDecision { block, incidents }
        }
        ClipboardPayload::Image => {
            let block = cfg.block_images;
            ClipboardDecision { block, incidents: vec![image_incident(block, channel)] }
        }
        ClipboardPayload::Uninspected(note) => {
            tracing::debug!(note = %note, "clipboard payload uninspected — no incident");
            ClipboardDecision::default()
        }
    }
}

/// The CA the agent trusts for bundle signatures (mirrors usb/kguard resolve_ca).
fn resolve_ca(cfg: &Config, storage: &Storage) -> Option<Vec<u8>> {
    if storage.has_identity() {
        storage.load_identity().ok().map(|(_, ca)| ca)
    } else {
        std::fs::read(&cfg.ca_cert_path).ok()
    }
}

/// Load + verify the cached index bundle (mirrors usb/kguard). None → no-policy.
fn load_verified_bundle(cfg: &Config, storage: &Storage) -> Option<Bundle> {
    let ca_pem = resolve_ca(cfg, storage)?;
    storage
        .load_index_bundle()
        .and_then(|bytes| Bundle::load(&bytes, &ca_pem).ok())
}

// ---------------------------------------------------------------------------
// Windows: the live monitor (message-only clipboard listener).
// ---------------------------------------------------------------------------
#[cfg(windows)]
pub fn run_monitor<R>(cfg: &Config, storage: &Storage, enforce: bool, mut report: R)
where
    R: FnMut(UsbIncident),
{
    let cb = &cfg.clipboard;
    if !cb.enabled {
        tracing::warn!("clipboard channel disabled in config ([clipboard] enabled=false) — monitor idle");
    }
    let mode = if enforce { enforce::Mode::Live } else { enforce::Mode::DryRun };
    tracing::info!(
        enforce,
        default_action = ?cb.default_action,
        block_images = cb.block_images,
        max_bytes = cb.max_bytes,
        "clipboard monitor starting"
    );

    let bundle = load_verified_bundle(cfg, storage);
    if bundle.is_none() {
        tracing::warn!(
            fail_block = cb.fail_block,
            "no verified index bundle cached — clipboard audit runs in no-policy mode"
        );
    }

    let mut guard = enforce::LoopGuard::new();
    let mut last_seq: u32 = 0;

    // The reaction to each WM_CLIPBOARDUPDATE. Pure decision + report + optional
    // clear; the loop guard suppresses the echo of our own clear.
    let mut on_update = || {
        let seq = watch::sequence_number();
        if seq == last_seq {
            return; // debounce duplicate notifications (spec §1.4 edge 3)
        }
        last_seq = seq;
        if guard.should_ignore(seq) {
            return; // our own clear re-fired the listener (spec §1.4 edge 4)
        }

        let payload = watch::read_snapshot();
        let decision = inspect(&payload, bundle.as_ref(), &cfg.clipboard);
        for inc in decision.incidents {
            report(inc);
        }

        if enforce && cfg.clipboard.enabled && decision.block {
            let plan = enforce::plan(true, Some("Copy blocked by DLP policy".into()));
            match enforce::apply(&plan, mode) {
                Ok(enforce::ApplyOutcome::Executed(_)) => {
                    // Record the new sequence so we ignore our own echo.
                    guard.record_written(watch::sequence_number());
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "clipboard clear failed — degrading to audit"),
            }
        }
    };

    if let Err(e) = watch::run_listener(&mut on_update) {
        tracing::error!(error = %e, "clipboard listener ended with error");
    }
}

// ---------------------------------------------------------------------------
// Non-Windows stub so the crate builds cross-platform (tests, CI).
// ---------------------------------------------------------------------------
#[cfg(not(windows))]
pub fn run_monitor<R>(_cfg: &Config, _storage: &Storage, _enforce: bool, _report: R)
where
    R: FnMut(UsbIncident),
{
    tracing::warn!("clipboard channel is only available on Windows — monitor idle");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{EdmRowHit, EdmSourceHit, Extraction, IdmMatch};

    fn cfg() -> ClipboardConfig {
        ClipboardConfig::default()
    }

    fn matching_verdict() -> Verdict {
        Verdict {
            file_name: String::new(),
            file_sha256: "sha".into(),
            extraction: Extraction::Ok { format: "text".into() },
            idm: vec![IdmMatch {
                version_id: "v".into(),
                document_id: "d".into(),
                collection_id: "c".into(),
                title: "Plan".into(),
                containment: 0.9,
                coverage: 0.9,
                matched_count: 5,
                total_count: 5,
                matched_hashes: vec!["1".into()],
            }],
            edm: vec![],
        }
    }

    #[test]
    fn verdict_blocks_on_containment() {
        assert!(verdict_blocks(&matching_verdict(), 0.30, 0.60));
    }

    #[test]
    fn verdict_blocks_on_edm_row() {
        let mut v = matching_verdict();
        v.idm.clear();
        v.edm.push(EdmSourceHit {
            source_id: "s".into(),
            name: "PII".into(),
            rows_hit: vec![EdmRowHit { row_id: 1, fields: vec!["full_name".into()] }],
        });
        assert!(verdict_blocks(&v, 0.30, 0.60));
    }

    #[test]
    fn clean_verdict_does_not_block() {
        let v = Verdict {
            file_name: String::new(),
            file_sha256: "sha".into(),
            extraction: Extraction::Ok { format: "text".into() },
            idm: vec![],
            edm: vec![],
        };
        assert!(!verdict_blocks(&v, 0.30, 0.60));
    }

    #[test]
    fn image_payload_audits_by_default_blocks_when_configured() {
        // Default: images audited (uninspected), not blocked.
        let d = inspect(&ClipboardPayload::Image, None, &cfg());
        assert!(!d.block);
        assert_eq!(d.incidents.len(), 1);
        assert_eq!(d.incidents[0].kind, IncidentKind::ClipboardImageUninspected);

        // block_images=true → block.
        let mut c = cfg();
        c.block_images = true;
        let d = inspect(&ClipboardPayload::Image, None, &c);
        assert!(d.block);
        assert_eq!(d.incidents[0].action_taken, ActionTaken::Blocked);
    }

    #[test]
    fn no_bundle_text_follows_fail_block() {
        let mut c = cfg();
        c.fail_block = true;
        let d = inspect(&ClipboardPayload::Text("anything".into()), None, &c);
        assert!(d.block, "no-policy + fail_block must block under enforce");
        assert!(d.incidents.is_empty(), "no verdict to report without a bundle");

        c.fail_block = false;
        let d = inspect(&ClipboardPayload::Text("anything".into()), None, &c);
        assert!(!d.block);
    }

    #[test]
    fn oversize_text_is_skipped() {
        let mut c = cfg();
        c.max_bytes = 4;
        let d = inspect(&ClipboardPayload::Text("way too long".into()), None, &c);
        assert!(!d.block);
        assert!(d.incidents.is_empty());
    }

    #[test]
    fn uninspected_payload_yields_nothing() {
        let d = inspect(&ClipboardPayload::Uninspected("odd".into()), None, &cfg());
        assert!(!d.block);
        assert!(d.incidents.is_empty());
    }
}
