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
//! Two detection signals, fused: the cached fingerprint bundle (IDM/EDM) AND the
//! ONNX document classifier. A clipboard copy is an EGRESS path with an async
//! budget — nothing is blocked on our message-only window — so unlike the
//! synchronous kernel read up-call it can afford a forward pass, and it runs one
//! inline (`detect::decide`). The two are OR-ed, never AND-ed: fingerprinting
//! cannot see an unregistered document and the model cannot name which document
//! leaked. Each half answers to its own console action — `[clipboard]
//! default_action` for the fingerprint half, the ML policy's `action` (and, when
//! the model is unavailable, its `failBlock`) for the ML half.
//!
//! NEVER logs clipboard text or file contents (spec §1.3 / DO-NOT): incidents
//! carry only hashes, scores, and metadata — exactly like the USB path. That
//! binds the ML half too: a label id, a score and two counts, never a snippet.

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
///
/// This is now the FINGERPRINT HALF only, and it delegates to `detect::decide` so
/// the band test lives in exactly one place for every channel. The signature is
/// unchanged on purpose — `tests/clipboard_verdict.rs` gates it — and so is the
/// answer it gives; the ML half is fused on top of it in [`inspect`].
pub fn verdict_blocks(v: &Verdict, block_at: f64, coverage_block_at: f64) -> bool {
    detect::decide(v, &detect::Bands::new(block_at, coverage_block_at)).fingerprint
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
    // A model-only hit is a real detection and must raise a real incident —
    // otherwise the one case the classifier exists for (an UNREGISTERED sensitive
    // document) would be blocked with nothing to review.
    let ml_hit = verdict.ml.as_ref().is_some_and(|m| m.is_ok() && m.sensitive);
    let has_match = !verdict.idm.is_empty() || !verdict.edm.is_empty() || ml_hit;
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
            key_id: None,
            sealed_sha256: None,
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
            key_id: None,
            sealed_sha256: None,
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
        key_id: None,
        sealed_sha256: None,
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
                // The classifier is deliberately NOT consulted here either: with
                // no bundle there is no `Verdict` to hang a result on and no
                // incident to raise, and `fail_block` already covers the copy.
                return ClipboardDecision { block: cfg.fail_block, incidents: Vec::new() };
            };
            let mut verdict = detect::verdict_text(text, bundle);
            // The SECOND signal: classify the copied snippet inline. A clipboard
            // copy is an EGRESS path with an async budget (we are on our own
            // message-only window, nothing is blocked on us), so unlike the kernel
            // read up-call it can afford a forward pass. `None` while the console
            // policy is inert, which leaves the verdict byte-identical.
            verdict.ml = detect::decide::ml_for_text(text);
            // The signal decides IF the copy is sensitive; default_action decides
            // what to DO about it. `allow_audited` (default) records the incident
            // but never blocks; `block` clears the clipboard on a signal.
            //
            // FUSION (OR, never AND): a registered document caught by
            // fingerprinting, or an unregistered one the model puts in a class the
            // admin marked. Each covers the other's blind spot; ML can only add.
            let decision = detect::decide(
                &verdict,
                &detect::Bands::new(cfg.block_at, cfg.coverage_block_at),
            );
            // Each half answers to its OWN console action: the fingerprint half to
            // `[clipboard] default_action`, the ML half to the ML policy's
            // `action` (and, when the model is unavailable, to its `failBlock` —
            // honoured here because a copy is egress).
            let block = (decision.fingerprint && cfg.default_action == ClipboardAction::Block)
                || detect::decide::ml_blocks_egress(verdict.ml.as_ref());
            if decision.sensitive {
                // Metadata only — never the copied text.
                tracing::info!(
                    signal = decision.signal.as_deref().unwrap_or(""),
                    severity = decision.severity.map(|s| s.as_str()).unwrap_or(""),
                    block,
                    "clipboard fusion decision"
                );
            }
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
                    Ok(mut v) => {
                        // Same fusion as the text branch, per dropped file.
                        v.ml = detect::decide::ml_for_path(path);
                        let decision = detect::decide(
                            &v,
                            &detect::Bands::new(cfg.block_at, cfg.coverage_block_at),
                        );
                        let b = (decision.fingerprint
                            && cfg.default_action == ClipboardAction::Block)
                            || detect::decide::ml_blocks_egress(v.ml.as_ref());
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
                            key_id: None,
                            sealed_sha256: None,
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

    // Kept current by the watcher: this per-logon helper lives as long as the
    // user's session, so a one-shot load would miss every document registered
    // after logon. None → no-policy mode (per `fail_block`, see `inspect`).
    let live = crate::livebundle::LiveBundle::start(
        storage.dir(),
        &cfg.ca_cert_path,
        "clipboard",
        crate::livebundle::DEFAULT_POLL_INTERVAL,
    );
    if live.current().is_none() {
        tracing::warn!(
            fail_block = cb.fail_block,
            "no verified index bundle yet — clipboard audit runs in no-policy mode until one is downloaded"
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
        let bundle = live.current();
        let decision = inspect(&payload, bundle.as_deref(), &cfg.clipboard);
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
            ml: None,
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
            ml: None,
        };
        assert!(!verdict_blocks(&v, 0.30, 0.60));
    }

    #[test]
    fn ml_only_hit_still_raises_an_incident() {
        // The case the classifier exists for: NOTHING is fingerprinted (no idm,
        // no edm, extraction fine), and the model puts the copied text in a class
        // the admin marked. Without this the copy would be blocked — or audited —
        // with nothing for a reviewer to look at.
        let mut v = matching_verdict();
        v.idm.clear();
        v.ml = Some(crate::detect::MlResult::classified(
            "V6.2.01",
            "NUC",
            "Nuclear & Strategic Systems",
            0.97,
            true,
            1,
            120,
        ));
        let inc = verdict_incident("(clipboard text)", v, true, "clipboard")
            .expect("a model-only hit is a real detection");
        assert_eq!(inc.kind, IncidentKind::Match);
        assert_eq!(inc.action_taken, ActionTaken::Blocked);
        let carried = inc.verdict.expect("the verdict rides along");
        assert_eq!(carried.ml.unwrap().label_id.as_deref(), Some("NUC"));
    }

    #[test]
    fn ml_result_that_the_policy_rejected_raises_nothing() {
        // The model answered, the policy said the label is not sensitive here →
        // exactly as quiet as a clean fingerprint verdict.
        let mut v = matching_verdict();
        v.idm.clear();
        v.ml = Some(crate::detect::MlResult::classified(
            "V6.2.01", "PUB", "Public Information", 1.0, false, 1, 30,
        ));
        assert!(verdict_incident("(clipboard text)", v, false, "clipboard").is_none());
    }

    #[test]
    fn verdict_blocks_is_the_fingerprint_half_of_the_shared_fusion() {
        // The signature is frozen by tests/clipboard_verdict.rs; the answer must
        // stay identical to `detect::decide`'s fingerprint half for the same bands.
        for v in [matching_verdict(), {
            let mut m = matching_verdict();
            m.idm[0].containment = 0.05;
            m.idm[0].coverage = 0.05;
            m
        }] {
            assert_eq!(
                verdict_blocks(&v, 0.30, 0.60),
                detect::decide(&v, &detect::Bands::new(0.30, 0.60)).fingerprint
            );
        }
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
