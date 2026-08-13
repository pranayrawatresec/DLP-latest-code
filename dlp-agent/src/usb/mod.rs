//! User-mode USB removable-media channel (spec §2–§6): device control + copy
//! auditing for the DLP agent's first enforcement channel.
//!
//! This is the **user-mode** layer only. It provides:
//! * device identity + removable classification (`device`),
//! * a pure allow/read-only/block decision engine (`policy`),
//! * arrival/removal detection by polling (`watch`),
//! * dry-run-first enforcement planning (`enforce`),
//! * a settle/dedup/bounded-worker copy auditor reusing `detect::verdict`
//!   (`audit`),
//! * a bounded on-disk incident queue for offline operation (`queue`).
//!
//! True *pre-write blocking* needs a kernel minifilter (spec §9) and is
//! design-only — NOT built here. Audit-mode catches and attributes; it does not
//! guarantee prevention.
//!
//! All Win32 calls are `#[cfg(windows)]`-gated with non-Windows stubs so the
//! pure logic and its tests build and run cross-platform (the golden-vector
//! tests are cross-platform).

pub mod audit;
pub mod device;
pub mod enforce;
pub mod policy;
pub mod queue;
pub mod watch;

pub use audit::{
    scan_and_seal_to_incident, scan_batch, scan_to_incident, seal_file_in_place, ActionTaken,
    CopyAuditor, IncidentKind, SealOutcome, Settled, UsbIncident,
};
pub use device::{parse_storage_descriptor, DeviceIdentity};
pub use enforce::{
    plan, plan_mtp, plan_revert_mtp, plan_revert_read_only, plan_tethering, ApplyOutcome, Mode,
    PlannedAction,
};
pub use policy::{
    classify, decide, decide_full, Action, DeviceClass, DeviceRule, RuleMatch, UsbPolicy,
};
pub use watch::{diff_volumes, VolumeEvent, VolumeWatcher};

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::detect::{self, Bundle, Verdict};
use crate::storage::Storage;
use crate::trustdest::{BlockBandPolicy, EncryptMode};

/// Number of bounded scan workers for bulk copies (spec §3.5: 2–4, never one
/// thread per file).
const SCAN_WORKERS: usize = 4;

/// Seal parameters for a mounted `Action::Encrypt` volume (encrypt-on-write
/// spec §5.1/§5.2): resolved once at arrival from the matching `[[usb.rules]]`
/// entry (mode default `encrypt_sensitive`, key id default from `[crypto]`).
struct EncryptVolume {
    mode: EncryptMode,
    /// FREE-FORM key id — never parsed, only handed to the sealer.
    key_id: String,
    /// Block-band disposition for this destination (default: Block, spec §10;
    /// Seal only when the rule opts in via `on_block_band = "seal"`).
    on_block_band: BlockBandPolicy,
}

/// Per-volume auditor state held while a device is mounted.
struct VolumeAuditor {
    device: DeviceIdentity,
    action: Action,
    auditor: CopyAuditor,
    /// `Some` iff `action == Action::Encrypt` — the copy auditor then routes
    /// settled files through the seal pipeline instead of plain audit.
    encrypt: Option<EncryptVolume>,
}

/// Run the USB monitor loop (spec §3.6). Polls for removable-device
/// arrival/removal, applies policy (dry-run unless `enforce`), and audits files
/// copied to each mounted volume, delivering incidents through the injected
/// `report` sink.
///
/// `report` is injected (rather than posting directly) so the mTLS/queueing
/// concern stays in the binary and the loop remains decoupled from the network
/// — the same separation the check-in loop uses. This function runs its own
/// loop and is independent of the check-in heartbeat (spec §7: do not block or
/// be blocked by check-in).
///
/// `sealer` is the injected seal-in-place fn for `Action::Encrypt` volumes
/// (encrypt-on-write M3): `(path, key_id) → SealOutcome`. The binary wires the
/// real `seal_file_in_place` with the dev keyring (main.rs); on any sealer
/// error the plaintext is kept and an `EnforcementFailed` incident is raised
/// (fail secure — see `scan_and_seal_to_incident`).
pub fn run_monitor<R, S>(cfg: &Config, storage: &Storage, enforce: bool, sealer: S, mut report: R)
where
    R: FnMut(UsbIncident),
    S: Fn(&Path, &str) -> anyhow::Result<audit::SealOutcome>,
{
    let usb = &cfg.usb;
    if !usb.enabled {
        tracing::warn!("usb channel disabled in config ([usb] enabled=false) — monitor idle");
    }
    let policy = usb.to_policy();
    let mode = if enforce { Mode::Live } else { Mode::DryRun };
    tracing::info!(
        enforce,
        default_action = ?policy.default_action,
        rules = policy.rules.len(),
        poll_secs = usb.poll_interval_secs,
        "usb monitor starting"
    );

    // Load the cached, verified bundle once. None → audit logs "no-policy" and
    // scans are skipped; enforce mode still fails secure via the default action.
    let bundle = load_verified_bundle(cfg, storage);
    if bundle.is_none() {
        tracing::warn!("no verified index bundle cached — usb audit runs in no-policy mode");
    }
    let bundle = bundle.map(Arc::new);

    let mut watcher = VolumeWatcher::new();
    let mut auditors: HashMap<String, VolumeAuditor> = HashMap::new();
    // EncryptSensitive verdict bands: encrypt_at from [crypto], block band from
    // [kguard] (one source of truth — the whitelist never weakens blocking).
    let bands = cfg.encrypt_bands();
    let start = Instant::now();
    let poll = Duration::from_secs(usb.poll_interval_secs.max(1));
    let settle_ms = usb.settle_ms;
    let settle_timeout_ms = usb.settle_timeout_secs.saturating_mul(1000);

    loop {
        let now_ms = start.elapsed().as_millis() as u64;

        // 1. Detect arrivals/removals.
        for event in watcher.poll(device::list_removable_volumes()) {
            match event {
                VolumeEvent::Arrived(dev) => {
                    let (action, matched) = decide(&policy, &dev);
                    // Fail-secure: with no bundle, never relax below the default.
                    let action = if bundle.is_none() {
                        action.max_restrictive(policy.default_action)
                    } else {
                        action
                    };
                    tracing::info!(
                        drive = %dev.drive_letter,
                        serial = %dev.serial,
                        bus = %dev.bus_type,
                        ?action,
                        rule = matched.and_then(|r| r.note.clone()).unwrap_or_default(),
                        "removable device arrived"
                    );

                    if enforce && usb.enabled {
                        apply_enforcement(action, &dev, mode, &mut report);
                    }

                    // Start auditing unless the device was hard-blocked (and thus
                    // no longer mounted). Read-only/allow both still audit copies.
                    if action != Action::Block {
                        // Encrypt destination: resolve mode + key id ONCE at
                        // arrival from the matching rule (spec §5.2 — the rule
                        // engine IS the whitelist; key id default from [crypto]).
                        let encrypt = (action == Action::Encrypt).then(|| {
                            let (mode, key_id, on_block_band) = usb.encrypt_params(&dev);
                            EncryptVolume {
                                mode,
                                key_id: key_id
                                    .unwrap_or_else(|| cfg.crypto.default_key_id.clone()),
                                on_block_band,
                            }
                        });
                        let root = format!("{}\\", dev.drive_letter);
                        let mut auditor = CopyAuditor::new(root, settle_ms, settle_timeout_ms);
                        // Encrypt volumes: baseline the files already on the
                        // stick at mount so we seal only what the user copies
                        // AFTER plugging in — never the pre-existing content
                        // (which on a large/full stick would grind serially and
                        // re-seal data that is not this session's exfil). Matches
                        // the block channel's "act on new writes" behaviour.
                        if encrypt.is_some() {
                            let n = auditor.baseline_existing();
                            tracing::info!(
                                drive = %dev.drive_letter,
                                baselined = n,
                                "encrypt volume: pre-existing files baselined; only new copies are sealed"
                            );
                        }
                        auditors.insert(
                            dev.drive_letter.clone(),
                            VolumeAuditor {
                                device: dev.clone(),
                                action,
                                auditor,
                                encrypt,
                            },
                        );
                    }
                }
                VolumeEvent::Removed(letter) => {
                    if auditors.remove(&letter).is_some() {
                        tracing::info!(drive = %letter, "removable device removed — auditor stopped");
                    }
                }
            }
        }

        // 2. Audit settled files on each mounted volume.
        for va in auditors.values_mut() {
            let settled = va.auditor.poll(now_ms);
            if settled.is_empty() {
                continue;
            }
            if let Some(ev) = &va.encrypt {
                // Encrypt destination (M3, spec §5.1): route each settled file
                // through scan → decide_seal → seal-in-place. Processed
                // serially — sealing is I/O-bound on the destination volume
                // and v1 keeps the ordering deterministic. This path runs
                // WITH OR WITHOUT a bundle: no verdict fails secure to Seal
                // (encrypt_all never needed one).
                for s in &settled {
                    let inc = match &bundle {
                        Some(b) => audit::scan_and_seal_to_incident(
                            s,
                            usb.max_file_bytes,
                            &|p: &Path| detect::verdict(p, b),
                            &va.device,
                            &usb.channel_label,
                            ev.mode,
                            &bands,
                            ev.on_block_band,
                            &ev.key_id,
                            &sealer,
                        ),
                        None => audit::scan_and_seal_to_incident(
                            s,
                            usb.max_file_bytes,
                            &|_p: &Path| -> anyhow::Result<Verdict> {
                                anyhow::bail!("no verified bundle cached")
                            },
                            &va.device,
                            &usb.channel_label,
                            ev.mode,
                            &bands,
                            ev.on_block_band,
                            &ev.key_id,
                            &sealer,
                        ),
                    };
                    if let Some(inc) = inc {
                        report(inc);
                    }
                }
            } else if let Some(bundle) = &bundle {
                let bundle = Arc::clone(bundle);
                let incidents = scan_batch(
                    settled,
                    SCAN_WORKERS,
                    usb.max_file_bytes,
                    move |p| detect::verdict(p, &bundle),
                    va.device.clone(),
                    ActionTaken::from(va.action),
                    usb.channel_label.clone(),
                );
                for inc in incidents {
                    report(inc);
                }
            }
            // No-policy mode on a non-encrypt volume: the poll above already
            // drained the settle state; nothing to match against, no scan.
        }

        std::thread::sleep(poll);
    }
}

/// Apply an enforcement action, converting failure into an "enforcement-failed"
/// incident rather than crashing the monitor (spec §3.4).
fn apply_enforcement<R>(action: Action, dev: &DeviceIdentity, mode: Mode, report: &mut R)
where
    R: FnMut(UsbIncident),
{
    let planned = enforce::plan(action, dev);
    match enforce::apply(&planned, mode) {
        Ok(outcome) => tracing::info!(drive = %dev.drive_letter, ?outcome, "enforcement applied"),
        Err(e) => {
            tracing::warn!(drive = %dev.drive_letter, error = %e, "enforcement failed — degrading to audit");
            report(UsbIncident {
                kind: IncidentKind::EnforcementFailed,
                channel: "usb".into(),
                file_name: String::new(),
                file_sha256: String::new(),
                verdict: None,
                device: dev.clone(),
                action_taken: ActionTaken::from(action),
                note: Some(format!("enforcement-failed: {e}")),
                key_id: None,
                sealed_sha256: None,
            });
        }
    }
}

/// Load and verify the cached index bundle with the pinned CA (spec §3.6 step
/// 1). A load failure means "keep no bundle" → no-policy mode (fail closed:
/// nothing is trusted that hasn't verified).
fn load_verified_bundle(cfg: &Config, storage: &Storage) -> Option<Bundle> {
    let ca_pem = resolve_ca(cfg, storage)?;
    storage
        .load_index_bundle()
        .and_then(|bytes| Bundle::load(&bytes, &ca_pem).ok())
}

/// The CA the agent trusts for bundle signatures: pinned-at-enrollment when
/// enrolled, else the installer-provisioned CA file (mirrors main.rs::load_ca).
fn resolve_ca(cfg: &Config, storage: &Storage) -> Option<Vec<u8>> {
    if storage.has_identity() {
        storage.load_identity().ok().map(|(_, ca)| ca)
    } else {
        std::fs::read(&cfg.ca_cert_path).ok()
    }
}
