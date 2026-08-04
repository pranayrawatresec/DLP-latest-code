//! User-mode port client for the DLP filesystem minifilter (`dlpflt.sys`).
//!
//! This is the process the kernel driver talks to over the filter communication
//! port `\DlpFltPort` (SPEC §3). The flow, per message:
//!
//! 1. `FilterGetMessage` blocks until the driver hands us a scan request
//!    (path + metadata only — never file contents).
//! 2. We open and score the file with the existing, frozen `detect::verdict()`
//!    against the cached, signature-verified index bundle.
//! 3. We apply configurable policy thresholds (SPEC §3): BLOCK if any matched
//!    document's `containment >= block_at`, or `coverage >= coverage_block_at`,
//!    or any EDM row hit.
//! 4. `FilterReplyMessage` returns `{allow|block}` to the driver, which
//!    quarantines on BLOCK.
//! 5. On a match we raise an incident, reusing the exact mTLS/offline-queue path
//!    the `usb` channel already uses (a `UsbIncident` through the injected sink).
//!
//! **Skip-self:** the driver records THIS process's PID at connect and passes
//! its own I/O through untouched (SPEC §2.4). `usb-guard` must therefore be the
//! process that connects — do not proxy the connection through another process.
//!
//! **Verification boundary:** this module COMPILES and is analyzed here. End to
//! end it needs the loaded driver, which requires test-signing + reboot on a
//! test machine — that is the operator's manual test (SPEC §8). Nothing here
//! claims runtime behavior as verified.
//!
//! The wire structs mirror `dlp-minifilter/src/dlpflt.h` byte-for-byte via
//! `#[repr(C)]`; keep them in sync and bump `DLP_MSG_VERSION` on any change.

use crate::config::{Config, KguardConfig};
use crate::detect::{self, Bundle, Verdict};
use crate::storage::Storage;
use crate::usb::{ActionTaken, DeviceIdentity, IncidentKind, UsbIncident};

use anyhow::Result;

/// Wire protocol version — must equal `DLP_MSG_VERSION` in `dlpflt.h`.
pub const DLP_MSG_VERSION: u32 = 1;
/// Max path chars carried inline — must equal `DLP_MAX_PATH_CHARS` in `dlpflt.h`.
pub const DLP_MAX_PATH_CHARS: usize = 512;
/// Verdict codes — must equal `DLP_VERDICT_*` in `dlpflt.h`.
pub const DLP_VERDICT_ALLOW: u32 = 0;
pub const DLP_VERDICT_BLOCK: u32 = 1;

/// `#[repr(C)]` mirror of `DLP_SCAN_REQUEST` (dlpflt.h, `#pragma pack(8)`).
/// Field order + natural x64 alignment reproduce the C layout exactly
/// (Path at offset 22, total size 1048).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DlpScanRequest {
    pub version: u32,
    pub reserved: u32,
    pub file_id: u64,
    pub process_id: u32,
    pub path_length: u16, // bytes valid in `path`
    pub path: [u16; DLP_MAX_PATH_CHARS],
}

/// `#[repr(C)]` mirror of `DLP_SCAN_REPLY` (dlpflt.h).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DlpScanReply {
    pub file_id: u64,
    pub verdict: u32,
}

// Lock the wire layout to the C header (dlpflt.h, #pragma pack(8)). If either
// side drifts, this fails to compile rather than silently misparsing messages.
//   DLP_SCAN_REQUEST: 4+4+8+4+2 + 512*2, aligned to 8  = 1048 bytes
//   DLP_SCAN_REPLY:   8+4, aligned to 8                = 16 bytes
const _: () = {
    assert!(core::mem::size_of::<DlpScanRequest>() == 1048);
    assert!(core::mem::align_of::<DlpScanRequest>() == 8);
    assert!(core::mem::size_of::<DlpScanReply>() == 16);
    assert!(core::mem::align_of::<DlpScanReply>() == 8);
};

/// Config version — must equal `DLP_CONFIG.Version` the driver validates.
pub const DLP_CONFIG_VERSION: u32 = 1;
/// Max watch prefixes carried — must equal the `Watch[16][260]` bound in dlpflt.h.
pub const DLP_MAX_WATCH: usize = 16;
/// Max wchar length of one watch prefix — must equal the `260` in dlpflt.h.
pub const DLP_MAX_WATCH_CHARS: usize = 260;

/// `#[repr(C)]` mirror of `DLP_CONFIG` (dlpflt.h, `#pragma pack(8)`). The
/// user-mode `usb-guard` sends this to the driver once at connect
/// (`FilterSendMessage`); the driver's `MessageNotifyCallback` stores it in a
/// filter-global and switches its attach/inspect scope accordingly. An empty
/// watch-set (`watch_count == 0`, `scan_fixed == 0`) means removable-only —
/// the backward-compatible default (spec §3.0).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DlpConfig {
    pub version: u32,
    pub scan_fixed: u32,
    pub scan_network: u32,
    pub watch_count: u32,
    pub watch_len: [u16; DLP_MAX_WATCH],
    pub watch: [[u16; DLP_MAX_WATCH_CHARS]; DLP_MAX_WATCH],
}

// Lock the DLP_CONFIG layout to the C header. Header 4*4=16, WatchLen[16]=32
// (offset 16..48), Watch[16][260] wchar = 16*260*2 = 8320 (offset 48..8368).
//   total = 8368 bytes.
const _: () = {
    assert!(core::mem::size_of::<DlpConfig>() == 8368);
};

impl DlpConfig {
    /// Build the config message from the kguard watch-set (spec §3.0). Prefixes
    /// beyond `DLP_MAX_WATCH` are dropped; each is truncated to
    /// `DLP_MAX_WATCH_CHARS` wchars. Pure — no I/O — so it is unit-tested. An
    /// empty `watch_paths` yields `watch_count == 0` (removable-only).
    pub fn from_kguard(kg: &KguardConfig) -> DlpConfig {
        let mut cfg = DlpConfig {
            version: DLP_CONFIG_VERSION,
            scan_fixed: u32::from(kg.scan_fixed),
            scan_network: u32::from(kg.scan_network),
            watch_count: 0,
            watch_len: [0u16; DLP_MAX_WATCH],
            watch: [[0u16; DLP_MAX_WATCH_CHARS]; DLP_MAX_WATCH],
        };
        for (i, prefix) in kg.watch_paths.iter().take(DLP_MAX_WATCH).enumerate() {
            let units: Vec<u16> = prefix.encode_utf16().take(DLP_MAX_WATCH_CHARS).collect();
            cfg.watch_len[i] = units.len() as u16;
            cfg.watch[i][..units.len()].copy_from_slice(&units);
            cfg.watch_count += 1;
        }
        cfg
    }
}

/// Pure block decision (SPEC §3), unit-tested below without any I/O.
/// BLOCK if any EDM row hit, or any matched document reaches the containment or
/// coverage threshold.
pub fn should_block(v: &Verdict, cfg: &KguardConfig) -> bool {
    if !v.edm.is_empty() {
        return true;
    }
    v.idm
        .iter()
        .any(|m| m.containment >= cfg.block_at || m.coverage >= cfg.coverage_block_at)
}

/// The CA the agent trusts for bundle signatures: pinned-at-enrollment when
/// enrolled, else the installer-provisioned CA file (mirrors main.rs::load_ca /
/// usb::resolve_ca).
fn resolve_ca(cfg: &Config, storage: &Storage) -> Option<Vec<u8>> {
    if storage.has_identity() {
        storage.load_identity().ok().map(|(_, ca)| ca)
    } else {
        std::fs::read(&cfg.ca_cert_path).ok()
    }
}

/// Load + verify the cached index bundle. A load/verify failure means "no
/// bundle" → the guard answers per `fail_block` (fail-secure knob).
fn load_verified_bundle(cfg: &Config, storage: &Storage) -> Option<Bundle> {
    let ca_pem = resolve_ca(cfg, storage)?;
    storage
        .load_index_bundle()
        .and_then(|bytes| Bundle::load(&bytes, &ca_pem).ok())
}

/// Best-effort drive letter from an NT device path. The driver sends a
/// normalized name like `\Device\HarddiskVolume3\dir\file.txt`, which has no
/// drive letter; we leave it empty in that case. Only a genuine `X:\...` yields
/// a letter. Never panics.
fn drive_letter_of(path: &str) -> String {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return format!("{}:", (bytes[0] as char).to_ascii_uppercase());
    }
    String::new()
}

/// Synthesize a minimal removable `DeviceIdentity` for a kguard incident. The
/// driver only gives us a path; other fields are best-effort/empty (SPEC digest
/// §5). Marked removable because the driver attaches to removable volumes only.
fn synthetic_device(path: &str) -> DeviceIdentity {
    DeviceIdentity {
        drive_letter: drive_letter_of(path),
        vendor_id: String::new(),
        product_id: String::new(),
        serial: String::new(),
        product_name: String::new(),
        bus_type: "usb".into(),
        removable: true,
    }
}

/// Build the incident for a scored file, if any is warranted:
/// * BLOCK (match past threshold) → `Match`, action `Blocked`.
/// * an unreadable file on removable media → `UnreadableOnRemovable` (fail-safe
///   visibility), action per `blocked`.
/// * innocent, readable, below threshold → `None`.
fn incident_for(
    display_path: &str,
    verdict: Verdict,
    blocked: bool,
    channel: &str,
) -> Option<UsbIncident> {
    let device = synthetic_device(display_path);
    let action = if blocked { ActionTaken::Blocked } else { ActionTaken::Audited };

    if blocked {
        return Some(UsbIncident {
            kind: IncidentKind::Match,
            channel: channel.to_string(),
            file_name: verdict.file_name.clone(),
            file_sha256: verdict.file_sha256.clone(),
            verdict: Some(verdict),
            device,
            action_taken: action,
            note: Some("kernel-blocked".into()),
        });
    }

    if matches!(verdict.extraction, detect::Extraction::Unreadable { .. }) {
        return Some(UsbIncident {
            kind: IncidentKind::UnreadableOnRemovable,
            channel: channel.to_string(),
            file_name: verdict.file_name.clone(),
            file_sha256: verdict.file_sha256.clone(),
            verdict: Some(verdict),
            device,
            action_taken: action,
            note: Some("unreadable-on-removable".into()),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// Windows: the live port client.
// ---------------------------------------------------------------------------
#[cfg(windows)]
pub fn run<R>(cfg: &Config, storage: &Storage, mut report: R) -> Result<()>
where
    R: FnMut(UsbIncident),
{
    use anyhow::Context;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::InstallableFileSystems::FilterConnectCommunicationPort;

    let kg = &cfg.kguard;

    // Load the verified bundle once. None → answer per fail_block until a
    // bundle is present (fail-secure knob, SPEC §3).
    let bundle = load_verified_bundle(cfg, storage);
    if bundle.is_none() {
        tracing::warn!(
            fail_block = kg.fail_block,
            "no verified index bundle cached — kguard answers per fail_block until one is loaded"
        );
    }

    // Connect to \DlpFltPort. Failure here almost always means the driver is
    // not loaded (operator manual step, SPEC §8).
    let port_name: Vec<u16> = "\\DlpFltPort".encode_utf16().chain(std::iter::once(0)).collect();
    let port: HANDLE = unsafe {
        FilterConnectCommunicationPort(PCWSTR(port_name.as_ptr()), 0, None, 0, None)
    }
    .context("FilterConnectCommunicationPort(\\DlpFltPort) failed — is dlpflt.sys loaded?")?;

    tracing::info!("connected to \\DlpFltPort — this PID is the driver's skip-self identity");

    // Send the watch-set config (spec §3.0) so the driver knows whether to
    // inspect fixed/network volumes and which path prefixes to watch. An empty
    // watch-set leaves the driver in removable-only mode (backward compatible).
    send_config(port, &cfg.kguard);

    let _ = storage; // identity/CA already consumed above; kept for symmetry
    let result = message_loop(port, cfg, bundle.as_ref(), &mut report);

    unsafe {
        let _ = CloseHandle(port);
    }
    result
}

/// Send the `DLP_CONFIG` watch-set to the driver (spec §3.0). Best-effort: a
/// failure is logged, not fatal — the driver keeps its current (removable-only)
/// scope. The message is one-shot at connect; the driver's `MessageNotifyCallback`
/// validates `Version`/size and stores it in a filter-global.
#[cfg(windows)]
fn send_config(port: windows::Win32::Foundation::HANDLE, kg: &KguardConfig) {
    use std::mem::size_of;
    use windows::Win32::Storage::InstallableFileSystems::FilterSendMessage;

    let cfg = DlpConfig::from_kguard(kg);
    let rc = unsafe {
        FilterSendMessage(
            port,
            &cfg as *const DlpConfig as *const core::ffi::c_void,
            size_of::<DlpConfig>() as u32,
            None,
            0,
            &mut 0u32,
        )
    };
    match rc {
        Ok(()) => tracing::info!(
            scan_fixed = kg.scan_fixed,
            scan_network = kg.scan_network,
            watch_count = cfg.watch_count,
            "sent DLP_CONFIG watch-set to driver"
        ),
        Err(e) => tracing::warn!(error = %e, "FilterSendMessage(DLP_CONFIG) failed — driver keeps removable-only scope"),
    }
}

/// The blocking receive/score/reply loop. Split out so the connect/close
/// bracket stays tidy. Returns Ok when the port closes cleanly.
#[cfg(windows)]
fn message_loop<R>(
    port: windows::Win32::Foundation::HANDLE,
    cfg: &Config,
    bundle: Option<&Bundle>,
    report: &mut R,
) -> Result<()>
where
    R: FnMut(UsbIncident),
{
    use std::mem::size_of;
    use windows::Win32::Storage::InstallableFileSystems::{
        FilterGetMessage, FilterReplyMessage, FILTER_MESSAGE_HEADER, FILTER_REPLY_HEADER,
    };

    #[repr(C)]
    struct RequestMessage {
        header: FILTER_MESSAGE_HEADER,
        req: DlpScanRequest,
    }
    #[repr(C)]
    struct ReplyMessage {
        header: FILTER_REPLY_HEADER,
        reply: DlpScanReply,
    }

    let kg = &cfg.kguard;

    loop {
        // Zeroed buffer each iteration; FilterGetMessage fills header + payload.
        let mut msg: RequestMessage = unsafe { std::mem::zeroed() };
        let recv = unsafe {
            FilterGetMessage(
                port,
                &mut msg.header,
                size_of::<RequestMessage>() as u32,
                None,
            )
        };
        if let Err(e) = recv {
            // Port closed (driver unloaded) or a transient error: stop the loop
            // and let the caller decide whether to reconnect.
            tracing::warn!(error = %e, "FilterGetMessage returned error — ending kguard loop");
            return Ok(());
        }

        let req = &msg.req;
        let message_id = msg.header.MessageId;

        // Decode the inline path (bytes → UTF-16 units), bounded.
        let nchars = (req.path_length as usize / 2).min(DLP_MAX_PATH_CHARS);
        let device_path = String::from_utf16_lossy(&req.path[..nchars]);

        // Guard the wire version: a mismatch means driver/client are out of sync
        // — fail-safe per fail_block rather than misparse the payload.
        let (block, incident) = if req.version != DLP_MSG_VERSION {
            tracing::warn!(
                got = req.version,
                expected = DLP_MSG_VERSION,
                "scan request wire-version mismatch — applying fail_block"
            );
            (kg.fail_block, None)
        } else {
            // Score the file, or fall back to the configured fail behavior.
            decide(cfg, kg, bundle, &device_path)
        };

        // Reply to the driver.
        let mut out: ReplyMessage = unsafe { std::mem::zeroed() };
        out.header.MessageId = message_id;
        out.header.Status = windows::Win32::Foundation::NTSTATUS(0); // STATUS_SUCCESS
        out.reply.file_id = req.file_id;
        out.reply.verdict = if block { DLP_VERDICT_BLOCK } else { DLP_VERDICT_ALLOW };

        let sent = unsafe {
            FilterReplyMessage(port, &out.header, size_of::<ReplyMessage>() as u32)
        };
        if let Err(e) = sent {
            tracing::warn!(error = %e, "FilterReplyMessage failed — the driver will apply FailMode");
        }

        // Raise the incident (if any) AFTER replying, so a slow network sink
        // never delays the kernel's file-close path.
        if let Some(inc) = incident {
            report(inc);
        }
    }
}

/// Compute the block decision + optional incident for one requested path. Shared
/// shape so it can be reasoned about independently of the Win32 loop. On any
/// verdict error (unreadable device path, I/O failure) we honor `fail_block`.
#[cfg(windows)]
fn decide(
    _cfg: &Config,
    kg: &KguardConfig,
    bundle: Option<&Bundle>,
    device_path: &str,
) -> (bool, Option<UsbIncident>) {
    // Translate the NT device path so Win32/std can open it. \\?\GLOBALROOT
    // prefixes an NT object path; a genuine DOS path is used as-is.
    let open_path = if device_path.starts_with("\\Device\\") || device_path.starts_with("\\?\\") {
        format!("\\\\?\\GLOBALROOT{device_path}")
    } else {
        device_path.to_string()
    };

    let bundle = match bundle {
        Some(b) => b,
        None => {
            // No verified bundle: cannot score. Fail per configuration.
            return (kg.fail_block, None);
        }
    };

    match detect::verdict(std::path::Path::new(&open_path), bundle) {
        Ok(v) => {
            let block = should_block(&v, kg);
            let inc = incident_for(device_path, v, block, &kg.channel_label);
            (block, inc)
        }
        Err(e) => {
            // I/O error producing a verdict — fail per configuration and note it.
            tracing::warn!(path = %device_path, error = %e, "verdict failed — applying fail_block");
            (kg.fail_block, None)
        }
    }
}

// ---------------------------------------------------------------------------
// Non-Windows stub so the crate still builds cross-platform (tests, CI).
// ---------------------------------------------------------------------------
#[cfg(not(windows))]
pub fn run<R>(_cfg: &Config, _storage: &Storage, _report: R) -> Result<()>
where
    R: FnMut(UsbIncident),
{
    anyhow::bail!("usb-guard (kernel minifilter port client) is only available on Windows")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{Extraction, IdmMatch};

    fn verdict_with(containment: f64, coverage: f64) -> Verdict {
        Verdict {
            file_name: "f.txt".into(),
            file_sha256: "sha".into(),
            extraction: Extraction::Ok { format: "text".into() },
            idm: vec![IdmMatch {
                version_id: "v".into(),
                document_id: "d".into(),
                collection_id: "c".into(),
                title: "t".into(),
                containment,
                coverage,
                matched_count: 1,
                total_count: 1,
                matched_hashes: vec!["1".into()],
            }],
            edm: vec![],
        }
    }

    fn clean_verdict() -> Verdict {
        Verdict {
            file_name: "f.txt".into(),
            file_sha256: "sha".into(),
            extraction: Extraction::Ok { format: "text".into() },
            idm: vec![],
            edm: vec![],
        }
    }

    #[test]
    fn blocks_on_containment_threshold() {
        let cfg = KguardConfig::default(); // block_at 0.30
        assert!(should_block(&verdict_with(0.30, 0.0), &cfg));
        assert!(should_block(&verdict_with(0.95, 0.0), &cfg));
        assert!(!should_block(&verdict_with(0.29, 0.0), &cfg));
    }

    #[test]
    fn blocks_on_coverage_threshold() {
        let cfg = KguardConfig::default(); // coverage_block_at 0.60
        assert!(should_block(&verdict_with(0.0, 0.60), &cfg));
        assert!(!should_block(&verdict_with(0.0, 0.59), &cfg));
    }

    #[test]
    fn blocks_on_any_edm_row_hit() {
        let cfg = KguardConfig::default();
        let mut v = clean_verdict();
        v.edm.push(crate::detect::EdmSourceHit {
            source_id: "s".into(),
            name: "PII".into(),
            rows_hit: vec![crate::detect::EdmRowHit { row_id: 1, fields: vec!["x".into()] }],
        });
        assert!(should_block(&v, &cfg));
    }

    #[test]
    fn allows_clean_file() {
        let cfg = KguardConfig::default();
        assert!(!should_block(&clean_verdict(), &cfg));
    }

    #[test]
    fn drive_letter_parsing() {
        assert_eq!(drive_letter_of("E:\\dir\\f.txt"), "E:");
        assert_eq!(drive_letter_of("e:\\f"), "E:");
        assert_eq!(drive_letter_of("\\Device\\HarddiskVolume3\\f.txt"), "");
    }

    #[test]
    fn incident_for_block_is_match_blocked() {
        let inc = incident_for("E:\\x.docx", verdict_with(1.0, 1.0), true, "usb-kguard")
            .expect("a block must raise an incident");
        assert_eq!(inc.kind, IncidentKind::Match);
        assert_eq!(inc.action_taken, ActionTaken::Blocked);
        assert_eq!(inc.device.drive_letter, "E:");
        assert!(inc.verdict.is_some());
    }

    #[test]
    fn incident_for_clean_allow_is_none() {
        assert!(incident_for("E:\\ok.txt", clean_verdict(), false, "usb-kguard").is_none());
    }

    // --- DLP_CONFIG watch-set builder (spec §3.0) --------------------------

    #[test]
    fn empty_watch_set_is_removable_only() {
        // Back-compat invariant: default kguard config ⇒ no fixed/network scan,
        // no watch prefixes. The driver stays removable-only.
        let kg = KguardConfig::default();
        let cfg = DlpConfig::from_kguard(&kg);
        assert_eq!(cfg.version, DLP_CONFIG_VERSION);
        assert_eq!(cfg.scan_fixed, 0);
        assert_eq!(cfg.scan_network, 0);
        assert_eq!(cfg.watch_count, 0);
        assert!(cfg.watch_len.iter().all(|&l| l == 0));
    }

    #[test]
    fn watch_paths_are_encoded_utf16_with_lengths() {
        let mut kg = KguardConfig::default();
        kg.scan_fixed = true;
        kg.scan_network = true;
        kg.watch_paths = vec![r"\Users\alice\OneDrive".into(), r"\Dropbox".into()];
        let cfg = DlpConfig::from_kguard(&kg);
        assert_eq!(cfg.scan_fixed, 1);
        assert_eq!(cfg.scan_network, 1);
        assert_eq!(cfg.watch_count, 2);
        assert_eq!(cfg.watch_len[0] as usize, r"\Users\alice\OneDrive".encode_utf16().count());
        assert_eq!(cfg.watch_len[1] as usize, r"\Dropbox".encode_utf16().count());
        // First prefix reproduces exactly in the wide buffer.
        let n = cfg.watch_len[0] as usize;
        let round: String = String::from_utf16_lossy(&cfg.watch[0][..n]);
        assert_eq!(round, r"\Users\alice\OneDrive");
    }

    #[test]
    fn watch_set_is_capped_at_sixteen() {
        let mut kg = KguardConfig::default();
        kg.watch_paths = (0..40).map(|i| format!(r"\dir{i}")).collect();
        let cfg = DlpConfig::from_kguard(&kg);
        assert_eq!(cfg.watch_count as usize, DLP_MAX_WATCH);
    }

    #[test]
    fn overlong_prefix_is_truncated() {
        let mut kg = KguardConfig::default();
        kg.watch_paths = vec!["A".repeat(400)];
        let cfg = DlpConfig::from_kguard(&kg);
        assert_eq!(cfg.watch_len[0] as usize, DLP_MAX_WATCH_CHARS);
    }
}
