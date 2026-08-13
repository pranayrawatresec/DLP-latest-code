//! User-mode port client for the DLP filesystem minifilter (`dlpflt.sys`).
//!
//! This is the process the kernel driver talks to over the filter communication
//! port `\DlpFltPort` (SPEC §3). The flow, per message:
//!
//! 1. `FilterGetMessage` blocks until the driver hands us a scan request. As of
//!    wire protocol v2 the driver reads the file IN-KERNEL (it is inside the FS
//!    stack, so no sharing conflict with a process holding the file locked) and
//!    ships the first up-to-4-MiB of content inline after the fixed header. We
//!    NEVER re-open the file in user mode.
//! 2. We score those bytes with `detect::verdict_bytes()` against the cached,
//!    signature-verified index bundle. Content is used only for the fingerprint
//!    math and is NEVER logged.
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
//! **Coexistence with the user-mode sealer (`usb-monitor`):** the monitor runs
//! as a DIFFERENT PID, so its writes are NOT skip-self and the guard scans
//! them. Two user-mode accommodations make the pair safe together (the driver
//! and wire protocol are untouched — `DLP_MSG_VERSION` stays 2):
//! * `.dlpenc` envelopes (the `DLPE` magic, `crypto::envelope::MAGIC`) pass
//!   through unscanned on BOTH scan reasons — an envelope is already the
//!   strongest protected state; scanning ciphertext is noise, and quarantining
//!   the sealer's own output would undo the seal.
//! * WRITE scans headed to a whitelisted `action = "encrypt"` device stand
//!   aside per `trustdest::decide_seal` (only while `[usb] enabled = true` —
//!   with the monitor off nobody would seal, so the guard behaves exactly as
//!   before). Read-taint semantics are unchanged in every case.
//!
//! **Verification boundary:** this module COMPILES and is analyzed here. End to
//! end it needs the loaded driver, which requires test-signing + reboot on a
//! test machine — that is the operator's manual test (SPEC §8). Nothing here
//! claims runtime behavior as verified.
//!
//! The wire structs mirror `dlp-minifilter/src/dlpflt.h` byte-for-byte via
//! `#[repr(C)]`; keep them in sync and bump `DLP_MSG_VERSION` on any change.

use crate::config::{Config, KguardConfig, UsbConfig};
use crate::crypto::envelope::MAGIC as DLPENC_MAGIC;
use crate::detect::{self, Bundle, Verdict};
use crate::storage::Storage;
use crate::trustdest::{decide_seal, EncryptBands, SealDecision};
use crate::usb::{Action, ActionTaken, DeviceIdentity, IncidentKind, UsbIncident};

use anyhow::Result;

/// Wire protocol version — must equal `DLP_MSG_VERSION` in `dlpflt.h`.
/// v2 = content-over-port: the fixed header is followed by `content_length`
/// bytes of file content in the same message buffer.
pub const DLP_MSG_VERSION: u32 = 2;
/// Max path chars carried inline — must equal `DLP_MAX_PATH_CHARS` in `dlpflt.h`.
pub const DLP_MAX_PATH_CHARS: usize = 512;
/// Max bytes of file content that follow the header — must equal
/// `DLP_MAX_CONTENT` in `dlpflt.h` (4 MiB cap). Larger files are truncated to
/// this by the driver, which sets `truncated = 1`.
pub const DLP_MAX_CONTENT: usize = 4 * 1024 * 1024;
/// Verdict codes — must equal `DLP_VERDICT_*` in `dlpflt.h`.
pub const DLP_VERDICT_ALLOW: u32 = 0;
pub const DLP_VERDICT_BLOCK: u32 = 1;

/// Scan reason — must equal `DLP_REASON_*` in `dlpflt.h`. This REPURPOSES the
/// formerly-unused `ULONG Reserved` at offset 4 of `DLP_SCAN_REQUEST`: no wire
/// size change (still 1056 bytes), the byte-locked mirror is preserved. The
/// driver stamps `request->Reserved = Reason` in `DlpQueryVerdict` (comms.c).
///
/// * `WRITE` (0) — legacy write/quarantine scan. This is the OLD `Reserved`
///   value, so an old driver (which zeroed `Reserved`) is read as a write scan:
///   backward compatible in both directions (LLD §6).
/// * `READ` (1) — read-taint scan: on BLOCK the driver taints the process and we
///   additionally reset that PID's live TCP egress (close the in-flight socket
///   the steady-state WFP callout can't retroactively catch).
pub const DLP_REASON_WRITE: u32 = 0;
pub const DLP_REASON_READ: u32 = 1;

/// `#[repr(C)]` mirror of `DLP_SCAN_REQUEST` (dlpflt.h, `#pragma pack(8)`).
/// Field order + natural x64 alignment reproduce the C layout exactly
/// (Path at offset 24, total size 1056). The fixed header is followed in the
/// message buffer by `content_length` bytes of file content.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DlpScanRequest {
    pub version: u32,
    /// Scan reason (`DLP_REASON_*`). Byte-identical to the former `Reserved`
    /// field (same offset 4, same size) — renamed only, so the `size_of == 1056`
    /// / `align == 8` asserts below are untouched (LLD §6, §9.1).
    pub reason: u32,
    pub file_id: u64,
    pub process_id: u32,
    pub path_length: u16, // bytes valid in `path`
    pub pad: u16,         // alignment to match the C `USHORT Pad`
    pub path: [u16; DLP_MAX_PATH_CHARS], // NT device path (logging/incident only)
    pub content_length: u32, // bytes of content that FOLLOW this header (<= DLP_MAX_CONTENT)
    pub truncated: u32,      // 1 if the file was larger than the cap
}

/// `#[repr(C)]` mirror of `DLP_SCAN_REPLY` (dlpflt.h). Unchanged in v2.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DlpScanReply {
    pub file_id: u64,
    pub verdict: u32,
}

// Lock the wire layout to the C header (dlpflt.h, #pragma pack(8)). If either
// side drifts, this fails to compile rather than silently misparsing messages.
//   DLP_SCAN_REQUEST: 4+4+8+4+2+2 (=24) + 512*2 (=1024, ends at 1048)
//                     + 4 (ContentLength) + 4 (Truncated), aligned to 8 = 1056
//   DLP_SCAN_REPLY:   8+4, aligned to 8                                = 16
const _: () = {
    assert!(core::mem::size_of::<DlpScanRequest>() == 1056);
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

/// Human label for a scan reason, for structured logs. An unrecognised value
/// (a newer driver) is reported as `unknown` rather than misattributed — the
/// verdict path still runs, only the taint side-effect is gated on READ.
fn reason_label(reason: u32) -> &'static str {
    match reason {
        DLP_REASON_WRITE => "write",
        DLP_REASON_READ => "read-taint",
        _ => "unknown",
    }
}

/// The incident note for a kernel BLOCK, chosen by scan reason (pure, tested).
/// A read-taint scan (`DLP_REASON_READ`) that blocks is labelled `read-taint`
/// so a reviewer can tell "this file's reader was tainted, its egress cut" from
/// the legacy write/quarantine block, which keeps its `kernel-blocked` note.
fn block_note(reason: u32) -> &'static str {
    if reason == DLP_REASON_READ {
        "read-taint"
    } else {
        "kernel-blocked"
    }
}

/// Whether this scan verdict warrants tearing down the requestor PID's live TCP
/// egress: ONLY a read-taint scan (`DLP_REASON_READ`) that BLOCKED. A write scan
/// never resets connections (there is no tainted long-lived socket to close);
/// a clean read never resets. Pure — the Windows reset itself
/// (`netfilter::reset_pid_connections`) is operator-manual and not unit-tested.
pub fn should_reset_connections(reason: u32, blocked: bool) -> bool {
    reason == DLP_REASON_READ && blocked
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
    reason: u32,
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
            // `read-taint` for a read-scan block, `kernel-blocked` for a write.
            note: Some(block_note(reason).into()),
            key_id: None,
            sealed_sha256: None,
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
            key_id: None,
            sealed_sha256: None,
        });
    }

    None
}

/// PURE first gate of `decide()` (sealer-coexistence defect 1): `.dlpenc`
/// envelope passthrough. Content beginning with the envelope magic (`DLPE`,
/// reused from `crypto::envelope::MAGIC` — never duplicated as a literal) is
/// ALLOWED with no incident: an envelope is already the strongest protected
/// state a file can be in, so scanning its ciphertext is pure noise —
/// extraction reads it as `Unreadable`, and under `[kguard] fail_block = true`
/// the kernel would quarantine the very envelope the `usb-monitor` sealer (a
/// DIFFERENT PID than this guard, so NOT skip-self in the driver) just wrote.
///
/// Reason-INdependent by design, hence the deliberately unused `_reason`: a
/// write of an envelope must not be quarantined (it is the sealer's own
/// output) and a read of one must not taint the reader. Applies on every
/// volume. Returns the guard decision when the content is an envelope; `None`
/// otherwise (caller proceeds to scoring).
fn envelope_passthrough(content: &[u8], _reason: u32) -> Option<(bool, Option<UsbIncident>)> {
    if content.starts_with(&DLPENC_MAGIC) {
        Some((false, None))
    } else {
        None
    }
}

/// PURE write-path whitelist gate (sealer-coexistence defect 2), factored out
/// of `decide()` so the whole matrix is table-testable without FFI — the
/// Windows-only device resolution lives in `resolve_device_identity`.
///
/// A WRITE scan whose target volume resolves to an `Action::Encrypt` trusted
/// destination defers to the `usb-monitor` sealer instead of quarantining the
/// very file the monitor is about to armour. Gates, in order:
/// * READ scans are NEVER overridden — read-taint semantics are unchanged.
/// * `usb.enabled` must be true: with the monitor channel off there is nobody
///   to seal, so an allow here would strand plaintext on the stick. Fail
///   secure: guard behaviour is exactly as before.
/// * `device` is `None` when the volume could not be resolved ⇒ no override
///   (fail secure — never guess a whitelist match).
/// * The device's policy action (same first-match-wins rule engine the monitor
///   uses) must be `Encrypt`; every other action keeps today's behaviour.
///
/// Then `trustdest::decide_seal` (with the rule's mode + `on_block_band`):
/// * `Block` ⇒ `None` — the kernel block path runs unchanged (whitelisting
///   never weakens the block band unless the rule opted in).
/// * `Seal`  ⇒ ALLOW + an `allowed-pending-seal` incident: the audit trail
///   must show the kernel deliberately stood aside for the sealer.
/// * `Plain` ⇒ ALLOW, no incident (today's clean behaviour).
///
/// `verdict` is `None` when no verified bundle is cached — on an Encrypt
/// destination that still resolves to `Seal` (the monitor seals fail-secure
/// without a bundle), preferred over `fail_block`.
fn write_scan_override(
    reason: u32,
    usb: &UsbConfig,
    bands: &EncryptBands,
    device: Option<&DeviceIdentity>,
    verdict: Option<&Verdict>,
    display_path: &str,
    channel: &str,
) -> Option<(bool, Option<UsbIncident>)> {
    if reason == DLP_REASON_READ || !usb.enabled {
        return None;
    }
    let dev = device?;
    let (action, _rule) = crate::usb::policy::decide(&usb.to_policy(), dev);
    if action != Action::Encrypt {
        return None;
    }
    let (mode, _key_id, on_block_band) = usb.encrypt_params(dev);
    match decide_seal(mode, bands, on_block_band, verdict) {
        SealDecision::Block => None,
        SealDecision::Plain => Some((false, None)),
        SealDecision::Seal => Some((
            false,
            Some(pending_seal_incident(verdict.cloned(), dev.clone(), display_path, channel)),
        )),
    }
}

/// The audit record for a kernel ALLOW on an Encrypt destination: the guard
/// deliberately stood aside so the `usb-monitor` sealer can armour the file
/// (note `allowed-pending-seal`, action `Audited`). Metadata + verdict only —
/// never content. Kinds mirror `incident_for`: `Match` for a scored file,
/// `UnreadableOnRemovable` for unreadable content; `verdict: None` (no bundle)
/// is recorded metadata-only as `Sealed` — the kind whose contract already
/// covers "the fail-secure seal when no verdict could be produced" — with the
/// note distinguishing it from the monitor's own post-seal incident.
fn pending_seal_incident(
    verdict: Option<Verdict>,
    device: DeviceIdentity,
    display_path: &str,
    channel: &str,
) -> UsbIncident {
    let (kind, file_name, file_sha256) = match &verdict {
        Some(v) if matches!(v.extraction, detect::Extraction::Unreadable { .. }) => {
            (IncidentKind::UnreadableOnRemovable, v.file_name.clone(), v.file_sha256.clone())
        }
        Some(v) => (IncidentKind::Match, v.file_name.clone(), v.file_sha256.clone()),
        None => (IncidentKind::Sealed, basename_of(display_path), String::new()),
    };
    UsbIncident {
        kind,
        channel: channel.to_string(),
        file_name,
        file_sha256,
        verdict,
        device,
        action_taken: ActionTaken::Audited,
        note: Some("allowed-pending-seal".into()),
        key_id: None,
        sealed_sha256: None,
    }
}

/// PURE: match an NT device path (e.g. `\Device\HarddiskVolume3\dir\f.txt`)
/// against a map of UPPERCASE NT volume prefixes (`\DEVICE\HARDDISKVOLUME3`) →
/// drive letters (`"E:"`). The character after the prefix must be `\` — or the
/// path must end exactly at the prefix — so `...Volume1` never claims
/// `...Volume10\...`. Case-insensitive on the path side.
fn letter_for_nt_prefix(
    map: &std::collections::HashMap<String, String>,
    path: &str,
) -> Option<String> {
    let upper = path.to_ascii_uppercase();
    for (prefix, letter) in map {
        if let Some(rest) = upper.strip_prefix(prefix.as_str()) {
            if rest.is_empty() || rest.starts_with('\\') {
                return Some(letter.clone());
            }
        }
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

    // Read-deny: run a background tracker that pushes the exfil-channel PID set so
    // the driver's DlpPreRead can DENY sensitive reads by exfil processes. Only
    // when [kguard] exfil_read_block is set; the driver still gates on its own
    // ExfilReadBlockEnabled registry knob, so this is best-effort. Joined before
    // the port closes so the pusher never touches a closed handle.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let pusher = if cfg.kguard.exfil_read_block {
        let stop = stop.clone();
        // The pusher opens its OWN push-only connection (below) — it never touches
        // this scanner handle, so FilterSendMessage cannot collide with the
        // scanner's FilterGetMessage.
        Some(std::thread::spawn(move || exfil_push_loop(&stop)))
    } else {
        None
    };

    let _ = storage; // identity/CA already consumed above; kept for symmetry
    let result = message_loop(port, cfg, bundle.as_ref(), &mut report);

    // Stop + join the pusher BEFORE closing the port (no use of a closed handle).
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    if let Some(h) = pusher {
        let _ = h.join();
    }

    unsafe {
        let _ = CloseHandle(port);
    }
    result
}

/// Background loop: recompute the exfil-channel PID set and push it to the driver
/// every ~2s. Opens its OWN push-only port connection (context = DLP_EXFIL_VERSION)
/// so `FilterSendMessage` never shares a handle with the scanner's blocking
/// `FilterGetMessage` (which conflict). Exits on `stop` or a send error.
#[cfg(windows)]
fn exfil_push_loop(stop: &std::sync::atomic::AtomicBool) {
    use std::sync::atomic::Ordering;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::InstallableFileSystems::{
        FilterConnectCommunicationPort, FilterSendMessage,
    };

    // Open a dedicated push-only connection. The 4-byte context is the exfil magic
    // so the driver's DlpPortConnect marks it push-only (never the ClientPort).
    let port_name: Vec<u16> = "\\DlpFltPort".encode_utf16().chain(std::iter::once(0)).collect();
    let ctx: u32 = crate::exfil::DLP_EXFIL_VERSION;
    let port: HANDLE = match unsafe {
        FilterConnectCommunicationPort(
            PCWSTR(port_name.as_ptr()),
            0,
            Some(&ctx as *const u32 as *const core::ffi::c_void),
            core::mem::size_of::<u32>() as u16,
            None,
        )
    } {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = %e, "exfil pusher could not open its push connection — read-deny will not receive PID updates");
            return;
        }
    };

    let self_pid = std::process::id();
    while !stop.load(Ordering::Relaxed) {
        let pids = crate::exfil::compute_exfil_pids(self_pid);
        let msg = crate::exfil::DlpExfilUpdate::new(&pids);
        let rc = unsafe {
            FilterSendMessage(
                port,
                &msg as *const crate::exfil::DlpExfilUpdate as *const core::ffi::c_void,
                core::mem::size_of::<crate::exfil::DlpExfilUpdate>() as u32,
                None,
                0,
                &mut 0u32,
            )
        };
        if let Err(e) = rc {
            tracing::warn!(error = %e, "exfil-set push failed (port closing?) — ending pusher");
            break;
        }
        tracing::info!(count = pids.len(), pids = ?pids, "pushed exfil-channel PID set to driver");
        // ~2s cadence, checking stop every 100ms so shutdown is prompt.
        for _ in 0..20 {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    unsafe {
        let _ = CloseHandle(port);
    }
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
    struct ReplyMessage {
        header: FILTER_REPLY_HEADER,
        reply: DlpScanReply,
    }

    let kg = &cfg.kguard;

    // Receive buffer sized for the filter-manager header + our fixed request
    // header + up to DLP_MAX_CONTENT (4 MiB) of trailing file content, since
    // `FilterGetMessage` fills header + content into ONE buffer (v2 content-over-
    // port). This is a heap allocation, NEVER the stack — 4 MiB would overflow a
    // thread stack. Backed by a `Vec<u64>` so the start is 8-aligned, which the
    // 8-byte-aligned `FILTER_MESSAGE_HEADER`/`DlpScanRequest` require. Allocated
    // once and reused across iterations (we only read `content_length` bytes, so
    // stale tail bytes are never observed).
    let header_size = size_of::<FILTER_MESSAGE_HEADER>();
    let req_size = size_of::<DlpScanRequest>();
    let total_size = header_size + req_size + DLP_MAX_CONTENT;
    let mut backing: Vec<u64> = vec![0u64; total_size.div_ceil(8)];
    let buf_ptr = backing.as_mut_ptr() as *mut u8;

    loop {
        let recv = unsafe {
            FilterGetMessage(
                port,
                buf_ptr as *mut FILTER_MESSAGE_HEADER,
                total_size as u32,
                None,
            )
        };
        if let Err(e) = recv {
            // Port closed (driver unloaded) or a transient error: stop the loop
            // and let the caller decide whether to reconnect.
            tracing::warn!(error = %e, "FilterGetMessage returned error — ending kguard loop");
            return Ok(());
        }

        // SAFETY: `buf_ptr` is 8-aligned and `total_size` bytes long; the header
        // occupies the first `header_size` bytes and the fixed request the next
        // `req_size`. `DlpScanRequest` is `Copy`/POD, so a value read is sound.
        let message_id = unsafe { (*(buf_ptr as *const FILTER_MESSAGE_HEADER)).MessageId };
        let req: DlpScanRequest =
            unsafe { std::ptr::read(buf_ptr.add(header_size) as *const DlpScanRequest) };

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
            // The content that FOLLOWS the fixed header in the same buffer,
            // bounded to the 4 MiB cap. SAFETY: content occupies
            // [header_size + req_size, +content_len) inside the allocation.
            let content_len = (req.content_length as usize).min(DLP_MAX_CONTENT);
            let content: &[u8] = unsafe {
                std::slice::from_raw_parts(buf_ptr.add(header_size + req_size), content_len)
            };
            let truncated = req.truncated != 0;
            // Score the in-memory content (NO file re-open), or fall back to the
            // configured fail behavior. `req.reason` selects the write vs
            // read-taint incident labelling (verdict semantics are identical).
            decide(cfg, kg, bundle, &device_path, content, truncated, req.reason)
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

        // Read-taint side-effect: on a read-scan BLOCK the driver has just
        // tainted this PID, but its ALREADY-OPEN sockets predate the WFP
        // callout's new-connect block. Tear those live flows down by owning PID
        // (best-effort; the kernel callout still guarantees the steady state, so
        // a failure here only widens the tiny existing-connection race, LLD §7).
        // Done AFTER replying so the kernel's read path is never delayed by it.
        if should_reset_connections(req.reason, block) {
            tracing::info!(
                pid = req.process_id,
                reason = reason_label(req.reason),
                "read-taint block — tearing down live egress for tainted PID"
            );
            match crate::netfilter::reset_pid_connections(req.process_id) {
                Ok(n) => tracing::warn!(
                    pid = req.process_id,
                    reset = n,
                    "read-taint: reset tainted process's live TCP egress"
                ),
                Err(e) => tracing::warn!(
                    pid = req.process_id,
                    error = %e,
                    "read-taint: connection reset failed (best-effort; WFP callout still blocks new connects)"
                ),
            }
        }

        // Raise the incident (if any) AFTER replying, so a slow network sink
        // never delays the kernel's file-close path.
        if let Some(inc) = incident {
            report(inc);
        }
    }
}

/// The basename (final path component) of an NT device path, used only to give
/// extraction the file extension so it picks the right format. Splits on both NT
/// (`\`) and DOS/POSIX (`/`) separators; falls back to the whole path when the
/// last component is empty (trailing separator). Never panics.
fn basename_of(path: &str) -> String {
    let base = path.rsplit(['\\', '/']).next().unwrap_or(path);
    if base.is_empty() {
        path.to_string()
    } else {
        base.to_string()
    }
}

/// Compute the block decision + optional incident for one requested file. The
/// driver already read the file IN-KERNEL and shipped the bytes inline (v2
/// content-over-port), so we score `content` directly with `verdict_bytes` and
/// NEVER re-open the file — that was the source of the CLEANUP sharing violation.
/// `device_path` is used only as the incident/display label and to derive the
/// filename for extension-based extraction; `content` is NEVER logged. With no
/// verified bundle we honor `fail_block` (unless a whitelisted Encrypt
/// destination stands aside first — see `write_scan_override`).
#[cfg(windows)]
fn decide(
    cfg: &Config,
    kg: &KguardConfig,
    bundle: Option<&Bundle>,
    device_path: &str,
    content: &[u8],
    _truncated: bool,
    reason: u32,
) -> (bool, Option<UsbIncident>) {
    // Sealer coexistence, defect 1: a `.dlpenc` envelope passes untouched —
    // both scan reasons, every volume, before any scoring (see the gate's doc).
    if let Some(pass) = envelope_passthrough(content, reason) {
        tracing::debug!(
            reason = reason_label(reason),
            path_len = device_path.len(),
            "sealed .dlpenc envelope — passthrough (no scan, no incident)"
        );
        return pass;
    }

    // Derive a synthetic filename (basename of the NT path) so extraction picks
    // the right format from the extension. `verdict_bytes` is infallible —
    // unreadable/unsupported content is a valid verdict, not an error. No
    // bundle ⇒ no verdict ⇒ fail per `fail_block` below (unless an Encrypt
    // destination overrides — the monitor seals fail-secure without a bundle).
    let filename = basename_of(device_path);
    let verdict = bundle.map(|b| detect::verdict_bytes(content, &filename, b));
    if let Some(v) = &verdict {
        // DIAGNOSTIC: exactly what the driver shipped for this scan.
        tracing::info!(
            reason,
            filename = %filename,
            path_len = device_path.len(),
            content_len = content.len(),
            extraction = ?v.extraction,
            idm = v.idm.len(),
            edm = v.edm.len(),
            "kguard scan decide"
        );
    }

    // Sealer coexistence, defect 2: a WRITE headed to a whitelisted
    // `action = "encrypt"` device defers to the user-mode sealer instead of
    // quarantining what the monitor would seal. Device resolution is the FFI
    // shim (`resolve_device_identity`); the decision matrix is the pure
    // `write_scan_override`. The outer gate here only avoids the resolution
    // FFI on read scans / disabled channel — the pure fn re-checks both.
    if reason != DLP_REASON_READ && cfg.usb.enabled {
        let dev = resolve_device_identity(device_path);
        if let Some((block, incident)) = write_scan_override(
            reason,
            &cfg.usb,
            &cfg.encrypt_bands(),
            dev.as_ref(),
            verdict.as_ref(),
            device_path,
            &kg.channel_label,
        ) {
            return (block, incident);
        }
        // None ⇒ no override (unresolved device, non-Encrypt destination, or a
        // block-band verdict under the default `on_block_band = "block"`):
        // fall through to today's behaviour unchanged.
    }

    let v = match verdict {
        Some(v) => v,
        None => {
            // No verified bundle: cannot score. Fail per configuration.
            return (kg.fail_block, None);
        }
    };
    let block = if matches!(v.extraction, detect::Extraction::Unreadable { .. }) {
        // Content we can't parse. Fail-secure ONLY on the exfil-to-removable/network
        // (write) path, and only when `fail_block` is set: an unverifiable file must
        // not leave the machine. NEVER fail-secure on the READ (taint) path — that
        // would cut a user's network for merely opening an image/binary/encrypted
        // file. Read-taint stays a genuine content match, not a fail-open guess.
        reason != DLP_REASON_READ && kg.fail_block
    } else {
        should_block(&v, kg)
    };
    let inc = incident_for(device_path, v, block, &kg.channel_label, reason);
    (block, inc)
}

/// Resolve the identity of the volume a driver scan-path targets (sealer
/// coexistence, defect 2). Driver paths are usually NT form
/// `\Device\HarddiskVolumeN\...` (no drive letter — `drive_letter_of` returns
/// `""`); those go through the cached `QueryDosDeviceW` prefix map. A genuine
/// `X:\...` path uses its letter directly. Identity then comes from the SAME
/// `usb::device` IOCTL lookup the monitor's enumeration uses — no duplicated
/// identity logic. `None` ⇒ unresolvable: the caller falls through to today's
/// fail-secure behaviour, never guessing a whitelist match.
#[cfg(windows)]
fn resolve_device_identity(device_path: &str) -> Option<DeviceIdentity> {
    let direct = drive_letter_of(device_path);
    let letter = if direct.is_empty() {
        ntvol::drive_letter_for_nt_path(device_path)?
    } else {
        direct
    };
    crate::usb::device::query_device_identity(&letter).ok()
}

/// NT-volume-prefix → drive-letter map, built via `QueryDosDeviceW` over
/// `A:`..`Z:`, cached process-wide, refreshed once on a lookup miss so a
/// newly-mounted stick resolves without polling. FFI shim only — the prefix
/// matching itself is the pure `letter_for_nt_prefix` in the parent module.
#[cfg(windows)]
mod ntvol {
    use std::collections::HashMap;
    use std::sync::Mutex;

    static CACHE: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

    /// One `QueryDosDeviceW` sweep of the 26 letters. Cheap (no I/O to the
    /// volumes themselves); only run at first use and on a lookup miss.
    fn build_map() -> HashMap<String, String> {
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

        let mut map = HashMap::new();
        for i in 0..26u8 {
            let letter = format!("{}:", (b'A' + i) as char);
            let wide: Vec<u16> =
                letter.encode_utf16().chain(std::iter::once(0)).collect();
            let mut buf = [0u16; 1024];
            let n = unsafe { QueryDosDeviceW(PCWSTR(wide.as_ptr()), Some(&mut buf)) };
            if n == 0 {
                continue; // letter not mapped
            }
            // The buffer holds a MULTI_SZ; the first string is the current
            // device target (e.g. `\Device\HarddiskVolume3`).
            let end = buf.iter().position(|&c| c == 0).unwrap_or(0);
            if end > 0 {
                map.insert(String::from_utf16_lossy(&buf[..end]).to_ascii_uppercase(), letter);
            }
        }
        map
    }

    /// Drive letter (`"E:"`) for an NT device path. Consults the cache first;
    /// a miss rebuilds the map once (newly-mounted volumes appear there) and
    /// retries. `None` ⇒ genuinely unmapped (caller fails secure).
    pub fn drive_letter_for_nt_path(path: &str) -> Option<String> {
        let mut guard = match CACHE.lock() {
            Ok(g) => g,
            // The map is plain data — a poisoned lock (panicked holder) is
            // still safe to reuse; never panic the scan loop over it.
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(map) = guard.as_ref() {
            if let Some(letter) = super::letter_for_nt_prefix(map, path) {
                return Some(letter);
            }
        }
        let map = build_map();
        let hit = super::letter_for_nt_prefix(&map, path);
        *guard = Some(map);
        hit
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
        // A write-scan block (legacy path) keeps the `kernel-blocked` note.
        let inc = incident_for("E:\\x.docx", verdict_with(1.0, 1.0), true, "usb-kguard", DLP_REASON_WRITE)
            .expect("a block must raise an incident");
        assert_eq!(inc.kind, IncidentKind::Match);
        assert_eq!(inc.action_taken, ActionTaken::Blocked);
        assert_eq!(inc.device.drive_letter, "E:");
        assert!(inc.verdict.is_some());
        assert_eq!(inc.note.as_deref(), Some("kernel-blocked"));
    }

    #[test]
    fn incident_for_clean_allow_is_none() {
        assert!(incident_for("E:\\ok.txt", clean_verdict(), false, "usb-kguard", DLP_REASON_WRITE).is_none());
    }

    // --- Read-taint reason plumbing (LLD §9.1, §12 unit 5) -----------------

    #[test]
    fn read_scan_block_is_labelled_read_taint() {
        // A read-scan (DLP_REASON_READ) block drives the read-taint incident:
        // same Match/Blocked shape, but the note distinguishes it for reviewers.
        let inc = incident_for("E:\\secret.docx", verdict_with(1.0, 1.0), true, "usb-kguard", DLP_REASON_READ)
            .expect("a read-taint block must raise an incident");
        assert_eq!(inc.kind, IncidentKind::Match);
        assert_eq!(inc.action_taken, ActionTaken::Blocked);
        assert_eq!(inc.note.as_deref(), Some("read-taint"));
    }

    #[test]
    fn block_note_selects_by_reason() {
        assert_eq!(block_note(DLP_REASON_READ), "read-taint");
        assert_eq!(block_note(DLP_REASON_WRITE), "kernel-blocked");
    }

    #[test]
    fn reason_label_names_known_and_unknown() {
        assert_eq!(reason_label(DLP_REASON_WRITE), "write");
        assert_eq!(reason_label(DLP_REASON_READ), "read-taint");
        assert_eq!(reason_label(99), "unknown"); // forward-compat: newer driver
    }

    #[test]
    fn reset_only_on_read_scan_block() {
        // Only a READ scan that BLOCKED tears down the PID's live egress.
        assert!(should_reset_connections(DLP_REASON_READ, true));
        assert!(!should_reset_connections(DLP_REASON_READ, false)); // clean read
        assert!(!should_reset_connections(DLP_REASON_WRITE, true)); // legacy write block
        assert!(!should_reset_connections(DLP_REASON_WRITE, false));
    }

    #[test]
    fn wire_layout_is_byte_locked_after_reserved_to_reason_rename() {
        // The reserved->reason rename is byte-identical: the frozen v2 asserts
        // still hold (compile-time asserts at module scope already guarantee this
        // — restated here as an explicit, named regression guard, LLD §6).
        assert_eq!(core::mem::size_of::<DlpScanRequest>(), 1056);
        assert_eq!(core::mem::align_of::<DlpScanRequest>(), 8);
        assert_eq!(core::mem::size_of::<DlpScanReply>(), 16);
        // The reason field occupies the former Reserved slot at offset 4.
        let req = DlpScanRequest {
            version: DLP_MSG_VERSION,
            reason: DLP_REASON_READ,
            file_id: 0,
            process_id: 0,
            path_length: 0,
            pad: 0,
            path: [0u16; DLP_MAX_PATH_CHARS],
            content_length: 0,
            truncated: 0,
        };
        assert_eq!(req.reason, DLP_REASON_READ);
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

    // --- Sealer coexistence: `.dlpenc` envelope passthrough (defect 1) ------

    #[test]
    fn envelope_magic_is_the_dlpe_constant() {
        // The gate reuses crypto::envelope::MAGIC — pin its value so a drift
        // there would be caught here too.
        assert_eq!(&DLPENC_MAGIC, b"DLPE");
    }

    #[test]
    fn envelope_content_passes_on_both_reasons_with_no_incident() {
        // magic + version byte + arbitrary ciphertext-looking tail.
        let mut env = DLPENC_MAGIC.to_vec();
        env.extend_from_slice(&[0x01, 0x42, 0x00, 0xFF, 0x13]);
        for reason in [DLP_REASON_WRITE, DLP_REASON_READ] {
            let (block, inc) = envelope_passthrough(&env, reason)
                .expect("DLPE content must be passed through on every reason");
            assert!(!block, "an envelope is never blocked");
            assert!(inc.is_none(), "an envelope raises no incident");
        }
        // Bare magic (a truncated tmp file mid-write) still passes.
        assert!(envelope_passthrough(&DLPENC_MAGIC, DLP_REASON_WRITE).is_some());
    }

    #[test]
    fn non_envelope_content_is_not_passed_through() {
        for content in [
            &b""[..],
            &b"DLP"[..],                  // shorter than the magic
            &b"DLPX not an envelope"[..], // wrong 4th byte
            &b"plain text file body"[..],
        ] {
            for reason in [DLP_REASON_WRITE, DLP_REASON_READ] {
                assert!(
                    envelope_passthrough(content, reason).is_none(),
                    "non-envelope content must fall through to scoring"
                );
            }
        }
    }

    // --- Sealer coexistence: whitelist-aware write scans (defect 2) ---------

    use crate::config::UsbRule;
    use crate::trustdest::{BlockBandPolicy, EncryptMode};

    /// `[usb]` config with one `action = "encrypt"` rule for serial COURIER.
    fn encrypt_usb_cfg(on_block_band: BlockBandPolicy, mode: Option<EncryptMode>) -> UsbConfig {
        UsbConfig {
            enabled: true,
            rules: vec![UsbRule {
                match_serial: Some("COURIER".into()),
                match_vid: None,
                match_pid: None,
                match_bus_type: None,
                match_any: false,
                action: Action::Encrypt,
                note: None,
                mode,
                key_id: None,
                on_block_band,
            }],
            ..UsbConfig::default()
        }
    }

    fn dev_with_serial(serial: &str) -> DeviceIdentity {
        DeviceIdentity {
            drive_letter: "E:".into(),
            vendor_id: "Kingston".into(),
            product_id: "DataTraveler".into(),
            serial: serial.into(),
            product_name: "Kingston DataTraveler".into(),
            bus_type: "usb".into(),
            removable: true,
        }
    }

    fn unreadable_verdict() -> Verdict {
        Verdict {
            file_name: "f.zip".into(),
            file_sha256: "sha".into(),
            extraction: Extraction::Unreadable { reason: "encrypted-zip".into() },
            idm: vec![],
            edm: vec![],
        }
    }

    const NT_PATH: &str = "\\Device\\HarddiskVolume7\\out\\plan.docx";
    const CHANNEL: &str = "usb-kguard";

    #[test]
    fn block_band_with_rule_seal_opt_in_allows_pending_seal() {
        let usb = encrypt_usb_cfg(BlockBandPolicy::Seal, None);
        let dev = dev_with_serial("COURIER");
        let v = verdict_with(1.0, 1.0); // deep in the block band
        let (block, inc) = write_scan_override(
            DLP_REASON_WRITE,
            &usb,
            &EncryptBands::default(),
            Some(&dev),
            Some(&v),
            NT_PATH,
            CHANNEL,
        )
        .expect("seal opt-in must override the kernel block");
        assert!(!block, "the guard stands aside for the sealer");
        let inc = inc.expect("standing aside must leave an audit record");
        assert_eq!(inc.kind, IncidentKind::Match);
        assert_eq!(inc.action_taken, ActionTaken::Audited);
        assert_eq!(inc.note.as_deref(), Some("allowed-pending-seal"));
        assert_eq!(inc.device.serial, "COURIER", "the RESOLVED device is on record");
        assert!(inc.verdict.is_some(), "the full verdict travels with the incident");
    }

    #[test]
    fn block_band_with_default_rule_still_blocks_unchanged() {
        // on_block_band defaults to Block (spec §10): the override declines and
        // decide() runs the existing kernel-block path, incident unchanged
        // (shape pinned by `incident_for_block_is_match_blocked` above).
        let usb = encrypt_usb_cfg(BlockBandPolicy::Block, None);
        let dev = dev_with_serial("COURIER");
        let v = verdict_with(1.0, 1.0);
        assert!(write_scan_override(
            DLP_REASON_WRITE,
            &usb,
            &EncryptBands::default(),
            Some(&dev),
            Some(&v),
            NT_PATH,
            CHANNEL,
        )
        .is_none());
    }

    #[test]
    fn unreadable_on_encrypt_volume_is_allow_pending_seal() {
        // decide_seal treats Unreadable as sensitive ⇒ Seal; the guard lets it
        // through for the sealer instead of fail_block-quarantining it.
        let usb = encrypt_usb_cfg(BlockBandPolicy::Block, None);
        let dev = dev_with_serial("COURIER");
        let v = unreadable_verdict();
        let (block, inc) = write_scan_override(
            DLP_REASON_WRITE,
            &usb,
            &EncryptBands::default(),
            Some(&dev),
            Some(&v),
            NT_PATH,
            CHANNEL,
        )
        .expect("unreadable on an encrypt destination must defer to the sealer");
        assert!(!block);
        let inc = inc.unwrap();
        assert_eq!(inc.kind, IncidentKind::UnreadableOnRemovable);
        assert_eq!(inc.action_taken, ActionTaken::Audited);
        assert_eq!(inc.note.as_deref(), Some("allowed-pending-seal"));
    }

    #[test]
    fn unreadable_on_non_encrypt_volume_keeps_fail_block() {
        // The device matches NO encrypt rule (policy default is ReadOnly): the
        // override declines and decide() applies today's fail_block path.
        let usb = encrypt_usb_cfg(BlockBandPolicy::Block, None);
        let dev = dev_with_serial("SOME-OTHER-STICK");
        let v = unreadable_verdict();
        assert!(write_scan_override(
            DLP_REASON_WRITE,
            &usb,
            &EncryptBands::default(),
            Some(&dev),
            Some(&v),
            NT_PATH,
            CHANNEL,
        )
        .is_none());
    }

    #[test]
    fn clean_file_on_encrypt_sensitive_volume_is_plain_allow() {
        // SealDecision::Plain ⇒ allow with NO incident — today's clean path.
        let usb = encrypt_usb_cfg(BlockBandPolicy::Block, None);
        let dev = dev_with_serial("COURIER");
        let v = clean_verdict();
        let (block, inc) = write_scan_override(
            DLP_REASON_WRITE,
            &usb,
            &EncryptBands::default(),
            Some(&dev),
            Some(&v),
            NT_PATH,
            CHANNEL,
        )
        .expect("a resolved encrypt destination always yields a decision for non-block rows");
        assert!(!block);
        assert!(inc.is_none(), "clean files raise no incident");
    }

    #[test]
    fn seal_band_verdict_on_encrypt_volume_is_allow_pending_seal() {
        // Containment inside the encrypt band (0.05..0.30) ⇒ Seal ⇒ stand aside.
        let usb = encrypt_usb_cfg(BlockBandPolicy::Block, None);
        let dev = dev_with_serial("COURIER");
        let v = verdict_with(0.20, 0.0);
        let (block, inc) = write_scan_override(
            DLP_REASON_WRITE,
            &usb,
            &EncryptBands::default(),
            Some(&dev),
            Some(&v),
            NT_PATH,
            CHANNEL,
        )
        .unwrap();
        assert!(!block);
        assert_eq!(inc.unwrap().kind, IncidentKind::Match);
    }

    #[test]
    fn usb_disabled_never_overrides() {
        // With the monitor channel off there is nobody to seal — the guard
        // behaves exactly as before for EVERY input (fail secure).
        let mut usb = encrypt_usb_cfg(BlockBandPolicy::Seal, Some(EncryptMode::EncryptAll));
        usb.enabled = false;
        let dev = dev_with_serial("COURIER");
        for v in [None, Some(clean_verdict()), Some(unreadable_verdict()), Some(verdict_with(1.0, 1.0))]
        {
            assert!(
                write_scan_override(
                    DLP_REASON_WRITE,
                    &usb,
                    &EncryptBands::default(),
                    Some(&dev),
                    v.as_ref(),
                    NT_PATH,
                    CHANNEL,
                )
                .is_none(),
                "usb.enabled=false must leave guard behaviour untouched"
            );
        }
    }

    #[test]
    fn read_reason_is_never_overridden() {
        // Read-taint semantics unchanged: even a seal-opt-in courier stick
        // never suppresses a read-scan verdict.
        let usb = encrypt_usb_cfg(BlockBandPolicy::Seal, Some(EncryptMode::EncryptAll));
        let dev = dev_with_serial("COURIER");
        for v in [None, Some(verdict_with(1.0, 1.0)), Some(unreadable_verdict())] {
            assert!(write_scan_override(
                DLP_REASON_READ,
                &usb,
                &EncryptBands::default(),
                Some(&dev),
                v.as_ref(),
                NT_PATH,
                CHANNEL,
            )
            .is_none());
        }
    }

    #[test]
    fn no_bundle_on_encrypt_volume_is_allow_pending_seal_metadata_only() {
        // verdict None (no verified bundle): prefer allow + a metadata-only
        // record over kg.fail_block — the monitor seals fail-secure without a
        // bundle, and the trail still shows the kernel stood aside.
        let usb = encrypt_usb_cfg(BlockBandPolicy::Block, None);
        let dev = dev_with_serial("COURIER");
        let (block, inc) = write_scan_override(
            DLP_REASON_WRITE,
            &usb,
            &EncryptBands::default(),
            Some(&dev),
            None,
            NT_PATH,
            CHANNEL,
        )
        .expect("no-bundle on an encrypt destination must defer to the sealer");
        assert!(!block);
        let inc = inc.unwrap();
        assert_eq!(inc.kind, IncidentKind::Sealed);
        assert_eq!(inc.action_taken, ActionTaken::Audited);
        assert_eq!(inc.note.as_deref(), Some("allowed-pending-seal"));
        assert!(inc.verdict.is_none(), "metadata-only: no verdict existed");
        assert!(inc.file_sha256.is_empty(), "metadata-only: nothing was scored");
        assert_eq!(inc.file_name, "plan.docx", "basename of the NT path");
        assert_eq!(inc.channel, CHANNEL);
    }

    #[test]
    fn no_bundle_elsewhere_keeps_fail_block() {
        let usb = encrypt_usb_cfg(BlockBandPolicy::Block, None);
        // Non-matching device ⇒ decline (decide() then applies fail_block).
        let other = dev_with_serial("SOME-OTHER-STICK");
        assert!(write_scan_override(
            DLP_REASON_WRITE,
            &usb,
            &EncryptBands::default(),
            Some(&other),
            None,
            NT_PATH,
            CHANNEL,
        )
        .is_none());
        // Unresolved device ⇒ decline too — never guess a whitelist match.
        assert!(write_scan_override(
            DLP_REASON_WRITE,
            &usb,
            &EncryptBands::default(),
            None,
            None,
            NT_PATH,
            CHANNEL,
        )
        .is_none());
    }

    #[test]
    fn unresolved_device_never_guesses_a_whitelist_match() {
        // Even with a seal-band verdict in hand, no resolved device ⇒ no
        // override: today's behaviour, fail secure.
        let usb = encrypt_usb_cfg(BlockBandPolicy::Seal, None);
        let v = verdict_with(0.20, 0.0);
        assert!(write_scan_override(
            DLP_REASON_WRITE,
            &usb,
            &EncryptBands::default(),
            None,
            Some(&v),
            NT_PATH,
            CHANNEL,
        )
        .is_none());
    }

    #[test]
    fn encrypt_all_clean_file_is_still_pending_seal() {
        // Courier mode seals EVERYTHING — a clean verdict is still deferred to
        // the sealer (kind Match carries the clean verdict for the record).
        let usb = encrypt_usb_cfg(BlockBandPolicy::Block, Some(EncryptMode::EncryptAll));
        let dev = dev_with_serial("COURIER");
        let v = clean_verdict();
        let (block, inc) = write_scan_override(
            DLP_REASON_WRITE,
            &usb,
            &EncryptBands::default(),
            Some(&dev),
            Some(&v),
            NT_PATH,
            CHANNEL,
        )
        .unwrap();
        assert!(!block);
        assert_eq!(inc.unwrap().note.as_deref(), Some("allowed-pending-seal"));
    }

    // --- NT volume-prefix → drive-letter matching (pure part of the shim) ---

    #[test]
    fn nt_prefix_matching_resolves_letters_without_digit_confusion() {
        let mut map = std::collections::HashMap::new();
        map.insert("\\DEVICE\\HARDDISKVOLUME1".to_string(), "C:".to_string());
        map.insert("\\DEVICE\\HARDDISKVOLUME10".to_string(), "E:".to_string());

        // Exact-boundary matching: Volume1 never claims Volume10's paths.
        assert_eq!(
            letter_for_nt_prefix(&map, "\\Device\\HarddiskVolume1\\Users\\a\\f.txt").as_deref(),
            Some("C:")
        );
        assert_eq!(
            letter_for_nt_prefix(&map, "\\Device\\HarddiskVolume10\\out\\f.txt").as_deref(),
            Some("E:")
        );
        // Path ending exactly at the prefix still resolves.
        assert_eq!(letter_for_nt_prefix(&map, "\\Device\\HarddiskVolume10").as_deref(), Some("E:"));
        // Unknown volume ⇒ None (caller refreshes the cache, then fails secure).
        assert!(letter_for_nt_prefix(&map, "\\Device\\HarddiskVolume3\\f.txt").is_none());
        // Case-insensitive on the path side.
        assert_eq!(
            letter_for_nt_prefix(&map, "\\DEVICE\\harddiskvolume1\\F.TXT").as_deref(),
            Some("C:")
        );
    }
}
