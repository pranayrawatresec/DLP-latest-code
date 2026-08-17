//! User-mode network-egress control (Tier-2 plan §2.1/§2.2, mechanism ③ + ⑧).
//!
//! Structure mirrors the USB channel so it shares the incident/queue path:
//!   * `rules`        — the PURE allow/deny decision engine (unit-tested).
//!   * `remote_tools` — the AnyDesk/TeamViewer/VNC/… signature set + matcher.
//!   * `wfp`          — the `FWPM_FILTER0` spec builder (dry-run) + the live
//!     `FwpmFilterAdd0` path (`#[cfg(windows)]`, `--enforce`, never in tests).
//!   * this file      — `run_monitor`, the loop that ties them to the OS.
//!
//! HONEST SCOPE (plan §0/§5 — restated in the CLI help too):
//!   * This blocks the *socket connect* of a process (app-id) or to a destination
//!     (ip/port). It does NOT stop a screen already being viewed over VNC/AnyDesk
//!     (the analog hole), a privileged/SYSTEM payload that unhooks us, or
//!     encrypted exfil to an ALLOWED destination (content-blind).
//!   * Live `FwpmFilterAdd0`, live process kill, and per-connection enumeration
//!     are operator-manual (admin/VM). Verifiable here: the pure rule engine, the
//!     remote-tool matcher, the WFP filter-spec dry-run, and the fail-secure
//!     decisions. Default mode is `monitor` — NEVER default-deny (allowlist can
//!     brick a machine).
//!   * Incidents carry metadata only (app path, remote ip/port, tool id) — never
//!     packet contents. Network incidents have no `verdict`, so the shared sink
//!     LOGS them locally (they are not posted; a server-side network-incident
//!     schema is a follow-on).

pub mod remote_tools;
pub mod rules;
pub mod tcptable;
pub mod wfp;

pub use remote_tools::{RemoteToolPolicy, ToolAction};
pub use rules::{Connection, Decision, Direction, NetMode, NetPolicy, NetRule};

use crate::config::{Config, NetfilterConfig};
use crate::storage::Storage;
use crate::usb::{ActionTaken, DeviceIdentity, IncidentKind, UsbIncident};

/// Build the evaluated `NetPolicy` from config, with the CLI-selected `mode`.
pub fn build_policy(nf: &NetfilterConfig, mode: NetMode) -> NetPolicy {
    let rules = nf.rules.iter().filter_map(|r| r.to_net_rule()).collect();
    let remote_tools = RemoteToolPolicy {
        default_action: nf.remote_tool_action,
        overrides: nf.remote_tool_overrides.clone(),
    };
    NetPolicy { mode, rules, remote_tools }
}

/// Synthesize the placeholder device identity for a network incident. The
/// network is not a device; `bus_type` marks the origin so a reviewer can tell
/// network incidents from USB/clipboard ones. `product_name` carries the app.
fn network_device(app_path: &str) -> DeviceIdentity {
    DeviceIdentity {
        drive_letter: String::new(),
        vendor_id: String::new(),
        product_id: String::new(),
        serial: String::new(),
        product_name: app_path.to_string(),
        bus_type: "network".into(),
        removable: false,
    }
}

/// Build a metadata-only network incident (no `verdict` → the shared sink logs
/// it, never posts it). `note` carries ONLY metadata (app/ip/port/tool/reason) —
/// never packet contents (plan §5 DO-NOT).
fn network_incident(app_path: &str, note: String, blocked: bool, channel: &str) -> UsbIncident {
    UsbIncident {
        // `Match` is the closest existing kind: a connection matched network
        // policy. We do not add a new IncidentKind (keeps the usb module frozen).
        kind: IncidentKind::Match,
        channel: channel.to_string(),
        file_name: String::new(),
        file_sha256: String::new(),
        verdict: None,
        device: network_device(app_path),
        action_taken: if blocked { ActionTaken::Blocked } else { ActionTaken::Audited },
        note: Some(note),
        key_id: None,
        sealed_sha256: None,
    }
}

// ---------------------------------------------------------------------------
// Windows: the live monitor + (under --enforce) WFP install.
// ---------------------------------------------------------------------------
#[cfg(windows)]
pub fn run_monitor<R>(cfg: &Config, storage: &Storage, mode: NetMode, mut report: R)
where
    R: FnMut(UsbIncident),
{
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    let _ = storage; // reserved for future fail-secure bundle wiring (B4)
    let nf = &cfg.netfilter;
    let policy = build_policy(nf, mode);
    let channel = nf.channel_label.clone();

    tracing::info!(
        ?mode,
        rules = policy.rules.len(),
        remote_tool_default = ?nf.remote_tool_action,
        "net monitor starting"
    );
    if mode == NetMode::Allowlist {
        tracing::warn!(
            "ENFORCE allowlist mode: default-DENY egress. This CAN BRICK connectivity \
             if the allowlist is incomplete (DoS tradeoff, plan §2.1). Admin required."
        );
        if !policy.rules.iter().any(|r| matches!(r.action, rules::RuleAction::Permit)) {
            tracing::warn!(
                "allowlist has NO permit rules — every non-remote-tool connection would be \
                 blocked. Verify this is intended before relying on it."
            );
        }
    }

    let enforce = matches!(mode, NetMode::Allowlist | NetMode::Blocklist);

    // Under --enforce: install the explicit rule filters once (transactional,
    // dynamic session → auto-clean on exit). Remote-tool app-id blocks are added
    // as their processes are seen (below).
    if enforce {
        let mut specs = Vec::new();
        for r in &policy.rules {
            specs.extend(wfp::plan_filters(r));
        }
        match wfp::apply(&specs, wfp::WfpMode::Live) {
            Ok(wfp::WfpApplyOutcome::Executed(n)) => {
                tracing::warn!(filters = n, "installed rule filters (live WFP)")
            }
            Ok(other) => tracing::info!(?other, "rule filter apply"),
            Err(e) => tracing::error!(error = %e, "live WFP install failed — is this process admin?"),
        }
    }

    // Loop: enumerate remote-tool processes, evaluate the intended verdict, raise
    // incidents (once per image path), and under --enforce install app-id blocks
    // for tools whose action is block_network/kill. NOTE: full per-connection
    // enumeration (IpHelper owner-PID→conn table) is a follow-on; this loop
    // reports remote-tool processes + the configured policy intent.
    let mut seen_tools: HashSet<String> = HashSet::new();
    let mut blocked_paths: HashSet<String> = HashSet::new();
    loop {
        for (pid, image) in list_remote_tool_processes() {
            // Evaluate the intended verdict with a synthetic connection (image is
            // the authoritative signal; ip/port unknown without conn enumeration).
            let conn = Connection {
                app_path: image.clone(),
                remote_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                remote_port: 0,
                direction: Direction::Outbound,
            };
            let decision = rules::decide(&policy, &conn);
            let blocked_now = enforce && decision.is_block();

            if seen_tools.insert(image.clone()) {
                let tool = remote_tools::match_image(&image).map(|t| t.id).unwrap_or("unknown");
                tracing::warn!(
                    pid,
                    image = %image,
                    tool,
                    verdict = decision.reason(),
                    enforce,
                    "remote-access tool present (screen-view analog hole is NOT stopped)"
                );
                report(network_incident(
                    &image,
                    format!("remote-tool={tool} pid={pid} verdict={} enforce={enforce}", decision.reason()),
                    blocked_now,
                    &channel,
                ));
            }

            if enforce && decision.is_block() && blocked_paths.insert(image.clone()) {
                // Install an app-id BLOCK for this concrete exe path.
                let specs = wfp::plan_tool_block(&image, wfp::DEFAULT_WEIGHT);
                match wfp::apply(&specs, wfp::WfpMode::Live) {
                    Ok(o) => tracing::warn!(image = %image, ?o, "installed remote-tool app-id block"),
                    Err(e) => tracing::error!(image = %image, error = %e, "tool block install failed"),
                }
                // A `kill` action additionally terminates the process (live kill
                // is admin + --enforce, operator-manual; never exercised by tests).
                if let Some(m) = policy.remote_tools.match_app(&image) {
                    if m.action == ToolAction::Kill {
                        match terminate_process(pid) {
                            Ok(()) => tracing::warn!(pid, image = %image, "terminated remote-tool process"),
                            Err(e) => tracing::warn!(pid, error = %e, "process terminate failed"),
                        }
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

/// Enumerate running processes and return `(pid, full_image_path)` for those that
/// match a remote-access-tool signature. Windows-only. Best-effort: a process we
/// cannot open (higher privilege) is skipped.
#[cfg(windows)]
pub(crate) fn list_remote_tool_processes() -> Vec<(u32, String)> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::ProcessStatus::EnumProcesses;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let mut out = Vec::new();
    let mut pids = vec![0u32; 4096];
    let mut needed = 0u32;
    let ok = unsafe {
        EnumProcesses(
            pids.as_mut_ptr(),
            (pids.len() * std::mem::size_of::<u32>()) as u32,
            &mut needed,
        )
    };
    if ok.is_err() {
        tracing::warn!("EnumProcesses failed");
        return out;
    }
    let count = needed as usize / std::mem::size_of::<u32>();
    for &pid in pids.iter().take(count) {
        if pid == 0 {
            continue;
        }
        let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
            Ok(h) => h,
            Err(_) => continue, // access denied / gone — skip
        };
        let mut buf = vec![0u16; 1024];
        let mut size = buf.len() as u32;
        let r = unsafe {
            QueryFullProcessImageNameW(handle, PROCESS_NAME_FORMAT(0), PWSTR(buf.as_mut_ptr()), &mut size)
        };
        unsafe {
            let _ = CloseHandle(handle);
        }
        if r.is_err() {
            continue;
        }
        let image = String::from_utf16_lossy(&buf[..size as usize]);
        if remote_tools::match_image(&image).is_some() {
            out.push((pid, image));
        }
    }
    out
}

/// Terminate a process by PID. Windows-only, admin + `--enforce`, operator-manual.
#[cfg(windows)]
fn terminate_process(pid: u32) -> anyhow::Result<()> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) }?;
    let r = unsafe { TerminateProcess(handle, 1) };
    unsafe {
        let _ = CloseHandle(handle);
    }
    r?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Non-Windows stub so the crate builds cross-platform (tests, CI).
// ---------------------------------------------------------------------------
#[cfg(not(windows))]
pub fn run_monitor<R>(cfg: &Config, _storage: &Storage, mode: NetMode, _report: R)
where
    R: FnMut(UsbIncident),
{
    let policy = build_policy(&cfg.netfilter, mode);
    tracing::warn!(
        ?mode,
        rules = policy.rules.len(),
        "network egress control is only available on Windows — monitor idle"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetfilterConfig;

    #[test]
    fn build_policy_carries_mode_and_default_tool_action() {
        let nf = NetfilterConfig::default();
        let p = build_policy(&nf, NetMode::Blocklist);
        assert_eq!(p.mode, NetMode::Blocklist);
        // Decoupled: remote-tool action defaults to detect-only (never blocks).
        assert_eq!(p.remote_tools.default_action, ToolAction::Detect);
        assert!(p.rules.is_empty());
    }

    #[test]
    fn network_incident_has_no_verdict_and_metadata_only() {
        let inc = network_incident("anydesk.exe", "remote-tool=anydesk".into(), true, "network");
        assert!(inc.verdict.is_none(), "network incidents are metadata-only (logged, not posted)");
        assert_eq!(inc.device.bus_type, "network");
        assert_eq!(inc.action_taken, ActionTaken::Blocked);
        assert!(inc.file_sha256.is_empty());
    }
}
