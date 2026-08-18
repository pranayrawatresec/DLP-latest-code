//! Endpoint read-deny policy.
//!
//! Fetched from the console over mTLS (`GET /agent/read-deny-policy`) and APPLIED
//! to the kernel driver programmatically — the driver's mode/fail registry knobs
//! and the fixed-volume attach — so the operator never runs `reg add` or
//! `fltmc attach`. The [kguard] read-deny fields (on/off, posture, scope) are then
//! overridden from this central policy, so an admin configures everything in the
//! console and it flows down to every endpoint automatically.

use serde::{Deserialize, Serialize};

use crate::config::{Config, ExfilPosture};

/// The read-deny policy as delivered by the server. Field names match the
/// server's camelCase JSON. Every field defaults so a partial/old server response
/// still parses to the safe (off) state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadDenyPolicy {
    /// `off` | `monitor` | `enforce`.
    #[serde(default = "default_mode")]
    pub mode: String,
    /// `allowlist` | `blocklist`.
    #[serde(default = "default_posture")]
    pub posture: String,
    #[serde(default, rename = "scanFixed")]
    pub scan_fixed: bool,
    #[serde(default, rename = "watchPaths")]
    pub watch_paths: Vec<String>,
    #[serde(default, rename = "failBlock")]
    pub fail_block: bool,
}

fn default_mode() -> String {
    "off".into()
}
fn default_posture() -> String {
    "blocklist".into()
}

impl Default for ReadDenyPolicy {
    fn default() -> Self {
        ReadDenyPolicy {
            mode: "off".into(),
            posture: "blocklist".into(),
            scan_fixed: false,
            watch_paths: Vec::new(),
            fail_block: false,
        }
    }
}

impl ReadDenyPolicy {
    /// Driver `ExfilReadBlockEnabled` value: 0=off, 1=enforce, 2=monitor.
    pub fn driver_mode(&self) -> u32 {
        match self.mode.as_str() {
            "enforce" => 1,
            "monitor" => 2,
            _ => 0,
        }
    }
    /// Run the untrusted-reader pusher whenever the mode is not off.
    pub fn read_block(&self) -> bool {
        self.mode != "off"
    }
    pub fn exfil_posture(&self) -> ExfilPosture {
        if self.posture == "allowlist" {
            ExfilPosture::Allowlist
        } else {
            ExfilPosture::Blocklist
        }
    }
}

impl Config {
    /// Produce an effective config whose `[kguard]` read-deny fields come from the
    /// console policy (mode → on/off, posture, scope, fail), overriding the local
    /// `agent.toml`. The central policy is authoritative for these — they are
    /// configured in the console, never per-machine.
    pub fn with_read_deny_policy(&self, p: &ReadDenyPolicy) -> Config {
        let mut merged = self.clone();
        merged.kguard.exfil_read_block = p.read_block();
        merged.kguard.exfil_posture = p.exfil_posture();
        merged.kguard.scan_fixed = p.scan_fixed;
        merged.kguard.watch_paths = p.watch_paths.clone();
        merged.kguard.fail_block = p.fail_block;
        merged
    }
}

/// Apply the driver-side knobs this policy implies — with NO command line:
///   * write the read-deny mode + fail behaviour to the driver's registry key
///     (the `reg add` an operator would otherwise run), and
///   * attach the filter to C: when fixed-drive scanning is on (the `fltmc attach`).
/// Requires the agent to run elevated / as SYSTEM (the LocalSystem service does).
/// Best-effort: each step logs on failure and the guard still runs.
#[cfg(windows)]
pub fn apply_to_driver(p: &ReadDenyPolicy) {
    write_driver_knobs(p.driver_mode(), p.fail_block);
    if p.scan_fixed {
        attach_filter_to_volume("dlpflt", "C:");
    }
}

#[cfg(not(windows))]
pub fn apply_to_driver(_p: &ReadDenyPolicy) {}

/// Write the driver's read-deny registry DWORDs (read at driver load; the running
/// mode is also set live via the config message). Replaces the manual `reg add`.
#[cfg(windows)]
fn write_driver_knobs(mode: u32, fail_block: bool) {
    use windows::core::w;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{RegSetKeyValueW, HKEY_LOCAL_MACHINE, REG_DWORD};

    let svc = w!("SYSTEM\\CurrentControlSet\\Services\\dlpflt");
    let set = |name: windows::core::PCWSTR, val: u32| {
        let rc = unsafe {
            RegSetKeyValueW(
                HKEY_LOCAL_MACHINE,
                svc,
                name,
                REG_DWORD.0,
                Some(&val as *const u32 as *const core::ffi::c_void),
                std::mem::size_of::<u32>() as u32,
            )
        };
        if rc != ERROR_SUCCESS {
            tracing::warn!(rc = rc.0, "could not write a read-deny driver knob (needs SYSTEM/elevated)");
        }
    };
    set(w!("ExfilReadBlockEnabled"), mode);
    set(w!("ExfilReadFailBlock"), if fail_block { 1 } else { 0 });
    tracing::info!(mode, fail_block, "applied read-deny driver knobs from console policy");
}

/// Attach the minifilter to a fixed volume via the FltMgr API — the programmatic
/// equivalent of `fltmc attach dlpflt C:`. "Already attached" is success.
#[cfg(windows)]
fn attach_filter_to_volume(filter: &str, volume: &str) {
    use windows::core::{HSTRING, PCWSTR, PWSTR};
    use windows::Win32::Storage::InstallableFileSystems::FilterAttach;

    let f = HSTRING::from(filter);
    let v = HSTRING::from(volume);
    match unsafe { FilterAttach(&f, &v, PCWSTR::null(), 0, PWSTR::null()) } {
        Ok(()) => tracing::info!(volume, "attached read-deny filter to fixed volume"),
        Err(e) => {
            // ERROR_FLT_INSTANCE_NAME_COLLISION (already attached) is expected/fine.
            tracing::info!(volume, error = %e, "filter attach to volume (already-attached is OK)");
        }
    }
}
