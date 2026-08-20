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
    /// `central` | `merge`. `merge` (default) unions the console list with the
    /// endpoint's local `[[trusted_readers]]` (today's behaviour); `central` makes
    /// the console list the WHOLE allowlist so HQ can revoke a locally-typed rule
    /// (#9). An old/partial server response defaults to the back-compat `merge`.
    #[serde(default = "default_authority", rename = "readersAuthority")]
    pub readers_authority: String,
}

fn default_mode() -> String {
    "off".into()
}
fn default_posture() -> String {
    "blocklist".into()
}
fn default_authority() -> String {
    "merge".into()
}

impl Default for ReadDenyPolicy {
    fn default() -> Self {
        ReadDenyPolicy {
            mode: "off".into(),
            posture: "blocklist".into(),
            scan_fixed: false,
            watch_paths: Vec::new(),
            fail_block: false,
            readers_authority: "merge".into(),
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
    /// True when the console list is authoritative — local `[[trusted_readers]]`
    /// must be ignored so the central policy can revoke any endpoint-typed rule
    /// (#9). Defaults to false (`merge`), preserving today's union behaviour.
    pub fn readers_central(&self) -> bool {
        self.readers_authority == "central"
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
        // Carry the reader-allowlist authority to the exfil pusher so an EMPTY
        // console list under central authority fails secure (lockdown) instead of
        // being read as "unconfigured" (#9). Must be set alongside the readers merge
        // in `with_synced_readers(_, p.readers_central())`.
        merged.kguard.readers_central = p.readers_central();
        merged
    }
}

/// Apply the driver-side knobs this policy implies — with NO command line:
///   * write the read-deny mode + fail behaviour to the driver's registry key
///     (the `reg add` an operator would otherwise run).
/// The fixed-volume *attach* (the `fltmc attach`) is NOT done here: it must run
/// AFTER the driver has the watch-set (ScanFixed=1/WatchCount>0), otherwise the
/// driver's InstanceSetup answers STATUS_FLT_DO_NOT_ATTACH. The guard owns the
/// single \DlpFltPort connection and performs the attach right after it sends the
/// config, in the correct order — see [crate::kguard::run] / [attach_fixed_volume].
/// Requires the agent to run elevated / as SYSTEM (the LocalSystem service does).
/// Best-effort: each step logs on failure and the guard still runs.
#[cfg(windows)]
pub fn apply_to_driver(p: &ReadDenyPolicy) {
    write_driver_knobs(p.driver_mode(), p.fail_block);
    // Persist the fixed-volume scope so the driver can seed it at boot and attach
    // C: at mount time (before the agent is up) — otherwise a reboot leaves fixed
    // volumes unwatched until the guard reconnects (audit item #8). The runtime
    // DLP_CONFIG message (guard startup) remains the live-update path.
    write_scan_scope(p.scan_fixed, &p.watch_paths);
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

/// Persist the fixed-volume scan scope to the driver's registry key so the driver
/// seeds it at boot (DlpReadScanScope) and attaches C: at mount time — the boot-
/// persistence half of the fixed-volume attach. Writes `ExfilScanFixed` (DWORD)
/// and `ExfilWatchPaths` (REG_MULTI_SZ, one string per prefix). When fixed scanning
/// is off (or no paths), writes an EMPTY MULTI_SZ so a previously-seeded value can
/// never re-attach C: at the next boot. Requires SYSTEM/elevated (the service).
#[cfg(windows)]
fn write_scan_scope(scan_fixed: bool, watch_paths: &[String]) {
    use windows::core::w;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegSetKeyValueW, HKEY_LOCAL_MACHINE, REG_DWORD, REG_MULTI_SZ,
    };

    let svc = w!("SYSTEM\\CurrentControlSet\\Services\\dlpflt");

    // ExfilScanFixed (DWORD).
    let sf: u32 = if scan_fixed { 1 } else { 0 };
    let rc = unsafe {
        RegSetKeyValueW(
            HKEY_LOCAL_MACHINE,
            svc,
            w!("ExfilScanFixed"),
            REG_DWORD.0,
            Some(&sf as *const u32 as *const core::ffi::c_void),
            std::mem::size_of::<u32>() as u32,
        )
    };
    if rc != ERROR_SUCCESS {
        tracing::warn!(rc = rc.0, "could not write ExfilScanFixed (needs SYSTEM/elevated)");
    }

    // ExfilWatchPaths (REG_MULTI_SZ): each prefix as a NUL-terminated UTF-16 string,
    // then a final NUL. An empty list is a single NUL (clears any stale seed). Only
    // emit real prefixes when fixed scanning is actually on.
    let mut buf: Vec<u16> = Vec::new();
    if scan_fixed {
        for prefix in watch_paths.iter().take(16) {
            if prefix.is_empty() {
                continue;
            }
            buf.extend(prefix.encode_utf16());
            buf.push(0);
        }
    }
    buf.push(0); // final terminator (also the whole value when the list is empty)
    let bytes = (buf.len() * std::mem::size_of::<u16>()) as u32;
    let rc = unsafe {
        RegSetKeyValueW(
            HKEY_LOCAL_MACHINE,
            svc,
            w!("ExfilWatchPaths"),
            REG_MULTI_SZ.0,
            Some(buf.as_ptr() as *const core::ffi::c_void),
            bytes,
        )
    };
    if rc != ERROR_SUCCESS {
        tracing::warn!(rc = rc.0, "could not write ExfilWatchPaths (needs SYSTEM/elevated)");
    }
}

/// Attach the `dlpflt` minifilter to a fixed volume via the FltMgr API — the
/// programmatic equivalent of `fltmc attach dlpflt C:`. "Already attached" is
/// success. MUST be called only after the driver has the fixed-volume watch-set
/// (see the call site in [crate::kguard::run], right after `send_config`), or the
/// driver's InstanceSetup returns STATUS_FLT_DO_NOT_ATTACH.
#[cfg(windows)]
pub fn attach_fixed_volume(volume: &str) {
    use windows::core::{HSTRING, PCWSTR, PWSTR};
    use windows::Win32::Storage::InstallableFileSystems::FilterAttach;

    let f = HSTRING::from("dlpflt");
    let v = HSTRING::from(volume);
    match unsafe { FilterAttach(&f, &v, PCWSTR::null(), 0, PWSTR::null()) } {
        Ok(()) => tracing::info!(volume, "attached read-deny filter to fixed volume"),
        Err(e) => {
            // ERROR_FLT_INSTANCE_NAME_COLLISION (already attached) is expected/fine.
            tracing::info!(volume, error = %e, "filter attach to volume (already-attached is OK)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readers_authority_defaults_to_merge_when_absent() {
        // An old/partial server response (no readersAuthority) must default to the
        // back-compat 'merge' — never silently flip an endpoint to 'central'.
        let p: ReadDenyPolicy =
            serde_json::from_str(r#"{"mode":"enforce","posture":"allowlist"}"#).unwrap();
        assert_eq!(p.readers_authority, "merge");
        assert!(!p.readers_central());
    }

    #[test]
    fn readers_central_only_for_central() {
        let central: ReadDenyPolicy =
            serde_json::from_str(r#"{"readersAuthority":"central"}"#).unwrap();
        assert!(central.readers_central());

        let merge: ReadDenyPolicy =
            serde_json::from_str(r#"{"readersAuthority":"merge"}"#).unwrap();
        assert!(!merge.readers_central());

        // An unrecognised value fails safe to NOT central (keeps local trust).
        let weird: ReadDenyPolicy =
            serde_json::from_str(r#"{"readersAuthority":"bogus"}"#).unwrap();
        assert!(!weird.readers_central());

        // The Default is merge.
        assert!(!ReadDenyPolicy::default().readers_central());
    }
}
