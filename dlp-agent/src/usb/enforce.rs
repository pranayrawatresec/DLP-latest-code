//! Apply a policy action to a device (spec §3.4). ⚠️ This module can modify the
//! live system, so it is built around a **dry-run** contract: `plan()` computes
//! a `PlannedAction` describing exactly what would change, and `apply()` will
//! only touch the system when explicitly told to (`Mode::Live`). Every
//! automated test uses `Mode::DryRun` and asserts on the plan — no test ever
//! sets `WriteProtect`, disables a devnode, or dismounts a volume (spec §7).
//!
//! Live enforcement is additionally gated by the `--enforce` CLI flag AND a
//! config opt-in in `run_monitor`; the default is audit-only.

use super::device::DeviceIdentity;
use super::policy::Action;

/// The registry location that forces removable media read-only fleet-wide.
pub const WRITE_PROTECT_KEY: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies";
pub const WRITE_PROTECT_VALUE: &str = "WriteProtect";

/// The WPD device-setup-class policy key (spec §2.1). `Deny_Read`/`Deny_Write`
/// DWORDs here (=1 to deny) block MTP/PTP phones and cameras that expose files
/// through the Windows Portable Devices stack — devices that never mount a
/// drive letter and so escape the mass-storage `WriteProtect` control.
pub const WPD_DENY_KEY: &str =
    r"HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{6AC27878-A6FA-4155-BA85-F98F491D4F33}";
pub const WPD_DENY_READ_VALUE: &str = "Deny_Read";
pub const WPD_DENY_WRITE_VALUE: &str = "Deny_Write";

/// Device Installation Restriction key for USB-tethering (RNDIS/NCM) network
/// adapters (spec §2.2). Live blocking adds the net device-setup class to the
/// denied-classes list here; the concrete devnode disable is operator-manual.
pub const TETHERING_DENY_KEY: &str =
    r"HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses";
/// The net device setup class GUID (RNDIS/NCM adapters install under it).
pub const NET_CLASS_GUID: &str = "{4d36e972-e325-11ce-bfc1-08002be10318}";

/// A concrete, inspectable description of what enforcement *would* do. Returned
/// by `plan()` and asserted by tests without executing anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedAction {
    /// `AllowAudited` → no system change (auditing still happens elsewhere).
    NoChange,
    /// `ReadOnly` → set `WriteProtect=1`.
    SetWriteProtect {
        key: String,
        value_name: String,
        value: u32,
    },
    /// Revert read-only → set `WriteProtect=0` (spec §5 edge 14).
    ClearWriteProtect {
        key: String,
        value_name: String,
        value: u32,
    },
    /// `Block` → dismount the volume so it cannot be written. (The stronger
    /// `CM_Disable_DevNode` on the device instance is the design-only
    /// alternative — see docs; dismount is what this build implements.)
    DismountVolume { drive_letter: String },
    /// MTP/WPD enforcement (spec §2.1): set `Deny_Read`/`Deny_Write` under the
    /// WPD device-setup-class policy key. `read`/`write` are the deny flags
    /// (`Block` → both true, `ReadOnly` → write only, `AllowAudited` →
    /// `NoChange`). Live registry write is behind `--enforce`, MANUAL.
    SetWpdDeny { read: bool, write: bool },
    /// Revert MTP/WPD enforcement → clear the `Deny_*` DWORDs.
    ClearWpdDeny,
    /// USB-tethering block (spec §2.2): restrict install of the net device
    /// setup class so an RNDIS/NCM adapter cannot bring up an egress path.
    /// Live path is a Device Installation Restriction registry write / devnode
    /// disable — MANUAL.
    BlockTethering,
}

/// Whether an `apply()` is allowed to touch the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    DryRun,
    Live,
}

/// Outcome of applying an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Nothing needed doing.
    NoChange,
    /// Dry-run only: reports the plan that would have run.
    Planned(PlannedAction),
    /// Live enforcement succeeded.
    Executed(PlannedAction),
}

/// Compute the enforcement plan for an action against a device. Pure — no I/O.
pub fn plan(action: Action, dev: &DeviceIdentity) -> PlannedAction {
    match action {
        Action::AllowAudited => PlannedAction::NoChange,
        // Encrypt-on-write (spec §3.1/§5.1): at DEVICE level nothing changes —
        // writes proceed. The per-file seal on the volume is the copy
        // auditor's job (M3), not device enforcement.
        Action::Encrypt => PlannedAction::NoChange,
        Action::ReadOnly => PlannedAction::SetWriteProtect {
            key: WRITE_PROTECT_KEY.to_string(),
            value_name: WRITE_PROTECT_VALUE.to_string(),
            value: 1,
        },
        Action::Block => PlannedAction::DismountVolume {
            drive_letter: dev.drive_letter.clone(),
        },
    }
}

/// The plan to revert a previously-applied read-only enforcement (edge 14).
pub fn plan_revert_read_only() -> PlannedAction {
    PlannedAction::ClearWriteProtect {
        key: WRITE_PROTECT_KEY.to_string(),
        value_name: WRITE_PROTECT_VALUE.to_string(),
        value: 0,
    }
}

/// Compute the WPD/MTP enforcement plan for an action (spec §2.1). Pure — no
/// I/O. `Block` denies both read and write; `ReadOnly` denies write only;
/// `AllowAudited` changes nothing (the phone is still noted as an incident).
pub fn plan_mtp(action: Action) -> PlannedAction {
    match action {
        Action::AllowAudited => PlannedAction::NoChange,
        // MTP/WPD devices never mount a volume, so the copy auditor (which
        // performs the file-level seal) can never run there — `Encrypt`
        // cannot be honoured. Fail secure: deny writes (same as ReadOnly)
        // rather than silently allowing unarmoured copies.
        Action::Encrypt => PlannedAction::SetWpdDeny { read: false, write: true },
        Action::ReadOnly => PlannedAction::SetWpdDeny { read: false, write: true },
        Action::Block => PlannedAction::SetWpdDeny { read: true, write: true },
    }
}

/// The plan to revert a previously-applied MTP/WPD enforcement.
pub fn plan_revert_mtp() -> PlannedAction {
    PlannedAction::ClearWpdDeny
}

/// Compute the USB-tethering enforcement plan for an action (spec §2.2). Pure.
/// Only `Block` restricts; anything else is a no-op (tethering is allow/block).
pub fn plan_tethering(action: Action) -> PlannedAction {
    match action {
        Action::Block => PlannedAction::BlockTethering,
        // Tethering is allow/block only: ReadOnly has always been a no-op
        // here, and there is no file stream to seal, so Encrypt is too.
        // Explicit arms (no catch-all) so a future Action variant is flagged.
        Action::AllowAudited | Action::Encrypt | Action::ReadOnly => PlannedAction::NoChange,
    }
}

/// Apply a plan. In `Mode::DryRun` this executes NOTHING and returns
/// `Planned(..)`. In `Mode::Live` it performs the real operation (Windows) and
/// returns `Executed(..)`; failures are surfaced as `Err` so the caller can
/// degrade to audit + an "enforcement-failed" incident (spec §3.4) rather than
/// crash.
pub fn apply(plan: &PlannedAction, mode: Mode) -> anyhow::Result<ApplyOutcome> {
    if matches!(plan, PlannedAction::NoChange) {
        return Ok(ApplyOutcome::NoChange);
    }
    match mode {
        Mode::DryRun => Ok(ApplyOutcome::Planned(plan.clone())),
        Mode::Live => {
            execute_live(plan)?;
            Ok(ApplyOutcome::Executed(plan.clone()))
        }
    }
}

// ---------------------------------------------------------------------------
// Live execution (Windows only). Never reached by tests. On non-Windows this is
// a stub so the library builds cross-platform.
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn execute_live(plan: &PlannedAction) -> anyhow::Result<()> {
    match plan {
        PlannedAction::NoChange => Ok(()),
        PlannedAction::SetWriteProtect { value, .. } => set_write_protect(*value),
        PlannedAction::ClearWriteProtect { value, .. } => set_write_protect(*value),
        PlannedAction::DismountVolume { drive_letter } => dismount_volume(drive_letter),
        PlannedAction::SetWpdDeny { read, write } => set_wpd_deny(*read, *write),
        PlannedAction::ClearWpdDeny => set_wpd_deny(false, false),
        PlannedAction::BlockTethering => block_tethering(),
    }
}

#[cfg(not(windows))]
fn execute_live(_plan: &PlannedAction) -> anyhow::Result<()> {
    anyhow::bail!("live USB enforcement is only available on Windows")
}

/// Set (or clear) the `WriteProtect` DWORD under `StorageDevicePolicies`.
/// Requires administrator/SYSTEM; a failure is returned to the caller.
#[cfg(windows)]
fn set_write_protect(value: u32) -> anyhow::Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
        REG_DWORD, REG_OPTION_NON_VOLATILE,
    };

    let subkey: Vec<u16> = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let name: Vec<u16> = "WriteProtect".encode_utf16().chain(std::iter::once(0)).collect();

    let mut hkey = HKEY::default();
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut hkey,
            None,
        )
    };
    if rc != ERROR_SUCCESS {
        anyhow::bail!("RegCreateKeyEx(StorageDevicePolicies) failed: {rc:?} (need admin/SYSTEM)");
    }
    let bytes = value.to_le_bytes();
    let set = unsafe { RegSetValueExW(hkey, PCWSTR(name.as_ptr()), 0, REG_DWORD, Some(&bytes)) };
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    if set != ERROR_SUCCESS {
        anyhow::bail!("RegSetValueEx(WriteProtect={value}) failed: {set:?}");
    }
    tracing::warn!(write_protect = value, "live enforcement: set WriteProtect");
    Ok(())
}

/// Set (or clear) a DWORD value under an `HKLM\...` subkey. Shared by the WPD
/// and tethering enforcement paths. Requires administrator/SYSTEM.
#[cfg(windows)]
fn set_hklm_dword(subkey: &str, value_name: &str, value: u32) -> anyhow::Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
        REG_DWORD, REG_OPTION_NON_VOLATILE,
    };

    let subkey_w: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let name_w: Vec<u16> = value_name.encode_utf16().chain(std::iter::once(0)).collect();

    let mut hkey = HKEY::default();
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_w.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut hkey,
            None,
        )
    };
    if rc != ERROR_SUCCESS {
        anyhow::bail!("RegCreateKeyEx({subkey}) failed: {rc:?} (need admin/SYSTEM)");
    }
    let bytes = value.to_le_bytes();
    let set = unsafe { RegSetValueExW(hkey, PCWSTR(name_w.as_ptr()), 0, REG_DWORD, Some(&bytes)) };
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    if set != ERROR_SUCCESS {
        anyhow::bail!("RegSetValueEx({value_name}={value}) failed: {set:?}");
    }
    Ok(())
}

/// Apply MTP/WPD deny policy (spec §2.1): write `Deny_Read`/`Deny_Write` under
/// the WPD device-setup-class policy key. `false` clears the flag (revert).
/// Requires administrator/SYSTEM; a failure is returned to the caller.
#[cfg(windows)]
fn set_wpd_deny(read: bool, write: bool) -> anyhow::Result<()> {
    // Strip the leading "HKLM\" the public constant carries for display.
    let subkey = WPD_DENY_KEY.trim_start_matches(r"HKLM\");
    set_hklm_dword(subkey, WPD_DENY_READ_VALUE, u32::from(read))?;
    set_hklm_dword(subkey, WPD_DENY_WRITE_VALUE, u32::from(write))?;
    tracing::warn!(deny_read = read, deny_write = write, "live enforcement: set WPD deny policy");
    Ok(())
}

/// Block USB tethering (spec §2.2) by adding the net device setup class to the
/// Device Installation Restriction deny list. This prevents a NEW RNDIS/NCM
/// adapter from installing; disabling an already-present devnode is a separate,
/// operator-manual step. Requires administrator/SYSTEM.
#[cfg(windows)]
fn block_tethering() -> anyhow::Result<()> {
    let subkey = TETHERING_DENY_KEY.trim_start_matches(r"HKLM\");
    // The DenyDeviceClasses list is keyed by ordinal value-name; "1" = first
    // entry. Also flip DenyDeviceClasses master switch on under its parent.
    set_hklm_dword(
        r"Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
        "DenyDeviceClasses",
        1,
    )?;
    // Value-name "1" -> the net class GUID string (REG_SZ). Reuse a string write.
    set_hklm_string(subkey, "1", NET_CLASS_GUID)?;
    tracing::warn!(class = NET_CLASS_GUID, "live enforcement: denied net device class (tethering)");
    Ok(())
}

/// Set a REG_SZ string value under an `HKLM\...` subkey (tethering deny list).
#[cfg(windows)]
fn set_hklm_string(subkey: &str, value_name: &str, value: &str) -> anyhow::Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
        REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    let subkey_w: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let name_w: Vec<u16> = value_name.encode_utf16().chain(std::iter::once(0)).collect();
    let val_w: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();

    let mut hkey = HKEY::default();
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_w.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut hkey,
            None,
        )
    };
    if rc != ERROR_SUCCESS {
        anyhow::bail!("RegCreateKeyEx({subkey}) failed: {rc:?} (need admin/SYSTEM)");
    }
    // REG_SZ payload is the UTF-16 string INCLUDING its NUL terminator, as bytes.
    let bytes: Vec<u8> = val_w.iter().flat_map(|u| u.to_le_bytes()).collect();
    let set = unsafe { RegSetValueExW(hkey, PCWSTR(name_w.as_ptr()), 0, REG_SZ, Some(&bytes)) };
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    if set != ERROR_SUCCESS {
        anyhow::bail!("RegSetValueEx({value_name}) failed: {set:?}");
    }
    Ok(())
}

/// Lock + dismount a volume so pending/new writes cannot land. Requires
/// administrator/SYSTEM. Best-effort: a busy volume yields an error the caller
/// turns into an "enforcement-failed" incident.
#[cfg(windows)]
fn dismount_volume(drive_letter: &str) -> anyhow::Result<()> {
    use anyhow::Context;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Ioctl::{FSCTL_DISMOUNT_VOLUME, FSCTL_LOCK_VOLUME};
    use windows::Win32::System::IO::DeviceIoControl;

    let path = drive_letter.trim_end_matches('\\').trim_end_matches('/');
    let device = format!(r"\\.\{path}");
    let wide: Vec<u16> = device.encode_utf16().chain(std::iter::once(0)).collect();

    let handle: HANDLE = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .with_context(|| format!("opening {device} for dismount"))?;

    let mut returned = 0u32;
    let lock = unsafe {
        DeviceIoControl(handle, FSCTL_LOCK_VOLUME, None, 0, None, 0, Some(&mut returned), None)
    };
    let dismount = unsafe {
        DeviceIoControl(handle, FSCTL_DISMOUNT_VOLUME, None, 0, None, 0, Some(&mut returned), None)
    };
    unsafe {
        let _ = CloseHandle(handle);
    }
    lock.with_context(|| format!("locking {device}"))?;
    dismount.with_context(|| format!("dismounting {device}"))?;
    tracing::warn!(drive = %path, "live enforcement: dismounted volume");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::device::DeviceIdentity;

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

    #[test]
    fn allow_plans_no_change() {
        assert_eq!(plan(Action::AllowAudited, &dev()), PlannedAction::NoChange);
    }

    #[test]
    fn read_only_plans_write_protect() {
        let p = plan(Action::ReadOnly, &dev());
        assert_eq!(
            p,
            PlannedAction::SetWriteProtect {
                key: WRITE_PROTECT_KEY.to_string(),
                value_name: WRITE_PROTECT_VALUE.to_string(),
                value: 1,
            }
        );
    }

    #[test]
    fn block_plans_dismount_of_the_right_volume() {
        let p = plan(Action::Block, &dev());
        assert_eq!(p, PlannedAction::DismountVolume { drive_letter: "E:".into() });
    }

    #[test]
    fn revert_plans_clear_write_protect() {
        assert_eq!(
            plan_revert_read_only(),
            PlannedAction::ClearWriteProtect {
                key: WRITE_PROTECT_KEY.to_string(),
                value_name: WRITE_PROTECT_VALUE.to_string(),
                value: 0,
            }
        );
    }

    #[test]
    fn dry_run_apply_executes_nothing_and_returns_the_plan() {
        // The core safety property: dry-run must NOT touch the system.
        let p = plan(Action::ReadOnly, &dev());
        let outcome = apply(&p, Mode::DryRun).expect("dry-run never fails");
        assert_eq!(outcome, ApplyOutcome::Planned(p));
    }

    #[test]
    fn dry_run_block_returns_plan_without_dismount() {
        let p = plan(Action::Block, &dev());
        let outcome = apply(&p, Mode::DryRun).expect("dry-run never fails");
        assert_eq!(outcome, ApplyOutcome::Planned(PlannedAction::DismountVolume {
            drive_letter: "E:".into(),
        }));
    }

    #[test]
    fn no_change_apply_is_noop_in_any_mode() {
        assert_eq!(apply(&PlannedAction::NoChange, Mode::DryRun).unwrap(), ApplyOutcome::NoChange);
        // Even "Live" mode is a no-op for NoChange — nothing to execute.
        assert_eq!(apply(&PlannedAction::NoChange, Mode::Live).unwrap(), ApplyOutcome::NoChange);
    }

    // --- MTP/WPD + tethering enforcement (spec §2) -------------------------

    #[test]
    fn mtp_block_plans_deny_read_and_write() {
        assert_eq!(plan_mtp(Action::Block), PlannedAction::SetWpdDeny { read: true, write: true });
    }

    #[test]
    fn mtp_read_only_plans_deny_write_only() {
        assert_eq!(plan_mtp(Action::ReadOnly), PlannedAction::SetWpdDeny { read: false, write: true });
    }

    #[test]
    fn mtp_allow_plans_no_change() {
        assert_eq!(plan_mtp(Action::AllowAudited), PlannedAction::NoChange);
    }

    #[test]
    fn mtp_revert_clears_deny() {
        assert_eq!(plan_revert_mtp(), PlannedAction::ClearWpdDeny);
    }

    #[test]
    fn tethering_block_plans_block_tethering() {
        assert_eq!(plan_tethering(Action::Block), PlannedAction::BlockTethering);
    }

    #[test]
    fn tethering_non_block_is_no_change() {
        assert_eq!(plan_tethering(Action::AllowAudited), PlannedAction::NoChange);
        assert_eq!(plan_tethering(Action::ReadOnly), PlannedAction::NoChange);
    }

    #[test]
    fn dry_run_wpd_deny_executes_nothing_and_returns_plan() {
        // The core safety property for the new action: dry-run must NOT write
        // to the registry.
        let p = plan_mtp(Action::Block);
        let outcome = apply(&p, Mode::DryRun).expect("dry-run never fails");
        assert_eq!(outcome, ApplyOutcome::Planned(PlannedAction::SetWpdDeny { read: true, write: true }));
    }

    // --- Trusted-destination encryption (encrypt-on-write spec §3.1) --------

    #[test]
    fn encrypt_plans_no_change_at_device_level() {
        // The seal is the copy auditor's job (M3); device enforcement does
        // nothing for an Encrypt destination.
        assert_eq!(plan(Action::Encrypt, &dev()), PlannedAction::NoChange);
    }

    #[test]
    fn mtp_encrypt_fails_secure_to_write_deny() {
        // No auditor ever runs on MTP (no drive letter), so Encrypt cannot be
        // honoured there — it must NOT silently allow unarmoured writes.
        assert_eq!(
            plan_mtp(Action::Encrypt),
            PlannedAction::SetWpdDeny { read: false, write: true }
        );
    }

    #[test]
    fn tethering_encrypt_is_no_change_like_read_only() {
        assert_eq!(plan_tethering(Action::Encrypt), PlannedAction::NoChange);
    }

    #[test]
    fn dry_run_block_tethering_executes_nothing() {
        let p = plan_tethering(Action::Block);
        let outcome = apply(&p, Mode::DryRun).expect("dry-run never fails");
        assert_eq!(outcome, ApplyOutcome::Planned(PlannedAction::BlockTethering));
    }
}
