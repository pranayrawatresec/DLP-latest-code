//! Removable-volume enumeration + device identity (spec §3.1).
//!
//! The parsing of a `STORAGE_DEVICE_DESCRIPTOR` byte buffer into a
//! `DeviceIdentity` is factored into the pure function
//! `parse_storage_descriptor`, which a unit test drives with a hand-built
//! synthetic buffer — no hardware, no Windows API. The live IOCTL call
//! (`query_device_identity`) is a thin `#[cfg(windows)]` wrapper that fills the
//! buffer and delegates to the pure parser; it is compiled but not unit-tested.
//!
//! CRITICAL classification rule (spec §3.1): do NOT trust the drive *type*.
//! External USB SSDs/HDDs frequently report `DRIVE_FIXED`. We classify
//! removability from the **bus type** (`BusTypeUsb`/`BusTypeSd`/`BusTypeMmc`),
//! which catches USB SSDs and avoids flagging the internal OS disk.

/// Everything we can learn about a mounted volume's backing device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    /// e.g. "E:". Filled by the enumerator, not the descriptor parser.
    pub drive_letter: String,
    /// Vendor id string from the descriptor (trimmed). May be empty.
    pub vendor_id: String,
    /// Product id string from the descriptor (trimmed). May be empty.
    pub product_id: String,
    /// Device serial from the descriptor (trimmed). Spoofable — allowlist only.
    pub serial: String,
    /// Human-ish product name (vendor + product) for display/logs.
    pub product_name: String,
    /// Canonical lowercase bus type, e.g. "usb", "sd", "mmc", "sata", "nvme".
    pub bus_type: String,
    /// Whether we treat this device as removable (bus-type driven, see above).
    pub removable: bool,
}

// STORAGE_BUS_TYPE values (winioctl.h). Kept as a local table so the pure
// parser has no Windows dependency and builds cross-platform.
const BUS_TYPE_NAMES: &[(u32, &str)] = &[
    (0x00, "unknown"),
    (0x01, "scsi"),
    (0x02, "atapi"),
    (0x03, "ata"),
    (0x04, "1394"),
    (0x05, "ssa"),
    (0x06, "fibre"),
    (0x07, "usb"),
    (0x08, "raid"),
    (0x09, "iscsi"),
    (0x0A, "sas"),
    (0x0B, "sata"),
    (0x0C, "sd"),
    (0x0D, "mmc"),
    (0x0E, "virtual"),
    (0x0F, "file-backed-virtual"),
    (0x10, "spaces"),
    (0x11, "nvme"),
    (0x12, "scm"),
    (0x13, "ufs"),
];

/// Map a raw `STORAGE_BUS_TYPE` value to a canonical lowercase name.
fn bus_type_name(raw: u32) -> String {
    BUS_TYPE_NAMES
        .iter()
        .find(|(v, _)| *v == raw)
        .map(|(_, n)| (*n).to_string())
        .unwrap_or_else(|| format!("bus-0x{raw:02x}"))
}

/// Is this bus type inherently removable, regardless of the reported drive
/// type? USB / SD / MMC backing stores are always treated as removable.
pub fn bus_is_removable(bus_type: &str) -> bool {
    matches!(bus_type, "usb" | "sd" | "mmc")
}

// Field offsets within STORAGE_DEVICE_DESCRIPTOR (all little-endian).
const OFF_REMOVABLE_MEDIA: usize = 10; // BOOLEAN
const OFF_VENDOR_ID: usize = 12; // DWORD offset-to-string
const OFF_PRODUCT_ID: usize = 16;
const OFF_SERIAL: usize = 24;
const OFF_BUS_TYPE: usize = 28; // STORAGE_BUS_TYPE (DWORD)
const DESCRIPTOR_MIN: usize = 32;

fn read_u32_le(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

/// Read a NUL-terminated ASCII string at `offset` within `buf`. Offset 0 means
/// "field not present" (the Windows convention). Out-of-range offsets yield "".
fn read_c_string(buf: &[u8], offset: usize) -> String {
    if offset == 0 || offset >= buf.len() {
        return String::new();
    }
    let end = buf[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| offset + p)
        .unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[offset..end]).trim().to_string()
}

/// Pure parse of a `STORAGE_DEVICE_DESCRIPTOR` buffer → `DeviceIdentity`
/// (spec §3.1 testability requirement). `drive_letter` is left empty for the
/// caller to fill. Removability is derived from the bus type (USB/SD/MMC),
/// OR-ed with the descriptor's `RemovableMedia` flag.
pub fn parse_storage_descriptor(buf: &[u8]) -> DeviceIdentity {
    if buf.len() < DESCRIPTOR_MIN {
        return DeviceIdentity {
            drive_letter: String::new(),
            vendor_id: String::new(),
            product_id: String::new(),
            serial: String::new(),
            product_name: String::new(),
            bus_type: "unknown".into(),
            removable: false,
        };
    }

    let vendor_id = read_c_string(buf, read_u32_le(buf, OFF_VENDOR_ID) as usize);
    let product_id = read_c_string(buf, read_u32_le(buf, OFF_PRODUCT_ID) as usize);
    let serial = read_c_string(buf, read_u32_le(buf, OFF_SERIAL) as usize);
    let bus_raw = read_u32_le(buf, OFF_BUS_TYPE);
    let bus_type = bus_type_name(bus_raw);
    let removable_flag = buf[OFF_REMOVABLE_MEDIA] != 0;
    let removable = bus_is_removable(&bus_type) || removable_flag;

    let product_name = match (vendor_id.is_empty(), product_id.is_empty()) {
        (false, false) => format!("{vendor_id} {product_id}"),
        (true, false) => product_id.clone(),
        (false, true) => vendor_id.clone(),
        (true, true) => String::new(),
    };

    DeviceIdentity {
        drive_letter: String::new(),
        vendor_id,
        product_id,
        serial,
        product_name,
        bus_type,
        removable,
    }
}

// ---------------------------------------------------------------------------
// Live enumeration + IOCTL (Windows only). Compiled, not unit-tested; the pure
// parser above carries the tested logic. On non-Windows these are stubs so the
// library still builds for the cross-platform golden-vector tests.
// ---------------------------------------------------------------------------

/// Enumerate currently mounted removable volumes (spec §3.1). On Windows this
/// walks `GetLogicalDrives`, filters by drive type AND bus type, and queries
/// each device's identity. On other platforms it returns an empty list.
#[cfg(windows)]
pub fn list_removable_volumes() -> Vec<DeviceIdentity> {
    use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};

    // Drive-type values (winbase.h). Not exported as named constants by the
    // windows crate; GetDriveTypeW returns a plain u32.
    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_FIXED: u32 = 3;

    let mut out = Vec::new();
    let mask = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let letter = (b'A' + i as u8) as char;
        let root: Vec<u16> = format!("{letter}:\\").encode_utf16().chain(std::iter::once(0)).collect();
        let dtype = unsafe { GetDriveTypeW(windows::core::PCWSTR(root.as_ptr())) };
        // Consider removable drive types AND fixed drives (external USB SSDs
        // masquerade as fixed — the bus-type query below is the real gate).
        if dtype != DRIVE_REMOVABLE && dtype != DRIVE_FIXED {
            continue;
        }
        let drive = format!("{letter}:");
        match query_device_identity(&drive) {
            Ok(mut id) => {
                id.drive_letter = drive.clone();
                // Only surface devices we classify removable (USB/SD/MMC bus, or
                // the descriptor's removable flag) — this drops the OS disk.
                if id.removable {
                    out.push(id);
                }
            }
            Err(e) => {
                tracing::debug!(drive = %drive, error = %e, "device identity query failed");
            }
        }
    }
    out
}

#[cfg(not(windows))]
pub fn list_removable_volumes() -> Vec<DeviceIdentity> {
    Vec::new()
}

/// Query a single volume's backing-device identity via
/// `IOCTL_STORAGE_QUERY_PROPERTY` (spec §3.1). Thin wrapper: fills a descriptor
/// buffer, then hands off to the pure `parse_storage_descriptor`.
#[cfg(windows)]
pub fn query_device_identity(drive_letter: &str) -> anyhow::Result<DeviceIdentity> {
    use anyhow::{bail, Context};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Ioctl::{
        PropertyStandardQuery, StorageDeviceProperty, IOCTL_STORAGE_QUERY_PROPERTY,
        STORAGE_PROPERTY_QUERY,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    // Open the volume device (no trailing backslash): \\.\E:
    let path = drive_letter.trim_end_matches('\\').trim_end_matches('/');
    let device = format!(r"\\.\{path}");
    let wide: Vec<u16> = device.encode_utf16().chain(std::iter::once(0)).collect();

    let handle: HANDLE = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .with_context(|| format!("opening {device}"))?;

    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
    };

    let mut buf = vec![0u8; 1024];
    let mut returned: u32 = 0;
    let res = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            Some(&query as *const _ as *const core::ffi::c_void),
            std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            buf.len() as u32,
            Some(&mut returned),
            None,
        )
    };
    unsafe {
        let _ = CloseHandle(handle);
    }
    res.with_context(|| format!("IOCTL_STORAGE_QUERY_PROPERTY on {device}"))?;

    if (returned as usize) < DESCRIPTOR_MIN {
        bail!("short storage descriptor ({returned} bytes) from {device}");
    }
    buf.truncate(returned as usize);

    let mut id = parse_storage_descriptor(&buf);
    id.drive_letter = path.to_string();
    Ok(id)
}

#[cfg(not(windows))]
pub fn query_device_identity(_drive_letter: &str) -> anyhow::Result<DeviceIdentity> {
    anyhow::bail!("USB device identity query is only available on Windows")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic STORAGE_DEVICE_DESCRIPTOR: a header with offsets to
    /// three NUL-terminated strings packed after it, and a bus-type value.
    fn synthetic_descriptor(
        vendor: &str,
        product: &str,
        serial: &str,
        removable_flag: bool,
        bus_type: u32,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; DESCRIPTOR_MIN];
        // strings start right after the fixed header
        let push_str = |buf: &mut Vec<u8>, s: &str| -> u32 {
            if s.is_empty() {
                return 0;
            }
            let off = buf.len() as u32;
            buf.extend_from_slice(s.as_bytes());
            buf.push(0);
            off
        };
        // We must record offsets; strings are appended in order.
        let v_off = push_str(&mut buf, vendor);
        let p_off = push_str(&mut buf, product);
        let s_off = push_str(&mut buf, serial);

        buf[OFF_REMOVABLE_MEDIA] = if removable_flag { 1 } else { 0 };
        buf[OFF_VENDOR_ID..OFF_VENDOR_ID + 4].copy_from_slice(&v_off.to_le_bytes());
        buf[OFF_PRODUCT_ID..OFF_PRODUCT_ID + 4].copy_from_slice(&p_off.to_le_bytes());
        buf[OFF_SERIAL..OFF_SERIAL + 4].copy_from_slice(&s_off.to_le_bytes());
        buf[OFF_BUS_TYPE..OFF_BUS_TYPE + 4].copy_from_slice(&bus_type.to_le_bytes());
        buf
    }

    #[test]
    fn parses_usb_stick_and_classifies_removable() {
        // BusTypeUsb = 0x07, removable flag false (many sticks report false;
        // bus type is what makes it removable).
        let buf = synthetic_descriptor("Kingston", "DataTraveler", "0123456789AB", false, 0x07);
        let id = parse_storage_descriptor(&buf);
        assert_eq!(id.vendor_id, "Kingston");
        assert_eq!(id.product_id, "DataTraveler");
        assert_eq!(id.serial, "0123456789AB");
        assert_eq!(id.bus_type, "usb");
        assert!(id.removable, "USB bus type must classify removable");
        assert_eq!(id.product_name, "Kingston DataTraveler");
    }

    #[test]
    fn fixed_os_disk_is_not_removable() {
        // BusTypeSata = 0x0B, removable flag false → internal OS disk.
        let buf = synthetic_descriptor("Samsung", "SSD 990 PRO", "S6XPNF0T", false, 0x0B);
        let id = parse_storage_descriptor(&buf);
        assert_eq!(id.bus_type, "sata");
        assert!(!id.removable, "internal SATA disk must NOT be classified removable");
    }

    #[test]
    fn external_usb_ssd_reporting_fixed_flag_is_still_removable() {
        // The classic false-negative: a USB SSD whose removable flag is false,
        // but the bus type is USB → we still treat it as removable.
        let buf = synthetic_descriptor("WD", "My Passport", "575845", false, 0x07);
        let id = parse_storage_descriptor(&buf);
        assert!(id.removable, "USB-attached SSD must be removable despite a false flag");
    }

    #[test]
    fn sd_card_bus_is_removable() {
        let buf = synthetic_descriptor("Generic", "SD/MMC", "SD01", false, 0x0C);
        let id = parse_storage_descriptor(&buf);
        assert_eq!(id.bus_type, "sd");
        assert!(id.removable);
    }

    #[test]
    fn missing_string_offsets_are_empty_not_panicking() {
        // All offsets zero → no strings, no panic.
        let mut buf = vec![0u8; DESCRIPTOR_MIN];
        buf[OFF_BUS_TYPE..OFF_BUS_TYPE + 4].copy_from_slice(&0x03u32.to_le_bytes()); // ata
        let id = parse_storage_descriptor(&buf);
        assert!(id.vendor_id.is_empty());
        assert!(id.product_id.is_empty());
        assert!(id.serial.is_empty());
        assert_eq!(id.bus_type, "ata");
        assert!(!id.removable);
    }

    #[test]
    fn too_short_buffer_yields_safe_default() {
        let id = parse_storage_descriptor(&[0u8; 8]);
        assert_eq!(id.bus_type, "unknown");
        assert!(!id.removable);
    }

    #[test]
    fn scsi_removable_flag_classifies_removable() {
        // A SCSI device that genuinely reports removable media (e.g. some
        // card readers) is honoured via the flag even though the bus isn't USB.
        let buf = synthetic_descriptor("VENDOR", "READER", "X", true, 0x01);
        let id = parse_storage_descriptor(&buf);
        assert_eq!(id.bus_type, "scsi");
        assert!(id.removable, "explicit removable-media flag must classify removable");
    }
}
