//! TCP connection-table enumeration helpers (Windows).
//!
//! Thin wrappers over `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` used by the
//! read-deny exfil tracker (`crate::exfil`) to find processes holding an
//! ESTABLISHED connection to a public peer — the behavioral "this process can
//! move data off-box" signal. Enumeration only: nothing here modifies, resets,
//! or filters any connection.
//!
//! Windows-only by nature; the module is empty on other targets (the exfil
//! tracker's non-Windows stub never calls in here).

/// Call `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` for the given family into
/// an 8-aligned byte buffer (size-probe then fetch). Windows-only helper.
#[cfg(windows)]
pub(crate) fn query_tcp_table(family: u32) -> anyhow::Result<Vec<u64>> {
    use windows::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL};

    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const ERROR_OK: u32 = 0;

    // Probe the required size.
    let mut size: u32 = 0;
    let rc = unsafe {
        GetExtendedTcpTable(None, &mut size, true, family, TCP_TABLE_OWNER_PID_ALL, 0)
    };
    if rc != ERROR_OK && rc != ERROR_INSUFFICIENT_BUFFER {
        anyhow::bail!("GetExtendedTcpTable(size probe, af={family}) failed: {rc}");
    }
    if size == 0 {
        return Ok(vec![0u64; 1]); // empty table (dwNumEntries == 0)
    }

    // Allocate an 8-aligned buffer (Vec<u64>) large enough and fetch.
    let mut buf: Vec<u64> = vec![0u64; (size as usize).div_ceil(8)];
    let rc = unsafe {
        GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            &mut size,
            true,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if rc != ERROR_OK {
        anyhow::bail!("GetExtendedTcpTable(fetch, af={family}) failed: {rc}");
    }
    Ok(buf)
}

/// Interpret an 8-aligned buffer as `MIB_TCPTABLE_OWNER_PID` and return its rows.
/// SAFETY: `buf` was filled by `GetExtendedTcpTable(AF_INET, ...)`, so it begins
/// with `dwNumEntries` followed by that many `MIB_TCPROW_OWNER_PID`.
#[cfg(windows)]
pub(crate) unsafe fn v4_rows(
    buf: &[u64],
) -> &[windows::Win32::NetworkManagement::IpHelper::MIB_TCPROW_OWNER_PID] {
    use windows::Win32::NetworkManagement::IpHelper::MIB_TCPTABLE_OWNER_PID;
    let p = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
    let num = (*p).dwNumEntries as usize;
    std::slice::from_raw_parts((*p).table.as_ptr(), num)
}

/// v6 counterpart of `v4_rows`.
#[cfg(windows)]
pub(crate) unsafe fn v6_rows(
    buf: &[u64],
) -> &[windows::Win32::NetworkManagement::IpHelper::MIB_TCP6ROW_OWNER_PID] {
    use windows::Win32::NetworkManagement::IpHelper::MIB_TCP6TABLE_OWNER_PID;
    let p = buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
    let num = (*p).dwNumEntries as usize;
    std::slice::from_raw_parts((*p).table.as_ptr(), num)
}
