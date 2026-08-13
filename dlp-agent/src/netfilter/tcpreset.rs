//! Read-taint existing-connection teardown + the tainted-egress decision mirror
//! (read-taint LLD §7, §9.2, §12 units 4 & 6).
//!
//! When the kernel driver taints a process (it read sensitive content), its
//! *new* outbound connects are blocked by the in-kernel WFP callout. But a
//! socket that was ALREADY open before the read predates that callout and would
//! not re-trigger `ALE_AUTH_CONNECT`. The chosen v1 mechanism (LLD §7) closes
//! that race from user mode: on the read-scan BLOCK reply, `usb-guard` calls
//! `reset_pid_connections(pid)`, which enumerates the PID's live TCP flows and
//! issues `SetTcpEntry(DELETE_TCB)` to abort them.
//!
//! This mirrors the `wfp.rs` dry-run/live contract EXACTLY:
//!   * `select_pid_rows` is the PURE, fully unit-tested row-selection core — the
//!     analogue of `plan_filters`. It never touches the OS.
//!   * `reset_pid_connections` is `#[cfg(windows)]`, admin-gated, operator-manual
//!     (real `SetTcpEntry` DELETE_TCB), and is NEVER exercised by tests — the
//!     analogue of `wfp::execute_live`. A non-Windows build gets a `bail!` stub
//!     so the crate stays cross-platform.
//!   * `tainted_egress_action` is the PURE mirror of the kernel `DlpWfpClassify`
//!     block/permit decision, so the kernel's taint-egress matrix is validated in
//!     Rust even though the kernel path cannot run here (LLD §5.3, §12 unit 6).

// ---------------------------------------------------------------------------
// TCP row model + pure selection (unit-tested; no OS).
// ---------------------------------------------------------------------------

/// Address family of an enumerated TCP row. Carried so the selection logic (and
/// its tests) cover both v4 and v6 without pulling in the OS row structs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpFamily {
    V4,
    V6,
}

/// A minimal, OS-agnostic view of one TCP connection-table row. Only the fields
/// the pure selection needs: the owning PID and the connection state (a
/// `MIB_TCP_STATE` numeric value). Populated from `MIB_TCPROW_OWNER_PID` /
/// `MIB_TCP6ROW_OWNER_PID` in the live path; constructed directly in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpRow {
    pub owning_pid: u32,
    pub state: u32,
    pub family: TcpFamily,
}

// The two `MIB_TCP_STATE` boundary values (iprtrmib.h) that bracket the "active
// egress" band. Kept as local consts so the pure core has no Windows dependency.
const MIB_TCP_STATE_SYN_SENT: u32 = 3;
const MIB_TCP_STATE_LAST_ACK: u32 = 10;

/// Is this state an ACTIVE egress connection worth resetting? The band
/// `SYN_SENT`(3)..=`LAST_ACK`(10) is exactly the set of rows that have (or
/// recently had) a live remote peer — it includes `ESTAB`(5). Everything outside
/// is either below (`CLOSED`(1)/`LISTEN`(2) — dead or an inbound server socket)
/// or above (`TIME_WAIT`(11)/`DELETE_TCB`(12) — already gone), so a single range
/// check both selects the live egress flows and fail-safes toward NOT touching
/// unrelated/dead sockets.
fn is_active_egress_state(state: u32) -> bool {
    (MIB_TCP_STATE_SYN_SENT..=MIB_TCP_STATE_LAST_ACK).contains(&state)
}

/// The single selection predicate (shared by `select_pid_rows` and the live
/// reset loop, so the tested logic IS the enforced logic): a row is selected iff
/// it is owned by `pid` and is in an active egress state. PID 0 is never a valid
/// egress owner and is filtered out defensively (mirrors the kernel taint table's
/// "PID 0 never matches" invariant).
fn row_selected(row: &TcpRow, pid: u32) -> bool {
    pid != 0 && row.owning_pid == pid && is_active_egress_state(row.state)
}

/// PURE: select the active TCP rows owned by `pid` (LLD §9.2, §12 unit 4). No
/// I/O — this is what the tests exercise; the live path applies `SetTcpEntry`
/// only to the rows this returns.
pub fn select_pid_rows(rows: &[TcpRow], pid: u32) -> Vec<TcpRow> {
    rows.iter().copied().filter(|r| row_selected(r, pid)).collect()
}

// ---------------------------------------------------------------------------
// Tainted-egress decision — pure mirror of the kernel DlpWfpClassify (LLD §5.3).
// ---------------------------------------------------------------------------

/// Tainted-egress policy — mirrors the kernel `DLP_TEP_*` registry knob. What a
/// tainted PID's outbound connect does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tep {
    /// Block ALL outbound from a tainted PID (default, fail-secure) — `DLP_TEP_BLOCK_ALL`.
    BlockAll,
    /// Permit RFC1918/loopback/link-local, block the rest — `DLP_TEP_BLOCK_NONLOCAL`.
    BlockNonlocal,
}

/// The classify outcome: `Block` = veto the connection; `Continue` = do not
/// block here (let the user-mode default-deny sublayer still decide). Mirrors the
/// kernel's `FWP_ACTION_BLOCK` vs `FWP_ACTION_CONTINUE` — crucially `Continue`,
/// not `Permit`, so read-taint composes with (never overrides) the allow-list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressAction {
    Block,
    Continue,
}

/// PURE mirror of the kernel `DlpWfpClassify` taint decision (LLD §5.3, §12
/// unit 6). A clean PID always `Continue`s. A tainted PID is `Block`ed, except
/// under `BlockNonlocal` when the remote is local (RFC1918/loopback/link-local),
/// which is permitted. This validates the kernel block/permit matrix in Rust.
pub fn tainted_egress_action(tainted: bool, remote_is_local: bool, policy: Tep) -> EgressAction {
    if !tainted {
        return EgressAction::Continue;
    }
    match policy {
        Tep::BlockAll => EgressAction::Block,
        Tep::BlockNonlocal => {
            if remote_is_local {
                EgressAction::Continue
            } else {
                EgressAction::Block
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Live reset (Windows only). NEVER reached by tests. Enumerates the PID's TCP
// flows via GetExtendedTcpTable and aborts each v4 flow with SetTcpEntry
// (DELETE_TCB) — admin/SYSTEM, operator-manual, exactly like wfp::execute_live.
// On non-Windows this is a bail! stub so the library builds cross-platform.
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
pub fn reset_pid_connections(_pid: u32) -> anyhow::Result<usize> {
    anyhow::bail!("TCP connection reset (read-taint teardown) is only available on Windows")
}

#[cfg(windows)]
pub fn reset_pid_connections(pid: u32) -> anyhow::Result<usize> {
    // AF_INET / AF_INET6 as raw u32 (avoids pulling in the WinSock feature just
    // for two well-known constants).
    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;

    let mut reset = 0usize;

    // v4: enumerate, select, and abort each selected flow with SetTcpEntry.
    let v4buf = query_tcp_table(AF_INET)?;
    for raw in unsafe { v4_rows(&v4buf) } {
        let row = TcpRow { owning_pid: raw.dwOwningPid, state: raw.dwState, family: TcpFamily::V4 };
        if row_selected(&row, pid) {
            match reset_v4_row(raw) {
                Ok(()) => reset += 1,
                Err(e) => tracing::warn!(pid, error = %e, "SetTcpEntry(DELETE_TCB) failed for a v4 flow"),
            }
        }
    }

    // v6: Windows exposes no public per-connection SetTcp6Entry(DELETE_TCB), so
    // we cannot abort individual v6 flows from user mode. We enumerate them only
    // to report the residual race honestly; the in-kernel WFP callout still
    // blocks the PID's NEW v6 connects, so steady-state egress is covered.
    let v6buf = query_tcp_table(AF_INET6)?;
    let v6_live = unsafe { v6_rows(&v6buf) }
        .iter()
        .filter(|raw| {
            let row = TcpRow { owning_pid: raw.dwOwningPid, state: raw.dwState, family: TcpFamily::V6 };
            row_selected(&row, pid)
        })
        .count();
    if v6_live > 0 {
        tracing::warn!(
            pid,
            v6_live,
            "read-taint: PID has live IPv6 flows that cannot be user-mode reset \
             (no SetTcp6Entry); WFP callout still blocks new v6 connects"
        );
    }

    Ok(reset)
}

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

/// Abort one v4 flow: copy its 4-tuple into a `MIB_TCPROW_LH`, set the state to
/// `DELETE_TCB`, and call `SetTcpEntry` (admin/SYSTEM). Operator-manual.
#[cfg(windows)]
fn reset_v4_row(
    raw: &windows::Win32::NetworkManagement::IpHelper::MIB_TCPROW_OWNER_PID,
) -> anyhow::Result<()> {
    use windows::Win32::NetworkManagement::IpHelper::{SetTcpEntry, MIB_TCPROW_LH};

    // MIB_TCP_STATE_DELETE_TCB = 12 (iprtrmib.h): setting this state aborts the
    // connection (sends RST / tears down the TCB).
    const MIB_TCP_STATE_DELETE_TCB: u32 = 12;

    let mut row: MIB_TCPROW_LH = unsafe { std::mem::zeroed() };
    row.Anonymous.dwState = MIB_TCP_STATE_DELETE_TCB;
    row.dwLocalAddr = raw.dwLocalAddr;
    row.dwLocalPort = raw.dwLocalPort;
    row.dwRemoteAddr = raw.dwRemoteAddr;
    row.dwRemotePort = raw.dwRemotePort;

    let rc = unsafe { SetTcpEntry(&row) };
    if rc != 0 {
        // ERROR_ACCESS_DENIED (5) here almost always means "not admin/SYSTEM".
        anyhow::bail!("SetTcpEntry(DELETE_TCB) failed: {rc} (need admin/SYSTEM)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Full `MIB_TCP_STATE` set for the tests (the non-test core only needs the
    // SYN_SENT..=LAST_ACK boundary, imported via `super::*`).
    const MIB_TCP_STATE_CLOSED: u32 = 1;
    const MIB_TCP_STATE_LISTEN: u32 = 2;
    const MIB_TCP_STATE_ESTAB: u32 = 5;
    const MIB_TCP_STATE_TIME_WAIT: u32 = 11;
    const MIB_TCP_STATE_DELETE_TCB: u32 = 12;

    fn row(pid: u32, state: u32, family: TcpFamily) -> TcpRow {
        TcpRow { owning_pid: pid, state, family }
    }

    // --- select_pid_rows (LLD §12 unit 4) ----------------------------------

    #[test]
    fn selects_only_active_rows_owned_by_pid() {
        let rows = vec![
            row(1000, MIB_TCP_STATE_ESTAB, TcpFamily::V4), // ours, active   -> keep
            row(1000, MIB_TCP_STATE_LISTEN, TcpFamily::V4), // ours, listen  -> drop
            row(1000, MIB_TCP_STATE_TIME_WAIT, TcpFamily::V4), // ours, dead -> drop
            row(2222, MIB_TCP_STATE_ESTAB, TcpFamily::V4), // other pid      -> drop
        ];
        let got = select_pid_rows(&rows, 1000);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0], row(1000, MIB_TCP_STATE_ESTAB, TcpFamily::V4));
    }

    #[test]
    fn empty_when_no_rows_match_the_pid() {
        let rows = vec![
            row(10, MIB_TCP_STATE_ESTAB, TcpFamily::V4),
            row(20, MIB_TCP_STATE_ESTAB, TcpFamily::V6),
        ];
        assert!(select_pid_rows(&rows, 999).is_empty());
        assert!(select_pid_rows(&[], 10).is_empty());
    }

    #[test]
    fn selects_across_v4_and_v6() {
        let rows = vec![
            row(5000, MIB_TCP_STATE_ESTAB, TcpFamily::V4),
            row(5000, MIB_TCP_STATE_SYN_SENT, TcpFamily::V6),
            row(5000, MIB_TCP_STATE_LAST_ACK, TcpFamily::V6),
            row(5000, MIB_TCP_STATE_CLOSED, TcpFamily::V4), // inactive -> drop
        ];
        let got = select_pid_rows(&rows, 5000);
        assert_eq!(got.len(), 3);
        assert!(got.iter().any(|r| r.family == TcpFamily::V4 && r.state == MIB_TCP_STATE_ESTAB));
        assert_eq!(got.iter().filter(|r| r.family == TcpFamily::V6).count(), 2);
    }

    #[test]
    fn pid_zero_never_matches() {
        // Defensive invariant mirroring the kernel taint table: PID 0 is not a
        // valid egress owner and must never be selected even if the table lists it.
        let rows = vec![row(0, MIB_TCP_STATE_ESTAB, TcpFamily::V4)];
        assert!(select_pid_rows(&rows, 0).is_empty());
    }

    #[test]
    fn active_state_boundary() {
        assert!(!is_active_egress_state(MIB_TCP_STATE_CLOSED)); // 1
        assert!(!is_active_egress_state(MIB_TCP_STATE_LISTEN)); // 2
        assert!(is_active_egress_state(MIB_TCP_STATE_SYN_SENT)); // 3
        assert!(is_active_egress_state(MIB_TCP_STATE_ESTAB)); // 5
        assert!(is_active_egress_state(MIB_TCP_STATE_LAST_ACK)); // 10
        assert!(!is_active_egress_state(MIB_TCP_STATE_TIME_WAIT)); // 11
        assert!(!is_active_egress_state(MIB_TCP_STATE_DELETE_TCB)); // 12
    }

    // --- tainted_egress_action (LLD §12 unit 6): full matrix ---------------

    #[test]
    fn clean_pid_always_continues() {
        for policy in [Tep::BlockAll, Tep::BlockNonlocal] {
            for local in [true, false] {
                assert_eq!(
                    tainted_egress_action(false, local, policy),
                    EgressAction::Continue
                );
            }
        }
    }

    #[test]
    fn block_all_blocks_tainted_regardless_of_locality() {
        assert_eq!(tainted_egress_action(true, true, Tep::BlockAll), EgressAction::Block);
        assert_eq!(tainted_egress_action(true, false, Tep::BlockAll), EgressAction::Block);
    }

    #[test]
    fn block_nonlocal_permits_local_blocks_remote() {
        assert_eq!(
            tainted_egress_action(true, true, Tep::BlockNonlocal),
            EgressAction::Continue // local dest permitted
        );
        assert_eq!(
            tainted_egress_action(true, false, Tep::BlockNonlocal),
            EgressAction::Block // public dest blocked
        );
    }
}
