//! Exfil-channel PID tracker (read-deny feature — read-deny-LLD §2).
//!
//! Computes the set of PIDs that can move data off-box and packs it into the
//! `DLP_EXFIL_UPDATE` message the kernel's `DlpPreRead` consults. A PID is an
//! exfil channel if ANY of:
//!   * its image matches a remote-access-tool signature (RustDesk/AnyDesk/VNC/…), OR
//!   * it holds an ESTABLISHED TCP connection to a **non-local** (public) peer —
//!     the behavioral signal that catches unknown C2 with no signature, OR
//!   * it has a hypervisor runtime module loaded (WHP / VBoxVMM / vmwarebase) —
//!     it is hosting a VM, and every host→guest file path (shared folder,
//!     drag-and-drop, clipboard file transfer) is a host-side read by that PID.
//!
//! Signature + connection-table correlation is trivial in user mode and awful in
//! kernel, so the agent owns the definition and pushes the resulting set; the
//! driver only does the O(1) hot-path lookup. Pure enumeration here — the send
//! happens in `kguard` over `\DlpFltPort`.

pub const DLP_EXFIL_VERSION: u32 = 0x5870_6C44; // 'D''l''p''X' — MUST match dlpflt.h
pub const DLP_EXFIL_MSG_MAX: usize = 1024;

/// Wire mirror of the kernel `DLP_EXFIL_UPDATE` (`#[repr(C)]`, size-locked).
/// Full-replace: `count` valid PIDs in `pids`.
#[repr(C)]
pub struct DlpExfilUpdate {
    pub version: u32,
    pub count: u32,
    pub pids: [u32; DLP_EXFIL_MSG_MAX],
}

impl DlpExfilUpdate {
    /// Build a full-replace message from a PID set (truncated to the cap).
    pub fn new(pids: &[u32]) -> Self {
        let mut m = DlpExfilUpdate {
            version: DLP_EXFIL_VERSION,
            count: 0,
            pids: [0u32; DLP_EXFIL_MSG_MAX],
        };
        let n = pids.len().min(DLP_EXFIL_MSG_MAX);
        m.pids[..n].copy_from_slice(&pids[..n]);
        m.count = n as u32;
        m
    }
}

// Size-lock: the kernel struct is 8 + 1024*4 = 4104 bytes.
const _: () = assert!(core::mem::size_of::<DlpExfilUpdate>() == 8 + DLP_EXFIL_MSG_MAX * 4);

// ---------------------------------------------------------------------------
// Locality classifiers (pure; unit-tested). "Public" = not loopback / RFC1918 /
// link-local / ULA / multicast / unspecified. A public established peer is the
// exfil signal; a purely-LAN peer is left to the signature match (avoids marking
// every intranet-talking process as an exfil channel).
// ---------------------------------------------------------------------------

/// `addr` is `MIB_*ROW.dwRemoteAddr` — the IPv4 address in NETWORK byte order, so
/// its little-endian bytes are exactly the dotted octets [o0.o1.o2.o3].
pub fn is_public_v4(addr: u32) -> bool {
    let o = addr.to_le_bytes();
    let (a, b) = (o[0], o[1]);
    if a == 0 || a == 127 || a == 10 {
        return false; // unspecified / loopback / 10/8
    }
    if a == 172 && (16..=31).contains(&b) {
        return false; // 172.16/12
    }
    if a == 192 && b == 168 {
        return false; // 192.168/16
    }
    if a == 169 && b == 254 {
        return false; // 169.254/16 link-local
    }
    if a >= 224 {
        return false; // multicast / reserved
    }
    true
}

/// `addr` is the 16-byte IPv6 remote address (network order).
pub fn is_public_v6(a: &[u8; 16]) -> bool {
    if a.iter().all(|&b| b == 0) {
        return false; // ::
    }
    if a[..15].iter().all(|&b| b == 0) && a[15] == 1 {
        return false; // ::1 loopback
    }
    if a[0] == 0xfe && (a[1] & 0xc0) == 0x80 {
        return false; // fe80::/10 link-local
    }
    if (a[0] & 0xfe) == 0xfc {
        return false; // fc00::/7 ULA
    }
    if a[0] == 0xff {
        return false; // ff00::/8 multicast
    }
    true
}

// ---------------------------------------------------------------------------
// Windows: compute the exfil-PID set.
// ---------------------------------------------------------------------------
#[cfg(windows)]
pub fn compute_exfil_pids(self_pid: u32) -> Vec<u32> {
    use std::collections::HashSet;
    let mut set: HashSet<u32> = HashSet::new();

    let skip = |pid: u32| pid == 0 || pid == 4 || pid == self_pid;

    // 1. Remote-access-tool signatures (RustDesk/AnyDesk/VNC/…).
    for (pid, _image) in crate::netfilter::list_remote_tool_processes() {
        if !skip(pid) {
            set.insert(pid);
        }
    }

    // 2. Behavioral: any process with an ESTABLISHED connection to a public peer.
    for pid in pids_with_public_connection() {
        if !skip(pid) {
            set.insert(pid);
        }
    }

    // 3. Hypervisor VM workers: any process with a hypervisor runtime loaded.
    for pid in hypervisor_pids() {
        if !skip(pid) {
            set.insert(pid);
        }
    }

    set.into_iter().collect()
}

#[cfg(not(windows))]
pub fn compute_exfil_pids(_self_pid: u32) -> Vec<u32> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// Hypervisor VM-worker detection (rule 3). Substrate-based, not product-name
// based: on Windows a hypervisor must either go through the Windows Hypervisor
// Platform (winhvplatform.dll / vid.dll — Hyper-V, WSL2, Docker Desktop,
// QEMU-whpx, VirtualBox/VMware running in Hyper-V mode) or bring its own VMM
// runtime next to its kernel driver (VBoxVMM.dll, vmwarebase.dll). A brand-new
// hypervisor still has to load one of these substrates, so no per-product
// image-name list is needed. Deliberately NOT matched: VBoxRT.dll / VBoxSVC
// helpers — they are loaded by the whole VirtualBox suite (GUI manager,
// service); only the VM worker process that actually executes a guest (and
// performs the host-side reads for shared folders / drag-and-drop / clipboard
// file transfer) loads the VMM itself.
// ---------------------------------------------------------------------------

/// `path` is a full module path as reported by `GetModuleFileNameExW`.
/// Case-insensitive; pure so it unit-tests without a live hypervisor.
pub fn is_hypervisor_module(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    let base = p.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(&p);
    match base {
        "winhvplatform.dll" | "vboxvmm.dll" | "vmwarebase.dll" => true,
        // "vid.dll" is a generic-sounding name third-party apps have used;
        // only the OS-supplied Hyper-V VID client counts.
        "vid.dll" => p.contains("\\system32\\") || p.contains("\\syswow64\\"),
        _ => false,
    }
}

/// PIDs of processes with a hypervisor runtime module loaded. Best-effort like
/// the other rules: a process we cannot open or walk (protected, exiting) is
/// skipped, and the pusher cadence re-derives the whole set anyway.
#[cfg(windows)]
fn hypervisor_pids() -> Vec<u32> {
    use windows::Win32::Foundation::{CloseHandle, HMODULE};
    use windows::Win32::System::ProcessStatus::{
        EnumProcessModulesEx, EnumProcesses, GetModuleFileNameExW, LIST_MODULES_ALL,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
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
        tracing::warn!("EnumProcesses failed (hypervisor scan)");
        return out;
    }
    let count = needed as usize / std::mem::size_of::<u32>();
    'procs: for &pid in pids.iter().take(count) {
        if pid == 0 {
            continue;
        }
        // VM_READ on top of QUERY: EnumProcessModulesEx walks the target's PEB.
        let handle =
            match unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) } {
                Ok(h) => h,
                Err(_) => continue, // access denied / gone — skip
            };
        // 1024 modules is plenty: the hypervisor substrate is an early, static
        // import of the worker process, not a late plugin.
        let mut modules = [HMODULE::default(); 1024];
        let mut cb = 0u32;
        let ok = unsafe {
            EnumProcessModulesEx(
                handle,
                modules.as_mut_ptr(),
                std::mem::size_of_val(&modules) as u32,
                &mut cb,
                LIST_MODULES_ALL,
            )
        };
        if ok.is_ok() {
            let n = (cb as usize / std::mem::size_of::<HMODULE>()).min(modules.len());
            let mut buf = [0u16; 512];
            for &m in &modules[..n] {
                let len = unsafe { GetModuleFileNameExW(handle, m, &mut buf) } as usize;
                if len > 0 && is_hypervisor_module(&String::from_utf16_lossy(&buf[..len])) {
                    out.push(pid);
                    unsafe {
                        let _ = CloseHandle(handle);
                    }
                    continue 'procs;
                }
            }
        }
        unsafe {
            let _ = CloseHandle(handle);
        }
    }
    out
}

/// PIDs holding an ESTABLISHED TCP connection to a public (non-local) peer, v4+v6.
#[cfg(windows)]
fn pids_with_public_connection() -> Vec<u32> {
    use crate::netfilter::tcpreset::{query_tcp_table, v4_rows, v6_rows};

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    const MIB_TCP_STATE_ESTAB: u32 = 5;

    let mut out = Vec::new();

    if let Ok(buf) = query_tcp_table(AF_INET) {
        for r in unsafe { v4_rows(&buf) } {
            if r.dwState == MIB_TCP_STATE_ESTAB && is_public_v4(r.dwRemoteAddr) {
                out.push(r.dwOwningPid);
            }
        }
    }
    if let Ok(buf) = query_tcp_table(AF_INET6) {
        for r in unsafe { v6_rows(&buf) } {
            if r.dwState == MIB_TCP_STATE_ESTAB && is_public_v6(&r.ucRemoteAddr) {
                out.push(r.dwOwningPid);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_locality() {
        // network-order octets packed low-first
        let ip = |a: u8, b: u8, c: u8, d: u8| u32::from_le_bytes([a, b, c, d]);
        assert!(!is_public_v4(ip(127, 0, 0, 1)));
        assert!(!is_public_v4(ip(10, 1, 2, 3)));
        assert!(!is_public_v4(ip(172, 16, 0, 1)));
        assert!(!is_public_v4(ip(172, 31, 255, 1)));
        assert!(is_public_v4(ip(172, 32, 0, 1))); // outside 172.16/12
        assert!(!is_public_v4(ip(192, 168, 1, 1)));
        assert!(!is_public_v4(ip(169, 254, 1, 1)));
        assert!(!is_public_v4(ip(224, 0, 0, 1)));
        assert!(is_public_v4(ip(8, 8, 8, 8)));
        assert!(is_public_v4(ip(142, 250, 29, 113)));
    }

    #[test]
    fn v6_locality() {
        let mut lo = [0u8; 16];
        lo[15] = 1;
        assert!(!is_public_v6(&lo)); // ::1
        assert!(!is_public_v6(&[0u8; 16])); // ::
        let mut ll = [0u8; 16];
        ll[0] = 0xfe;
        ll[1] = 0x80;
        assert!(!is_public_v6(&ll)); // fe80::/10
        let mut ula = [0u8; 16];
        ula[0] = 0xfd;
        assert!(!is_public_v6(&ula)); // fc00::/7
        let mut pub6 = [0u8; 16];
        pub6[0] = 0x20;
        pub6[1] = 0x01;
        assert!(is_public_v6(&pub6)); // 2001::/… public
    }

    #[test]
    fn hypervisor_module_matcher() {
        // WHP / Hyper-V substrate (covers Hyper-V, WSL2, Docker, QEMU-whpx, …).
        assert!(is_hypervisor_module(r"C:\Windows\System32\WinHvPlatform.dll"));
        assert!(is_hypervisor_module(r"C:\Windows\System32\vid.dll"));
        // Generic "vid.dll" outside System32 is NOT the Hyper-V client.
        assert!(!is_hypervisor_module(r"C:\Games\OldCodec\vid.dll"));
        // Driver-class hypervisors' own VMM runtimes.
        assert!(is_hypervisor_module(r"C:\Program Files\Oracle\VirtualBox\VBoxVMM.dll"));
        assert!(is_hypervisor_module(
            r"C:\Program Files (x86)\VMware\VMware Workstation\x64\vmwarebase.dll"
        ));
        // Suite helpers that non-worker VirtualBox processes also load: not VM hosts.
        assert!(!is_hypervisor_module(r"C:\Program Files\Oracle\VirtualBox\VBoxRT.dll"));
        assert!(!is_hypervisor_module(r"C:\Windows\System32\kernel32.dll"));
    }

    #[test]
    fn message_full_replace_and_cap() {
        let m = DlpExfilUpdate::new(&[10, 20, 30]);
        assert_eq!(m.version, DLP_EXFIL_VERSION);
        assert_eq!(m.count, 3);
        assert_eq!(&m.pids[..3], &[10, 20, 30]);
        let big: Vec<u32> = (0..2000).collect();
        let m2 = DlpExfilUpdate::new(&big);
        assert_eq!(m2.count as usize, DLP_EXFIL_MSG_MAX);
    }
}
