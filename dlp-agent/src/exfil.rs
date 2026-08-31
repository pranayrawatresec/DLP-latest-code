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

// ---- Remote-session (RDP) read-deny push -----------------------------------
pub const DLP_SESSION_VERSION: u32 = 0x5370_6C44; // 'D''l''p''S' — MUST match dlpflt.h
pub const DLP_SESSION_MAX: usize = 64;

/// Wire mirror of the kernel `DLP_SESSION_UPDATE` (`#[repr(C)]`, size-locked).
/// Full-replace: `count` remote (RDP) session IDs in `sessions`.
#[repr(C)]
pub struct DlpSessionUpdate {
    pub version: u32,
    pub count: u32,
    pub sessions: [u32; DLP_SESSION_MAX],
}

impl DlpSessionUpdate {
    /// Build a full-replace message from a session-ID set (truncated to the cap).
    pub fn new(sessions: &[u32]) -> Self {
        let mut m = DlpSessionUpdate {
            version: DLP_SESSION_VERSION,
            count: 0,
            sessions: [0u32; DLP_SESSION_MAX],
        };
        let n = sessions.len().min(DLP_SESSION_MAX);
        m.sessions[..n].copy_from_slice(&sessions[..n]);
        m.count = n as u32;
        m
    }
}

// Size-lock: the kernel struct is 8 + 64*4 = 264 bytes.
const _: () = assert!(core::mem::size_of::<DlpSessionUpdate>() == 8 + DLP_SESSION_MAX * 4);

// ---- Read-deny AUDIT drain (cache-hit deny notifications) ------------------
pub const DLP_DRAIN_VERSION: u32 = 0x796E_6544; // 'D''e''n''y' — MUST match dlpflt.h
pub const DLP_DENYRING_MAX: usize = 256;

/// Wire mirror of the kernel `DLP_DENY_EVENT` (`#[repr(C)]`, size-locked).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DlpDenyEvent {
    pub pid: u32,
    pub reason: u32,
    pub file_id: u64,
}

/// The drain REQUEST the guard sends (first ULONG discriminates it in the driver).
#[repr(C)]
pub struct DlpDrainRequest {
    pub version: u32,
}

/// Wire mirror of the kernel `DLP_DENY_DRAIN_REPLY` — the driver fills this.
#[repr(C)]
pub struct DlpDenyDrainReply {
    pub count: u32,
    pub dropped: u32,
    pub events: [DlpDenyEvent; DLP_DENYRING_MAX],
}

// Size-lock the reply: 8 header + 256 * 16 = 4104 bytes (matches dlpflt.h).
const _: () = assert!(core::mem::size_of::<DlpDenyEvent>() == 16);
const _: () = assert!(core::mem::size_of::<DlpDenyDrainReply>() == 8 + DLP_DENYRING_MAX * 16);

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
// Read-deny ALLOWLIST posture: compute the UNTRUSTED-reader PID set.
//
// A process is untrusted (pushed to the driver, subject to read-deny) unless it
// is on the admin-authored sanctioned-reader allowlist (publisher / path / name;
// `crate::trustedreaders`). Known remote tools and VM workers are ALSO forced
// untrusted even if a rule would sanction them (belt-and-suspenders against a
// too-broad path rule). This scales against unknown tools: a never-before-seen
// uploader isn't on the allowlist, so it is denied at the read.
// ---------------------------------------------------------------------------
use crate::trustedreaders::ReaderMatch;

#[cfg(not(windows))]
pub fn compute_untrusted_pids(
    _self_pid: u32,
    _rules: &[ReaderMatch],
    _central: bool,
) -> Option<Vec<u32>> {
    Some(Vec::new())
}

/// `central` = the console list is AUTHORITATIVE (read-deny policy
/// `readersAuthority = central`, #9). It changes only the EMPTY-list behaviour:
///   * `central == false` (merge/legacy) — an empty list means "not configured",
///     so push nothing (fail toward availability), as before.
///   * `central == true` — an empty list is a deliberate "trust no application"
///     declaration, so EVERY non-agent process is untrusted (fail-secure lockdown).
/// A NON-empty list behaves identically either way.
#[cfg(windows)]
pub fn compute_untrusted_pids(
    self_pid: u32,
    rules: &[ReaderMatch],
    central: bool,
) -> Option<Vec<u32>> {
    use std::collections::HashSet;

    // Empty list handling depends on WHY it is empty:
    //   * merge/legacy (central == false): almost always "not configured / monitor
    //     mode" — pushing every PID would deny sensitive reads system-wide, so push
    //     nothing (fail toward AVAILABILITY) and warn to populate the list.
    //   * central (central == true): an empty CENTRAL allowlist is an authoritative
    //     "trust no application" — fall through so every non-agent process is
    //     untrusted (fail-secure LOCKDOWN). The agent's own binary stays trusted
    //     (own_exe below), so it never blocks itself.
    if rules.is_empty() {
        if central {
            tracing::warn!(
                "read-deny CENTRAL authority with an EMPTY sanctioned-reader list — every \
                 non-agent process is treated as untrusted (fail-secure lockdown); add the apps \
                 that must read sensitive files to the console allowlist to relax this"
            );
            // fall through: with no rule to sanction anything, the loop below marks
            // every identifiable process untrusted.
        } else {
            tracing::warn!(
                "read-deny allowlist posture with an EMPTY sanctioned-reader list — pushing no \
                 PIDs (populate the trusted-reader allowlist before it can enforce)"
            );
            return Some(Vec::new());
        }
    }

    // Enable SeDebugPrivilege once (best-effort): when the guard runs elevated /
    // as SYSTEM this lets `OpenProcess` identify SYSTEM- and higher-integrity
    // processes (e.g. a remote-access tool's privileged helper). Without it those
    // come back with an empty image path and are skipped — so they would never be
    // pushed and never denied. No-op when not elevated.
    use std::sync::atomic::{AtomicBool, Ordering};
    static SEDEBUG_OK: AtomicBool = AtomicBool::new(false);
    {
        use std::sync::Once;
        static DEBUG_PRIV: Once = Once::new();
        DEBUG_PRIV.call_once(|| {
            let granted = enable_debug_privilege();
            SEDEBUG_OK.store(granted, Ordering::Relaxed);
            if granted {
                tracing::info!(
                    "guard is elevated — SeDebugPrivilege enabled; SYSTEM/high-integrity \
                     processes are identifiable and enforced"
                );
            } else {
                tracing::warn!(
                    "guard is NOT elevated — SeDebugPrivilege was not granted; SYSTEM/high-\
                     integrity processes cannot be identified and will NOT be enforced. Run the \
                     guard as the LocalSystem service (run-endpoint) in production."
                );
            }
        });
    }
    let elevated = SEDEBUG_OK.load(Ordering::Relaxed);

    let skip = |pid: u32| pid == 0 || pid == 4 || pid == self_pid;
    let has_publisher_rule = rules.iter().any(ReaderMatch::needs_publisher);

    // Auto-sanction the agent's OWN installed binary, independent of the admin
    // allowlist. Sibling agent processes (notably the usb-monitor sealer, which
    // legitimately reads files to seal them) run the SAME binary as a different
    // subcommand → same image path. Without this they'd be untrusted and the
    // driver would deny the very reads the sealer needs, breaking encrypt-on-write.
    let own_exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(str::to_owned));

    let mut set: HashSet<u32> = HashSet::new();

    // Enumeration failure must NOT clear the driver's set (the push is a full
    // replace). Signal it (None) so the pusher RETAINS the previous set — fail
    // secure, never drop protection on a transient glitch.
    let processes = match enumerate_processes_with_image() {
        Some(p) => p,
        None => return None,
    };

    let mut unidentifiable: u32 = 0;
    // Every process that is NOT sanctioned → untrusted (deny-by-default).
    for (pid, image) in processes {
        if skip(pid) {
            continue;
        }
        // Could not resolve the image path. Under an ALLOWLIST posture an
        // unidentifiable process is, by definition, not sanctioned. When the guard
        // is elevated, an unopenable process is genuinely protected/PPL (rare and
        // suspicious) → treat as UNTRUSTED (fail secure). When NOT elevated we
        // cannot tell a benign SYSTEM service from a tool and pushing them all
        // would deny the OS — so we skip them here, and the loud not-elevated
        // warning above is the signal to fix the deployment.
        if image.is_empty() {
            unidentifiable += 1;
            if elevated {
                set.insert(pid);
            }
            continue;
        }

        // The agent's own binary (main guard + the sealer sibling) is always trusted.
        if own_exe.as_deref().is_some_and(|own| image.eq_ignore_ascii_case(own)) {
            continue;
        }

        // Cheap matchers first (path/name — no signature work).
        let cheap_ok = rules
            .iter()
            .filter(|r| !r.needs_publisher())
            .any(|r| r.matches(&image, None));
        if cheap_ok {
            continue;
        }

        // Only verify the Authenticode signer when a publisher rule might still
        // sanction it — bounds signature verification to the processes the cheap
        // rules didn't already clear (and it is cached per image path).
        if has_publisher_rule {
            let publisher = cached_publisher(&image);
            let pub_ok = rules
                .iter()
                .filter(|r| r.needs_publisher())
                .any(|r| r.matches(&image, publisher.as_deref()));
            if pub_ok {
                continue;
            }
        }

        set.insert(pid);
    }

    // NOTE: the allowlist is authoritative in this posture — any process not
    // sanctioned above is ALREADY untrusted. We deliberately do NOT additionally
    // run the blocklist-style remote-tool / hypervisor-module scan here: it is
    // redundant (an un-allowlisted tool/VM worker is already flagged) and the
    // per-process module walk is O(processes x modules), which pushed the refresh
    // cycle to ~25 s. Dropping it keeps the cycle ~1-2 s so a new untrusted
    // process is denied almost immediately. (If a site allowlists a remote tool
    // or VM host, that is an explicit trust decision — don't.)

    if unidentifiable > 0 {
        tracing::warn!(
            count = unidentifiable,
            elevated,
            "processes the guard could not identify this cycle (treated as untrusted when \
             elevated; not enforced when non-elevated — run as the LocalSystem service)"
        );
    }

    Some(set.into_iter().collect())
}

/// The SESSION IDs of every **remote (RDP) session**. The pusher ships these to the
/// driver (DLP_SESSION_UPDATE) when the console read-deny policy has `denyRemoteSessions`
/// on, so EVERY process in an RDP session (even an otherwise-trusted app) is denied the
/// read of a sensitive file — the strict / token model, mirroring how an EV signing token
/// refuses to be used over RDP (session isolation).
///
/// Classic RDP ONLY: AnyDesk/RustDesk/TeamViewer hijack the physical **console** session
/// (protocol = console, not RDP), so WTS reports them as local and they are NOT flagged
/// here — they stay covered by the process allowlist. Best-effort: any WTS failure returns
/// whatever was found (never panics, never blocks the pusher).
#[cfg(not(windows))]
pub fn remote_session_ids() -> Vec<u32> {
    Vec::new()
}

/// The SESSION IDs of every **remote (RDP) session** (WTS client protocol = RDP).
/// The driver flags reads whose requestor lives in one of these sessions — pushing
/// session IDs (stable for the session's whole life) rather than the PIDs inside them
/// closes the launch-to-flag race a per-PID push leaves open (a fast reader like a
/// browser's PDF renderer reads before the ~2 s PID push can flag it).
#[cfg(windows)]
pub fn remote_session_ids() -> Vec<u32> {
    use windows::core::PWSTR;
    use windows::Win32::System::RemoteDesktop::{
        WTSClientProtocolType, WTSEnumerateSessionsW, WTSFreeMemory, WTSQuerySessionInformationW,
        WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
    };
    // WTS_PROTOCOL_TYPE: 0 = console, 1 = ICA (Citrix), 2 = RDP.
    const WTS_PROTOCOL_TYPE_RDP: u16 = 2;

    let mut ids: Vec<u32> = Vec::new();
    unsafe {
        let mut sess: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut sess_count: u32 = 0;
        if WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut sess, &mut sess_count).is_ok()
            && !sess.is_null()
        {
            let list = std::slice::from_raw_parts(sess, sess_count as usize);
            for s in list {
                let mut buf: PWSTR = PWSTR::null();
                let mut bytes: u32 = 0;
                let ok = WTSQuerySessionInformationW(
                    WTS_CURRENT_SERVER_HANDLE,
                    s.SessionId,
                    WTSClientProtocolType,
                    &mut buf,
                    &mut bytes,
                )
                .is_ok();
                if ok && !buf.is_null() && bytes >= 2 {
                    // The buffer holds a USHORT protocol code, not a string.
                    let proto = *(buf.0 as *const u16);
                    // Session 0 is services (never a client session) — never flag it.
                    if proto == WTS_PROTOCOL_TYPE_RDP && s.SessionId != 0 {
                        ids.push(s.SessionId);
                    }
                }
                if !buf.is_null() {
                    WTSFreeMemory(buf.0 as *mut core::ffi::c_void);
                }
            }
            WTSFreeMemory(sess as *mut core::ffi::c_void);
        }
    }
    ids
}

/// Enable SeDebugPrivilege on the current process token (best-effort). Lets an
/// elevated / SYSTEM guard `OpenProcess` SYSTEM- and higher-integrity processes
/// for image identification; a no-op (silently) when the token doesn't hold the
/// privilege (non-elevated). Windows-only.
#[cfg(windows)]
fn enable_debug_privilege() -> bool {
    use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_SUCCESS, HANDLE, LUID};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_DEBUG_NAME,
        SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .is_err()
        {
            return false;
        }
        let mut granted = false;
        let mut luid = LUID::default();
        if LookupPrivilegeValueW(None, SE_DEBUG_NAME, &mut luid).is_ok() {
            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
            };
            // AdjustTokenPrivileges returns Ok even when the token does NOT hold the
            // privilege — Windows signals that via GetLastError == ERROR_NOT_ALL_
            // ASSIGNED (i.e. last error != ERROR_SUCCESS). Read it immediately after
            // so we actually know whether SeDebug was enabled (elevated) or not.
            let _ = AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None);
            granted = GetLastError() == ERROR_SUCCESS;
        }
        let _ = CloseHandle(token);
        granted
    }
}

/// Enumerate every process as `(pid, full_image_path)`. A process we cannot open
/// (protected / exited) yields an EMPTY path — the caller treats that as "cannot
/// identify ⇒ do not push" (fail toward availability). Windows-only.
#[cfg(windows)]
fn enumerate_processes_with_image() -> Option<Vec<(u32, String)>> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::ProcessStatus::EnumProcesses;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let mut out = Vec::new();
    // Grow-and-retry: if EnumProcesses fills the entire buffer the list was likely
    // truncated (busy host), so double the buffer and re-query rather than silently
    // missing processes beyond the cap — an un-enumerated process is never pushed,
    // i.e. never enforced.
    let mut cap = 4096usize;
    let (pids, count) = loop {
        let mut pids = vec![0u32; cap];
        let mut needed = 0u32;
        let ok = unsafe {
            EnumProcesses(
                pids.as_mut_ptr(),
                (cap * std::mem::size_of::<u32>()) as u32,
                &mut needed,
            )
        };
        if ok.is_err() {
            tracing::warn!(
                "EnumProcesses failed (allowlist reader scan) — signalling failure so the pusher \
                 retains the driver's previous set instead of clearing it"
            );
            return None;
        }
        let returned = needed as usize / std::mem::size_of::<u32>();
        // returned < cap ⇒ the buffer held the whole list; else grow (bounded).
        if returned < cap || cap >= 1usize << 18 {
            break (pids, returned);
        }
        cap *= 2;
    };
    for &pid in pids.iter().take(count) {
        if pid == 0 {
            continue;
        }
        let image = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
            Ok(handle) => {
                let mut buf = vec![0u16; 1024];
                let mut size = buf.len() as u32;
                let r = unsafe {
                    QueryFullProcessImageNameW(
                        handle,
                        PROCESS_NAME_FORMAT(0),
                        PWSTR(buf.as_mut_ptr()),
                        &mut size,
                    )
                };
                unsafe {
                    let _ = CloseHandle(handle);
                }
                if r.is_ok() {
                    String::from_utf16_lossy(&buf[..size as usize])
                } else {
                    String::new() // can't read the path → treat as unidentifiable
                }
            }
            Err(_) => String::new(), // access denied (protected) / gone → unidentifiable
        };
        out.push((pid, image));
    }
    Some(out)
}

/// Process-wide cache of image-path → Authenticode publisher (signer subject
/// CN). A binary's signature does not change, so we verify each distinct image
/// at most once. `None` = unsigned / untrusted / unverifiable (fail-safe: a
/// publisher rule then does NOT sanction it). Windows-only.
#[cfg(windows)]
fn cached_publisher(image_path: &str) -> Option<String> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static CACHE: Mutex<Option<HashMap<String, Option<String>>>> = Mutex::new(None);

    // Bound the cache so a process spawning many uniquely-named binaries (e.g.
    // random temp paths) can't grow it without limit. A flat cap + clear is enough
    // here — this is a verify-once accelerator, not a correctness store. (NOTE:
    // keyed on path only, so a binary swapped at a cached path keeps its old
    // verdict until the cap clears; keying on file identity is a follow-up.)
    const CACHE_CAP: usize = 4096;

    let key = image_path.to_ascii_lowercase();
    if let Ok(mut guard) = CACHE.lock() {
        let map = guard.get_or_insert_with(HashMap::new);
        if let Some(hit) = map.get(&key) {
            return hit.clone();
        }
        if map.len() >= CACHE_CAP {
            map.clear();
        }
        let publisher = authenticode_publisher(image_path);
        map.insert(key, publisher.clone());
        publisher
    } else {
        // Poisoned lock (a prior panic): compute without caching rather than fail.
        authenticode_publisher(image_path)
    }
}

/// Verify the file's Authenticode signature and, if trusted, return the signer's
/// subject common-name (the "publisher"). Returns `None` on ANY failure —
/// unsigned, untrusted chain, or an extraction error — so an unverifiable binary
/// is never sanctioned by a publisher rule (fail-safe / more restrictive).
///
/// Handles BOTH signing styles a Windows binary can carry:
/// * **Embedded** signature (third-party apps + many OS services like
///   `svchost`/`explorer`): `WinVerifyTrust` then `CryptQueryObject` → signer
///   `CERT_INFO` → `CertGetNameStringW`.
/// * **Catalog** signature (OS binaries like `cmd.exe`/`notepad.exe` whose
///   signature lives in a system `.cat`, not the PE): find the catalog that
///   vouches for the file's hash, and read the signer of that catalog (which is
///   itself an embedded-signed PKCS#7).
///
/// Every handle is released on every path. Windows-only.
#[cfg(windows)]
fn authenticode_publisher(image_path: &str) -> Option<String> {
    // 1) Embedded signature.
    if file_signature_is_trusted(image_path) {
        if let Some(p) = signer_display_name(image_path) {
            return Some(p);
        }
    }
    // 2) System catalog (catalog-signed OS binaries).
    catalog_publisher(image_path)
}

/// Resolve the publisher of a **catalog-signed** file: hash the file, find the
/// system catalog whose membership vouches for that hash, and return the signer
/// of that (embedded-signed) catalog. `None` when the file is in no catalog or
/// any step fails. Windows-only.
#[cfg(windows)]
fn catalog_publisher(image_path: &str) -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
    use windows::Win32::Security::Cryptography::Catalog::{
        CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
        CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
        CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
    };

    let wide: Vec<u16> = image_path.encode_utf16().chain(std::iter::once(0)).collect();

    // Catalog admin context. SHA-256 catalogs are the Win10+ baseline (the same
    // NTDDI baseline this driver targets).
    let mut h_admin: isize = 0;
    let algo: Vec<u16> = "SHA256".encode_utf16().chain(std::iter::once(0)).collect();
    if unsafe { CryptCATAdminAcquireContext2(&mut h_admin, None, PCWSTR(algo.as_ptr()), None, 0) }.is_err()
        || h_admin == 0
    {
        return None;
    }

    let result = (|| {
        let h_file: HANDLE = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .ok()?;
        if h_file == INVALID_HANDLE_VALUE {
            return None;
        }

        let cat_path = (|| {
            // Size then compute the file's catalog hash.
            let mut cb: u32 = 0;
            let _ = unsafe {
                CryptCATAdminCalcHashFromFileHandle2(h_admin, h_file, &mut cb, None, 0)
            };
            if cb == 0 {
                return None;
            }
            let mut hash = vec![0u8; cb as usize];
            if unsafe {
                CryptCATAdminCalcHashFromFileHandle2(h_admin, h_file, &mut cb, Some(hash.as_mut_ptr()), 0)
            }
            .is_err()
            {
                return None;
            }
            // A catalog that contains this hash = the OS vouches for the file.
            let h_cat = unsafe { CryptCATAdminEnumCatalogFromHash(h_admin, &hash, 0, None) };
            if h_cat == 0 {
                return None;
            }
            let mut info = CATALOG_INFO {
                cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
                ..Default::default()
            };
            let got = unsafe { CryptCATCatalogInfoFromContext(h_cat, &mut info, 0) };
            unsafe {
                let _ = CryptCATAdminReleaseCatalogContext(h_admin, h_cat, 0);
            }
            if got.is_err() {
                return None;
            }
            let n = info
                .wszCatalogFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(info.wszCatalogFile.len());
            let p = String::from_utf16_lossy(&info.wszCatalogFile[..n]);
            if p.is_empty() {
                None
            } else {
                Some(p)
            }
        })();

        unsafe {
            let _ = CloseHandle(h_file);
        }

        // The .cat is an embedded-signed PKCS#7 — its signer IS the effective
        // publisher of the catalog-signed member. Verify the .cat then read it.
        cat_path.and_then(|c| {
            if file_signature_is_trusted(&c) {
                signer_display_name(&c)
            } else {
                None
            }
        })
    })();

    unsafe {
        let _ = CryptCATAdminReleaseContext(h_admin, 0);
    }
    result
}

/// `WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)` on the file — TRUE only
/// when the file has a valid, trusted Authenticode signature.
#[cfg(windows)]
fn file_signature_is_trusted(image_path: &str) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
        WINTRUST_DATA_0, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    let wide: Vec<u16> = image_path.encode_utf16().chain(std::iter::once(0)).collect();

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        hFile: Default::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file_info },
        dwStateAction: WTD_STATEACTION_VERIFY,
        ..Default::default()
    };

    // WinVerifyTrust returns 0 (ERROR_SUCCESS) exactly when the file is validly,
    // trustedly signed; any non-zero is untrusted/unsigned/error → not trusted.
    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut _ as *mut core::ffi::c_void,
        )
    };

    // Always close the verify state to release the cached context.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        let _ = WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut _ as *mut core::ffi::c_void,
        );
    }

    status == 0
}

/// Extract the embedded signer's subject display name (the publisher). Assumes
/// the caller already confirmed the signature is trusted. `None` on any error.
#[cfg(windows)]
fn signer_display_name(image_path: &str) -> Option<String> {
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext,
        CertGetNameStringW, CryptMsgClose, CryptMsgGetParam, CryptQueryObject, CERT_CONTEXT,
        CERT_FIND_SUBJECT_CERT, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_ENCODING_TYPE, CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE,
        CMSG_SIGNER_CERT_INFO_PARAM, HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };

    let wide: Vec<u16> = image_path.encode_utf16().chain(std::iter::once(0)).collect();

    let mut h_store = HCERTSTORE::default();
    // The message handle is an opaque `*mut c_void` in this binding (no HCRYPTMSG type).
    let mut h_msg: *mut core::ffi::c_void = std::ptr::null_mut();

    // Open the file's embedded PKCS#7 signature: gives us the cert store + the
    // signed message we can pull the signer CERT_INFO from.
    let ok = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide.as_ptr() as *const core::ffi::c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut h_store),
            Some(&mut h_msg),
            None,
        )
    };
    if ok.is_err() || h_msg.is_null() {
        if !h_msg.is_null() {
            unsafe { let _ = CryptMsgClose(Some(h_msg)); }
        }
        return None;
    }

    let result = (|| {
        // Size the signer CERT_INFO, then fetch it.
        let mut needed: u32 = 0;
        let sized = unsafe {
            CryptMsgGetParam(h_msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, None, &mut needed)
        };
        if sized.is_err() || needed == 0 {
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        let got = unsafe {
            CryptMsgGetParam(
                h_msg,
                CMSG_SIGNER_CERT_INFO_PARAM,
                0,
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                &mut needed,
            )
        };
        if got.is_err() {
            return None;
        }

        // Find the signer certificate in the store by its issuer+serial.
        let cert_ctx: *mut CERT_CONTEXT = unsafe {
            CertFindCertificateInStore(
                h_store,
                CERT_QUERY_ENCODING_TYPE(PKCS_7_ASN_ENCODING.0 | X509_ASN_ENCODING.0),
                0,
                CERT_FIND_SUBJECT_CERT,
                Some(buf.as_ptr() as *const core::ffi::c_void),
                None,
            )
        };
        if cert_ctx.is_null() {
            return None;
        }

        // Read the signer's simple display name (the publisher CN): size, then fetch.
        let name = unsafe {
            let len = CertGetNameStringW(cert_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None);
            if len <= 1 {
                let _ = CertFreeCertificateContext(Some(cert_ctx as *const CERT_CONTEXT));
                return None;
            }
            let mut namebuf = vec![0u16; len as usize];
            let wrote = CertGetNameStringW(
                cert_ctx,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                None,
                Some(&mut namebuf),
            );
            let _ = CertFreeCertificateContext(Some(cert_ctx as *const CERT_CONTEXT));
            if wrote <= 1 {
                return None;
            }
            // `wrote` includes the trailing NUL.
            String::from_utf16_lossy(&namebuf[..(wrote as usize - 1)])
        };
        let name = name.trim();
        if name.is_empty() {
            None
        } else {
            Some(name.to_string())
        }
    })();

    unsafe {
        let _ = CryptMsgClose(Some(h_msg));
        let _ = CertCloseStore(h_store, 0);
    }
    result
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
    use crate::netfilter::tcptable::{query_tcp_table, v4_rows, v6_rows};

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

    // ----- Windows RUNTIME probe (run with `-- --nocapture`) -----------------
    // Exercises the real Authenticode FFI + process enumeration against this
    // machine's actual binaries — the part that unit tests can't cover. The one
    // HARD assertion is fail-safe (an unsigned file must yield None); the rest is
    // diagnostic printout so we can see what real signatures resolve to.
    #[cfg(windows)]
    #[test]
    #[ignore = "runtime probe over the live process table; run explicitly: cargo test windows_runtime_authenticode_probe -- --ignored --nocapture"]
    fn windows_runtime_authenticode_probe() {
        // 1) Deterministic, fail-safe invariant: an unsigned file → None.
        let tmp = std::env::temp_dir().join(format!("dlp-unsigned-{}.bin", std::process::id()));
        std::fs::write(&tmp, b"not a signed PE, just bytes").unwrap();
        let unsigned = authenticode_publisher(&tmp.to_string_lossy());
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(unsigned, None, "an unsigned file must never resolve to a publisher");
        eprintln!("[probe] unsigned temp file -> publisher = {unsigned:?} (expected None) OK");

        // 2) Candidate system binaries: print trusted? + extracted publisher.
        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let candidates = [
            format!(r"{sysroot}\System32\svchost.exe"),
            format!(r"{sysroot}\System32\notepad.exe"),
            format!(r"{sysroot}\explorer.exe"),
            format!(r"{sysroot}\System32\cmd.exe"),
            format!(r"{sysroot}\System32\taskhostw.exe"),
        ];
        eprintln!("[probe] --- system binaries (trusted? / publisher) ---");
        for c in &candidates {
            if std::path::Path::new(c).exists() {
                let trusted = file_signature_is_trusted(c);
                let publisher = authenticode_publisher(c);
                eprintln!("[probe]  trusted={trusted:<5} publisher={:?}  {c}", publisher);
            }
        }

        // 3) Sample of live processes: (pid, publisher, image).
        eprintln!("[probe] --- live processes (up to 20) ---");
        let mut shown = 0;
        for (pid, image) in enumerate_processes_with_image().unwrap_or_default() {
            if image.is_empty() {
                continue;
            }
            let publisher = authenticode_publisher(&image);
            eprintln!("[probe]  pid={pid:<6} publisher={:?}  {image}", publisher);
            shown += 1;
            if shown >= 20 {
                break;
            }
        }

        // 4) compute_untrusted_pids with a realistic Microsoft-publisher + Windows-path
        //    allowlist. Print how many of the machine's processes it would flag.
        let rules = vec![
            ReaderMatch::Publisher("Microsoft Corporation".into()),
            ReaderMatch::Path(format!(r"{sysroot}")),
        ];
        let untrusted = compute_untrusted_pids(std::process::id(), &rules, false)
            .expect("enumeration succeeded");
        eprintln!(
            "[probe] compute_untrusted_pids(Microsoft + {sysroot}) -> {} untrusted PID(s)",
            untrusted.len()
        );
        // self / 0 / 4 must never be in the set.
        assert!(!untrusted.contains(&std::process::id()));
        assert!(!untrusted.contains(&0));
        assert!(!untrusted.contains(&4));
    }

    // Empty-allowlist behaviour differs by authority (#9): merge => push nothing
    // (availability); central => push everything non-agent (fail-secure lockdown).
    #[test]
    fn empty_allowlist_merge_pushes_nothing_central_locks_down() {
        // MERGE + empty: unconfigured => enforce nothing.
        let merge = compute_untrusted_pids(std::process::id(), &[], false)
            .expect("enumeration succeeded");
        assert!(merge.is_empty(), "merge + empty list must push NO pids");

        // CENTRAL + empty: authoritative "trust nothing" => every non-agent process
        // is untrusted. There are always other processes on the machine, so the set
        // is non-empty — and never contains self / 0 / 4.
        let central = compute_untrusted_pids(std::process::id(), &[], true)
            .expect("enumeration succeeded");
        assert!(
            !central.is_empty(),
            "central + empty list must lock down (push every non-agent pid)"
        );
        assert!(!central.contains(&std::process::id()));
        assert!(!central.contains(&0));
        assert!(!central.contains(&4));
    }
}
