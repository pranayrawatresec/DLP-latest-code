// openprobe -- isolates the OPEN (handle acquisition) from any read, to verify the
// driver's FltCancelFileOpen open-deny (the mechanism that closes the RustDesk/
// AnyDesk delegate-read: cancel the untrusted process's OPEN so no handle exists
// for a delegate like Explorer to read through). Untrusted by path (run it from
// C:\Users\Public, i.e. NOT under the allowlisted C:\Windows or Program Files).
//
//   openprobe <open|read|overwrite|overwrite-rw> <path>
//
// 'read' opens AND reads bytes: the untrusted-reader test. In enforce mode an
// untrusted read-capable open is cancelled at the OPEN, so 'read' reports
// READ-DENIED (the bytes never leave) -- use this instead of a Microsoft-signed
// cmd.exe copy, which the starter allowlist now (correctly) trusts by publisher.
//
// Sleeps ~11s first so the agent's ~2s untrusted-PID push flags THIS process
// before it opens (otherwise it would race the new-process window). Prints exactly
// whether the OPEN succeeded (handle acquired) or was denied, and the error code.
//
// Build (no dependencies, no cargo): rustc -O openprobe.rs -o openprobe.exe
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::time::Duration;

#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        sa: *const core::ffi::c_void,
        disposition: u32,
        flags: u32,
        template: *mut core::ffi::c_void,
    ) -> isize;
    fn GetLastError() -> u32;
    fn CloseHandle(h: isize) -> i32;
    fn ReadFile(
        h: isize,
        buf: *mut u8,
        to_read: u32,
        read: *mut u32,
        overlapped: *mut core::ffi::c_void,
    ) -> i32;
}

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const INVALID_HANDLE: isize = -1;

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        println!("usage: openprobe <open|overwrite|overwrite-rw> <path>");
        std::process::exit(2);
    }
    let mode = args[1].as_str();
    let path = wide(&args[2]);

    // Let the agent flag this (untrusted) process before we open.
    std::thread::sleep(Duration::from_secs(11));

    let (access, disposition, share) = match mode {
        // Create/overwrite (truncate-on-open), write-only: NOT a read-capable open,
        // so open-deny should never touch it -- must succeed.
        "overwrite" => (GENERIC_WRITE, CREATE_ALWAYS, FILE_SHARE_READ | FILE_SHARE_WRITE),
        // Overwrite WITH read access too -- the risky case #4 scoping must handle:
        // the create truncates first (empty content => not a positive sensitive
        // match), so the open must NOT be cancelled and no data loss/hang occurs.
        "overwrite-rw" => (
            GENERIC_READ | GENERIC_WRITE,
            CREATE_ALWAYS,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        ),
        // Plain read open of an existing file -- a sensitive file here MUST be denied
        // at the OPEN (FltCancelFileOpen), proving no handle is ever handed out.
        _ => (GENERIC_READ, OPEN_EXISTING, FILE_SHARE_READ),
    };

    let h = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            share,
            std::ptr::null(),
            disposition,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE {
        let e = unsafe { GetLastError() };
        // In enforce mode an untrusted read-capable open is cancelled here, so for
        // 'read' this IS the block (the bytes never leave).
        if mode == "read" {
            println!("read READ-DENIED err={e} (open cancelled)");
        } else {
            println!("{mode} OPEN-DENIED err={e}");
        }
    } else if mode == "read" {
        let mut buf = [0u8; 4096];
        let mut got: u32 = 0;
        let ok = unsafe { ReadFile(h, buf.as_mut_ptr(), buf.len() as u32, &mut got, std::ptr::null_mut()) };
        unsafe { CloseHandle(h); }
        if ok == 0 {
            let e = unsafe { GetLastError() };
            println!("read READ-DENIED err={e}");
        } else {
            println!("read READ-OK bytes={got}");
        }
    } else {
        unsafe {
            CloseHandle(h);
        }
        println!("{mode} OPEN-OK handle-acquired");
    }
}
