//! Launch and supervise a per-user-session child process from the Session-0
//! service (WTS + `CreateProcessAsUserW`). The DLPAgent service runs as LocalSystem
//! in **session 0**, which has its OWN clipboard/window-station — NOT the logged-in
//! user's. So the clipboard monitor must run as a child **inside the interactive
//! user session**. This mirrors the toast-spawn in [`crate::notify`], but returns a
//! handle so the supervisor can detect exit (logoff / crash) and relaunch.
//!
//! Non-Windows builds get inert stubs so the crate still compiles.

/// A child process launched into a user session. Closes its process handle on
/// drop; call [`terminate`](Self::terminate) first to stop the child.
#[cfg(windows)]
pub struct SessionChild {
    proc: windows::Win32::Foundation::HANDLE,
    pub session: u32,
}

#[cfg(windows)]
impl SessionChild {
    /// True while the child is still running (GetExitCodeProcess == STILL_ACTIVE).
    pub fn is_alive(&self) -> bool {
        use windows::Win32::System::Threading::GetExitCodeProcess;
        const STILL_ACTIVE: u32 = 259;
        let mut code: u32 = 0;
        unsafe { GetExitCodeProcess(self.proc, &mut code).is_ok() && code == STILL_ACTIVE }
    }

    /// Ask the child to exit (TerminateProcess). Best-effort.
    pub fn terminate(&self) {
        use windows::Win32::System::Threading::TerminateProcess;
        unsafe {
            let _ = TerminateProcess(self.proc, 1);
        }
    }
}

#[cfg(windows)]
impl Drop for SessionChild {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        unsafe {
            let _ = CloseHandle(self.proc);
        }
    }
}

/// The interactive console session id, or `None` when there is no interactive
/// user (session 0 / the login screen). The clipboard helper is spawned here.
#[cfg(windows)]
pub fn active_console_session() -> Option<u32> {
    use windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
    const INVALID_SESSION: u32 = 0xFFFF_FFFF;
    let s = unsafe { WTSGetActiveConsoleSessionId() };
    // 0xFFFFFFFF = no session attached; 0 = the service session (no interactive user).
    if s == INVALID_SESSION || s == 0 {
        None
    } else {
        Some(s)
    }
}

/// Spawn `dlp-agent <args…>` inside `session` under that user's token, on the
/// interactive desktop (`winsta0\default`). Returns a handle the caller supervises.
#[cfg(windows)]
pub fn spawn_in_session(session: u32, args: &[&str]) -> anyhow::Result<SessionChild> {
    use anyhow::anyhow;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
    use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
    use windows::Win32::System::RemoteDesktop::WTSQueryUserToken;
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION,
        STARTUPINFOW,
    };

    unsafe {
        let mut token = HANDLE::default();
        WTSQueryUserToken(session, &mut token)
            .map_err(|e| anyhow!("WTSQueryUserToken(session {session}): {e}"))?;

        // User environment (best-effort; the child still runs without it).
        let mut env: *mut core::ffi::c_void = core::ptr::null_mut();
        let have_env = CreateEnvironmentBlock(&mut env, token, BOOL(0)).is_ok();

        let exe = std::env::current_exe().map_err(|e| anyhow!("current_exe: {e}"))?;
        // Build a quoted command line: "exe" "arg1" "arg2" … . Args here are fixed
        // internal tokens (subcommand + flags), never user text; strip stray quotes
        // defensively so an argument can't break out of its quotes.
        let mut cmd = String::new();
        cmd.push('"');
        cmd.push_str(&exe.to_string_lossy());
        cmd.push('"');
        for a in args {
            cmd.push(' ');
            cmd.push('"');
            cmd.push_str(&a.replace('"', ""));
            cmd.push('"');
        }
        let mut cmd_w: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
        let mut desktop_w: Vec<u16> =
            "winsta0\\default".encode_utf16().chain(std::iter::once(0)).collect();

        let si = STARTUPINFOW {
            cb: core::mem::size_of::<STARTUPINFOW>() as u32,
            lpDesktop: PWSTR(desktop_w.as_mut_ptr()),
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        let env_ptr: Option<*const core::ffi::c_void> =
            if have_env { Some(env as *const _) } else { None };

        let created = CreateProcessAsUserW(
            token,
            PCWSTR::null(),
            PWSTR(cmd_w.as_mut_ptr()),
            None,
            None,
            BOOL(0),
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            env_ptr,
            PCWSTR::null(),
            &si,
            &mut pi,
        );

        if have_env {
            let _ = DestroyEnvironmentBlock(env);
        }
        let _ = CloseHandle(token);

        created.map_err(|e| anyhow!("CreateProcessAsUserW: {e}"))?;
        let _ = CloseHandle(pi.hThread);
        Ok(SessionChild { proc: pi.hProcess, session })
    }
}

// ---- non-Windows stubs (the crate is Windows-targeted; keep it cross-compiling) --

#[cfg(not(windows))]
pub struct SessionChild {
    pub session: u32,
}

#[cfg(not(windows))]
impl SessionChild {
    pub fn is_alive(&self) -> bool {
        false
    }
    pub fn terminate(&self) {}
}

#[cfg(not(windows))]
pub fn active_console_session() -> Option<u32> {
    None
}

#[cfg(not(windows))]
pub fn spawn_in_session(_session: u32, _args: &[&str]) -> anyhow::Result<SessionChild> {
    anyhow::bail!("per-session spawn is only available on Windows")
}
