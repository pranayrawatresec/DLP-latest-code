//! Endpoint "blocked by DLP" notification (the user-facing toast).
//!
//! When any channel BLOCKS a sensitive action, the end user gets a native
//! Windows toast so they know *their machine's* DLP stopped it (and can call
//! security). This is UX only — enforcement already happened in the kernel /
//! agent; the toast is strictly best-effort and MUST never gate or delay a block.
//!
//! # The Session-0 problem (why "Option A: spawn-into-session")
//! The USB / clipboard / network guards run as a SYSTEM service in **Session 0**,
//! which cannot draw a toast on the interactive desktop. So when we detect we are
//! in Session 0 we re-launch ourselves (`dlp-agent toast …`) **inside the active
//! user session** via `WTSQueryUserToken` + `CreateProcessAsUserW`; that child
//! renders the WinRT toast. `browser-host` already runs in the user session, so it
//! renders directly. Everything is `#[cfg(windows)]` with cross-platform stubs.
//!
//! # Verbosity is a policy knob (`[notify] mode`)
//! `standard` shows file + channel + a local reference; it deliberately hides the
//! detection internals (which document, score, classifier) — that is evasion intel
//! for an insider. `minimal` drops the file/ref. `covert` suppresses the toast
//! entirely (block + log only) for counter-insider sites.

use crate::config::{NotifyConfig, NotifyMode};
use crate::usb::{ActionTaken, UsbIncident};

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Public entry points (cross-platform surface)
// ---------------------------------------------------------------------------

/// The single hook every channel's incident sink calls. Fires a toast iff the
/// incident is an actual BLOCK and notifications are enabled + non-covert.
/// Best-effort: any failure below is swallowed (logged) — enforcement stands.
pub fn on_block_for_incident(cfg: &NotifyConfig, inc: &UsbIncident) {
    if inc.action_taken != ActionTaken::Blocked {
        return; // audited / read-only / not-a-block: no toast
    }
    if !cfg.enabled || cfg.mode == NotifyMode::Covert {
        return; // policy: silent
    }
    if !throttle_allow(cfg, &inc.channel, &inc.file_name) {
        return; // coalesced / rate-capped (storm control)
    }
    let reference = next_reference();
    let (title, body) = build_message(cfg, inc, &reference);
    dispatch(&cfg.aumid, &title, &body);
}

/// Render a toast in the CURRENT session — used by the `dlp-agent toast`
/// subcommand that the Session-0 service spawns into the user session, and
/// usable directly when the agent already runs interactively.
pub fn show_toast_from_cli(title: &str, body: &str, aumid: &str) -> anyhow::Result<()> {
    show_toast(title, body, aumid)
}

/// Best-effort name of the interactive console user (for the incident's "who").
/// `None` if it cannot be determined (e.g. no interactive session).
pub fn current_user() -> Option<String> {
    console_username()
}

// ---------------------------------------------------------------------------
// Message building + throttling (pure; cross-platform, unit-tested)
// ---------------------------------------------------------------------------

/// Human label for the incident channel shown in the toast.
fn channel_label(channel: &str) -> &'static str {
    match channel {
        "usb" | "usb-kguard" => "USB / removable media",
        "clipboard" => "Clipboard",
        "web-upload" => "Web upload",
        "network" => "Network",
        _ => "Data transfer",
    }
}

/// Build (title, body) for the toast per the configured verbosity. NEVER includes
/// detection internals (matched document / score / classifier).
fn build_message(cfg: &NotifyConfig, inc: &UsbIncident, reference: &str) -> (String, String) {
    match cfg.mode {
        NotifyMode::Minimal => (
            cfg.org_name.clone(),
            "An action was blocked by security policy.".to_string(),
        ),
        NotifyMode::Standard => {
            let title = format!("Blocked by {}", cfg.org_name);
            let mut lines: Vec<String> = Vec::new();
            let file = sanitize_display(&inc.file_name);
            if !file.is_empty() {
                lines.push(format!("File: {file}"));
            }
            lines.push(format!("Channel: {}", channel_label(&inc.channel)));
            lines.push(format!("Ref: {reference} — contact security"));
            (title, lines.join("\n"))
        }
        // Gated out in on_block_for_incident; keep total for exhaustiveness.
        NotifyMode::Covert => (String::new(), String::new()),
    }
}

/// Trim a file name for safe single-line display: strip any path, control chars,
/// and quotes; clamp length. Never surfaces file contents (this is only a name).
fn sanitize_display(name: &str) -> String {
    let base = name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(name);
    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control() && *c != '"')
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.chars().count() > 96 {
        let mut s: String = cleaned.chars().take(93).collect();
        s.push_str("...");
        s
    } else {
        cleaned.to_string()
    }
}

/// XML-escape for the toast payload (WinRT `XmlDocument.LoadXml`).
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Short, local, human-quotable reference for the toast (e.g. `L-1A2B`). It is a
/// display aid only — the authoritative incident id is the server's.
fn next_reference() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("L-{:04X}", n & 0xFFFF)
}

struct Throttle {
    last_shown: HashMap<String, Instant>,
    window_start: Instant,
    count_in_window: u32,
}

static THROTTLE: OnceLock<Mutex<Throttle>> = OnceLock::new();

/// Storm control: suppress a repeat block of the SAME (channel, file) within the
/// dedup window, and cap the total toasts per rolling minute. Returns `true` if
/// this block is allowed to toast.
fn throttle_allow(cfg: &NotifyConfig, channel: &str, file: &str) -> bool {
    let m = THROTTLE.get_or_init(|| {
        Mutex::new(Throttle {
            last_shown: HashMap::new(),
            window_start: Instant::now(),
            count_in_window: 0,
        })
    });
    let mut t = match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(), // poisoned: proceed with recovered state
    };
    let now = Instant::now();

    // Rolling one-minute rate cap.
    if now.duration_since(t.window_start).as_secs() >= 60 {
        t.window_start = now;
        t.count_in_window = 0;
    }
    if cfg.max_per_minute != 0 && t.count_in_window >= cfg.max_per_minute {
        return false;
    }

    // Per-(channel,file) dedup window.
    let key = format!("{channel}\u{1}{file}");
    if let Some(&prev) = t.last_shown.get(&key) {
        if now.duration_since(prev).as_secs() < cfg.dedup_secs {
            return false;
        }
    }
    // Bound the dedup map so it cannot grow without limit.
    if t.last_shown.len() > 1024 {
        t.last_shown.clear();
    }
    t.last_shown.insert(key, now);
    t.count_in_window += 1;
    true
}

// ===========================================================================
// Windows implementation
// ===========================================================================
#[cfg(windows)]
mod imp {
    use super::xml_escape;
    use core::ffi::c_void;
    use windows::core::{HSTRING, PCWSTR, PWSTR};
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenSessionId, TOKEN_QUERY,
    };
    use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
    use windows::Win32::System::RemoteDesktop::{
        WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW, WTSQueryUserToken,
        WTSUserName, WTS_CURRENT_SERVER_HANDLE,
    };
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, GetCurrentProcess, OpenProcessToken, CREATE_NO_WINDOW,
        CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
    };
    use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};

    const INVALID_SESSION: u32 = 0xFFFF_FFFF;

    /// Show a WinRT toast in the current session under `aumid`.
    pub fn show_toast(title: &str, body: &str, aumid: &str) -> anyhow::Result<()> {
        let xml = format!(
            "<toast activationType=\"foreground\"><visual><binding template=\"ToastGeneric\">\
             <text>{}</text><text>{}</text></binding></visual></toast>",
            xml_escape(title),
            xml_escape(body)
        );
        let doc = XmlDocument::new()?;
        doc.LoadXml(&HSTRING::from(xml))?;
        let toast = ToastNotification::CreateToastNotification(&doc)?;
        let notifier =
            ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(aumid))?;
        notifier.Show(&toast)?;
        Ok(())
    }

    /// Decide where the toast must render and get it there. Never propagates an
    /// error — the block already happened; a toast failure is only logged.
    pub fn dispatch(aumid: &str, title: &str, body: &str) {
        match current_session() {
            // Session 0 == the SYSTEM service: hop into the interactive session.
            Some(0) | None => {
                let session = unsafe { WTSGetActiveConsoleSessionId() };
                if session == INVALID_SESSION {
                    tracing::debug!("no interactive console session — toast skipped (block stands)");
                    return;
                }
                if let Err(e) = spawn_toast_in_session(session, aumid, title, body) {
                    tracing::warn!(error = %e, "could not deliver toast to user session (block stands)");
                }
            }
            // Already interactive (browser-host, or manual/admin run): render here.
            Some(_) => {
                if let Err(e) = show_toast(title, body, aumid) {
                    tracing::warn!(error = %e, "toast render failed (block stands)");
                }
            }
        }
    }

    /// Session id of the current process, or `None` if it cannot be queried.
    /// Read from our own access token (`TokenSessionId`) — avoids depending on
    /// `ProcessIdToSessionId`, whose module path varies across `windows` versions.
    fn current_session() -> Option<u32> {
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
            let _guard = HandleGuard(token);
            let mut sid: u32 = 0;
            let mut ret_len: u32 = 0;
            GetTokenInformation(
                token,
                TokenSessionId,
                Some(&mut sid as *mut u32 as *mut c_void),
                core::mem::size_of::<u32>() as u32,
                &mut ret_len,
            )
            .ok()?;
            Some(sid)
        }
    }

    /// Re-launch `dlp-agent toast …` inside `session` under that user's token, so
    /// the child renders the toast on the interactive desktop.
    fn spawn_toast_in_session(
        session: u32,
        aumid: &str,
        title: &str,
        body: &str,
    ) -> anyhow::Result<()> {
        unsafe {
            let mut token = HANDLE::default();
            WTSQueryUserToken(session, &mut token)
                .map_err(|e| anyhow::anyhow!("WTSQueryUserToken(session {session}): {e}"))?;
            let _token_guard = HandleGuard(token);

            // User environment (best-effort; toast still works without it).
            let mut env: *mut core::ffi::c_void = core::ptr::null_mut();
            let have_env = CreateEnvironmentBlock(&mut env, token, BOOL(0)).is_ok();

            let exe = std::env::current_exe()
                .map_err(|e| anyhow::anyhow!("current_exe: {e}"))?;
            let cmdline = build_toast_cmdline(&exe.to_string_lossy(), aumid, title, body);
            let mut cmd_w: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
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

            created.map_err(|e| anyhow::anyhow!("CreateProcessAsUserW: {e}"))?;
            let _ = CloseHandle(pi.hThread);
            let _ = CloseHandle(pi.hProcess);
            Ok(())
        }
    }

    /// Build the child command line, quoting each argument. Title/body are already
    /// display-sanitized upstream; we additionally strip embedded quotes here so an
    /// argument can never break out of its quotes.
    fn build_toast_cmdline(exe: &str, aumid: &str, title: &str, body: &str) -> String {
        fn q(s: &str) -> String {
            let cleaned: String = s.chars().filter(|c| *c != '"' && !matches!(c, '\r')).collect();
            // Toast body newlines are meaningful; pass them as a literal token the
            // child splits back into lines.
            let cleaned = cleaned.replace('\n', "\u{2028}");
            format!("\"{cleaned}\"")
        }
        format!(
            "{} toast --aumid {} --title {} --body {}",
            q(exe),
            q(aumid),
            q(title),
            q(body)
        )
    }

    /// The interactive console user's login name (best-effort), for the incident.
    pub fn console_username() -> Option<String> {
        unsafe {
            let session = WTSGetActiveConsoleSessionId();
            if session == INVALID_SESSION {
                return None;
            }
            let mut buffer: PWSTR = PWSTR::null();
            let mut bytes: u32 = 0;
            WTSQuerySessionInformationW(
                WTS_CURRENT_SERVER_HANDLE,
                session,
                WTSUserName,
                &mut buffer,
                &mut bytes,
            )
            .ok()?;
            if buffer.is_null() {
                return None;
            }
            let name = buffer.to_string().ok().filter(|s| !s.is_empty());
            WTSFreeMemory(buffer.0 as *mut core::ffi::c_void);
            name
        }
    }

    /// RAII closer for a token HANDLE.
    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }
}

#[cfg(windows)]
fn dispatch(aumid: &str, title: &str, body: &str) {
    imp::dispatch(aumid, title, body);
}
#[cfg(windows)]
fn show_toast(title: &str, body: &str, aumid: &str) -> anyhow::Result<()> {
    imp::show_toast(title, body, aumid)
}
#[cfg(windows)]
fn console_username() -> Option<String> {
    imp::console_username()
}

// ===========================================================================
// Non-Windows stubs (so the crate builds + pure logic runs cross-platform)
// ===========================================================================
#[cfg(not(windows))]
fn dispatch(_aumid: &str, _title: &str, _body: &str) {
    tracing::debug!("endpoint toast is Windows-only — skipped");
}
#[cfg(not(windows))]
fn show_toast(_title: &str, _body: &str, _aumid: &str) -> anyhow::Result<()> {
    Ok(())
}
#[cfg(not(windows))]
fn console_username() -> Option<String> {
    None
}

// ---------------------------------------------------------------------------
// Tests (pure logic only; no OS side effects)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NotifyConfig;
    use crate::usb::{ActionTaken, DeviceIdentity, IncidentKind, UsbIncident};

    fn dev() -> DeviceIdentity {
        DeviceIdentity {
            drive_letter: "E:".into(),
            vendor_id: String::new(),
            product_id: String::new(),
            serial: String::new(),
            product_name: String::new(),
            bus_type: "usb".into(),
            removable: true,
        }
    }

    fn inc(action: ActionTaken, channel: &str, file: &str) -> UsbIncident {
        UsbIncident {
            kind: IncidentKind::Match,
            channel: channel.into(),
            file_name: file.into(),
            file_sha256: String::new(),
            verdict: None,
            device: dev(),
            action_taken: action,
            note: None,
            key_id: None,
            sealed_sha256: None,
        }
    }

    #[test]
    fn standard_message_has_file_channel_ref_but_no_internals() {
        let cfg = NotifyConfig::default();
        let i = inc(ActionTaken::Blocked, "usb", "C:\\secret\\OPORD.pdf");
        let (title, body) = build_message(&cfg, &i, "L-00AB");
        assert!(title.contains(&cfg.org_name));
        assert!(body.contains("OPORD.pdf"), "shows the bare file name");
        assert!(!body.contains("C:\\"), "strips the path");
        assert!(body.contains("USB"), "shows the channel");
        assert!(body.contains("L-00AB"), "shows the reference");
        // No detection internals leak into the toast.
        assert!(!body.to_lowercase().contains("containment"));
        assert!(!body.to_lowercase().contains("idm"));
    }

    #[test]
    fn minimal_mode_hides_file_and_ref() {
        let mut cfg = NotifyConfig::default();
        cfg.mode = NotifyMode::Minimal;
        let i = inc(ActionTaken::Blocked, "usb", "OPORD.pdf");
        let (_t, body) = build_message(&cfg, &i, "L-00AB");
        assert!(!body.contains("OPORD"));
        assert!(!body.contains("L-00AB"));
    }

    #[test]
    fn sanitize_strips_path_control_and_quotes_and_clamps() {
        assert_eq!(sanitize_display("C:\\a\\b\\report.pdf"), "report.pdf");
        assert_eq!(sanitize_display("na\"me\t.txt"), "name.txt");
        let long = "x".repeat(200);
        let out = sanitize_display(&long);
        assert!(out.chars().count() <= 96);
        assert!(out.ends_with("..."));
    }

    #[test]
    fn xml_escape_encodes_markup() {
        assert_eq!(xml_escape("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&apos;");
    }

    #[test]
    fn dedup_suppresses_same_channel_file_within_window() {
        let cfg = NotifyConfig { dedup_secs: 60, max_per_minute: 0, ..NotifyConfig::default() };
        // Unique key so the shared static state doesn't collide across tests.
        assert!(throttle_allow(&cfg, "unit-dedup", "same.pdf"));
        assert!(!throttle_allow(&cfg, "unit-dedup", "same.pdf"), "second within window suppressed");
        assert!(throttle_allow(&cfg, "unit-dedup", "other.pdf"), "different file allowed");
    }

    #[test]
    fn covert_and_disabled_never_toast() {
        // These go through the public entry; we can only assert they don't panic
        // and return quickly (dispatch is a no-op path when gated).
        let mut cfg = NotifyConfig::default();
        cfg.mode = NotifyMode::Covert;
        on_block_for_incident(&cfg, &inc(ActionTaken::Blocked, "usb", "x.pdf"));
        cfg.mode = NotifyMode::Standard;
        cfg.enabled = false;
        on_block_for_incident(&cfg, &inc(ActionTaken::Blocked, "usb", "x.pdf"));
        // Non-block action never toasts either.
        cfg.enabled = true;
        on_block_for_incident(&cfg, &inc(ActionTaken::Audited, "usb", "x.pdf"));
    }
}
