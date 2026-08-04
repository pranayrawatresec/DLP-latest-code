//! Clipboard change listener (spec §1.1 `watch.rs`).
//!
//! A **message-only** window (`HWND_MESSAGE`) registers with
//! `AddClipboardFormatListener`; Windows then posts `WM_CLIPBOARDUPDATE` to its
//! queue on every clipboard change. We dedup with `GetClipboardSequenceNumber`.
//!
//! CRITICAL (spec §1.1 / DO-NOT): the message pump is `#[cfg(windows)]` and is
//! NEVER reachable from a test — a running pump would hang `cargo test`. The
//! reaction to each update is a closure the caller supplies; the pure decision
//! it calls (`clipboard::inspect`) is what the tests exercise directly. On
//! non-Windows every function here is an inert stub so the crate still builds.
//!
//! NEVER logs clipboard content — only the read bytes flow into the fingerprint
//! math via `formats` (spec §1.3).

use super::formats::{self, ClipboardPayload};

/// Current clipboard sequence number — bumps on every change, including our own
/// clear. Used for dedup/debounce and the enforce loop guard. 0 on non-Windows.
#[cfg(windows)]
pub fn sequence_number() -> u32 {
    use windows::Win32::System::DataExchange::GetClipboardSequenceNumber;
    unsafe { GetClipboardSequenceNumber() }
}

#[cfg(not(windows))]
pub fn sequence_number() -> u32 {
    0
}

/// Read + classify the current clipboard into a `ClipboardPayload`, preferring
/// the most inspectable format present (files > text > html/rtf > image). A
/// clipboard locked by another process is retried a few times, then reported as
/// an `Uninspected` note rather than spun on (spec §1.4 edge 1). Delayed-render
/// data that comes back NULL is handled gracefully (edge 2).
#[cfg(windows)]
pub fn read_snapshot() -> ClipboardPayload {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::DataExchange::{
        CloseClipboard, IsClipboardFormatAvailable, OpenClipboard,
    };

    // Bounded open-with-backoff: never spin on a locked clipboard.
    let mut opened = false;
    for attempt in 0..5u32 {
        if unsafe { OpenClipboard(HWND::default()) }.is_ok() {
            opened = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20 * (attempt as u64 + 1)));
    }
    if !opened {
        return ClipboardPayload::Uninspected("clipboard-locked".into());
    }

    let html_fmt = register_format("HTML Format");
    let rtf_fmt = register_format("Rich Text Format");

    let available = |fmt: u32| -> bool { unsafe { IsClipboardFormatAvailable(fmt) }.is_ok() };

    let payload = if available(formats::CF_HDROP) {
        match read_global(formats::CF_HDROP) {
            Some(bytes) => ClipboardPayload::Files(formats::parse_hdrop(&bytes)),
            None => ClipboardPayload::Uninspected("hdrop-null".into()),
        }
    } else if available(formats::CF_UNICODETEXT) {
        match read_global(formats::CF_UNICODETEXT) {
            Some(bytes) => ClipboardPayload::Text(formats::parse_unicode_text(&bytes)),
            None => ClipboardPayload::Uninspected("text-null".into()),
        }
    } else if html_fmt != 0 && available(html_fmt) {
        match read_global(html_fmt) {
            Some(bytes) => ClipboardPayload::Text(formats::strip_html(&String::from_utf8_lossy(&bytes))),
            None => ClipboardPayload::Uninspected("html-null".into()),
        }
    } else if rtf_fmt != 0 && available(rtf_fmt) {
        match read_global(rtf_fmt) {
            Some(bytes) => ClipboardPayload::Text(formats::strip_rtf(&String::from_utf8_lossy(&bytes))),
            None => ClipboardPayload::Uninspected("rtf-null".into()),
        }
    } else if available(formats::CF_DIB)
        || available(formats::CF_BITMAP)
        || available(formats::CF_DIBV5)
    {
        ClipboardPayload::Image
    } else {
        ClipboardPayload::Uninspected("unhandled-format".into())
    };

    unsafe {
        let _ = CloseClipboard();
    }
    payload
}

#[cfg(not(windows))]
pub fn read_snapshot() -> ClipboardPayload {
    ClipboardPayload::Uninspected("non-windows".into())
}

/// Register (or look up) a named clipboard format. Returns 0 on failure.
#[cfg(windows)]
fn register_format(name: &str) -> u32 {
    use windows::core::PCWSTR;
    use windows::Win32::System::DataExchange::RegisterClipboardFormatW;
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { RegisterClipboardFormatW(PCWSTR(wide.as_ptr())) }
}

/// Copy a global-memory clipboard object for `fmt` into an owned byte vector.
/// Returns None on delayed-render NULL or a failed lock (spec §1.4 edge 2). The
/// clipboard must already be open.
#[cfg(windows)]
fn read_global(fmt: u32) -> Option<Vec<u8>> {
    use windows::Win32::Foundation::HGLOBAL;
    use windows::Win32::System::DataExchange::GetClipboardData;
    use windows::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};

    let handle = unsafe { GetClipboardData(fmt) }.ok()?;
    if handle.is_invalid() {
        return None; // delayed render / not really present
    }
    let hglobal = HGLOBAL(handle.0);
    let size = unsafe { GlobalSize(hglobal) };
    if size == 0 {
        return None;
    }
    let ptr = unsafe { GlobalLock(hglobal) } as *const u8;
    if ptr.is_null() {
        return None;
    }
    let mut bytes = vec![0u8; size];
    unsafe {
        std::ptr::copy_nonoverlapping(ptr, bytes.as_mut_ptr(), size);
        let _ = GlobalUnlock(hglobal);
    }
    Some(bytes)
}

/// Create a message-only window, register the clipboard listener, and pump
/// messages, invoking `on_update` on each `WM_CLIPBOARDUPDATE`. Blocks until the
/// window is destroyed / the pump ends (operator-manual; never in a test).
///
/// Because `AddClipboardFormatListener` POSTS `WM_CLIPBOARDUPDATE` to the queue,
/// we can handle it directly in the `GetMessage` loop with a `DefWindowProc`
/// class — no custom wndproc/user-data plumbing needed.
#[cfg(windows)]
pub fn run_listener<F>(mut on_update: F) -> anyhow::Result<()>
where
    F: FnMut(),
{
    use anyhow::Context;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HINSTANCE, HWND};
    use windows::Win32::System::DataExchange::AddClipboardFormatListener;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DispatchMessageW, GetMessageW, TranslateMessage, HMENU, HWND_MESSAGE, MSG,
        WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLIPBOARDUPDATE,
    };

    // Use the always-registered built-in "STATIC" window class for the
    // message-only window (no RegisterClassW → no Win32_Graphics_Gdi dependency).
    // AddClipboardFormatListener POSTS WM_CLIPBOARDUPDATE to the thread queue, so
    // the default wndproc is fine — the GetMessage loop below handles the update.
    let class_name: Vec<u16> = "STATIC".encode_utf16().chain(std::iter::once(0)).collect();

    let hwnd: HWND = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            PCWSTR(class_name.as_ptr()),
            PCWSTR::null(),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            HMENU::default(),
            HINSTANCE::default(),
            None,
        )
    }
    .context("CreateWindowExW(message-only) failed")?;

    unsafe { AddClipboardFormatListener(hwnd) }
        .context("AddClipboardFormatListener failed")?;

    tracing::info!("clipboard listener window created — pumping WM_CLIPBOARDUPDATE");

    // Message pump. GetMessage returns 0 on WM_QUIT, -1 on error.
    let mut msg = MSG::default();
    loop {
        let got = unsafe { GetMessageW(&mut msg, HWND::default(), 0, 0) };
        if got.0 == 0 {
            break; // WM_QUIT
        }
        if got.0 == -1 {
            anyhow::bail!("GetMessageW failed");
        }
        if msg.message == WM_CLIPBOARDUPDATE {
            on_update();
        } else {
            unsafe {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn run_listener<F>(_on_update: F) -> anyhow::Result<()>
where
    F: FnMut(),
{
    anyhow::bail!("clipboard listener is only available on Windows")
}
