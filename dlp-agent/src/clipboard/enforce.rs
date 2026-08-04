//! Clipboard enforcement (spec §1.1 `enforce.rs`). Same dry-run contract as the
//! USB channel: `plan()` computes what would happen, `apply()` only touches the
//! system in `Mode::Live`. Every automated test uses `Mode::DryRun` and asserts
//! on the plan — no test ever clears the real clipboard (spec §1.5 / DO-NOT).
//!
//! Block = `EmptyClipboard()` so a subsequent paste yields nothing. Because our
//! own clear bumps the clipboard sequence number and re-fires
//! `WM_CLIPBOARDUPDATE`, a `LoopGuard` records the sequence we wrote and skips
//! the next update that matches it (spec §1.1 loop guard / §1.4 edge 4).

/// A concrete, inspectable description of what clipboard enforcement *would* do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardPlannedAction {
    /// Audit-only → no system change.
    NoChange,
    /// Block → empty the clipboard so the paste yields nothing. When
    /// `redaction_notice` is set, a short notice string is placed instead so the
    /// user sees why the paste was blocked.
    ClearClipboard { redaction_notice: Option<String> },
}

/// Whether an `apply()` is allowed to touch the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    DryRun,
    Live,
}

/// Outcome of applying a clipboard action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    NoChange,
    /// Dry-run only: reports the plan that would have run.
    Planned(ClipboardPlannedAction),
    /// Live enforcement succeeded.
    Executed(ClipboardPlannedAction),
}

/// Compute the enforcement plan. Pure — no I/O. `block == false` → audit only.
pub fn plan(block: bool, redaction_notice: Option<String>) -> ClipboardPlannedAction {
    if block {
        ClipboardPlannedAction::ClearClipboard { redaction_notice }
    } else {
        ClipboardPlannedAction::NoChange
    }
}

/// Apply a plan. In `Mode::DryRun` this executes NOTHING and returns
/// `Planned(..)`. In `Mode::Live` it performs the real clear (Windows) and
/// returns `Executed(..)`. On success in Live mode the caller is handed back the
/// plan so it can record the new sequence number in its `LoopGuard`.
pub fn apply(plan: &ClipboardPlannedAction, mode: Mode) -> anyhow::Result<ApplyOutcome> {
    if matches!(plan, ClipboardPlannedAction::NoChange) {
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

/// Loop guard (spec §1.1): our own `EmptyClipboard`/`SetClipboardData` bumps the
/// clipboard sequence number and re-fires `WM_CLIPBOARDUPDATE`. Record the
/// sequence number we just wrote; the next update carrying that number is our
/// own echo and must be ignored so we do not re-scan (and re-clear) forever.
#[derive(Debug, Default)]
pub struct LoopGuard {
    ignore_seq: Option<u32>,
}

impl LoopGuard {
    pub fn new() -> Self {
        LoopGuard { ignore_seq: None }
    }

    /// Record the sequence number produced by our own clipboard write.
    pub fn record_written(&mut self, seq: u32) {
        self.ignore_seq = Some(seq);
    }

    /// Should the update at `seq` be ignored? Consumes the guard for that seq so
    /// only ONE echo is suppressed (a later, genuine change at a new seq fires).
    pub fn should_ignore(&mut self, seq: u32) -> bool {
        if self.ignore_seq == Some(seq) {
            self.ignore_seq = None;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Live execution (Windows only). Never reached by tests. On non-Windows this is
// a stub so the library builds cross-platform.
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn execute_live(plan: &ClipboardPlannedAction) -> anyhow::Result<()> {
    use anyhow::Context;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard};

    let ClipboardPlannedAction::ClearClipboard { redaction_notice } = plan else {
        return Ok(());
    };

    // OpenClipboard(None) associates it with the current task; a NULL owner is
    // fine for a clear. A busy clipboard returns an error the caller degrades on.
    unsafe { OpenClipboard(HWND::default()) }.context("OpenClipboard for clear")?;
    let cleared = unsafe { EmptyClipboard() };
    if let Some(notice) = redaction_notice {
        // Best-effort: place a short redaction notice so the paste is not silent.
        let _ = set_clipboard_notice(notice);
    }
    let _ = unsafe { CloseClipboard() };
    cleared.context("EmptyClipboard")?;
    tracing::warn!("live enforcement: cleared clipboard (blocked sensitive copy)");
    Ok(())
}

/// Place a short UTF-16 redaction notice on the (already-open) clipboard so the
/// user's paste is not silently empty. Best-effort; failure is non-fatal.
#[cfg(windows)]
fn set_clipboard_notice(notice: &str) -> anyhow::Result<()> {
    use anyhow::Context;
    use windows::Win32::Foundation::{HANDLE, HGLOBAL};
    use windows::Win32::System::DataExchange::SetClipboardData;
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};

    const CF_UNICODETEXT: u32 = 13;
    let mut units: Vec<u16> = notice.encode_utf16().collect();
    units.push(0);
    let bytes = units.len() * 2;

    let hglobal: HGLOBAL = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes) }.context("GlobalAlloc")?;
    let ptr = unsafe { GlobalLock(hglobal) } as *mut u16;
    if ptr.is_null() {
        anyhow::bail!("GlobalLock returned null");
    }
    unsafe {
        std::ptr::copy_nonoverlapping(units.as_ptr(), ptr, units.len());
        let _ = GlobalUnlock(hglobal);
    }
    // Ownership of hglobal transfers to the clipboard on success.
    unsafe { SetClipboardData(CF_UNICODETEXT, HANDLE(hglobal.0)) }
        .context("SetClipboardData(redaction notice)")?;
    Ok(())
}

#[cfg(not(windows))]
fn execute_live(_plan: &ClipboardPlannedAction) -> anyhow::Result<()> {
    anyhow::bail!("live clipboard enforcement is only available on Windows")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_plans_no_change() {
        assert_eq!(plan(false, None), ClipboardPlannedAction::NoChange);
    }

    #[test]
    fn block_plans_clear() {
        assert_eq!(
            plan(true, None),
            ClipboardPlannedAction::ClearClipboard { redaction_notice: None }
        );
    }

    #[test]
    fn block_plans_clear_with_notice() {
        assert_eq!(
            plan(true, Some("blocked by DLP".into())),
            ClipboardPlannedAction::ClearClipboard {
                redaction_notice: Some("blocked by DLP".into())
            }
        );
    }

    #[test]
    fn dry_run_executes_nothing_and_returns_plan() {
        // Core safety property: dry-run must NOT clear the real clipboard.
        let p = plan(true, None);
        assert_eq!(apply(&p, Mode::DryRun).unwrap(), ApplyOutcome::Planned(p));
    }

    #[test]
    fn no_change_is_noop_in_any_mode() {
        assert_eq!(apply(&ClipboardPlannedAction::NoChange, Mode::DryRun).unwrap(), ApplyOutcome::NoChange);
        assert_eq!(apply(&ClipboardPlannedAction::NoChange, Mode::Live).unwrap(), ApplyOutcome::NoChange);
    }

    #[test]
    fn loop_guard_ignores_our_own_echo_once() {
        let mut g = LoopGuard::new();
        g.record_written(42);
        // The echo at seq 42 is our own write → ignore it.
        assert!(g.should_ignore(42));
        // Only once: a second update at 42 (or the same seq) is no longer ours.
        assert!(!g.should_ignore(42));
    }

    #[test]
    fn loop_guard_does_not_ignore_genuine_changes() {
        let mut g = LoopGuard::new();
        g.record_written(10);
        // A genuine new copy at a different seq must NOT be suppressed.
        assert!(!g.should_ignore(11));
        // And the recorded echo seq is still pending until it actually arrives.
        assert!(g.should_ignore(10));
    }

    #[test]
    fn fresh_guard_ignores_nothing() {
        let mut g = LoopGuard::new();
        assert!(!g.should_ignore(1));
    }
}
