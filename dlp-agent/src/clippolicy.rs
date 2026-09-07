//! Endpoint CLIPBOARD policy — the console-managed mode the DLPAgent service's
//! per-session clipboard helper applies. Delivered at `GET /agent/clipboard-policy`
//! (see the server route). Metadata only — no secrets, and NEVER any clipboard
//! content.
//!
//! Model A (strict): a sensitive copy is blocked regardless of the paste
//! destination — there is no per-app exception. `mode` maps onto the existing
//! [`crate::config::ClipboardConfig`] the monitor already understands:
//!
//!   off     -> disabled (helper idle)
//!   monitor -> enabled, `AllowAudited` (classify + incident, but ALLOW the paste)
//!   enforce -> enabled, `Block` (clear the clipboard so the paste yields nothing)

use serde::{Deserialize, Serialize};

use crate::config::{ClipboardAction, ClipboardConfig, Config};

/// Off | Monitor | Enforce. Defaults to `Off` so an absent/unknown value (older
/// cache, older server) leaves clipboard protection inert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ClipboardMode {
    #[default]
    Off,
    Monitor,
    Enforce,
}

impl std::fmt::Display for ClipboardMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ClipboardMode::Off => "off",
            ClipboardMode::Monitor => "monitor",
            ClipboardMode::Enforce => "enforce",
        })
    }
}

fn default_true() -> bool {
    true
}

/// The wire + at-rest shape of the clipboard policy (`{mode, blockImages, failBlock}`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClipboardPolicy {
    #[serde(default)]
    pub mode: ClipboardMode,
    #[serde(default, rename = "blockImages")]
    pub block_images: bool,
    /// Fail-secure default TRUE (block when a verdict can't be produced).
    #[serde(default = "default_true", rename = "failBlock")]
    pub fail_block: bool,
}

impl Default for ClipboardPolicy {
    fn default() -> Self {
        ClipboardPolicy {
            mode: ClipboardMode::Off,
            block_images: false,
            fail_block: true,
        }
    }
}

impl ClipboardPolicy {
    /// Protection is inert (the helper need not run).
    pub fn is_off(&self) -> bool {
        matches!(self.mode, ClipboardMode::Off)
    }

    /// Enforce (block) vs monitor (audit-only).
    pub fn enforce(&self) -> bool {
        matches!(self.mode, ClipboardMode::Enforce)
    }

    /// Override the local `[clipboard]` config so the console is the single source
    /// of truth. The monitor blocks only when `enabled` AND `default_action=Block`
    /// AND it is run with enforce=true — [`enforce`](Self::enforce) drives all three.
    pub fn apply_to_config(&self, cfg: &mut Config) {
        self.apply(&mut cfg.clipboard);
    }

    /// Pure mapping onto a `[clipboard]` config section (unit-tested).
    pub fn apply(&self, c: &mut ClipboardConfig) {
        c.enabled = !self.is_off();
        c.default_action = if self.enforce() {
            ClipboardAction::Block
        } else {
            ClipboardAction::AllowAudited
        };
        c.block_images = self.block_images;
        c.fail_block = self.fail_block;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_off_failsecure() {
        let p = ClipboardPolicy::default();
        assert!(p.is_off());
        assert!(!p.enforce());
        assert!(p.fail_block);
    }

    #[test]
    fn wire_omitted_fields_default() {
        // Older server omits blockImages/failBlock → block_images false, fail_block true.
        let p: ClipboardPolicy = serde_json::from_str(r#"{"mode":"enforce"}"#).unwrap();
        assert_eq!(p.mode, ClipboardMode::Enforce);
        assert!(!p.block_images);
        assert!(p.fail_block);
        // Entirely empty → off.
        let e: ClipboardPolicy = serde_json::from_str("{}").unwrap();
        assert!(e.is_off());
    }

    #[test]
    fn maps_modes_onto_clipboard_config() {
        let mut c = ClipboardConfig::default();

        ClipboardPolicy { mode: ClipboardMode::Off, block_images: true, fail_block: true }.apply(&mut c);
        assert!(!c.enabled);

        ClipboardPolicy { mode: ClipboardMode::Monitor, block_images: false, fail_block: false }.apply(&mut c);
        assert!(c.enabled);
        assert_eq!(c.default_action, ClipboardAction::AllowAudited);
        assert!(!c.fail_block);

        ClipboardPolicy { mode: ClipboardMode::Enforce, block_images: true, fail_block: true }.apply(&mut c);
        assert!(c.enabled);
        assert_eq!(c.default_action, ClipboardAction::Block);
        assert!(c.block_images);
        assert!(c.fail_block);
    }
}
