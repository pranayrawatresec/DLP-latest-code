//! Endpoint OCR / image-inspection policy — one console-managed switch every
//! channel honors (clipboard, USB, read-deny/RDP, browser upload). Delivered at
//! `GET /agent/ocr-policy`. Metadata only.
//!
//! A process-wide "active" copy is published at startup (and refreshed on resync)
//! so the classify sites can read it inline without threading it through the frozen
//! `detect::verdict*` signatures. Each site decides its own read-vs-write behavior:
//! the write/copy paths OCR inline; the synchronous kernel read path fail-secure
//! blocks an image instead (no time to OCR in the up-call budget).

use serde::{Deserialize, Serialize};
use std::sync::RwLock;

fn default_true() -> bool {
    true
}
fn default_max_pixels() -> u64 {
    8_000_000
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OcrPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_pixels", rename = "maxPixels")]
    pub max_pixels: u64,
    #[serde(default = "default_true", rename = "failBlock")]
    pub fail_block: bool,
}

impl Default for OcrPolicy {
    fn default() -> Self {
        OcrPolicy { enabled: false, max_pixels: default_max_pixels(), fail_block: true }
    }
}

// Process-wide active policy. Off until a process publishes the synced policy.
static ACTIVE: RwLock<Option<OcrPolicy>> = RwLock::new(None);

/// Publish the active OCR policy for this process (call at startup + on resync).
pub fn set_active(p: OcrPolicy) {
    match ACTIVE.write() {
        Ok(mut w) => *w = Some(p),
        Err(e) => *e.into_inner() = Some(p),
    }
}

/// The active OCR policy (default = off when never published).
pub fn active() -> OcrPolicy {
    match ACTIVE.read() {
        Ok(r) => r.clone().unwrap_or_default(),
        Err(e) => e.into_inner().clone().unwrap_or_default(),
    }
}

/// Convenience: is OCR/image-inspection turned on for this process?
pub fn enabled() -> bool {
    active().enabled
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_off_failsecure() {
        let p = OcrPolicy::default();
        assert!(!p.enabled);
        assert!(p.fail_block);
        assert_eq!(p.max_pixels, 8_000_000);
    }

    #[test]
    fn wire_omitted_fields_default() {
        let p: OcrPolicy = serde_json::from_str(r#"{"enabled":true}"#).unwrap();
        assert!(p.enabled);
        assert!(p.fail_block);
        assert_eq!(p.max_pixels, 8_000_000);
    }
}
