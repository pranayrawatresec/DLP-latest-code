//! Windows built-in Bluetooth file transfer. Detection is shared; disposition
//! belongs to this channel, independently of generic read-deny and ML audit mode.
use crate::detect::{self, Bands, Extraction, Verdict};
use serde::{Deserialize, Serialize};

pub const CHANNEL: &str = "bluetooth";
pub const POLICY_MAGIC: u32 = 0x4270_6c44; // DlpB; mirrored in dlpflt.h
pub const PROTOCOL: u32 = 1;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Off,
    Monitor,
    Enforce,
}

impl Mode {
    pub fn wire(self) -> u32 {
        match self {
            Self::Off => 0,
            Self::Enforce => 1,
            Self::Monitor => 2,
        }
    }
}

#[repr(C)]
pub struct PolicyMessage {
    pub magic: u32,
    pub protocol: u32,
    pub mode: u32,
}
const _: () = assert!(core::mem::size_of::<PolicyMessage>() == 12);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Sensitive,
    Clean,
    Unknown(&'static str),
}

/// No clean prefix, missing detector, or failed extraction becomes an ALLOW.
/// A positive detector always wins, including when the other is unavailable.
pub fn decide(
    verdict: Option<&Verdict>,
    bands: &Bands,
    ml_required: bool,
    truncated: bool,
) -> Decision {
    let Some(v) = verdict else {
        return Decision::Unknown("fingerprints-unavailable");
    };
    if detect::decide(v, bands).sensitive {
        return Decision::Sensitive;
    }
    if truncated {
        return Decision::Unknown("file-exceeds-scan-limit");
    }
    if matches!(v.extraction, Extraction::Unreadable { .. }) {
        return Decision::Unknown("content-unreadable");
    }
    if ml_required && !v.ml.as_ref().is_some_and(|m| m.is_ok()) {
        return Decision::Unknown("classification-pending-or-unavailable");
    }
    Decision::Clean
}
