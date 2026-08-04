//! Agent configuration. In production this is written by the MSI installer into
//! ProgramData; the enrollment token and CA certificate are provisioned with
//! the install. Environment variables override file values (used for testing).
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

use crate::usb::policy::{Action, DeviceRule, RuleMatch, UsbPolicy};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Base URL of the management server's mTLS listener, e.g.
    /// `https://dlp-server.internal:8443`. Its host MUST match a SAN in the
    /// server certificate, or CA-pinned verification fails.
    pub server_url: String,

    /// One-time enrollment token. Only needed until the agent has a certificate;
    /// ignored thereafter.
    #[serde(default)]
    pub enrollment_token: Option<String>,

    /// Path to the CA certificate (PEM) shipped with the installer. The agent
    /// pins this to verify the server from the very first connection — including
    /// enrollment — so it can never be pointed at a counterfeit console.
    pub ca_cert_path: PathBuf,

    /// Where the agent keeps its protected identity and cached state.
    pub state_dir: PathBuf,

    /// Fallback check-in cadence; the server's response takes precedence, so
    /// this is only a configuration knob for the initial value.
    #[serde(default = "default_checkin")]
    #[allow(dead_code)]
    pub checkin_interval_seconds: u64,

    /// Optional USB removable-media channel settings (spec §6). An absent
    /// `[usb]` section yields safe audit-only defaults, so existing configs
    /// keep working unchanged.
    #[serde(default)]
    pub usb: UsbConfig,

    /// Optional kernel-minifilter port-client settings (`usb-guard`). An absent
    /// `[kguard]` section yields safe defaults.
    #[serde(default)]
    pub kguard: KguardConfig,

    /// Optional clipboard channel settings (spec §1). An absent `[clipboard]`
    /// section yields safe audit-only defaults, so existing configs keep working.
    #[serde(default)]
    pub clipboard: ClipboardConfig,
}

fn default_checkin() -> u64 {
    300
}

/// USB channel configuration (spec §6). Every field is defaulted so the whole
/// section — and any individual field — may be omitted.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct UsbConfig {
    /// Master switch for the channel. Default false = the monitor idles unless
    /// explicitly turned on (opt-in), so merely having the binary does nothing.
    pub enabled: bool,
    /// Volume-set poll cadence in seconds (spec §3.2).
    pub poll_interval_secs: u64,
    /// Inspect-on-settle quiet window in milliseconds (spec §3.5).
    pub settle_ms: u64,
    /// Cap on the settle wait in seconds; a still-growing file is scanned once
    /// at this point, noted "settled-by-timeout" (spec §3.5).
    pub settle_timeout_secs: u64,
    /// Files larger than this are skipped with a note (spec §5 edge 3).
    pub max_file_bytes: u64,
    /// Action for devices no rule matches. Fail-secure default: `read_only`.
    pub default_action: Action,
    /// Incident channel label (spec §4). Default "usb".
    pub channel_label: String,
    /// Disposition for MTP/WPD devices (phones, cameras) that expose files but
    /// never mount a drive letter (spec §2.1). Default `Block` (defence). These
    /// bypass the `[[usb.rules]]` matrix — they get this knob instead.
    pub mtp_action: Action,
    /// Disposition for USB-tethering (RNDIS/NCM) network adapters that create an
    /// unmonitored egress path (spec §2.2). Default `Block`.
    pub tethering_action: Action,
    /// Ordered match rules (spec §6, `[[usb.rules]]`). First match wins.
    pub rules: Vec<UsbRule>,
}

impl Default for UsbConfig {
    fn default() -> Self {
        UsbConfig {
            enabled: false,
            poll_interval_secs: 2,
            settle_ms: 1500,
            settle_timeout_secs: 30,
            max_file_bytes: 104_857_600, // 100 MB
            default_action: Action::ReadOnly, // fail-secure
            channel_label: "usb".into(),
            mtp_action: Action::Block,        // defence default: deny phones/cameras
            tethering_action: Action::Block,  // defence default: deny USB egress
            rules: Vec::new(),
        }
    }
}

impl UsbConfig {
    /// Build the evaluated `UsbPolicy` from the config's default action + rules.
    pub fn to_policy(&self) -> UsbPolicy {
        UsbPolicy {
            default_action: self.default_action,
            rules: self.rules.iter().filter_map(UsbRule::to_device_rule).collect(),
        }
    }
}

/// Kernel-minifilter port-client configuration (`usb-guard`, SPEC §3). Every
/// field is defaulted so the whole `[kguard]` section may be omitted.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct KguardConfig {
    /// Block when a matched document's containment reaches this fraction
    /// (`idm[].containment >= block_at`). Default 0.30.
    pub block_at: f64,
    /// Block when a scanned file's coverage by protected material reaches this
    /// fraction (`idm[].coverage >= coverage_block_at`). Default 0.60.
    pub coverage_block_at: f64,
    /// What to answer the driver when NO verified bundle is cached, or a verdict
    /// cannot be produced (I/O error). `true` = block (fail-secure, classified
    /// sites); `false` = allow + audit (general use). Mirrors the driver's
    /// `FailMode`. Default `false` (matches the INF's shipped FailMode=0).
    pub fail_block: bool,
    /// Incident channel label for blocks/matches raised by the guard.
    pub channel_label: String,
    /// Inspect fixed-volume (C:) writes under the `watch_paths` prefixes
    /// (spec §3, minifilter extension). Default false = removable-only, the
    /// backward-compatible behavior. Sent to the driver in `DLP_CONFIG`.
    pub scan_fixed: bool,
    /// Inspect network (SMB) volume writes. Default false. Sent in `DLP_CONFIG`.
    pub scan_network: bool,
    /// Case-insensitive path prefixes the driver inspects on FIXED volumes
    /// (e.g. `\Users\*\OneDrive`, `\Dropbox`, staging dirs). Up to 16, each up
    /// to 260 wchars. Empty ⇒ the driver never attaches to fixed volumes
    /// (safety/back-compat invariant). Sent in `DLP_CONFIG`.
    pub watch_paths: Vec<String>,
}

impl Default for KguardConfig {
    fn default() -> Self {
        KguardConfig {
            block_at: 0.30,
            coverage_block_at: 0.60,
            fail_block: false,
            channel_label: "usb-kguard".into(),
            scan_fixed: false,
            scan_network: false,
            watch_paths: Vec::new(),
        }
    }
}

/// Clipboard channel action — clipboard has only two dispositions: audit the
/// copy (incident only) or block it by clearing the clipboard (spec §1.3).
/// Deserializes from `allow_audited` | `block`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardAction {
    AllowAudited,
    Block,
}

/// Clipboard channel configuration (spec §1.3). Every field is defaulted so the
/// whole `[clipboard]` section — and any individual field — may be omitted.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ClipboardConfig {
    /// Master switch. Default false = the monitor idles unless turned on.
    pub enabled: bool,
    /// Action for a clipboard payload that no signal flags. Default
    /// `allow_audited` (audit-only). Blocks come from a matched verdict, not this.
    pub default_action: ClipboardAction,
    /// Skip payloads larger than this many bytes with a note (spec §1.4 edge 5).
    pub max_bytes: u64,
    /// Block images wholesale (they cannot be inspected without OCR, spec §1.4
    /// edge 6). Default false = image copies are audited as "uninspected", not
    /// blocked.
    pub block_images: bool,
    /// Incident channel label (spec §1.3). Default "clipboard".
    pub channel_label: String,
    /// Block when a matched document's containment reaches this fraction
    /// (mirrors `[kguard] block_at`). Default 0.30.
    pub block_at: f64,
    /// Block when a payload's coverage by protected material reaches this
    /// fraction (mirrors `[kguard] coverage_block_at`). Default 0.60.
    pub coverage_block_at: f64,
    /// When no verified bundle is cached, block (`true`, fail-secure) or allow +
    /// audit (`false`). Default false. Only meaningful under `--enforce`.
    pub fail_block: bool,
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        ClipboardConfig {
            enabled: false,
            default_action: ClipboardAction::AllowAudited,
            max_bytes: 8_388_608, // 8 MB — clipboards are small; huge = skip
            block_images: false,
            channel_label: "clipboard".into(),
            block_at: 0.30,
            coverage_block_at: 0.60,
            fail_block: false,
        }
    }
}

/// A single TOML rule (`[[usb.rules]]`). Exactly one matcher should be set; the
/// first present matcher (serial → vid/pid → bus type → any) is used.
#[derive(Debug, Clone, Deserialize)]
pub struct UsbRule {
    #[serde(default)]
    pub match_serial: Option<String>,
    #[serde(default)]
    pub match_vid: Option<String>,
    #[serde(default)]
    pub match_pid: Option<String>,
    #[serde(default)]
    pub match_bus_type: Option<String>,
    #[serde(default)]
    pub match_any: bool,
    pub action: Action,
    #[serde(default)]
    pub note: Option<String>,
}

impl UsbRule {
    /// Convert to an evaluated `DeviceRule`, choosing the matcher by priority.
    /// A rule with no matcher at all is dropped (returns None) rather than
    /// silently becoming a catch-all.
    fn to_device_rule(&self) -> Option<DeviceRule> {
        let match_on = if let Some(s) = &self.match_serial {
            RuleMatch::Serial(s.clone())
        } else if let (Some(vid), Some(pid)) = (&self.match_vid, &self.match_pid) {
            RuleMatch::VidPid { vid: vid.clone(), pid: pid.clone() }
        } else if let Some(b) = &self.match_bus_type {
            RuleMatch::BusType(b.clone())
        } else if self.match_any {
            RuleMatch::Any
        } else {
            return None;
        };
        Some(DeviceRule { match_on, action: self.action, note: self.note.clone() })
    }
}

impl Config {
    /// Load from a TOML file, then apply DLP_AGENT_* environment overrides.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let mut cfg: Config = if path.exists() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading config {}", path.display()))?;
            toml::from_str(&text).with_context(|| "parsing config TOML")?
        } else {
            // No file: build entirely from environment (test convenience).
            Config {
                server_url: env_required("DLP_AGENT_SERVER_URL")?,
                enrollment_token: std::env::var("DLP_AGENT_TOKEN").ok(),
                ca_cert_path: PathBuf::from(env_required("DLP_AGENT_CA_CERT")?),
                state_dir: PathBuf::from(env_required("DLP_AGENT_STATE_DIR")?),
                checkin_interval_seconds: default_checkin(),
                usb: UsbConfig::default(),
                kguard: KguardConfig::default(),
                clipboard: ClipboardConfig::default(),
            }
        };

        if let Ok(v) = std::env::var("DLP_AGENT_SERVER_URL") {
            cfg.server_url = v;
        }
        if let Ok(v) = std::env::var("DLP_AGENT_TOKEN") {
            cfg.enrollment_token = Some(v);
        }
        if let Ok(v) = std::env::var("DLP_AGENT_CA_CERT") {
            cfg.ca_cert_path = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("DLP_AGENT_STATE_DIR") {
            cfg.state_dir = PathBuf::from(v);
        }
        Ok(cfg)
    }

    pub fn enroll_url(&self) -> String {
        format!("{}/agent/enroll", self.server_url.trim_end_matches('/'))
    }
    pub fn checkin_url(&self) -> String {
        format!("{}/agent/checkin", self.server_url.trim_end_matches('/'))
    }
    pub fn index_url(&self) -> String {
        format!("{}/agent/index", self.server_url.trim_end_matches('/'))
    }
    pub fn incidents_url(&self) -> String {
        format!("{}/agent/incidents", self.server_url.trim_end_matches('/'))
    }
}

fn env_required(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing required env {key} (and no config file)"))
}
