//! Agent configuration. In production this is written by the MSI installer into
//! ProgramData; the enrollment token and CA certificate are provisioned with
//! the install. Environment variables override file values (used for testing).
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

use std::collections::HashMap;

use crate::netfilter::remote_tools::ToolAction;
use crate::netfilter::rules::{Cidr, NetMode, NetRule, RuleAction};
use crate::trustdest::{BlockBandPolicy, EncryptBands, EncryptMode};
use crate::trustedreaders::{SyncedReader, TrustedReaderRule};
use crate::trustsync::{merge_into_usb, SyncedDestination};
use crate::usb::device::DeviceIdentity;
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

    /// Optional network-egress (WFP) channel settings (Tier-2 plan §2). An absent
    /// `[netfilter]` section yields the safe `monitor` default (NEVER default-deny),
    /// so existing configs keep working unchanged.
    #[serde(default)]
    pub netfilter: NetfilterConfig,

    /// Optional endpoint-notification settings (`[notify]`). Controls the native
    /// Windows "blocked by DLP" toast the agent shows the end user on any block.
    /// An absent section yields the safe default: toasts ON, standard verbosity.
    #[serde(default)]
    pub notify: NotifyConfig,

    /// Optional trusted-destination encryption settings (`[crypto]`,
    /// encrypt-on-write spec §3.2). An absent section yields defaults, so
    /// existing configs keep parsing unchanged.
    #[serde(default)]
    pub crypto: CryptoConfig,

    /// Optional web-upload trusted-origin settings (`[webupload]`, consumed by
    /// the browser-host channel in M7). Absent ⇒ no trusted origins.
    #[serde(default)]
    pub webupload: WebuploadConfig,

    /// Sanctioned-reader allowlist (`[[trusted_readers]]`) — the applications
    /// allowed to read sensitive content locally under the read-deny
    /// **allowlist** posture (`[kguard] exfil_posture = "allowlist"`). Every
    /// process NOT matching one of these is treated as an untrusted reader and
    /// pushed to the driver for read-deny. Empty in the default *blocklist*
    /// posture (where it is unused), so existing configs keep working. The
    /// console-authored list is merged in over mTLS via [`Config::with_synced_readers`].
    #[serde(default)]
    pub trusted_readers: Vec<TrustedReaderRule>,
}

/// Read-deny classification posture (`[kguard] exfil_posture`).
///
/// * `Blocklist` (default, UNCHANGED behaviour) — a process is an exfil channel
///   only if it matches a remote-tool SIGNATURE, holds a public connection, or
///   hosts a VM ([`crate::exfil::compute_exfil_pids`]). Robust against nothing
///   new; the shipped default so turning read-deny on changes nothing else.
/// * `Allowlist` — a process is an untrusted reader UNLESS it is on the
///   sanctioned-reader allowlist ([`Config::trusted_readers`]). Scales against
///   unknown tools (a never-before-seen uploader isn't on the allowlist, so it
///   is denied at the read). This is the recommended posture; pair it with a
///   curated allowlist (monitor → measure → enforce).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExfilPosture {
    Blocklist,
    Allowlist,
}

fn default_checkin() -> u64 {
    300
}

/// How much the endpoint "blocked by DLP" toast reveals to the user.
///
/// Defence trade-off: enough for a legitimate employee to understand and call
/// security, but never the detection internals (which document matched, score,
/// classifier) — that is evasion intel for an insider. `Covert` suppresses the
/// toast entirely (block + log only) for counter-insider deployments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotifyMode {
    /// "Blocked by <Org> DLP · File · Channel · Ref" — no detection internals.
    Standard,
    /// "An action was blocked by security policy." — no file, no ref.
    Minimal,
    /// No toast at all; the block is still enforced and logged.
    Covert,
}

/// Endpoint-notification configuration (`[notify]`). Every field is defaulted so
/// the whole section — and any individual field — may be omitted.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NotifyConfig {
    /// Master switch. Default `true` = show a toast on every block. Setting this
    /// `false` is equivalent to `mode = "covert"` (block + log, no toast).
    pub enabled: bool,
    /// Verbosity of the toast (see `NotifyMode`). Default `standard`.
    pub mode: NotifyMode,
    /// Organisation name shown in the toast title. Default "Data Loss Prevention".
    pub org_name: String,
    /// AppUserModelID the toast is shown under. For the toast to actually appear
    /// in the Action Center it must be a REGISTERED AUMID — the installer drops a
    /// Start-Menu shortcut carrying it. Default is the DLP agent's own AUMID.
    pub aumid: String,
    /// Coalescing window (seconds): a repeat block of the SAME (channel, file) is
    /// suppressed within this window so a read-flood cannot spam toasts. Default 5.
    pub dedup_secs: u64,
    /// Hard rate cap: at most this many toasts per rolling minute (a global
    /// backstop against notification storms). Default 20. 0 disables the cap.
    pub max_per_minute: u32,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        NotifyConfig {
            enabled: true,
            mode: NotifyMode::Standard,
            org_name: "Data Loss Prevention".into(),
            aumid: "Resec.DLP.Agent".into(),
            dedup_secs: 5,
            max_per_minute: 20,
        }
    }
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

    /// Resolve the encrypt mode + key id for a device on an `Action::Encrypt`
    /// destination (encrypt-on-write spec §3.2/§5.2, M3). Walks the SAME
    /// first-match-wins rule order as `to_policy` (rules without a matcher are
    /// dropped in both), so the rule that decided `Encrypt` is the rule whose
    /// `mode`/`key_id` apply. Absent fields fall back to `encrypt_sensitive`
    /// (fail-secure banded default) and `None` (caller substitutes
    /// `[crypto] default_key_id` — the key id stays a FREE-FORM opaque string).
    /// Returned tuple: (mode, key id, block-band policy). The policy defaults
    /// to `Block` (spec §10) and is only `Seal` when the matching rule opts in.
    pub fn encrypt_params(
        &self,
        dev: &DeviceIdentity,
    ) -> (EncryptMode, Option<String>, BlockBandPolicy) {
        for rule in &self.rules {
            if let Some(dr) = rule.to_device_rule() {
                if dr.match_on.matches(dev) {
                    return (
                        rule.mode.unwrap_or(EncryptMode::EncryptSensitive),
                        rule.key_id.clone(),
                        rule.on_block_band,
                    );
                }
            }
        }
        (EncryptMode::EncryptSensitive, None, BlockBandPolicy::Block)
    }
}

/// Kernel-minifilter port-client configuration (`usb-guard`, SPEC §3). Every
/// field is defaulted so the whole `[kguard]` section may be omitted.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct KguardConfig {
    /// Block when a matched document's containment reaches this fraction
    /// (`idm[].containment >= block_at`). Default 0.30. Used by the read-scan
    /// (read-deny classify) path (`should_block`) and mirrored into the
    /// trusted-side seal block band (`Config::encrypt_bands`).
    pub block_at: f64,
    /// Block when a scanned file's coverage by protected material reaches this
    /// fraction (`idm[].coverage >= coverage_block_at`). Default 0.60.
    pub coverage_block_at: f64,
    /// CONTAINMENT threshold for BLOCKING a sensitive file copied to a
    /// NON-whitelisted removable device (the WRITE-reason, non-Encrypt
    /// fall-through in `kguard::decide`). Deliberately LOWER than `block_at`
    /// (0.30) — data leaving the machine on an untrusted stick is blocked at a
    /// tighter containment than the read-scan band uses. Default 0.15. EDM hits
    /// and `coverage >= coverage_block_at` also block (see
    /// `should_block_removable_write`). Does NOT affect read-deny or the
    /// trusted-side `decide_seal` bands.
    pub removable_write_block_at: f64,
    /// Staleness window (seconds) for the in-process sealer liveness signal used
    /// by `run-endpoint`. The guard treats the sealer as healthy iff the keyring
    /// is present AND the sealer marked itself alive within this window; when the
    /// sealer is unhealthy a seal-eligible file is BLOCKED instead of allowed as
    /// plaintext (fail secure). Default 10. Ignored by the standalone `usb-guard`
    /// (no in-process sealer — it keeps today's allow-pending-seal behaviour).
    pub sealer_health_timeout_secs: u64,
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
    ///
    /// Read-deny *scope* (which fixed-volume files an exfil PID's reads are
    /// classified against) REUSES this set — the driver's
    /// `DlpConfigPathIsWatched` gate — so no separate scope config exists.
    /// Removable and network volumes are always in scope.
    pub watch_paths: Vec<String>,

    /// Read-deny (content-aware exfil-tool read blocking): when `true`, `usb-guard`
    /// runs a background tracker that computes the untrusted-reader PID set and
    /// pushes it to the driver so the kernel's `DlpPreRead` can DENY a sensitive
    /// read by an untrusted process. Default `false`. Pair with the driver
    /// registry knob `ExfilReadBlockEnabled=1` (out-of-band) for kernel enforcement.
    ///
    /// WHICH PIDs get pushed is governed by [`exfil_posture`](Self::exfil_posture).
    pub exfil_read_block: bool,

    /// Read-deny classification posture. `blocklist` (default) keeps the exact
    /// prior behaviour (exfil channels chosen by signature/behaviour/VM);
    /// `allowlist` treats every process NOT on the sanctioned-reader allowlist
    /// ([`Config::trusted_readers`]) as an untrusted reader. Only consulted when
    /// [`exfil_read_block`](Self::exfil_read_block) is on.
    pub exfil_posture: ExfilPosture,
}

impl Default for KguardConfig {
    fn default() -> Self {
        KguardConfig {
            block_at: 0.30,
            coverage_block_at: 0.60,
            removable_write_block_at: 0.15,
            sealer_health_timeout_secs: 10,
            fail_block: false,
            channel_label: "usb-kguard".into(),
            scan_fixed: false,
            scan_network: false,
            watch_paths: Vec::new(),
            exfil_read_block: false,
            exfil_posture: ExfilPosture::Blocklist,
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

/// Network-egress (WFP) channel configuration (Tier-2 plan §2.4). Every field is
/// defaulted so the whole `[netfilter]` section — and any individual field — may
/// be omitted; an absent section is the safe `monitor` posture (NEVER default-deny).
///
/// # Allow-list MUST include agent lifelines
/// This allow-list blocks *any* PID's egress to an unapproved destination. To
/// avoid the agent cutting ITSELF off when running `--enforce allowlist`, the
/// `[[netfilter.rules]]` allow-list MUST permit, at minimum:
///   * the management server `host:port` (mTLS check-in, incident upload),
///   * the DNS resolver(s) (UDP/TCP 53) so name resolution keeps working,
///   * any internal services the agent depends on.
/// Example (illustrative):
///
/// ```toml
/// [netfilter]
/// mode = "monitor"                 # flip to allowlist only via --enforce
/// [[netfilter.rules]]
/// cidr = "10.20.0.5/32"            # management server
/// port = 8443
/// action = "permit"
/// note = "mgmt-server mTLS"
/// [[netfilter.rules]]
/// cidr = "10.20.0.53/32"           # internal DNS resolver
/// port = 53
/// action = "permit"
/// note = "DNS"
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NetfilterConfig {
    /// Enforcement mode. Default `monitor` (log intended verdicts, block nothing).
    /// `allowlist`/`blocklist` require the operator to pass `--enforce <mode>` on
    /// the CLI (the CLI mode wins over this); this is the config-file default when
    /// no `--enforce` is given. Kept `monitor` so a stray config can never brick a
    /// machine.
    pub mode: NetMode,
    /// Incident channel label (plan §2.1). Default "network".
    pub channel_label: String,
    /// Default action for a matched remote-access tool (AnyDesk/TeamViewer/VNC/…).
    /// **Default `detect` (visibility only — never blocks/kills).** Remote-tool
    /// blocking is NOT part of blocking agent-detected sensitive data (that is
    /// read-deny + default-deny); it is optional, opt-in hygiene that only helps
    /// the analog-hole/screen-view case. Set `block_network` (cut the relay) or
    /// `kill` (terminate; admin + `--enforce`) to deliberately opt in.
    pub remote_tool_action: ToolAction,
    /// Per-tool overrides keyed by tool id (e.g. `rdp-out = "detect"`).
    pub remote_tool_overrides: HashMap<String, ToolAction>,
    /// Persist filters across reboot (BOOTTIME) vs a dynamic session that
    /// auto-cleans on exit. Default false = dynamic (safer; this build installs a
    /// dynamic session regardless — BOOTTIME persistence is a follow-on).
    pub persist: bool,
    /// Ordered egress rules (`[[netfilter.rules]]`). First match wins.
    pub rules: Vec<NetRuleConfig>,
}

impl Default for NetfilterConfig {
    fn default() -> Self {
        NetfilterConfig {
            mode: NetMode::Monitor, // NEVER default-deny (plan §2.4/§5)
            channel_label: "network".into(),
            // detect-only by default: remote-tool blocking is decoupled from the
            // data-exfil layers (read-deny + default-deny) and is opt-in.
            remote_tool_action: ToolAction::Detect,
            remote_tool_overrides: HashMap::new(),
            persist: false,
            rules: Vec::new(),
        }
    }
}

/// A single TOML network rule (`[[netfilter.rules]]`). At least one matcher (app,
/// cidr, port) must be set; a rule with none is dropped (never a catch-all).
#[derive(Debug, Clone, Deserialize)]
pub struct NetRuleConfig {
    /// Process image path or base name (case-insensitive), e.g. `curl.exe`.
    #[serde(default)]
    pub app: Option<String>,
    /// Remote address/prefix, e.g. `10.0.0.0/8` or `203.0.113.4`.
    #[serde(default)]
    pub cidr: Option<String>,
    /// Remote port.
    #[serde(default)]
    pub port: Option<u16>,
    /// `permit` or `block`.
    pub action: RuleAction,
    /// Optional note used as the WFP filter display name + incident reason.
    #[serde(default)]
    pub note: Option<String>,
}

impl NetRuleConfig {
    /// Convert to an evaluated `NetRule`. A rule with no matcher, or with an
    /// unparseable CIDR, is dropped (returns None) — fail closed, never widen.
    pub fn to_net_rule(&self) -> Option<NetRule> {
        let match_cidr = match &self.cidr {
            Some(s) => Some(Cidr::parse(s)?), // bad CIDR ⇒ drop the whole rule
            None => None,
        };
        if self.app.is_none() && match_cidr.is_none() && self.port.is_none() {
            return None;
        }
        Some(NetRule {
            match_app: self.app.clone(),
            match_cidr,
            match_port: self.port,
            action: self.action,
            note: self.note.clone(),
        })
    }
}

/// Trusted-destination encryption configuration (`[crypto]`, encrypt-on-write
/// spec §3.2). Every field is defaulted so the whole section may be omitted.
///
/// NOTE: `block_at` / `coverage_block_at` are deliberately NOT here — they are
/// read from `[kguard]` (one source of truth for the block band); see
/// `Config::encrypt_bands()`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CryptoConfig {
    /// KEK id sealed files reference when a rule names none. FREE-FORM opaque
    /// string (per-classification by convention, e.g. `"class-internal/v1"`)
    /// — never parsed anywhere, only looked up in the keyring.
    pub default_key_id: String,
    /// Lower edge of the seal band for `encrypt_sensitive` destinations.
    /// Default 0.05.
    pub encrypt_at: f64,
    /// DEV ONLY (until server key sync, M6): path to a local keyring file so
    /// the feature runs end-to-end without a server. Keep it git-ignored;
    /// never log its contents.
    pub keyfile: Option<PathBuf>,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        CryptoConfig {
            default_key_id: "class-internal/v1".into(),
            encrypt_at: 0.05,
            keyfile: None,
        }
    }
}

/// Web-upload trusted-origin configuration (`[webupload]`, spec §3.2).
/// Consumed by the browser-host channel (M7). Absent ⇒ no trusted origins:
/// every origin keeps today's behaviour.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct WebuploadConfig {
    /// Origins whose uploads are sealed instead of blocked. Matched by the
    /// browser host: exact origin first, then registrable-domain suffix.
    pub trusted_origins: Vec<TrustedOrigin>,
}

/// One trusted web-upload origin (spec §3.2 / §7.2).
#[derive(Debug, Clone, Deserialize)]
pub struct TrustedOrigin {
    /// Full origin, e.g. `"https://mail.internal.example"`.
    pub origin: String,
    /// How much gets sealed. Absent ⇒ `encrypt_sensitive` (fail-secure banded
    /// default).
    #[serde(default = "default_encrypt_sensitive")]
    pub mode: EncryptMode,
    /// KEK id override; FREE-FORM string, never parsed. Absent ⇒
    /// `[crypto] default_key_id`.
    #[serde(default)]
    pub key_id: Option<String>,
}

fn default_encrypt_sensitive() -> EncryptMode {
    EncryptMode::EncryptSensitive
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
    /// Trusted-destination encryption fields (encrypt-on-write spec §3.2) —
    /// only meaningful with `action = "encrypt"`. `mode` chooses how much is
    /// sealed; absent ⇒ `encrypt_sensitive` (the fail-secure verdict-banded
    /// default, resolved at use-site in the copy auditor, M3).
    #[serde(default)]
    pub mode: Option<EncryptMode>,
    /// KEK id to seal with, e.g. `"class-internal/v1"`. FREE-FORM opaque
    /// string — never parsed anywhere. Absent ⇒ `[crypto] default_key_id`.
    #[serde(default)]
    pub key_id: Option<String>,
    /// What `encrypt_sensitive` does with BLOCK-band verdicts on this
    /// destination: `"block"` (spec default — whitelisting never weakens the
    /// block threshold) or `"seal"` (owner opt-in, 2026-08-12: sensitive files
    /// leave this whitelisted device armoured instead of blocked). Explicit
    /// per-rule; never a global default.
    #[serde(default)]
    pub on_block_band: BlockBandPolicy,
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
                netfilter: NetfilterConfig::default(),
                notify: NotifyConfig::default(),
                crypto: CryptoConfig::default(),
                webupload: WebuploadConfig::default(),
                trusted_readers: Vec::new(),
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
    /// Agent-facing trusted-destination + key sync endpoint (encrypt-on-write
    /// M6, PINNED contract). Served over the same mTLS listener as check-in.
    pub fn trusted_config_url(&self) -> String {
        format!("{}/agent/trusted-config", self.server_url.trim_end_matches('/'))
    }

    /// Agent-facing sanctioned-reader allowlist endpoint (read-deny allowlist
    /// posture). Served over the same mTLS listener as check-in; independent of
    /// encryption config (no Org Root Key required).
    pub fn trusted_readers_url(&self) -> String {
        format!("{}/agent/trusted-readers", self.server_url.trim_end_matches('/'))
    }

    /// Agent-facing read-deny policy endpoint (mode/posture/scope/fail). Served
    /// over the same mTLS listener as check-in; the agent applies it to the driver.
    pub fn read_deny_policy_url(&self) -> String {
        format!("{}/agent/read-deny-policy", self.server_url.trim_end_matches('/'))
    }

    /// Produce an effective config whose `[usb]` section has the synced
    /// trusted destinations merged in (encrypt-on-write M6). The
    /// console-authored whitelist takes precedence (first-match-wins) and any
    /// `usb` destination flips the channel on; the more-restrictive of
    /// (synced, local) wins per device. Everything else (`[crypto]`,
    /// `state_dir`, …) is unchanged. Pure — the merge itself is
    /// [`crate::trustsync::merge_into_usb`].
    pub fn with_synced_destinations(&self, dests: &[SyncedDestination]) -> Config {
        let mut merged = self.clone();
        merged.usb = merge_into_usb(&self.usb, dests);
        merged
    }

    /// Produce an effective config whose sanctioned-reader allowlist is the
    /// UNION of the local `[[trusted_readers]]` and the console-authored readers
    /// synced over mTLS (read-deny allowlist posture). Union is correct: a reader
    /// trusted either locally or centrally is trusted. Pure — a clone with the
    /// synced rules appended; everything else is unchanged.
    pub fn with_synced_readers(&self, readers: &[SyncedReader]) -> Config {
        if readers.is_empty() {
            return self.clone();
        }
        let mut merged = self.clone();
        merged.trusted_readers.extend(readers.iter().map(SyncedReader::to_rule));
        merged
    }

    /// The `EncryptSensitive` verdict bands (encrypt-on-write spec §3.1):
    /// `encrypt_at` comes from `[crypto]`; the block band is read from
    /// `[kguard]` so there is ONE source of truth for block thresholds —
    /// whitelisting a destination can never weaken them.
    pub fn encrypt_bands(&self) -> EncryptBands {
        EncryptBands {
            encrypt_at: self.crypto.encrypt_at,
            block_at: self.kguard.block_at,
            coverage_block_at: self.kguard.coverage_block_at,
        }
    }
}

fn env_required(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing required env {key} (and no config file)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
server_url = "https://dlp-server.internal:8443"
ca_cert_path = "C:\\ProgramData\\DLPAgent\\ca-cert.pem"
state_dir = "C:\\ProgramData\\DLPAgent"
"#;

    #[test]
    fn existing_toml_without_new_sections_still_parses() {
        // Backward compatibility: a pre-encryption config (old-style [usb]
        // rules, no [crypto]/[webupload]) must keep parsing with defaults.
        let toml_str = format!(
            "{BASE}
[usb]
enabled = true
default_action = \"read_only\"

[[usb.rules]]
match_serial = \"ABC123\"
action = \"allow_audited\"
note = \"legacy rule\"
"
        );
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(cfg.usb.rules.len(), 1);
        assert_eq!(cfg.usb.rules[0].action, Action::AllowAudited);
        assert!(cfg.usb.rules[0].mode.is_none());
        assert!(cfg.usb.rules[0].key_id.is_none());
        // Absent [crypto]/[webupload] ⇒ spec defaults.
        assert_eq!(cfg.crypto.default_key_id, "class-internal/v1");
        assert_eq!(cfg.crypto.encrypt_at, 0.05);
        assert!(cfg.crypto.keyfile.is_none());
        assert!(cfg.webupload.trusted_origins.is_empty());
    }

    #[test]
    fn encrypt_rule_fields_parse() {
        let toml_str = format!(
            "{BASE}
[crypto]
default_key_id = \"class-secret/v3\"
encrypt_at = 0.08

[[usb.rules]]
match_serial = \"0401396FBBF0C89E\"
action = \"encrypt\"
mode = \"encrypt_all\"
key_id = \"class-secret/v3\"
note = \"site-A courier stick\"

[[usb.rules]]
match_vid = \"0951\"
match_pid = \"1666\"
action = \"encrypt\"
"
        );
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        let r0 = &cfg.usb.rules[0];
        assert_eq!(r0.action, Action::Encrypt);
        assert_eq!(r0.mode, Some(EncryptMode::EncryptAll));
        assert_eq!(r0.key_id.as_deref(), Some("class-secret/v3"));
        // Second rule: mode/key_id absent ⇒ resolved at use-site (M3) to
        // encrypt_sensitive / [crypto] default_key_id.
        let r1 = &cfg.usb.rules[1];
        assert_eq!(r1.action, Action::Encrypt);
        assert!(r1.mode.is_none());
        assert!(r1.key_id.is_none());
        assert_eq!(cfg.crypto.default_key_id, "class-secret/v3");
        // to_policy carries the encrypt action into the rule engine unchanged.
        let policy = cfg.usb.to_policy();
        assert_eq!(policy.rules[0].action, Action::Encrypt);
    }

    #[test]
    fn encrypt_params_resolve_first_match_with_defaults() {
        let toml_str = format!(
            "{BASE}
[crypto]
default_key_id = \"class-secret/v3\"

[[usb.rules]]
match_serial = \"COURIER\"
action = \"encrypt\"
mode = \"encrypt_all\"
key_id = \"class-courier/v1\"

[[usb.rules]]
match_vid = \"0951\"
match_pid = \"1666\"
action = \"encrypt\"
"
        );
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        let dev = |serial: &str, vid: &str, pid: &str| DeviceIdentity {
            drive_letter: "E:".into(),
            vendor_id: vid.into(),
            product_id: pid.into(),
            serial: serial.into(),
            product_name: format!("{vid} {pid}"),
            bus_type: "usb".into(),
            removable: true,
        };
        // First rule: explicit mode + key id; block-band policy stays the
        // spec default unless the rule opts in.
        let (mode, key, obb) = cfg.usb.encrypt_params(&dev("courier", "x", "y"));
        assert_eq!(mode, EncryptMode::EncryptAll);
        assert_eq!(key.as_deref(), Some("class-courier/v1"));
        assert_eq!(obb, BlockBandPolicy::Block);
        // Second rule: absent fields ⇒ fail-secure banded mode, no key id
        // (the caller substitutes [crypto] default_key_id).
        let (mode, key, obb) = cfg.usb.encrypt_params(&dev("other", "0951", "1666"));
        assert_eq!(mode, EncryptMode::EncryptSensitive);
        assert!(key.is_none());
        assert_eq!(obb, BlockBandPolicy::Block);
        // No rule matches ⇒ same fail-secure defaults.
        let (mode, key, obb) = cfg.usb.encrypt_params(&dev("z", "a", "b"));
        assert_eq!(mode, EncryptMode::EncryptSensitive);
        assert!(key.is_none());
        assert_eq!(obb, BlockBandPolicy::Block);
    }

    #[test]
    fn on_block_band_seal_opt_in_parses_and_resolves() {
        let toml_str = format!(
            "{BASE}
[[usb.rules]]
match_serial = \"FIELD-STICK\"
action = \"encrypt\"
on_block_band = \"seal\"
"
        );
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        let dev = DeviceIdentity {
            drive_letter: "E:".into(),
            vendor_id: "v".into(),
            product_id: "p".into(),
            serial: "field-stick".into(),
            product_name: "x".into(),
            bus_type: "usb".into(),
            removable: true,
        };
        let (mode, key, obb) = cfg.usb.encrypt_params(&dev);
        assert_eq!(mode, EncryptMode::EncryptSensitive);
        assert!(key.is_none());
        assert_eq!(obb, BlockBandPolicy::Seal);
    }

    #[test]
    fn webupload_trusted_origins_parse_with_mode_default() {
        let toml_str = format!(
            "{BASE}
[webupload]
trusted_origins = [
  {{ origin = \"https://mail.internal.example\", mode = \"encrypt_sensitive\" }},
  {{ origin = \"https://drop.internal.example\" }},
]
"
        );
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(cfg.webupload.trusted_origins.len(), 2);
        assert_eq!(cfg.webupload.trusted_origins[0].mode, EncryptMode::EncryptSensitive);
        // Absent mode ⇒ fail-secure banded default, NOT encrypt_all.
        assert_eq!(cfg.webupload.trusted_origins[1].mode, EncryptMode::EncryptSensitive);
        assert!(cfg.webupload.trusted_origins[1].key_id.is_none());
    }

    #[test]
    fn kguard_new_defaults_present() {
        // Absent [kguard] ⇒ the two new knobs take their fail-secure defaults.
        let cfg: Config = toml::from_str(BASE).unwrap();
        assert_eq!(cfg.kguard.removable_write_block_at, 0.15);
        assert_eq!(cfg.kguard.sealer_health_timeout_secs, 10);
        // block_at is unchanged and distinct from the removable-write threshold.
        assert_eq!(cfg.kguard.block_at, 0.30);
    }

    #[test]
    fn kguard_new_fields_parse_when_set() {
        let toml_str = format!(
            "{BASE}
[kguard]
removable_write_block_at = 0.05
sealer_health_timeout_secs = 30
"
        );
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(cfg.kguard.removable_write_block_at, 0.05);
        assert_eq!(cfg.kguard.sealer_health_timeout_secs, 30);
    }

    #[test]
    fn encrypt_bands_read_block_thresholds_from_kguard() {
        // One source of truth: [crypto] owns only the seal band's lower edge;
        // the block band always comes from [kguard].
        let toml_str = format!(
            "{BASE}
[crypto]
encrypt_at = 0.10

[kguard]
block_at = 0.40
coverage_block_at = 0.70
"
        );
        let cfg: Config = toml::from_str(&toml_str).unwrap();
        let bands = cfg.encrypt_bands();
        assert_eq!(bands.encrypt_at, 0.10);
        assert_eq!(bands.block_at, 0.40);
        assert_eq!(bands.coverage_block_at, 0.70);
    }
}
