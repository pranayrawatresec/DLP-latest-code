//! USB device-control decision engine — PURE LOGIC (spec §3.3).
//!
//! No I/O, no Windows calls, no state. Given a device identity and a policy,
//! decide whether the removable device is allowed (still audited), forced
//! read-only, or blocked. This is the most-tested file in the channel: the
//! whole point of factoring it out is that the allow/read-only/block matrix is
//! exercised without touching hardware.
//!
//! Security note (spec §3.3): serial matching is a **convenience allowlist,
//! not a security control** — serials are spoofable. Read-only/audit still
//! applies to allowed devices (defence in depth), and the default action is
//! fail-secure (see `UsbConfig` in config.rs, which defaults to `ReadOnly`).

use serde::Deserialize;

use super::device::DeviceIdentity;

/// What to do with a removable device. `AllowAudited` still audits copies; it
/// only means "do not restrict the device itself". `ReadOnly` forces the
/// volume read-only; `Block` prevents mounting/writing entirely.
///
/// Deserializes from the snake_case strings used in the TOML `[usb]` section
/// (`allow_audited` | `read_only` | `block`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    AllowAudited,
    ReadOnly,
    Block,
}

impl Action {
    /// Ordering by restrictiveness (Allow < ReadOnly < Block). Used to pick the
    /// safer of two actions when composing (e.g. no-bundle fail-secure).
    pub fn restrictiveness(self) -> u8 {
        match self {
            Action::AllowAudited => 0,
            Action::ReadOnly => 1,
            Action::Block => 2,
        }
    }

    /// The stricter (more fail-secure) of two actions.
    pub fn max_restrictive(self, other: Action) -> Action {
        if other.restrictiveness() > self.restrictiveness() {
            other
        } else {
            self
        }
    }
}

/// How a rule selects a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleMatch {
    /// Exact serial (case-insensitive). Convenience allowlist only — spoofable.
    Serial(String),
    /// USB vendor/product identifiers (descriptor strings, case-insensitive).
    VidPid { vid: String, pid: String },
    /// Bus type, e.g. "usb", "sd", "mmc" (case-insensitive).
    BusType(String),
    /// Matches any device — use as a catch-all before the default.
    Any,
}

impl RuleMatch {
    /// Does this matcher select `dev`?
    pub fn matches(&self, dev: &DeviceIdentity) -> bool {
        match self {
            // An empty configured serial never matches (avoids matching devices
            // that report no serial at all).
            RuleMatch::Serial(s) => {
                let s = s.trim();
                !s.is_empty() && dev.serial.eq_ignore_ascii_case(s)
            }
            RuleMatch::VidPid { vid, pid } => {
                dev.vendor_id.eq_ignore_ascii_case(vid.trim())
                    && dev.product_id.eq_ignore_ascii_case(pid.trim())
            }
            RuleMatch::BusType(b) => dev.bus_type.eq_ignore_ascii_case(b.trim()),
            RuleMatch::Any => true,
        }
    }
}

/// One policy rule: a matcher, the action to take, and an optional operator note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRule {
    pub match_on: RuleMatch,
    pub action: Action,
    pub note: Option<String>,
}

/// The evaluated USB policy: an ordered rule list plus a fail-secure default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbPolicy {
    pub default_action: Action,
    pub rules: Vec<DeviceRule>,
}

impl Default for UsbPolicy {
    /// Fail-secure default when nothing is configured: read-only, no allow rules.
    fn default() -> Self {
        UsbPolicy {
            default_action: Action::ReadOnly,
            rules: Vec::new(),
        }
    }
}

/// Decide the action for a device. **First matching rule wins**; if no rule
/// matches, the policy's `default_action` applies (spec §3.3). Returns the
/// chosen action and the rule that produced it (None if the default was used).
pub fn decide<'a>(policy: &'a UsbPolicy, dev: &DeviceIdentity) -> (Action, Option<&'a DeviceRule>) {
    for rule in &policy.rules {
        if rule.match_on.matches(dev) {
            return (rule.action, Some(rule));
        }
    }
    (policy.default_action, None)
}

/// Non-mass-storage USB device categories that are governed by their own
/// fail-secure knobs rather than the mass-storage rule matrix (spec §2.1/§2.2):
///   * `Mtp` — phones/cameras that expose files over MTP/PTP through the
///     Windows Portable Devices (WPD) stack; they do NOT mount a drive letter,
///     so the `[[usb.rules]]` (serial/vid-pid/bus) never see them.
///   * `Tethering` — a USB device that presents as a network interface
///     (RNDIS/NCM), turning the PC's traffic egress into an unmonitored path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceClass {
    MassStorage,
    Mtp,
    Tethering,
}

/// Classify a device by its (already-lowercased) bus/class hint. Mass-storage
/// is the default; the enumerator/ watcher tags MTP and tethering devices with
/// a distinguishing `bus_type` (`"mtp"`/`"ptp"`/`"wpd"`, `"rndis"`/`"ncm"`).
pub fn classify(dev: &DeviceIdentity) -> DeviceClass {
    match dev.bus_type.as_str() {
        "mtp" | "ptp" | "wpd" => DeviceClass::Mtp,
        "rndis" | "ncm" | "tethering" => DeviceClass::Tethering,
        _ => DeviceClass::MassStorage,
    }
}

/// Full disposition for ANY USB device (spec §2). Mass-storage devices go
/// through the rule matrix (`decide`); MTP/WPD and USB-tethering devices are
/// governed by their dedicated fail-secure knobs instead of the mass-storage
/// rules. Returns the chosen action and the classified device category.
pub fn decide_full(
    policy: &UsbPolicy,
    dev: &DeviceIdentity,
    mtp_action: Action,
    tethering_action: Action,
) -> (Action, DeviceClass) {
    match classify(dev) {
        DeviceClass::MassStorage => (decide(policy, dev).0, DeviceClass::MassStorage),
        DeviceClass::Mtp => (mtp_action, DeviceClass::Mtp),
        DeviceClass::Tethering => (tethering_action, DeviceClass::Tethering),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::device::DeviceIdentity;

    fn dev(serial: &str, vid: &str, pid: &str, bus: &str) -> DeviceIdentity {
        DeviceIdentity {
            drive_letter: "E:".into(),
            vendor_id: vid.into(),
            product_id: pid.into(),
            serial: serial.into(),
            product_name: format!("{vid} {pid}"),
            bus_type: bus.into(),
            removable: true,
        }
    }

    fn rule(m: RuleMatch, a: Action) -> DeviceRule {
        DeviceRule { match_on: m, action: a, note: None }
    }

    #[test]
    fn serial_allowlist_matches_case_insensitively() {
        let policy = UsbPolicy {
            default_action: Action::Block,
            rules: vec![rule(RuleMatch::Serial("ABC123".into()), Action::AllowAudited)],
        };
        let (action, matched) = decide(&policy, &dev("abc123", "Kingston", "DT", "usb"));
        assert_eq!(action, Action::AllowAudited);
        assert!(matched.is_some(), "serial rule must be the matched rule");
    }

    #[test]
    fn serial_rule_does_not_match_different_serial() {
        let policy = UsbPolicy {
            default_action: Action::Block,
            rules: vec![rule(RuleMatch::Serial("ABC123".into()), Action::AllowAudited)],
        };
        let (action, matched) = decide(&policy, &dev("ZZZ999", "Kingston", "DT", "usb"));
        assert_eq!(action, Action::Block, "no rule matched → default");
        assert!(matched.is_none());
    }

    #[test]
    fn empty_serial_rule_never_matches() {
        let policy = UsbPolicy {
            default_action: Action::ReadOnly,
            rules: vec![rule(RuleMatch::Serial("".into()), Action::AllowAudited)],
        };
        // Device that also reports no serial must NOT be caught by an empty rule.
        let (action, matched) = decide(&policy, &dev("", "V", "P", "usb"));
        assert_eq!(action, Action::ReadOnly);
        assert!(matched.is_none());
    }

    #[test]
    fn vidpid_matches_both_fields() {
        let policy = UsbPolicy {
            default_action: Action::Block,
            rules: vec![rule(
                RuleMatch::VidPid { vid: "SanDisk".into(), pid: "Ultra".into() },
                Action::ReadOnly,
            )],
        };
        assert_eq!(decide(&policy, &dev("s", "sandisk", "ultra", "usb")).0, Action::ReadOnly);
        // One field wrong → no match → default.
        assert_eq!(decide(&policy, &dev("s", "sandisk", "Cruzer", "usb")).0, Action::Block);
    }

    #[test]
    fn bus_type_rule_matches() {
        let policy = UsbPolicy {
            default_action: Action::AllowAudited,
            rules: vec![rule(RuleMatch::BusType("usb".into()), Action::ReadOnly)],
        };
        assert_eq!(decide(&policy, &dev("s", "v", "p", "USB")).0, Action::ReadOnly);
        assert_eq!(decide(&policy, &dev("s", "v", "p", "sata")).0, Action::AllowAudited);
    }

    #[test]
    fn any_rule_is_a_catch_all() {
        let policy = UsbPolicy {
            default_action: Action::AllowAudited,
            rules: vec![rule(RuleMatch::Any, Action::Block)],
        };
        assert_eq!(decide(&policy, &dev("anything", "x", "y", "sd")).0, Action::Block);
    }

    #[test]
    fn first_match_wins_precedence() {
        let policy = UsbPolicy {
            default_action: Action::Block,
            rules: vec![
                rule(RuleMatch::Serial("GOOD".into()), Action::AllowAudited),
                rule(RuleMatch::Any, Action::ReadOnly),
            ],
        };
        // Serial rule precedes the Any catch-all.
        assert_eq!(decide(&policy, &dev("good", "v", "p", "usb")).0, Action::AllowAudited);
        // Non-matching serial falls through to the Any rule (not the default).
        let (action, matched) = decide(&policy, &dev("other", "v", "p", "usb"));
        assert_eq!(action, Action::ReadOnly);
        assert_eq!(matched.map(|r| &r.match_on), Some(&RuleMatch::Any));
    }

    #[test]
    fn unknown_device_uses_default_block() {
        let policy = UsbPolicy { default_action: Action::Block, rules: vec![] };
        let (action, matched) = decide(&policy, &dev("unknown", "v", "p", "usb"));
        assert_eq!(action, Action::Block, "fail-secure default for unknown device");
        assert!(matched.is_none());
    }

    #[test]
    fn unknown_device_uses_default_read_only() {
        let policy = UsbPolicy { default_action: Action::ReadOnly, rules: vec![] };
        assert_eq!(decide(&policy, &dev("unknown", "v", "p", "usb")).0, Action::ReadOnly);
    }

    #[test]
    fn default_policy_is_fail_secure_read_only() {
        let policy = UsbPolicy::default();
        assert_eq!(policy.default_action, Action::ReadOnly);
        assert!(policy.rules.is_empty());
        assert_eq!(decide(&policy, &dev("x", "v", "p", "usb")).0, Action::ReadOnly);
    }

    #[test]
    fn restrictiveness_picks_the_stricter_action() {
        assert_eq!(Action::AllowAudited.max_restrictive(Action::ReadOnly), Action::ReadOnly);
        assert_eq!(Action::ReadOnly.max_restrictive(Action::Block), Action::Block);
        assert_eq!(Action::Block.max_restrictive(Action::AllowAudited), Action::Block);
    }

    // --- Device-class extension (spec §2): MTP/WPD + USB tethering ----------

    fn dev_bus(bus: &str) -> DeviceIdentity {
        DeviceIdentity {
            drive_letter: String::new(),
            vendor_id: "V".into(),
            product_id: "P".into(),
            serial: "S".into(),
            product_name: "V P".into(),
            bus_type: bus.into(),
            removable: true,
        }
    }

    #[test]
    fn classify_recognizes_mtp_and_tethering() {
        assert_eq!(classify(&dev_bus("mtp")), DeviceClass::Mtp);
        assert_eq!(classify(&dev_bus("ptp")), DeviceClass::Mtp);
        assert_eq!(classify(&dev_bus("wpd")), DeviceClass::Mtp);
        assert_eq!(classify(&dev_bus("rndis")), DeviceClass::Tethering);
        assert_eq!(classify(&dev_bus("ncm")), DeviceClass::Tethering);
        assert_eq!(classify(&dev_bus("usb")), DeviceClass::MassStorage);
        assert_eq!(classify(&dev_bus("sata")), DeviceClass::MassStorage);
    }

    #[test]
    fn mtp_device_uses_mtp_action_not_the_rule_matrix() {
        // Even a permissive Any→Allow rule must NOT relax an MTP phone: MTP is
        // governed by the dedicated knob (default block for defence).
        let policy = UsbPolicy {
            default_action: Action::AllowAudited,
            rules: vec![rule(RuleMatch::Any, Action::AllowAudited)],
        };
        let (action, class) =
            decide_full(&policy, &dev_bus("mtp"), Action::Block, Action::Block);
        assert_eq!(class, DeviceClass::Mtp);
        assert_eq!(action, Action::Block, "MTP must honour mtp_action, not the mass-storage rule");
    }

    #[test]
    fn tethering_device_uses_tethering_action() {
        let policy = UsbPolicy { default_action: Action::AllowAudited, rules: vec![] };
        let (action, class) =
            decide_full(&policy, &dev_bus("rndis"), Action::Block, Action::Block);
        assert_eq!(class, DeviceClass::Tethering);
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn mass_storage_still_flows_through_the_rule_matrix() {
        let policy = UsbPolicy {
            default_action: Action::ReadOnly,
            rules: vec![rule(RuleMatch::Serial("GOOD".into()), Action::AllowAudited)],
        };
        // Matching serial → the rule wins; MTP/tethering knobs are irrelevant here.
        let mut d = dev_bus("usb");
        d.serial = "GOOD".into();
        let (action, class) = decide_full(&policy, &d, Action::Block, Action::Block);
        assert_eq!(class, DeviceClass::MassStorage);
        assert_eq!(action, Action::AllowAudited);
        // Non-matching mass-storage → default.
        let (action, _) = decide_full(&policy, &dev_bus("usb"), Action::Block, Action::Block);
        assert_eq!(action, Action::ReadOnly);
    }

    #[test]
    fn mtp_action_allow_is_honoured_when_configured() {
        // A site that only wants audit (not block) for phones can set it.
        let policy = UsbPolicy::default();
        let (action, _) =
            decide_full(&policy, &dev_bus("mtp"), Action::AllowAudited, Action::Block);
        assert_eq!(action, Action::AllowAudited);
    }
}
