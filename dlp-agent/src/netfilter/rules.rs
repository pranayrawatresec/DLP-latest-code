//! Pure network-egress rule-decision engine (Tier-2 plan §2.1, §2.5).
//!
//! Given one connection (`app_path`, `remote_ip`, `remote_port`, `direction`) and
//! a `NetPolicy`, decide `Permit` or `Block(reason)`. This is the brain of the
//! user-mode WFP layer; the WFP filter-spec builder (`wfp.rs`) and the live
//! `FwpmFilterAdd0` path are downstream of the decision made here.
//!
//! Semantics (plan §2.1):
//!   * explicit config rules are evaluated **first-match** (order matters);
//!   * then the built-in **remote-access-tool** set (§2.2);
//!   * then the **default per mode**: `allowlist` = default-DENY (fail-secure but
//!     can brick a machine — hence `monitor` is the shipped default), `blocklist`
//!     = default-PERMIT, `monitor` = default-PERMIT (it never blocks; it logs the
//!     verdict it *would* apply).
//!
//! Pure: no I/O, no Win32, no globals. Fully unit-tested below (≥12 cases).

use std::net::IpAddr;

use serde::Deserialize;

use super::remote_tools::{RemoteToolPolicy, ToolAction};

/// Enforcement mode. `monitor` is the safe shipped default (never default-deny).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetMode {
    /// Add no blocking filters; enumerate + log the verdict we WOULD apply.
    Monitor,
    /// Default-deny: PERMIT only approved dests/apps, BLOCK everything else.
    Allowlist,
    /// Default-permit: PERMIT all except blocked dests/apps/remote-tools.
    Blocklist,
}

/// Connection direction. WFP `ALE_AUTH_CONNECT` is the outbound-connect layer;
/// direction is carried so the engine can be reused for inbound policy later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Outbound,
    Inbound,
}

/// One connection to be judged. `app_path` is the initiating process image path.
#[derive(Debug, Clone)]
pub struct Connection {
    pub app_path: String,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub direction: Direction,
}

/// A rule's disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Permit,
    Block,
}

/// An IP prefix (CIDR) for v4 or v6, e.g. `10.0.0.0/8`, `2001:db8::/32`, or a
/// bare address (implicit `/32` / `/128`). Pure parsing + membership, std-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    pub base: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    /// Parse `addr/prefix` or a bare address. Returns None on malformed input or
    /// an out-of-range prefix (fail closed: a bad rule is dropped, not widened).
    pub fn parse(s: &str) -> Option<Cidr> {
        let s = s.trim();
        let (addr_s, prefix_s) = match s.split_once('/') {
            Some((a, p)) => (a.trim(), Some(p.trim())),
            None => (s, None),
        };
        let base: IpAddr = addr_s.parse().ok()?;
        let max: u8 = match base {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix = match prefix_s {
            Some(p) => p.parse::<u8>().ok()?,
            None => max,
        };
        if prefix > max {
            return None;
        }
        Some(Cidr { base, prefix })
    }

    /// Is `ip` inside this prefix? A family mismatch (v4 prefix vs v6 ip) is false.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.base, ip) {
            (IpAddr::V4(b), IpAddr::V4(t)) => {
                let mask = if self.prefix == 0 {
                    0u32
                } else {
                    u32::MAX << (32 - self.prefix as u32)
                };
                (u32::from(b) & mask) == (u32::from(*t) & mask)
            }
            (IpAddr::V6(b), IpAddr::V6(t)) => {
                let mask = if self.prefix == 0 {
                    0u128
                } else {
                    u128::MAX << (128 - self.prefix as u32)
                };
                (u128::from(b) & mask) == (u128::from(*t) & mask)
            }
            _ => false,
        }
    }

    pub fn is_v4(&self) -> bool {
        matches!(self.base, IpAddr::V4(_))
    }
}

/// One evaluated rule. Any present matcher must match (AND); a rule with NO
/// matcher never matches (it is dropped at construction so it can't become an
/// accidental catch-all — mirrors the USB rule discipline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetRule {
    pub match_app: Option<String>,
    pub match_cidr: Option<Cidr>,
    pub match_port: Option<u16>,
    pub action: RuleAction,
    pub note: Option<String>,
}

/// Case-insensitive app-path match: full path equality, base-name equality, or a
/// path suffix (so a rule may name just `anydesk.exe` or a full install path).
fn app_matches(app_path: &str, pat: &str) -> bool {
    let a = app_path.to_ascii_lowercase().replace('/', "\\");
    let p = pat.to_ascii_lowercase().replace('/', "\\");
    if p.is_empty() {
        return false;
    }
    if a == p {
        return true;
    }
    let base = a.rsplit('\\').next().unwrap_or(&a);
    base == p || a.ends_with(&p)
}

impl NetRule {
    /// Does this rule match the connection? False if the rule has no matcher.
    pub fn matches(&self, conn: &Connection) -> bool {
        let mut any = false;
        if let Some(app) = &self.match_app {
            any = true;
            if !app_matches(&conn.app_path, app) {
                return false;
            }
        }
        if let Some(cidr) = &self.match_cidr {
            any = true;
            if !cidr.contains(&conn.remote_ip) {
                return false;
            }
        }
        if let Some(port) = self.match_port {
            any = true;
            if conn.remote_port != port {
                return false;
            }
        }
        any
    }

    fn reason(&self) -> String {
        self.note
            .clone()
            .unwrap_or_else(|| format!("matched {:?} rule", self.action))
    }
}

/// The verdict for one connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Permit,
    Block(String),
}

impl Decision {
    pub fn is_block(&self) -> bool {
        matches!(self, Decision::Block(_))
    }
    pub fn reason(&self) -> &str {
        match self {
            Decision::Permit => "permit",
            Decision::Block(r) => r,
        }
    }
}

/// A full network policy: mode + ordered explicit rules + the remote-tool set.
#[derive(Debug, Clone)]
pub struct NetPolicy {
    pub mode: NetMode,
    pub rules: Vec<NetRule>,
    pub remote_tools: RemoteToolPolicy,
}

impl NetPolicy {
    /// A minimal monitor-mode policy (no explicit rules, default remote-tool set).
    pub fn monitor() -> Self {
        NetPolicy {
            mode: NetMode::Monitor,
            rules: Vec::new(),
            remote_tools: RemoteToolPolicy::default(),
        }
    }
}

/// THE decision. First-match explicit rules → remote-tool set → default per mode.
pub fn decide(policy: &NetPolicy, conn: &Connection) -> Decision {
    // 1. Explicit config rules, first match wins (order is significant).
    for rule in &policy.rules {
        if rule.matches(conn) {
            return match rule.action {
                RuleAction::Permit => Decision::Permit,
                RuleAction::Block => Decision::Block(rule.reason()),
            };
        }
    }

    // 2. Built-in remote-access tools. `block_network`/`kill` block the egress;
    //    `detect` is incident-only and falls through to the mode default.
    if let Some(m) = policy.remote_tools.match_app(&conn.app_path) {
        match m.action {
            ToolAction::BlockNetwork | ToolAction::Kill => {
                return Decision::Block(format!("remote-access tool: {}", m.tool_id));
            }
            ToolAction::Detect => {}
        }
    }

    // 3. Default per mode. Allowlist is the only default-DENY (fail-secure).
    match policy.mode {
        NetMode::Allowlist => Decision::Block("default-deny (allowlist mode)".into()),
        NetMode::Blocklist | NetMode::Monitor => Decision::Permit,
    }
}

/// Fail-secure egress policy (plan §2.3 / B4): a file-bearing channel whose
/// payload is UNREADABLE (an encrypted container we cannot inspect) headed to a
/// destination that is NOT on the allowlist must be BLOCKED — content-blindness
/// is treated as hostile when we can't also vouch for the destination. Pure.
pub fn fail_secure_egress(file_unreadable: bool, dest_allowlisted: bool) -> Decision {
    if file_unreadable && !dest_allowlisted {
        Decision::Block(
            "fail-secure: unreadable (encrypted) payload to non-allowlisted destination".into(),
        )
    } else {
        Decision::Permit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netfilter::remote_tools::RemoteToolPolicy;
    use std::net::Ipv4Addr;

    fn conn(app: &str, ip: &str, port: u16) -> Connection {
        Connection {
            app_path: app.into(),
            remote_ip: ip.parse().unwrap(),
            remote_port: port,
            direction: Direction::Outbound,
        }
    }

    fn rule(app: Option<&str>, cidr: Option<&str>, port: Option<u16>, action: RuleAction) -> NetRule {
        NetRule {
            match_app: app.map(|s| s.to_string()),
            match_cidr: cidr.map(|s| Cidr::parse(s).unwrap()),
            match_port: port,
            action,
            note: None,
        }
    }

    fn policy(mode: NetMode, rules: Vec<NetRule>) -> NetPolicy {
        NetPolicy { mode, rules, remote_tools: RemoteToolPolicy::default() }
    }

    #[test]
    fn app_allow_rule_permits() {
        let p = policy(NetMode::Allowlist, vec![rule(Some("curl.exe"), None, None, RuleAction::Permit)]);
        assert_eq!(decide(&p, &conn(r"C:\bin\curl.exe", "1.1.1.1", 443)), Decision::Permit);
    }

    #[test]
    fn app_deny_rule_blocks() {
        let p = policy(NetMode::Blocklist, vec![rule(Some("ftp.exe"), None, None, RuleAction::Block)]);
        assert!(decide(&p, &conn(r"C:\w\ftp.exe", "9.9.9.9", 21)).is_block());
    }

    #[test]
    fn cidr_match_blocks_and_non_match_falls_through() {
        let p = policy(NetMode::Blocklist, vec![rule(None, Some("10.0.0.0/8"), None, RuleAction::Block)]);
        assert!(decide(&p, &conn("app.exe", "10.5.4.3", 80)).is_block());
        // Outside the CIDR → no rule matches → blocklist default permit.
        assert_eq!(decide(&p, &conn("app.exe", "11.0.0.1", 80)), Decision::Permit);
    }

    #[test]
    fn cidr_v6_membership() {
        let c = Cidr::parse("2001:db8::/32").unwrap();
        assert!(c.contains(&"2001:db8::1".parse().unwrap()));
        assert!(!c.contains(&"2001:dead::1".parse().unwrap()));
        // Family mismatch is never a member.
        assert!(!c.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn port_match_blocks() {
        let p = policy(NetMode::Blocklist, vec![rule(None, None, Some(22), RuleAction::Block)]);
        assert!(decide(&p, &conn("ssh.exe", "1.2.3.4", 22)).is_block());
        assert_eq!(decide(&p, &conn("ssh.exe", "1.2.3.4", 443)), Decision::Permit);
    }

    #[test]
    fn combined_matchers_are_anded() {
        // app AND port must both match.
        let p = policy(NetMode::Blocklist, vec![rule(Some("git.exe"), None, Some(9418), RuleAction::Block)]);
        assert!(decide(&p, &conn("git.exe", "1.2.3.4", 9418)).is_block());
        assert_eq!(decide(&p, &conn("git.exe", "1.2.3.4", 443)), Decision::Permit);
        assert_eq!(decide(&p, &conn("curl.exe", "1.2.3.4", 9418)), Decision::Permit);
    }

    #[test]
    fn remote_tool_detect_by_default_does_not_block() {
        // Decoupled from the data-exfil layers: the default policy DETECTS remote
        // tools (visibility) but does not block them — a matched tool falls through
        // to the mode decision (blocklist = default-permit here).
        let p = policy(NetMode::Blocklist, vec![]);
        let d = decide(&p, &conn(r"C:\AnyDesk\AnyDesk.exe", "50.7.8.9", 443));
        assert_eq!(d, Decision::Permit);
    }

    #[test]
    fn remote_tool_blocks_when_opted_in() {
        // Opt-in (block_network) still cuts the tool's relay.
        let rt = RemoteToolPolicy { default_action: ToolAction::BlockNetwork, overrides: Default::default() };
        let p = NetPolicy { mode: NetMode::Blocklist, rules: vec![], remote_tools: rt };
        let d = decide(&p, &conn(r"C:\AnyDesk\AnyDesk.exe", "50.7.8.9", 443));
        assert!(d.is_block());
        assert!(d.reason().contains("anydesk"));
    }

    #[test]
    fn remote_tool_detect_action_falls_through() {
        let mut rt = RemoteToolPolicy::default();
        rt.overrides.insert("rdp-out".into(), ToolAction::Detect);
        let p = NetPolicy { mode: NetMode::Blocklist, rules: vec![], remote_tools: rt };
        // detect-only → not blocked by the tool set → blocklist default permit.
        assert_eq!(decide(&p, &conn("mstsc.exe", "1.2.3.4", 3389)), Decision::Permit);
    }

    #[test]
    fn explicit_permit_overrides_remote_tool_block_precedence() {
        // An explicit Permit rule earlier than the tool set wins (first-match).
        let p = policy(
            NetMode::Blocklist,
            vec![rule(Some("anydesk.exe"), None, None, RuleAction::Permit)],
        );
        assert_eq!(decide(&p, &conn(r"C:\x\anydesk.exe", "50.7.8.9", 443)), Decision::Permit);
    }

    #[test]
    fn first_match_ordering_is_respected() {
        // First rule (permit port 443) wins over a later broad block.
        let p = policy(
            NetMode::Blocklist,
            vec![
                rule(None, None, Some(443), RuleAction::Permit),
                rule(None, Some("0.0.0.0/0"), None, RuleAction::Block),
            ],
        );
        assert_eq!(decide(&p, &conn("app.exe", "8.8.8.8", 443)), Decision::Permit);
        // A different port hits the second rule and is blocked.
        assert!(decide(&p, &conn("app.exe", "8.8.8.8", 80)).is_block());
    }

    #[test]
    fn allowlist_default_denies() {
        let p = policy(NetMode::Allowlist, vec![]);
        assert!(decide(&p, &conn("app.exe", "8.8.8.8", 443)).is_block());
    }

    #[test]
    fn blocklist_default_permits() {
        let p = policy(NetMode::Blocklist, vec![]);
        assert_eq!(decide(&p, &conn("app.exe", "8.8.8.8", 443)), Decision::Permit);
    }

    #[test]
    fn monitor_default_permits_never_bricks() {
        // Monitor never default-denies — even with an allowlist-style intent it
        // permits and logs. (The banner/loop logs the intended verdict.)
        let p = policy(NetMode::Monitor, vec![]);
        assert_eq!(decide(&p, &conn("app.exe", "8.8.8.8", 443)), Decision::Permit);
    }

    #[test]
    fn allowlisted_dest_still_permitted_in_allowlist_mode() {
        let p = policy(
            NetMode::Allowlist,
            vec![rule(None, Some("192.168.0.0/16"), None, RuleAction::Permit)],
        );
        assert_eq!(decide(&p, &conn("app.exe", "192.168.4.4", 443)), Decision::Permit);
        assert!(decide(&p, &conn("app.exe", "8.8.8.8", 443)).is_block());
    }

    #[test]
    fn fail_secure_blocks_unreadable_to_unknown_dest() {
        assert!(fail_secure_egress(true, false).is_block());
        assert_eq!(fail_secure_egress(true, true), Decision::Permit);
        assert_eq!(fail_secure_egress(false, false), Decision::Permit);
        assert_eq!(fail_secure_egress(false, true), Decision::Permit);
    }

    #[test]
    fn cidr_parse_rejects_bad_prefix() {
        assert!(Cidr::parse("10.0.0.0/33").is_none());
        assert!(Cidr::parse("2001:db8::/129").is_none());
        assert!(Cidr::parse("not-an-ip").is_none());
        // Bare address → host route.
        assert_eq!(Cidr::parse("10.1.2.3").unwrap().prefix, 32);
        assert_eq!(Cidr::parse("::1").unwrap().prefix, 128);
    }
}
