//! Remote-access-tool signature set + matcher (optional, opt-in hygiene).
//!
//! IMPORTANT — this is NOT one of the network data-exfil layers. Blocking
//! agent-*detected* sensitive data leaving over any tool (AnyDesk/RustDesk/…) is
//! done by **read-taint** (content the agent flags → taint the reader → cut its
//! egress) and **default-deny egress** (a tool's relay isn't an approved
//! destination → blocked). Neither needs to know the tool's name.
//!
//! This signature set exists only for the ONE case those two cannot cover: the
//! **analog hole** — an operator *screen-viewing* a document over a remote tool
//! and photographing it. No file leaves, so there is nothing to detect or taint;
//! the only lever is to forbid the tool itself. Because that is a different threat
//! (and disruptive), remote-tool action **defaults to `detect` (visibility only —
//! never blocks/kills)**; blocking is a deliberate opt-in
//! (`[netfilter] remote_tool_action = "block_network" | "kill"`).
//!
//! **Matching is PRIMARY on process image name.** Ports are unreliable (every one
//! of these tools falls back to 443/TCP to punch through firewalls), so a port
//! match is only a weak secondary signal; relay domains are a secondary signal
//! for the netfilter layer. The image-name matcher below is the authoritative
//! one. Pure logic, fully unit-tested; no I/O.
//!
//! **Matching is PRIMARY on process image name.** Ports are unreliable (every one
//! of these tools falls back to 443/TCP to punch through firewalls), so a port
//! match is only a weak secondary signal; relay domains are a secondary signal
//! for the netfilter layer. The image-name matcher below is the authoritative
//! one. Pure logic, fully unit-tested; no I/O.

use std::collections::HashMap;

use serde::Deserialize;

/// What to do when a remote-access tool is identified. Config-selectable per tool
/// (`[netfilter] remote_tool_action` / `remote_tool_overrides`); the defence
/// default is `block_network` (cut the relay) — never `kill` by default, because
/// terminating a running admin session is disruptive and is an operator choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolAction {
    /// Incident only — do not block or kill. Visibility without disruption.
    Detect,
    /// Add a WFP app-id BLOCK filter so the tool cannot reach its relay.
    BlockNetwork,
    /// Terminate the process (live kill is admin + `--enforce`, operator-manual;
    /// never exercised by tests).
    Kill,
}

/// A single remote-access-tool signature. `images` are lowercase process image
/// base names (the authoritative signal). `publishers`/`relay_domains`/`ports`
/// are secondary corroborating signals only.
#[derive(Debug, Clone, Copy)]
pub struct RemoteTool {
    pub id: &'static str,
    pub name: &'static str,
    pub images: &'static [&'static str],
    pub publishers: &'static [&'static str],
    pub relay_domains: &'static [&'static str],
    pub ports: &'static [u16],
}

/// The built-in signature set (plan §2.2). Extend by adding rows — the matcher is
/// data-driven. Image names are the primary key; keep them lowercase.
pub const REMOTE_TOOLS: &[RemoteTool] = &[
    RemoteTool {
        id: "anydesk",
        name: "AnyDesk",
        images: &["anydesk.exe"],
        publishers: &["AnyDesk Software GmbH"],
        relay_domains: &["anydesk.com", "net.anydesk.com"],
        ports: &[7070],
    },
    RemoteTool {
        id: "rustdesk",
        name: "RustDesk",
        // Self-hosted or public-relay remote desktop with built-in file transfer.
        // Single main image; the tray/service run from the same rustdesk.exe.
        images: &["rustdesk.exe"],
        publishers: &["Purslane Ltd", "RustDesk"],
        relay_domains: &["rustdesk.com"],
        // hbbs/hbbr signal ports (21115-21119); secondary — RustDesk also uses
        // 443 relay fallback, so image name stays the authoritative signal.
        ports: &[21115, 21116, 21117, 21118, 21119],
    },
    RemoteTool {
        id: "teamviewer",
        name: "TeamViewer",
        images: &[
            "teamviewer.exe",
            "teamviewer_service.exe",
            "tv_w32.exe",
            "tv_x64.exe",
        ],
        publishers: &["TeamViewer Germany GmbH", "TeamViewer GmbH"],
        relay_domains: &["teamviewer.com"],
        ports: &[5938],
    },
    RemoteTool {
        id: "realvnc",
        name: "RealVNC",
        images: &["vncserver.exe", "vncviewer.exe", "winvnc4.exe"],
        publishers: &["RealVNC Limited"],
        relay_domains: &["realvnc.com"],
        ports: &[5900],
    },
    RemoteTool {
        id: "tightvnc",
        name: "TightVNC",
        images: &["tvnserver.exe", "tvnviewer.exe"],
        publishers: &["GlavSoft LLC"],
        relay_domains: &["tightvnc.com"],
        ports: &[5900],
    },
    RemoteTool {
        id: "ultravnc",
        name: "UltraVNC",
        images: &["winvnc.exe", "uvnc_service.exe", "vncviewer.exe"],
        publishers: &["uvnc"],
        relay_domains: &["uvnc.com"],
        ports: &[5900],
    },
    RemoteTool {
        id: "chrome-remote-desktop",
        name: "Chrome Remote Desktop",
        images: &["remoting_host.exe", "remote_assistance_host.exe"],
        publishers: &["Google LLC"],
        relay_domains: &["remotedesktop.google.com", "talkgadget.google.com"],
        ports: &[443],
    },
    RemoteTool {
        id: "rdp-out",
        name: "RDP client (mstsc, outbound)",
        images: &["mstsc.exe"],
        publishers: &["Microsoft Corporation"],
        relay_domains: &[],
        ports: &[3389],
    },
    RemoteTool {
        id: "splashtop",
        name: "Splashtop",
        images: &["srservice.exe", "srserver.exe", "strwinclt.exe", "splashtop.exe"],
        publishers: &["Splashtop Inc."],
        relay_domains: &["splashtop.com"],
        ports: &[6783],
    },
    RemoteTool {
        id: "logmein",
        name: "LogMeIn",
        images: &["logmein.exe", "lmiguardiansvc.exe", "ramaint.exe", "logmeinsystray.exe"],
        publishers: &["LogMeIn, Inc.", "GoTo Technologies"],
        relay_domains: &["logmein.com"],
        ports: &[],
    },
];

/// The lowercased Windows/Unix base name of a path (drive/dir stripped).
fn basename(path: &str) -> String {
    let norm = path.to_ascii_lowercase().replace('/', "\\");
    norm.rsplit('\\').next().unwrap_or("").to_string()
}

/// PRIMARY matcher: identify a remote-access tool by process image name. Returns
/// the first signature whose image list contains this base name. Case-insensitive.
pub fn match_image(app_path: &str) -> Option<&'static RemoteTool> {
    let base = basename(app_path);
    if base.is_empty() {
        return None;
    }
    REMOTE_TOOLS
        .iter()
        .find(|t| t.images.iter().any(|img| img.eq_ignore_ascii_case(&base)))
}

/// SECONDARY matcher: identify a tool by a relay hostname (exact or a subdomain
/// of a known relay). Weaker than image matching — used only to enrich an
/// incident, never as the sole basis to block.
pub fn match_relay_domain(host: &str) -> Option<&'static RemoteTool> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return None;
    }
    REMOTE_TOOLS.iter().find(|t| {
        t.relay_domains
            .iter()
            .any(|d| h == *d || h.ends_with(&format!(".{d}")))
    })
}

/// The concrete outcome of matching one process against the tool set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolMatch {
    pub tool_id: &'static str,
    pub action: ToolAction,
}

/// Policy layered over the signature set: a default action plus per-tool
/// overrides (keyed by `tool_id`). Built from `[netfilter]` config.
#[derive(Debug, Clone)]
pub struct RemoteToolPolicy {
    pub default_action: ToolAction,
    pub overrides: HashMap<String, ToolAction>,
}

impl Default for RemoteToolPolicy {
    fn default() -> Self {
        // Default `detect` (visibility only): remote-tool blocking is decoupled
        // from the data-exfil layers (read-taint + default-deny) and is opt-in.
        // Set block_network/kill via config to deliberately forbid the tools.
        RemoteToolPolicy {
            default_action: ToolAction::Detect,
            overrides: HashMap::new(),
        }
    }
}

impl RemoteToolPolicy {
    /// Match an app image and resolve the effective action (override else default).
    pub fn match_app(&self, app_path: &str) -> Option<ToolMatch> {
        let tool = match_image(app_path)?;
        let action = self
            .overrides
            .get(tool.id)
            .copied()
            .unwrap_or(self.default_action);
        Some(ToolMatch { tool_id: tool.id, action })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_anydesk_by_full_path() {
        let t = match_image(r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe").unwrap();
        assert_eq!(t.id, "anydesk");
    }

    #[test]
    fn matches_teamviewer_service_variant() {
        assert_eq!(match_image(r"C:\x\TeamViewer_Service.exe").unwrap().id, "teamviewer");
        assert_eq!(match_image("tv_x64.exe").unwrap().id, "teamviewer");
    }

    #[test]
    fn matches_rustdesk() {
        assert_eq!(match_image(r"C:\Program Files\RustDesk\rustdesk.exe").unwrap().id, "rustdesk");
        assert_eq!(match_image("RustDesk.exe").unwrap().id, "rustdesk");
        assert_eq!(match_relay_domain("rs-ny.rustdesk.com").unwrap().id, "rustdesk");
    }

    #[test]
    fn matches_vnc_family() {
        assert_eq!(match_image("vncserver.exe").unwrap().id, "realvnc");
        assert_eq!(match_image("tvnserver.exe").unwrap().id, "tightvnc");
        assert_eq!(match_image(r"D:\uvnc\winvnc.exe").unwrap().id, "ultravnc");
    }

    #[test]
    fn matches_rdp_out_and_crd_and_splashtop_and_logmein() {
        assert_eq!(match_image("mstsc.exe").unwrap().id, "rdp-out");
        assert_eq!(match_image("remoting_host.exe").unwrap().id, "chrome-remote-desktop");
        assert_eq!(match_image("SRService.exe").unwrap().id, "splashtop");
        assert_eq!(match_image("LMIGuardianSvc.exe").unwrap().id, "logmein");
    }

    #[test]
    fn unknown_process_does_not_match() {
        assert!(match_image(r"C:\Windows\notepad.exe").is_none());
        assert!(match_image("").is_none());
    }

    #[test]
    fn relay_domain_match_is_secondary_signal() {
        assert_eq!(match_relay_domain("net.anydesk.com").unwrap().id, "anydesk");
        assert_eq!(match_relay_domain("REMOTEDESKTOP.GOOGLE.COM").unwrap().id, "chrome-remote-desktop");
        assert!(match_relay_domain("example.com").is_none());
    }

    #[test]
    fn policy_default_is_detect_not_block() {
        // Decoupled: by default remote tools are DETECTED (visibility), never
        // blocked/killed. Blocking is opt-in via config.
        let pol = RemoteToolPolicy::default();
        let m = pol.match_app("anydesk.exe").unwrap();
        assert_eq!(m.tool_id, "anydesk");
        assert_eq!(m.action, ToolAction::Detect);
    }

    #[test]
    fn policy_override_opts_in_to_block() {
        // An operator can still deliberately forbid a specific tool.
        let mut pol = RemoteToolPolicy::default();
        pol.overrides.insert("rdp-out".into(), ToolAction::BlockNetwork);
        assert_eq!(pol.match_app("mstsc.exe").unwrap().action, ToolAction::BlockNetwork);
        // A tool without an override still gets the detect-only default.
        assert_eq!(pol.match_app("anydesk.exe").unwrap().action, ToolAction::Detect);
    }

    #[test]
    fn explicit_block_default_still_works() {
        // Setting the whole policy to block (opt-in) is preserved.
        let pol = RemoteToolPolicy { default_action: ToolAction::BlockNetwork, overrides: HashMap::new() };
        assert_eq!(pol.match_app("anydesk.exe").unwrap().action, ToolAction::BlockNetwork);
    }

    #[test]
    fn policy_ignores_non_tool() {
        assert!(RemoteToolPolicy::default().match_app("chrome.exe").is_none());
    }
}
