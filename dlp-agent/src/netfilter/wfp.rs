//! WFP filter-spec builder + dry-run apply (Tier-2 plan §2.1, §2.5).
//!
//! This mirrors the USB-enforce dry-run contract EXACTLY (`src/usb/enforce.rs`):
//!   * `WfpFilterSpec` is a pure, inspectable description of the `FWPM_FILTER0`
//!     we WOULD add (layer / action / conditions / weight / provider+sublayer
//!     GUIDs) — the analogue of `PlannedAction`.
//!   * `plan_filter(...)` / `plan_filters(...)` are pure builders (no Win32).
//!   * `apply(specs, WfpMode::DryRun)` returns `Planned(..)` executing NOTHING —
//!     the named safety test asserts this without ever calling `FwpmFilterAdd0`.
//!   * `apply(specs, WfpMode::Live)` is `#[cfg(windows)]` + `--enforce`, opens a
//!     DYNAMIC WFP session (auto-cleanup on process exit), installs our provider
//!     + sublayer and the filters transactionally, and is **never hit by tests**.
//!     A non-Windows build gets a `bail!` stub so the crate stays cross-platform.
//!
//! Honesty (plan §0/§5): a live BLOCK filter stops the tool's *socket connect*.
//! It does not stop a screen already being viewed (analog hole), a privileged
//! payload that unhooks us, or encrypted exfil to an ALLOWED destination.

use super::rules::{Cidr, NetRule, RuleAction};

/// Our WFP provider + sublayer identity (stable, product-specific GUIDs). Teardown
/// targets only these so we never disturb Windows' own or third-party filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid(pub u128);

pub const DLP_PROVIDER_GUID: Guid = Guid(0x7b2e_6f10_9c3a_4d21_b8e4_5f1a2c3d4e5f);
pub const DLP_SUBLAYER_GUID: Guid = Guid(0x7b2e_6f11_9c3a_4d21_b8e4_5f1a2c3d4e60);

/// Default filter weight (mid-range; higher = evaluated earlier within a sublayer).
pub const DEFAULT_WEIGHT: u8 = 10;

/// The two ALE outbound-connect layers we install at (v4 + v6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpLayer {
    AleAuthConnectV4,
    AleAuthConnectV6,
}

/// BLOCK or PERMIT (the only two actions in this user-mode build — no callout).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpAction {
    Permit,
    Block,
}

/// One filter condition (the subset of `FWPM_CONDITION_*` we use).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WfpCondition {
    /// `FWPM_CONDITION_ALE_APP_ID` — the initiating process image path.
    AppId(String),
    /// `FWPM_CONDITION_IP_REMOTE_ADDRESS` — a remote address/prefix.
    RemoteAddress(Cidr),
    /// `FWPM_CONDITION_IP_REMOTE_PORT` — a remote port.
    RemotePort(u16),
}

/// The pure description of an `FWPM_FILTER0` we would add. Asserted by tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpFilterSpec {
    pub name: String,
    pub layer: WfpLayer,
    pub action: WfpAction,
    pub conditions: Vec<WfpCondition>,
    pub weight: u8,
    pub provider: Guid,
    pub sublayer: Guid,
}

fn action_of(a: RuleAction) -> WfpAction {
    match a {
        RuleAction::Permit => WfpAction::Permit,
        RuleAction::Block => WfpAction::Block,
    }
}

fn conditions_of(rule: &NetRule) -> Vec<WfpCondition> {
    let mut c = Vec::new();
    if let Some(app) = &rule.match_app {
        c.push(WfpCondition::AppId(app.clone()));
    }
    if let Some(cidr) = &rule.match_cidr {
        c.push(WfpCondition::RemoteAddress(cidr.clone()));
    }
    if let Some(port) = rule.match_port {
        c.push(WfpCondition::RemotePort(port));
    }
    c
}

/// Which layers a rule installs at. A v4 CIDR → V4 only; a v6 CIDR → V6 only; an
/// app/port-only rule (no address) → BOTH layers (so it covers v4 and v6 egress).
pub fn layers_for(rule: &NetRule) -> Vec<WfpLayer> {
    match &rule.match_cidr {
        Some(c) if c.is_v4() => vec![WfpLayer::AleAuthConnectV4],
        Some(_) => vec![WfpLayer::AleAuthConnectV6],
        None => vec![WfpLayer::AleAuthConnectV4, WfpLayer::AleAuthConnectV6],
    }
}

/// Build one filter spec for a rule at a given layer. Pure — no I/O.
pub fn plan_filter(rule: &NetRule, layer: WfpLayer, weight: u8) -> WfpFilterSpec {
    WfpFilterSpec {
        name: rule.note.clone().unwrap_or_else(|| "dlp-net-rule".into()),
        layer,
        action: action_of(rule.action),
        conditions: conditions_of(rule),
        weight,
        provider: DLP_PROVIDER_GUID,
        sublayer: DLP_SUBLAYER_GUID,
    }
}

/// Build the full filter set for a rule (both layers when address-agnostic).
pub fn plan_filters(rule: &NetRule) -> Vec<WfpFilterSpec> {
    layers_for(rule)
        .into_iter()
        .map(|layer| plan_filter(rule, layer, DEFAULT_WEIGHT))
        .collect()
}

/// Build the BLOCK filter set for a remote-access tool identified by image path
/// (both layers; app-id condition only — ports are unreliable, plan §2.2).
pub fn plan_tool_block(app_path: &str, weight: u8) -> Vec<WfpFilterSpec> {
    [WfpLayer::AleAuthConnectV4, WfpLayer::AleAuthConnectV6]
        .into_iter()
        .map(|layer| WfpFilterSpec {
            name: format!("dlp-block-tool:{}", basename(app_path)),
            layer,
            action: WfpAction::Block,
            conditions: vec![WfpCondition::AppId(app_path.to_string())],
            weight,
            provider: DLP_PROVIDER_GUID,
            sublayer: DLP_SUBLAYER_GUID,
        })
        .collect()
}

fn basename(path: &str) -> String {
    path.replace('/', "\\")
        .rsplit('\\')
        .next()
        .unwrap_or(path)
        .to_string()
}

/// Whether `apply()` is allowed to touch the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpMode {
    DryRun,
    Live,
}

/// Outcome of applying a filter set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WfpApplyOutcome {
    /// Dry-run: the specs that WOULD be installed. Nothing was touched.
    Planned(Vec<WfpFilterSpec>),
    /// Live: number of filters actually added to the engine.
    Executed(usize),
}

/// Apply a filter set. `DryRun` executes NOTHING and returns `Planned`. `Live`
/// installs the filters via WFP (Windows only, admin required) and returns
/// `Executed(n)`. Tests only ever call `DryRun`.
pub fn apply(specs: &[WfpFilterSpec], mode: WfpMode) -> anyhow::Result<WfpApplyOutcome> {
    match mode {
        WfpMode::DryRun => Ok(WfpApplyOutcome::Planned(specs.to_vec())),
        WfpMode::Live => {
            let n = execute_live(specs)?;
            Ok(WfpApplyOutcome::Executed(n))
        }
    }
}

fn layer_guid(layer: WfpLayer) -> u128 {
    match layer {
        // FWPM_LAYER_ALE_AUTH_CONNECT_V4 / _V6 (from the WFP headers).
        WfpLayer::AleAuthConnectV4 => 0xc38d57d1_05a7_4c33_904f_7fbceee60e82,
        WfpLayer::AleAuthConnectV6 => 0x4a72393b_319f_44bc_84c3_ba54dcb3b6b4,
    }
}

// ---------------------------------------------------------------------------
// Live execution (Windows only). NEVER reached by tests. Opens a DYNAMIC WFP
// session so all our provider/sublayer/filters are auto-removed when this
// process exits (plan §2.1 hygiene). On non-Windows this is a bail! stub so the
// library builds cross-platform, exactly like usb::enforce::execute_live.
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
fn execute_live(_specs: &[WfpFilterSpec]) -> anyhow::Result<usize> {
    anyhow::bail!("live WFP enforcement is only available on Windows")
}

#[cfg(windows)]
fn execute_live(specs: &[WfpFilterSpec]) -> anyhow::Result<usize> {
    use windows::core::{GUID, PCWSTR, PWSTR};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineOpen0, FwpmProviderAdd0, FwpmSubLayerAdd0, FwpmTransactionAbort0,
        FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_PROVIDER0, FWPM_SESSION0,
        FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    };
    use windows::Win32::Security::PSECURITY_DESCRIPTOR;

    // Success + benign "already installed" codes (FWP_E_ALREADY_EXISTS).
    const ERROR_OK: u32 = 0;
    const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;
    // RPC_C_AUTHN_WINNT — the standard auth service for a local WFP session.
    const RPC_C_AUTHN_WINNT: u32 = 10;

    unsafe {
        // 1. Open a DYNAMIC session (auto-teardown of everything we add on exit).
        let mut session: FWPM_SESSION0 = std::mem::zeroed();
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        let mut engine = HANDLE::default();
        let rc = FwpmEngineOpen0(
            PCWSTR::null(),
            RPC_C_AUTHN_WINNT,
            None,
            Some(&session),
            &mut engine,
        );
        if rc != ERROR_OK {
            anyhow::bail!("FwpmEngineOpen0 failed: {rc:#x} (need admin/SYSTEM)");
        }

        // 2. Install our provider (idempotent).
        let mut prov_name: Vec<u16> = "DLP Agent".encode_utf16().chain([0]).collect();
        let mut provider: FWPM_PROVIDER0 = std::mem::zeroed();
        provider.providerKey = GUID::from_u128(DLP_PROVIDER_GUID.0);
        provider.displayData.name = PWSTR(prov_name.as_mut_ptr());
        let rc = FwpmProviderAdd0(engine, &provider, PSECURITY_DESCRIPTOR::default());
        if rc != ERROR_OK && rc != FWP_E_ALREADY_EXISTS {
            anyhow::bail!("FwpmProviderAdd0 failed: {rc:#x}");
        }

        // 3. Install our sublayer (idempotent), owned by our provider.
        let mut sub_name: Vec<u16> = "DLP Agent egress".encode_utf16().chain([0]).collect();
        let mut prov_key = GUID::from_u128(DLP_PROVIDER_GUID.0);
        let mut sublayer: FWPM_SUBLAYER0 = std::mem::zeroed();
        sublayer.subLayerKey = GUID::from_u128(DLP_SUBLAYER_GUID.0);
        sublayer.displayData.name = PWSTR(sub_name.as_mut_ptr());
        sublayer.providerKey = &mut prov_key;
        sublayer.weight = 0x8000;
        let rc = FwpmSubLayerAdd0(engine, &sublayer, PSECURITY_DESCRIPTOR::default());
        if rc != ERROR_OK && rc != FWP_E_ALREADY_EXISTS {
            anyhow::bail!("FwpmSubLayerAdd0 failed: {rc:#x}");
        }

        // 4. Add filters transactionally.
        let rc = FwpmTransactionBegin0(engine, 0);
        if rc != ERROR_OK {
            anyhow::bail!("FwpmTransactionBegin0 failed: {rc:#x}");
        }

        let mut added = 0usize;
        for spec in specs {
            let action = match spec.action {
                WfpAction::Block => FWP_ACTION_BLOCK,
                WfpAction::Permit => FWP_ACTION_PERMIT,
            };
            if let Err(e) = add_one_filter(engine, spec, action) {
                let _ = FwpmTransactionAbort0(engine);
                return Err(e);
            }
            added += 1;
        }

        let rc = FwpmTransactionCommit0(engine);
        if rc != ERROR_OK {
            let _ = FwpmTransactionAbort0(engine);
            anyhow::bail!("FwpmTransactionCommit0 failed: {rc:#x}");
        }

        // Intentionally DO NOT close the engine handle: with a DYNAMIC session,
        // closing it (FwpmEngineClose0) would immediately remove our filters. We
        // simply never close it — the handle is a plain Copy value with no Drop,
        // so it stays open for the process lifetime and Windows tears everything
        // down when the process exits (auto-cleanup). `net-monitor` blocks after
        // this call to keep the process (and thus the filters) alive.
        let _keep_engine_open = engine;

        tracing::warn!(filters = added, "live WFP enforcement: filters installed (dynamic session)");
        Ok(added)
    }
}

/// Build one `FWPM_FILTER0` (with its conditions) and add it. All backing storage
/// (condition array, address masks, app-id blob, display name) is kept alive
/// across the `FwpmFilterAdd0` call — WFP copies the filter, so blobs are freed
/// immediately afterward.
#[cfg(windows)]
unsafe fn add_one_filter(
    engine: windows::Win32::Foundation::HANDLE,
    spec: &WfpFilterSpec,
    action_type: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_TYPE,
) -> anyhow::Result<()> {
    use windows::core::{GUID, PCWSTR, PWSTR};
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmFilterAdd0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FWPM_CONDITION_ALE_APP_ID,
        FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER0,
        FWPM_FILTER_CONDITION0, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_MATCH_EQUAL, FWP_UINT16,
        FWP_UINT8, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
    };
    use windows::Win32::Security::PSECURITY_DESCRIPTOR;

    const ERROR_OK: u32 = 0;

    // Backing storage that must outlive the FwpmFilterAdd0 call.
    let mut conds: Vec<FWPM_FILTER_CONDITION0> = Vec::new();
    let mut v4masks: Vec<Box<FWP_V4_ADDR_AND_MASK>> = Vec::new();
    let mut v6masks: Vec<Box<FWP_V6_ADDR_AND_MASK>> = Vec::new();
    let mut appid_blobs: Vec<*mut FWP_BYTE_BLOB> = Vec::new();
    // Keep the wide app-id path buffers alive across FwpmGetAppIdFromFileName0.
    let mut appid_paths: Vec<Vec<u16>> = Vec::new();

    for cond in &spec.conditions {
        let mut fc: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
        fc.matchType = FWP_MATCH_EQUAL;
        match cond {
            WfpCondition::AppId(path) => {
                let path_w: Vec<u16> = path.encode_utf16().chain([0]).collect();
                let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
                let rc = FwpmGetAppIdFromFileName0(PCWSTR(path_w.as_ptr()), &mut blob);
                if rc != ERROR_OK {
                    anyhow::bail!("FwpmGetAppIdFromFileName0({path}) failed: {rc:#x}");
                }
                appid_paths.push(path_w);
                appid_blobs.push(blob);
                fc.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                fc.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                fc.conditionValue.Anonymous.byteBlob = blob;
            }
            WfpCondition::RemoteAddress(cidr) => {
                fc.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                match cidr.base {
                    std::net::IpAddr::V4(v4) => {
                        let mask = if cidr.prefix == 0 { 0 } else { u32::MAX << (32 - cidr.prefix as u32) };
                        let am = Box::new(FWP_V4_ADDR_AND_MASK { addr: u32::from(v4), mask });
                        fc.conditionValue.r#type = FWP_V4_ADDR_MASK;
                        fc.conditionValue.Anonymous.v4AddrMask = am.as_ref() as *const _ as *mut _;
                        v4masks.push(am);
                    }
                    std::net::IpAddr::V6(v6) => {
                        let am = Box::new(FWP_V6_ADDR_AND_MASK {
                            addr: v6.octets(),
                            prefixLength: cidr.prefix,
                        });
                        fc.conditionValue.r#type = FWP_V6_ADDR_MASK;
                        fc.conditionValue.Anonymous.v6AddrMask = am.as_ref() as *const _ as *mut _;
                        v6masks.push(am);
                    }
                }
            }
            WfpCondition::RemotePort(port) => {
                fc.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                fc.conditionValue.r#type = FWP_UINT16;
                fc.conditionValue.Anonymous.uint16 = *port;
            }
        }
        conds.push(fc);
    }

    let mut name_w: Vec<u16> = spec.name.encode_utf16().chain([0]).collect();
    let mut prov_key = GUID::from_u128(spec.provider.0);

    let mut filter: FWPM_FILTER0 = std::mem::zeroed();
    filter.displayData.name = PWSTR(name_w.as_mut_ptr());
    filter.layerKey = GUID::from_u128(layer_guid(spec.layer));
    filter.subLayerKey = GUID::from_u128(spec.sublayer.0);
    filter.providerKey = &mut prov_key;
    filter.weight.r#type = FWP_UINT8;
    filter.weight.Anonymous.uint8 = spec.weight;
    filter.numFilterConditions = conds.len() as u32;
    filter.filterCondition = if conds.is_empty() { std::ptr::null_mut() } else { conds.as_mut_ptr() };
    filter.action.r#type = action_type;

    let rc = FwpmFilterAdd0(engine, &filter, PSECURITY_DESCRIPTOR::default(), None);

    // WFP has copied the filter — free the app-id blobs we allocated.
    for blob in appid_blobs {
        let mut p = blob as *mut core::ffi::c_void;
        FwpmFreeMemory0(&mut p);
    }
    // v4masks/v6masks/name_w/appid_paths/prov_key drop here, after the add.

    if rc != ERROR_OK {
        anyhow::bail!("FwpmFilterAdd0({}) failed: {rc:#x}", spec.name);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netfilter::rules::{Cidr, NetRule, RuleAction};

    fn rule(app: Option<&str>, cidr: Option<&str>, port: Option<u16>, action: RuleAction, note: &str) -> NetRule {
        NetRule {
            match_app: app.map(|s| s.to_string()),
            match_cidr: cidr.map(|s| Cidr::parse(s).unwrap()),
            match_port: port,
            action,
            note: Some(note.to_string()),
        }
    }

    #[test]
    fn permit_rule_builds_permit_action() {
        let r = rule(Some("curl.exe"), None, Some(443), RuleAction::Permit, "allow curl 443");
        let specs = plan_filters(&r);
        // app/port-only rule → both v4 and v6 layers.
        assert_eq!(specs.len(), 2);
        assert!(specs.iter().any(|s| s.layer == WfpLayer::AleAuthConnectV4));
        assert!(specs.iter().any(|s| s.layer == WfpLayer::AleAuthConnectV6));
        for s in &specs {
            assert_eq!(s.action, WfpAction::Permit);
            assert_eq!(s.provider, DLP_PROVIDER_GUID);
            assert_eq!(s.sublayer, DLP_SUBLAYER_GUID);
            assert_eq!(s.name, "allow curl 443");
            assert!(s.conditions.contains(&WfpCondition::AppId("curl.exe".into())));
            assert!(s.conditions.contains(&WfpCondition::RemotePort(443)));
        }
    }

    #[test]
    fn v4_cidr_rule_is_v4_layer_only_with_address_condition() {
        let r = rule(None, Some("10.0.0.0/8"), None, RuleAction::Block, "block 10/8");
        let specs = plan_filters(&r);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].layer, WfpLayer::AleAuthConnectV4);
        assert_eq!(specs[0].action, WfpAction::Block);
        assert_eq!(
            specs[0].conditions,
            vec![WfpCondition::RemoteAddress(Cidr::parse("10.0.0.0/8").unwrap())]
        );
    }

    #[test]
    fn v6_cidr_rule_is_v6_layer_only() {
        let r = rule(None, Some("2001:db8::/32"), None, RuleAction::Block, "block v6");
        let specs = plan_filters(&r);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].layer, WfpLayer::AleAuthConnectV6);
    }

    #[test]
    fn tool_block_spec_has_app_id_and_both_layers() {
        let specs = plan_tool_block(r"C:\AnyDesk\AnyDesk.exe", DEFAULT_WEIGHT);
        assert_eq!(specs.len(), 2);
        for s in &specs {
            assert_eq!(s.action, WfpAction::Block);
            assert_eq!(s.conditions.len(), 1);
            assert!(matches!(&s.conditions[0], WfpCondition::AppId(p) if p.ends_with("AnyDesk.exe")));
        }
    }

    #[test]
    fn dry_run_apply_executes_nothing_and_returns_the_plan() {
        // The core safety property: dry-run must NOT call FwpmFilterAdd0.
        let r = rule(Some("ftp.exe"), None, None, RuleAction::Block, "block ftp");
        let specs = plan_filters(&r);
        let outcome = apply(&specs, WfpMode::DryRun).expect("dry-run never fails");
        assert_eq!(outcome, WfpApplyOutcome::Planned(specs));
    }

    #[test]
    fn dry_run_of_empty_set_is_empty_plan() {
        let outcome = apply(&[], WfpMode::DryRun).unwrap();
        assert_eq!(outcome, WfpApplyOutcome::Planned(vec![]));
    }
}
