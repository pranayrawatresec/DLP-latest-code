//! Check-in: the mutual-TLS heartbeat. Proves identity with the client
//! certificate, refreshes state, and (Phase 3) will receive the licensed
//! entitlement token and signed policy bundle.
use crate::{client, config::Config, storage::Storage};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct CheckinRequest<'a> {
    #[serde(rename = "agentVersion")]
    agent_version: &'a str,
}

#[derive(Deserialize)]
struct CheckinResponse {
    status: String,
    #[serde(rename = "agentId")]
    agent_id: String,
    #[serde(rename = "checkinIntervalSeconds")]
    checkin_interval_seconds: u64,
    #[serde(rename = "policyBundle")]
    policy_bundle: Option<serde_json::Value>,
    /// Latest compiled index bundle advertisement. Tolerant: servers without
    /// the detection feature omit it entirely (→ latest 0).
    #[serde(default)]
    index: Option<IndexAdvert>,
}

#[derive(Deserialize, Default)]
struct IndexAdvert {
    #[serde(default)]
    latest: u64,
}

/// What one check-in told us, beyond "still trusted".
pub struct CheckinOutcome {
    pub interval_seconds: u64,
    /// Latest index bundle version on the server (0 = none advertised).
    pub index_latest: u64,
}

/// Perform one check-in. Returns the server-directed interval until the next.
pub fn checkin(cfg: &Config, storage: &Storage) -> Result<u64> {
    checkin_full(cfg, storage).map(|o| o.interval_seconds)
}

/// Perform one check-in and return the full outcome (interval + index
/// advertisement) — used by `index-update`.
pub fn checkin_full(cfg: &Config, storage: &Storage) -> Result<CheckinOutcome> {
    let (identity_pem, ca_pem) = storage.load_identity()?;
    let client = client::checkin_client(&ca_pem, &identity_pem)?;

    let resp = client
        .post(cfg.checkin_url())
        .json(&CheckinRequest {
            agent_version: env!("CARGO_PKG_VERSION"),
        })
        .send()
        .context("check-in request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        // 403 here means de-enrolled/retired — the server has revoked us.
        bail!("check-in refused [{status}]: {body}");
    }
    let cr: CheckinResponse = resp.json().context("parsing check-in response")?;
    if cr.status != "active" {
        bail!("unexpected check-in status: {}", cr.status);
    }

    // Cache the policy for fail-secure enforcement when offline (null in Phase 2).
    if let Some(bundle) = &cr.policy_bundle {
        let _ = storage.cache_policy(&bundle.to_string());
    }

    tracing::info!(agent_id = %cr.agent_id, next_in = cr.checkin_interval_seconds, "checked in");
    Ok(CheckinOutcome {
        interval_seconds: cr.checkin_interval_seconds,
        index_latest: cr.index.map(|i| i.latest).unwrap_or(0),
    })
}
