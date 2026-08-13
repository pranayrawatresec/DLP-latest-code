//! Check-in: the mutual-TLS heartbeat. Proves identity with the client
//! certificate, refreshes state, and (Phase 3) will receive the licensed
//! entitlement token and signed policy bundle.
use crate::trustsync::{self, SyncedDestination, TrustedConfig};
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

/// M6: pull the console-authored trusted-destination whitelist + encryption
/// keys from the management server over the agent's mTLS identity
/// (`GET /agent/trusted-config`, PINNED contract), persist the keyring (DPAPI at
/// rest) and the destinations (metadata only), and return the parsed config.
///
/// FAIL SOFT (offline fail-secure): on ANY network/parse error, log a warning
/// and return the LAST-persisted destinations — the DPAPI-sealed keyring at rest
/// already survives — so the channels keep enforcing the last known whitelist
/// with no server round-trip on the hot path. NEVER logs key material: only key
/// **ids** and counts.
pub fn sync_trusted_config(cfg: &Config, storage: &Storage) -> Result<TrustedConfig> {
    match fetch_trusted_config(cfg, storage) {
        Ok(tc) => {
            // Keyring first: the raw KEK bytes go ONLY into the DPAPI-sealed
            // store (never a log, never the destinations file).
            match tc.to_keyring_json() {
                Some(json) => {
                    if let Err(e) = storage.store_keyring(&json) {
                        tracing::warn!(error = %e, "could not persist synced keyring at rest");
                    }
                }
                None => tracing::warn!(
                    "trusted-config delivered no keys — keeping any keyring already at rest"
                ),
            }
            // Destinations: metadata only (channel/matcher/mode/key IDS/band).
            if let Err(e) =
                storage.store_trusted_destinations(&trustsync::serialize_destinations(&tc.destinations))
            {
                tracing::warn!(error = %e, "could not persist synced trusted destinations");
            }
            tracing::info!(
                destinations = tc.destinations.len(),
                keys = tc.keys.len(),
                "synced trusted config from server"
            );
            Ok(tc)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "trusted-config sync failed — using last-persisted whitelist (offline, fail secure)"
            );
            Ok(TrustedConfig {
                destinations: load_synced_destinations(storage),
                keys: Vec::new(),
            })
        }
    }
}

/// The mTLS GET half of the sync — the SAME CA-pinned client identity as
/// check-in. Separated so `sync_trusted_config` owns the fail-soft persistence.
fn fetch_trusted_config(cfg: &Config, storage: &Storage) -> Result<TrustedConfig> {
    let (identity_pem, ca_pem) = storage.load_identity()?;
    let client = client::checkin_client(&ca_pem, &identity_pem)?;
    let resp = client
        .get(cfg.trusted_config_url())
        .send()
        .context("trusted-config request failed")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        bail!("trusted-config refused [{status}]: {body}");
    }
    resp.json::<TrustedConfig>()
        .context("parsing trusted-config response")
}

/// The last-persisted trusted destinations (metadata only). Empty when the agent
/// has never synced, or when the persisted file is unparseable (logged). Never
/// returns key material.
pub fn load_synced_destinations(storage: &Storage) -> Vec<SyncedDestination> {
    match storage.load_trusted_destinations() {
        Some(bytes) => match trustsync::parse_destinations(&bytes) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, "persisted trusted-destinations unparseable — ignoring");
                Vec::new()
            }
        },
        None => Vec::new(),
    }
}
