//! Check-in: the mutual-TLS heartbeat. Proves identity with the client
//! certificate, refreshes state, and (Phase 3) will receive the licensed
//! entitlement token and signed policy bundle.
use crate::readdenypolicy::{self, ReadDenyPolicy};
use crate::clippolicy::ClipboardPolicy;
// Addressed through the library crate rather than `crate::mlpolicy`: the
// crate-root re-export list that gives the binary's submodules their `crate::*`
// aliases lives in main.rs, which this change deliberately does not touch.
use dlp_agent::ml;
use dlp_agent::mlpolicy::{self, MlPolicy};
use crate::trustedreaders::{self, SyncedReader};
use crate::trustsync::{self, SyncedDestination, TrustedConfig};
use crate::{client, config::Config, storage::Storage};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct CheckinRequest<'a> {
    #[serde(rename = "agentVersion")]
    agent_version: &'a str,
    /// ML classification coverage — NUMBERS ONLY, and only once the pipeline is
    /// actually doing something. See [`MlCoverage`]. Additive: a server that has
    /// never heard of it ignores it (the check-in handler reads `agentVersion`
    /// and nothing else off the body), and an agent whose ML policy is inert
    /// omits the field entirely, so the pre-feature payload is unchanged.
    #[serde(rename = "mlCoverage", skip_serializing_if = "Option::is_none")]
    ml_coverage: Option<MlCoverage>,
}

// ---------------------------------------------------------------------------
// ML coverage telemetry
// ---------------------------------------------------------------------------

/// **"Has this endpoint been covered yet?"** — the one question an operator must
/// be able to answer before turning `denyUnclassified` on, asked of a fleet
/// rather than of one PC.
///
/// `dlp-agent ml-status` answers it at a terminal, on the box. That does not
/// scale to ten thousand endpoints, so the same counts ride the heartbeat the
/// agent already sends: the console can then show which machines have a
/// completed discovery sweep under the CURRENT model, and which would start
/// denying first reads the moment the flag flipped.
///
/// WHAT MAY BE IN HERE, AND WHAT MAY NOT (cache contract C6, house rules).
/// Counts, flags, a model version string and unix seconds. **Never a path,
/// never a file name, never a label distribution, never content.** "How many
/// files were covered" is an operations metric; "which files" is the customer's
/// data, and it stays on the endpoint. The one string is `modelVersion`, which
/// is a build identifier the server issued in the first place.
///
/// It is also NOT an incident (contract F5): classifying a file is not a
/// detection, so coverage arrives as a property of the agent, on the existing
/// heartbeat, and never as an incident report.
#[derive(Serialize, Debug, Clone, Default, PartialEq)]
pub struct MlCoverage {
    /// Is the ONNX graph resident in the enforcing process right now?
    #[serde(rename = "modelLoaded")]
    pub model_loaded: bool,
    /// The version coverage is claimed under. Cache entries and sweep records
    /// written under any other version read as stale (cache contract C3), so a
    /// console comparing this against the completion record below is doing
    /// exactly what the read path does.
    #[serde(rename = "modelVersion")]
    pub model_version: String,
    #[serde(rename = "policyEnabled")]
    pub policy_enabled: bool,
    /// How many classes the console marked sensitive. A COUNT — the selection
    /// itself is the server's own configuration and needs no echo.
    #[serde(rename = "policyLabels")]
    pub policy_labels: usize,
    /// The flag this whole surface exists to gate.
    #[serde(rename = "denyUnclassified")]
    pub deny_unclassified: bool,
    /// Absent when no verdict cache is open in this process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache: Option<MlCacheCoverage>,
    /// Absent when this process runs no on-demand classifier worker.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue: Option<MlQueueCoverage>,
    pub discovery: MlDiscoveryCoverage,
}

/// [`ml::CacheStats`] on the wire. Re-stated rather than serialized directly so
/// the internal counter struct can change shape without moving the contract.
#[derive(Serialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MlCacheCoverage {
    pub entries: u64,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    /// **Any non-zero value is a tamper signal**, not a performance note.
    #[serde(rename = "hmacFailures")]
    pub hmac_failures: u64,
    #[serde(rename = "bytesOnDisk")]
    pub bytes_on_disk: u64,
}

impl From<ml::CacheStats> for MlCacheCoverage {
    fn from(s: ml::CacheStats) -> Self {
        MlCacheCoverage {
            entries: s.entries as u64,
            hits: s.hits,
            misses: s.misses,
            evictions: s.evictions,
            hmac_failures: s.hmac_failures,
            bytes_on_disk: s.bytes_on_disk,
        }
    }
}

/// [`ml::queue::QueueStats`] on the wire.
#[derive(Serialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MlQueueCoverage {
    pub capacity: usize,
    pub depth: usize,
    pub queued: u64,
    pub classified: u64,
    pub failed: u64,
    pub unextractable: u64,
    /// **Non-zero means this endpoint is missing coverage**, not merely that it
    /// is busy: a dropped job is content nothing classified.
    pub dropped: u64,
    pub deduped: u64,
    /// Reads denied by `denyUnclassified`. The counter that stands in for the
    /// per-read incident we deliberately do not raise (F5).
    #[serde(rename = "readsDenied")]
    pub reads_denied: u64,
}

impl From<ml::queue::QueueStats> for MlQueueCoverage {
    fn from(s: ml::queue::QueueStats) -> Self {
        MlQueueCoverage {
            capacity: s.capacity,
            depth: s.depth,
            queued: s.queued,
            classified: s.classified,
            failed: s.failed,
            unextractable: s.unextractable,
            dropped: s.dropped,
            deduped: s.deduped,
            reads_denied: s.deny_unclassified,
        }
    }
}

/// The at-rest walker's coverage evidence, read from its own state files rather
/// than from a live `Walker` handle — so a process that does not own the sweeper
/// (and the `ml-status` CLI) reports the same facts as the one that does.
#[derive(Serialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct MlDiscoveryCoverage {
    /// A full sweep has completed at least once on this endpoint.
    #[serde(rename = "sweepCompleted")]
    pub sweep_completed: bool,
    /// Unix seconds; 0 = never.
    #[serde(rename = "completedAt")]
    pub completed_at: u64,
    /// Files the completed sweep actually looked at.
    #[serde(rename = "filesCovered")]
    pub files_covered: u64,
    /// The completed sweep ran under the model version now in force. **False
    /// with `sweepCompleted` true means the endpoint is NOT covered**: every
    /// entry that sweep wrote is stale.
    #[serde(rename = "coversCurrentModel")]
    pub covers_current_model: bool,
    /// A sweep is resumable right now, i.e. one is in progress.
    #[serde(rename = "inProgress")]
    pub in_progress: bool,
    /// Candidates the in-progress sweep has processed so far.
    #[serde(rename = "inProgressCandidates")]
    pub in_progress_candidates: u64,
    /// How many trees the producers cover. A COUNT — the scope paths are the
    /// console's own configuration and never echo back from an endpoint.
    pub scopes: usize,
}

/// Gather the coverage counts for this process. Cheap and side-effect free: it
/// reads published in-memory counters plus two small JSON state files, opens
/// nothing and classifies nothing, so it is safe on every heartbeat.
pub fn ml_coverage(cfg: &Config) -> MlCoverage {
    let policy = mlpolicy::active();
    let model_version = ml::queue::model_version_for_cache();
    let completion = ml::walk::load_completion(&cfg.state_dir);
    let checkpoint = ml::walk::load_checkpoint(&cfg.state_dir);

    MlCoverage {
        model_loaded: ml::active().is_some(),
        policy_enabled: policy.enabled,
        policy_labels: policy.labels.len(),
        deny_unclassified: policy.deny_unclassified,
        cache: ml::queue::verdict_cache().map(|c| MlCacheCoverage::from(c.stats())),
        queue: ml::queue::running().then(|| MlQueueCoverage::from(ml::queue::stats())),
        discovery: MlDiscoveryCoverage {
            sweep_completed: completion.is_some(),
            completed_at: completion.as_ref().map(|c| c.completed_at).unwrap_or(0),
            files_covered: completion.as_ref().map(|c| c.files_covered()).unwrap_or(0),
            covers_current_model: completion
                .as_ref()
                .is_some_and(|c| c.covers_model(&model_version)),
            in_progress: checkpoint.is_some(),
            in_progress_candidates: checkpoint.map(|c| c.counts.candidates).unwrap_or(0),
            scopes: cfg.ml_scopes().len(),
        },
        model_version,
    }
}

/// Should this check-in carry coverage at all?
///
/// NO when the ML policy is inert AND no cache is open — contract F3: an
/// endpoint whose console has not selected a single label must behave exactly
/// like the agent that predates this feature, and that includes the bytes it
/// puts on the wire. There is also nothing to say: no producer has run, so every
/// count would be zero.
fn ml_coverage_for_checkin(cfg: &Config) -> Option<MlCoverage> {
    if mlpolicy::active().is_inert() && ml::queue::verdict_cache().is_none() {
        return None;
    }
    Some(ml_coverage(cfg))
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
            ml_coverage: ml_coverage_for_checkin(cfg),
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

/// Read-deny allowlist posture: pull the console-authored sanctioned-reader
/// allowlist from the management server over the agent's mTLS identity
/// (`GET /agent/trusted-readers`), persist it (metadata only), and return it.
///
/// FAIL SOFT (offline fail-secure, matching `sync_trusted_config`): on ANY
/// network/parse error, log a warning and return the LAST-persisted allowlist —
/// so a curated list keeps enforcing with no server round-trip on the hot path.
/// Independent of encryption config (no Org Root Key involved).
pub fn sync_trusted_readers(cfg: &Config, storage: &Storage) -> Vec<SyncedReader> {
    match fetch_trusted_readers(cfg, storage) {
        Ok(readers) => {
            if let Err(e) = storage.store_trusted_readers(&trustedreaders::serialize_readers(&readers)) {
                tracing::warn!(error = %e, "could not persist synced trusted readers");
            }
            tracing::info!(readers = readers.len(), "synced trusted readers from server");
            readers
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "trusted-readers sync failed — using last-persisted allowlist (offline, fail secure)"
            );
            load_synced_readers(storage)
        }
    }
}

/// The mTLS GET half of the reader sync — same CA-pinned client identity as
/// check-in. Response shape: `{ "readers": [ {matchType, value} ] }`.
fn fetch_trusted_readers(cfg: &Config, storage: &Storage) -> Result<Vec<SyncedReader>> {
    #[derive(Deserialize)]
    struct ReadersResponse {
        #[serde(default)]
        readers: Vec<SyncedReader>,
    }
    let (identity_pem, ca_pem) = storage.load_identity()?;
    let client = client::checkin_client(&ca_pem, &identity_pem)?;
    let resp = client
        .get(cfg.trusted_readers_url())
        .send()
        .context("trusted-readers request failed")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        bail!("trusted-readers refused [{status}]: {body}");
    }
    Ok(resp
        .json::<ReadersResponse>()
        .context("parsing trusted-readers response")?
        .readers)
}

/// Fetch the read-deny policy from the console, PERSIST + APPLY it (driver registry
/// knobs + volume attach — no CLI), and return it for the `[kguard]` config
/// override. On an unreachable server, reuse the last-persisted policy (fail-secure
/// offline); the driver already holds the last-applied knobs from a prior success.
pub fn sync_read_deny_policy(cfg: &Config, storage: &Storage) -> ReadDenyPolicy {
    match fetch_read_deny_policy(cfg, storage) {
        Ok(policy) => {
            if let Ok(json) = serde_json::to_vec(&policy) {
                if let Err(e) = storage.store_read_deny_policy(&json) {
                    tracing::warn!(error = %e, "could not persist read-deny policy");
                }
            }
            tracing::info!(
                mode = %policy.mode,
                posture = %policy.posture,
                scan_fixed = policy.scan_fixed,
                "synced read-deny policy from server"
            );
            readdenypolicy::apply_to_driver(&policy);
            policy
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "read-deny policy sync failed — using last-persisted policy (offline, fail secure)"
            );
            load_read_deny_policy(storage)
        }
    }
}

fn fetch_read_deny_policy(cfg: &Config, storage: &Storage) -> Result<ReadDenyPolicy> {
    #[derive(Deserialize)]
    struct PolicyResponse {
        policy: ReadDenyPolicy,
    }
    let (identity_pem, ca_pem) = storage.load_identity()?;
    let client = client::checkin_client(&ca_pem, &identity_pem)?;
    let resp = client
        .get(cfg.read_deny_policy_url())
        .send()
        .context("read-deny-policy request failed")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        bail!("read-deny-policy refused [{status}]: {body}");
    }
    Ok(resp
        .json::<PolicyResponse>()
        .context("parsing read-deny-policy response")?
        .policy)
}

/// The last-persisted read-deny policy, or the default (off) when never synced.
pub fn load_read_deny_policy(storage: &Storage) -> ReadDenyPolicy {
    match storage.load_read_deny_policy() {
        Some(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        None => ReadDenyPolicy::default(),
    }
}

/// Pull the console-managed CLIPBOARD policy and persist it (metadata only) so the
/// per-session helper keeps applying it if the server is briefly unreachable
/// (fail-soft to the last-persisted policy — default off when never synced).
pub fn sync_clipboard_policy(cfg: &Config, storage: &Storage) -> ClipboardPolicy {
    match fetch_clipboard_policy(cfg, storage) {
        Ok(policy) => {
            if let Ok(json) = serde_json::to_vec(&policy) {
                if let Err(e) = storage.store_clipboard_policy(&json) {
                    tracing::warn!(error = %e, "could not persist clipboard policy");
                }
            }
            tracing::info!(
                mode = %policy.mode,
                block_images = policy.block_images,
                "synced clipboard policy from server"
            );
            policy
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "clipboard policy sync failed — using last-persisted policy (offline)"
            );
            load_clipboard_policy(storage)
        }
    }
}

fn fetch_clipboard_policy(cfg: &Config, storage: &Storage) -> Result<ClipboardPolicy> {
    #[derive(Deserialize)]
    struct PolicyResponse {
        policy: ClipboardPolicy,
    }
    let (identity_pem, ca_pem) = storage.load_identity()?;
    let client = client::checkin_client(&ca_pem, &identity_pem)?;
    let resp = client
        .get(cfg.clipboard_policy_url())
        .send()
        .context("clipboard-policy request failed")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        bail!("clipboard-policy refused [{status}]: {body}");
    }
    Ok(resp
        .json::<PolicyResponse>()
        .context("parsing clipboard-policy response")?
        .policy)
}

/// The last-persisted clipboard policy, or the default (off) when never synced.
pub fn load_clipboard_policy(storage: &Storage) -> ClipboardPolicy {
    match storage.load_clipboard_policy() {
        Some(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        None => ClipboardPolicy::default(),
    }
}

/// Pull the console-managed ML document-classification policy, persist it
/// (metadata only — thresholds + selected label ids, never text or model bytes)
/// and PUBLISH it process-wide via [`mlpolicy::set_active`] so every classify site
/// reads one consistent copy without threading it through the frozen
/// `detect::verdict*` signatures.
///
/// FAIL SOFT (offline fail-secure, matching the clipboard/read-deny syncs): on ANY
/// network/parse error, log a warning and fall back to the LAST-PERSISTED policy —
/// the endpoint keeps applying the last console decision instead of silently
/// dropping to "off". Never synced at all ⇒ the inert default (disabled, no
/// labels), which is the pre-ML behaviour.
///
/// Logs `enabled` + a label COUNT only. The selected label set is admin
/// configuration, not endpoint content, but a count is all any operator needs and
/// it keeps this line free of anything resembling classification output.
pub fn sync_ml_policy(cfg: &Config, storage: &Storage) -> MlPolicy {
    let policy = match fetch_ml_policy(cfg, storage) {
        Ok(policy) => {
            if let Ok(json) = serde_json::to_vec(&policy) {
                if let Err(e) = storage.store_ml_policy(&json) {
                    tracing::warn!(error = %e, "could not persist ml policy");
                }
            }
            tracing::info!(
                enabled = policy.enabled,
                labels = policy.labels.len(),
                action = %policy.action,
                model_version = %policy.model_version,
                "synced ml policy from server"
            );
            policy
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "ml policy sync failed — using last-persisted policy (offline, fail secure)"
            );
            load_ml_policy(storage)
        }
    };
    // Publish on BOTH paths: the cached policy must keep applying while the
    // server is unreachable, so the fallback is published exactly like a fresh one.
    mlpolicy::set_active(policy.clone());
    policy
}

fn fetch_ml_policy(cfg: &Config, storage: &Storage) -> Result<MlPolicy> {
    #[derive(Deserialize)]
    struct PolicyResponse {
        policy: MlPolicy,
    }
    let (identity_pem, ca_pem) = storage.load_identity()?;
    let client = client::checkin_client(&ca_pem, &identity_pem)?;
    let resp = client
        .get(cfg.ml_policy_url())
        .send()
        .context("ml-policy request failed")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        bail!("ml-policy refused [{status}]: {body}");
    }
    Ok(resp
        .json::<PolicyResponse>()
        .context("parsing ml-policy response")?
        .policy)
}

/// The last-persisted ML policy, or the inert default (disabled, no labels) when
/// never synced or the cache is unparseable.
pub fn load_ml_policy(storage: &Storage) -> MlPolicy {
    match storage.load_ml_policy() {
        Some(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        None => MlPolicy::default(),
    }
}

/// The last-persisted sanctioned-reader allowlist (metadata only). Empty when
/// the agent has never synced, or when the persisted file is unparseable (logged).
pub fn load_synced_readers(storage: &Storage) -> Vec<SyncedReader> {
    match storage.load_trusted_readers() {
        Some(bytes) => match trustedreaders::parse_readers(&bytes) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "persisted trusted-readers unparseable — ignoring");
                Vec::new()
            }
        },
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F3, on the wire: an endpoint whose ML policy is inert sends the payload
    /// it sent before this feature existed — not an empty `mlCoverage` object.
    #[test]
    fn a_checkin_without_coverage_is_byte_identical_to_the_pre_feature_payload() {
        let body = serde_json::to_string(&CheckinRequest {
            agent_version: "9.9.9",
            ml_coverage: None,
        })
        .unwrap();
        assert_eq!(body, r#"{"agentVersion":"9.9.9"}"#);
    }

    /// C6: coverage telemetry is COUNTS. The only strings that may ever appear
    /// in it are build identifiers — never a path, a file name or a label.
    #[test]
    fn coverage_telemetry_carries_numbers_and_no_endpoint_strings() {
        let coverage = MlCoverage {
            model_loaded: true,
            model_version: "V6.2.01".into(),
            policy_enabled: true,
            policy_labels: 2,
            deny_unclassified: false,
            cache: Some(MlCacheCoverage {
                entries: 41_207,
                hits: 900,
                misses: 12,
                evictions: 0,
                hmac_failures: 3,
                bytes_on_disk: 7_654_321,
            }),
            queue: Some(MlQueueCoverage {
                capacity: 256,
                depth: 4,
                queued: 41_195,
                classified: 41_100,
                failed: 60,
                unextractable: 35,
                dropped: 7,
                deduped: 12,
                reads_denied: 0,
            }),
            discovery: MlDiscoveryCoverage {
                sweep_completed: true,
                completed_at: 1_788_946_333,
                files_covered: 41_207,
                covers_current_model: true,
                in_progress: false,
                in_progress_candidates: 0,
                scopes: 2,
            },
        };
        let v = serde_json::to_value(CheckinRequest {
            agent_version: "9.9.9",
            ml_coverage: Some(coverage),
        })
        .unwrap();

        // The camelCase field names the console will read.
        assert_eq!(v["mlCoverage"]["cache"]["hmacFailures"], 3);
        assert_eq!(v["mlCoverage"]["cache"]["bytesOnDisk"], 7_654_321);
        assert_eq!(v["mlCoverage"]["queue"]["readsDenied"], 0);
        assert_eq!(v["mlCoverage"]["queue"]["dropped"], 7);
        assert_eq!(v["mlCoverage"]["discovery"]["filesCovered"], 41_207);
        assert_eq!(v["mlCoverage"]["discovery"]["coversCurrentModel"], true);
        assert_eq!(v["mlCoverage"]["denyUnclassified"], false);

        // And NOTHING else that is a string. Two build identifiers, no more:
        // a path or a file name reaching the server would be a data-residency
        // bug, not a formatting one.
        let mut strings = Vec::new();
        collect_strings(&v, &mut strings);
        strings.sort();
        assert_eq!(strings, vec!["9.9.9", "V6.2.01"]);
    }

    fn collect_strings(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::String(s) => out.push(s.clone()),
            serde_json::Value::Array(a) => a.iter().for_each(|x| collect_strings(x, out)),
            serde_json::Value::Object(o) => o.values().for_each(|x| collect_strings(x, out)),
            _ => {}
        }
    }
}
