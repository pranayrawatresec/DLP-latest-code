//! Enrollment: the one-time handshake that turns an unknown PC into a trusted
//! agent. Generate a key + CSR locally, present the one-time token, receive a
//! CA-signed certificate. The private key never leaves this machine.
use crate::{client, config::Config, identity, storage::{AgentMeta, Storage}};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct EnrollRequest<'a> {
    token: &'a str,
    #[serde(rename = "csrPem")]
    csr_pem: &'a str,
    hostname: &'a str,
    os: &'a str,
    #[serde(rename = "agentVersion")]
    agent_version: &'a str,
}

#[derive(Deserialize)]
struct EnrollResponse {
    #[serde(rename = "agentId")]
    agent_id: String,
    certificate: String,
    ca: String,
    #[serde(rename = "checkinIntervalSeconds")]
    checkin_interval_seconds: u64,
}

pub fn enroll(cfg: &Config, storage: &Storage) -> Result<AgentMeta> {
    let token = cfg
        .enrollment_token
        .as_deref()
        .context("no enrollment token configured — cannot enroll")?;
    let hostname = crate::hostname();
    let os = std::env::consts::OS;
    let version = env!("CARGO_PKG_VERSION");

    tracing::info!("generating key pair + CSR (private key stays local)");
    let key = identity::generate(&hostname).context("generating identity")?;

    // CA pinned from the installer — the server is verified even on this first
    // connection.
    let ca_pem = std::fs::read(&cfg.ca_cert_path)
        .with_context(|| format!("reading pinned CA {}", cfg.ca_cert_path.display()))?;
    let client = client::enroll_client(&ca_pem)?;

    tracing::info!(url = %cfg.enroll_url(), "enrolling");
    let resp = client
        .post(cfg.enroll_url())
        .json(&EnrollRequest {
            token,
            csr_pem: &key.csr_pem,
            hostname: &hostname,
            os,
            agent_version: version,
        })
        .send()
        .context("enrollment request failed (server unreachable?)")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        bail!("enrollment rejected [{status}]: {body}");
    }
    let er: EnrollResponse = resp.json().context("parsing enrollment response")?;

    // Persist: identity bundle = private key PEM + issued cert PEM. The CA
    // returned here becomes the trust anchor for all future check-ins.
    let identity_pem = format!("{}{}", key.private_key_pem, er.certificate);
    let meta = AgentMeta {
        agent_id: er.agent_id.clone(),
        checkin_interval_seconds: er.checkin_interval_seconds,
    };
    storage
        .save_identity(&identity_pem, &er.ca, &meta)
        .context("saving enrolled identity")?;

    tracing::info!(agent_id = %er.agent_id, "enrolled — certificate stored and sealed");
    Ok(meta)
}
