//! mTLS HTTP clients. Both pin ONLY our CA (system roots disabled), so the
//! agent will refuse to talk to anything not signed by the customer's own CA —
//! no counterfeit console, and it works fully offline.
use anyhow::{Context, Result};
use reqwest::blocking::Client;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(30);

/// For enrollment: verifies the server (CA-pinned) but presents NO client
/// certificate — the agent doesn't have one yet.
pub fn enroll_client(ca_pem: &[u8]) -> Result<Client> {
    let ca = reqwest::Certificate::from_pem(ca_pem).context("parsing CA certificate")?;
    Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .timeout(TIMEOUT)
        .build()
        .context("building enrollment client")
}

/// For check-in: full mutual TLS — verifies the server (CA-pinned) AND presents
/// the agent's own certificate.
pub fn checkin_client(ca_pem: &[u8], identity_pem: &[u8]) -> Result<Client> {
    let ca = reqwest::Certificate::from_pem(ca_pem).context("parsing CA certificate")?;
    let identity =
        reqwest::Identity::from_pem(identity_pem).context("loading agent client identity")?;
    Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .identity(identity)
        .timeout(TIMEOUT)
        .build()
        .context("building check-in client")
}
