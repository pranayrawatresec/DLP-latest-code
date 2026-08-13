//! Decrypt path for `.dlpenc` envelopes — encrypt-on-write spec §5.3 (M4).
//!
//! Library core of the `dlp-agent decrypt` subcommand, kept pure so tests can
//! drive it end-to-end without a server, a queue, or a filesystem: the audit
//! sink and the plaintext writer are BOTH injected. The binary (main.rs) wires
//! the real ones (mTLS post → bounded on-disk queue fallback; `std::fs::write`).
//!
//! Contract (spec §5.3, plus project decisions):
//! * **Audit BEFORE plaintext.** The `channel = "decrypt"` incident — key id,
//!   plaintext hash, agent id, outcome — is handed to the sink FIRST; if the
//!   sink errors, the plaintext is NEVER written ([`DecryptError::AuditFailed`],
//!   fail secure: no un-audited decrypt exists).
//! * **Offline by design.** The only key source is the locally cached
//!   [`Keyring`] — no server round-trip, matching cached-policy semantics.
//! * **Unknown/destroyed keys deny with signal.** Any [`EnvelopeError`] raises
//!   an [`IncidentKind::DecryptDenied`] incident (best effort) and surfaces as
//!   the typed [`DecryptError::Envelope`] — the caller exits non-zero with
//!   nothing written. `KeyDestroyed` stays distinct from `UnknownKeyId`
//!   (crypto-shredded media vs foreign media — both are signal, UC-5).
//! * **No content, no keys, in any record.** Incidents carry hashes, ids and
//!   outcome labels only; this module writes no logs of its own beyond a
//!   metadata-only warn when a denial incident could not be recorded.
//!
//! Key ids remain FREE-FORM opaque strings — copied into incidents, never
//! parsed (project decision).

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::envelope::{self, EnvelopeError, EnvelopeHeader};
use crate::crypto::Keyring;
use crate::detect::{Extraction, Verdict};
use crate::usb::{ActionTaken, DeviceIdentity, IncidentKind, UsbIncident};

/// The incident channel every decrypt audit uses (spec §5.3).
pub const CHANNEL: &str = "decrypt";

/// Why a decrypt did not produce a plaintext file. Typed — the binary maps
/// each variant to a distinct message and ALL of them to a non-zero exit.
#[derive(Debug)]
pub enum DecryptError {
    /// The envelope refused to open (unknown/destroyed key, tampered,
    /// wrong key, malformed…). A `DecryptDenied` incident was raised
    /// (best effort) before this was returned; nothing was written.
    Envelope(EnvelopeError),
    /// The decrypt succeeded but the audit incident could NOT be recorded —
    /// the plaintext was NOT written (fail secure: no un-audited decrypt).
    AuditFailed(anyhow::Error),
    /// Audited fine, but writing the plaintext failed. The audit record
    /// exists; the caller reports the write failure.
    WriteFailed(anyhow::Error),
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecryptError::Envelope(e) => write!(f, "decrypt denied: {e}"),
            DecryptError::AuditFailed(e) => write!(
                f,
                "decrypt aborted: audit incident could not be recorded ({e:#}); plaintext NOT written (fail secure)"
            ),
            DecryptError::WriteFailed(e) => write!(f, "plaintext write failed: {e:#}"),
        }
    }
}

impl std::error::Error for DecryptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DecryptError::Envelope(e) => Some(e),
            _ => None,
        }
    }
}

/// What a successful decrypt produced — metadata only, never the plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptSummary {
    /// The authenticated envelope header (origin agent, orig name, key id…).
    pub header: EnvelopeHeader,
    /// Plaintext size in bytes.
    pub plaintext_len: usize,
    /// hex SHA-256 of the recovered plaintext, computed from the actual bytes
    /// (matches the authenticated header's `plaintextSha256`).
    pub plaintext_sha256: String,
}

/// Open `envelope_bytes` with the cached `keyring` and hand the plaintext to
/// `write` — but only AFTER the audit incident has been accepted by `audit`.
///
/// Order of operations (spec §5.3, machine-verified in tests/decrypt_path.rs):
/// 1. `open()` — full envelope authentication; any failure ⇒ a
///    `DecryptDenied` incident (best effort) + [`DecryptError::Envelope`],
///    `write` never called.
/// 2. `audit(&incident)` with the `Decrypted` incident — an `Err` here means
///    the caller could neither post NOR queue the record: the plaintext is
///    dropped (zeroized), `write` never called ([`DecryptError::AuditFailed`]).
/// 3. `write(&header, &plaintext)`.
///
/// `agent_id` is the DECRYPTING agent (from identity.rs; the header's
/// `origin_agent` is the sealer) and lands in the incident note; both ids are
/// metadata, never credentials.
pub fn decrypt_envelope<A, W>(
    envelope_bytes: &[u8],
    envelope_name: &str,
    keyring: &Keyring,
    agent_id: &str,
    mut audit: A,
    write: W,
) -> Result<DecryptSummary, DecryptError>
where
    A: FnMut(&UsbIncident) -> anyhow::Result<()>,
    W: FnOnce(&EnvelopeHeader, &[u8]) -> anyhow::Result<()>,
{
    // Identifies the exact envelope in both outcomes' incidents.
    let envelope_sha256 = hex(&Sha256::digest(envelope_bytes));
    // Key id CLAIM for denial incidents. peek_header is unauthenticated —
    // a claim, not a fact (its doc says so) — but a denied open has nothing
    // stronger, and the claimed id is precisely the signal a reviewer needs.
    let claimed_key_id = envelope::peek_header(envelope_bytes).ok().map(|h| h.key_id);

    match envelope::open(envelope_bytes, keyring) {
        Err(e) => {
            let inc = denied_incident(
                envelope_name,
                claimed_key_id,
                &envelope_sha256,
                agent_id,
                &e,
            );
            // Best effort: the denial stands (nothing was written) whether or
            // not the record lands; the sink already queues offline, so a
            // failure here is exceptional and worth a metadata-only warn.
            if let Err(audit_err) = audit(&inc) {
                tracing::warn!(error = %audit_err, "decrypt-denied incident could not be recorded");
            }
            Err(DecryptError::Envelope(e))
        }
        Ok((header, plaintext)) => {
            // Scrubbed on every exit path from here on.
            let plaintext = Zeroizing::new(plaintext);
            let plaintext_sha256 = hex(&Sha256::digest(plaintext.as_slice()));
            let inc = decrypted_incident(&header, &plaintext_sha256, &envelope_sha256, agent_id);

            // Audit FIRST (spec §5.3). No record ⇒ no plaintext (fail secure).
            audit(&inc).map_err(DecryptError::AuditFailed)?;
            write(&header, &plaintext).map_err(DecryptError::WriteFailed)?;

            Ok(DecryptSummary {
                plaintext_len: plaintext.len(),
                plaintext_sha256,
                header,
            })
        }
    }
}

/// Stable machine label for a denial cause (lands in the incident note).
fn denial_label(e: &EnvelopeError) -> &'static str {
    match e {
        EnvelopeError::UnknownKeyId(_) => "unknown-key-id",
        EnvelopeError::KeyDestroyed(_) => "key-destroyed",
        EnvelopeError::WrongKey => "wrong-key",
        EnvelopeError::Tampered => "tampered",
        EnvelopeError::Malformed(_) => "malformed",
        // seal-side variants — unreachable from open(), kept total so no
        // future variant can panic this path.
        EnvelopeError::HeaderTooLarge | EnvelopeError::SealFailed => "internal",
    }
}

/// The decrypt path has no device — a fixed placeholder identity keeps the
/// shared `UsbIncident` shape (and its wire body) without inventing one.
fn no_device() -> DeviceIdentity {
    DeviceIdentity {
        drive_letter: String::new(),
        vendor_id: String::new(),
        product_id: String::new(),
        serial: String::new(),
        product_name: "local-decrypt".into(),
        bus_type: String::new(),
        removable: false,
    }
}

/// Minimal verdict wrapper so decrypt incidents ride the existing wire body
/// (spec §4 subset: channel/fileName/fileSha256/verdict). No detection ran —
/// idm/edm stay empty; the "format" records what was inspected: an envelope.
fn wire_verdict(file_name: &str, file_sha256: &str) -> Verdict {
    Verdict {
        file_name: file_name.to_string(),
        file_sha256: file_sha256.to_string(),
        extraction: Extraction::Ok { format: "dlpenc".into() },
        idm: Vec::new(),
        edm: Vec::new(),
    }
}

fn decrypted_incident(
    header: &EnvelopeHeader,
    plaintext_sha256: &str,
    envelope_sha256: &str,
    agent_id: &str,
) -> UsbIncident {
    UsbIncident {
        kind: IncidentKind::Decrypted,
        channel: CHANNEL.into(),
        file_name: header.orig_name.clone(),
        file_sha256: plaintext_sha256.to_string(),
        verdict: Some(wire_verdict(&header.orig_name, plaintext_sha256)),
        device: no_device(),
        action_taken: ActionTaken::Audited,
        // Metadata only: who decrypted, who sealed, when it was sealed.
        note: Some(format!(
            "decrypted agent={agent_id} origin={} sealed-at={}",
            header.origin_agent, header.created_unix
        )),
        key_id: Some(header.key_id.clone()),
        sealed_sha256: Some(envelope_sha256.to_string()),
    }
}

fn denied_incident(
    envelope_name: &str,
    claimed_key_id: Option<String>,
    envelope_sha256: &str,
    agent_id: &str,
    e: &EnvelopeError,
) -> UsbIncident {
    UsbIncident {
        kind: IncidentKind::DecryptDenied,
        channel: CHANNEL.into(),
        file_name: envelope_name.to_string(),
        // No authenticated plaintext hash exists on a denial.
        file_sha256: String::new(),
        verdict: Some(wire_verdict(envelope_name, "")),
        device: no_device(),
        action_taken: ActionTaken::Blocked,
        note: Some(format!("decrypt-denied({}) agent={agent_id}", denial_label(e))),
        key_id: claimed_key_id,
        sealed_sha256: Some(envelope_sha256.to_string()),
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
