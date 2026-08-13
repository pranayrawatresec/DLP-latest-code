//! KEKs and the agent-side keyring (spec §4.1).
//!
//! Hierarchy: ORK (server-side only, never here) → KEK per classification,
//! e.g. `"class-internal/v1"` → per-file DEK (lives only inside the envelope
//! header). This module holds ONLY the middle layer: [`Kek`] (32 bytes,
//! zeroized on drop) and [`Keyring`] (id → KEK map + active id + destroyed
//! set).
//!
//! Key ids are FREE-FORM opaque strings (project decision): they are map keys
//! and audit-log values, NEVER parsed — no splitting on `/`, no version
//! extraction, anywhere, ever.
//!
//! Offline by design: sealing and opening use this in-memory ring — the hot
//! path never talks to the server. Rotation/revocation lands at check-in (M6)
//! with bounded staleness.
//!
//! Destruction (crypto-shredding) is terminal and single-person sysadmin-only
//! in v1 (project decision overriding the spec's two-person flow) — but
//! [`Keyring::destroy`] is deliberately the ONLY mutation that can retire a
//! key, so a later confirm step wraps this one choke point without reshaping
//! the API. Heavy auditing of destroys is the caller's duty (M4/M6); this
//! module is pure and writes no logs (and must never log key material).
//!
//! Persistence at rest via DPAPI (machine scope) is milestone **M4**, not
//! here. Until then, [`Keyring::load_dev_keyfile`] reads a **PLAINTEXT dev
//! keyfile** — ⚠ DEV ONLY: the file holds raw KEKs base64'd, must be
//! git-ignored, and must never ship in a production deployment.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::envelope::EnvelopeError;

/// A key-encryption key: free-form id + 32 secret bytes. The bytes (and the
/// id) are zeroized when the value drops. `Debug` never prints key material.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Kek {
    id: String,
    key: [u8; 32],
}

impl Kek {
    pub fn new(id: impl Into<String>, key: [u8; 32]) -> Self {
        Kek { id: id.into(), key }
    }

    /// The free-form key id (opaque — never parse it).
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Raw key bytes — crate-internal so key material cannot leak past the
    /// crypto module's API surface.
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl std::fmt::Debug for Kek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // House rule 2: never log key material.
        f.debug_struct("Kek")
            .field("id", &self.id)
            .field("key", &"<32 bytes redacted>")
            .finish()
    }
}

/// Typed keyring/keyfile errors — no `anyhow` in the crypto core. Variants
/// carry ids and lengths only, never key bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyringError {
    /// Reading the keyfile failed (message from std::io, path not included
    /// to keep the variant comparable in tests).
    Io(String),
    /// The keyfile is not the expected JSON shape.
    Parse(String),
    /// A key decoded to something other than 32 bytes.
    BadKeyLength { key_id: String, len: usize },
    /// `activeKeyId` names a key that is absent (or listed as destroyed).
    MissingActive(String),
}

impl std::fmt::Display for KeyringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyringError::Io(e) => write!(f, "keyfile read failed: {e}"),
            KeyringError::Parse(e) => write!(f, "keyfile parse failed: {e}"),
            KeyringError::BadKeyLength { key_id, len } => {
                write!(f, "key {key_id:?} decodes to {len} bytes, expected 32")
            }
            KeyringError::MissingActive(id) => {
                write!(f, "active key id {id:?} not present (or destroyed) in keyfile")
            }
        }
    }
}

impl std::error::Error for KeyringError {}

/// In-memory keyring: every KEK this agent may seal/open with, which one new
/// seals use, and which ids have been crypto-shredded.
pub struct Keyring {
    keys: HashMap<String, Kek>,
    /// Ids that were destroyed — kept forever so lookups fail `KeyDestroyed`
    /// (signal: someone holds old media) instead of `UnknownKeyId`, and so a
    /// destroyed key can never be resurrected by a stale sync (fail secure).
    destroyed: BTreeSet<String>,
    active_key_id: String,
}

impl Keyring {
    pub fn new(active_key_id: impl Into<String>) -> Self {
        Keyring {
            keys: HashMap::new(),
            destroyed: BTreeSet::new(),
            active_key_id: active_key_id.into(),
        }
    }

    /// Insert (or replace) a KEK under its own id. Silently refuses to
    /// resurrect a destroyed id — destruction is terminal.
    pub fn insert(&mut self, kek: Kek) {
        if self.destroyed.contains(kek.id()) {
            return;
        }
        self.keys.insert(kek.id().to_string(), kek);
    }

    /// Resolve a key id for `open`. Destroyed wins over present (fail secure).
    pub fn lookup(&self, key_id: &str) -> Result<&Kek, EnvelopeError> {
        if self.destroyed.contains(key_id) {
            return Err(EnvelopeError::KeyDestroyed(key_id.to_string()));
        }
        self.keys
            .get(key_id)
            .ok_or_else(|| EnvelopeError::UnknownKeyId(key_id.to_string()))
    }

    /// The id new seals should use.
    pub fn active_key_id(&self) -> &str {
        &self.active_key_id
    }

    /// The KEK new seals should use.
    pub fn active(&self) -> Result<&Kek, EnvelopeError> {
        self.lookup(&self.active_key_id)
    }

    /// Point new seals at a different (held, not destroyed) key.
    pub fn set_active(&mut self, key_id: &str) -> Result<(), EnvelopeError> {
        self.lookup(key_id)?;
        self.active_key_id = key_id.to_string();
        Ok(())
    }

    /// Crypto-shred a key: drop the bytes (zeroized on drop) and remember the
    /// id as destroyed forever. Returns whether the key was actually held.
    ///
    /// v1: single-person, sysadmin-only, invoked by the server-driven sync or
    /// an admin action — heavy audit entries are the CALLER's obligation
    /// before calling this. This is the single choke point a future
    /// two-person confirm step will wrap.
    pub fn destroy(&mut self, key_id: &str) -> bool {
        let held = self.keys.remove(key_id).is_some(); // Kek drop zeroizes
        self.destroyed.insert(key_id.to_string());
        held
    }

    /// ⚠ DEV ONLY (until M6 server sync / M4 DPAPI-at-rest land): load a
    /// PLAINTEXT JSON keyfile. Format (camelCase, matching wire conventions):
    ///
    /// ```json
    /// {
    ///   "activeKeyId": "class-internal/v1",
    ///   "keys": { "class-internal/v1": "<base64 of exactly 32 bytes>" },
    ///   "destroyed": ["class-old/v1"]
    /// }
    /// ```
    ///
    /// The file contains raw KEKs — it must be git-ignored and never deployed.
    pub fn load_dev_keyfile(path: &Path) -> Result<Keyring, KeyringError> {
        let bytes = zeroize::Zeroizing::new(
            std::fs::read(path).map_err(|e| KeyringError::Io(e.to_string()))?,
        );
        Self::from_dev_json(&bytes)
    }

    /// Parse the dev keyfile format from bytes (separated for tests).
    pub fn from_dev_json(bytes: &[u8]) -> Result<Keyring, KeyringError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct DevKeyfile {
            active_key_id: String,
            keys: HashMap<String, String>,
            #[serde(default)]
            destroyed: Vec<String>,
        }

        let parsed: DevKeyfile =
            serde_json::from_slice(bytes).map_err(|e| KeyringError::Parse(e.to_string()))?;

        let mut ring = Keyring::new(parsed.active_key_id.clone());
        for id in parsed.destroyed {
            ring.destroyed.insert(id);
        }
        for (id, mut b64) in parsed.keys {
            let mut raw = B64
                .decode(&b64)
                .map_err(|e| KeyringError::Parse(format!("key {id:?}: {e}")))?;
            b64.zeroize();
            if raw.len() != 32 {
                let len = raw.len();
                raw.zeroize();
                return Err(KeyringError::BadKeyLength { key_id: id, len });
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&raw);
            raw.zeroize();
            ring.insert(Kek::new(id, key)); // insert() drops keys listed destroyed
            key.zeroize();
        }

        // Fail secure: refuse a ring whose active key cannot actually seal.
        if ring.lookup(&parsed.active_key_id).is_err() {
            return Err(KeyringError::MissingActive(parsed.active_key_id));
        }
        Ok(ring)
    }
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Ids only — never key material.
        let mut ids: Vec<&str> = self.keys.keys().map(String::as_str).collect();
        ids.sort_unstable();
        f.debug_struct("Keyring")
            .field("active_key_id", &self.active_key_id)
            .field("key_ids", &ids)
            .field("destroyed", &self.destroyed)
            .finish()
    }
}
