//! The `.dlpenc` envelope — exact wire format from
//! ENCRYPT-ON-WRITE-IMPLEMENTATION.md §4. Pure functions over byte slices;
//! no I/O in this file; golden-vector tested in tests/crypto_envelope.rs.
//!
//! ```text
//! offset   size  field
//! 0        4     magic = "DLPE"
//! 4        1     version = 0x01
//! 5        2     header_len (u16 LE) = H
//! 7        H     header: canonical JSON (serde_json to_vec of EnvelopeHeader —
//!                field order fixed by struct definition; no floats)
//! 7+H      12    nonce (96-bit, OS CSPRNG, unique per file)
//! 7+H+12   C     ciphertext = AES-256-GCM(key=DEK, nonce, plaintext,
//!                aad = bytes[0 .. 7+H])   ← magic+version+len+header are ALL
//! 7+H+12+C 16    GCM tag                    authenticated; tamper ⇒ open fails
//! ```
//!
//! Keys: a fresh random 256-bit DEK per file encrypts the body; the DEK is
//! wrapped by the KEK with AES-256-GCM under its own 96-bit nonce (spec §10:
//! GCM, not AES-KW — one primitive in the whole feature) and travels base64'd
//! inside the header. DEK buffers are zeroized on drop.
//!
//! Randomness is injected behind [`EnvelopeRng`]; [`seal`] uses the OS CSPRNG
//! ([`OsEnvelopeRng`]), tests use a scripted RNG via [`seal_with_rng`]. The
//! draw order is part of the golden-vector contract: DEK (32 bytes), then the
//! DEK-wrap nonce (12), then the body nonce (12). The clock is the `now_unix`
//! parameter — never read inside this module.
//!
//! Errors are ONE typed enum, [`EnvelopeError`] — never `anyhow` here: callers
//! (decrypt subcommand, USB auditor, browser host) must distinguish
//! `WrongKey` / `Tampered` / `Malformed` / `KeyDestroyed` to raise the right
//! incident. No variant ever carries key material or plaintext.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::keyring::{Kek, Keyring};

/// File magic — the first four bytes of every `.dlpenc` envelope.
pub const MAGIC: [u8; 4] = *b"DLPE";
/// Envelope format version this module writes and the only one it reads.
pub const VERSION: u8 = 0x01;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// wrapped_dek = GCM(32-byte DEK) = 32 + 16-byte tag.
const WRAPPED_DEK_LEN: usize = 32 + TAG_LEN;
/// magic(4) + version(1) + header_len(2).
const PREFIX_LEN: usize = 7;

/// The authenticated envelope header. Serialized as canonical JSON — field
/// order is the struct-definition order below and is golden-vector locked;
/// camelCase matches the wire conventions in `detect/verdict.rs`. Contains no
/// plaintext and no unwrapped key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeHeader {
    /// KEK id/version, e.g. `"class-internal/v1"` — the crypto-shred unit.
    /// FREE-FORM opaque string: never parse it anywhere.
    pub key_id: String,
    /// base64: AES-256-GCM(KEK, dek_nonce, DEK).
    pub wrapped_dek: String,
    /// base64: the 96-bit nonce used to wrap the DEK.
    pub dek_nonce: String,
    /// Agent id (from identity.rs), NOT hostname.
    pub origin_agent: String,
    /// Seal time, injected by the caller (unix seconds).
    pub created_unix: u64,
    /// hex SHA-256 of the plaintext — correlates with `UsbIncident.file_sha256`.
    pub plaintext_sha256: String,
    /// Original filename (name only, no path) — survives renames because the
    /// header is authenticated.
    pub orig_name: String,
}

/// Every way sealing or opening can fail. Distinct variants because channels
/// map them to distinct incidents (`DecryptDenied` vs tamper evidence vs
/// operator error). `Malformed` carries a short static reason — one per
/// structural failure mode — so tests pin each tamper case exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Structural rot before any crypto ran: `"truncated"`, `"magic"`,
    /// `"version"`, `"header-len-overflow"`, `"header-json"`,
    /// `"header-field"` (bad base64 / wrong nonce or wrapped-DEK length).
    Malformed(&'static str),
    /// The keyring holds this key id but GCM refused to unwrap the DEK —
    /// wrong KEK bytes (or a corrupted wrappedDek field).
    WrongKey,
    /// DEK unwrapped fine but body authentication failed — ciphertext, tag,
    /// or any authenticated prefix byte (incl. the header) was modified.
    Tampered,
    /// The keyring has never seen this key id (foreign media / not yet synced).
    UnknownKeyId(String),
    /// The key id was crypto-shredded; this envelope is permanently
    /// unopenable. Surfaced as a `DecryptDenied` incident by callers.
    KeyDestroyed(String),
    /// seal-side: the serialized header does not fit the u16 length field.
    HeaderTooLarge,
    /// seal-side internal cipher failure (practically unreachable; kept so no
    /// path can panic).
    SealFailed,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeError::Malformed(what) => write!(f, "malformed envelope ({what})"),
            EnvelopeError::WrongKey => write!(f, "wrong key: DEK unwrap failed"),
            EnvelopeError::Tampered => write!(f, "authentication failed: envelope tampered or truncated"),
            EnvelopeError::UnknownKeyId(id) => write!(f, "unknown key id: {id}"),
            EnvelopeError::KeyDestroyed(id) => write!(f, "key destroyed (crypto-shredded): {id}"),
            EnvelopeError::HeaderTooLarge => write!(f, "envelope header exceeds u16 length field"),
            EnvelopeError::SealFailed => write!(f, "internal seal failure"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Injected randomness source. Production uses [`OsEnvelopeRng`]; golden-vector
/// tests script the bytes. Implementations MUST fill the whole buffer with
/// cryptographically strong bytes (test doubles excepted).
pub trait EnvelopeRng {
    fn fill(&mut self, buf: &mut [u8]);
}

/// The OS CSPRNG (`aes_gcm::aead::OsRng`, i.e. getrandom) — the only RNG that
/// may ever back [`seal`] in production.
pub struct OsEnvelopeRng;

impl EnvelopeRng for OsEnvelopeRng {
    fn fill(&mut self, buf: &mut [u8]) {
        use aes_gcm::aead::rand_core::RngCore;
        aes_gcm::aead::OsRng.fill_bytes(buf);
    }
}

/// Seal `plaintext` into a `.dlpenc` envelope under `key` (production RNG).
///
/// `now_unix` is injected (house style; keeps golden vectors deterministic).
/// `orig_name` should be the file name only — no path components.
pub fn seal(
    plaintext: &[u8],
    orig_name: &str,
    key: &Kek,
    agent_id: &str,
    now_unix: u64,
) -> Result<Vec<u8>, EnvelopeError> {
    seal_with_rng(&mut OsEnvelopeRng, plaintext, orig_name, key, agent_id, now_unix)
}

/// [`seal`] with an injected RNG. Draw order (golden-vector contract):
/// DEK (32 bytes) → DEK-wrap nonce (12) → body nonce (12).
pub fn seal_with_rng(
    rng: &mut dyn EnvelopeRng,
    plaintext: &[u8],
    orig_name: &str,
    key: &Kek,
    agent_id: &str,
    now_unix: u64,
) -> Result<Vec<u8>, EnvelopeError> {
    // Fresh per-file DEK, scrubbed on every exit path.
    let mut dek = Zeroizing::new([0u8; 32]);
    rng.fill(dek.as_mut());
    let mut dek_nonce = [0u8; NONCE_LEN];
    rng.fill(&mut dek_nonce);
    let mut body_nonce = [0u8; NONCE_LEN];
    rng.fill(&mut body_nonce);

    // Wrap the DEK under the KEK (own nonce, no AAD — the header that carries
    // it is authenticated by the BODY's AAD instead).
    let kek_cipher =
        Aes256Gcm::new_from_slice(key.bytes()).map_err(|_| EnvelopeError::SealFailed)?;
    let wrapped_dek = kek_cipher
        .encrypt(Nonce::from_slice(&dek_nonce), dek.as_slice())
        .map_err(|_| EnvelopeError::SealFailed)?;

    let header = EnvelopeHeader {
        key_id: key.id().to_string(),
        wrapped_dek: B64.encode(&wrapped_dek),
        dek_nonce: B64.encode(dek_nonce),
        origin_agent: agent_id.to_string(),
        created_unix: now_unix,
        plaintext_sha256: hex(&Sha256::digest(plaintext)),
        orig_name: orig_name.to_string(),
    };
    let header_bytes = serde_json::to_vec(&header).map_err(|_| EnvelopeError::SealFailed)?;
    let header_len: u16 = header_bytes
        .len()
        .try_into()
        .map_err(|_| EnvelopeError::HeaderTooLarge)?;

    let mut out =
        Vec::with_capacity(PREFIX_LEN + header_bytes.len() + NONCE_LEN + plaintext.len() + TAG_LEN);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&header_len.to_le_bytes());
    out.extend_from_slice(&header_bytes);

    // Body: everything before the nonce is AAD, so magic, version, length and
    // header are all authenticated.
    let body_cipher = Aes256Gcm::new_from_slice(dek.as_ref()).map_err(|_| EnvelopeError::SealFailed)?;
    let ciphertext_and_tag = body_cipher
        .encrypt(
            Nonce::from_slice(&body_nonce),
            Payload { msg: plaintext, aad: &out },
        )
        .map_err(|_| EnvelopeError::SealFailed)?;

    out.extend_from_slice(&body_nonce);
    out.extend_from_slice(&ciphertext_and_tag);
    Ok(out)
}

/// Open a `.dlpenc` envelope with the locally cached keyring — offline by
/// design, no server round-trip ever. Returns the authenticated header and
/// the plaintext. Nothing is returned unless the FULL envelope authenticates.
pub fn open(envelope: &[u8], keyring: &Keyring) -> Result<(EnvelopeHeader, Vec<u8>), EnvelopeError> {
    let parsed = parse(envelope)?;
    let kek = keyring.lookup(&parsed.header.key_id)?;

    let wrapped_dek = B64
        .decode(&parsed.header.wrapped_dek)
        .map_err(|_| EnvelopeError::Malformed("header-field"))?;
    let dek_nonce = B64
        .decode(&parsed.header.dek_nonce)
        .map_err(|_| EnvelopeError::Malformed("header-field"))?;
    if wrapped_dek.len() != WRAPPED_DEK_LEN || dek_nonce.len() != NONCE_LEN {
        return Err(EnvelopeError::Malformed("header-field"));
    }

    let kek_cipher =
        Aes256Gcm::new_from_slice(kek.bytes()).map_err(|_| EnvelopeError::WrongKey)?;
    let dek = Zeroizing::new(
        kek_cipher
            .decrypt(Nonce::from_slice(&dek_nonce), wrapped_dek.as_slice())
            .map_err(|_| EnvelopeError::WrongKey)?,
    );
    if dek.len() != 32 {
        return Err(EnvelopeError::WrongKey);
    }

    let body_cipher =
        Aes256Gcm::new_from_slice(&dek).map_err(|_| EnvelopeError::WrongKey)?;
    let plaintext = body_cipher
        .decrypt(
            Nonce::from_slice(parsed.nonce),
            Payload { msg: parsed.ciphertext_and_tag, aad: parsed.aad },
        )
        .map_err(|_| EnvelopeError::Tampered)?;

    Ok((parsed.header, plaintext))
}

/// Read the (structurally validated) header without any key material — used
/// by the decrypt subcommand to find the key id and by incident enrichment.
/// NOTE: without a successful [`open`] the header is NOT yet authenticated;
/// treat peeked values as claims, not facts.
pub fn peek_header(envelope: &[u8]) -> Result<EnvelopeHeader, EnvelopeError> {
    Ok(parse(envelope)?.header)
}

struct Parsed<'a> {
    header: EnvelopeHeader,
    /// bytes[0 .. 7+H] — the authenticated prefix.
    aad: &'a [u8],
    nonce: &'a [u8],
    ciphertext_and_tag: &'a [u8],
}

fn parse(envelope: &[u8]) -> Result<Parsed<'_>, EnvelopeError> {
    if envelope.len() < PREFIX_LEN {
        return Err(EnvelopeError::Malformed("truncated"));
    }
    if envelope[0..4] != MAGIC {
        return Err(EnvelopeError::Malformed("magic"));
    }
    if envelope[4] != VERSION {
        return Err(EnvelopeError::Malformed("version"));
    }
    let header_len = u16::from_le_bytes([envelope[5], envelope[6]]) as usize;
    let header_end = PREFIX_LEN + header_len; // max 7 + 65535: cannot overflow usize
    if header_end > envelope.len() {
        return Err(EnvelopeError::Malformed("header-len-overflow"));
    }
    let header: EnvelopeHeader = serde_json::from_slice(&envelope[PREFIX_LEN..header_end])
        .map_err(|_| EnvelopeError::Malformed("header-json"))?;
    if envelope.len() < header_end + NONCE_LEN + TAG_LEN {
        return Err(EnvelopeError::Malformed("truncated"));
    }
    Ok(Parsed {
        header,
        aad: &envelope[..header_end],
        nonce: &envelope[header_end..header_end + NONCE_LEN],
        ciphertext_and_tag: &envelope[header_end + NONCE_LEN..],
    })
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}
