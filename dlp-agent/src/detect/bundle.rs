//! Signed index bundle loader — byte-exact port of the normative format in
//! dlp-management-server/docs/index-bundle-format.md (`DLPX1`, format v1).
//!
//! FAIL CLOSED: the RSASSA-PKCS1-v1_5 / SHA-256 signature is verified against
//! the pinned CA certificate BEFORE any parsed value is trusted, and ANY
//! structural inconsistency (bad magic, truncation, unsorted sections,
//! out-of-range indexes, count mismatches, trailing bytes, foreign matcher
//! parameters) rejects the whole file. Callers must keep using their previous
//! verified bundle when this loader returns an error.
//!
//! Hashes are stored as signed i64 (the server's BIGINT convention) but are
//! always COMPARED, SORTED and bloom-keyed as unsigned u64 — same duality as
//! shingle.rs / the server's lib/indexBundle.js.

use anyhow::{anyhow, Context, Result};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use serde::Deserialize;
use sha2::Sha256;
use std::collections::BTreeMap;
use x509_cert::der::{DecodePem, Encode};

use super::shingle::{DEFAULT_K, DEFAULT_W};

pub const MAGIC: &[u8; 5] = b"DLPX1";
pub const FORMAT_VERSION: u16 = 1;

// ---------------------------------------------------------------------
// Header JSON (parsed as JSON — key order in the file is not guaranteed)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct Header {
    #[serde(rename = "bundleVersion")]
    pub bundle_version: u64,
    pub params: Params,
    #[serde(rename = "edmSalts", default)]
    pub edm_salts: BTreeMap<String, String>,
    #[serde(default)]
    pub scope: Vec<String>,
    pub counts: Counts,
    #[serde(default)]
    pub docs: Vec<Doc>,
    #[serde(rename = "edmSources", default)]
    pub edm_sources: Vec<EdmSource>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub struct Params {
    pub k: usize,
    pub w: usize,
    #[serde(rename = "hashBits")]
    pub hash_bits: u32,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub struct Counts {
    pub idm: usize,
    pub edm: usize,
    pub docs: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Doc {
    #[serde(rename = "versionId")]
    pub version_id: String,
    #[serde(rename = "documentId")]
    pub document_id: String,
    #[serde(rename = "collectionId")]
    pub collection_id: String,
    pub title: String,
    #[serde(rename = "fpCount")]
    pub fp_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EdmSource {
    #[serde(rename = "sourceId")]
    pub source_id: String,
    pub name: String,
    #[serde(default)]
    pub fields: Vec<EdmField>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EdmField {
    #[serde(rename = "fieldId")]
    pub field_id: u16,
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    #[serde(default)]
    pub primary: bool,
}

// ---------------------------------------------------------------------
// Binary sections
// ---------------------------------------------------------------------

/// One IDM record: a winnowed document fingerprint and the document (by
/// index into `header.docs`) that contains it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdmEntry {
    pub hash: i64,
    pub doc_index: u32,
}

/// One EDM record: a salted cell hash and where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdmEntry {
    pub hash: i64,
    pub source_index: u16,
    pub row_id: u32,
    pub field_id: u16,
}

#[derive(Debug, Clone)]
struct Bloom {
    m_bits: u32,
    k_hashes: u32,
    bits: Vec<u8>,
}

/// A fully verified, parsed bundle. Existence of this value implies the
/// signature checked out and every structural invariant held.
#[derive(Debug, Clone)]
pub struct Bundle {
    pub format_version: u16,
    pub header: Header,
    bloom: Bloom,
    idm: Vec<IdmEntry>,
    edm: Vec<EdmEntry>,
}

// ---------------------------------------------------------------------
// Bloom filter primitives (format contract — constants must not change)
// ---------------------------------------------------------------------

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a 64 over raw bytes (the bloom key), wrapping arithmetic.
fn fnv1a64_bytes(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET_BASIS;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// splitmix64 finalizer — exact constants from the format doc §3.2.
fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

impl Bloom {
    /// Kirsch–Mitzenmacher double hashing over the 8-byte LE key (§3.1–3.3).
    fn has(&self, hash: i64) -> bool {
        let key = (hash as u64).to_le_bytes();
        let h1 = fnv1a64_bytes(&key);
        let h2 = splitmix64(h1);
        for i in 0..u64::from(self.k_hashes) {
            let bit = h1.wrapping_add(i.wrapping_mul(h2)) % u64::from(self.m_bits);
            if self.bits[(bit >> 3) as usize] & (1 << (bit & 7)) == 0 {
                return false;
            }
        }
        true
    }
}

// ---------------------------------------------------------------------
// Byte reader (bounds-checked; every failure is a parse rejection)
// ---------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, off: 0 }
    }

    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8]> {
        let end = self
            .off
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(|| anyhow!("bundle parse error: truncated: {what}"))?;
        let out = &self.buf[self.off..end];
        self.off = end;
        Ok(out)
    }

    fn u16(&mut self, what: &str) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2, what)?.try_into().unwrap()))
    }

    fn u32(&mut self, what: &str) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4, what)?.try_into().unwrap()))
    }
}

// ---------------------------------------------------------------------
// Signature verification (RSASSA-PKCS1-v1_5 / SHA-256, CA public key)
// ---------------------------------------------------------------------

fn verify_signature(message: &[u8], signature: &[u8], ca_cert_pem: &[u8]) -> Result<()> {
    let cert =
        x509_cert::Certificate::from_pem(ca_cert_pem).context("parsing CA certificate")?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .context("encoding CA public key")?;
    let public_key =
        rsa::RsaPublicKey::from_public_key_der(&spki_der).context("CA public key is not RSA")?;
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public_key);
    let signature =
        rsa::pkcs1v15::Signature::try_from(signature).context("malformed signature")?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| anyhow!("bundle signature verification failed"))
}

// ---------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------

fn parse_err(msg: &str) -> anyhow::Error {
    anyhow!("bundle parse error: {msg}")
}

impl Bundle {
    /// Parse and verify a bundle file. The signature is checked over the raw
    /// bytes before any content (header JSON, entries) is interpreted; any
    /// failure rejects the whole file.
    pub fn load(bytes: &[u8], ca_cert_pem: &[u8]) -> Result<Bundle> {
        // Pass 1 — locate section boundaries from raw lengths only.
        let mut r = Reader::new(bytes);
        if r.take(MAGIC.len(), "magic")? != MAGIC {
            return Err(parse_err("bad magic"));
        }
        let format_version = r.u16("format version")?;
        if format_version != FORMAT_VERSION {
            return Err(parse_err(&format!(
                "unsupported format version {format_version}"
            )));
        }
        let header_len = r.u32("header length")? as usize;
        let header_bytes = r.take(header_len, "header")?;

        let m_bits = r.u32("bloom mBits")?;
        let k_hashes = r.u32("bloom kHashes")?;
        if m_bits < 8 || k_hashes < 1 || k_hashes > 64 {
            return Err(parse_err("bad bloom parameters"));
        }
        let bloom_bytes = r.take(m_bits as usize / 8 + usize::from(m_bits % 8 != 0), "bloom bits")?;

        let idm_count = r.u32("idm count")? as usize;
        let idm_bytes = r.take(
            idm_count.checked_mul(12).ok_or_else(|| parse_err("idm count overflow"))?,
            "idm entries",
        )?;
        let edm_count = r.u32("edm count")? as usize;
        let edm_bytes = r.take(
            edm_count.checked_mul(16).ok_or_else(|| parse_err("edm count overflow"))?,
            "edm entries",
        )?;

        let signed_end = r.off; // signature covers [0, signed_end)
        let sig_len = r.u32("signature length")? as usize;
        let signature = r.take(sig_len, "signature")?;
        if r.off != bytes.len() {
            return Err(parse_err("trailing bytes after signature"));
        }

        // Verify BEFORE trusting any parsed value (format doc §6).
        verify_signature(&bytes[..signed_end], signature, ca_cert_pem)?;

        // Pass 2 — interpret content, cross-checking every invariant.
        let header: Header =
            serde_json::from_slice(header_bytes).context("bundle header is not valid JSON")?;
        if header.params.k != DEFAULT_K
            || header.params.w != DEFAULT_W
            || header.params.hash_bits != 64
        {
            return Err(parse_err("bundle built with foreign matcher parameters"));
        }

        let mut idm = Vec::with_capacity(idm_count);
        let mut prev: Option<(u64, u32)> = None;
        for rec in idm_bytes.chunks_exact(12) {
            let hash = i64::from_le_bytes(rec[0..8].try_into().unwrap());
            let doc_index = u32::from_le_bytes(rec[8..12].try_into().unwrap());
            let key = (hash as u64, doc_index);
            if prev.is_some_and(|p| key <= p) {
                return Err(parse_err("idm section not sorted"));
            }
            prev = Some(key);
            if doc_index as usize >= header.docs.len() {
                return Err(parse_err("idm docIndex out of range"));
            }
            idm.push(IdmEntry { hash, doc_index });
        }

        let mut edm = Vec::with_capacity(edm_count);
        let mut prev: Option<(u64, u16, u32, u16)> = None;
        for rec in edm_bytes.chunks_exact(16) {
            let hash = i64::from_le_bytes(rec[0..8].try_into().unwrap());
            let source_index = u16::from_le_bytes(rec[8..10].try_into().unwrap());
            let row_id = u32::from_le_bytes(rec[10..14].try_into().unwrap());
            let field_id = u16::from_le_bytes(rec[14..16].try_into().unwrap());
            let key = (hash as u64, source_index, row_id, field_id);
            if prev.is_some_and(|p| key <= p) {
                return Err(parse_err("edm section not sorted"));
            }
            prev = Some(key);
            if source_index as usize >= header.edm_sources.len() {
                return Err(parse_err("edm sourceIndex out of range"));
            }
            edm.push(EdmEntry { hash, source_index, row_id, field_id });
        }

        if header.counts.idm != idm.len()
            || header.counts.edm != edm.len()
            || header.counts.docs != header.docs.len()
        {
            return Err(parse_err("header counts do not match sections"));
        }

        Ok(Bundle {
            format_version,
            header,
            bloom: Bloom { m_bits, k_hashes, bits: bloom_bytes.to_vec() },
            idm,
            edm,
        })
    }

    /// The server-assigned bundle version (matches `index.latest`).
    pub fn version(&self) -> u64 {
        self.header.bundle_version
    }

    /// `(mBits, kHashes)` as stored in the file.
    pub fn bloom_params(&self) -> (u32, u32) {
        (self.bloom.m_bits, self.bloom.k_hashes)
    }

    /// Bloom pre-filter: `false` ⇒ definitely not in the bundle;
    /// `true` ⇒ confirm via `lookup_idm` / `lookup_edm`.
    pub fn bloom_has(&self, hash: i64) -> bool {
        self.bloom.has(hash)
    }

    /// All IDM records for a hash (binary search, unsigned compare).
    pub fn lookup_idm(&self, hash: i64) -> &[IdmEntry] {
        let key = hash as u64;
        let start = self.idm.partition_point(|e| (e.hash as u64) < key);
        let len = self.idm[start..].iter().take_while(|e| e.hash == hash).count();
        &self.idm[start..start + len]
    }

    /// All EDM records for a hash (binary search, unsigned compare).
    pub fn lookup_edm(&self, hash: i64) -> &[EdmEntry] {
        let key = hash as u64;
        let start = self.edm.partition_point(|e| (e.hash as u64) < key);
        let len = self.edm[start..].iter().take_while(|e| e.hash == hash).count();
        &self.edm[start..start + len]
    }

    /// Full sections (read-only) — used by tests and diagnostics.
    pub fn idm_entries(&self) -> &[IdmEntry] {
        &self.idm
    }
    pub fn edm_entries(&self) -> &[EdmEntry] {
        &self.edm
    }
}
