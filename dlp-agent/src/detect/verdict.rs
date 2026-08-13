//! The verdict — the ONE entry point detection channels call (design doc
//! docs/fingerprinting.html §8). Audit-mode only: this reports what was
//! found (which doc, how much, which EDM rows); policy thresholds are NOT
//! applied here — allow/warn/block decisions come later with the policy
//! engine.
//!
//! Serialized shape is a protocol: the server's incident resolution reads
//! `idm[].versionId` + `idm[].matchedHashes` (signed-i64 decimal strings) to
//! map matches back to document positions. Field names are camelCase on the
//! wire.
//!
//! NEVER log file content or extracted text. The verdict itself carries only
//! hashes, scores and identifiers.

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use super::bundle::Bundle;
use super::edm::{match_edm, EdmSourceHit};
use super::extract::extract_text;
use super::normalize::normalize;
use super::shingle::{fnv1a64, shingles_of, winnow};

/// Whether text could be pulled out of the file. Unreadable is a VALID
/// verdict (policy later decides what to do with e.g. an encrypted zip),
/// not an error.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum Extraction {
    Ok { format: String },
    Unreadable { reason: String },
}

/// One protected document version found in the scanned text.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IdmMatch {
    pub version_id: String,
    pub document_id: String,
    pub collection_id: String,
    pub title: String,
    /// matched distinct hashes / the doc's fpCount (how much of the
    /// protected doc appears in the scanned file).
    pub containment: f64,
    /// matched distinct hashes / the scanned file's distinct hashes (how
    /// much of the scanned file is protected material).
    pub coverage: f64,
    pub matched_count: usize,
    pub total_count: usize,
    /// Signed-i64 decimal strings — the server resolves these to positions.
    pub matched_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Verdict {
    pub file_name: String,
    pub file_sha256: String,
    pub extraction: Extraction,
    pub idm: Vec<IdmMatch>,
    pub edm: Vec<EdmSourceHit>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Scan one file against a verified bundle. Errors only on I/O (unreadable
/// content is a verdict, not an error). This is now a thin wrapper: read the
/// file bytes, then hand them to `verdict_bytes` (the content-in-hand core).
pub fn verdict(path: &Path, bundle: &Bundle) -> Result<Verdict> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    Ok(verdict_bytes(&bytes, &file_name, bundle))
}

/// Score already-in-memory file content against a verified bundle. This is the
/// content-over-port entry point (the kernel minifilter reads the file in the
/// FS stack and ships the bytes here, so user mode never re-opens the file and
/// cannot hit a sharing violation). Infallible — the content is already in hand,
/// so there is no I/O; an unreadable/unsupported format is a VALID verdict, not
/// an error. `filename` is used only to pick the extraction format (extension)
/// and to label the verdict; NEVER log `content`.
pub fn verdict_bytes(content: &[u8], filename: &str, bundle: &Bundle) -> Verdict {
    let file_name = filename.to_string();
    let file_sha256 = sha256_hex(content);

    let extracted = match extract_text(content, &file_name) {
        Ok(e) => e,
        Err(unreadable) => {
            return Verdict {
                file_name,
                file_sha256,
                extraction: Extraction::Unreadable { reason: unreadable.reason.code().into() },
                idm: Vec::new(),
                edm: Vec::new(),
            };
        }
    };

    let (idm, edm) = match_text(&extracted.text, bundle);

    Verdict {
        file_name,
        file_sha256,
        extraction: Extraction::Ok { format: extracted.format },
        idm,
        edm,
    }
}

/// The post-extraction matching core (IDM containment/coverage + EDM
/// proximity), shared byte-for-byte by `verdict(path)` and `verdict_text`.
/// This is a behavior-preserving factor-out of the matching that used to live
/// inline in `verdict()`; the fingerprint math is unchanged (golden vectors
/// gate it). No I/O, no state — given the already-extracted text and a verified
/// bundle it returns `(idm matches, edm hits)`.
fn match_text(text: &str, bundle: &Bundle) -> (Vec<IdmMatch>, Vec<EdmSourceHit>) {
    // One normalization pass feeds both matchers (determinism + speed).
    let normalized = normalize(text);
    let shingles = shingles_of(&normalized.tokens, bundle.header.params.k);
    let hashes: Vec<i64> = shingles.iter().map(|s| fnv1a64(s)).collect();
    let fingerprints = winnow(&hashes, bundle.header.params.w);

    // Distinct scanned hashes in first-seen order (stable output).
    let mut seen = HashSet::new();
    let mut scanned: Vec<i64> = Vec::new();
    for fp in &fingerprints {
        if seen.insert(fp.hash) {
            scanned.push(fp.hash);
        }
    }

    // Bloom-gate each scanned hash, confirm in the sorted IDM section, and
    // accumulate matched hashes per document.
    let mut per_doc: BTreeMap<u32, Vec<i64>> = BTreeMap::new();
    for &hash in &scanned {
        if !bundle.bloom_has(hash) {
            continue;
        }
        for entry in bundle.lookup_idm(hash) {
            per_doc.entry(entry.doc_index).or_default().push(hash);
        }
    }

    let mut idm: Vec<IdmMatch> = per_doc
        .into_iter()
        .map(|(doc_index, matched)| {
            let doc = &bundle.header.docs[doc_index as usize];
            let matched_count = matched.len();
            IdmMatch {
                version_id: doc.version_id.clone(),
                document_id: doc.document_id.clone(),
                collection_id: doc.collection_id.clone(),
                title: doc.title.clone(),
                // Guard division by zero — an empty protected doc must never
                // score as a full match (fail secure).
                containment: if doc.fp_count == 0 {
                    0.0
                } else {
                    matched_count as f64 / doc.fp_count as f64
                },
                coverage: if scanned.is_empty() {
                    0.0
                } else {
                    matched_count as f64 / scanned.len() as f64
                },
                matched_count,
                total_count: doc.fp_count,
                matched_hashes: matched.iter().map(|h| h.to_string()).collect(),
            }
        })
        .collect();
    // Strongest match first; title tiebreak keeps output deterministic.
    idm.sort_by(|a, b| {
        b.containment
            .partial_cmp(&a.containment)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.title.cmp(&b.title))
    });

    let edm = match_edm(bundle, &normalized.tokens);

    (idm, edm)
}

/// Score raw in-memory text (clipboard/HTML/RTF snippets) against a verified
/// bundle, WITHOUT a file on disk. Same matching core as `verdict(path)` — the
/// only difference is the source of the text and that there is no extraction
/// step (the caller already has plain text), so this is infallible and returns
/// a `Verdict` directly. `file_name` is left empty; the channel supplies a
/// label. NEVER pass or store the text anywhere but the fingerprint math.
pub fn verdict_text(text: &str, bundle: &Bundle) -> Verdict {
    let file_sha256 = sha256_hex(text.as_bytes());
    let (idm, edm) = match_text(text, bundle);
    Verdict {
        file_name: String::new(),
        file_sha256,
        extraction: Extraction::Ok { format: "text".into() },
        idm,
        edm,
    }
}
