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
//! The ML document-classification signal rides along in the OPTIONAL `ml` field
//! (see [`MlResult`]). It is additive: the field is
//! `skip_serializing_if = "Option::is_none"`, every construction site in this
//! file sets `ml: None`, and the fingerprint math below is untouched — so a
//! verdict produced by a fingerprint-only channel (and every frozen golden
//! vector) serializes BYTE-FOR-BYTE as it did before the model existed. That
//! matters because this shape is a protocol the server parses: an unconditional
//! `"ml": null` on every verdict would be a wire change, and this is not one.
//!
//! NEVER log file content or extracted text. The verdict itself carries only
//! hashes, scores and identifiers — and that rule binds `ml` too: a label id, a
//! score and two counts, never a snippet of what was classified.

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

/// `ml.status` vocabulary (contract §C). Kept as `&'static str` constants rather
/// than an enum because [`crate::ml::MlError`] already speaks these exact strings
/// (`MlError::status()` / `MlError::reason()`), and one vocabulary with one
/// spelling cannot drift.
pub const ML_STATUS_OK: &str = "ok";
pub const ML_STATUS_UNAVAILABLE: &str = "unavailable";
pub const ML_STATUS_SKIPPED: &str = "skipped";
pub const ML_STATUS_EMPTY: &str = "empty";

/// `ml.reason` vocabulary (contract §C) — populated only when `status != "ok"`.
pub const ML_REASON_MODEL_NOT_LOADED: &str = "model_not_loaded";
pub const ML_REASON_NO_TEXT: &str = "no_text";
/// The synchronous kernel read up-call (`DLP_REASON_READ`) deliberately does not
/// run the model: there is no budget for a forward pass in a call the FS stack is
/// blocked on. That read is decided on fingerprints alone.
pub const ML_REASON_READ_PATH_SKIP: &str = "read_path_skip";
/// The classifier was not consulted because the console policy is inert. Channels
/// normally omit `ml` entirely in that case (keeping the verdict byte-identical
/// to a pre-model one); this reason exists for a caller that wants the
/// "deliberately not consulted" fact recorded on the wire.
pub const ML_REASON_POLICY_OFF: &str = "policy_off";
pub const ML_REASON_LOAD_FAILED: &str = "load_failed";

/// The ML document-classification result for the scanned item — the SECOND,
/// independent detection signal, carried inside the existing verdict rather than
/// beside it so every channel, incident and audit record already knows how to
/// move it.
///
/// `sensitive` is the policy answer, not the model's: it is true only when the
/// predicted label is one the admin marked AND the confidence reached that
/// label's threshold (`mlpolicy::MlPolicy::label_is_sensitive`). The fusion in
/// [`super::decide`] reads only this flag, which is what keeps `decide()` pure
/// and policy-free.
///
/// Content NEVER appears here: a label id, a display name, a score, a chunk count
/// and a token count. That is deliberate — this struct is written to the incident
/// report and to the tamper-evident audit log, and neither may hold document text.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MlResult {
    /// One of [`ML_STATUS_OK`], [`ML_STATUS_UNAVAILABLE`], [`ML_STATUS_SKIPPED`],
    /// [`ML_STATUS_EMPTY`].
    pub status: String,
    /// Which model produced this, e.g. `"V6.2.01"` — so an incident stays
    /// interpretable after a model update changes the label distribution.
    pub model_version: String,
    /// Frozen taxonomy id (`"FIN"`), `None` unless `status == "ok"`.
    pub label_id: Option<String>,
    /// Display name (`"Finance"`), `None` unless `status == "ok"`.
    pub label_name: Option<String>,
    /// Softmax probability of the winning label; 0.0 when there is none.
    pub confidence: f64,
    /// The POLICY verdict on that label (see the struct doc), never the model's
    /// raw opinion.
    pub sensitive: bool,
    pub chunks: usize,
    /// Present ONLY when `[ml] max_chunks` capped the document — the chunk count
    /// BEFORE the cap. Its absence therefore means "the whole document was
    /// classified", which is the reference-faithful default, so no existing
    /// verdict changes shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunks_total: Option<usize>,
    pub tokens: usize,
    /// `None` when `status == "ok"`; otherwise one of the `ML_REASON_*` values.
    pub reason: Option<String>,
}

impl MlResult {
    /// A completed classification. `sensitive` is supplied by the caller because
    /// it is a policy answer (see the struct doc), not a property of the model.
    pub fn classified(
        model_version: &str,
        label_id: &str,
        label_name: &str,
        confidence: f64,
        sensitive: bool,
        chunks: usize,
        tokens: usize,
    ) -> Self {
        MlResult {
            status: ML_STATUS_OK.to_string(),
            model_version: model_version.to_string(),
            label_id: Some(label_id.to_string()),
            label_name: Some(label_name.to_string()),
            confidence,
            sensitive,
            chunks,
            chunks_total: None,
            tokens,
            // `reason` is the "why not" field: an answered classification has none.
            reason: None,
        }
    }

    /// Record that a cost bound classified a PREFIX of the document.
    ///
    /// A builder rather than an eighth positional argument: truncation is the rare
    /// case (`[ml] max_chunks` defaults to unlimited), and every call site that
    /// does not cap keeps reading as it did.
    pub fn truncated_from(mut self, chunks_total: usize) -> Self {
        if chunks_total > self.chunks {
            self.chunks_total = Some(chunks_total);
        }
        self
    }

    /// No prediction: `status` + `reason` say why. Never `sensitive` — a document
    /// the model did not classify is not a model hit, whatever went wrong.
    pub fn not_classified(model_version: &str, status: &str, reason: &str) -> Self {
        MlResult {
            status: status.to_string(),
            model_version: model_version.to_string(),
            label_id: None,
            label_name: None,
            confidence: 0.0,
            sensitive: false,
            chunks: 0,
            chunks_total: None,
            tokens: 0,
            reason: Some(reason.to_string()),
        }
    }

    /// The model could not answer (missing, unloadable, inference failure). This
    /// is the state EGRESS channels weigh `failBlock` against; the kernel read
    /// path never does (a model that will not load must not deny every read).
    pub fn unavailable(model_version: &str, reason: &str) -> Self {
        Self::not_classified(model_version, ML_STATUS_UNAVAILABLE, reason)
    }

    /// The model was deliberately not run on this path.
    pub fn skipped(model_version: &str, reason: &str) -> Self {
        Self::not_classified(model_version, ML_STATUS_SKIPPED, reason)
    }

    /// There was nothing to classify (empty clipboard, no extractable text). An
    /// outcome, not a fault — it must never fail-block.
    pub fn empty(model_version: &str) -> Self {
        Self::not_classified(model_version, ML_STATUS_EMPTY, ML_REASON_NO_TEXT)
    }

    /// A prediction was actually produced.
    pub fn is_ok(&self) -> bool {
        self.status == ML_STATUS_OK
    }

    /// The model owed an answer and could not give one — the only state that
    /// feeds `failBlock`.
    pub fn is_unavailable(&self) -> bool {
        self.status == ML_STATUS_UNAVAILABLE
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Verdict {
    pub file_name: String,
    pub file_sha256: String,
    pub extraction: Extraction,
    pub idm: Vec<IdmMatch>,
    pub edm: Vec<EdmSourceHit>,
    /// The ML signal, when a channel ran (or deliberately skipped) the
    /// classifier. `None` = the model was never in the picture, and the verdict
    /// then serializes exactly as it did before this field existed — see the
    /// module header. Fingerprint-only producers (`verdict`, `verdict_bytes`,
    /// `verdict_text`) always leave it `None`; the channel attaches it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ml: Option<MlResult>,
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
                ml: None,
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
        ml: None,
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
        ml: None,
    }
}
