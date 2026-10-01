//! ML document classification — the agent's second, independent detection signal.
//!
//! Why the model runs HERE, on the endpoint
//! ----------------------------------------
//! Two product rules make on-endpoint inference the only option, not an
//! optimisation:
//!
//! * **Content never leaves the PC.** Fingerprinting (`detect/`) already scores
//!   documents locally and ships only hashes and scores to the management server.
//!   A classifier that posted extracted text to a server for scoring would put
//!   the customer's classified paragraphs on the wire — precisely the leak the
//!   product exists to stop — and would break data residency even though the
//!   server is on-premise.
//! * **It must work with the server unreachable.** Fail secure, not fail open: a
//!   PC on a submarine, an air-gapped lab, a laptop off the network still has to
//!   enforce. The graph, the tokenizer and the last-persisted policy are all on
//!   disk, so a detached endpoint classifies exactly as an attached one does.
//!
//! What this signal is FOR
//! -----------------------
//! Fingerprinting can only recognise a document somebody registered; the model
//! can only say what *kind* of document it is looking at, never which one leaked.
//! The two blind spots are complementary, which is why fusion ORs them
//! (`sensitive = fingerprint_sensitive OR ml_sensitive`) and why the model can
//! only ever ADD sensitivity — it never downgrades a fingerprint hit.
//!
//! Latency budget, per channel
//! ---------------------------
//! A DistilBERT forward pass on a CPU costs tens of milliseconds per chunk, so
//! where it runs is a policy decision, not a free one:
//!
//! | channel | ML |
//! |---|---|
//! | kguard WRITE scan, USB, clipboard copy, browser upload | inline, on the async budget |
//! | kguard READ scan (`DLP_REASON_READ`, a synchronous kernel up-call) | **never** — the up-call must return in microseconds, so the result is `status = "skipped"`, `reason = "read_path_skip"`, and the read is decided on fingerprints alone |
//!
//! The same asymmetry the OCR channel already has (`src/ocrpolicy.rs`), for the
//! same reason, with one difference: the read path never fail-blocks on the model
//! being unavailable, because a model that cannot load must not turn every file
//! read on the endpoint into a denial.
//!
//! Module layout
//! -------------
//! * [`labels`] — the frozen 29-label space (index order is the model's).
//! * [`chunk`]  — the port of the reference chunker; pure, no model needed.
//! * [`engine`] — the ONNX lifecycle: load once, classify many, log nothing.
//! * [`cache`]  — content-hash verdict cache: what lets the read path CONSULT the
//!   model's answer without ever running it. The "never" in the table above is
//!   about INFERENCE, not about the ML signal: an off-path producer (creation
//!   watcher, at-rest walker, background queue) classifies and deposits, and the
//!   read up-call does a microsecond HashMap lookup. A miss still degrades to
//!   `read_path_skip` unless the policy opts into denying unclassified content.
//!
//! **Never log document text here.** Counts, ids, labels and scores only — the
//! same rule `detect/` obeys, applied to a component that by construction holds
//! whole documents in memory.

pub mod cache;
pub mod chunk;
pub mod engine;
pub mod filter;
pub mod frontier;
pub mod labels;
pub mod walk;
pub mod watch;
pub mod queue;

pub use cache::{
    read_prefix_for_hashing, CacheKey, CacheStats, CachedVerdict, VerdictCache, MAX_HASHED_BYTES,
};
pub use chunk::{chunk_ids_sha256, tokenizer_from_file, ChunkError, ChunkGeometry, Chunker, Encoder};
pub use engine::{active, classify, load, set_active, unload, MlConfig, MlEngine};
pub use labels::{MlLabel, LABELS, LABEL_COUNT};

use std::fmt;

/// The model's answer for one document.
///
/// Carries no text, no snippet and no offset — deliberately. The verdict this
/// becomes (`Verdict.ml`) is written to the incident report and to the audit
/// log, and neither may ever hold content.
#[derive(Debug, Clone, PartialEq)]
pub struct MlPrediction {
    /// The winning label's frozen id, e.g. `"FIN"`.
    pub label_id: &'static str,
    /// Its display name, e.g. `"Finance"`.
    pub label_name: &'static str,
    /// Its index into the model's output layer, 0..28.
    pub label_index: usize,
    /// Softmax probability of the winning label, in `[0, 1]`.
    pub confidence: f64,
    /// How many chunks were actually fed to the graph.
    pub chunks: usize,
    /// How many chunks the document became before any cost bound was applied.
    /// Equal to [`chunks`](Self::chunks) unless `[ml] max_chunks` capped the
    /// document, in which case the answer was formed from a leading PREFIX and
    /// this is what says so.
    pub chunks_total: usize,
    /// Content tokens in the document before chunking, special tokens excluded.
    pub tokens: usize,
    /// The 29 raw logits, in label index order. Kept so a threshold can be
    /// re-evaluated and so the golden vectors can gate the numerics rather than
    /// just the argmax.
    pub logits: Vec<f64>,
}

/// Why a classification did not produce a prediction.
///
/// Every variant maps onto the `ml.status` / `ml.reason` pair on the wire, so the
/// verdict's vocabulary and this enum cannot drift apart:
///
/// | variant | `status` | `reason` |
/// |---|---|---|
/// | [`MlError::NotLoaded`] | `unavailable` | `model_not_loaded` |
/// | [`MlError::LoadFailed`] | `unavailable` | `load_failed` |
/// | [`MlError::Inference`] | `unavailable` | `load_failed` |
/// | [`MlError::Chunk`] | `unavailable` | `load_failed` |
/// | [`MlError::Empty`] | `empty` | `no_text` |
#[derive(Debug, Clone)]
pub enum MlError {
    /// No engine has been loaded in this process. Not a failure of the model —
    /// the caller asked before startup published one.
    NotLoaded,
    /// The artifacts are missing, unreadable, or not the model we expect (wrong
    /// output width, a label space that disagrees with [`labels`]).
    LoadFailed(String),
    /// The graph ran and failed, or returned something that is not `[1, 29]`.
    Inference(String),
    /// Tokenization or chunking failed. A broken artifact, never a property of
    /// the document.
    Chunk(ChunkError),
    /// Nothing but whitespace survived truncation, or the text tokenized to no
    /// tokens at all. An outcome, not a fault: an empty clipboard is not an
    /// incident.
    Empty,
}

impl MlError {
    /// The `ml.status` this error becomes on the wire.
    pub fn status(&self) -> &'static str {
        match self {
            MlError::Empty => "empty",
            _ => "unavailable",
        }
    }

    /// The `ml.reason` this error becomes on the wire.
    pub fn reason(&self) -> &'static str {
        match self {
            MlError::NotLoaded => "model_not_loaded",
            MlError::Empty => "no_text",
            _ => "load_failed",
        }
    }
}

impl fmt::Display for MlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MlError::NotLoaded => write!(f, "no ML engine loaded in this process"),
            MlError::LoadFailed(m) => write!(f, "ML model failed to load: {m}"),
            MlError::Inference(m) => write!(f, "ML inference failed: {m}"),
            MlError::Chunk(e) => write!(f, "ML chunking failed: {e}"),
            MlError::Empty => write!(f, "no text to classify"),
        }
    }
}

impl std::error::Error for MlError {}

impl From<ChunkError> for MlError {
    fn from(e: ChunkError) -> Self {
        MlError::Chunk(e)
    }
}
