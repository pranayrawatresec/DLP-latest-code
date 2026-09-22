//! The ONNX Runtime lifecycle: load the graph once per process, classify many
//! documents, log nothing but counts and scores.
//!
//! ============================ BUILD RECIPE =============================
//!
//! `ort` is a binding, not an implementation: the ONNX Runtime itself is a
//! ~18 MB native library that has to come from somewhere. `ort`'s default
//! `download-binaries` feature fetches it over HTTPS from parcel.pyke.io during
//! `cargo build`, which is unacceptable for this product — a defence build must
//! be reproducible from a vendored source tree with the network unplugged, and a
//! binary pulled at build time is a supply-chain artifact nobody signed off.
//!
//! So `Cargo.toml` selects `default-features = false, features = ["std",
//! "load-dynamic", "api-17"]`. Consequences, in order:
//!
//! * **Build**: nothing is downloaded and nothing is linked. `cargo build` works
//!   offline with no ONNX Runtime present at all; a machine that cannot classify
//!   still compiles and still runs every other channel.
//! * **Run**: `onnxruntime.dll` is `dlopen`'d at first use. If it is absent,
//!   [`load`] returns `MlError::LoadFailed` and the ML signal reports
//!   `status = "unavailable"` — it never panics and never takes the agent down.
//!
//! Where the library comes from, per environment:
//!
//! * **Production / air-gapped**: the installer drops `onnxruntime.dll` beside
//!   the model, at `<ml root>/runtime/onnxruntime.dll` (see
//!   [`MlConfig::under`]), and it is re-signed and inventoried with the rest of
//!   the agent payload. No network, no build-time fetch, one file to attest.
//! * **Developer box / CI**: the same DLL, obtained once from the official
//!   Microsoft `onnxruntime` Python wheel, which is how the reference pipeline in
//!   `tools/ml-reference/` already gets it:
//!
//!   ```text
//!   python -m pip download onnxruntime --no-deps -d %TEMP%\ort
//!   python -c "import zipfile,shutil,os; z=zipfile.ZipFile(r'%TEMP%\ort\onnxruntime-<ver>-win_amd64.whl'); \
//!              d=os.path.expanduser('~/.dlp-onnxruntime'); os.makedirs(d, exist_ok=True); \
//!              shutil.copyfileobj(z.open('onnxruntime/capi/onnxruntime.dll'), open(d+'/onnxruntime.dll','wb'))"
//!   set ORT_DYLIB_PATH=%USERPROFILE%\.dlp-onnxruntime\onnxruntime.dll
//!   cargo test --test ml_golden
//!   ```
//!
//!   An existing `pip install onnxruntime` works just as well: the file is at
//!   `<site-packages>/onnxruntime/capi/onnxruntime.dll` (`.so` on Linux).
//!
//! Resolution order for the library, most specific first (see [`resolve_dylib`]):
//!   1. [`MlConfig::dylib`], when the caller set it;
//!   2. `<ml root>/runtime/onnxruntime.{dll,so,dylib}`, the shipped location;
//!   3. the `ORT_DYLIB_PATH` environment variable;
//!   4. the bare platform file name, which `ort` resolves next to the executable
//!      and then through the OS loader search path.
//!
//! `api-17` pins the ONNX Runtime **API** surface (1.17), not the ONNX **opset**
//! (17, a property of the graph). Any runtime ≥ 1.17 satisfies it, so the shipped
//! DLL can be updated for a CVE without a Rust change — while the exact `ort`
//! version stays pinned in `Cargo.toml`, because a binding bump can move
//! numerics and the golden vectors are the contract.
//!
//! ======================================================================
//!
//! Lifecycle
//! ---------
//! One process, one loaded graph. The 256 MB model is memory-mapped by ONNX
//! Runtime and the session is not cheap to build, so [`load`] publishes it into a
//! process-wide handle — the same `RwLock<Option<…>>` "ACTIVE" pattern
//! `src/ocrpolicy.rs` uses for the policy — and every classify site reads it
//! through [`classify`] without threading a handle through the frozen
//! `detect::verdict*` signatures. `Session::run` needs `&mut`, so the session
//! itself sits behind a `Mutex`: inference is serialised per process, which is
//! what we want anyway (a document scan must not be able to spawn N concurrent
//! forward passes on an employee's PC).
//!
//! Validation on load
//! ------------------
//! A model whose output width is not 29, or whose sidecar label space disagrees
//! with [`labels`](super::labels), is **refused**. Loading it anyway would not
//! error later — it would quietly re-label predictions, reporting a NUC document
//! as ADM. Refusing is the fail-secure answer: the ML signal goes
//! `unavailable` and the channels honour `failBlock`.
//!
//! Privacy
//! -------
//! No function here logs, returns or stores document text. The only things that
//! leave this module are token counts, chunk counts, a label and a score.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use serde::Deserialize;

use ort::session::{builder::GraphOptimizationLevel, Session};
use ort::value::{Tensor, ValueType};
use tokenizers::Tokenizer;

use super::chunk::{ChunkGeometry, Chunker};
use super::labels;
use super::{MlError, MlPrediction};

/// The id the batch is padded with — `[PAD]` in the bundled WordPiece vocabulary.
/// Padding belongs to the batch, not to a chunk, and is masked out by
/// `attention_mask`.
pub const PAD_ID: i64 = 0;

/// The character bound applied *before a single token exists*. Truncating by
/// tokens instead — or at a different count — feeds the model text it was never
/// trained to see, and gives a different answer.
pub const DEFAULT_MAX_CHARS: usize = 200_000;

/// The graph output the classification head writes.
const LOGITS_OUTPUT: &str = "logits";

/// Split-graph tensor names, from `model/onnx_split/split_metadata.json`.
const CLS_OUTPUT: &str = "cls";
const POOLED_INPUT: &str = "pooled";

/// Directory holding the split graphs, relative to the model file.
const SPLIT_DIR: &str = "onnx_split";
const ENCODER_FILE: &str = "encoder.onnx";
const HEAD_FILE: &str = "head.onnx";

/// Chunks per encoder forward pass. See [`MlConfig::micro_batch_size`].
pub const DEFAULT_MICRO_BATCH_SIZE: usize = 8;

// --------------------------------------------------------------------- //
// Configuration
// --------------------------------------------------------------------- //

/// Where the four artifacts live and how the session is built.
#[derive(Debug, Clone)]
pub struct MlConfig {
    /// The exported ONNX graph (`model.onnx`).
    pub model: PathBuf,
    /// Its sidecar (`model.onnx.json`) — labels, chunk geometry, max_chars,
    /// model version. Read from beside the weights so neither can drift.
    pub sidecar: PathBuf,
    /// The bundled HuggingFace fast tokenizer (`tokenizer.json`).
    pub tokenizer: PathBuf,
    /// An explicit ONNX Runtime shared library, when the caller knows better than
    /// the search order documented at the top of this file.
    pub dylib: Option<PathBuf>,
    /// Threads ONNX Runtime may use inside one operator. One by default: this
    /// runs on an employee's PC while they work, and a classifier that pegs every
    /// core is a support ticket. It also makes the golden vectors reproducible.
    pub intra_threads: usize,
    /// The character bound the CALLER believes is in force. `0` accepts whatever
    /// the sidecar declares; any other value must MATCH the sidecar or [`load`]
    /// refuses.
    ///
    /// This mirrors `_require_matching_max_chars` in the reference pipeline, and
    /// for the same reason: `max_chars` is applied before a single token exists,
    /// so a bound lower than the model was built for silently shortens the
    /// document and no amount of correct chunking recovers it. The failure is
    /// invisible in the output, so it is checked rather than warned about.
    pub max_chars: usize,
    /// Chunks pushed through the ENCODER per forward pass, when the split graphs
    /// are in use. Ignored by the monolithic graph, which has no seam to batch at.
    ///
    /// THIS IS THE MEMORY DIAL. Encoder cost is ~65 MB per chunk held at once
    /// (512x512 attention, 12 heads, 6 layers, f32), so peak is roughly
    /// `350 MB + 65 MB * micro_batch_size` REGARDLESS of how long the document
    /// is. Measured on this model: batch 4 -> 650 MB, batch 8 -> 942 MB,
    /// batch 16 -> 1565 MB, and feeding all 72 chunks of a max-length document
    /// at once -> 4995 MB, which is what exhausted an 8 GiB endpoint.
    ///
    /// 8 is the default because it is what the model's own card specifies for the
    /// reference PyTorch path (`micro_batch_size: 8`). Batching changes nothing
    /// about the answer — the mean is a running sum divided by the count, and the
    /// non-linear head runs exactly once on the pooled vector — which
    /// `tests/ml_golden.rs` proves against fixtures generated from the
    /// authoritative pipeline.
    pub micro_batch_size: usize,
    /// Hard ceiling on how many chunks are fed to the graph. `0` = unlimited,
    /// which is the reference-faithful setting and the default.
    ///
    /// A non-zero value bounds inference cost on a slow endpoint by classifying
    /// only the document's leading `max_chunks` chunks — a real behaviour change,
    /// not a tuning knob, so a truncated classification says so on its result
    /// (`MlPrediction::chunks_total`) and on the wire.
    pub max_chunks: usize,
}

impl MlConfig {
    /// The standard artifact layout, rooted anywhere.
    ///
    /// ```text
    /// <root>/model/model.onnx
    /// <root>/model/model.onnx.json
    /// <root>/backbone/tokenizer.json
    /// <root>/runtime/onnxruntime.dll        (optional; see the build recipe)
    /// ```
    ///
    /// This is both the repository layout (`Document_classification/`) and the
    /// shipped one (`<install dir>/ml/`), on purpose: a developer and an endpoint
    /// exercise the same paths.
    pub fn under(root: &Path) -> Self {
        let runtime = root.join("runtime").join(dylib_file_name());
        MlConfig {
            model: root.join("model").join("model.onnx"),
            sidecar: root.join("model").join("model.onnx.json"),
            tokenizer: root.join("backbone").join("tokenizer.json"),
            dylib: runtime.is_file().then_some(runtime),
            intra_threads: 1,
            // Reference-faithful defaults: accept the sidecar's bound, no chunk cap.
            max_chars: 0,
            max_chunks: 0,
            micro_batch_size: DEFAULT_MICRO_BATCH_SIZE,
        }
    }

    /// True when the graph, its sidecar and the tokenizer are all present. Cheap
    /// enough to call before deciding whether ML is even possible on this box.
    pub fn artifacts_present(&self) -> bool {
        self.model.is_file() && self.sidecar.is_file() && self.tokenizer.is_file()
    }
}

/// The platform's ONNX Runtime shared-library file name.
fn dylib_file_name() -> &'static str {
    if cfg!(windows) {
        "onnxruntime.dll"
    } else if cfg!(target_os = "macos") {
        "libonnxruntime.dylib"
    } else {
        "libonnxruntime.so"
    }
}

// --------------------------------------------------------------------- //
// The sidecar
// --------------------------------------------------------------------- //

/// The parts of `model.onnx.json` inference actually consumes. Unknown keys are
/// ignored so an exporter may add fields without breaking the agent; the fields
/// that *would* change an answer (labels, geometry, max_chars) are all read here
/// rather than assumed.
#[derive(Debug, Deserialize)]
struct Sidecar {
    #[serde(default)]
    model_version: String,
    #[serde(default)]
    labels: Vec<String>,
    #[serde(default)]
    max_chars: Option<usize>,
    #[serde(default)]
    chunking: Option<SidecarChunking>,
}

#[derive(Debug, Deserialize)]
struct SidecarChunking {
    max_tokens: Option<usize>,
    overlap_tokens: Option<usize>,
    min_tokens: Option<usize>,
}

// --------------------------------------------------------------------- //
// The engine
// --------------------------------------------------------------------- //

/// A loaded tokenizer + graph, ready to classify. Built by [`load`]; one instance
/// serves any number of documents and keeps nothing between calls.
/// The two sessions of the split model, behind ONE lock.
///
/// One lock rather than two: a classification is encoder-loop-then-head, and
/// holding a single guard for the whole sequence keeps inference serialised per
/// process exactly as the monolithic path was. Two locks would permit two
/// documents to interleave through the encoder, doubling peak memory — the one
/// thing this split exists to prevent.
struct SplitSessions {
    encoder: Session,
    head: Session,
}

/// How this process runs the model.
///
/// WHY TWO SHAPES. The monolithic `model.onnx` is a sealed box: chunks in,
/// logits out, with the per-chunk `[CLS]` mean pooling locked INSIDE it. That
/// forces every chunk of a document through the encoder in a single call, so
/// encoder memory grows with document length — ~65 MB per chunk, reaching
/// ~5 GB on a 72-chunk document and exhausting an 8 GiB endpoint.
///
/// The split graphs open the box at the only seam where it is mathematically
/// safe to cut: the encoder emits per-chunk `[CLS]` vectors, we accumulate them
/// ourselves, and the head (which contains the non-linear ReLU, and therefore
/// CANNOT be decomposed) runs exactly once on the pooled vector. That makes
/// micro-batching possible and peak memory a function of the batch size instead
/// of the document.
///
/// Both are kept because a deployment staged before the split existed has only
/// `model.onnx`, and must keep working rather than reporting `unavailable`.
enum Graph {
    /// `model.onnx`: chunks -> logits. Memory grows with the document.
    Monolithic(Mutex<Session>),
    /// `onnx_split/{encoder,head}.onnx` with a running CLS sum between them.
    /// Memory is bounded by `micro_batch`.
    Split {
        sessions: Mutex<SplitSessions>,
        micro_batch: usize,
    },
}

pub struct MlEngine {
    tokenizer: Tokenizer,
    /// `Session::run` takes `&mut self`, and we deliberately serialise inference:
    /// one forward pass at a time on a user's PC.
    graph: Graph,
    geometry: ChunkGeometry,
    max_chars: usize,
    /// `0` = unlimited. See [`MlConfig::max_chunks`].
    max_chunks: usize,
    model_version: String,
}

/// Hand-written so a `{:?}` on an engine (in a log line, in a test failure)
/// prints the version and the geometry and NOTHING that could hold document
/// text — the tokenizer's vocabulary and the session's tensors are not things to
/// spill into a log.
impl std::fmt::Debug for MlEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlEngine")
            .field("model_version", &self.model_version)
            .field("geometry", &self.geometry)
            .field("max_chars", &self.max_chars)
            .field("labels", &labels::LABEL_COUNT)
            .field("graph", &self.graph_kind())
            .finish()
    }
}

impl MlEngine {
    /// The model version string the sidecar declares, e.g. `"V6.2.01"`. Carried
    /// on every verdict so an incident can be traced to the weights that produced
    /// it.
    pub fn model_version(&self) -> &str {
        &self.model_version
    }

    /// The chunk geometry in force, as read from the sidecar.
    pub fn geometry(&self) -> ChunkGeometry {
        self.geometry
    }

    /// Apply the two pre-tokenizer steps in the reference's order.
    ///
    /// 1. truncate to `max_chars` **characters** (not bytes, not tokens);
    /// 2. presentation is `"full"` for V6.2.01, which is the identity transform —
    ///    so there is deliberately no step 2. Porting `presentation.py` would add
    ///    a branch that never runs.
    fn prepare<'a>(&self, raw_text: &'a str) -> Result<&'a str, MlError> {
        let text = if self.max_chars == 0 {
            raw_text
        } else {
            match raw_text.char_indices().nth(self.max_chars) {
                Some((byte, _)) => &raw_text[..byte],
                None => raw_text,
            }
        };
        if text.trim().is_empty() {
            return Err(MlError::Empty);
        }
        Ok(text)
    }

    /// Truncate and chunk, stopping short of inference.
    ///
    /// Split out for the same reason the reference splits it: the chunk ids are
    /// what the port is actually gated on, and a geometry test should not need
    /// the 256 MB graph.
    pub fn chunk(&self, raw_text: &str) -> Result<Vec<Vec<i64>>, MlError> {
        let text = self.prepare(raw_text)?;
        let chunker = Chunker::new(&self.tokenizer, self.geometry)?;
        Ok(chunker.chunk(text)?)
    }

    /// Classify one document.
    ///
    /// Returns the label, the confidence, the chunk geometry and the raw logits.
    /// No text, no snippet, no fragment of the input.
    pub fn classify(&self, raw_text: &str) -> Result<MlPrediction, MlError> {
        let text = self.prepare(raw_text)?;
        let chunker = Chunker::new(&self.tokenizer, self.geometry)?;

        let mut chunks = chunker.chunk(text)?;
        if chunks.is_empty() {
            return Err(MlError::Empty);
        }
        let tokens = chunker.count_tokens(text)?;

        // The optional cost bound. Reference-faithful is `max_chunks == 0`; a
        // configured cap classifies the document's LEADING chunks only, and
        // `chunks_total` carries the fact forward so a reviewer can see that the
        // answer was formed from a prefix rather than the whole document.
        let chunks_total = chunks.len();
        if self.max_chunks != 0 && chunks_total > self.max_chunks {
            chunks.truncate(self.max_chunks);
            tracing::debug!(
                classified = self.max_chunks,
                chunks_total,
                "ml chunk cap in force — classifying a prefix of the document"
            );
        }

        let logits = self.run(&chunks)?;
        let probabilities = softmax(&logits);

        // argmax. Ties go to the lowest index, as numpy's argmax does.
        let mut index = 0usize;
        for (i, p) in probabilities.iter().enumerate() {
            if *p > probabilities[index] {
                index = i;
            }
        }

        let label = labels::by_index(index).ok_or_else(|| {
            MlError::Inference(format!("output index {index} is outside the {}-label space", labels::LABEL_COUNT))
        })?;

        Ok(MlPrediction {
            label_id: label.id,
            label_name: label.name,
            label_index: index,
            confidence: probabilities[index],
            chunks: chunks.len(),
            chunks_total,
            tokens,
            logits,
        })
    }

    /// Feed one document's chunks through the graph, in ONE call.
    ///
    /// Padding is to the LONGEST CHUNK IN THIS CALL, not always to 512: the
    /// graph's sequence axis is dynamic, so a short single-chunk document runs a
    /// short sequence. Padding to 512 regardless would change the attention
    /// masks — and with them the pooled representation, and with that the answer.
    ///
    /// The graph performs the encoder pass, the per-chunk `[CLS]` mean pooling
    /// and the classification head, so the batch axis of the output is 1 however
    /// many chunks went in: every chunk fed into one call is ONE document.
    fn run(&self, chunks: &[Vec<i64>]) -> Result<Vec<f64>, MlError> {
        if chunks.iter().all(|c| c.is_empty()) {
            return Err(MlError::Empty);
        }
        match &self.graph {
            Graph::Monolithic(session) => self.run_monolithic(session, chunks),
            Graph::Split { sessions, micro_batch } => {
                self.run_split(sessions, chunks, *micro_batch)
            }
        }
    }

    /// Which backend is live, for logs and `{:?}`.
    pub fn graph_kind(&self) -> &'static str {
        match &self.graph {
            Graph::Monolithic(_) => "monolithic",
            Graph::Split { .. } => "split+microbatched",
        }
    }

    /// Pad a group of chunks into the `[rows, width]` pair the graphs expect.
    ///
    /// Padding is to the LONGEST CHUNK IN THIS GROUP, not always to 512: the
    /// sequence axis is dynamic, so a short chunk runs a short sequence. Padding
    /// to 512 regardless would change the attention masks - and with them the
    /// pooled representation, and with that the answer.
    fn pad_group(chunks: &[Vec<i64>]) -> Result<(Tensor<i64>, Tensor<i64>), MlError> {
        let rows = chunks.len();
        let width = chunks.iter().map(Vec::len).max().unwrap_or(0);
        if width == 0 {
            return Err(MlError::Empty);
        }
        let mut input_ids = vec![PAD_ID; rows * width];
        let mut attention_mask = vec![0i64; rows * width];
        for (row, chunk) in chunks.iter().enumerate() {
            let base = row * width;
            input_ids[base..base + chunk.len()].copy_from_slice(chunk);
            attention_mask[base..base + chunk.len()].fill(1);
        }
        let shape = vec![rows as i64, width as i64];
        let ids = Tensor::from_array((shape.clone(), input_ids))
            .map_err(|e| MlError::Inference(format!("input_ids tensor: {e}")))?;
        let mask = Tensor::from_array((shape, attention_mask))
            .map_err(|e| MlError::Inference(format!("attention_mask tensor: {e}")))?;
        Ok((ids, mask))
    }

    /// The sealed graph: every chunk in one call.
    ///
    /// The graph performs the encoder pass, the per-chunk `[CLS]` mean pooling
    /// and the classification head, so the batch axis of the output is 1 however
    /// many chunks went in: every chunk fed into one call is ONE document.
    ///
    /// Retained for deployments staged before the split graphs existed. Peak
    /// memory here grows with the document and is what the split path fixes.
    fn run_monolithic(
        &self,
        session: &Mutex<Session>,
        chunks: &[Vec<i64>],
    ) -> Result<Vec<f64>, MlError> {
        let (ids, mask) = Self::pad_group(chunks)?;
        let mut session = session.lock().unwrap_or_else(|p| p.into_inner());
        let outputs = session
            .run(ort::inputs!["input_ids" => ids, "attention_mask" => mask])
            .map_err(|e| MlError::Inference(e.to_string()))?;
        let (out_shape, data) = outputs[LOGITS_OUTPUT]
            .try_extract_tensor::<f32>()
            .map_err(|e| MlError::Inference(format!("logits: {e}")))?;
        if data.len() != labels::LABEL_COUNT {
            return Err(MlError::Inference(format!(
                "graph returned {} values with shape {:?}; this build only understands a {}-label head",
                data.len(),
                out_shape.as_ref(),
                labels::LABEL_COUNT
            )));
        }
        Ok(data.iter().map(|&v| v as f64).collect())
    }

    /// The split graphs: encode at most `micro_batch` chunks at a time,
    /// accumulate the per-chunk `[CLS]`, run the head ONCE.
    ///
    /// WHY THIS IS THE SAME ANSWER, not an approximation:
    ///
    /// ```text
    ///   pooled = (CLS_1 + CLS_2 + ... + CLS_n) / n   <- a sum: decomposable
    ///   logits = head(pooled)                        <- holds a ReLU: NOT decomposable
    /// ```
    ///
    /// A sum can be accumulated in any grouping, so encoding 8 chunks at a time
    /// and adding as we go reaches exactly the same total. The head runs once, on
    /// the finished pooled vector. Averaging per-batch LOGITS instead is the
    /// tempting shortcut and is simply WRONG: through a non-linearity
    /// `mean(head(x))` is not `head(mean(x))`, and the error is silent - a
    /// confident wrong label. `tests/ml_golden.rs` gates this path against
    /// fixtures produced by the authoritative Python pipeline.
    ///
    /// The accumulator is `f64` while the graphs are `f32`: summing hundreds of
    /// f32 values loses low bits, and the pooled vector feeds a classifier whose
    /// margins are compared against policy thresholds.
    fn run_split(
        &self,
        sessions: &Mutex<SplitSessions>,
        chunks: &[Vec<i64>],
        micro_batch: usize,
    ) -> Result<Vec<f64>, MlError> {
        let batch = micro_batch.max(1);
        let mut guard = sessions.lock().unwrap_or_else(|p| p.into_inner());
        let s = &mut *guard;

        let mut sum: Vec<f64> = Vec::new();
        let mut counted: usize = 0;

        for group in chunks.chunks(batch) {
            let (ids, mask) = Self::pad_group(group)?;
            let outputs = s
                .encoder
                .run(ort::inputs!["input_ids" => ids, "attention_mask" => mask])
                .map_err(|e| MlError::Inference(format!("encoder: {e}")))?;
            let (shape, data) = outputs[CLS_OUTPUT]
                .try_extract_tensor::<f32>()
                .map_err(|e| MlError::Inference(format!("cls: {e}")))?;

            let rows = group.len();
            if rows == 0 || data.len() % rows != 0 {
                return Err(MlError::Inference(format!(
                    "encoder returned {} values with shape {:?} for {rows} chunk(s)",
                    data.len(),
                    shape.as_ref()
                )));
            }
            let hidden = data.len() / rows;
            if sum.is_empty() {
                sum = vec![0.0f64; hidden];
            } else if sum.len() != hidden {
                return Err(MlError::Inference(format!(
                    "encoder hidden size changed mid-document: {} then {hidden}",
                    sum.len()
                )));
            }
            for row in 0..rows {
                let base = row * hidden;
                for (i, acc) in sum.iter_mut().enumerate() {
                    *acc += data[base + i] as f64;
                }
            }
            counted += rows;
            // `outputs` - and with it this batch's activations - drops HERE,
            // before the next group is encoded. That is what bounds peak memory
            // to one batch rather than the whole document.
        }

        if counted == 0 || sum.is_empty() {
            return Err(MlError::Empty);
        }

        let hidden = sum.len();
        let pooled: Vec<f32> = sum.iter().map(|v| (v / counted as f64) as f32).collect();
        let pooled_tensor = Tensor::from_array((vec![1i64, hidden as i64], pooled))
            .map_err(|e| MlError::Inference(format!("pooled tensor: {e}")))?;

        let outputs = s
            .head
            .run(ort::inputs![POOLED_INPUT => pooled_tensor])
            .map_err(|e| MlError::Inference(format!("head: {e}")))?;
        let (out_shape, data) = outputs[LOGITS_OUTPUT]
            .try_extract_tensor::<f32>()
            .map_err(|e| MlError::Inference(format!("logits: {e}")))?;
        if data.len() != labels::LABEL_COUNT {
            return Err(MlError::Inference(format!(
                "head returned {} values with shape {:?}; this build only understands a {}-label head",
                data.len(),
                out_shape.as_ref(),
                labels::LABEL_COUNT
            )));
        }
        Ok(data.iter().map(|&v| v as f64).collect())
    }
}

/// Softmax over one document's logits, in f64 with the maximum subtracted.
///
/// The subtraction is not cosmetic: without it a logit near 90 overflows the
/// exponential and the confidence comes back NaN — which would then be compared
/// against a policy threshold, and `NaN >= threshold` is false, so a highly
/// confident hit would silently pass.
fn softmax(logits: &[f64]) -> Vec<f64> {
    let max = logits.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let exponentiated: Vec<f64> = logits.iter().map(|&v| (v - max).exp()).collect();
    let total: f64 = exponentiated.iter().sum();
    if total == 0.0 || !total.is_finite() {
        // Unreachable for finite logits (the max term is always exp(0) = 1), but
        // a uniform distribution is a safer answer than a division by zero.
        return vec![1.0 / logits.len() as f64; logits.len()];
    }
    exponentiated.into_iter().map(|v| v / total).collect()
}

// --------------------------------------------------------------------- //
// Process-wide handle (the ocrpolicy.rs ACTIVE pattern)
// --------------------------------------------------------------------- //

/// The loaded engine for this process. `None` until startup publishes one, which
/// is the fail-secure default: no engine means `status = "unavailable"`, never a
/// silently unclassified document.
static ACTIVE: RwLock<Option<Arc<MlEngine>>> = RwLock::new(None);

/// The ONNX Runtime environment is global to the process and may only be
/// initialised once; the result (including a failure to find the DLL) is cached
/// so a hot path cannot retry a `dlopen` on every document.
static RUNTIME: OnceLock<Result<(), String>> = OnceLock::new();

/// Publish an engine as this process's active one (call at startup, and again if
/// a model update swaps the artifacts).
pub fn set_active(engine: Arc<MlEngine>) {
    match ACTIVE.write() {
        Ok(mut w) => *w = Some(engine),
        Err(e) => *e.into_inner() = Some(engine),
    }
}

/// The active engine, if one has been published.
pub fn active() -> Option<Arc<MlEngine>> {
    match ACTIVE.read() {
        Ok(r) => r.clone(),
        Err(e) => e.into_inner().clone(),
    }
}

/// Drop the active engine — used when the console turns the ML policy off, so a
/// disabled feature does not keep 256 MB resident on an employee's PC.
pub fn unload() {
    match ACTIVE.write() {
        Ok(mut w) => *w = None,
        Err(e) => *e.into_inner() = None,
    }
}

/// Classify with this process's active engine.
///
/// The convenience the classify sites use, so none of them has to hold a handle.
/// [`MlError::NotLoaded`] when nothing has been published — which the caller maps
/// to `status = "unavailable"`, `reason = "model_not_loaded"`.
pub fn classify(text: &str) -> Result<MlPrediction, MlError> {
    active().ok_or(MlError::NotLoaded)?.classify(text)
}

/// Load the tokenizer and the graph, validate them, and return the engine.
///
/// Does NOT publish it — [`set_active`] does, so a caller can load, check and
/// only then swap. Loading is slow (hundreds of milliseconds and ~300 MB
/// resident); it belongs on a startup or resync thread, never on a scan path.
pub fn load(config: &MlConfig) -> Result<Arc<MlEngine>, MlError> {
    for path in [&config.model, &config.sidecar, &config.tokenizer] {
        if !path.is_file() {
            return Err(MlError::LoadFailed(format!("missing artifact: {}", path.display())));
        }
    }

    // ---- sidecar: label space, geometry, truncation bound, version --------
    let sidecar_text = fs::read_to_string(&config.sidecar)
        .map_err(|e| MlError::LoadFailed(format!("{}: {e}", config.sidecar.display())))?;
    let sidecar: Sidecar = serde_json::from_str(&sidecar_text)
        .map_err(|e| MlError::LoadFailed(format!("{}: {e}", config.sidecar.display())))?;

    // A sidecar that names a different label space is a different model. Loading
    // it would not fail — it would re-label every prediction — so refuse.
    if !sidecar.labels.is_empty() {
        let expected = labels::ids();
        if sidecar.labels.len() != expected.len()
            || sidecar.labels.iter().zip(expected.iter()).any(|(a, b)| a != b)
        {
            return Err(MlError::LoadFailed(format!(
                "sidecar declares a {}-label space that does not match this build's frozen {} labels",
                sidecar.labels.len(),
                expected.len()
            )));
        }
    }

    let defaults = ChunkGeometry::default();
    let geometry = match &sidecar.chunking {
        Some(c) => ChunkGeometry {
            max_tokens: c.max_tokens.unwrap_or(defaults.max_tokens),
            overlap_tokens: c.overlap_tokens.unwrap_or(defaults.overlap_tokens),
            min_tokens: c.min_tokens.unwrap_or(defaults.min_tokens),
        },
        None => defaults,
    };
    let max_chars = sidecar.max_chars.unwrap_or(DEFAULT_MAX_CHARS);

    // The sidecar is authoritative — the bound travels WITH the weights so it
    // cannot drift from them. A caller that states a different one is describing
    // a model this is not, so refuse rather than silently truncate the document
    // before the model ever sees it (the reference pipeline refuses here too).
    if config.max_chars != 0 && config.max_chars != max_chars {
        return Err(MlError::LoadFailed(format!(
            "{} declares max_chars = {max_chars}, but the agent config sets [ml] max_chars = {}.              That bound is applied before tokenization, so this configuration would shorten a              document before the model saw it. Set it to {max_chars}, or to 0 to accept whatever              the model declares.",
            config.sidecar.display(),
            config.max_chars
        )));
    }

    // ---- tokenizer -------------------------------------------------------
    let tokenizer = super::chunk::tokenizer_from_file(&config.tokenizer)?;
    // Fail here rather than on the first document: this is what proves the
    // tokenizer wraps rather than rewrites, and that the budget is usable.
    Chunker::new(&tokenizer, geometry)?;

    // ---- ONNX Runtime + session -----------------------------------------
    ensure_runtime(config)?;

    let model_path = config.model.display().to_string();
    let session_error = |e: &dyn std::fmt::Display| MlError::LoadFailed(format!("{model_path}: {e}"));

    // Prefer the SPLIT graphs when they are staged beside the model.
    //
    // `model.onnx` holds the per-chunk mean pooling INSIDE itself, so it can only
    // be run with every chunk of a document at once - ~65 MB of encoder
    // activations per chunk, ~5 GB on a 72-chunk document, which is enough to
    // exhaust an 8 GiB endpoint. The split pair exposes the seam: the encoder
    // emits per-chunk [CLS], we accumulate, and the head runs once. That makes
    // peak memory a function of `micro_batch_size` instead of document length.
    //
    // Falling back to the monolithic graph is deliberate, not laziness: an
    // endpoint staged before the split existed has only `model.onnx`, and must
    // keep classifying rather than reporting `unavailable` (which, with
    // `failBlock`, would block its egress).
    let split = SplitPaths::beside(&config.model);
    let graph = if split.present() {
        let encoder = build_session(config, &split.encoder).map_err(|e| session_error(&e))?;
        let head = build_session(config, &split.head).map_err(|e| session_error(&e))?;
        // The HEAD is what emits logits, so it is the graph whose width must be 29.
        validate_output_width(&head)?;
        Graph::Split {
            sessions: Mutex::new(SplitSessions { encoder, head }),
            micro_batch: if config.micro_batch_size == 0 {
                DEFAULT_MICRO_BATCH_SIZE
            } else {
                config.micro_batch_size
            },
        }
    } else {
        let session = build_session(config, &config.model).map_err(|e| session_error(&e))?;
        validate_output_width(&session)?;
        Graph::Monolithic(Mutex::new(session))
    };

    let model_version = if sidecar.model_version.is_empty() {
        "unknown".to_string()
    } else {
        sidecar.model_version.clone()
    };

    // Counts and identifiers only — never a path to a scanned document, never
    // any text.
    tracing::info!(
        model_version = %model_version,
        labels = labels::LABEL_COUNT,
        max_tokens = geometry.max_tokens,
        overlap = geometry.overlap_tokens,
        max_chars,
        max_chunks = config.max_chunks,
        graph = graph_kind_of(&graph),
        micro_batch = micro_batch_of(&graph),
        "ML classifier loaded"
    );

    Ok(Arc::new(MlEngine {
        tokenizer,
        graph,
        geometry,
        max_chars,
        max_chunks: config.max_chunks,
        model_version,
    }))
}


/// Where the split graphs live relative to `model.onnx`: `<model dir>/onnx_split/`.
///
/// Derived from the model path rather than configured separately, so the three
/// artifacts cannot be pointed at different model versions by a typo in a config
/// file. `split_metadata.json` records the `split_from_sha256` they were carved
/// from; staging is responsible for keeping the set together.
struct SplitPaths {
    encoder: PathBuf,
    head: PathBuf,
}

impl SplitPaths {
    fn beside(model: &Path) -> Self {
        let dir = model.parent().unwrap_or(Path::new(".")).join(SPLIT_DIR);
        SplitPaths {
            encoder: dir.join(ENCODER_FILE),
            head: dir.join(HEAD_FILE),
        }
    }

    /// BOTH or neither. A half-staged pair is treated as absent: running the
    /// encoder without its head is not a partial capability, it is no capability,
    /// and silently falling back is better than failing to load at all.
    fn present(&self) -> bool {
        self.encoder.is_file() && self.head.is_file()
    }
}

/// One session builder for every graph, so the encoder, the head and the
/// monolithic model are all built with identical options. Divergent optimisation
/// levels between the two halves of a split model would be a very quiet way to
/// get different numbers out of the same weights.
fn build_session(config: &MlConfig, path: &Path) -> Result<Session, ort::Error> {
    Session::builder()?
        .with_optimization_level(GraphOptimizationLevel::Level3)?
        .with_intra_threads(config.intra_threads.max(1))?
        .commit_from_file(path)
}

fn graph_kind_of(graph: &Graph) -> &'static str {
    match graph {
        Graph::Monolithic(_) => "monolithic",
        Graph::Split { .. } => "split+microbatched",
    }
}

fn micro_batch_of(graph: &Graph) -> usize {
    match graph {
        // 0 reads as "not applicable": the monolithic graph has no seam to batch at.
        Graph::Monolithic(_) => 0,
        Graph::Split { micro_batch, .. } => *micro_batch,
    }
}

/// The SHA-256 of a model file, lower-case hex, streamed so a 256 MB graph never
/// lands in memory twice.
///
/// Which weights produced a verdict is an audit question — an incident reviewed
/// six months later has to be attributable to a specific graph, not merely to
/// "V6.2.01" — and it is also how `tests/ml_golden.rs` proves the fixture and the
/// weights on disk are a matched pair.
pub fn model_sha256(path: &Path) -> Result<String, MlError> {
    use sha2::Digest as _;
    use std::io::Read as _;

    let io_error = |e: std::io::Error| MlError::LoadFailed(format!("{}: {e}", path.display()));
    let mut file = fs::File::open(path).map_err(io_error)?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let read = file.read(&mut buffer).map_err(io_error)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let mut out = String::with_capacity(64);
    for b in sha2::Digest::finalize(hasher) {
        let _ = write!(out, "{b:02x}");
    }
    Ok(out)
}

/// Refuse a graph whose classification head is not the 29-wide one this build
/// knows how to name. A 28- or 30-class head would run perfectly and report the
/// wrong label for every document.
fn validate_output_width(session: &Session) -> Result<(), MlError> {
    let outlet = session
        .outputs()
        .iter()
        .find(|o| o.name() == LOGITS_OUTPUT)
        .or_else(|| session.outputs().first())
        .ok_or_else(|| MlError::LoadFailed("the graph declares no outputs".into()))?;

    let ValueType::Tensor { shape, .. } = outlet.dtype() else {
        return Err(MlError::LoadFailed(format!("graph output {:?} is not a tensor", outlet.name())));
    };

    match shape.as_ref().last() {
        // A static width must be 29.
        Some(&width) if width >= 0 => {
            if width as usize != labels::LABEL_COUNT {
                let mut dims = String::new();
                let _ = write!(dims, "{:?}", shape.as_ref());
                return Err(MlError::LoadFailed(format!(
                    "graph output {LOGITS_OUTPUT} has shape {dims}; this build only understands a \
                     {}-label head",
                    labels::LABEL_COUNT
                )));
            }
            Ok(())
        }
        // A symbolic width cannot be checked here; MlEngine::run checks the
        // realised width on every single inference, so nothing gets through
        // unvalidated either way.
        _ => Ok(()),
    }
}

/// Where to look for the ONNX Runtime shared library, most specific first.
fn resolve_dylib(config: &MlConfig) -> PathBuf {
    if let Some(explicit) = &config.dylib {
        return explicit.clone();
    }
    // The shipped location, derived from the model path so a caller that built
    // its config by hand still finds it.
    if let Some(root) = config.model.parent().and_then(Path::parent) {
        let beside = root.join("runtime").join(dylib_file_name());
        if beside.is_file() {
            return beside;
        }
    }
    match std::env::var("ORT_DYLIB_PATH") {
        Ok(s) if !s.is_empty() => PathBuf::from(s),
        // A bare file name; `ort` resolves it next to the executable and then
        // through the OS loader search path.
        _ => PathBuf::from(dylib_file_name()),
    }
}

/// Initialise the ONNX Runtime environment exactly once per process.
///
/// Always through `init_from` with a resolved path, never through the implicit
/// `ort::init()`: `ort`'s lazy loader **panics** ("Failed to load ONNX Runtime
/// dylib") the first time an API is touched with no library present, and an
/// agent that aborts because a model file is missing is the opposite of fail
/// secure. `init_from` hands the same failure back as a `Result`, which becomes
/// `status = "unavailable"` and lets the channels apply `failBlock`.
fn ensure_runtime(config: &MlConfig) -> Result<(), MlError> {
    let path = resolve_dylib(config);

    let result = RUNTIME.get_or_init(|| match ort::init_from(&path) {
        Ok(builder) => {
            builder.with_name("dlp-agent").commit();
            Ok(())
        }
        Err(e) => Err(format!("ONNX Runtime shared library: {e}")),
    });

    result.clone().map_err(MlError::LoadFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn softmax_sums_to_one_and_picks_the_max() {
        let p = softmax(&[1.0, 2.0, 3.0]);
        assert!((p.iter().sum::<f64>() - 1.0).abs() < 1e-12);
        assert!(p[2] > p[1] && p[1] > p[0]);
    }

    #[test]
    fn softmax_does_not_overflow_on_a_large_logit() {
        // Without subtracting the max, exp(900) is +inf and every probability
        // becomes NaN — which would then be compared against a policy threshold.
        let p = softmax(&[900.0, 1.0, 2.0]);
        assert!(p.iter().all(|v| v.is_finite()));
        assert!((p[0] - 1.0).abs() < 1e-12);
    }

    #[test]
    fn config_under_a_root_uses_the_shipped_layout() {
        let cfg = MlConfig::under(Path::new("X:/agent/ml"));
        assert!(cfg.model.ends_with("model/model.onnx"));
        assert!(cfg.sidecar.ends_with("model/model.onnx.json"));
        assert!(cfg.tokenizer.ends_with("backbone/tokenizer.json"));
        assert!(!cfg.artifacts_present());
    }

    #[test]
    fn classify_without_a_loaded_engine_is_unavailable_not_a_panic() {
        unload();
        let err = classify("some extracted text").unwrap_err();
        assert_eq!(err.status(), "unavailable");
        assert_eq!(err.reason(), "model_not_loaded");
    }
}
