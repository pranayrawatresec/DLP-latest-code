//! FUSION — the unified sensitivity decision. This is the detection engine's
//! single answer to "is this sensitive?", and every channel (kguard write scan,
//! USB, clipboard copy, browser upload) asks it here instead of re-deriving a
//! threshold expression of its own.
//!
//! WHY THE TWO SIGNALS ARE OR-ed, NEVER AND-ed
//! -------------------------------------------
//! The product carries two independent detectors and they are blind in exactly
//! opposite directions:
//!
//! * **Fingerprinting** (`detect::verdict*`) recognises a document somebody
//!   REGISTERED. It can name the leak — "this is v3 of the Himalayan Shield
//!   OPORD, 87% of it" — which is what an incident reviewer needs. It cannot see
//!   a classified document that was never enrolled: a plan drafted this morning,
//!   a paragraph retyped from a briefing, a spreadsheet nobody indexed.
//! * **The classifier** (`ml/`) recognises what KIND of document it is looking
//!   at — NUC, WPN, FIN — without having seen it before. It cannot say which
//!   document leaked, and it will never be as precise as a hash match.
//!
//! AND-ing them would protect only documents that are BOTH registered and
//! classifiable, which is the intersection of two coverage sets — strictly worse
//! than either detector alone, and fail-open by construction. OR-ing them means
//! each detector covers the other's blind spot, which is the whole reason the
//! second signal was added.
//!
//! Consequence, stated as a rule: **ML can only ADD sensitivity. It never
//! downgrades a fingerprint hit.** A registered document at 0.95 containment is
//! sensitive whatever the model thinks it is, whether the model ran, whether the
//! model even loaded. Nothing in this module can turn a fingerprint hit off.
//!
//! PURITY
//! ------
//! [`decide`] is pure: a verdict and the bands the caller is applying go in, a
//! [`Decision`] comes out. It never reads the policy store, never touches the
//! model, does no I/O. The policy question — "is THIS label sensitive at THIS
//! confidence?" — was already answered upstream by
//! `mlpolicy::MlPolicy::label_is_sensitive` and is carried in
//! `verdict.ml.sensitive`; this module only reads that flag. That is what lets
//! one function serve every channel and be exhaustively table-tested
//! (`tests/fusion_decision.rs`) with no fixtures, no model and no server.
//!
//! The impure half — running the model and shaping its answer into an
//! [`MlResult`] — lives at the bottom of this file, clearly fenced off, because
//! all three channels need exactly the same bridge and duplicating it three times
//! is how the fail-secure rules drift apart.

use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;

use super::verdict::{MlResult, Verdict};
use crate::ml;
use crate::mlpolicy;

/// The block bands the CALLING channel is applying. The same fusion serves every
/// channel precisely because the thresholds come from the caller: the kernel
/// read-deny scan uses `[kguard] block_at` (0.30), a write to a non-whitelisted
/// removable device uses the tighter `removable_write_block_at` (0.15), the
/// clipboard and the browser host use their own `[clipboard]` / host defaults.
///
/// An EDM row hit is NOT banded — a matched structured record (a name + a
/// national id on the same row) is a hit at any threshold, in every channel.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bands {
    /// `idm[].containment >= this` ⇒ fingerprint hit.
    pub containment_at: f64,
    /// `idm[].coverage >= this` ⇒ fingerprint hit.
    pub coverage_at: f64,
}

impl Bands {
    pub fn new(containment_at: f64, coverage_at: f64) -> Self {
        Bands { containment_at, coverage_at }
    }
}

/// How bad the hit is, derived from WHICH detectors fired (contract §D). Both
/// detectors agreeing on one file is the strongest evidence the endpoint can
/// produce; the model alone is the weakest, because it is a statement about a
/// category rather than about a known document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Fingerprint AND model.
    Critical,
    /// Fingerprint only — a registered document, named.
    High,
    /// Model only — an unregistered document in a category the admin marked.
    Medium,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The unified answer. `sensitive` is what a channel acts on; `fingerprint`,
/// `ml`, `signal` and `severity` are what an incident reviewer needs to
/// understand WHY, without re-running anything.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    /// `fingerprint || ml` — the OR the module header argues for.
    pub sensitive: bool,
    /// Any EDM row hit, or an IDM match at or over the caller's bands.
    pub fingerprint: bool,
    /// The model hit a label the admin marked, at or over that label's threshold.
    pub ml: bool,
    /// Which detectors fired, in a stable order: `"idm"`, `"edm"`, `"idm+edm"`,
    /// `"ml"`, `"idm+ml"`, `"edm+ml"`, `"idm+edm+ml"`, or `None` for nothing.
    pub signal: Option<String>,
    /// `None` when nothing fired.
    pub severity: Option<Severity>,
}

impl Decision {
    /// Nothing fired — the shape a clean scan produces.
    pub fn clean() -> Self {
        Decision { sensitive: false, fingerprint: false, ml: false, signal: None, severity: None }
    }
}

/// THE fusion (contract §D). Pure — no policy, no model, no I/O.
///
/// `fingerprint` is exactly the expression the channels used to hand-roll
/// (`kguard::should_block` / `should_block_removable_write`,
/// `clipboard::verdict_blocks`, `browser_host::map_verdict`), now stated once:
/// any EDM row hit, or any matched document at/over the caller's containment or
/// coverage band.
///
/// `ml` is read straight off `verdict.ml.sensitive` — the policy answer computed
/// at the classify site. A verdict with no `ml` field (fingerprint-only channel,
/// inert policy, the frozen golden vectors) therefore decides exactly as it did
/// before the model existed.
pub fn decide(verdict: &Verdict, bands: &Bands) -> Decision {
    let edm_hit = !verdict.edm.is_empty();
    let idm_hit = verdict
        .idm
        .iter()
        .any(|m| m.containment >= bands.containment_at || m.coverage >= bands.coverage_at);
    let fingerprint = idm_hit || edm_hit;

    // Belt and braces: `sensitive` is only ever set on a completed
    // classification, but a hand-built MlResult must not be able to smuggle a
    // model hit in on an `unavailable` status.
    let ml = verdict.ml.as_ref().is_some_and(|m| m.is_ok() && m.sensitive);

    let mut parts: Vec<&str> = Vec::with_capacity(3);
    if idm_hit {
        parts.push("idm");
    }
    if edm_hit {
        parts.push("edm");
    }
    if ml {
        parts.push("ml");
    }

    let severity = match (fingerprint, ml) {
        (true, true) => Some(Severity::Critical),
        (true, false) => Some(Severity::High),
        (false, true) => Some(Severity::Medium),
        (false, false) => None,
    };

    Decision {
        sensitive: fingerprint || ml,
        fingerprint,
        ml,
        signal: if parts.is_empty() { None } else { Some(parts.join("+")) },
        severity,
    }
}

// ------------------------------------------------------------------------- //
// The classify bridge — IMPURE. Everything above this line is pure.
// ------------------------------------------------------------------------- //
//
// Running the model needs two process-wide things the frozen `detect::verdict*`
// signatures cannot carry: the console policy (`mlpolicy::active`) and the loaded
// ONNX session (`ml::classify`). Both are published once at startup, exactly like
// the OCR policy, and read inline here — see `src/mlpolicy.rs` for why that
// indirection exists at all.
//
// FAIL-SECURE CONTRACT, in one place so the three channels cannot disagree:
//   * policy inert (off, or no label selected) ⇒ `None`. The classifier
//     contributes NOTHING and the verdict serializes byte-for-byte as a
//     pre-model one. This is the fully-inert state the product ships in.
//   * a prediction ⇒ `status = "ok"`, with `sensitive` decided by
//     `label_is_sensitive` (the label must be one the admin marked AND the
//     confidence must reach that label's own threshold).
//   * no text to classify ⇒ `status = "empty"`. An outcome, not a fault: it
//     must never fail-block, or every image and every empty clipboard would.
//   * anything else (no engine, load failure, inference error) ⇒
//     `status = "unavailable"`. THAT is the state an EGRESS channel weighs
//     `failBlock` against. The kernel read path never does.
//
// Nothing here logs, returns or stores the text it was handed.

/// Classify already-extracted text under the active policy.
///
/// `None` means "the classifier is inert here" — not "clean". Callers must treat
/// it as the model having contributed nothing at all.
pub fn ml_for_text(text: &str) -> Option<MlResult> {
    ml_for_text_inner(text, None)
}

/// [`ml_for_text`], optionally DEPOSITING a successful classification into the
/// verdict cache (contract P4).
///
/// `deposit` is `Some((key, truncated))` when the caller holds the exact bytes
/// the read path will one day be handed for the same file — i.e. the driver's
/// ≤4 MiB prefix on the kguard WRITE scan. That is what makes a file scanned on
/// its way to a USB stick already known when RustDesk later reads it, with no
/// second forward pass.
///
/// Nothing is deposited unless the model actually answered (F2), and the cache
/// stores the MODEL's label, never the policy's `sensitive` conclusion (C2).
fn ml_for_text_inner(
    text: &str,
    deposit: Option<(ml::CacheKey, bool)>,
) -> Option<MlResult> {
    let policy = mlpolicy::active();
    if policy.is_inert() {
        return None;
    }
    let version = policy.model_version.clone();

    match ml::classify(text) {
        Ok(p) => {
            if let Some((key, truncated)) = deposit {
                ml::queue::deposit(key, &p, truncated);
            }
            let sensitive = policy.label_is_sensitive(p.label_id, p.confidence);
            // Metadata only: label, score, counts. NEVER the text.
            tracing::debug!(
                label = p.label_id,
                confidence = p.confidence,
                chunks = p.chunks,
                tokens = p.tokens,
                sensitive,
                "ml classification"
            );
            Some(
                MlResult::classified(
                    &version,
                    p.label_id,
                    p.label_name,
                    p.confidence,
                    sensitive,
                    p.chunks,
                    p.tokens,
                )
                // No-op unless `[ml] max_chunks` capped the document.
                .truncated_from(p.chunks_total),
            )
        }
        Err(e) => {
            // `MlError` already speaks the wire vocabulary (status/reason), so
            // there is no second mapping table to keep in step.
            let status = e.status();
            let reason = e.reason();
            if status == super::verdict::ML_STATUS_UNAVAILABLE {
                tracing::warn!(reason, error = %e, "ml classification unavailable");
            }
            Some(MlResult::not_classified(&version, status, reason))
        }
    }
}

/// Classify a file's BYTES: extract text the same way the fingerprint path does,
/// then classify it.
///
/// The extraction is deliberately repeated rather than plumbed out of
/// `verdict_bytes` — that function is frozen and its signature may not grow an
/// out-parameter. `filename` picks the extractor by extension and is never
/// content; `content` is never logged.
///
/// Unextractable content (an encrypted zip, an image, an unsupported container)
/// yields `status = "empty"`, NOT `unavailable`: the model is fine, there is
/// simply nothing to read, so it must not fail-block. The channels' existing
/// unreadable-content rules already cover that case.
pub fn ml_for_bytes(content: &[u8], filename: &str) -> Option<MlResult> {
    let policy = mlpolicy::active();
    if policy.is_inert() {
        return None;
    }
    match super::extract::extract_text(content, filename) {
        Ok(extracted) => ml_for_text(&extracted.text),
        Err(_) => Some(MlResult::empty(&policy.model_version)),
    }
}

/// [`ml_for_bytes`] that also DEPOSITS its answer in the verdict cache
/// (contract P4).
///
/// `content` MUST be exactly the bytes the kernel read path will be handed for
/// the same file — the driver's `min(file_size, DLP_MAX_CONTENT)` prefix — or the
/// key minted here can never be produced by a lookup and the deposit is dead
/// weight. `truncated` is the driver's own flag (the file was longer than the
/// prefix) and is stored for reporting only; it does not enter the key, because
/// the key IS the prefix.
///
/// Callers that hold something else (a whole file read in user mode, a clipboard
/// buffer, a browser upload) must keep using [`ml_for_bytes`]: a wrong key is
/// worse than no key, since it silently fills the cache with entries that never
/// hit.
pub fn ml_for_bytes_caching(content: &[u8], filename: &str, truncated: bool) -> Option<MlResult> {
    let policy = mlpolicy::active();
    if policy.is_inert() {
        return None;
    }

    // LOOK UP BEFORE CLASSIFYING.
    //
    // The write scan runs inside the driver's CLEANUP up-call, and the driver
    // enforces a block by DELETING the file it has already written to the media
    // (detect-and-quarantine: `DlpQuarantineFile` sets FileDispositionInformation).
    // So the file exists on the stick for exactly as long as this verdict takes.
    //
    // Fingerprinting answers in single-digit milliseconds, and the file is gone
    // before Explorer redraws. A cold ML answer is extraction + tokenize + chunk +
    // a DistilBERT forward pass, which is long enough for Explorer to enumerate
    // and cache the entry - leaving a GHOST FILE that the user can see but not
    // open ("the file is not present"). Same block, worse experience, and it
    // looks like a product defect.
    //
    // A cache hit collapses that to a SHA-256 plus a HashMap lookup, which puts
    // the ML path back in the same latency class as fingerprinting. The at-rest
    // walker and the at-creation watcher exist precisely so that a document a
    // user is about to copy has already been classified - this is where that
    // investment is spent. It also stops the endpoint re-running inference on
    // the same bytes every time somebody copies them.
    match ml_from_cache(content, filename) {
        CacheOutcome::Hit(hit) => return Some(hit),
        // Inert was already handled above; a miss falls through to classify.
        CacheOutcome::Inert | CacheOutcome::Miss => {}
    }

    match super::extract::extract_text(content, filename) {
        Ok(extracted) => ml_for_text_inner(
            &extracted.text,
            Some((ml::VerdictCache::key_for(content), truncated)),
        ),
        Err(_) => Some(MlResult::empty(&policy.model_version)),
    }
}

/// Classify a file ON DISK (a clipboard file-drop, a `scan_file` upload).
///
/// The inertness check comes FIRST so a switched-off policy costs no read at all;
/// the file is then read once more than the fingerprint path already read it,
/// which is the price of leaving `detect::verdict(path)` frozen. A read failure
/// is `empty`, not `unavailable`: the channel's own unreadable-file rule already
/// covers a file we cannot open, and the model is not at fault.
pub fn ml_for_path(path: &std::path::Path) -> Option<MlResult> {
    let policy = mlpolicy::active();
    if policy.is_inert() {
        return None;
    }
    let filename = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    match std::fs::read(path) {
        Ok(bytes) => ml_for_bytes(&bytes, &filename),
        Err(_) => Some(MlResult::empty(&policy.model_version)),
    }
}

/// The kernel READ up-call's ML result: the model is deliberately not run.
///
/// `DLP_REASON_READ` is synchronous — the filesystem stack is blocked on our
/// reply — and a DistilBERT forward pass costs tens of milliseconds per chunk.
/// Recording the skip explicitly (rather than omitting `ml`) tells a reviewer the
/// read was decided on fingerprints ALONE and that no model failure is hiding
/// behind a clean verdict. `None` while the policy is inert, so an endpoint with
/// the feature off still produces byte-identical read verdicts.
///
/// SUPERSEDED ON THE KGUARD READ BRANCH by [`read_path_ml`], which keeps the
/// "never run the model here" rule and adds the one thing that was missing: a
/// LOOKUP of what an off-path producer already learned about these exact bytes.
/// This function stays because it is the definition of the pre-cache behaviour
/// — the thing an inert policy and a cache-less process must remain identical to
/// — and because a channel that has no cache key to offer still needs it.
pub fn ml_read_path_skip() -> Option<MlResult> {
    let policy = mlpolicy::active();
    if policy.is_inert() {
        return None;
    }
    Some(MlResult::skipped(
        &policy.model_version,
        super::verdict::ML_REASON_READ_PATH_SKIP,
    ))
}

// ------------------------------------------------------------------------- //
// The READ path — a cache LOOKUP, never an inference.
// ------------------------------------------------------------------------- //
//
// `ml_read_path_skip` above is what the read up-call did before this cache
// existed, and it is still exactly what it does while the policy is inert. What
// follows is the addition: when the policy IS live, the read consults what an
// off-path producer (the at-creation watcher, the at-rest walker, this file's
// own WRITE-path deposit, or the on-demand queue) already learned about these
// bytes. A lookup is a hash of the driver's buffer plus a `HashMap` read —
// microseconds — so the 500 ms kernel budget and the single-threaded message
// loop are both untouched.

/// `ml.reason` for content the model has not seen yet.
///
/// Distinct from [`ML_REASON_READ_PATH_SKIP`](super::verdict::ML_REASON_READ_PATH_SKIP),
/// which means "we deliberately did not run the model on this path". This one
/// means "we looked, and nobody has classified these bytes" — a coverage gap a
/// reviewer can act on (the walker has not reached this file) rather than a
/// design decision.
pub const ML_REASON_NOT_CLASSIFIED: &str = "not_classified";

/// What a read-path cache consultation found. Three cases, spelled out, so that
/// a caller physically cannot conflate "nobody has classified this" with "the
/// model said it is fine" (contract F1).
#[derive(Debug, Clone, PartialEq)]
pub enum CacheOutcome {
    /// The console policy is inert. The classifier contributes NOTHING and the
    /// verdict must serialize byte-for-byte as a pre-model one (F3).
    Inert,
    /// A cached answer for exactly these bytes, from the model version currently
    /// in force, with `sensitive` computed against the CURRENT policy.
    Hit(MlResult),
    /// No usable entry: never classified, or classified by a different model
    /// (C3), or the entry failed its HMAC and was discarded. **Not** "clean".
    Miss,
}

/// Consult the verdict cache for content the driver already handed us.
///
/// `content` is the driver's `min(file_size, DLP_MAX_CONTENT)` prefix — the same
/// bytes every off-path producer hashes via `ml::read_prefix_for_hashing`, which
/// is what makes the keys meet at all (C1). `filename` is used only for the
/// debug trace's extension; it is never a full path and never logged above
/// debug.
///
/// A HIT's `sensitive` is evaluated HERE, against the policy loaded right now —
/// never read back from the entry, which does not store one. That is the whole
/// point of C2: an admin who marks a new label sensitive, or lowers a threshold,
/// changes the answer for every already-cached file on the estate on the next
/// read, with no reclassification and no invalidation.
///
/// This function NEVER runs the model and never enqueues: the caller decides
/// what a miss costs, because only the caller knows whether it is on the kernel
/// hot loop.
pub fn ml_from_cache(content: &[u8], filename: &str) -> CacheOutcome {
    let policy = mlpolicy::active();
    if policy.is_inert() {
        return CacheOutcome::Inert;
    }
    let cache = match ml::queue::verdict_cache() {
        Some(c) => c,
        // No cache wired in this process: every read is a miss, i.e. exactly the
        // pre-cache behaviour. Fail-safe by construction (F1).
        None => return CacheOutcome::Miss,
    };

    let key = ml::VerdictCache::key_for(content);
    let version = ml::queue::model_version_for_cache();
    match cache.get(&key, &version) {
        Some(v) => {
            let sensitive = policy.label_is_sensitive(&v.label_id, v.confidence);
            let label_name = ml::labels::LABELS
                .iter()
                .find(|l| l.id == v.label_id)
                .map(|l| l.name)
                .unwrap_or("");
            tracing::debug!(
                filename,
                label = %v.label_id,
                confidence = v.confidence,
                sensitive,
                "ml verdict cache hit on the read path"
            );
            // A hit is an ANSWER: status "ok", no reason. "cached" is
            // deliberately NOT part of the status vocabulary — where the answer
            // came from is an implementation detail, and a channel that started
            // treating "cached" as second-class would reintroduce exactly the
            // fail-open gap this cache closes.
            CacheOutcome::Hit(MlResult::classified(
                &v.model_version,
                &v.label_id,
                label_name,
                v.confidence,
                sensitive,
                v.chunks,
                v.tokens,
            ))
        }
        None => CacheOutcome::Miss,
    }
}

/// The `ml` field a caller attaches on a MISS when it is NOT denying
/// unclassified content: the model has contributed nothing, and the read is
/// decided on fingerprints alone — today's behaviour, stated explicitly rather
/// than by omitting `ml`, so a reviewer can tell a coverage gap from a clean
/// classification.
///
/// `None` while the policy is inert, so an endpoint with the feature off still
/// produces byte-identical read verdicts (F3).
pub fn ml_unclassified_result() -> Option<MlResult> {
    let policy = mlpolicy::active();
    if policy.is_inert() {
        return None;
    }
    Some(MlResult::skipped(
        &policy.model_version,
        ML_REASON_NOT_CLASSIFIED,
    ))
}

/// `denyUnclassified` — deny a read of content nobody has classified yet.
///
/// **The default is false and that is not negotiable.** Turning it on before the
/// at-rest walker has covered an endpoint denies the FIRST read of every legacy
/// file on it; the supported rollout is deploy → walker completes → verify
/// coverage → enable. It exists because the alternative, for a site that demands
/// it, is a window in which a document the model would call sensitive can be
/// read out by RustDesk/AnyDesk/RDP purely because nothing had classified it yet.
///
/// Three gates, all of which must hold:
/// * the console policy is LIVE (an inert policy changes nothing, anywhere — F3);
/// * the flag is set;
/// * the on-demand worker is RUNNING. Without it a denial can never heal: the
///   content would never be classified, so every read of that file would be
///   denied for ever. That is a pure outage with no security gain, so a missing
///   worker disables the deny rather than bricking the endpoint.
///
/// PLUMBING NOTE: the flag is held here as a process-wide atomic rather than as
/// an `MlPolicy` field because `src/mlpolicy.rs` belongs to another change in
/// flight. When it grows the `denyUnclassified` wire field, `main.rs::activate_ml`
/// should call [`set_deny_unclassified`] beside `mlpolicy::set_active`, and this
/// shim becomes a one-line read of the policy.
static DENY_UNCLASSIFIED: AtomicBool = AtomicBool::new(false);

/// Publish the `denyUnclassified` policy flag for this process.
pub fn set_deny_unclassified(on: bool) {
    DENY_UNCLASSIFIED.store(on, Ordering::Relaxed);
}

/// Whether THIS endpoint has finished a discovery sweep, and may therefore honour
/// `denyUnclassified`. Published by the walker; see [`deny_unclassified`].
static SWEEP_COMPLETED: AtomicBool = AtomicBool::new(false);

/// Publish that a full discovery sweep has completed on this endpoint.
///
/// Called by the walker when it records a [`crate::ml::walk::SweepCompletion`], and
/// at startup from the persisted completion record so a restart does not un-arm a
/// machine that was already covered.
pub fn set_sweep_completed(done: bool) {
    SWEEP_COMPLETED.store(done, Ordering::Relaxed);
}

/// Should a read-path cache MISS be denied? See [`set_deny_unclassified`].
///
/// THE LOCAL INTERLOCK. `denyUnclassified` is one console switch applied to a whole
/// fleet, but "has this machine been classified yet" is a per-ENDPOINT fact, and the
/// console cannot know it. A laptop that enrolled an hour ago has a nearly empty
/// verdict cache: honouring the switch there denies the first read of essentially
/// every document on the machine.
///
/// So the endpoint holds its own veto. The switch takes effect here only once THIS
/// machine has completed a full discovery sweep — the same fact `ml-status` prints
/// and the runbook tells an operator to check. An admin who enables it fleet-wide on
/// Monday morning arms the covered machines and leaves the rest on their previous
/// behaviour until their sweep finishes, instead of denying the estate at once.
///
/// This can only ever make the feature LESS aggressive than the console asked for,
/// never more, so it cannot introduce a fail-open: a miss with the switch off is
/// still the pre-cache fingerprint-only answer, never "clean".
pub fn deny_unclassified() -> bool {
    DENY_UNCLASSIFIED.load(Ordering::Relaxed)
        && SWEEP_COMPLETED.load(Ordering::Relaxed)
        && !mlpolicy::active().is_inert()
        && ml::queue::running()
}

/// The READ up-call's ML step: CONSULT the verdict cache, never run the model.
///
/// Returns `(ml_field_to_attach, cache_miss)`.
///
/// * inert policy ⇒ `(None, false)` — byte-identical to the pre-cache
///   `decide::ml_read_path_skip()`, which is also `None` when inert (contract F3).
/// * HIT ⇒ `(Some(ok result), false)`, `sensitive` computed against the policy
///   loaded RIGHT NOW, so a console change takes effect on the whole estate
///   without reclassifying anything (C2).
/// * MISS ⇒ `(Some(skipped/not_classified), true)`, and the bytes are handed to
///   the background classifier so the NEXT read of the same content hits.
///
/// `content` is the driver's ≤4 MiB prefix, borrowed from the message loop's
/// reusable receive buffer — hence the explicit `to_vec()` on the enqueue path
/// (contract P3): the buffer is zeroed and refilled by the next
/// `FilterGetMessage`. The enqueue itself is bounded and never waits.
///
/// Cross-platform and free of kernel types on purpose, so the read-path rules are
/// table-tested without a driver (`tests/ml_readpath.rs`).
pub fn read_path_ml(content: &[u8], filename: &str) -> (Option<MlResult>, bool) {
    match ml_from_cache(content, filename) {
        CacheOutcome::Inert => (None, false),
        CacheOutcome::Hit(r) => (Some(r), false),
        CacheOutcome::Miss => {
            ml::queue::enqueue(content.to_vec(), filename.to_string());
            (ml_unclassified_result(), true)
        }
    }
}

/// PURE: what the READ branch replies once both detection halves have spoken.
/// `None` is `DLP_VERDICT_NOVERDICT`.
///
/// `deny_unclassified` is the policy answer from [`deny_unclassified`], which is
/// already gated on the policy
/// being live AND the background classifier running — a denial nothing can ever
/// clear is an outage, not a control. With the flag clear (the shipped default)
/// this is the identity `Some(block)`, i.e. exactly the pre-cache behaviour.
///
/// `!block` first, deliberately: when the fingerprint or ML half already says
/// BLOCK, `Some(true)` is strictly better than NOVERDICT — the driver caches the
/// decision and seeds `DlpBadHashInsert`, and the caller's incident names the
/// document. NOVERDICT is reserved for the genuinely-unknown case: the driver
/// denies per `ExfilReadFailBlock`, caches NOTHING, and the next read of the same
/// file up-calls again — by which time the queued classification has made the
/// answer authoritative. Per `comms.c` a NOVERDICT reply does not count toward
/// the IPC circuit breaker, so this can never trip the machine into its fail mode.
///
/// NO INCIDENT accompanies a `None`, on purpose. A deny-because-unclassified is
/// "we do not know yet", not a detection (contract F5), and since the driver
/// caches nothing the same file re-up-calls on every read attempt until the queue
/// drains — an incident here would be one per READ, and on the day an admin
/// enables the flag, one per legacy file on every endpoint. The operator signal
/// is the RATE, which `ml::queue::note_deny_unclassified` counts and logs
/// aggregated. A real detection still raises its ordinary incident.
///
/// PURE, unlike the rest of this section: it is the one rule the kguard READ
/// branch applies after both halves have spoken, and it is table-tested without
/// a driver in `tests/ml_readpath.rs`.
pub fn read_path_reply(block: bool, cache_miss: bool, deny_unclassified: bool) -> Option<bool> {
    if cache_miss && !block && deny_unclassified {
        None
    } else {
        Some(block)
    }
}

/// EGRESS fail-secure: should this channel block because the model owed an answer
/// and could not give one?
///
/// True only when the policy is live, the result says `unavailable`, and the
/// policy's `failBlock` is set. Call it ONLY on egress paths (write to removable,
/// clipboard copy, web upload) — NEVER on the kernel read path, where a model
/// that will not load would otherwise deny every file read on the endpoint.
pub fn ml_fail_blocks(ml: Option<&MlResult>) -> bool {
    match ml {
        Some(r) if r.is_unavailable() => {
            let p = mlpolicy::active();
            // Inertness is checked FIRST: `fail_block` defaults to true, so an
            // inert policy whose `fail_block` was never cleared must not be able
            // to block anything. Off means off.
            !p.is_inert() && p.fail_block
        }
        _ => false,
    }
}

/// The ML half of an EGRESS block, in one expression:
///
/// * a model hit (`sensitive`) blocks only when the console policy's `action` is
///   `block` — under `audit` the hit is still recorded, still fuses into
///   [`Decision::sensitive`] and still raises an incident, it just does not stop
///   the copy. A brand-new signal must not silently start denying work;
/// * an `unavailable` model blocks per `failBlock` (see [`ml_fail_blocks`]).
///
/// Deliberately NOT usable on the kernel read path: the read path never runs the
/// model, so its `ml` is `skipped`, for which this returns false anyway — but the
/// rule is "read never fail-blocks", so the read path simply does not call this.
pub fn ml_blocks_egress(ml: Option<&MlResult>) -> bool {
    let policy = mlpolicy::active();
    // Off means off — see [`ml_fail_blocks`].
    if policy.is_inert() {
        return false;
    }
    match ml {
        Some(r) if r.is_ok() && r.sensitive => policy.blocks(),
        Some(r) if r.is_unavailable() => policy.fail_block,
        _ => false,
    }
}

/// The ML half of a kernel READ-path deny — [`ml_blocks_egress`] minus the
/// fail-block arm.
///
/// The read up-call and an egress copy differ in exactly one way, and it is worth
/// stating precisely because getting it wrong in either direction is severe:
///
/// * a POSITIVE hit denies the read. The verdict cache exists so that a document
///   the model called NUC — classified at creation, or by the discovery sweep, or
///   by the previous read's self-heal — is stopped when RustDesk, AnyDesk or an
///   RDP session reads it. Discarding a positive answer here is discarding the
///   entire pipeline: the file goes out with no block and no incident;
/// * an `unavailable` model does NOT. A model that will not load must never turn
///   every file read on the endpoint into a denial. That asymmetry is the whole
///   reason this is a separate function rather than a flag on the egress one —
///   the previous version expressed it as `reason != READ && ml_blocks_egress(..)`,
///   which threw the positive answer away along with the fail-block arm.
///
/// The unclassified case is not decided here at all: a read whose content the
/// model has never seen is [`read_path_reply`]'s business (`denyUnclassified`),
/// and reaches this function as `skipped`/`empty`, for which it returns false.
pub fn ml_blocks_read(ml: Option<&MlResult>) -> bool {
    let policy = mlpolicy::active();
    if policy.is_inert() {
        return false;
    }
    match ml {
        Some(r) if r.is_ok() && r.sensitive => policy.blocks(),
        // NOTE the deliberate absence of an `is_unavailable` arm.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{EdmRowHit, EdmSourceHit, Extraction, IdmMatch};

    fn bands() -> Bands {
        Bands::new(0.30, 0.60)
    }

    fn clean_verdict() -> Verdict {
        Verdict {
            file_name: "f.txt".into(),
            file_sha256: "sha".into(),
            extraction: Extraction::Ok { format: "text".into() },
            idm: Vec::new(),
            edm: Vec::new(),
            ml: None,
        }
    }

    fn with_idm(containment: f64, coverage: f64) -> Verdict {
        let mut v = clean_verdict();
        v.idm.push(IdmMatch {
            version_id: "v".into(),
            document_id: "d".into(),
            collection_id: "c".into(),
            title: "Plan".into(),
            containment,
            coverage,
            matched_count: 1,
            total_count: 1,
            matched_hashes: vec!["1".into()],
        });
        v
    }

    fn with_edm(mut v: Verdict) -> Verdict {
        v.edm.push(EdmSourceHit {
            source_id: "s".into(),
            name: "PII".into(),
            rows_hit: vec![EdmRowHit { row_id: 1, fields: vec!["full_name".into()] }],
        });
        v
    }

    fn ml_hit(sensitive: bool) -> MlResult {
        MlResult::classified("V6.2.01", "NUC", "Nuclear & Strategic Systems", 0.99, sensitive, 1, 24)
    }

    #[test]
    fn nothing_fires_is_clean() {
        let d = decide(&clean_verdict(), &bands());
        assert_eq!(d, Decision::clean());
        assert!(!d.sensitive);
        assert!(d.signal.is_none());
        assert!(d.severity.is_none());
    }

    #[test]
    fn idm_over_band_is_high() {
        let d = decide(&with_idm(0.9, 0.0), &bands());
        assert!(d.sensitive && d.fingerprint && !d.ml);
        assert_eq!(d.signal.as_deref(), Some("idm"));
        assert_eq!(d.severity, Some(Severity::High));
    }

    #[test]
    fn idm_under_band_does_not_fire() {
        let d = decide(&with_idm(0.10, 0.10), &bands());
        assert!(!d.sensitive);
        assert!(d.signal.is_none());
    }

    #[test]
    fn coverage_band_fires_independently_of_containment() {
        let d = decide(&with_idm(0.01, 0.75), &bands());
        assert!(d.fingerprint);
        assert_eq!(d.signal.as_deref(), Some("idm"));
    }

    #[test]
    fn edm_row_hit_is_unbanded() {
        // No IDM match at all, and an EDM row hit still fires at any band.
        let d = decide(&with_edm(clean_verdict()), &Bands::new(1.0, 1.0));
        assert!(d.fingerprint);
        assert_eq!(d.signal.as_deref(), Some("edm"));
        assert_eq!(d.severity, Some(Severity::High));
    }

    #[test]
    fn ml_only_is_medium() {
        let mut v = clean_verdict();
        v.ml = Some(ml_hit(true));
        let d = decide(&v, &bands());
        assert!(d.sensitive && d.ml && !d.fingerprint);
        assert_eq!(d.signal.as_deref(), Some("ml"));
        assert_eq!(d.severity, Some(Severity::Medium));
    }

    #[test]
    fn both_signals_are_critical_in_stable_order() {
        let mut v = with_edm(with_idm(0.9, 0.9));
        v.ml = Some(ml_hit(true));
        let d = decide(&v, &bands());
        assert_eq!(d.signal.as_deref(), Some("idm+edm+ml"));
        assert_eq!(d.severity, Some(Severity::Critical));
    }

    #[test]
    fn ml_never_downgrades_a_fingerprint_hit() {
        // The model is confidently sure this is PUBLIC information; the document
        // is still a 95%-containment match of a registered plan.
        let mut v = with_idm(0.95, 0.95);
        v.ml = Some(MlResult::classified(
            "V6.2.01",
            "PUB",
            "Public Information",
            1.0,
            false,
            1,
            10,
        ));
        let d = decide(&v, &bands());
        assert!(d.sensitive, "ML can only add sensitivity, never remove it");
        assert_eq!(d.severity, Some(Severity::High));
        assert_eq!(d.signal.as_deref(), Some("idm"));
    }

    #[test]
    fn unavailable_ml_is_not_a_model_hit() {
        let mut v = clean_verdict();
        v.ml = Some(MlResult::unavailable("V6.2.01", "model_not_loaded"));
        let d = decide(&v, &bands());
        assert!(!d.sensitive, "an unavailable model detects nothing (failBlock is a channel rule)");
        assert!(d.signal.is_none());
    }

    #[test]
    fn sensitive_flag_on_a_non_ok_status_is_ignored() {
        let mut v = clean_verdict();
        let mut bogus = MlResult::unavailable("V6.2.01", "load_failed");
        bogus.sensitive = true; // must not be believed
        v.ml = Some(bogus);
        assert!(!decide(&v, &bands()).ml);
    }

    #[test]
    fn tighter_removable_band_fires_where_the_read_band_does_not() {
        let v = with_idm(0.20, 0.0);
        assert!(!decide(&v, &Bands::new(0.30, 0.60)).fingerprint, "read band 0.30");
        assert!(decide(&v, &Bands::new(0.15, 0.60)).fingerprint, "removable-write band 0.15");
    }
}
