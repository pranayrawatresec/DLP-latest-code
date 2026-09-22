//! A faithful Rust port of the classifier's document chunker.
//!
//! Why a port and not "something close"
//! ------------------------------------
//! Chunk geometry is the one place in this pipeline where a disagreement is
//! *silent*. An off-by-one in the overlap carry, a sentence regex that splits one
//! character earlier, a block separator that swallows one newline too many — none
//! of them error. They change the token ids the encoder sees, which changes the
//! pooled representation, which changes the label, which changes whether a
//! document is blocked at a USB port. So this module mirrors
//! `Document_classification/ai_classifier/training/chunking.py` structure for
//! structure — `_token_units` / `_split_until_it_fits` / `_pack` / `_carry_over` /
//! `_extend_short_tail` are all here under the same names — so the two can be read
//! side by side, and `tests/ml_chunker.rs` gates the result against the frozen
//! fixture the Python reference generated.
//!
//! What it does (contract PREPROCESSING step 4), at V6.2.01 geometry:
//! content budget = max_tokens(512) − specials(2) = 510, overlap = min(64, 510/2)
//! = 64, min_tokens = 32.
//!
//! 1. split the text into blank-line **blocks**; a block that still exceeds the
//!    budget descends to **lines**, then **sentences**, then a **hard split** of
//!    the token ids, which cannot fail and is what makes coverage unconditional.
//!    A split that yields ≤ 1 part descends a level instead of recursing on the
//!    same text forever.
//! 2. pack whole units greedily in document order. When a unit will not fit, close
//!    the chunk and seed the next one with the **carry-over** — the last `overlap`
//!    tokens of the chunk just closed — so a sentence straddling a boundary is
//!    seen whole at least once.
//! 3. while the carried head plus the unit still exceeds the budget, **trim the
//!    head from the left**.
//! 4. if there are ≥ 2 chunks and the last holds fewer than `min_tokens`, replace
//!    it with the tail of the flat token stream. (Unreachable at V6.2.01 geometry
//!    — overlap 64 > min_tokens 32 makes the shortest reachable final chunk 65
//!    content tokens — but the geometry is read from the sidecar, so a future
//!    model with `overlap < min_tokens` does reach it. Ported, not assumed away.)
//! 5. wrap each chunk in the tokenizer's own special tokens, which are *measured*
//!    rather than assumed — see [`Chunker::new`].
//!
//! Pure: no I/O, no logging, no global state, and it never sees a filename, a
//! path or a label. Text in, token ids out.

use std::fmt;
use std::path::Path;

use sha2::{Digest, Sha256};

/// The characters Python's `SENTENCE_PATTERN` = `(?<=[.!?])\s+` looks behind for.
const SENTENCE_TERMINATORS: [char; 3] = ['.', '!', '?'];

/// Anything the chunker can refuse to do. All of it is a broken artifact —
/// a tokenizer that cannot encode, or one whose special tokens leave no room —
/// never a property of the document.
#[derive(Debug, Clone)]
pub enum ChunkError {
    /// The tokenizer itself failed on a fragment.
    Encode(String),
    /// `max_tokens` leaves no room for content after the special tokens, or the
    /// tokenizer rewrites content instead of wrapping it (so chunk ids could not
    /// be assembled by hand).
    Geometry(String),
}

impl fmt::Display for ChunkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChunkError::Encode(m) => write!(f, "tokenizer failed: {m}"),
            ChunkError::Geometry(m) => write!(f, "unusable chunk geometry: {m}"),
        }
    }
}

impl std::error::Error for ChunkError {}

/// How a document is cut up. Mirrors `ChunkingSettings`; only the fields
/// inference actually consumes are carried (`micro_batch_size`, `aggregation`
/// and the training-only flags belong to the exporter, and the graph already
/// performs the mean pooling).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkGeometry {
    /// Ceiling for one chunk *including* the special tokens the backbone adds.
    pub max_tokens: usize,
    /// How many tokens of the previous chunk are repeated at the head of the
    /// next. Zero disables overlap.
    pub overlap_tokens: usize,
    /// The shortest a *final* chunk may be before it is extended backwards.
    pub min_tokens: usize,
}

impl Default for ChunkGeometry {
    /// V6.2.01, as `model/model.onnx.json` declares it. Repeated here so a
    /// sidecar missing a key fails at the wrong-answer level rather than
    /// silently chunking to some library default.
    fn default() -> Self {
        ChunkGeometry { max_tokens: 512, overlap_tokens: 64, min_tokens: 32 }
    }
}

/// The one tokenizer call the chunker makes.
///
/// `DocumentChunker` in Python uses exactly one tokenizer API —
/// `tok(text, add_special_tokens=…)["input_ids"]` — and nothing else: no masks,
/// no offsets, no padding, no batching. Naming that one call as a trait is what
/// lets `tests/ml_chunker.rs` drive the chunker with a stub and, more usefully,
/// keeps this module free of any dependency on the model being present.
pub trait Encoder {
    /// Token ids for a fragment. `add_special_tokens` is used exactly twice: once
    /// with `true` at construction, to *measure* what the tokenizer wraps a
    /// sequence in, and `false` for every fragment thereafter, because a chunk is
    /// packed from many fragments and wrapped exactly once.
    fn encode_ids(&self, text: &str, add_special_tokens: bool) -> Result<Vec<i64>, ChunkError>;
}

/// Load `tokenizer.json` off disk.
///
/// Wrapped rather than used directly by callers so that nothing outside this
/// module has to name the `tokenizers` crate: the chunker's whole interface to
/// it is [`Encoder`], and keeping it that way is what lets a test drive the
/// chunker with a stub.
pub fn tokenizer_from_file(path: &Path) -> Result<tokenizers::Tokenizer, ChunkError> {
    tokenizers::Tokenizer::from_file(path)
        .map_err(|e| ChunkError::Encode(format!("{}: {e}", path.display())))
}

impl Encoder for tokenizers::Tokenizer {
    fn encode_ids(&self, text: &str, add_special_tokens: bool) -> Result<Vec<i64>, ChunkError> {
        if text.is_empty() {
            return Ok(Vec::new());
        }
        let encoding = self
            .encode(text, add_special_tokens)
            .map_err(|e| ChunkError::Encode(e.to_string()))?;
        Ok(encoding.get_ids().iter().map(|&id| id as i64).collect())
    }
}

/// Turns a document's full text into backbone-sized chunks. Holds the tokenizer
/// and the budget; chunks any number of documents and keeps nothing between calls.
pub struct Chunker<'t> {
    tokenizer: &'t dyn Encoder,
    /// What the tokenizer prepends — `[CLS]` (101) for this WordPiece backbone,
    /// but measured, never named.
    prefix: Vec<i64>,
    /// What the tokenizer appends — `[SEP]` (102) here.
    suffix: Vec<i64>,
    /// How many *content* tokens fit in one chunk, after the specials.
    pub content_budget: usize,
    /// The effective carry-over, clamped so a chunk always makes progress.
    pub overlap: usize,
    min_tokens: usize,
}

impl<'t> Chunker<'t> {
    /// Resolve the content budget for a tokenizer.
    ///
    /// The special tokens are **measured** rather than assumed, by encoding one
    /// probe both ways and reading off what the tokenizer added — exactly what
    /// `_special_token_affixes` does. Hard-coding 101/102 here would bake BERT's
    /// convention into a module that has no other opinion about the backbone, and
    /// would not notice the day the exported tokenizer.json changes its
    /// post-processor.
    pub fn new(tokenizer: &'t dyn Encoder, geometry: ChunkGeometry) -> Result<Self, ChunkError> {
        let (prefix, suffix) = Self::special_token_affixes(tokenizer)?;

        let reserved = prefix.len() + suffix.len();
        let content_budget = geometry.max_tokens.saturating_sub(reserved);
        if content_budget < 1 {
            return Err(ChunkError::Geometry(format!(
                "max_tokens={} leaves no room for content after {reserved} special tokens",
                geometry.max_tokens
            )));
        }

        // Overlap must leave room for progress. An overlap equal to the budget
        // would carry the whole previous chunk forward and never advance.
        let overlap = geometry.overlap_tokens.min(content_budget / 2);

        Ok(Chunker { tokenizer, prefix, suffix, content_budget, overlap, min_tokens: geometry.min_tokens })
    }

    /// Discover what a tokenizer wraps a sequence in: encode one probe with and
    /// without special tokens and locate the bare ids inside the wrapped ones.
    fn special_token_affixes(tokenizer: &dyn Encoder) -> Result<(Vec<i64>, Vec<i64>), ChunkError> {
        const PROBE: &str = "chunk boundary probe";
        let bare = tokenizer.encode_ids(PROBE, false)?;
        let wrapped = tokenizer.encode_ids(PROBE, true)?;

        if bare.is_empty() {
            return Err(ChunkError::Geometry("the tokenizer produced no tokens for a probe string".into()));
        }
        if wrapped.len() < bare.len() {
            return Err(ChunkError::Geometry(
                "the tokenizer's encoding with special tokens is shorter than without them".into(),
            ));
        }

        for start in 0..=(wrapped.len() - bare.len()) {
            if wrapped[start..start + bare.len()] == bare[..] {
                return Ok((wrapped[..start].to_vec(), wrapped[start + bare.len()..].to_vec()));
            }
        }

        Err(ChunkError::Geometry(
            "could not determine which special tokens this tokenizer adds: its encoding with \
             special tokens does not contain its encoding without them"
                .into(),
        ))
    }

    /// Add the backbone's special tokens around one chunk's content.
    fn wrap(&self, ids: &[i64]) -> Vec<i64> {
        let mut out = Vec::with_capacity(self.prefix.len() + ids.len() + self.suffix.len());
        out.extend_from_slice(&self.prefix);
        out.extend_from_slice(ids);
        out.extend_from_slice(&self.suffix);
        out
    }

    // ----------------------------------------------------------------- //
    // Public
    // ----------------------------------------------------------------- //

    /// Split one document's text into chunks of token ids, in document order,
    /// each already wrapped in the backbone's special tokens. Empty only when the
    /// text holds no tokens at all.
    pub fn chunk(&self, text: &str) -> Result<Vec<Vec<i64>>, ChunkError> {
        let units = self.token_units(text)?;
        if units.is_empty() {
            return Ok(Vec::new());
        }

        let packed = self.pack(&units);
        let packed = self.extend_short_tail(packed, &units);

        Ok(packed.iter().map(|ids| self.wrap(ids)).collect())
    }

    /// How many content tokens a text holds, before any chunking — the
    /// `tokenCount` the fixture records and the `tokens` field of the verdict.
    /// Special tokens excluded.
    pub fn count_tokens(&self, text: &str) -> Result<usize, ChunkError> {
        Ok(self.encode(text)?.len())
    }

    // ----------------------------------------------------------------- //
    // Splitting into units
    // ----------------------------------------------------------------- //

    /// Token ids for a fragment, without special tokens.
    fn encode(&self, text: &str) -> Result<Vec<i64>, ChunkError> {
        if text.is_empty() {
            return Ok(Vec::new());
        }
        self.tokenizer.encode_ids(text, false)
    }

    /// Break text into the smallest units that will not be split further. Each
    /// returned unit is guaranteed to fit inside one chunk, so [`Self::pack`]
    /// never has to split anything itself.
    fn token_units(&self, text: &str) -> Result<Vec<Vec<i64>>, ChunkError> {
        let mut units: Vec<Vec<i64>> = Vec::new();

        for block in split_blocks(text) {
            if block.trim().is_empty() {
                continue;
            }
            units.extend(self.split_until_it_fits(block, 0)?);
        }

        units.retain(|u| !u.is_empty());
        Ok(units)
    }

    /// Split one fragment as far as necessary for it to fit the budget.
    ///
    /// `level` names the boundary that *produced* this fragment: 0 a block (split
    /// it into lines next), 1 a line (sentences next), 2 or more a sentence —
    /// there is nothing weaker left, so the token ids are split directly. Each
    /// level is a weaker semantic boundary than the last and is only reached for
    /// when the one above did not do the job.
    fn split_until_it_fits(&self, text: &str, level: u8) -> Result<Vec<Vec<i64>>, ChunkError> {
        let ids = self.encode(text)?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        if ids.len() <= self.content_budget {
            return Ok(vec![ids]);
        }

        let (parts, next): (Vec<&str>, u8) = match level {
            0 => (text.split('\n').filter(|p| !p.trim().is_empty()).collect(), 1),
            1 => (split_sentences(text).into_iter().filter(|p| !p.trim().is_empty()).collect(), 2),
            // The fragment is one indivisible run of text longer than a whole
            // chunk — a table row with no spaces, a base64 blob. Split the ids
            // directly. This cannot fail, which is what makes full coverage
            // unconditional.
            _ => {
                return Ok(ids.chunks(self.content_budget).map(<[i64]>::to_vec).collect());
            }
        };

        // A split that produced one part did not split anything; descend rather
        // than recursing on the same text forever.
        if parts.len() <= 1 {
            return self.split_until_it_fits(text, next);
        }

        let mut units: Vec<Vec<i64>> = Vec::new();
        for part in parts {
            units.extend(self.split_until_it_fits(part, next)?);
        }
        Ok(units)
    }

    // ----------------------------------------------------------------- //
    // Packing units into chunks
    // ----------------------------------------------------------------- //

    /// Greedily fill chunks with whole units, in order. Units are never
    /// reordered, never sampled and never skipped: chunk *i* ends where chunk
    /// *i+1* begins, save for the overlap deliberately repeated between them.
    fn pack(&self, units: &[Vec<i64>]) -> Vec<Vec<i64>> {
        let mut chunks: Vec<Vec<i64>> = Vec::new();
        let mut current: Vec<i64> = Vec::new();

        for unit in units {
            if !current.is_empty() && current.len() + unit.len() > self.content_budget {
                let carried = self.carry_over(&current);
                chunks.push(std::mem::replace(&mut current, carried));
            }

            // A unit that cannot fit even a fresh chunk was already split by
            // split_until_it_fits, so this only trims the carried overlap — from
            // the LEFT, keeping the tokens nearest the incoming unit.
            while !current.is_empty() && current.len() + unit.len() > self.content_budget {
                let keep = self.content_budget - unit.len();
                current.drain(..current.len() - keep);
            }

            current.extend_from_slice(unit);
        }

        if !current.is_empty() {
            chunks.push(current);
        }

        chunks
    }

    /// The tail of a chunk, repeated at the head of the next one.
    fn carry_over(&self, chunk: &[i64]) -> Vec<i64> {
        if self.overlap == 0 {
            return Vec::new();
        }
        chunk[chunk.len().saturating_sub(self.overlap)..].to_vec()
    }

    /// Give a stubby final chunk more preceding context.
    ///
    /// The fragment is extended *backwards* into text that already appeared in
    /// the previous chunk, so nothing is added and nothing is removed — the tail
    /// simply arrives with context.
    fn extend_short_tail(&self, mut chunks: Vec<Vec<i64>>, units: &[Vec<i64>]) -> Vec<Vec<i64>> {
        if chunks.len() < 2 || self.min_tokens == 0 {
            return chunks;
        }
        if chunks[chunks.len() - 1].len() >= self.min_tokens {
            return chunks;
        }

        // Rebuild the tail from the flat token stream so the extension can cross
        // unit boundaries.
        let flat: Vec<i64> = units.iter().flatten().copied().collect();
        let wanted = self.min_tokens.min(self.content_budget).min(flat.len());
        let last = chunks.len() - 1;
        chunks[last] = flat[flat.len() - wanted..].to_vec();
        chunks
    }
}

/// A stable digest of exactly what the model was shown, and nothing else.
///
/// The construction is fixed by `tools/ml-reference/README.md` so Rust and the
/// Python reference agree character for character:
///
/// 1. take the **final** token ids of each chunk — `[CLS]`/`[SEP]` included,
///    padding excluded (padding belongs to the batch, not to a chunk);
/// 2. within a chunk, render each id in decimal and join with `,`;
/// 3. join the chunks with `;`, in document order;
/// 4. SHA-256 of that string's UTF-8 bytes, lower-case hex.
///
/// So `[[101, 5, 6, 102], [101, 7, 102]]` hashes `"101,5,6,102;101,7,102"`.
///
/// This is how `tests/ml_chunker.rs` asserts on every token of a 64-chunk
/// document in 64 characters, and it is safe to log: token ids of a chunking are
/// a one-way digest, never the text.
pub fn chunk_ids_sha256(chunks: &[Vec<i64>]) -> String {
    let mut hasher = Sha256::new();
    for (i, chunk) in chunks.iter().enumerate() {
        if i > 0 {
            hasher.update(b";");
        }
        for (j, id) in chunk.iter().enumerate() {
            if j > 0 {
                hasher.update(b",");
            }
            hasher.update(id.to_string().as_bytes());
        }
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// --------------------------------------------------------------------- //
// The two splitters Python expresses as regexes
// --------------------------------------------------------------------- //
//
// Rust's `regex` crate has no look-behind, and pulling a backtracking engine into
// an air-gapped agent to spell two splits is not a trade worth making — so both
// are scanned by hand, with the Python semantics stated at each step and pinned
// by the unit tests at the bottom of this file.
//
// One documented, deliberate difference: Python's `\s` for `str` patterns matches
// what `str.isspace()` matches, which additionally includes the C0 separators
// U+001C..U+001F; Rust's `char::is_whitespace` is the Unicode `White_Space`
// property, which does not. Extracted document text does not contain file/group/
// record/unit separators, and the golden vectors cover the accented-Latin and CJK
// cases where the two could realistically differ.

/// `re.split(r"\n\s*\n", text)` — the blank-line block boundary.
///
/// Python's engine is leftmost-first with backtracking: at the first `\n` it lets
/// `\s*` take the whole whitespace run and then backs off to the LAST `\n` in it,
/// so `"a\n \n \nb"` separates on `"\n \n \n"` and yields `["a", "b"]`. This
/// reproduces that: find the last newline in the maximal whitespace run that
/// starts at a newline; if the run holds no second newline, no match starts here.
pub fn split_blocks(text: &str) -> Vec<&str> {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut parts: Vec<&str> = Vec::new();
    let mut prev_byte = 0usize;
    let mut k = 0usize;

    while k < chars.len() {
        if chars[k].1 != '\n' {
            k += 1;
            continue;
        }

        // The maximal whitespace run starting at this newline.
        let mut end = k;
        while end < chars.len() && chars[end].1.is_whitespace() {
            end += 1;
        }

        // `\s*` greedy, then backtrack to the last `\n` it can give back.
        let last_newline = (k + 1..end).rev().find(|&m| chars[m].1 == '\n');

        match last_newline {
            Some(j) => {
                let sep_start = chars[k].0;
                let sep_end = chars[j].0 + chars[j].1.len_utf8();
                parts.push(&text[prev_byte..sep_start]);
                prev_byte = sep_end;
                k = j + 1;
            }
            // No second newline: the match fails here and the scan moves on one
            // position, exactly as the regex engine would.
            None => k += 1,
        }
    }

    parts.push(&text[prev_byte..]);
    parts
}

/// `re.split(r"(?<=[.!?])\s+", text)` — the sentence boundary.
///
/// A match is a maximal run of whitespace whose preceding character is `.`, `!`
/// or `?`. (Inside such a run every later position fails the look-behind, because
/// the character before it is whitespace — so only run *starts* can match, and
/// `\s+` being greedy consumes the whole run.) We split AFTER the punctuation,
/// which is what the look-behind means: the terminator stays with the sentence it
/// ends.
pub fn split_sentences(text: &str) -> Vec<&str> {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut parts: Vec<&str> = Vec::new();
    let mut prev_byte = 0usize;
    let mut k = 0usize;

    while k < chars.len() {
        if !chars[k].1.is_whitespace() {
            k += 1;
            continue;
        }
        let preceded = k > 0 && SENTENCE_TERMINATORS.contains(&chars[k - 1].1);
        if !preceded {
            k += 1;
            continue;
        }

        let mut end = k;
        while end < chars.len() && chars[end].1.is_whitespace() {
            end += 1;
        }

        let sep_start = chars[k].0;
        let sep_end = if end < chars.len() { chars[end].0 } else { text.len() };
        parts.push(&text[prev_byte..sep_start]);
        prev_byte = sep_end;
        k = end;
    }

    parts.push(&text[prev_byte..]);
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic stand-in for the real tokenizer: one id per character,
    /// wrapped in 101/102 the way the WordPiece backbone does. It lets the packer,
    /// the carry-over and the tail extension be exercised with token arithmetic a
    /// reader can do in their head, and with no 460 KB tokenizer.json in the loop.
    struct CharEncoder;

    impl Encoder for CharEncoder {
        fn encode_ids(&self, text: &str, add_special_tokens: bool) -> Result<Vec<i64>, ChunkError> {
            if text.is_empty() {
                return Ok(Vec::new());
            }
            let mut ids: Vec<i64> = text.chars().map(|c| 1000 + (c as i64 % 100)).collect();
            if add_special_tokens {
                let mut wrapped = vec![101];
                wrapped.append(&mut ids);
                wrapped.push(102);
                return Ok(wrapped);
            }
            Ok(ids)
        }
    }

    fn chunker(max_tokens: usize, overlap: usize, min_tokens: usize) -> Chunker<'static> {
        Chunker::new(
            &CharEncoder,
            ChunkGeometry { max_tokens, overlap_tokens: overlap, min_tokens },
        )
        .expect("geometry")
    }

    #[test]
    fn specials_are_measured_not_assumed() {
        let c = chunker(512, 64, 32);
        assert_eq!(c.prefix, vec![101]);
        assert_eq!(c.suffix, vec![102]);
        assert_eq!(c.content_budget, 510);
        assert_eq!(c.overlap, 64);
    }

    #[test]
    fn overlap_is_clamped_to_half_the_budget() {
        // budget 10 -> overlap can never exceed 5, or a chunk never advances.
        let c = chunker(12, 64, 32);
        assert_eq!(c.content_budget, 10);
        assert_eq!(c.overlap, 5);
    }

    // ---- split_blocks: the `\n\s*\n` equivalence ------------------------- //

    #[test]
    fn blocks_split_on_a_blank_line() {
        assert_eq!(split_blocks("a\n\nb"), vec!["a", "b"]);
        assert_eq!(split_blocks("a\nb"), vec!["a\nb"]);
        assert_eq!(split_blocks("a"), vec!["a"]);
        assert_eq!(split_blocks(""), vec![""]);
    }

    #[test]
    fn blocks_consume_the_whole_whitespace_run_back_to_the_last_newline() {
        // Python: re.split(r"\n\s*\n", "a\n \n \nb") == ["a", "b"]
        assert_eq!(split_blocks("a\n \n \nb"), vec!["a", "b"]);
        // Trailing spaces after the last newline belong to the NEXT block, since
        // `\s*` had to give them back to reach a `\n`.
        assert_eq!(split_blocks("a\n\n  b"), vec!["a", "  b"]);
        // Four newlines are one separator, not two.
        assert_eq!(split_blocks("a\n\n\n\nb"), vec!["a", "b"]);
    }

    #[test]
    fn a_lone_newline_inside_spaces_is_not_a_block_boundary() {
        assert_eq!(split_blocks("a\n   b"), vec!["a\n   b"]);
    }

    #[test]
    fn blocks_are_utf8_safe() {
        // Multi-byte characters either side of the separator must not panic and
        // must slice on character boundaries.
        assert_eq!(split_blocks("café\n\n漢字"), vec!["café", "漢字"]);
    }

    // ---- split_sentences: the `(?<=[.!?])\s+` equivalence ---------------- //

    #[test]
    fn sentences_split_after_the_terminator() {
        assert_eq!(split_sentences("One. Two! Three? Four"), vec!["One.", "Two!", "Three?", "Four"]);
    }

    #[test]
    fn whitespace_not_preceded_by_a_terminator_is_not_a_boundary() {
        assert_eq!(split_sentences("one two three"), vec!["one two three"]);
        assert_eq!(split_sentences("v1 2 3"), vec!["v1 2 3"]);
    }

    #[test]
    fn a_run_of_whitespace_after_a_terminator_is_one_boundary() {
        assert_eq!(split_sentences("One.   Two."), vec!["One.", "Two."]);
        assert_eq!(split_sentences("One.\n\tTwo."), vec!["One.", "Two."]);
    }

    #[test]
    fn a_trailing_terminator_and_space_yields_an_empty_tail_like_python() {
        // Python: re.split(r"(?<=[.!?])\s+", "One. ") == ["One.", ""]
        assert_eq!(split_sentences("One. "), vec!["One.", ""]);
    }

    #[test]
    fn a_terminator_with_no_following_whitespace_is_not_a_boundary() {
        // "3.14" must not become two sentences.
        assert_eq!(split_sentences("pi is 3.14 exactly."), vec!["pi is 3.14 exactly."]);
    }

    #[test]
    fn sentences_are_utf8_safe() {
        assert_eq!(split_sentences("¿Qué? Sí. Ünicode"), vec!["¿Qué?", "Sí.", "Ünicode"]);
    }

    // ---- packing, carry-over, trimming, tail extension ------------------- //

    #[test]
    fn a_short_document_is_one_wrapped_chunk() {
        let c = chunker(512, 64, 32);
        let chunks = c.chunk("hello").unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 7); // [CLS] + 5 + [SEP]
        assert_eq!(chunks[0][0], 101);
        assert_eq!(*chunks[0].last().unwrap(), 102);
    }

    #[test]
    fn a_second_chunk_is_seeded_with_the_carry_over() {
        // budget 10, overlap 5. Two units of 8 chars separated by a blank line:
        // unit A fills 8; unit B does not fit (8+8 > 10) so the chunk closes and
        // the next one starts with A's last 5 tokens, then trims from the LEFT to
        // make room for B: keep = 10-8 = 2.
        let c = chunker(12, 5, 0);
        let a = "aaaaaaaa";
        let b = "bbbbbbbb";
        let chunks = c.chunk(&format!("{a}\n\n{b}")).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 10); // 101 + 8 + 102
        assert_eq!(chunks[1].len(), 12); // 101 + (2 carried + 8) + 102
        // The carried head is the TAIL of chunk 0's content, so both carried ids
        // are 'a' ids and everything after them is 'b'.
        let a_id = 1000 + ('a' as i64 % 100);
        let b_id = 1000 + ('b' as i64 % 100);
        assert_eq!(chunks[1][1], a_id);
        assert_eq!(chunks[1][2], a_id);
        assert_eq!(chunks[1][3], b_id);
    }

    #[test]
    fn an_indivisible_run_longer_than_a_chunk_is_hard_split() {
        // One block, one line, one "sentence" of 25 characters with budget 10:
        // levels 0 and 1 cannot split it, so level 2+ splits the ids: 10/10/5.
        let c = chunker(12, 0, 0);
        let chunks = c.chunk(&"x".repeat(25)).unwrap();
        assert_eq!(chunks.iter().map(|k| k.len() - 2).collect::<Vec<_>>(), vec![10, 10, 5]);
    }

    #[test]
    fn a_short_final_chunk_is_extended_from_the_flat_stream() {
        // budget 10, NO overlap (so the tail really can be short), min_tokens 4.
        // Units: 10 chars then 1 char -> chunks [10], [1]; the 1-token tail is
        // replaced by the last 4 tokens of the flat 11-token stream.
        let c = chunker(12, 0, 4);
        let chunks = c.chunk(&format!("{}\n\n{}", "a".repeat(10), "b")).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[1].len(), 6); // 101 + 4 + 102
        let a_id = 1000 + ('a' as i64 % 100);
        let b_id = 1000 + ('b' as i64 % 100);
        assert_eq!(&chunks[1][1..5], &[a_id, a_id, a_id, b_id]);
    }

    #[test]
    fn the_tail_extension_never_fires_at_v6_2_01_geometry() {
        // overlap(64) > min_tokens(32) makes the shortest reachable final chunk
        // 65 content tokens. Reproduce the worst case the reference identified —
        // unit lengths (510, 1) — and confirm it.
        let c = chunker(512, 64, 32);
        let chunks = c.chunk(&format!("{}\n\n{}", "a".repeat(510), "b")).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[1].len() - 2, 65);
    }

    #[test]
    fn whitespace_only_text_produces_no_chunks() {
        let c = chunker(512, 64, 32);
        assert!(c.chunk("   \n\n \t ").unwrap().is_empty());
        assert!(c.chunk("").unwrap().is_empty());
    }

    #[test]
    fn chunk_ids_digest_matches_the_documented_construction() {
        // The example spelled out in tools/ml-reference/README.md: the ids of
        // [[101,5,6,102],[101,7,102]] hash the string "101,5,6,102;101,7,102".
        let expected = {
            let mut h = Sha256::new();
            h.update(b"101,5,6,102;101,7,102");
            h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        assert_eq!(chunk_ids_sha256(&[vec![101, 5, 6, 102], vec![101, 7, 102]]), expected);
    }

    #[test]
    fn count_tokens_excludes_specials() {
        let c = chunker(512, 64, 32);
        assert_eq!(c.count_tokens("hello").unwrap(), 5);
    }
}
