'use strict';
// =====================================================================
// IDM fingerprinting (Indexed Document Matching) — guide Phase 4 groundwork.
//
// Turns a protected document into a compact, order-robust set of hashes so
// agents can detect when (parts of) it leave the organisation, even after
// reformatting, case changes, or partial copy-paste. Classic pipeline:
//
//   normalize   — NFKC → lowercase → non-alphanumeric runs become one space
//   shingles    — sliding window of k=8 consecutive tokens (overlap k-1)
//   hash        — 64-bit FNV-1a over the UTF-8 bytes of each shingle
//   winnow      — window w=8 over the hash sequence; keep each window's
//                 minimum (rightmost on ties), record only when it changes
//   containment — |distinct(A) ∩ distinct(B)| / |distinct(A)| for detection
//
// DETERMINISM IS A CONTRACT. The Rust agent will be ported against the
// golden vectors in test/fixtures/fingerprint-vectors.json — any change to
// this algorithm is a breaking protocol change and invalidates every stored
// fingerprint. Do not "improve" the math without a migration plan.
//
// Hash representation: FNV-1a yields an unsigned 64-bit value. We expose it
// as a SIGNED 64-bit BigInt (BigInt.asIntN) because fingerprints land in a
// PostgreSQL BIGINT column. Winnowing comparisons are done UNSIGNED
// (BigInt.asUintN) so the selection order matches the raw u64 math the
// agent will use. BigInt is not JSON-safe — serialize hashes as strings.
//
// Pure computation: no DB, no I/O, no state. (The fingerprint storage
// tables arrive in a later migration; this module stays reusable as-is.)
// =====================================================================

const DEFAULT_K = 8; // tokens per shingle
const DEFAULT_W = 8; // winnowing window (in shingles)

const FNV_OFFSET_BASIS = 0xcbf29ce484222325n;
const FNV_PRIME = 0x100000001b3n;
const MASK_64 = 0xffffffffffffffffn;

// ---------------------------------------------------------------------
// 1. Normalization — the only step that touches raw text. Everything
//    downstream sees canonical tokens, so cosmetic edits (case, punctuation,
//    whitespace, Unicode presentation forms) cannot dodge detection.
// ---------------------------------------------------------------------
function normalize(text) {
  const canonical = String(text == null ? '' : text)
    .normalize('NFKC')
    .toLowerCase()
    // Every run of non-alphanumeric chars (Unicode letters/digits) → one space.
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .trim();
  const tokens = canonical.length === 0 ? [] : canonical.split(' ');
  return { canonical, tokens };
}

// ---------------------------------------------------------------------
// 2. Shingles — k-token sliding window (overlap k-1), joined with a single
//    space. A document shorter than k tokens still yields ONE shingle (the
//    whole token string) so short protected snippets remain matchable.
// ---------------------------------------------------------------------
function shinglesOf(tokens, k = DEFAULT_K) {
  if (!Number.isInteger(k) || k < 1) throw new Error('k must be an integer >= 1');
  if (tokens.length === 0) return [];
  if (tokens.length < k) return [tokens.join(' ')];
  const out = [];
  for (let i = 0; i + k <= tokens.length; i++) {
    out.push(tokens.slice(i, i + k).join(' '));
  }
  return out;
}

// ---------------------------------------------------------------------
// 3. Hash — 64-bit FNV-1a over UTF-8 bytes. Non-cryptographic on purpose:
//    fingerprints are not secrets, and the agent needs this cheap and
//    byte-for-byte portable to Rust. Returned SIGNED (see header).
// ---------------------------------------------------------------------
function fnv1a64(str) {
  const bytes = Buffer.from(String(str), 'utf8');
  let h = FNV_OFFSET_BASIS;
  for (let i = 0; i < bytes.length; i++) {
    h ^= BigInt(bytes[i]);
    h = (h * FNV_PRIME) & MASK_64;
  }
  return BigInt.asIntN(64, h);
}

// ---------------------------------------------------------------------
// 4. Winnowing (Schleimer et al.) — guarantees any match of at least
//    w + k - 1 tokens shares a recorded fingerprint, while storing only
//    ~2/(w+1) of all shingle hashes. Rules (the Rust port must mirror them):
//      * compare hashes UNSIGNED;
//      * ties choose the RIGHTMOST minimum in the window;
//      * record a fingerprint only when the min POSITION changes;
//      * fewer than w hashes → keep the single min of what exists.
//    seq is the index of the chosen shingle in the full shingle sequence.
// ---------------------------------------------------------------------
function winnow(hashes, w = DEFAULT_W) {
  if (!Number.isInteger(w) || w < 1) throw new Error('w must be an integer >= 1');
  const n = hashes.length;
  if (n === 0) return [];
  const u = hashes.map((h) => BigInt.asUintN(64, h)); // unsigned view for comparison

  const minIndexIn = (start, end) => {
    // Rightmost minimum in [start, end): <= keeps later equal values.
    let m = start;
    for (let i = start + 1; i < end; i++) {
      if (u[i] <= u[m]) m = i;
    }
    return m;
  };

  if (n < w) {
    const m = minIndexIn(0, n);
    return [{ hash: hashes[m], seq: m }];
  }

  const out = [];
  let prevMin = -1;
  for (let start = 0; start + w <= n; start++) {
    const m = minIndexIn(start, start + w);
    if (m !== prevMin) {
      out.push({ hash: hashes[m], seq: m });
      prevMin = m;
    }
  }
  return out;
}

// ---------------------------------------------------------------------
// 5. Full pipeline.
// ---------------------------------------------------------------------
function fingerprint(text, { k = DEFAULT_K, w = DEFAULT_W } = {}) {
  const { tokens } = normalize(text);
  const shingles = shinglesOf(tokens, k);
  const hashes = shingles.map(fnv1a64);
  return {
    fingerprints: winnow(hashes, w),
    shingleCount: shingles.length,
    tokenCount: tokens.length,
  };
}

// ---------------------------------------------------------------------
// 6. Similarity — distinct-hash set operations used by detection.
//    Accepts fingerprint arrays ([{hash, seq}]), arrays of hashes
//    (BigInt or string), or Sets of hash strings.
// ---------------------------------------------------------------------
function toHashSet(fp) {
  const set = new Set();
  for (const item of fp) {
    if (item !== null && typeof item === 'object' && 'hash' in item) {
      set.add(String(item.hash));
    } else {
      set.add(String(item));
    }
  }
  return set;
}

function intersectionSize(a, b) {
  const [small, large] = a.size <= b.size ? [a, b] : [b, a];
  let n = 0;
  for (const h of small) if (large.has(h)) n++;
  return n;
}

// Fraction of the PROTECTED doc's (A) distinct hashes present in B.
// 1.0 = all of A appears in B. Empty A → 0 (an empty protected doc must
// never match everything — fail secure).
function containment(setA, setB) {
  const a = toHashSet(setA);
  const b = toHashSet(setB);
  if (a.size === 0) return 0;
  return intersectionSize(a, b) / a.size;
}

// containment: how much of protected A shows up in scanned B.
// coverage:    how much of scanned B consists of protected A's material.
function similarity(fpA, fpB) {
  const a = toHashSet(fpA);
  const b = toHashSet(fpB);
  const inter = intersectionSize(a, b);
  return {
    containment: a.size === 0 ? 0 : inter / a.size,
    coverage: b.size === 0 ? 0 : inter / b.size,
  };
}

// BigInt is not JSON-safe — this is the wire/storage form ([{hash: string, seq}]).
function serializeFingerprints(fingerprints) {
  return fingerprints.map((f) => ({ hash: f.hash.toString(), seq: f.seq }));
}

module.exports = {
  normalize,
  shinglesOf,
  fnv1a64,
  winnow,
  fingerprint,
  containment,
  similarity,
  serializeFingerprints,
  DEFAULT_K,
  DEFAULT_W,
};
