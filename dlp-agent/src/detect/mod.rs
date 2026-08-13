//! IDM fingerprinting (Indexed Document Matching) — Rust port of the server's
//! lib/fingerprint.js, guide Phase 4 groundwork.
//!
//! Pipeline: normalize → k-token shingles → FNV-1a 64 → winnow → containment.
//!
//! DETERMINISM IS A CONTRACT. This port is gated byte-for-byte by the golden
//! vectors in dlp-management-server/test/fixtures/fingerprint-vectors.json
//! (see tests/golden_vectors.rs). Any change to the math here or on the
//! server is a breaking protocol change that invalidates every stored
//! fingerprint — do not "improve" it without a migration plan.
//!
//! Pure computation: no I/O, no network, no state.

pub mod bundle;
pub mod edm;
pub mod extract;
pub mod normalize;
pub mod shingle;
pub mod verdict;

pub use bundle::Bundle;
pub use edm::{match_edm, EdmRowHit, EdmSourceHit};
pub use extract::{extract_text, ExtractedText, Reason, Unreadable};
pub use normalize::{normalize, Normalized};
pub use shingle::{fnv1a64, shingles_of, winnow, Fingerprint, DEFAULT_K, DEFAULT_W};
pub use verdict::{verdict, verdict_bytes, verdict_text, Extraction, IdmMatch, Verdict};

use std::collections::HashSet;

/// Result of the full pipeline, mirroring the JS `fingerprint()` return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintResult {
    pub fingerprints: Vec<Fingerprint>,
    pub shingle_count: usize,
    pub token_count: usize,
}

/// Full pipeline: normalize → shingles → hashes → winnow.
pub fn fingerprint(text: &str, k: usize, w: usize) -> FingerprintResult {
    let normalized = normalize(text);
    let shingles = shingles_of(&normalized.tokens, k);
    let hashes: Vec<i64> = shingles.iter().map(|s| fnv1a64(s)).collect();
    FingerprintResult {
        fingerprints: winnow(&hashes, w),
        shingle_count: shingles.len(),
        token_count: normalized.tokens.len(),
    }
}

fn to_hash_set(fp: &[Fingerprint]) -> HashSet<i64> {
    fp.iter().map(|f| f.hash).collect()
}

fn intersection_size(a: &HashSet<i64>, b: &HashSet<i64>) -> usize {
    let (small, large) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    small.iter().filter(|h| large.contains(h)).count()
}

/// Fraction of the PROTECTED doc's (A) distinct hashes present in B.
/// 1.0 = all of A appears in B. Empty A → 0 (an empty protected doc must
/// never match everything — fail secure).
pub fn containment(fp_a: &[Fingerprint], fp_b: &[Fingerprint]) -> f64 {
    let a = to_hash_set(fp_a);
    if a.is_empty() {
        return 0.0;
    }
    let b = to_hash_set(fp_b);
    intersection_size(&a, &b) as f64 / a.len() as f64
}

/// containment: how much of protected A shows up in scanned B.
/// coverage:    how much of scanned B consists of protected A's material.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Similarity {
    pub containment: f64,
    pub coverage: f64,
}

pub fn similarity(fp_a: &[Fingerprint], fp_b: &[Fingerprint]) -> Similarity {
    let a = to_hash_set(fp_a);
    let b = to_hash_set(fp_b);
    let inter = intersection_size(&a, &b);
    Similarity {
        containment: if a.is_empty() { 0.0 } else { inter as f64 / a.len() as f64 },
        coverage: if b.is_empty() { 0.0 } else { inter as f64 / b.len() as f64 },
    }
}
