//! Shingling, FNV-1a 64 hashing, and winnowing (Schleimer et al.).
//!
//! Port of dlp-management-server/lib/fingerprint.js. Rules the server side
//! pins as protocol (see the golden vectors):
//!   * shingles: k-token sliding window (overlap k-1) joined with one space;
//!     fewer than k tokens → ONE whole-text shingle; no tokens → none;
//!   * hash: 64-bit FNV-1a over the UTF-8 bytes, exposed SIGNED (i64 from the
//!     raw u64 bits — PostgreSQL BIGINT form);
//!   * winnowing: window w over the hash sequence, compare UNSIGNED, ties
//!     choose the RIGHTMOST minimum, record only when the min POSITION
//!     changes; fewer than w hashes → the single min of what exists.

pub const DEFAULT_K: usize = 8; // tokens per shingle
pub const DEFAULT_W: usize = 8; // winnowing window (in shingles)

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// 64-bit FNV-1a over UTF-8 bytes, returned signed (same bits as the u64).
pub fn fnv1a64(s: &str) -> i64 {
    let mut h = FNV_OFFSET_BASIS;
    for &b in s.as_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h as i64
}

/// k-token shingles joined with a single space (overlap k-1). A document
/// shorter than k tokens still yields ONE shingle so short snippets match.
pub fn shingles_of(tokens: &[String], k: usize) -> Vec<String> {
    assert!(k >= 1, "k must be >= 1");
    if tokens.is_empty() {
        return Vec::new();
    }
    if tokens.len() < k {
        return vec![tokens.join(" ")];
    }
    tokens.windows(k).map(|w| w.join(" ")).collect()
}

/// One recorded fingerprint: the shingle hash and its index in the full
/// shingle sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    pub hash: i64,
    pub seq: u32,
}

pub fn winnow(hashes: &[i64], w: usize) -> Vec<Fingerprint> {
    assert!(w >= 1, "w must be >= 1");
    let n = hashes.len();
    if n == 0 {
        return Vec::new();
    }
    // Unsigned view for comparison — selection order must match raw u64 math.
    let u: Vec<u64> = hashes.iter().map(|&h| h as u64).collect();

    // Rightmost minimum in [start, end): <= keeps later equal values.
    let min_index_in = |start: usize, end: usize| {
        let mut m = start;
        for i in start + 1..end {
            if u[i] <= u[m] {
                m = i;
            }
        }
        m
    };

    if n < w {
        let m = min_index_in(0, n);
        return vec![Fingerprint {
            hash: hashes[m],
            seq: m as u32,
        }];
    }

    let mut out = Vec::new();
    let mut prev_min: Option<usize> = None;
    for start in 0..=n - w {
        let m = min_index_in(start, start + w);
        if prev_min != Some(m) {
            out.push(Fingerprint {
                hash: hashes[m],
                seq: m as u32,
            });
            prev_min = Some(m);
        }
    }
    out
}
