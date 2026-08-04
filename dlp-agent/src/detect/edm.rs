//! EDM (Exact Data Match) — agent-side candidate generation, salted lookup,
//! and the v1 proximity rule.
//!
//! The typed normalization and salted hashing are a port of the server's
//! lib/edm.js — DETERMINISM IS A CONTRACT: `hashField` must produce the exact
//! hashes the server stored, or nothing ever matches. Cell hash:
//!   SHA-256(salt || uint16BE(fieldId) || utf8(normalizedValue)),
//!   first 8 bytes big-endian, reinterpreted signed i64 (BIGINT form).
//!
//! Candidate generation works on the ALREADY-normalized token stream (the
//! same `normalize()` used for IDM), so values that punctuation split apart
//! are re-joined here per field type:
//!   text    token n-grams (1..=4) joined with one space — a cell like
//!           "Smith, John" is stored as canonical "smith john";
//!   id      token n-grams (1..=4) concatenated + uppercased ("ab","1234"
//!           → "AB1234" — the server strips non-alphanumerics);
//!   number  single tokens and "int.frac" token pairs through the canonical
//!           digit-string rules;
//!   date    v1: ISO-shaped values only — single ISO-shaped tokens plus
//!           3-token windows re-assembled to yyyy-mm-dd (tokenization splits
//!           every date shape apart, e.g. "1990-07-02" → "1990","07","02").
//!
//! PROXIMITY RULE (fail noisy-safe): one matched cell is not an incident —
//! a row is reported only when >= MIN_MATCHED_FIELDS distinct fields of the
//! SAME (source, row), at least one of them primary, co-occur within a
//! 300-char window of the normalized text.
//!
//! NEVER log candidate values or extracted text here — they are exactly the
//! sensitive data this product protects.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use super::bundle::Bundle;
use super::normalize::{is_letter_or_number, normalize};
use unicode_normalization::UnicodeNormalization;

/// Two matched cells "co-occur" when their first tokens start within this
/// many characters of each other in the normalized text.
pub const PROXIMITY_WINDOW_CHARS: usize = 300;
/// Minimum distinct matched fields of one (source, row) to report the row.
pub const MIN_MATCHED_FIELDS: usize = 2;
/// Longest token n-gram considered when re-assembling text/id candidates.
const MAX_NGRAM_TOKENS: usize = 4;

// ---------------------------------------------------------------------
// Typed normalization (port of lib/edm.js normalizeField)
// ---------------------------------------------------------------------

/// Canonical form per declared type, or None for empty/unparseable cells
/// (never hashed — junk cannot become a match-everything hash).
pub fn normalize_field(value: &str, field_type: &str) -> Option<String> {
    let s = value.trim();
    if s.is_empty() {
        return None;
    }
    match field_type {
        "text" => {
            let n = normalize(s);
            if n.canonical.is_empty() { None } else { Some(n.canonical) }
        }
        "id" => {
            let out: String = s
                .nfkc()
                .filter(|&c| is_letter_or_number(c))
                .collect::<String>()
                .to_uppercase();
            if out.is_empty() { None } else { Some(out) }
        }
        "number" => normalize_number(s),
        "date" => normalize_date(s),
        _ => None,
    }
}

/// Canonical digit string: grouping separators (commas, whitespace,
/// underscores) stripped, no leading zeros, fraction kept but trailing
/// zeros dropped; "-0" never happens.
pub fn normalize_number(s: &str) -> Option<String> {
    let stripped: String = s
        .chars()
        .filter(|&c| c != ',' && c != '_' && !c.is_whitespace())
        .collect();
    let b = stripped.as_bytes();
    let mut i = 0;
    let mut sign = "";
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        if b[i] == b'-' {
            sign = "-";
        }
        i += 1;
    }
    let int_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == int_start {
        return None;
    }
    let int = &stripped[int_start..i];
    let mut frac = "";
    if i < b.len() && b[i] == b'.' {
        i += 1;
        let frac_start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == frac_start {
            return None;
        }
        frac = &stripped[frac_start..i];
    }
    if i != b.len() {
        return None;
    }
    let int = { let t = int.trim_start_matches('0'); if t.is_empty() { "0" } else { t } };
    let frac = frac.trim_end_matches('0');
    let out = if frac.is_empty() { int.to_string() } else { format!("{int}.{frac}") };
    if out == "0" {
        return Some("0".into()); // never '-0'
    }
    Some(format!("{sign}{out}"))
}

const MONTHS: [&str; 12] = [
    "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november", "december",
];

fn month_from_name(word: &str) -> Option<u32> {
    if word.len() < 3 || !word.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    let lower = word.to_ascii_lowercase();
    let month = MONTHS.iter().position(|m| m.starts_with(&lower[..3]))? as u32 + 1;
    // A word longer than the 3-letter abbreviation must be the full name.
    if lower.len() > 3 && lower != MONTHS[(month - 1) as usize] {
        return None;
    }
    Some(month)
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => if is_leap_year(year) { 29 } else { 28 },
        _ => 0,
    }
}

fn to_iso_date(day: u32, month: u32, year: u32) -> Option<String> {
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    Some(format!("{year}-{month:02}-{day:02}"))
}

/// dd/mm/yyyy, dd-mm-yyyy, yyyy-mm-dd, or "dd Mon yyyy" → 'yyyy-mm-dd';
/// None if unparseable (bad shape, bad month, day out of range).
pub fn normalize_date(s: &str) -> Option<String> {
    // Split into runs of ASCII digits / ASCII letters / single separators.
    let b = s.as_bytes();
    let take_digits = |mut i: usize| { let s0 = i; while i < b.len() && b[i].is_ascii_digit() { i += 1; } (s0, i) };

    let (d1s, d1e) = take_digits(0);
    if d1e == d1s {
        return None;
    }
    let d1 = &s[d1s..d1e];

    // "dd Mon yyyy" — digits, whitespace+, ASCII letters (>=3), whitespace+, 4 digits.
    if d1.len() <= 2 && d1e < b.len() && b[d1e].is_ascii_whitespace() {
        let mut i = d1e;
        while i < b.len() && b[i].is_ascii_whitespace() { i += 1; }
        let ws = i;
        while i < b.len() && b[i].is_ascii_alphabetic() { i += 1; }
        let word = &s[ws..i];
        let mut j = i;
        while j < b.len() && b[j].is_ascii_whitespace() { j += 1; }
        let (ys, ye) = take_digits(j);
        if word.len() >= 3 && j > i && ye - ys == 4 && ye == b.len() {
            let month = month_from_name(word)?;
            return to_iso_date(d1.parse().ok()?, month, s[ys..ye].parse().ok()?);
        }
        return None;
    }

    // Numeric shapes: run [/-] run [/-] run.
    if d1e >= b.len() || !(b[d1e] == b'/' || b[d1e] == b'-') {
        return None;
    }
    let sep1 = b[d1e];
    let (d2s, d2e) = take_digits(d1e + 1);
    if d2e == d2s || d2e >= b.len() || !(b[d2e] == b'/' || b[d2e] == b'-') {
        return None;
    }
    let sep2 = b[d2e];
    let (d3s, d3e) = take_digits(d2e + 1);
    if d3e == d3s || d3e != b.len() {
        return None;
    }
    let (d2, d3) = (&s[d2s..d2e], &s[d3s..d3e]);

    if d1.len() <= 2 && d2.len() <= 2 && d3.len() == 4 {
        // dd/mm/yyyy or dd-mm-yyyy (separators may mix, as in the server regex)
        return to_iso_date(d1.parse().ok()?, d2.parse().ok()?, d3.parse().ok()?);
    }
    if d1.len() == 4 && d2.len() <= 2 && d3.len() <= 2 && sep1 == b'-' && sep2 == b'-' {
        // yyyy-mm-dd
        return to_iso_date(d3.parse().ok()?, d2.parse().ok()?, d1.parse().ok()?);
    }
    None
}

// ---------------------------------------------------------------------
// Salted hashing (port of lib/edm.js hashField)
// ---------------------------------------------------------------------

/// SHA-256(salt || uint16BE(fieldId) || utf8(value)), first 8 bytes
/// big-endian, exposed signed (the BIGINT wire form).
pub fn hash_field(salt: &[u8], field_id: u16, normalized_value: &str) -> i64 {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(field_id.to_be_bytes());
    hasher.update(normalized_value.as_bytes());
    let digest = hasher.finalize();
    u64::from_be_bytes(digest[0..8].try_into().unwrap()) as i64
}

pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || s.is_empty() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

// ---------------------------------------------------------------------
// Candidate generation
// ---------------------------------------------------------------------

/// One candidate cell value re-assembled from the token stream, tagged with
/// the char offset of its first token in the canonical text.
struct Candidate {
    value: String,
    pos: usize,
}

fn all_ascii_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Candidate values for one field type over the whole token stream.
/// `starts[i]` is the char offset of `tokens[i]` in the canonical text.
fn candidates_for_type(tokens: &[String], starts: &[usize], field_type: &str) -> Vec<Candidate> {
    let mut out = Vec::new();
    match field_type {
        "text" => {
            for n in 1..=MAX_NGRAM_TOKENS.min(tokens.len()) {
                for i in 0..=tokens.len() - n {
                    out.push(Candidate { value: tokens[i..i + n].join(" "), pos: starts[i] });
                }
            }
        }
        "id" => {
            for n in 1..=MAX_NGRAM_TOKENS.min(tokens.len()) {
                for i in 0..=tokens.len() - n {
                    out.push(Candidate {
                        value: tokens[i..i + n].concat().to_uppercase(),
                        pos: starts[i],
                    });
                }
            }
        }
        "number" => {
            for (i, t) in tokens.iter().enumerate() {
                if let Some(v) = normalize_number(t) {
                    out.push(Candidate { value: v, pos: starts[i] });
                }
                // Decimal split apart by the point: "1234", "5" → "1234.5".
                if i + 1 < tokens.len() && all_ascii_digits(t) && all_ascii_digits(&tokens[i + 1]) {
                    if let Some(v) = normalize_number(&format!("{t}.{}", tokens[i + 1])) {
                        out.push(Candidate { value: v, pos: starts[i] });
                    }
                }
            }
        }
        "date" => {
            for (i, t) in tokens.iter().enumerate() {
                // ISO-shaped single token (v1 rule; defensive — separators
                // normally split dates into the 3-token windows below).
                if let Some(v) = normalize_date(t) {
                    out.push(Candidate { value: v, pos: starts[i] });
                }
                if i + 2 < tokens.len() {
                    if let Some(v) = date_from_window(t, &tokens[i + 1], &tokens[i + 2]) {
                        out.push(Candidate { value: v, pos: starts[i] });
                    }
                }
            }
        }
        _ => {}
    }
    out
}

/// Re-assemble a date from 3 consecutive tokens: (yyyy, m, d), (d, m, yyyy)
/// or (d, mon-name, yyyy) — all canonicalized to ISO yyyy-mm-dd.
fn date_from_window(t0: &str, t1: &str, t2: &str) -> Option<String> {
    if all_ascii_digits(t0) && t0.len() == 4 && all_ascii_digits(t1) && t1.len() <= 2
        && all_ascii_digits(t2) && t2.len() <= 2
    {
        return to_iso_date(t2.parse().ok()?, t1.parse().ok()?, t0.parse().ok()?);
    }
    if all_ascii_digits(t0) && t0.len() <= 2 && all_ascii_digits(t2) && t2.len() == 4 {
        if all_ascii_digits(t1) && t1.len() <= 2 {
            return to_iso_date(t0.parse().ok()?, t1.parse().ok()?, t2.parse().ok()?);
        }
        if let Some(month) = month_from_name(t1) {
            return to_iso_date(t0.parse().ok()?, month, t2.parse().ok()?);
        }
    }
    None
}

// ---------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------

/// One row of an EDM source whose cells were found in the scanned text
/// (proximity rule satisfied). `fields` are the matched field names.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EdmRowHit {
    pub row_id: u32,
    pub fields: Vec<String>,
}

/// All qualifying rows of one EDM source.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EdmSourceHit {
    pub source_id: String,
    pub name: String,
    pub rows_hit: Vec<EdmRowHit>,
}

/// Match the normalized token stream against every EDM source in the bundle.
/// `tokens` must come from the same `normalize()` pass as the IDM matcher.
pub fn match_edm(bundle: &Bundle, tokens: &[String]) -> Vec<EdmSourceHit> {
    if tokens.is_empty() {
        return Vec::new();
    }
    // Char offset of each token in the canonical text (tokens + single spaces).
    let mut starts = Vec::with_capacity(tokens.len());
    let mut pos = 0usize;
    for t in tokens {
        starts.push(pos);
        pos += t.chars().count() + 1;
    }

    let mut hits = Vec::new();
    for (source_index, source) in bundle.header.edm_sources.iter().enumerate() {
        // No salt ⇒ no way to hash candidates ⇒ this source cannot match.
        let Some(salt) = bundle.header.edm_salts.get(&source.source_id).and_then(|h| hex_decode(h))
        else {
            continue;
        };

        // (source, row) → matched cells as (pos, field_id).
        let mut rows: BTreeMap<u32, Vec<(usize, u16)>> = BTreeMap::new();
        for field in &source.fields {
            for cand in candidates_for_type(tokens, &starts, &field.field_type) {
                let hash = hash_field(&salt, field.field_id, &cand.value);
                if !bundle.bloom_has(hash) {
                    continue;
                }
                for entry in bundle.lookup_edm(hash) {
                    if entry.source_index as usize == source_index
                        && entry.field_id == field.field_id
                    {
                        rows.entry(entry.row_id).or_default().push((cand.pos, field.field_id));
                    }
                }
            }
        }

        let primary: BTreeSet<u16> =
            source.fields.iter().filter(|f| f.primary).map(|f| f.field_id).collect();
        let mut rows_hit = Vec::new();
        for (row_id, mut cells) in rows {
            cells.sort_unstable();
            cells.dedup();
            if !row_qualifies(&cells, &primary) {
                continue;
            }
            let field_ids: BTreeSet<u16> = cells.iter().map(|&(_, f)| f).collect();
            let fields = field_ids
                .iter()
                .filter_map(|id| {
                    source.fields.iter().find(|f| f.field_id == *id).map(|f| f.name.clone())
                })
                .collect();
            rows_hit.push(EdmRowHit { row_id, fields });
        }
        if !rows_hit.is_empty() {
            hits.push(EdmSourceHit {
                source_id: source.source_id.clone(),
                name: source.name.clone(),
                rows_hit,
            });
        }
    }
    hits
}

/// Proximity rule: some 300-char window must contain >= MIN_MATCHED_FIELDS
/// distinct fields of this row, at least one of them primary.
/// `cells` is sorted by position.
fn row_qualifies(cells: &[(usize, u16)], primary: &BTreeSet<u16>) -> bool {
    for i in 0..cells.len() {
        let mut fields = BTreeSet::new();
        let mut has_primary = false;
        for &(pos, field_id) in &cells[i..] {
            if pos - cells[i].0 > PROXIMITY_WINDOW_CHARS {
                break;
            }
            fields.insert(field_id);
            has_primary = has_primary || primary.contains(&field_id);
        }
        if fields.len() >= MIN_MATCHED_FIELDS && has_primary {
            return true;
        }
    }
    false
}
