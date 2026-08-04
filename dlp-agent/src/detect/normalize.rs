//! Text normalization — the only step that ever touches raw text.
//!
//! Port of `normalize()` in dlp-management-server/lib/fingerprint.js:
//!
//!   NFKC → lowercase (full Unicode mapping) → every run of characters that
//!   are NOT Unicode letters/numbers becomes one space → trim → split.
//!
//! "Letter or number" means Unicode general categories L* and N* exactly,
//! matching the JS `/[^\p{L}\p{N}]+/gu` class. Do NOT use
//! `char::is_alphanumeric` here — that tests the Alphabetic property, which
//! is broader than L* (e.g. some marks/circled letters), and would silently
//! diverge from the server's fingerprints.

use unicode_normalization::UnicodeNormalization;
use unicode_properties::{GeneralCategoryGroup, UnicodeGeneralCategory};

/// Canonical form + tokens, mirroring the JS `{ canonical, tokens }` return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalized {
    pub canonical: String,
    pub tokens: Vec<String>,
}

/// General categories L* (letters) and N* (numbers) — `/\p{L}\p{N}/u` semantics.
/// Shared with edm.rs, whose `id` normalization uses the same class.
pub(crate) fn is_letter_or_number(c: char) -> bool {
    matches!(
        c.general_category_group(),
        GeneralCategoryGroup::Letter | GeneralCategoryGroup::Number
    )
}

pub fn normalize(text: &str) -> Normalized {
    let mut canonical = String::with_capacity(text.len());
    // Pending separator: emit a single space only between kept characters,
    // which also gives us the JS `.trim()` for free (no leading/trailing space).
    let mut pending_space = false;
    for c in text.nfkc().flat_map(char::to_lowercase) {
        if is_letter_or_number(c) {
            if pending_space && !canonical.is_empty() {
                canonical.push(' ');
            }
            pending_space = false;
            canonical.push(c);
        } else {
            pending_space = true;
        }
    }
    let tokens = if canonical.is_empty() {
        Vec::new()
    } else {
        canonical.split(' ').map(str::to_owned).collect()
    };
    Normalized { canonical, tokens }
}
