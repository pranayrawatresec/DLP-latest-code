//! Trusted-reader allowlist — the "allowlist posture" for read-deny.
//!
//! Read-deny (kernel `DlpPreRead`) denies an **exfil-channel process** the read
//! of sensitive content. In the default *blocklist* posture the agent decides a
//! process is an exfil channel by SIGNATURE / behaviour (see [`crate::exfil`]).
//! That never scales against unknown tools, so this module implements the
//! *allowlist* posture instead:
//!
//! > A process is treated as an **untrusted reader** (pushed to the driver,
//! > subject to read-deny) unless it matches the admin-authored
//! > **sanctioned-reader allowlist** — a small, stable set of applications
//! > allowed to read sensitive content locally (Office, the PDF reader, the OS,
//! > AV, backup, the DLP agent itself), identified by **Authenticode publisher**,
//! > **image path prefix**, or **image base name**.
//!
//! Why publisher/path over image name: the name alone is trivially spoofed
//! (`rustdesk.exe` → `notepad2.exe`), so the robust identity is the code-signing
//! **publisher** ("malware cannot sign as Microsoft") or a non-user-writable
//! **path** (`C:\Program Files\…`, `C:\Windows\…`). Name matching is offered too
//! for cases the site controls tightly (e.g. paired with WDAC/AppLocker).
//!
//! This module is **pure and cross-platform**: it holds the rule types (local
//! TOML `[[trusted_readers]]` and the server-sync wire shape) plus the matching
//! decision. The OS side — enumerating processes, resolving image paths, and
//! extracting the Authenticode signer — lives in [`crate::exfil`]
//! (`#[cfg(windows)]`), so the matching logic here is unit-tested without a live
//! process table or a signed binary.

use serde::Deserialize;

/// A normalized sanctioned-reader matcher. Produced from a local
/// [`TrustedReaderRule`] or a synced [`SyncedReader`]; consumed by the exfil
/// classifier. Case-insensitive throughout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReaderMatch {
    /// Authenticode signer subject common-name, e.g. `"Microsoft Corporation"`.
    /// Matches only a process whose image is trusted-signed AND whose signer CN
    /// equals this value. An unsigned / unverifiable image never matches.
    Publisher(String),
    /// Image path prefix at a path-component boundary, e.g.
    /// `C:\Program Files\Microsoft Office`. Backslash/forward-slash agnostic.
    Path(String),
    /// Image base name, e.g. `winword.exe`.
    Name(String),
}

impl ReaderMatch {
    /// Does deciding this matcher require the (expensive) Authenticode signer
    /// lookup? Only [`ReaderMatch::Publisher`] does — so the classifier can test
    /// the cheap path/name matchers first and only verify a signature when a
    /// publisher rule might still sanction the process.
    pub fn needs_publisher(&self) -> bool {
        matches!(self, ReaderMatch::Publisher(_))
    }

    /// Does this matcher sanction a process with the given image path and
    /// (optional, already-extracted) signer publisher? `publisher == None` means
    /// the image is unsigned / the signer could not be verified — a
    /// [`ReaderMatch::Publisher`] rule then does NOT match (fail-safe: an
    /// unverifiable binary is never sanctioned by publisher).
    pub fn matches(&self, image_path: &str, publisher: Option<&str>) -> bool {
        match self {
            ReaderMatch::Publisher(want) => {
                publisher.map(|p| eq_ci(p, want)).unwrap_or(false)
            }
            ReaderMatch::Path(prefix) => path_has_prefix(image_path, prefix),
            ReaderMatch::Name(name) => eq_ci(base_name(image_path), name),
        }
    }
}

/// True when `image_path` (any process) is sanctioned by ANY rule in `rules`.
/// `publisher` is the already-extracted signer CN (or `None` if unsigned /
/// unverifiable). Pure — the full-matcher form the tests exercise; the live
/// classifier ([`crate::exfil`]) applies the same predicate but defers the
/// signer lookup until a publisher rule is actually in play.
pub fn is_sanctioned(image_path: &str, publisher: Option<&str>, rules: &[ReaderMatch]) -> bool {
    rules.iter().any(|r| r.matches(image_path, publisher))
}

// ---------------------------------------------------------------------------
// Pure matching helpers.
// ---------------------------------------------------------------------------

fn eq_ci(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// Final path component of `image_path`, splitting on either separator. Empty
/// input (or a trailing separator) yields the whole (trimmed) string.
fn base_name(image_path: &str) -> &str {
    let p = image_path.trim_end_matches(['\\', '/']);
    match p.rsplit(['\\', '/']).next() {
        Some(b) if !b.is_empty() => b,
        _ => p,
    }
}

/// Case-insensitive, separator-agnostic path-prefix test at a component
/// boundary: `C:\Program Files\App` matches `C:\Program Files\App\bin\a.exe` and
/// the exact path, but NOT `C:\Program Files\Application\…` (boundary guard, so
/// `…\App` never claims `…\Application`). Both sides are lowercased and have
/// their separators normalized to `\` before comparison.
fn path_has_prefix(image_path: &str, prefix: &str) -> bool {
    let norm = |s: &str| s.trim().replace('/', "\\").to_ascii_lowercase();
    let path = norm(image_path);
    let mut pfx = norm(prefix);
    if pfx.is_empty() {
        return false;
    }
    // A prefix written with a trailing separator matches at that boundary
    // already; strip it so the boundary check below is uniform.
    while pfx.ends_with('\\') {
        pfx.pop();
    }
    if pfx.is_empty() {
        return false;
    }
    // Defensive: a bare drive root ("c:" after the trailing-slash strip) would
    // match every path on the volume — a catch-all that silently disables read-
    // deny. The server rejects such rules, but a local agent.toml rule is
    // unchecked, so never honour a whole-volume path prefix here.
    if pfx.len() == 2 && pfx.as_bytes()[1] == b':' && pfx.as_bytes()[0].is_ascii_alphabetic() {
        return false;
    }
    match path.strip_prefix(&pfx) {
        Some(rest) => rest.is_empty() || rest.starts_with('\\'),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Local TOML rule ([[trusted_readers]]) — mirrors UsbRule's "first present
// matcher wins" ergonomics so the config style is familiar.
// ---------------------------------------------------------------------------

/// One `[[trusted_readers]]` entry from `agent.toml`. Exactly one matcher field
/// should be set; priority when several are present is publisher → path → name.
/// A rule with no matcher is dropped (never a catch-all — an empty allowlist in
/// the allowlist posture would make EVERY process untrusted, so a malformed
/// rule must not silently become one).
#[derive(Debug, Clone, Deserialize)]
pub struct TrustedReaderRule {
    /// Authenticode signer subject CN (e.g. `"Microsoft Corporation"`).
    #[serde(default)]
    pub publisher: Option<String>,
    /// Image path prefix (e.g. `"C:\\Program Files\\Microsoft Office"`).
    #[serde(default)]
    pub path: Option<String>,
    /// Image base name (e.g. `"winword.exe"`).
    #[serde(default)]
    pub name: Option<String>,
    /// Free-form operator note (why this app is trusted).
    #[serde(default)]
    pub note: Option<String>,
}

impl TrustedReaderRule {
    /// Resolve to a normalized [`ReaderMatch`], choosing the matcher by
    /// priority. `None` when the rule carries no (non-empty) matcher.
    pub fn to_match(&self) -> Option<ReaderMatch> {
        if let Some(p) = non_empty(&self.publisher) {
            Some(ReaderMatch::Publisher(p))
        } else if let Some(p) = non_empty(&self.path) {
            Some(ReaderMatch::Path(p))
        } else if let Some(n) = non_empty(&self.name) {
            Some(ReaderMatch::Name(n))
        } else {
            None
        }
    }
}

fn non_empty(v: &Option<String>) -> Option<String> {
    v.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

/// Resolve a slice of local + synced rules into the effective matcher list,
/// dropping any rule with no matcher. This is what [`crate::exfil`] evaluates
/// each process against.
pub fn resolve_matches(rules: &[TrustedReaderRule]) -> Vec<ReaderMatch> {
    rules.iter().filter_map(TrustedReaderRule::to_match).collect()
}

// ---------------------------------------------------------------------------
// Server-sync wire shape (GET /agent/trusted-readers) + persistence. Mirrors
// trustsync.rs's destination flow: metadata only, fail-soft to last-persisted.
// ---------------------------------------------------------------------------

/// One reader rule as delivered by the management server: `{matchType, value}`
/// where `matchType ∈ {publisher, path, name}`. An unknown `matchType` yields
/// no matcher (dropped by [`resolve_matches`]).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
pub struct SyncedReader {
    #[serde(rename = "matchType")]
    pub match_type: String,
    pub value: String,
}

impl SyncedReader {
    /// Convert to a local-shaped rule so the merged list is one type.
    pub fn to_rule(&self) -> TrustedReaderRule {
        let val = Some(self.value.clone());
        match self.match_type.as_str() {
            "publisher" => TrustedReaderRule { publisher: val, path: None, name: None, note: None },
            "path" => TrustedReaderRule { publisher: None, path: val, name: None, note: None },
            "name" => TrustedReaderRule { publisher: None, path: None, name: val, note: None },
            _ => TrustedReaderRule { publisher: None, path: None, name: None, note: None },
        }
    }
}

/// Serialize synced readers for the at-rest `trusted-readers.json` (metadata
/// only). Round-trips with [`parse_readers`].
pub fn serialize_readers(readers: &[SyncedReader]) -> Vec<u8> {
    let doc = serde_json::json!({ "readers": readers });
    serde_json::to_vec(&doc).unwrap_or_else(|_| br#"{"readers":[]}"#.to_vec())
}

/// Parse the persisted `trusted-readers.json` back into synced readers.
pub fn parse_readers(bytes: &[u8]) -> Result<Vec<SyncedReader>, serde_json::Error> {
    #[derive(Deserialize)]
    struct PersistedFile {
        #[serde(default)]
        readers: Vec<SyncedReader>,
    }
    let pf: PersistedFile = serde_json::from_slice(bytes)?;
    Ok(pf.readers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(v: &[ReaderMatch]) -> Vec<ReaderMatch> {
        v.to_vec()
    }

    // --- base_name / path prefix (pure) ------------------------------------

    #[test]
    fn base_name_splits_both_separators() {
        assert_eq!(base_name(r"C:\Program Files\App\winword.exe"), "winword.exe");
        assert_eq!(base_name("/usr/bin/curl"), "curl");
        assert_eq!(base_name("solo.exe"), "solo.exe");
    }

    #[test]
    fn path_prefix_matches_at_component_boundary() {
        let pfx = r"C:\Program Files\Microsoft Office";
        assert!(path_has_prefix(r"C:\Program Files\Microsoft Office\root\WINWORD.EXE", pfx));
        assert!(path_has_prefix(r"c:\program files\microsoft office\excel.exe", pfx)); // case
        assert!(path_has_prefix(r"C:/Program Files/Microsoft Office/x.exe", pfx)); // slash
        assert!(path_has_prefix(pfx, pfx)); // exact
        assert!(path_has_prefix(&format!("{pfx}\\"), pfx)); // exact + trailing sep
    }

    #[test]
    fn path_prefix_rejects_sibling_with_shared_stem() {
        // The classic boundary bug: \App must not claim \Application.
        assert!(!path_has_prefix(r"C:\Program Files\Application\evil.exe", r"C:\Program Files\App"));
        assert!(!path_has_prefix(r"D:\other\thing.exe", r"C:\Program Files"));
        assert!(!path_has_prefix("anything", "")); // empty prefix never matches
    }

    #[test]
    fn path_rule_with_trailing_separator_is_equivalent() {
        let a = ReaderMatch::Path(r"C:\Windows".into());
        let b = ReaderMatch::Path(r"C:\Windows\".into());
        let p = r"C:\Windows\System32\svchost.exe";
        assert!(a.matches(p, None));
        assert!(b.matches(p, None));
    }

    // --- publisher matching (fail-safe on unsigned) ------------------------

    #[test]
    fn publisher_matches_ci_and_requires_a_signer() {
        let r = ReaderMatch::Publisher("Microsoft Corporation".into());
        assert!(r.matches(r"C:\x\word.exe", Some("microsoft corporation")));
        assert!(r.matches(r"C:\x\word.exe", Some("  Microsoft Corporation ")));
        // Unsigned / unverifiable => never sanctioned by publisher.
        assert!(!r.matches(r"C:\x\word.exe", None));
        assert!(!r.matches(r"C:\x\word.exe", Some("Evil Publisher")));
    }

    #[test]
    fn needs_publisher_only_for_publisher_rule() {
        assert!(ReaderMatch::Publisher("x".into()).needs_publisher());
        assert!(!ReaderMatch::Path("x".into()).needs_publisher());
        assert!(!ReaderMatch::Name("x".into()).needs_publisher());
    }

    // --- name matching -----------------------------------------------------

    #[test]
    fn name_matches_base_name_ci() {
        let r = ReaderMatch::Name("winword.exe".into());
        assert!(r.matches(r"C:\Program Files\Office\WINWORD.EXE", None));
        assert!(!r.matches(r"C:\evil\winword.exe.bak", None));
        assert!(!r.matches(r"C:\evil\notword.exe", None));
    }

    // --- is_sanctioned aggregate -------------------------------------------

    #[test]
    fn is_sanctioned_any_rule_wins() {
        let rs = rules(&[
            ReaderMatch::Path(r"C:\Windows".into()),
            ReaderMatch::Publisher("Adobe Inc.".into()),
            ReaderMatch::Name("winword.exe".into()),
        ]);
        // by path
        assert!(is_sanctioned(r"C:\Windows\System32\svchost.exe", None, &rs));
        // by publisher (needs the signer)
        assert!(is_sanctioned(r"C:\x\acrobat.exe", Some("Adobe Inc."), &rs));
        // by name
        assert!(is_sanctioned(r"C:\any\WINWORD.EXE", None, &rs));
        // an unknown, unsigned tool → NOT sanctioned → untrusted reader.
        assert!(!is_sanctioned(r"C:\Users\bob\Downloads\rustdesk.exe", None, &rs));
        // empty allowlist → nothing sanctioned (every process is untrusted).
        assert!(!is_sanctioned(r"C:\Windows\explorer.exe", None, &[]));
    }

    // --- rule resolution + priority ----------------------------------------

    #[test]
    fn rule_priority_publisher_then_path_then_name() {
        let r = TrustedReaderRule {
            publisher: Some("Microsoft Corporation".into()),
            path: Some(r"C:\Windows".into()),
            name: Some("x.exe".into()),
            note: None,
        };
        assert_eq!(r.to_match(), Some(ReaderMatch::Publisher("Microsoft Corporation".into())));

        let only_path = TrustedReaderRule {
            publisher: Some("   ".into()), // blank ⇒ skipped
            path: Some(r"C:\Windows".into()),
            name: None,
            note: None,
        };
        assert_eq!(only_path.to_match(), Some(ReaderMatch::Path(r"C:\Windows".into())));

        let empty = TrustedReaderRule { publisher: None, path: None, name: Some("  ".into()), note: None };
        assert_eq!(empty.to_match(), None, "a rule with no non-empty matcher is dropped");
    }

    #[test]
    fn resolve_drops_matcherless_rules() {
        let rules = vec![
            TrustedReaderRule { publisher: None, path: None, name: None, note: Some("junk".into()) },
            TrustedReaderRule { publisher: None, path: Some(r"C:\Windows".into()), name: None, note: None },
        ];
        assert_eq!(resolve_matches(&rules), vec![ReaderMatch::Path(r"C:\Windows".into())]);
    }

    // --- synced wire conversion + persistence round-trip -------------------

    #[test]
    fn synced_reader_converts_by_match_type() {
        let cases = [
            ("publisher", ReaderMatch::Publisher("Microsoft Corporation".into())),
            ("path", ReaderMatch::Path(r"C:\Windows".into())),
            ("name", ReaderMatch::Name("winword.exe".into())),
        ];
        for (mt, expected) in cases {
            let sr = SyncedReader { match_type: mt.into(), value: match &expected {
                ReaderMatch::Publisher(v) | ReaderMatch::Path(v) | ReaderMatch::Name(v) => v.clone(),
            }};
            assert_eq!(sr.to_rule().to_match(), Some(expected));
        }
        // Unknown match type ⇒ no matcher (dropped).
        let unknown = SyncedReader { match_type: "sha256".into(), value: "abc".into() };
        assert_eq!(unknown.to_rule().to_match(), None);
    }

    #[test]
    fn readers_persist_round_trips() {
        let readers = vec![
            SyncedReader { match_type: "publisher".into(), value: "Microsoft Corporation".into() },
            SyncedReader { match_type: "path".into(), value: r"C:\Program Files\Adobe".into() },
            SyncedReader { match_type: "name".into(), value: "backup.exe".into() },
        ];
        let bytes = serialize_readers(&readers);
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.contains("matchType"));
        assert!(text.contains("Microsoft Corporation"));
        assert_eq!(parse_readers(&bytes).unwrap(), readers);
    }

    #[test]
    fn parse_readers_missing_shape_is_empty() {
        assert!(parse_readers(b"{}").unwrap().is_empty());
    }
}
