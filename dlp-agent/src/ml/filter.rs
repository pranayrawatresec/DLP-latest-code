//! Is this file worth classifying? — the gate in front of every ML producer.
//!
//! Why this module exists
//! ----------------------
//! The at-creation watcher and the at-rest walker see EVERY file the endpoint
//! touches: a compiler's object files, a browser's cache, the pagefile-adjacent
//! churn of Windows Update, `node_modules` being unpacked, our own append-only
//! verdict log. A DistilBERT forward pass costs tens to hundreds of milliseconds
//! and this is a background service on somebody's work PC. Without a gate the
//! feature does not ship — the laptop never idles, the fan never stops, and the
//! customer turns the agent off. That is a *security* outcome, not a comfort one.
//!
//! So the rule is: **classify documents, ignore machinery.** Everything here is
//! pure (no I/O, no clock, no globals) so the whole decision table is exercised
//! by `tests/ml_filter.rs` rather than by watching a real directory and hoping.
//!
//! What a skip does and does NOT mean
//! ----------------------------------
//! A skip is a *coverage/cost* decision, never a *safety* one. It only means
//! "no producer will proactively classify this"; it does not grant the file
//! anything. If such a file is later read on an exfil path the kernel hands the
//! agent its bytes and the read path's on-demand trigger classifies it then, and
//! `denyUnclassified` still governs what happens in the meantime. So an
//! over-eager exclusion costs latency on first read; it never opens a hole. That
//! asymmetry is why the exclusion list can be generous.
//!
//! Two lists that must not drift
//! -----------------------------
//! [`SUPPORTED_EXTENSIONS`] mirrors what `crate::detect::extract` can actually
//! turn into text (`is_text_extension` + the `docx/xlsx/pptx/pdf/zip` arms of
//! `extract_by_extension`). Those helpers are private to that module, so this is
//! a hand-kept mirror — and `tests/ml_filter.rs::supported_extensions_match_the_extractor`
//! probes `extract_text()` for every entry so the mirror cannot drift silently:
//! add a format there, the test tells you to add it here. Classifying a format
//! the extractor refuses would burn a queue slot to produce `Reason::Empty`.

use std::path::{Path, PathBuf};

/// Skip files larger than this by default.
///
/// The trade-off, stated explicitly because it looks like a coverage hole and is
/// not one: the cache key and the classification only ever cover the first
/// `ml::cache::MAX_HASHED_BYTES` (4 MiB) of a file — that is all the driver ships
/// on the read path, so that is all any producer may hash (contract C1). A 900 MB
/// VM image and a 900 MB mailbox archive would therefore be classified from the
/// same 4 MiB prefix as a 5 MB one, at the cost of reading the prefix off disk.
/// The bound is not about the model's cost, it is about I/O and about not
/// touching multi-gigabyte files a user is actively streaming. 64 MiB is well
/// above any real office document and well below the artefacts that hurt.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Extensions the text extractor supports. MIRROR of `detect::extract` — see
/// the module header; the drift test is the enforcement.
///
/// Lower-case, no leading dot. Source/config extensions are here because the
/// extractor accepts them: a `.sql` dump or a `.json` export is exactly the kind
/// of file a defence customer would rather not see leave, and the path
/// exclusions (`node_modules`, `target`, `.git`) are what keep a developer's
/// checkout from becoming the workload.
pub const SUPPORTED_EXTENSIONS: &[&str] = &[
    // --- plain-text family (extract::is_text_extension) ---
    "txt", "md", "markdown", "csv", "tsv", "log", "js", "mjs", "cjs", "jsx", "ts", "tsx", "json",
    "xml", "html", "htm", "css", "py", "java", "c", "h", "cpp", "hpp", "cc", "cs", "go", "rs", "rb",
    "php", "pl", "sh", "bash", "ps1", "psm1", "bat", "cmd", "sql", "yaml", "yml", "ini", "cfg",
    "conf", "toml", "properties", "env",
    // --- container/document formats (extract::extract_by_extension) ---
    "docx", "xlsx", "pptx", "pdf", "zip",
];

/// The subset of [`SUPPORTED_EXTENSIONS`] the at-rest WALKER admits by default.
///
/// Measured on a real developer profile: `SUPPORTED_EXTENSIONS` (source and
/// config formats included) let through 125,744 of 232,719 files, of which 126
/// -- 0.10% -- were an actual document. The other 99.9% was Python, HTML,
/// `node_modules` overflow and log churn the extractor happens to be able to
/// read, not anything a defence customer is trying to keep in the building.
/// At `DEFAULT_FILES_PER_MINUTE = 120` that turned a background backfill into a
/// 17.5-hour sweep that classified 126 real documents and starved its own
/// 6-hour rescan interval forever.
///
/// This restriction is a WALKER-ONLY, proactive-coverage decision, same as any
/// other [`SkipReason::UnsupportedExtension`] -- never a safety one. The
/// at-creation watcher and the on-demand read path are NOT gated by this list:
/// [`super::watch`] still classifies a `.py` the moment it is created, and the
/// synchronous enforcement path (`detect::extract_text` direct, no filter at
/// all) classifies anything read on an exfil channel regardless of extension.
/// A site that wants the walker to proactively cover source/config files too
/// sets `[ml] walk_scan_source_files = true`, which restores the full
/// `SUPPORTED_EXTENSIONS` set for the sweep.
pub const DOCUMENT_EXTENSIONS: &[&str] =
    &["docx", "xlsx", "pptx", "pdf", "zip", "txt", "md", "markdown", "csv", "tsv"];

/// Directory NAMES excluded wherever they appear in a path. Case-insensitive.
///
/// Three families, all of them machine-generated churn: version control and
/// package trees (`.git`, `node_modules`, `.nuget`), build output (`target`,
/// `build`, `dist`, `obj`, `__pycache__`), and caches/temp (`temp`, `tmp`,
/// `cache`, `.cache`) — the last of which also covers `AppData\Local\Temp`
/// without needing a per-user absolute path. `$Recycle.Bin` and
/// `System Volume Information` are Windows' own pseudo-directories: a deleted
/// file is not a creation event worth spending a forward pass on, and VSS
/// snapshots would re-classify the whole volume.
pub const DEFAULT_EXCLUDED_COMPONENTS: &[&str] = &[
    "$recycle.bin",
    "system volume information",
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "target",
    "build",
    "dist",
    "obj",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".cache",
    "cache",
    "caches",
    "temp",
    "tmp",
    ".gradle",
    ".cargo",
    ".npm",
    ".nuget",
    ".vs",
    ".idea",
    // Python/native dependency trees -- measured at 74.5% of one developer
    // sweep's candidate count alongside the extension-tier fix above.
    "site-packages",
    "vendor",
    "bower_components",
    "packages",
    ".tox",
    ".pytest_cache",
    ".mypy_cache",
    ".next",
    ".nuxt",
    "wheels",
    "pkgs",
    ".conda",
    ".pyenv",
];

/// Directory names excluded only at the ROOT of a volume, i.e. `C:\Windows\…`
/// and `C:\Program Files\…`.
///
/// Anchored at the root deliberately: `C:\Windows` is the operating system and
/// classifying it is pure waste, but `D:\Projects\Windows Rollout\plan.docx` is
/// a document a customer very much cares about. A bare component match would eat
/// the second along with the first.
pub const DEFAULT_ROOT_EXCLUDED_COMPONENTS: &[&str] =
    &["windows", "program files", "program files (x86)", "winnt"];

/// Why a file will not be classified. Reported as a counter label — never with
/// the path attached at info level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Zero bytes. There is no document here, only a placeholder.
    Empty,
    /// Above the configured size bound (see [`DEFAULT_MAX_FILE_BYTES`]).
    TooLarge,
    /// The text extractor cannot read this format, so classification could only
    /// ever produce "no text".
    UnsupportedExtension,
    /// Inside a temp/build/cache directory, or the OS's own trees.
    ExcludedDirectory,
    /// Under a caller-supplied excluded prefix — in practice the agent's own
    /// state directory. A classifier that classifies its own verdict log writes
    /// an entry, which is a write, which notifies the watcher: a livelock.
    ExcludedPrefix,
    /// An editor's in-flight artefact (`~$report.docx`, the Office owner file).
    /// It carries a supported extension and no document.
    TempArtifact,
}

impl SkipReason {
    /// Stable machine label for counters/logs.
    pub fn code(self) -> &'static str {
        match self {
            SkipReason::Empty => "empty",
            SkipReason::TooLarge => "too-large",
            SkipReason::UnsupportedExtension => "unsupported-extension",
            SkipReason::ExcludedDirectory => "excluded-directory",
            SkipReason::ExcludedPrefix => "excluded-prefix",
            SkipReason::TempArtifact => "temp-artifact",
        }
    }
}

/// The answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Classify,
    Skip(SkipReason),
}

impl Decision {
    pub fn is_classify(self) -> bool {
        matches!(self, Decision::Classify)
    }
    /// `Some(reason)` when skipped.
    pub fn skip_reason(self) -> Option<SkipReason> {
        match self {
            Decision::Skip(r) => Some(r),
            Decision::Classify => None,
        }
    }
}

/// The tunable part of the gate. Defaults are the constants above; every field
/// is a hook so a test — or a site with an unusual layout — can change one rule
/// without forking the module.
#[derive(Debug, Clone)]
pub struct FilterConfig {
    /// Upper size bound, in bytes. 0 means "no bound" (not recommended).
    pub max_file_bytes: u64,
    /// Directory names excluded anywhere in the path (lower-case).
    pub excluded_components: Vec<String>,
    /// Directory names excluded only directly under a volume root (lower-case).
    pub root_excluded_components: Vec<String>,
    /// Absolute path prefixes excluded wholesale — the agent's state directory,
    /// its install directory, anything else a deployment wants left alone.
    /// Compared segment-wise, so `C:\ProgramData\DLPAgent` does not exclude
    /// `C:\ProgramData\DLPAgentBackups`.
    pub excluded_prefixes: Vec<PathBuf>,
    /// Which extensions this PRODUCER treats as eligible. Default
    /// [`SUPPORTED_EXTENSIONS`] — every producer except a walker that has been
    /// narrowed to [`DOCUMENT_EXTENSIONS`] (see that constant's doc). Distinct
    /// from `extension_supported()`, which always checks the FULL mirror and
    /// exists for the extractor drift test — this field is a per-producer
    /// coverage/cost policy layered on top of "can the extractor read this at
    /// all", not a change to what the extractor supports.
    pub extensions: &'static [&'static str],
}

impl Default for FilterConfig {
    fn default() -> Self {
        FilterConfig {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            excluded_components: DEFAULT_EXCLUDED_COMPONENTS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            root_excluded_components: DEFAULT_ROOT_EXCLUDED_COMPONENTS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            excluded_prefixes: Vec::new(),
            extensions: SUPPORTED_EXTENSIONS,
        }
    }
}

impl FilterConfig {
    /// Defaults plus the mandatory self-exclusion of the agent's own state
    /// directory. Every production construction should go through this: the
    /// verdict log lives under `state_dir`, and classifying it would make each
    /// `put()` produce another notification, another read, another `put()`.
    pub fn with_state_dir(state_dir: impl AsRef<Path>) -> Self {
        let mut cfg = Self::default();
        cfg.exclude_prefix(state_dir);
        cfg
    }

    /// Add an excluded absolute path prefix (chainable at construction sites).
    pub fn exclude_prefix(&mut self, prefix: impl AsRef<Path>) -> &mut Self {
        self.excluded_prefixes.push(prefix.as_ref().to_path_buf());
        self
    }
}

/// THE decision. Pure: the caller supplies the size it already stat'ed, so this
/// never touches the disk and the whole table is unit-testable.
///
/// Order matters only for which reason is reported — a path can violate several
/// rules at once. Cheapest and most decisive first: location, then shape, then
/// size.
pub fn should_classify(path: &Path, size: u64, cfg: &FilterConfig) -> Decision {
    let raw = path.to_string_lossy();
    let segments = split_segments(&raw);

    let Some(name) = segments.last() else {
        // No final component at all ("C:\", ""): not a file.
        return Decision::Skip(SkipReason::UnsupportedExtension);
    };

    if is_excluded_prefix(&segments, cfg) {
        return Decision::Skip(SkipReason::ExcludedPrefix);
    }
    if is_excluded_directory(&raw, &segments, cfg) {
        return Decision::Skip(SkipReason::ExcludedDirectory);
    }
    if is_temp_artifact(name) {
        return Decision::Skip(SkipReason::TempArtifact);
    }
    let ext = extension_of(name);
    if !cfg.extensions.contains(&ext.as_str()) {
        return Decision::Skip(SkipReason::UnsupportedExtension);
    }
    if size == 0 {
        return Decision::Skip(SkipReason::Empty);
    }
    if cfg.max_file_bytes != 0 && size > cfg.max_file_bytes {
        return Decision::Skip(SkipReason::TooLarge);
    }
    Decision::Classify
}

/// Is this extension one the text extractor can read? Lower-case, no dot.
pub fn extension_supported(ext: &str) -> bool {
    !ext.is_empty() && SUPPORTED_EXTENSIONS.contains(&ext)
}

/// Lower-case extension of a file NAME, with the same rule as
/// `detect::extract::extension_of`: a leading dot is not an extension, so
/// `.env` has none (and is therefore unsupported) while `agent.env` has `env`.
pub fn extension_of(name: &str) -> String {
    match name.rfind('.') {
        Some(dot) if dot > 0 => name[dot + 1..].to_lowercase(),
        _ => String::new(),
    }
}

/// Editor/downloader in-flight artefacts that wear a document extension.
/// `~$Report.docx` is Word's 162-byte owner file, not the report.
fn is_temp_artifact(name: &str) -> bool {
    name.starts_with("~$") || name.starts_with("~wr")
}

/// True when any path segment is an excluded directory name, or the segment
/// directly under the volume root is an OS tree.
///
/// `is_unc` shifts the root: `\\server\share\Windows` has its root-level
/// directory at index 2, not 0.
pub fn is_excluded_directory(raw: &str, segments: &[String], cfg: &FilterConfig) -> bool {
    // The file name itself is not a directory — check only the parents.
    let dirs = &segments[..segments.len().saturating_sub(1)];

    if dirs
        .iter()
        .any(|s| cfg.excluded_components.iter().any(|e| e == s))
    {
        return true;
    }

    let root_idx = root_index(raw, segments);
    match dirs.get(root_idx) {
        Some(first) => cfg.root_excluded_components.iter().any(|e| e == first),
        None => false,
    }
}

/// True when the path lies under one of the configured excluded prefixes.
/// Segment-wise so a prefix can never match half a directory name.
pub fn is_excluded_prefix(segments: &[String], cfg: &FilterConfig) -> bool {
    cfg.excluded_prefixes.iter().any(|prefix| {
        let praw = prefix.to_string_lossy();
        let pseg = split_segments(&praw);
        !pseg.is_empty() && segments.len() > pseg.len() && segments[..pseg.len()] == pseg[..]
    })
}

/// Index of the first segment that is a real directory under the volume root.
/// `C:\Windows\…` → 1 (segment 0 is the drive), `\\srv\share\Windows\…` → 2,
/// a relative path → 0.
fn root_index(raw: &str, segments: &[String]) -> usize {
    if raw.starts_with("\\\\") || raw.starts_with("//") {
        return 2; // \\server\share\<root dirs…>
    }
    match segments.first() {
        Some(s) if s.len() == 2 && s.ends_with(':') => 1,
        _ => 0,
    }
}

/// Split a path into lower-case segments on BOTH separators.
///
/// Deliberately not `Path::components()`: that helper is platform-dependent, so
/// on a non-Windows build (the crate must cross-compile, and these tests run
/// everywhere) `C:\Users\x` would be ONE component and every exclusion would
/// silently stop working. Windows accepts `/` interchangeably, so both are
/// separators here.
///
/// Trailing spaces and dots are trimmed from each segment because Win32 does the
/// same when it resolves the path: `C:\Windows.\x` and `C:\Windows \x` open the
/// same directory as `C:\Windows\x`, and an exclusion list that compares the
/// literal text would miss both. `.` and `..` trim to empty and drop out.
pub fn split_segments(raw: &str) -> Vec<String> {
    raw.split(['/', '\\'])
        .map(|s| s.trim_end_matches([' ', '.']).to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments_split_on_both_separators_and_lowercase() {
        assert_eq!(
            split_segments(r"C:\Users\Ana\Report.DOCX"),
            vec!["c:", "users", "ana", "report.docx"]
        );
        assert_eq!(
            split_segments("C:/Users//Ana/./x.txt"),
            vec!["c:", "users", "ana", "x.txt"]
        );
    }

    #[test]
    fn root_index_handles_drive_unc_and_relative() {
        let d = split_segments(r"C:\Windows\a.txt");
        assert_eq!(root_index(r"C:\Windows\a.txt", &d), 1);
        let u = split_segments(r"\\srv\share\Windows\a.txt");
        assert_eq!(root_index(r"\\srv\share\Windows\a.txt", &u), 2);
        let r = split_segments(r"docs\a.txt");
        assert_eq!(root_index(r"docs\a.txt", &r), 0);
    }

    #[test]
    fn extension_rules_match_the_extractor_convention() {
        assert_eq!(extension_of("Report.DOCX"), "docx");
        assert_eq!(extension_of(".env"), ""); // dotfile: no extension
        assert_eq!(extension_of("noext"), "");
        assert!(extension_supported("pdf"));
        assert!(!extension_supported(""));
        assert!(!extension_supported("exe"));
    }
}
