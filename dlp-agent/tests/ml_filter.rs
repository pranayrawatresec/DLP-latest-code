//! The at-creation/at-rest classification gate (`ml::filter`), as a table.
//!
//! This gate decides what the endpoint spends forward passes on. Get it wrong in
//! one direction and the agent classifies `node_modules` forever (the customer
//! turns it off); get it wrong in the other and documents are never
//! proactively classified (every first read pays the on-demand penalty). Neither
//! failure announces itself, so the whole decision table is pinned here.
//!
//! The most important single case in this file is
//! [`the_agents_own_state_directory_is_excluded`]: the verdict cache's
//! append-only log lives in the state directory and has a supported extension.
//! A classifier that classified its own log would write an entry, which is a
//! write, which notifies the watcher, which classifies the log again — a
//! livelock that would be discovered in production, not in a review.

use std::path::{Path, PathBuf};

use dlp_agent::detect::extract::{extract_text, Reason};
use dlp_agent::ml::filter::{
    extension_of, extension_supported, should_classify, Decision, FilterConfig, SkipReason,
    DEFAULT_MAX_FILE_BYTES, SUPPORTED_EXTENSIONS,
};

const STATE_DIR: &str = r"C:\ProgramData\DLPAgent";
/// A plausible document size — every "is this path in scope" case uses it so the
/// size rules never accidentally decide a path case.
const OK_SIZE: u64 = 64 * 1024;

fn cfg() -> FilterConfig {
    FilterConfig::with_state_dir(STATE_DIR)
}

fn decide(path: &str, size: u64) -> Decision {
    should_classify(Path::new(path), size, &cfg())
}

fn assert_in(path: &str) {
    assert_eq!(
        decide(path, OK_SIZE),
        Decision::Classify,
        "expected {path} to be classified"
    );
}

fn assert_out(path: &str, reason: SkipReason) {
    assert_eq!(
        decide(path, OK_SIZE),
        Decision::Skip(reason),
        "expected {path} to be skipped as {}",
        reason.code()
    );
}

// ---------------------------------------------------------------------------
// In scope
// ---------------------------------------------------------------------------

#[test]
fn ordinary_user_documents_are_classified() {
    for p in [
        r"C:\Users\Ana\Documents\plan.docx",
        r"C:\Users\Ana\Documents\q3 figures.xlsx",
        r"C:\Users\Ana\Desktop\briefing.pptx",
        r"C:\Users\Ana\Downloads\spec.pdf",
        r"D:\Data\notes.txt",
        r"D:\Data\export.csv",
        r"E:\Archive\bundle.zip",
        r"\\fileserver\share\Reports\q3.xlsx",
    ] {
        assert_in(p);
    }
}

#[test]
fn extension_matching_is_case_insensitive() {
    assert_in(r"C:\Users\Ana\Documents\REPORT.PDF");
    assert_in(r"C:\Users\Ana\Documents\Report.DocX");
}

#[test]
fn forward_slashes_are_separators_too() {
    // Win32 accepts them, so the exclusions must see them.
    assert_in("C:/Users/Ana/Documents/plan.docx");
    assert_out(
        "C:/Users/Ana/project/node_modules/pkg/readme.md",
        SkipReason::ExcludedDirectory,
    );
}

#[test]
fn a_directory_named_windows_below_the_root_is_still_in_scope() {
    // The OS-tree exclusion is anchored at the volume root. A project folder
    // called "Windows Rollout" is exactly the kind of document set a customer
    // cares about and must not be swallowed by it.
    assert_in(r"D:\Projects\Windows Rollout\plan.docx");
    assert_in(r"C:\Users\Ana\Program Files Migration\notes.txt");
}

// ---------------------------------------------------------------------------
// Out of scope — shape
// ---------------------------------------------------------------------------

#[test]
fn formats_the_extractor_cannot_read_are_skipped() {
    for p in [
        r"C:\Users\Ana\Downloads\setup.exe",
        r"C:\Users\Ana\Pictures\holiday.jpg",
        r"C:\Users\Ana\Videos\clip.mp4",
        r"C:\Users\Ana\Documents\legacy.doc", // .doc (CFB) is NOT .docx
        r"C:\Users\Ana\Documents\macro.docm",
        r"C:\Users\Ana\Documents\image.iso",
        r"C:\Users\Ana\Documents\README", // no extension at all
        r"C:\Users\Ana\.env",             // dotfile: no extension by convention
    ] {
        assert_out(p, SkipReason::UnsupportedExtension);
    }
}

#[test]
fn office_and_editor_in_flight_artifacts_are_skipped() {
    // `~$plan.docx` is Word's owner file: a supported extension wrapped around
    // ~162 bytes of user name, not the document.
    assert_out(r"C:\Users\Ana\Documents\~$plan.docx", SkipReason::TempArtifact);
    assert_out(r"C:\Users\Ana\Documents\~WRD0003.txt", SkipReason::TempArtifact);
}

#[test]
fn size_bounds_are_enforced_at_both_ends() {
    assert_eq!(
        decide(r"C:\Users\Ana\Documents\empty.docx", 0),
        Decision::Skip(SkipReason::Empty)
    );
    assert_eq!(
        decide(r"C:\Users\Ana\Documents\huge.pdf", DEFAULT_MAX_FILE_BYTES + 1),
        Decision::Skip(SkipReason::TooLarge)
    );
    // Exactly at the bound is still in scope.
    assert_eq!(
        decide(r"C:\Users\Ana\Documents\big.pdf", DEFAULT_MAX_FILE_BYTES),
        Decision::Classify
    );
}

#[test]
fn the_size_bound_is_configurable() {
    let mut c = FilterConfig::with_state_dir(STATE_DIR);
    c.max_file_bytes = 1_024;
    let p = Path::new(r"C:\Users\Ana\Documents\plan.docx");
    assert_eq!(should_classify(p, 2_048, &c), Decision::Skip(SkipReason::TooLarge));
    assert_eq!(should_classify(p, 512, &c), Decision::Classify);

    // 0 disables the bound entirely.
    c.max_file_bytes = 0;
    assert_eq!(should_classify(p, u64::MAX, &c), Decision::Classify);
}

// ---------------------------------------------------------------------------
// Out of scope — location
// ---------------------------------------------------------------------------

#[test]
fn temp_build_and_cache_trees_are_excluded() {
    for p in [
        r"C:\Users\Ana\AppData\Local\Temp\tmp1234.txt",
        r"C:\Temp\scratch.csv",
        r"C:\Users\Ana\src\app\node_modules\lodash\readme.md",
        r"C:\Users\Ana\src\app\target\debug\build.log",
        r"C:\Users\Ana\src\app\dist\bundle.js",
        r"C:\Users\Ana\src\app\build\out.json",
        r"C:\Users\Ana\src\app\.git\COMMIT_EDITMSG.txt",
        r"C:\Users\Ana\src\app\__pycache__\mod.py",
        r"C:\Users\Ana\AppData\Local\Google\Chrome\User Data\Default\Cache\f_00001.txt",
        r"C:\$Recycle.Bin\S-1-5-21-1\$RABCDEF.docx",
        r"D:\System Volume Information\tracking.log",
    ] {
        assert_out(p, SkipReason::ExcludedDirectory);
    }
}

#[test]
fn exclusions_are_case_insensitive() {
    for p in [
        r"C:\Users\Ana\src\NODE_MODULES\pkg\readme.md",
        r"C:\Users\Ana\src\app\Target\debug\notes.txt",
        r"C:\users\ana\appdata\local\TEMP\x.txt",
        r"c:\WINDOWS\system32\drivers\etc\hosts.txt",
        r"C:\PROGRAM FILES (X86)\Vendor\readme.md",
    ] {
        assert!(
            matches!(decide(p, OK_SIZE), Decision::Skip(_)),
            "expected {p} to be skipped whatever its casing"
        );
    }
}

#[test]
fn the_operating_system_trees_are_excluded_at_the_volume_root() {
    for p in [
        r"C:\Windows\System32\config.txt",
        r"C:\Windows\Temp\x.log",
        r"C:\Program Files\Vendor\App\readme.md",
        r"C:\Program Files (x86)\Vendor\App\notes.txt",
        r"D:\Windows\notes.txt", // a second OS install on another volume
    ] {
        assert_out(p, SkipReason::ExcludedDirectory);
    }
}

#[test]
fn trailing_dots_and_spaces_cannot_evade_an_exclusion() {
    // Win32 strips these when it resolves the path, so `C:\Windows.\x` opens
    // C:\Windows. An exclusion list comparing raw text would miss it.
    assert_out(r"C:\Windows.\System32\x.txt", SkipReason::ExcludedDirectory);
    assert_out(r"C:\Windows \System32\x.txt", SkipReason::ExcludedDirectory);
    assert_out(
        r"C:\Users\Ana\src\node_modules.\pkg\readme.md",
        SkipReason::ExcludedDirectory,
    );
}

#[test]
fn the_agents_own_state_directory_is_excluded() {
    // THE livelock case: the verdict cache's append-only log is a `.log` file
    // (a supported extension) inside the state directory. Classifying it would
    // append an entry, which is a write, which notifies the watcher, forever.
    for p in [
        r"C:\ProgramData\DLPAgent\ml-verdicts.log",
        r"C:\ProgramData\DLPAgent\ml-cache\ml-verdicts.log",
        r"C:\ProgramData\DLPAgent\logs\agent.log",
        r"C:\ProgramData\DLPAgent\policy.json",
        r"C:\programdata\dlpagent\ml-cache\ml-verdicts.log", // casing must not matter
        "C:/ProgramData/DLPAgent/ml-verdicts.log",           // nor separators
    ] {
        assert_out(p, SkipReason::ExcludedPrefix);
    }
}

#[test]
fn a_prefix_exclusion_matches_whole_segments_only() {
    // `C:\ProgramData\DLPAgent` must not exclude `…\DLPAgentBackups`, which is
    // somebody else's directory that merely starts with the same letters.
    assert_in(r"C:\ProgramData\DLPAgentBackups\export.csv");
    // The prefix itself is a directory, not a file: nothing to classify AT it.
    assert!(matches!(
        decide(r"C:\ProgramData\DLPAgent", OK_SIZE),
        Decision::Skip(_)
    ));
}

#[test]
fn extra_exclusions_are_configurable() {
    let mut c = FilterConfig::with_state_dir(STATE_DIR);
    c.exclude_prefix(r"E:\Backups");
    assert_eq!(
        should_classify(Path::new(r"E:\Backups\2026\jan.zip"), OK_SIZE, &c),
        Decision::Skip(SkipReason::ExcludedPrefix)
    );
    c.excluded_components.push("sandbox".into());
    assert_eq!(
        should_classify(Path::new(r"D:\work\sandbox\a.txt"), OK_SIZE, &c),
        Decision::Skip(SkipReason::ExcludedDirectory)
    );
    // And a deployment that wants Program Files watched can say so.
    let mut open = FilterConfig::default();
    open.root_excluded_components.clear();
    assert_eq!(
        should_classify(Path::new(r"C:\Program Files\App\readme.md"), OK_SIZE, &open),
        Decision::Classify
    );
}

// ---------------------------------------------------------------------------
// The two lists that must not drift
// ---------------------------------------------------------------------------

#[test]
fn every_allowlisted_extension_is_one_the_extractor_accepts() {
    // The allowlist in `ml::filter` mirrors `detect::extract`'s private
    // `is_text_extension` + format arms. Probing the public `extract_text()` is
    // how that mirror is held: a supported format fails a garbage probe for some
    // CONTENT reason (corrupt container, no text layer…), never with
    // `unsupported-format`. Delete a format from the extractor and this fails.
    for ext in SUPPORTED_EXTENSIONS {
        let name = format!("probe.{ext}");
        let reason = match extract_text(b"dlp filter probe", &name) {
            Ok(_) => continue, // plain-text family decodes fine
            Err(e) => e.reason,
        };
        assert_ne!(
            reason,
            Reason::UnsupportedFormat,
            "ml::filter allows .{ext} but detect::extract refuses it as unsupported — the two lists have drifted"
        );
    }
}

#[test]
fn formats_the_extractor_refuses_are_not_allowlisted() {
    for ext in ["exe", "dll", "png", "jpg", "mp4", "iso", "doc", "xls", "docm", "7z"] {
        assert!(
            !extension_supported(ext),
            ".{ext} must not be allowlisted — the extractor cannot read it"
        );
        let err = extract_text(b"dlp filter probe", &format!("probe.{ext}"))
            .expect_err("extractor should refuse an unsupported format");
        assert_eq!(err.reason, Reason::UnsupportedFormat);
    }
}

#[test]
fn extension_parsing_follows_the_extractors_convention() {
    assert_eq!(extension_of("Report.DOCX"), "docx");
    assert_eq!(extension_of("archive.tar.gz"), "gz");
    assert_eq!(extension_of(".env"), "", "a dotfile has no extension");
    assert_eq!(extension_of("README"), "");
    assert!(!extension_supported(""));
}

#[test]
fn the_allowlist_has_no_duplicates_and_is_lowercase() {
    let mut seen: Vec<&str> = SUPPORTED_EXTENSIONS.to_vec();
    seen.sort_unstable();
    let before = seen.len();
    seen.dedup();
    assert_eq!(before, seen.len(), "duplicate entry in SUPPORTED_EXTENSIONS");
    for e in SUPPORTED_EXTENSIONS {
        assert_eq!(*e, e.to_lowercase(), "allowlist entries are compared lower-case");
        assert!(!e.starts_with('.'), "allowlist entries carry no leading dot");
    }
}

// ---------------------------------------------------------------------------
// The walker's document-only tier (`[ml] walk_scan_source_files = false`)
// ---------------------------------------------------------------------------

/// Every entry the walker's document tier admits must also be one the
/// extractor (and therefore `SUPPORTED_EXTENSIONS`) actually accepts — the
/// narrower list must be a genuine SUBSET, never introduce a format of its
/// own that would silently fail extraction.
#[test]
fn document_extensions_is_a_subset_of_the_full_allowlist() {
    use dlp_agent::ml::filter::DOCUMENT_EXTENSIONS;
    for e in DOCUMENT_EXTENSIONS {
        assert!(
            SUPPORTED_EXTENSIONS.contains(e),
            "DOCUMENT_EXTENSIONS has {e:?}, which SUPPORTED_EXTENSIONS does not \
             — the walker would try to classify a format the extractor refuses"
        );
    }
    let mut seen: Vec<&str> = DOCUMENT_EXTENSIONS.to_vec();
    seen.sort_unstable();
    let before = seen.len();
    seen.dedup();
    assert_eq!(before, seen.len(), "duplicate entry in DOCUMENT_EXTENSIONS");
}

/// `FilterConfig::extensions` — not the global `extension_supported()` mirror —
/// is what `should_classify` actually gates on. A source file must be admitted
/// under the default (full) set and refused once a producer is narrowed to the
/// document tier, while a real document is classified either way.
#[test]
fn a_narrowed_extension_set_restricts_should_classify_without_touching_the_extractor() {
    use dlp_agent::ml::filter::DOCUMENT_EXTENSIONS;

    let full = cfg();
    assert_eq!(full.extensions, SUPPORTED_EXTENSIONS, "default is the full mirror");

    let mut narrowed = cfg();
    narrowed.extensions = DOCUMENT_EXTENSIONS;

    let source = Path::new(r"C:\Users\alex\code\app.py");
    let doc = Path::new(r"C:\Users\alex\Documents\report.pdf");

    assert_eq!(should_classify(source, OK_SIZE, &full), Decision::Classify);
    assert_eq!(
        should_classify(source, OK_SIZE, &narrowed),
        Decision::Skip(SkipReason::UnsupportedExtension),
        "a source file must be skipped once the walker is narrowed to documents"
    );
    assert_eq!(should_classify(doc, OK_SIZE, &full), Decision::Classify);
    assert_eq!(
        should_classify(doc, OK_SIZE, &narrowed),
        Decision::Classify,
        "a real document stays eligible under either tier"
    );

    // extension_supported() itself is untouched — it always checks the FULL
    // mirror, because it exists for the extractor drift test, not for a
    // producer's coverage policy.
    assert!(extension_supported("py"));
}

/// The dependency-tree names the sweep's eligibility fix depends on: pruning
/// happens on the DIRECTORY, so a real document one level below one of these
/// stays in scope even though the noisy tree beside it does not.
#[test]
fn the_added_dependency_tree_exclusions_are_present() {
    for name in [
        "site-packages",
        "venv",
        "vendor",
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
        "bower_components",
    ] {
        let c = cfg();
        assert!(
            c.excluded_components.iter().any(|e| e == name),
            "{name:?} must be in the default exclusion list"
        );
    }
}

// ---------------------------------------------------------------------------
// Sanity: the filter never panics on hostile input
// ---------------------------------------------------------------------------

#[test]
fn degenerate_paths_are_handled_not_panicked_on() {
    let c = cfg();
    for p in ["", r"C:\", "/", r"\\", r"\\server", "...", r"C:\a\\\b\\x.txt"] {
        let _ = should_classify(&PathBuf::from(p), OK_SIZE, &c); // must not panic
    }
    assert!(matches!(
        should_classify(Path::new(r"C:\a\\\b\\notes.txt"), OK_SIZE, &c),
        Decision::Classify
    ));
}

// =====================================================================
// The OVERLAPPED lifetime rule — a SOURCE-level guard.
//
// The watcher's `ReadDirectoryChangesW` loop crashed the whole service on a real
// endpoint with STATUS_STACK_BUFFER_OVERRUN (0xC0000409): a per-iteration stack
// `OVERLAPPED` was abandoned while its I/O was still pending, and the kernel
// later wrote the completion into a stack frame that no longer existed. It took
// ~30 minutes of heavy notification churn to trigger and left NOTHING in the log.
//
// The invariant is not expressible as a behavioural test — reproducing it needs a
// real volume under churn and a lot of patience — so it is pinned at the source
// level instead. That is unusual, and deliberate: the cost of regressing it is a
// silent process abort on a customer machine, and the shape of the mistake is
// easy to reintroduce while "tidying" the loop.
// =====================================================================

#[test]
fn the_watcher_never_abandons_a_pending_overlapped_read() {
    let src = include_str!("../src/ml/watch.rs");

    // 1. ONE stable OVERLAPPED for the thread, not one per iteration.
    assert!(
        src.contains("let mut ovl = Box::new(OVERLAPPED {"),
        "the OVERLAPPED must live outside the loop in a stable allocation — a \
         per-iteration stack one is written by the kernel after its frame dies"
    );

    // 2. Every path that stops waiting on a read must drain it first.
    let drains = src.matches("drain_pending(dir, &ovl);").count();
    assert!(
        drains >= 3,
        "expected every abandon path (stop, overlapped-result error, wait \
         failure) to call drain_pending; found {drains}. Re-issuing or returning \
         with an I/O still pending is the 0xC0000409 bug."
    );

    // 3. The drain must actually WAIT. CancelIoEx only requests cancellation;
    //    until the completion is collected the kernel may still write.
    let drain_fn = src
        .split("fn drain_pending(")
        .nth(1)
        .expect("drain_pending must exist");
    let body = &drain_fn[..drain_fn.find("\n}").unwrap_or(drain_fn.len())];
    assert!(
        body.contains("CancelIoEx") && body.contains("GetOverlappedResult"),
        "drain_pending must cancel AND collect the completion"
    );
    assert!(
        body.contains("&mut n, true"),
        "drain_pending must pass bWait = true — a non-blocking collect leaves the \
         kernel holding the buffer, which is the whole bug"
    );

    // 4. The raw two-line cancel that used to be inlined must not come back.
    assert!(
        !src.contains("let _ = CancelIoEx(dir, Some(&ovl));"),
        "cancellation must go through drain_pending so no call site can forget \
         to wait for the completion"
    );
}
