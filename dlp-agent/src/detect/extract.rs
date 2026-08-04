//! Bounded-format text extraction — Rust port of the server's
//! lib/extractText.js (content-inspection groundwork).
//!
//! Turns file bytes into plain text so the detection layers (keyword /
//! fingerprint matching) can inspect content on the endpoint without ever
//! shelling out or touching the network. Same bounded format set and the
//! same machine-readable refusal reasons as the server:
//!   plain text  — .txt .md .csv .log + common source extensions (UTF-8,
//!                 with UTF-8 / UTF-16LE / UTF-16BE BOM handling)
//!   .docx/.xlsx/.pptx — OOXML zips, text pulled from the relevant XML
//!                 parts with a narrow scanner (no XML DOM)
//!   .pdf        — text layer only, via pdf-extract (no OCR)
//!   .zip        — recurse into supported members (depth/size bounded)
//!
//! Behaviour parity with the server matters (same formats readable, same
//! refusal reasons); byte-identical text does NOT — fingerprint
//! normalization absorbs whitespace differences between the two extractors.
//!
//! Bombs and abuse are bounded exactly like the server: 100MB input cap,
//! zip recursion depth cap, per-member and total-extracted-text caps, and
//! hard-capped inflation (a lying zip size field cannot balloon memory).
//!
//! NEVER log extracted text or input bytes here or in callers — document
//! content is exactly the sensitive data this product exists to protect.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{Cursor, Read};

/// Reject anything larger outright.
pub const MAX_BUFFER_BYTES: usize = 100 * 1024 * 1024;
/// Zip-in-zip nesting cap (top-level zip = depth 1).
pub const ZIP_MAX_DEPTH: u32 = 3;
/// Per-member inflated cap.
pub const ZIP_MEMBER_CAP_BYTES: u64 = 20 * 1024 * 1024;
/// Total extracted text cap (chars) across a zip recursion.
pub const ZIP_TOTAL_TEXT_CAP: usize = 10 * 1024 * 1024;

/// Machine-readable refusal reasons — the exact reason codes the server's
/// UnreadableError carries, so policy decisions stay consistent across the
/// server and the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    UnsupportedFormat,
    BinaryContent,
    EncryptedContainer,
    NoTextLayer,
    CorruptContainer,
    TooLarge,
}

impl Reason {
    /// Wire/reason code — identical strings to lib/extractText.js.
    pub fn code(self) -> &'static str {
        match self {
            Reason::UnsupportedFormat => "unsupported-format",
            Reason::BinaryContent => "binary-content",
            Reason::EncryptedContainer => "encrypted-container",
            Reason::NoTextLayer => "no-text-layer",
            Reason::CorruptContainer => "corrupt-container",
            Reason::TooLarge => "too-large",
        }
    }
}

/// Refusal error — mirrors the server's UnreadableError (message == reason).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unreadable {
    pub reason: Reason,
}

impl Unreadable {
    fn new(reason: Reason) -> Self {
        Self { reason }
    }
}

impl fmt::Display for Unreadable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason.code())
    }
}

impl std::error::Error for Unreadable {}

/// Successful extraction: the text plus the recognised format
/// ("text" | "docx" | "xlsx" | "pptx" | "pdf" | "zip").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedText {
    pub text: String,
    pub format: String,
}

// ---------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------

/// Plain-text family: decoded as UTF-8 (BOM-aware). Deliberately a closed
/// list — "looks like text" sniffing is how binary junk sneaks in.
fn is_text_extension(ext: &str) -> bool {
    matches!(
        ext,
        "txt" | "md" | "markdown" | "csv" | "tsv" | "log"
            // common source / config extensions
            | "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" | "json" | "xml" | "html"
            | "htm" | "css" | "py" | "java" | "c" | "h" | "cpp" | "hpp" | "cc" | "cs"
            | "go" | "rs" | "rb" | "php" | "pl" | "sh" | "bash" | "ps1" | "psm1"
            | "bat" | "cmd" | "sql" | "yaml" | "yml" | "ini" | "cfg" | "conf"
            | "toml" | "properties" | "env"
    )
}

fn extension_of(filename: &str) -> String {
    let base = filename.rsplit(['/', '\\']).next().unwrap_or("");
    match base.rfind('.') {
        // no extension, or dotfiles like ".env" — unsupported in v1
        Some(dot) if dot > 0 => base[dot + 1..].to_lowercase(),
        _ => String::new(),
    }
}

/// Decode ONLY the five predefined XML entities (v1 scope — OOXML writers
/// escape text content with exactly these).
fn decode_xml_entities(s: &str) -> String {
    const ENTITIES: [(&str, char); 5] = [
        ("&amp;", '&'),
        ("&lt;", '<'),
        ("&gt;", '>'),
        ("&quot;", '"'),
        ("&apos;", '\''),
    ];
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        match ENTITIES.iter().find(|(ent, _)| rest.starts_with(ent)) {
            Some((ent, ch)) => {
                out.push(*ch);
                rest = &rest[ent.len()..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// OLE/CFB magic — password-protected OOXML files are wrapped in a CFB
/// container (plain OOXML is a zip). Seeing this under a .docx/.xlsx/.pptx
/// name means "encrypted", not "legacy binary office".
fn is_cfb(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[0] == 0xd0 && bytes[1] == 0xcf && bytes[2] == 0x11 && bytes[3] == 0xe0
}

fn decode_utf16(body: &[u8], big_endian: bool) -> Result<String, Unreadable> {
    if body.len() % 2 != 0 {
        return Err(Unreadable::new(Reason::BinaryContent));
    }
    let units: Vec<u16> = body
        .chunks_exact(2)
        .map(|c| {
            if big_endian {
                u16::from_be_bytes([c[0], c[1]])
            } else {
                u16::from_le_bytes([c[0], c[1]])
            }
        })
        .collect();
    // Lossy, matching Node's Buffer.toString('utf16le') (unpaired
    // surrogates become U+FFFD rather than refusing the whole file).
    Ok(String::from_utf16_lossy(&units))
}

/// UTF-8 (BOM-aware) decode with sanity checks. NUL bytes or invalid UTF-8
/// mean "this is not text" — refuse rather than emit mojibake the policy
/// engine would silently fail to match against.
fn decode_plain_text(bytes: &[u8]) -> Result<String, Unreadable> {
    // UTF-16 BOMs first (a UTF-16 file is FULL of NUL bytes — legitimate).
    if bytes.len() >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe {
        return decode_utf16(&bytes[2..], false);
    }
    if bytes.len() >= 2 && bytes[0] == 0xfe && bytes[1] == 0xff {
        return decode_utf16(&bytes[2..], true);
    }
    if bytes.contains(&0x00) {
        return Err(Unreadable::new(Reason::BinaryContent));
    }
    let body = bytes.strip_prefix(b"\xef\xbb\xbf".as_slice()).unwrap_or(bytes);
    match std::str::from_utf8(body) {
        Ok(s) => Ok(s.to_string()),
        Err(_) => Err(Unreadable::new(Reason::BinaryContent)),
    }
}

// ---------------------------------------------------------------------
// zip plumbing (zip crate, bounded)
// ---------------------------------------------------------------------

/// `data: None` means the member exceeded the per-file cap and was skipped.
struct ZipEntry {
    name: String,
    data: Option<Vec<u8>>,
}

/// Read selected members of a zip buffer into memory, in archive order.
/// * ANY entry with the encryption bit set makes the whole container
///   'encrypted-container' — fail secure, no partials.
/// * Members whose (claimed or actual) inflated size exceeds the cap are
///   skipped via `data: None` — reads are hard-capped, so a lying size
///   field cannot balloon memory.
fn read_zip_entries(
    bytes: &[u8],
    should_read: &dyn Fn(&str) -> bool,
    per_file_cap: u64,
) -> Result<Vec<ZipEntry>, Unreadable> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|_| Unreadable::new(Reason::CorruptContainer))?;
    let mut out = Vec::new();
    for i in 0..archive.len() {
        // Raw handle first: the encryption check must run for EVERY entry,
        // including directories and members we will never read.
        let (name, size, wanted) = {
            let entry = archive
                .by_index_raw(i)
                .map_err(|_| Unreadable::new(Reason::CorruptContainer))?;
            if entry.encrypted() {
                return Err(Unreadable::new(Reason::EncryptedContainer));
            }
            let name = entry.name().to_string();
            let wanted = !entry.is_dir() && !name.ends_with('/') && should_read(&name);
            (name, entry.size(), wanted)
        };
        if !wanted {
            continue; // directory or not wanted — skip without inflating
        }
        if size > per_file_cap {
            out.push(ZipEntry { name, data: None });
            continue;
        }
        let mut entry = archive
            .by_index(i)
            .map_err(|_| Unreadable::new(Reason::CorruptContainer))?;
        let mut data = Vec::new();
        if (&mut entry)
            .take(per_file_cap + 1)
            .read_to_end(&mut data)
            .is_err()
        {
            return Err(Unreadable::new(Reason::CorruptContainer));
        }
        let oversized = data.len() as u64 > per_file_cap;
        out.push(ZipEntry {
            name,
            data: if oversized { None } else { Some(data) },
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// narrow OOXML scanning (no XML DOM — same v1 scope as the server's regex)
// ---------------------------------------------------------------------

/// Pull the text of every `<tag>` / `<tag attr…>` element from OOXML
/// markup, in document order. The OOXML text elements we target never nest
/// themselves, so a linear scan is sufficient.
fn xml_element_text(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(found) = xml[pos..].find(&open) {
        let after_open = pos + found + open.len();
        let rest = &xml[after_open..];
        let content_start = if rest.starts_with('>') {
            after_open + 1
        } else if rest.chars().next().is_some_and(char::is_whitespace) {
            // attributes: skip to the closing '>' of the start tag
            match rest.find('>') {
                Some(gt) => after_open + gt + 1,
                None => break,
            }
        } else {
            // longer tag name sharing the prefix (e.g. <w:tbl> vs <w:t>)
            pos = after_open;
            continue;
        };
        match xml[content_start..].find(&close) {
            Some(end) => {
                out.push(decode_xml_entities(&xml[content_start..content_start + end]));
                pos = content_start + end + close.len();
            }
            None => break,
        }
    }
    out
}

// ---------------------------------------------------------------------
// per-format extractors
// ---------------------------------------------------------------------

fn is_docx_part(name: &str) -> bool {
    if name == "word/document.xml" {
        return true;
    }
    // word/header\d*.xml | word/footer\d*.xml
    let Some(rest) = name.strip_prefix("word/") else {
        return false;
    };
    let Some(digits) = rest
        .strip_prefix("header")
        .or_else(|| rest.strip_prefix("footer"))
        .and_then(|r| r.strip_suffix(".xml"))
    else {
        return false;
    };
    digits.chars().all(|c| c.is_ascii_digit())
}

/// .docx — word/document.xml (+ headers/footers). `<w:t>` holds the runs;
/// `</w:p>` ends a paragraph, which we render as a newline.
fn extract_docx(bytes: &[u8]) -> Result<String, Unreadable> {
    let entries = read_zip_entries(bytes, &is_docx_part, ZIP_MEMBER_CAP_BYTES)?;
    let mut by_name: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for entry in entries {
        if let Some(data) = entry.data {
            by_name.insert(entry.name, data);
        }
    }
    if !by_name.contains_key("word/document.xml") {
        return Err(Unreadable::new(Reason::CorruptContainer));
    }
    // document.xml first, then headers/footers in sorted-name order
    // (BTreeMap iteration is already sorted).
    let part_names = std::iter::once("word/document.xml")
        .chain(by_name.keys().map(String::as_str).filter(|n| *n != "word/document.xml"));
    let mut paragraphs = Vec::new();
    for name in part_names {
        let xml = String::from_utf8_lossy(&by_name[name]);
        for chunk in xml.split("</w:p>") {
            let runs = xml_element_text(chunk, "w:t").concat();
            if !runs.is_empty() {
                paragraphs.push(runs);
            }
        }
    }
    Ok(paragraphs.join("\n"))
}

fn is_xlsx_part(name: &str) -> bool {
    if name == "xl/sharedStrings.xml" {
        return true;
    }
    // xl/worksheets/sheet[^/]*.xml
    name.strip_prefix("xl/worksheets/sheet")
        .and_then(|r| r.strip_suffix(".xml"))
        .is_some_and(|mid| !mid.contains('/'))
}

/// .xlsx — the shared-string table plus inline strings in the sheets.
/// (Numbers/formulas are not text content and are out of v1 scope.)
fn extract_xlsx(bytes: &[u8]) -> Result<String, Unreadable> {
    let entries = read_zip_entries(bytes, &is_xlsx_part, ZIP_MEMBER_CAP_BYTES)?;
    let usable: Vec<&ZipEntry> = entries.iter().filter(|e| e.data.is_some()).collect();
    if usable.is_empty() {
        return Err(Unreadable::new(Reason::CorruptContainer));
    }
    let mut parts = Vec::new();
    for entry in usable {
        let xml = String::from_utf8_lossy(entry.data.as_deref().unwrap_or_default());
        if entry.name == "xl/sharedStrings.xml" {
            parts.extend(xml_element_text(&xml, "t"));
        } else {
            // inline strings live in <is><t>…</t></is> cells; only pull those
            let mut pos = 0;
            while let Some(found) = xml[pos..].find("<is>") {
                let start = pos + found;
                match xml[start..].find("</is>") {
                    Some(end) => {
                        let block = &xml[start..start + end + "</is>".len()];
                        parts.extend(xml_element_text(block, "t"));
                        pos = start + end + "</is>".len();
                    }
                    None => break,
                }
            }
        }
    }
    Ok(parts.join("\n"))
}

/// ppt/slides/slideN.xml → N
fn pptx_slide_number(name: &str) -> Option<u64> {
    let digits = name
        .strip_prefix("ppt/slides/slide")?
        .strip_suffix(".xml")?;
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// .pptx — every ppt/slides/slideN.xml in slide order; `<a:t>` holds the text.
fn extract_pptx(bytes: &[u8]) -> Result<String, Unreadable> {
    let entries = read_zip_entries(bytes, &|n| pptx_slide_number(n).is_some(), ZIP_MEMBER_CAP_BYTES)?;
    let mut usable: Vec<(u64, Vec<u8>)> = entries
        .into_iter()
        .filter_map(|e| Some((pptx_slide_number(&e.name)?, e.data?)))
        .collect();
    if usable.is_empty() {
        return Err(Unreadable::new(Reason::CorruptContainer));
    }
    usable.sort_by_key(|(n, _)| *n);
    let slides: Vec<String> = usable
        .iter()
        .map(|(_, data)| xml_element_text(&String::from_utf8_lossy(data), "a:t").join("\n"))
        .collect();
    Ok(slides.join("\n"))
}

/// .pdf — text layer only (no OCR; scanned documents refuse loudly so
/// policy can decide, instead of silently matching nothing). pdf-extract
/// panics on some malformed inputs, so the call is unwind-guarded — a
/// hostile PDF must refuse, never crash the agent.
fn extract_pdf(bytes: &[u8]) -> Result<String, Unreadable> {
    let text = match std::panic::catch_unwind(|| pdf_extract::extract_text_from_mem(bytes)) {
        Ok(Ok(text)) => text,
        Ok(Err(err)) => {
            // lopdf reports password-protected PDFs as decryption errors.
            let msg = err.to_string().to_lowercase();
            if msg.contains("decrypt") || msg.contains("password") || msg.contains("encrypt") {
                return Err(Unreadable::new(Reason::EncryptedContainer));
            }
            return Err(Unreadable::new(Reason::CorruptContainer));
        }
        Err(_) => return Err(Unreadable::new(Reason::CorruptContainer)),
    };
    if text.trim().is_empty() {
        return Err(Unreadable::new(Reason::NoTextLayer));
    }
    Ok(text)
}

// ---------------------------------------------------------------------
// zip recursion + dispatch
// ---------------------------------------------------------------------

struct Budget {
    remaining: usize, // chars of extracted text still allowed
}

/// First `max_chars` chars of `text` (byte-safe) plus the char count used.
fn clip_chars(text: &str, max_chars: usize) -> (&str, usize) {
    if text.len() <= max_chars {
        return (text, text.chars().count()); // bytes >= chars, so it fits
    }
    let mut count = 0;
    for (i, _) in text.char_indices() {
        if count == max_chars {
            return (&text[..i], count);
        }
        count += 1;
    }
    (text, count)
}

/// .zip — recurse into supported members, bounded (see caps at top).
/// Unsupported/unreadable members are skipped SILENTLY (a zip full of .exes
/// legitimately yields the text of just its one .txt) — but encryption
/// anywhere inside still refuses the whole container, fail secure.
fn extract_zip(bytes: &[u8], depth: u32, budget: &mut Budget) -> Result<String, Unreadable> {
    let entries = read_zip_entries(bytes, &|_| true, ZIP_MEMBER_CAP_BYTES)?;
    let mut pieces = Vec::new();
    for entry in entries {
        let Some(data) = entry.data else {
            continue; // oversized member
        };
        if budget.remaining == 0 {
            break;
        }
        let ext = extension_of(&entry.name);
        if ext == "zip" && depth >= ZIP_MAX_DEPTH {
            continue; // depth cap: skip, don't recurse
        }
        let next_depth = depth + u32::from(ext == "zip");
        match extract_by_extension(&data, &ext, next_depth, budget) {
            Ok(text) => {
                if text.is_empty() {
                    continue;
                }
                let (clipped, used) = clip_chars(&text, budget.remaining);
                budget.remaining -= used;
                pieces.push(clipped.to_string());
            }
            Err(err) if err.reason == Reason::EncryptedContainer => {
                return Err(err); // encryption anywhere = refuse whole container
            }
            Err(_) => continue, // unsupported/binary/corrupt member — skip silently
        }
    }
    Ok(pieces.join("\n"))
}

fn extract_by_extension(
    bytes: &[u8],
    ext: &str,
    depth: u32,
    budget: &mut Budget,
) -> Result<String, Unreadable> {
    if is_text_extension(ext) {
        return decode_plain_text(bytes);
    }
    match ext {
        "docx" | "xlsx" | "pptx" => {
            if is_cfb(bytes) {
                return Err(Unreadable::new(Reason::EncryptedContainer));
            }
            match ext {
                "docx" => extract_docx(bytes),
                "xlsx" => extract_xlsx(bytes),
                _ => extract_pptx(bytes),
            }
        }
        "pdf" => extract_pdf(bytes),
        "zip" => extract_zip(bytes, depth, budget),
        _ => Err(Unreadable::new(Reason::UnsupportedFormat)),
    }
}

/// Extract plain text from file bytes. Returns the text and the recognised
/// format; refuses anything outside the bounded v1 scope with the same
/// reason codes as the server.
pub fn extract_text(bytes: &[u8], filename: &str) -> Result<ExtractedText, Unreadable> {
    if bytes.len() > MAX_BUFFER_BYTES {
        return Err(Unreadable::new(Reason::TooLarge));
    }
    let ext = extension_of(filename);
    let mut budget = Budget {
        remaining: ZIP_TOTAL_TEXT_CAP,
    };
    let text = extract_by_extension(bytes, &ext, 1, &mut budget)?;
    let format = if is_text_extension(&ext) {
        "text".to_string()
    } else {
        ext
    };
    Ok(ExtractedText { text, format })
}
