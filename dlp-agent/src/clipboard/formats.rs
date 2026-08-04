//! Clipboard format classification + parsing (spec §1.1 `formats.rs`).
//!
//! The bytes → payload step is a set of PURE functions unit-tested with
//! synthetic buffers (CF_UNICODETEXT UTF-16 blobs, CF_HDROP `DROPFILES`
//! structures) — no Win32, no live clipboard. The live read that fills those
//! buffers lives in `watch.rs` behind `#[cfg(windows)]` and is operator-manual.
//!
//! What each format becomes:
//!   * `CF_UNICODETEXT` → `Text` (scored with `detect::verdict_text`).
//!   * `CF_HDROP`       → `Files` (each path scored with `detect::verdict`).
//!   * `CF_HTML`/`CF_RTF` → best-effort stripped to `Text`.
//!   * `CF_DIB`/`CF_BITMAP` → `Image` (uninspectable without OCR — out of scope).
//!   * anything else    → `Uninspected` note (never crashes).
//!
//! NEVER log or persist the parsed text/paths — only hashes/scores leave here
//! (spec §1.3): the payload is handed straight to the fingerprint math.

use std::path::PathBuf;

/// A classified, inspectable clipboard snapshot. Carries the raw text/paths ONLY
/// long enough to fingerprint them; callers must not log or store the content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardPayload {
    /// Unicode text (from CF_UNICODETEXT, or stripped CF_HTML/CF_RTF).
    Text(String),
    /// A file drop (CF_HDROP) — a list of paths copied to the clipboard.
    Files(Vec<PathBuf>),
    /// A bitmap/DIB image — not inspectable without OCR (out of scope §1.4).
    Image,
    /// The clipboard held nothing we recognise (empty, or an unhandled format).
    Uninspected(String),
}

/// Standard clipboard format ids we handle (winuser.h). Kept as a local table so
/// the pure parser has no Windows dependency and builds cross-platform.
pub const CF_BITMAP: u32 = 2;
pub const CF_DIB: u32 = 8;
pub const CF_DIBV5: u32 = 17;
pub const CF_HDROP: u32 = 15;
pub const CF_UNICODETEXT: u32 = 13;

/// Decode a CF_UNICODETEXT global-memory blob (UTF-16LE, NUL-terminated) into a
/// Rust `String`. Stops at the first NUL; a dangling final byte is ignored;
/// invalid units are replaced (lossy) rather than panicking (spec §1.4 edge 6:
/// never crash on odd formats).
pub fn parse_unicode_text(bytes: &[u8]) -> String {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let u = u16::from_le_bytes([pair[0], pair[1]]);
        if u == 0 {
            break; // NUL terminator ends the string
        }
        units.push(u);
    }
    String::from_utf16_lossy(&units)
}

// DROPFILES header layout (shlobj_core.h), all little-endian:
//   DWORD pFiles;  // offset (bytes) to the file list        @0
//   POINT pt;      // 2 * LONG                                 @4
//   BOOL  fNC;     // LONG                                     @12
//   BOOL  fWide;   // LONG (nonzero => UTF-16 names)           @16
const DROPFILES_MIN: usize = 20;
const OFF_PFILES: usize = 0;
const OFF_FWIDE: usize = 16;

fn read_u32_le(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

/// Parse a CF_HDROP `DROPFILES` blob into the list of dropped paths. The file
/// list is a run of NUL-terminated strings (wide if `fWide`, else ANSI) ending
/// in an empty string (double-NUL). Malformed/short buffers yield an empty list,
/// never a panic (spec §1.4 edge 6).
pub fn parse_hdrop(bytes: &[u8]) -> Vec<PathBuf> {
    if bytes.len() < DROPFILES_MIN {
        return Vec::new();
    }
    let p_files = read_u32_le(bytes, OFF_PFILES) as usize;
    let wide = read_u32_le(bytes, OFF_FWIDE) != 0;
    if p_files == 0 || p_files > bytes.len() {
        return Vec::new();
    }
    let list = &bytes[p_files..];
    let mut out = Vec::new();

    if wide {
        // UTF-16LE strings, each NUL-terminated; empty string ends the list.
        let mut cur: Vec<u16> = Vec::new();
        for pair in list.chunks_exact(2) {
            let u = u16::from_le_bytes([pair[0], pair[1]]);
            if u == 0 {
                if cur.is_empty() {
                    break; // double-NUL: end of list
                }
                out.push(PathBuf::from(String::from_utf16_lossy(&cur)));
                cur.clear();
            } else {
                cur.push(u);
            }
        }
    } else {
        // ANSI strings, each NUL-terminated; empty string ends the list.
        let mut start = 0usize;
        let mut i = 0usize;
        while i < list.len() {
            if list[i] == 0 {
                if i == start {
                    break; // double-NUL: end of list
                }
                let s = String::from_utf8_lossy(&list[start..i]).into_owned();
                out.push(PathBuf::from(s));
                start = i + 1;
            }
            i += 1;
        }
    }
    out
}

/// Best-effort strip of a CF_HTML payload to plain text. CF_HTML is UTF-8 with a
/// small `Version:/StartHTML:/StartFragment:` header followed by an HTML
/// document; we drop the header, then remove tags and comments. This is a
/// heuristic for fingerprinting only — not a compliant HTML parser.
pub fn strip_html(input: &str) -> String {
    // Skip the CF_HTML descriptor header: everything up to the first '<'.
    let body = match input.find('<') {
        Some(i) => &input[i..],
        None => input,
    };
    strip_tags(body)
}

/// Best-effort strip of an RTF payload to plain text: drop control words
/// (`\word`), braces, and the header groups. Heuristic, for fingerprinting only.
pub fn strip_rtf(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                // Control word: backslash + letters, optional numeric arg,
                // optional trailing space. Or an escaped char (\{ \} \\).
                if let Some(&n) = chars.peek() {
                    if n.is_ascii_alphabetic() {
                        while let Some(&m) = chars.peek() {
                            if m.is_ascii_alphabetic() {
                                chars.next();
                            } else {
                                break;
                            }
                        }
                        // optional numeric parameter
                        while let Some(&m) = chars.peek() {
                            if m.is_ascii_digit() || m == '-' {
                                chars.next();
                            } else {
                                break;
                            }
                        }
                        if chars.peek() == Some(&' ') {
                            chars.next();
                        }
                    } else {
                        // escaped literal char
                        chars.next();
                        out.push(n);
                    }
                }
            }
            '{' | '}' => {}
            _ => out.push(c),
        }
    }
    // Collapse whitespace runs for a cleaner token stream.
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Remove `<...>` tags and `<!-- -->` comments from a fragment, decode the few
/// most-common entities, and collapse whitespace.
fn strip_tags(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut depth = 0u32;
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '<' => depth += 1,
            '>' => {
                if depth > 0 {
                    depth -= 1;
                }
                out.push(' ');
            }
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    let decoded = out
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ");
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Is a clipboard format id an (uninspectable) image?
pub fn is_image_format(fmt: u32) -> bool {
    matches!(fmt, CF_BITMAP | CF_DIB | CF_DIBV5)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic CF_UNICODETEXT blob for `s` (UTF-16LE + NUL).
    fn unicode_blob(s: &str) -> Vec<u8> {
        let mut b: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        b.extend_from_slice(&[0, 0]); // NUL terminator
        b
    }

    /// Build a synthetic wide CF_HDROP blob from a list of paths.
    fn hdrop_wide(paths: &[&str]) -> Vec<u8> {
        let mut buf = vec![0u8; DROPFILES_MIN];
        buf[OFF_PFILES..OFF_PFILES + 4].copy_from_slice(&(DROPFILES_MIN as u32).to_le_bytes());
        buf[OFF_FWIDE..OFF_FWIDE + 4].copy_from_slice(&1u32.to_le_bytes()); // fWide
        for p in paths {
            for u in p.encode_utf16() {
                buf.extend_from_slice(&u.to_le_bytes());
            }
            buf.extend_from_slice(&[0, 0]); // string NUL
        }
        buf.extend_from_slice(&[0, 0]); // final empty string (double-NUL)
        buf
    }

    /// Build a synthetic ANSI CF_HDROP blob.
    fn hdrop_ansi(paths: &[&str]) -> Vec<u8> {
        let mut buf = vec![0u8; DROPFILES_MIN];
        buf[OFF_PFILES..OFF_PFILES + 4].copy_from_slice(&(DROPFILES_MIN as u32).to_le_bytes());
        // fWide left 0
        for p in paths {
            buf.extend_from_slice(p.as_bytes());
            buf.push(0);
        }
        buf.push(0); // final empty string
        buf
    }

    #[test]
    fn unicode_text_round_trips() {
        let b = unicode_blob("Operation fixture alpha.");
        assert_eq!(parse_unicode_text(&b), "Operation fixture alpha.");
    }

    #[test]
    fn unicode_text_stops_at_nul() {
        let mut b = unicode_blob("visible");
        // Append trailing junk after the NUL; must be ignored.
        b.extend_from_slice(&[0x41, 0x00]);
        assert_eq!(parse_unicode_text(&b), "visible");
    }

    #[test]
    fn unicode_text_odd_length_does_not_panic() {
        let b = vec![0x41, 0x00, 0x42]; // 'A', NUL, dangling
        assert_eq!(parse_unicode_text(&b), "A");
    }

    #[test]
    fn hdrop_wide_parses_multiple_paths() {
        let b = hdrop_wide(&[r"C:\secret\plan.docx", r"C:\a.txt"]);
        let paths = parse_hdrop(&b);
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], PathBuf::from(r"C:\secret\plan.docx"));
        assert_eq!(paths[1], PathBuf::from(r"C:\a.txt"));
    }

    #[test]
    fn hdrop_ansi_parses_paths() {
        let b = hdrop_ansi(&[r"C:\one.txt", r"C:\two.txt"]);
        let paths = parse_hdrop(&b);
        assert_eq!(paths, vec![PathBuf::from(r"C:\one.txt"), PathBuf::from(r"C:\two.txt")]);
    }

    #[test]
    fn hdrop_empty_or_short_is_empty_not_panic() {
        assert!(parse_hdrop(&[]).is_empty());
        assert!(parse_hdrop(&[0u8; 8]).is_empty());
        // pFiles pointing past the buffer must be rejected.
        let mut b = vec![0u8; DROPFILES_MIN];
        b[OFF_PFILES..OFF_PFILES + 4].copy_from_slice(&9999u32.to_le_bytes());
        assert!(parse_hdrop(&b).is_empty());
    }

    #[test]
    fn strip_html_extracts_visible_text() {
        let html = "Version:0.9\r\nStartHTML:00000097\r\n<html><body><p>Hello <b>secret</b> world</p></body></html>";
        let text = strip_html(html);
        assert!(text.contains("Hello"));
        assert!(text.contains("secret"));
        assert!(text.contains("world"));
        assert!(!text.contains('<'));
    }

    #[test]
    fn strip_rtf_extracts_visible_text() {
        let rtf = r"{\rtf1\ansi\deff0 {\fonttbl{\f0 Arial;}} Hello \b secret\b0 world}";
        let text = strip_rtf(rtf);
        assert!(text.contains("Hello"));
        assert!(text.contains("secret"));
        assert!(text.contains("world"));
        assert!(!text.contains('\\'));
    }

    #[test]
    fn image_format_ids_are_detected() {
        assert!(is_image_format(CF_DIB));
        assert!(is_image_format(CF_BITMAP));
        assert!(is_image_format(CF_DIBV5));
        assert!(!is_image_format(CF_UNICODETEXT));
        assert!(!is_image_format(CF_HDROP));
    }
}
