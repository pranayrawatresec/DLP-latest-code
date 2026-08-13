//! Browser native-messaging host (Tier-2 plan §3, mechanism ④).
//!
//! Content visibility on the web-upload channel — the TLS-blind spot of WFP. A
//! force-installed MV3 extension intercepts `<input type=file>` / drag-drop /
//! fetch-with-body uploads, hands the file/text to THIS host over Chrome native
//! messaging, and blocks the upload on a `block` verdict.
//!
//! PINNED protocol (extension ⇄ host — both sides must match):
//!   Framing: 4-byte LITTLE-ENDIAN length prefix + UTF-8 JSON.
//!   Request  (ext→host): {"version":1,"kind":"scan_text"|"scan_file"|"scan_bytes",
//!                          "text"?:string,"path"?:string,"content_b64"?:string,
//!                          "url":string,"origin":string,"id":number}
//!     - scan_text : `text` is the readable text (paste / text-like file prefix).
//!     - scan_bytes: `content_b64` is base64 of the file's bytes and `path` is the
//!                   filename (format detection); the host runs `verdict_bytes`,
//!                   i.e. REAL content inspection of PDF/DOCX/XLSX like an endpoint
//!                   DLP. This is the Purview-equivalent binary path.
//!     - scan_file : legacy name-only (browsers sandbox the disk path); kept for
//!                   compatibility but scan_bytes is preferred for binaries.
//!   Reply    (host→ext): {"version":1,"id":number,
//!                          "verdict":"allow"|"block"|"warn",
//!                          "reason"?:string,
//!                          "match"?:{"title":string,"containment":number}}
//!
//! Scoring reuses the FROZEN `detect::verdict`/`verdict_text` (DO-NOT change
//! `detect/`). `detect` is audit-only (no allow/block mapping), so we map the
//! verdict to allow/warn/block HERE using the same thresholds as
//! `kguard::should_block` (containment ≥ block_at OR coverage ≥ coverage_block_at
//! OR any EDM hit ⇒ block; any lesser match ⇒ warn; else allow).
//!
//! NEVER logs or transmits file/upload CONTENT: the reply and any incident carry
//! only hashes, scores, the match title, and the url/origin metadata.
//!
//! Verifiable here: the framing (encode/decode) and the verdict→reply mapping are
//! unit-tested with an injected scanner. True end-to-end (real Chrome →
//! extension → host) is operator-MANUAL (plan §3).

use std::io::{self, Read, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::detect::Verdict;

/// Max message the host will accept. Chrome's 1 MB cap is on messages the host
/// SENDS to the extension; messages FROM the extension may be larger, and a
/// `scan_bytes` upload carries base64 file content (≈1.33× the raw bytes). We
/// accept up to 8 MiB so a ~4 MiB file (the extension's read cap, matching the
/// kernel content cap) fits with room for the JSON envelope; a larger declared
/// length is rejected rather than allocated.
pub const MAX_MESSAGE_BYTES: u32 = 8 * 1024 * 1024;

/// Max raw file bytes the host will content-inspect from a `scan_bytes` upload
/// (mirrors the extension's read cap and the kernel's DLP_MAX_CONTENT).
pub const MAX_SCAN_BYTES: usize = 4 * 1024 * 1024;

/// Default block thresholds (mirror `[kguard]` / `[clipboard]`).
pub const DEFAULT_BLOCK_AT: f64 = 0.30;
pub const DEFAULT_COVERAGE_BLOCK_AT: f64 = 0.60;

/// What the extension asked us to scan.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanKind {
    ScanText,
    ScanFile,
    /// Binary upload (PDF/DOCX/XLSX/…): the extension read the file's bytes and
    /// sent them base64 in `content_b64` (with `path` = the filename for format
    /// detection). The host decodes and runs `verdict_bytes` — real content
    /// inspection of a binary file, like an endpoint DLP.
    ScanBytes,
}

/// A request from the extension.
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    #[serde(default = "one")]
    pub version: u32,
    pub kind: ScanKind,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    /// base64 of the file's bytes (for `scan_bytes`). Present only for binary
    /// uploads; never logged.
    #[serde(default)]
    pub content_b64: Option<String>,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub origin: String,
    pub id: u64,
}

fn one() -> u32 {
    1
}

/// The allow/block/warn disposition (lowercase on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WebVerdict {
    Allow,
    Block,
    Warn,
}

/// The strongest match, echoed to the extension for its UI (title + containment
/// only — never content).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MatchInfo {
    pub title: String,
    pub containment: f64,
}

/// A reply to the extension.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Reply {
    pub version: u32,
    pub id: u64,
    pub verdict: WebVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "match", skip_serializing_if = "Option::is_none")]
    pub match_: Option<MatchInfo>,
}

impl Reply {
    fn new(id: u64, verdict: WebVerdict, reason: Option<String>, match_: Option<MatchInfo>) -> Self {
        Reply { version: 1, id, verdict, reason, match_ }
    }
}

/// Read one native-messaging frame: a 4-byte LE length prefix + that many bytes.
/// Returns `Ok(None)` on a clean EOF (the browser closed the pipe).
pub fn read_message<R: Read>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("native message length {len} exceeds cap {MAX_MESSAGE_BYTES}"),
        ));
    }
    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Write one native-messaging frame: a 4-byte LE length prefix + the bytes.
pub fn write_message<W: Write>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    let len = bytes.len() as u32;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()
}

/// Map a `detect::Verdict` to a web disposition using the shared thresholds
/// (mirror `kguard::should_block`). Returns the disposition + the strongest
/// match (if any) for the reply/incident. Pure — no I/O.
pub fn map_verdict(v: &Verdict, block_at: f64, coverage_block_at: f64) -> (WebVerdict, Option<MatchInfo>) {
    // Strongest IDM match (verdict already sorts strongest-first) for the UI.
    let strongest = v.idm.first().map(|m| MatchInfo {
        title: m.title.clone(),
        containment: m.containment,
    });

    let block = !v.edm.is_empty()
        || v
            .idm
            .iter()
            .any(|m| m.containment >= block_at || m.coverage >= coverage_block_at);
    if block {
        return (WebVerdict::Block, strongest);
    }
    // A lesser match (below block thresholds) → warn (audit but let through).
    if !v.idm.is_empty() || !v.edm.is_empty() {
        return (WebVerdict::Warn, strongest);
    }
    (WebVerdict::Allow, None)
}

/// The outcome of handling one request: the reply to send, plus the scored
/// verdict + a human label (for the incident) when a scan produced one.
pub struct Handled {
    pub reply: Reply,
    /// Present when a verdict was produced AND it is worth an incident (a match).
    pub incident: Option<(Verdict, String)>,
}

/// Handle one request with INJECTED scanners (so this is unit-testable without a
/// real `Bundle`). `scan_text` scores raw text; `scan_file` scores a file path.
/// Either may be absent from the request → an `allow` reply with a reason.
pub fn handle_request<FT, FF, FB>(
    req: &Request,
    block_at: f64,
    coverage_block_at: f64,
    scan_text: FT,
    scan_file: FF,
    scan_bytes: FB,
) -> Handled
where
    FT: FnOnce(&str) -> Verdict,
    FF: FnOnce(&Path) -> anyhow::Result<Verdict>,
    FB: FnOnce(&[u8], &str) -> Verdict,
{
    let verdict = match req.kind {
        ScanKind::ScanText => match &req.text {
            Some(t) => Ok(scan_text(t)),
            None => Err("scan_text request without text".to_string()),
        },
        ScanKind::ScanFile => match &req.path {
            Some(p) => scan_file(Path::new(p)).map_err(|e| format!("file scan failed: {e}")),
            None => Err("scan_file request without path".to_string()),
        },
        ScanKind::ScanBytes => match &req.content_b64 {
            Some(b64) => {
                use base64::Engine;
                match base64::engine::general_purpose::STANDARD.decode(b64) {
                    Ok(mut bytes) => {
                        // Bound what we score, matching the extension/kernel cap.
                        if bytes.len() > MAX_SCAN_BYTES {
                            bytes.truncate(MAX_SCAN_BYTES);
                        }
                        // Filename (from `path`) only drives extractor format
                        // selection; content comes from the decoded bytes.
                        let name = req
                            .path
                            .as_deref()
                            .and_then(|p| Path::new(p).file_name().map(|s| s.to_string_lossy().into_owned()))
                            .unwrap_or_else(|| "upload".to_string());
                        Ok(scan_bytes(&bytes, &name))
                    }
                    Err(e) => Err(format!("scan_bytes base64 decode failed: {e}")),
                }
            }
            None => Err("scan_bytes request without content_b64".to_string()),
        },
    };

    match verdict {
        Ok(v) => {
            let (disp, mi) = map_verdict(&v, block_at, coverage_block_at);
            let reason = match disp {
                WebVerdict::Allow => None,
                WebVerdict::Block => Some("matched protected content".to_string()),
                WebVerdict::Warn => Some("partial match — audited".to_string()),
            };
            let incident = if disp != WebVerdict::Allow {
                let label = match req.kind {
                    ScanKind::ScanText => "(web upload text)".to_string(),
                    ScanKind::ScanFile | ScanKind::ScanBytes => req
                        .path
                        .as_deref()
                        .map(|p| Path::new(p).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| p.to_string()))
                        .unwrap_or_else(|| "(web upload file)".to_string()),
                };
                Some((v, label))
            } else {
                None
            };
            Handled {
                reply: Reply::new(req.id, disp, reason, mi),
                incident,
            }
        }
        Err(reason) => Handled {
            // Malformed request → allow (do not brick the browser) but say why.
            reply: Reply::new(req.id, WebVerdict::Allow, Some(reason), None),
            incident: None,
        },
    }
}

/// Build the incident wire body's `UsbIncident` for a web-upload match, reusing
/// the shared incident type (channel "web-upload"). Carries the verdict so the
/// shared sink POSTS it over mTLS (a real detection, unlike metadata-only network
/// incidents). `url`/`origin` are metadata (allowed to log) — NOT content.
pub fn web_incident(
    verdict: Verdict,
    label: &str,
    blocked: bool,
    url: &str,
    origin: &str,
    channel: &str,
) -> crate::usb::UsbIncident {
    use crate::usb::{ActionTaken, DeviceIdentity, IncidentKind, UsbIncident};
    UsbIncident {
        kind: IncidentKind::Match,
        channel: channel.to_string(),
        file_name: label.to_string(),
        file_sha256: verdict.file_sha256.clone(),
        verdict: Some(verdict),
        device: DeviceIdentity {
            drive_letter: String::new(),
            vendor_id: String::new(),
            product_id: String::new(),
            serial: String::new(),
            product_name: origin.to_string(),
            bus_type: "web".into(),
            removable: false,
        },
        action_taken: if blocked { ActionTaken::Blocked } else { ActionTaken::Audited },
        // Metadata only: url + origin. NEVER the uploaded content.
        note: Some(format!("url={url} origin={origin}")),
        key_id: None,
        sealed_sha256: None,
    }
}

/// Run the native-messaging loop over the given reader/writer until EOF. For each
/// request: score (injected scanners), reply, and hand any match to `incident`.
/// Generic over I/O + scanners so the binary wires stdio + `detect`, and tests
/// can drive it in-memory.
pub fn serve<R, W, FT, FF, FB, S>(
    reader: &mut R,
    writer: &mut W,
    block_at: f64,
    coverage_block_at: f64,
    channel: &str,
    mut scan_text: FT,
    mut scan_file: FF,
    mut scan_bytes: FB,
    mut incident: S,
) -> io::Result<()>
where
    R: Read,
    W: Write,
    FT: FnMut(&str) -> Verdict,
    FF: FnMut(&Path) -> anyhow::Result<Verdict>,
    FB: FnMut(&[u8], &str) -> Verdict,
    S: FnMut(crate::usb::UsbIncident),
{
    while let Some(body) = read_message(reader)? {
        let req: Request = match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "malformed native message — ignoring");
                continue;
            }
        };
        let handled = handle_request(
            &req,
            block_at,
            coverage_block_at,
            |t| scan_text(t),
            |p| scan_file(p),
            |b, n| scan_bytes(b, n),
        );
        let blocked = handled.reply.verdict == WebVerdict::Block;
        if let Some((verdict, label)) = handled.incident {
            incident(web_incident(verdict, &label, blocked, &req.url, &req.origin, channel));
        }
        let bytes = serde_json::to_vec(&handled.reply)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_message(writer, &bytes)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{EdmRowHit, EdmSourceHit, Extraction, IdmMatch, Verdict};

    fn clean() -> Verdict {
        Verdict {
            file_name: String::new(),
            file_sha256: "sha".into(),
            extraction: Extraction::Ok { format: "text".into() },
            idm: vec![],
            edm: vec![],
        }
    }

    fn with_idm(containment: f64, coverage: f64) -> Verdict {
        let mut v = clean();
        v.idm.push(IdmMatch {
            version_id: "v".into(),
            document_id: "d".into(),
            collection_id: "c".into(),
            title: "Secret Plan".into(),
            containment,
            coverage,
            matched_count: 1,
            total_count: 1,
            matched_hashes: vec!["1".into()],
        });
        v
    }

    #[test]
    fn framing_roundtrip_little_endian() {
        let payload = br#"{"hello":"world"}"#;
        let mut buf = Vec::new();
        write_message(&mut buf, payload).unwrap();
        // 4-byte LE length prefix.
        assert_eq!(&buf[..4], &(payload.len() as u32).to_le_bytes());
        let mut cursor = std::io::Cursor::new(buf);
        let got = read_message(&mut cursor).unwrap().unwrap();
        assert_eq!(got, payload);
        // Second read hits EOF cleanly.
        assert!(read_message(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn oversize_length_prefix_is_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_MESSAGE_BYTES + 1).to_le_bytes());
        let mut cursor = std::io::Cursor::new(buf);
        assert!(read_message(&mut cursor).is_err());
    }

    #[test]
    fn map_verdict_blocks_on_containment_and_edm() {
        assert_eq!(map_verdict(&with_idm(0.5, 0.0), 0.30, 0.60).0, WebVerdict::Block);
        let mut v = clean();
        v.edm.push(EdmSourceHit {
            source_id: "s".into(),
            name: "PII".into(),
            rows_hit: vec![EdmRowHit { row_id: 1, fields: vec!["x".into()] }],
        });
        assert_eq!(map_verdict(&v, 0.30, 0.60).0, WebVerdict::Block);
    }

    #[test]
    fn map_verdict_warns_on_lesser_match_and_allows_clean() {
        let (disp, mi) = map_verdict(&with_idm(0.10, 0.10), 0.30, 0.60);
        assert_eq!(disp, WebVerdict::Warn);
        assert_eq!(mi.unwrap().title, "Secret Plan");
        assert_eq!(map_verdict(&clean(), 0.30, 0.60).0, WebVerdict::Allow);
    }

    #[test]
    fn handle_scan_text_block_produces_incident() {
        let req = Request {
            version: 1,
            kind: ScanKind::ScanText,
            text: Some("...".into()),
            path: None,
            content_b64: None,
            url: "https://mail.example.com/upload".into(),
            origin: "https://mail.example.com".into(),
            id: 42,
        };
        let handled = handle_request(
            &req,
            0.30,
            0.60,
            |_t| with_idm(0.9, 0.9),
            |_p| unreachable!("scan_file not called for scan_text"),
            |_b, _n| unreachable!("scan_bytes not called for scan_text"),
        );
        assert_eq!(handled.reply.verdict, WebVerdict::Block);
        assert_eq!(handled.reply.id, 42);
        assert!(handled.incident.is_some());
        let (_v, label) = handled.incident.unwrap();
        assert_eq!(label, "(web upload text)");
    }

    #[test]
    fn handle_missing_text_allows_with_reason() {
        let req = Request {
            version: 1,
            kind: ScanKind::ScanText,
            text: None,
            path: None,
            content_b64: None,
            url: String::new(),
            origin: String::new(),
            id: 7,
        };
        let handled = handle_request(&req, 0.30, 0.60, |_| clean(), |_| Ok(clean()), |_, _| clean());
        assert_eq!(handled.reply.verdict, WebVerdict::Allow);
        assert!(handled.reply.reason.is_some());
        assert!(handled.incident.is_none());
    }

    #[test]
    fn handle_scan_bytes_decodes_content_and_blocks() {
        use base64::Engine;
        let raw = b"pretend this is the OPORD pdf bytes";
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        let req = Request {
            version: 1,
            kind: ScanKind::ScanBytes,
            text: None,
            path: Some("OperationHimalayanShield_OPORD.pdf".into()),
            content_b64: Some(b64),
            url: "https://drive.example.com/upload".into(),
            origin: "https://drive.example.com".into(),
            id: 11,
        };
        let handled = handle_request(
            &req,
            0.30,
            0.60,
            |_t| unreachable!("scan_text not called for scan_bytes"),
            |_p| unreachable!("scan_file not called for scan_bytes"),
            |bytes, name| {
                // The host must hand the decoded bytes + the filename (for
                // extractor format selection) to the byte scanner.
                assert_eq!(bytes, b"pretend this is the OPORD pdf bytes");
                assert_eq!(name, "OperationHimalayanShield_OPORD.pdf");
                with_idm(0.9, 0.9)
            },
        );
        assert_eq!(handled.reply.verdict, WebVerdict::Block);
        let (_v, label) = handled.incident.expect("a block raises an incident");
        assert_eq!(label, "OperationHimalayanShield_OPORD.pdf");
    }

    #[test]
    fn handle_scan_bytes_bad_base64_allows_with_reason() {
        let req = Request {
            version: 1,
            kind: ScanKind::ScanBytes,
            text: None,
            path: Some("x.pdf".into()),
            content_b64: Some("!!!not base64!!!".into()),
            url: String::new(),
            origin: String::new(),
            id: 3,
        };
        let handled = handle_request(&req, 0.30, 0.60, |_| clean(), |_| Ok(clean()), |_, _| clean());
        // Malformed content must not brick the browser → allow with a reason.
        assert_eq!(handled.reply.verdict, WebVerdict::Allow);
        assert!(handled.reply.reason.is_some());
    }

    #[test]
    fn reply_serializes_pinned_shape() {
        let r = Reply::new(
            5,
            WebVerdict::Block,
            Some("matched protected content".into()),
            Some(MatchInfo { title: "Plan".into(), containment: 0.9 }),
        );
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""version":1"#));
        assert!(json.contains(r#""id":5"#));
        assert!(json.contains(r#""verdict":"block""#));
        assert!(json.contains(r#""match":{"title":"Plan""#));
    }

    #[test]
    fn allow_reply_omits_reason_and_match() {
        let r = Reply::new(1, WebVerdict::Allow, None, None);
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("reason"));
        assert!(!json.contains("match"));
    }

    #[test]
    fn serve_roundtrip_over_pipe_with_stub_scanner() {
        // One scan_text request → block reply + one incident.
        let req = br#"{"version":1,"kind":"scan_text","text":"x","url":"https://u/","origin":"https://o","id":9}"#;
        let mut input = Vec::new();
        write_message(&mut input, req).unwrap();
        let mut reader = std::io::Cursor::new(input);
        let mut out = Vec::new();
        let mut incidents = Vec::new();
        serve(
            &mut reader,
            &mut out,
            0.30,
            0.60,
            "web-upload",
            |_t| with_idm(0.9, 0.9),
            |_p| Ok(clean()),
            |_b, _n| clean(),
            |inc| incidents.push(inc),
        )
        .unwrap();
        // Decode the reply frame.
        let mut rc = std::io::Cursor::new(out);
        let body = read_message(&mut rc).unwrap().unwrap();
        let reply: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(reply["verdict"], "block");
        assert_eq!(reply["id"], 9);
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].channel, "web-upload");
        assert_eq!(incidents[0].device.bus_type, "web");
    }
}
