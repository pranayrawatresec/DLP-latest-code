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
//! verdict to allow/warn/block HERE, via the shared fusion `detect::decide`:
//! containment ≥ block_at OR coverage ≥ coverage_block_at OR any EDM hit ⇒ block
//! (the same bands `kguard::should_block` applies), any lesser match ⇒ warn, else
//! allow.
//!
//! On top of that the ONNX document classifier is fused in as a SECOND,
//! independent signal — which is what catches the upload this channel could
//! otherwise never see: a sensitive document nobody ever fingerprinted. It can
//! only ADD (`sensitive = fingerprint OR ml`); an ML hit maps to block under the
//! ML policy's `action = "block"` and to warn under `audit`, and an UNAVAILABLE
//! model honours `failBlock` because a web upload is an egress path.
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

use crate::detect::{self, Verdict};
use crate::mlpolicy::MlPolicy;

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

/// Map a `detect::Verdict` to a web disposition, fusing BOTH detection signals
/// through `detect::decide` (the fingerprint half is the same band test
/// `kguard::should_block` applies). Returns the disposition + the strongest match
/// (if any) for the reply/incident. Pure — no I/O; the ML policy comes in as
/// `ml`, so this stays exhaustively unit-testable.
///
/// Mapping semantics are preserved and extended, in priority order:
/// * fingerprint hit (EDM row, or an IDM match at/over the bands) → **Block**, as
///   before;
/// * an ML hit (a class the admin marked, at/over its threshold) → **Block** when
///   the ML policy's `action` is `block`, **Warn** when it is `audit` — a brand-new
///   signal must not silently start denying uploads;
/// * the model was UNAVAILABLE while the policy is live → **Block** if `failBlock`.
///   A web upload is egress, so it honours fail-secure (unlike the kernel read
///   path, which never does);
/// * a lesser fingerprint match, below the bands → **Warn**, as before;
/// * nothing → **Allow**.
pub fn map_verdict(
    v: &Verdict,
    block_at: f64,
    coverage_block_at: f64,
    ml: &MlPolicy,
) -> (WebVerdict, Option<MatchInfo>) {
    // Strongest IDM match (verdict already sorts strongest-first) for the UI.
    let strongest = v.idm.first().map(|m| MatchInfo {
        title: m.title.clone(),
        containment: m.containment,
    });

    let decision = detect::decide(v, &detect::Bands::new(block_at, coverage_block_at));
    // Fail-secure: the model owed an answer on an EGRESS path and could not give
    // one. Weighed with the fingerprint half, never against it.
    // An INERT policy (off, or no label selected) contributes nothing at all —
    // checked explicitly because `failBlock` defaults to true, so a policy that
    // was never armed must not be able to block on a stale result.
    let live = !ml.is_inert();
    let unavailable = live && v.ml.as_ref().is_some_and(|m| m.is_unavailable());
    if decision.fingerprint || (unavailable && ml.fail_block) {
        return (WebVerdict::Block, strongest);
    }
    if live && decision.ml {
        // OR, never AND: an unregistered document the model puts in a marked
        // class is caught here even though no fingerprint could ever match it.
        return (
            if ml.blocks() { WebVerdict::Block } else { WebVerdict::Warn },
            strongest,
        );
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
///
/// The ML half is attached to the scored verdict HERE, before the disposition is
/// mapped, because the host is the only place that still holds the upload's
/// content (the injected scanners consume it). The classifier is reached through
/// the process-wide handle the same way the policy is (see `src/mlpolicy.rs` for
/// why that indirection exists): with the policy inert — the shipped default, and
/// every unit test below — the helpers return `None` and this function behaves
/// exactly as it did before the model existed.
pub fn handle_request<FT, FF, FB>(
    req: &Request,
    block_at: f64,
    coverage_block_at: f64,
    ml: &MlPolicy,
    scan_text: FT,
    scan_file: FF,
    scan_bytes: FB,
) -> Handled
where
    FT: FnOnce(&str) -> Verdict,
    FF: FnOnce(&Path) -> anyhow::Result<Verdict>,
    FB: FnOnce(&[u8], &str) -> Verdict,
{
    // Each arm yields the fingerprint verdict AND the ML result for the same
    // bytes, so the two signals are always about the same thing.
    let verdict = match req.kind {
        ScanKind::ScanText => match &req.text {
            Some(t) => Ok((scan_text(t), detect::decide::ml_for_text(t))),
            None => Err("scan_text request without text".to_string()),
        },
        ScanKind::ScanFile => match &req.path {
            Some(p) => scan_file(Path::new(p))
                .map(|v| (v, detect::decide::ml_for_path(Path::new(p))))
                .map_err(|e| format!("file scan failed: {e}")),
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
                        let ml_result = detect::decide::ml_for_bytes(&bytes, &name);
                        Ok((scan_bytes(&bytes, &name), ml_result))
                    }
                    Err(e) => Err(format!("scan_bytes base64 decode failed: {e}")),
                }
            }
            None => Err("scan_bytes request without content_b64".to_string()),
        },
    };

    match verdict {
        Ok((mut v, ml_result)) => {
            v.ml = ml_result;
            let (disp, mi) = map_verdict(&v, block_at, coverage_block_at, ml);
            // The reason names WHICH signal fired, so the extension's banner can
            // say something true. A label id is metadata, never content.
            let ml_label = v
                .ml
                .as_ref()
                .filter(|m| m.is_ok() && m.sensitive)
                .and_then(|m| m.label_id.clone());
            let ml_unavailable = v.ml.as_ref().is_some_and(|m| m.is_unavailable());
            let reason = match disp {
                WebVerdict::Allow => None,
                // No fingerprint match at all ⇒ the ML half is what fired.
                _ if mi.is_none() && ml_label.is_some() => Some(format!(
                    "classified as sensitive ({})",
                    ml_label.unwrap_or_default()
                )),
                _ if mi.is_none() && ml_unavailable => {
                    "classifier unavailable — fail-secure".to_string().into()
                }
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
        // Re-read the ML policy per request, not once per session: a console
        // change that arrives on the next check-in must take effect on the very
        // next upload, not when the browser is restarted. It is a cheap
        // `RwLock` clone of a handful of fields.
        let ml = crate::mlpolicy::active();
        let handled = handle_request(
            &req,
            block_at,
            coverage_block_at,
            &ml,
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
    use crate::detect::{EdmRowHit, EdmSourceHit, Extraction, IdmMatch, MlResult, Verdict};
    use crate::mlpolicy::{MlAction, MlLabelRule};

    /// The shipped default: ML inert. Every pre-existing test below runs under
    /// it, which is how they prove the fusion changed nothing when the feature
    /// is off.
    fn ml_off() -> MlPolicy {
        MlPolicy::default()
    }

    /// A live policy that marks NUC sensitive, with the given action.
    fn ml_on(action: MlAction) -> MlPolicy {
        MlPolicy {
            enabled: true,
            action,
            labels: vec![MlLabelRule { id: "NUC".into(), min_confidence: None }],
            ..MlPolicy::default()
        }
    }

    fn clean() -> Verdict {
        Verdict {
            file_name: String::new(),
            file_sha256: "sha".into(),
            extraction: Extraction::Ok { format: "text".into() },
            idm: vec![],
            edm: vec![],
            ml: None,
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
        assert_eq!(map_verdict(&with_idm(0.5, 0.0), 0.30, 0.60, &ml_off()).0, WebVerdict::Block);
        let mut v = clean();
        v.edm.push(EdmSourceHit {
            source_id: "s".into(),
            name: "PII".into(),
            rows_hit: vec![EdmRowHit { row_id: 1, fields: vec!["x".into()] }],
        });
        assert_eq!(map_verdict(&v, 0.30, 0.60, &ml_off()).0, WebVerdict::Block);
    }

    #[test]
    fn map_verdict_warns_on_lesser_match_and_allows_clean() {
        let (disp, mi) = map_verdict(&with_idm(0.10, 0.10), 0.30, 0.60, &ml_off());
        assert_eq!(disp, WebVerdict::Warn);
        assert_eq!(mi.unwrap().title, "Secret Plan");
        assert_eq!(map_verdict(&clean(), 0.30, 0.60, &ml_off()).0, WebVerdict::Allow);
    }

    /// An `ok` ML result the policy already judged sensitive (or not).
    fn ml_result(sensitive: bool) -> MlResult {
        MlResult::classified("V6.2.01", "NUC", "Nuclear & Strategic Systems", 0.98, sensitive, 1, 40)
    }

    #[test]
    fn map_verdict_ml_only_hit_blocks_under_block_action() {
        // The upload this channel could otherwise never see: nothing registered
        // matches it, but the model puts it in a class the admin marked.
        let mut v = clean();
        v.ml = Some(ml_result(true));
        let (disp, mi) = map_verdict(&v, 0.30, 0.60, &ml_on(MlAction::Block));
        assert_eq!(disp, WebVerdict::Block);
        assert!(mi.is_none(), "no fingerprint match to name");
    }

    #[test]
    fn map_verdict_ml_only_hit_warns_under_audit_action() {
        let mut v = clean();
        v.ml = Some(ml_result(true));
        assert_eq!(
            map_verdict(&v, 0.30, 0.60, &ml_on(MlAction::Audit)).0,
            WebVerdict::Warn,
            "a new signal must not silently start denying uploads"
        );
    }

    #[test]
    fn map_verdict_ml_below_policy_is_allow() {
        // The model answered, the policy said "not sensitive" → nothing fired.
        let mut v = clean();
        v.ml = Some(ml_result(false));
        assert_eq!(map_verdict(&v, 0.30, 0.60, &ml_on(MlAction::Block)).0, WebVerdict::Allow);
    }

    #[test]
    fn map_verdict_ml_unavailable_honours_fail_block_on_this_egress_path() {
        let mut v = clean();
        v.ml = Some(MlResult::unavailable("V6.2.01", "model_not_loaded"));

        let mut p = ml_on(MlAction::Audit);
        p.fail_block = true;
        assert_eq!(map_verdict(&v, 0.30, 0.60, &p).0, WebVerdict::Block, "fail secure");

        p.fail_block = false;
        assert_eq!(map_verdict(&v, 0.30, 0.60, &p).0, WebVerdict::Allow, "fail open by choice");
    }

    #[test]
    fn map_verdict_ml_never_downgrades_a_fingerprint_block() {
        // Model confidently says PUBLIC, policy is audit-only — the registered
        // document still blocks.
        let mut v = with_idm(0.9, 0.9);
        v.ml = Some(MlResult::classified("V6.2.01", "PUB", "Public Information", 1.0, false, 1, 8));
        assert_eq!(map_verdict(&v, 0.30, 0.60, &ml_on(MlAction::Audit)).0, WebVerdict::Block);
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
            &ml_off(),
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
        let handled = handle_request(&req, 0.30, 0.60, &ml_off(), |_| clean(), |_| Ok(clean()), |_, _| clean());
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
            &ml_off(),
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
        let handled = handle_request(&req, 0.30, 0.60, &ml_off(), |_| clean(), |_| Ok(clean()), |_, _| clean());
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
