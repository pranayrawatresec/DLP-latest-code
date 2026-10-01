// ============================================================================
// DEVELOPMENT & TESTING ONLY — do not deploy to production endpoints.
//
// This binary exposes the ML engine over plain HTTP with no authentication.
// It is for evaluating model correctness and measuring inference metrics on
// a developer or QA machine. It does not write to the agent's state, raise
// incidents, or interact with the management server.
//
// Usage:
//   cargo run --bin ml_eval_server
//   # explicit model root (default: ../Document_classification relative to cwd):
//   set ML_EVAL_MODEL_ROOT=C:\path\to\Document_classification
//   cargo run --bin ml_eval_server
//
// Then open http://localhost:7400 in a browser.
// ============================================================================

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use dlp_agent::ml::{engine, labels, MlConfig, MlEngine, LABELS, LABEL_COUNT};
use serde::{Deserialize, Serialize};

// The single-page frontend, embedded at compile time so the binary is
// fully self-contained. No web server, no asset directory to deploy.
static UI_HTML: &str = include_str!("ml_eval_ui.html");

const PORT: u16 = 7400;
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024; // 16 MB — enough for a large batch manifest

// ============================================================================
// Shared state (read-only after startup)
// ============================================================================

struct AppState {
    engine: Option<Arc<MlEngine>>,
    model_sha256: Option<String>,
    model_root: PathBuf,
    load_error: Option<String>,
}

// ============================================================================
// JSON types
// ============================================================================

#[derive(Serialize)]
struct LabelInfo {
    index: usize,
    id: &'static str,
    name: &'static str,
    domain: &'static str,
}

#[derive(Serialize)]
struct GeometryInfo {
    max_tokens: usize,
    overlap_tokens: usize,
    min_tokens: usize,
}

#[derive(Serialize)]
struct StatusResponse {
    available: bool,
    model_version: Option<String>,
    graph_kind: Option<String>,
    geometry: Option<GeometryInfo>,
    max_chars: Option<usize>,
    label_count: usize,
    model_sha256: Option<String>,
    model_root: String,
    load_error: Option<String>,
    labels: Vec<LabelInfo>,
}

#[derive(Deserialize)]
struct ClassifyRequest {
    text: String,
}

#[derive(Serialize)]
struct ClassifyResponse {
    ok: bool,
    label_id: Option<String>,
    label_name: Option<String>,
    label_index: Option<usize>,
    domain: Option<String>,
    confidence: Option<f64>,
    chunks: Option<usize>,
    chunks_total: Option<usize>,
    tokens: Option<usize>,
    latency_ms: f64,
    logits: Option<Vec<f64>>,
    error: Option<String>,
    error_status: Option<String>,
    error_reason: Option<String>,
}

#[derive(Deserialize)]
struct BatchCase {
    #[serde(default)]
    name: String,
    expected: String,
    text: String,
}

#[derive(Deserialize)]
struct BatchRequest {
    cases: Vec<BatchCase>,
}

#[derive(Serialize)]
struct LatencyStats {
    p50: f64,
    p95: f64,
    p99: f64,
    min: f64,
    max: f64,
    mean: f64,
}

#[derive(Serialize)]
struct LabelMetrics {
    id: String,
    name: String,
    domain: String,
    support: usize,
    tp: usize,
    fp: usize,
    fn_count: usize,
    precision: f64,
    recall: f64,
    f1: f64,
}

#[derive(Serialize)]
struct ErrorPair {
    expected: String,
    predicted: String,
    count: usize,
}

#[derive(Serialize)]
struct CaseResult {
    name: String,
    expected: String,
    predicted: Option<String>,
    confidence: Option<f64>,
    latency_ms: f64,
    correct: bool,
    error: Option<String>,
}

#[derive(Serialize)]
struct BatchResponse {
    ok: bool,
    total_cases: usize,
    passed: usize,
    accuracy: f64,
    macro_f1: f64,
    total_latency_ms: f64,
    throughput_docs_per_sec: f64,
    latency: LatencyStats,
    label_metrics: Vec<LabelMetrics>,
    top_errors: Vec<ErrorPair>,
    cases: Vec<CaseResult>,
    error: Option<String>,
}

// ============================================================================
// HTTP plumbing (minimal, stdlib only)
// ============================================================================

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_http_request(stream: &TcpStream) -> std::io::Result<Option<HttpRequest>> {
    let mut reader = BufReader::new(stream);

    let mut first_line = String::new();
    if reader.read_line(&mut first_line)? == 0 {
        return Ok(None);
    }
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(None);
    }
    let method = parts[0].to_string();
    let path = parts[1].split('?').next().unwrap_or("/").to_string();

    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if trimmed.to_ascii_lowercase().starts_with("content-length:") {
            let val = trimmed["content-length:".len()..].trim();
            content_length = val.parse().unwrap_or(0);
        }
    }

    let read_len = content_length.min(MAX_BODY_BYTES);
    let mut body = vec![0u8; read_len];
    if read_len > 0 {
        reader.read_exact(&mut body)?;
    }

    Ok(Some(HttpRequest { method, path, body }))
}

fn build_response(status: u16, status_text: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let headers = format!(
        "HTTP/1.1 {status} {status_text}\r\n\
         Content-Type: {content_type}; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    let mut out = headers.into_bytes();
    out.extend_from_slice(body);
    out
}

fn json_response(status: u16, status_text: &str, body: &[u8]) -> Vec<u8> {
    build_response(status, status_text, "application/json", body)
}

fn ok_json<T: Serialize>(value: &T) -> Vec<u8> {
    let json = serde_json::to_vec(value).unwrap_or_else(|e| {
        format!("{{\"error\":\"serialization failed: {e}\"}}").into_bytes()
    });
    json_response(200, "OK", &json)
}

fn err_json(msg: &str) -> Vec<u8> {
    let body = serde_json::json!({"error": msg});
    json_response(400, "Bad Request", body.to_string().as_bytes())
}

fn not_found() -> Vec<u8> {
    json_response(404, "Not Found", b"{\"error\":\"not found\"}")
}

fn options_response() -> Vec<u8> {
    let headers = "HTTP/1.1 204 No Content\r\n\
                   Access-Control-Allow-Origin: *\r\n\
                   Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
                   Access-Control-Allow-Headers: Content-Type\r\n\
                   Connection: close\r\n\
                   \r\n";
    headers.as_bytes().to_vec()
}

// ============================================================================
// API handlers
// ============================================================================

fn handle_status(state: &AppState) -> Vec<u8> {
    let label_list: Vec<LabelInfo> = LABELS
        .iter()
        .enumerate()
        .map(|(i, l)| LabelInfo { index: i, id: l.id, name: l.name, domain: l.domain })
        .collect();

    let resp = match &state.engine {
        Some(eng) => {
            let geo = eng.geometry();
            StatusResponse {
                available: true,
                model_version: Some(eng.model_version().to_string()),
                graph_kind: Some(eng.graph_kind().to_string()),
                geometry: Some(GeometryInfo {
                    max_tokens: geo.max_tokens,
                    overlap_tokens: geo.overlap_tokens,
                    min_tokens: geo.min_tokens,
                }),
                max_chars: None, // not exposed on MlEngine directly; sidecar owns it
                label_count: LABEL_COUNT,
                model_sha256: state.model_sha256.clone(),
                model_root: state.model_root.display().to_string(),
                load_error: None,
                labels: label_list,
            }
        }
        None => StatusResponse {
            available: false,
            model_version: None,
            graph_kind: None,
            geometry: None,
            max_chars: None,
            label_count: LABEL_COUNT,
            model_sha256: None,
            model_root: state.model_root.display().to_string(),
            load_error: state.load_error.clone(),
            labels: label_list,
        },
    };

    ok_json(&resp)
}

fn handle_classify(body: &[u8], state: &AppState) -> Vec<u8> {
    let req: ClassifyRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return err_json(&format!("invalid JSON: {e}")),
    };

    let engine = match &state.engine {
        Some(e) => e,
        None => {
            let resp = ClassifyResponse {
                ok: false,
                label_id: None,
                label_name: None,
                label_index: None,
                domain: None,
                confidence: None,
                chunks: None,
                chunks_total: None,
                tokens: None,
                latency_ms: 0.0,
                logits: None,
                error: Some(
                    state.load_error.clone().unwrap_or_else(|| "model not loaded".into()),
                ),
                error_status: Some("unavailable".into()),
                error_reason: Some("model_not_loaded".into()),
            };
            return ok_json(&resp);
        }
    };

    let start = Instant::now();
    let result = engine.classify(&req.text);
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    let resp = match result {
        Ok(pred) => {
            let domain = labels::by_index(pred.label_index)
                .map(|l| l.domain.to_string())
                .unwrap_or_default();
            ClassifyResponse {
                ok: true,
                label_id: Some(pred.label_id.to_string()),
                label_name: Some(pred.label_name.to_string()),
                label_index: Some(pred.label_index),
                domain: Some(domain),
                confidence: Some(pred.confidence),
                chunks: Some(pred.chunks),
                chunks_total: Some(pred.chunks_total),
                tokens: Some(pred.tokens),
                latency_ms,
                logits: Some(pred.logits),
                error: None,
                error_status: None,
                error_reason: None,
            }
        }
        Err(e) => ClassifyResponse {
            ok: false,
            label_id: None,
            label_name: None,
            label_index: None,
            domain: None,
            confidence: None,
            chunks: None,
            chunks_total: None,
            tokens: None,
            latency_ms,
            logits: None,
            error: Some(e.to_string()),
            error_status: Some(e.status().to_string()),
            error_reason: Some(e.reason().to_string()),
        },
    };

    ok_json(&resp)
}

fn handle_batch(body: &[u8], state: &AppState) -> Vec<u8> {
    let req: BatchRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return err_json(&format!("invalid JSON: {e}")),
    };

    if req.cases.is_empty() {
        return err_json("cases array is empty");
    }

    let engine = match &state.engine {
        Some(e) => e,
        None => {
            let resp = BatchResponse {
                ok: false,
                total_cases: req.cases.len(),
                passed: 0,
                accuracy: 0.0,
                macro_f1: 0.0,
                total_latency_ms: 0.0,
                throughput_docs_per_sec: 0.0,
                latency: LatencyStats { p50: 0.0, p95: 0.0, p99: 0.0, min: 0.0, max: 0.0, mean: 0.0 },
                label_metrics: vec![],
                top_errors: vec![],
                cases: vec![],
                error: Some(
                    state.load_error.clone().unwrap_or_else(|| "model not loaded".into()),
                ),
            };
            return ok_json(&resp);
        }
    };

    // Per-label accumulators: tp, fp, fn_count, support
    #[derive(Default)]
    struct LabelAcc { tp: usize, fp: usize, fn_count: usize, support: usize }
    let mut per_label: HashMap<String, LabelAcc> = HashMap::new();
    // Confusion: (expected, predicted) → count, for off-diagonal error reporting
    let mut confusion: HashMap<(String, String), usize> = HashMap::new();
    let mut latencies: Vec<f64> = Vec::with_capacity(req.cases.len());
    let mut case_results: Vec<CaseResult> = Vec::with_capacity(req.cases.len());
    let mut passed = 0usize;

    let wall_start = Instant::now();
    for (i, case) in req.cases.iter().enumerate() {
        let name = if case.name.is_empty() {
            format!("case-{i}")
        } else {
            case.name.clone()
        };

        let case_start = Instant::now();
        let result = engine.classify(&case.text);
        let latency_ms = case_start.elapsed().as_secs_f64() * 1000.0;
        latencies.push(latency_ms);

        match result {
            Ok(pred) => {
                let predicted = pred.label_id.to_string();
                let correct = predicted == case.expected;
                if correct {
                    passed += 1;
                }

                // Drop acc before the second entry() borrow.
                {
                    let acc = per_label.entry(case.expected.clone()).or_default();
                    acc.support += 1;
                    if correct { acc.tp += 1; } else { acc.fn_count += 1; }
                }
                if !correct {
                    per_label.entry(predicted.clone()).or_default().fp += 1;
                }
                *confusion.entry((case.expected.clone(), predicted.clone())).or_insert(0) += 1;

                case_results.push(CaseResult {
                    name,
                    expected: case.expected.clone(),
                    predicted: Some(predicted),
                    confidence: Some(pred.confidence),
                    latency_ms,
                    correct,
                    error: None,
                });
            }
            Err(e) => {
                let acc = per_label.entry(case.expected.clone()).or_default();
                acc.support += 1;
                acc.fn_count += 1;
                case_results.push(CaseResult {
                    name,
                    expected: case.expected.clone(),
                    predicted: None,
                    confidence: None,
                    latency_ms,
                    correct: false,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    let total_latency_ms = wall_start.elapsed().as_secs_f64() * 1000.0;
    let n = req.cases.len();
    let accuracy = if n > 0 { passed as f64 / n as f64 } else { 0.0 };
    let throughput_docs_per_sec =
        if total_latency_ms > 0.0 { n as f64 / (total_latency_ms / 1000.0) } else { 0.0 };

    // Latency percentiles
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let latency_stats = LatencyStats {
        p50: percentile(&latencies, 0.50),
        p95: percentile(&latencies, 0.95),
        p99: percentile(&latencies, 0.99),
        min: latencies.first().copied().unwrap_or(0.0),
        max: latencies.last().copied().unwrap_or(0.0),
        mean: if latencies.is_empty() {
            0.0
        } else {
            latencies.iter().sum::<f64>() / latencies.len() as f64
        },
    };

    // Per-label precision / recall / F1
    let mut label_metrics: Vec<LabelMetrics> = per_label
        .iter()
        .map(|(id, acc)| {
            let precision = if acc.tp + acc.fp > 0 {
                acc.tp as f64 / (acc.tp + acc.fp) as f64
            } else {
                0.0
            };
            let recall = if acc.tp + acc.fn_count > 0 {
                acc.tp as f64 / (acc.tp + acc.fn_count) as f64
            } else {
                0.0
            };
            let f1 = if precision + recall > 0.0 {
                2.0 * precision * recall / (precision + recall)
            } else {
                0.0
            };
            let label_info = labels::by_id(id).map(|(_, l)| l);
            LabelMetrics {
                id: id.clone(),
                name: label_info.map(|l| l.name.to_string()).unwrap_or_else(|| id.clone()),
                domain: label_info.map(|l| l.domain.to_string()).unwrap_or_else(|| "unknown".into()),
                support: acc.support,
                tp: acc.tp,
                fp: acc.fp,
                fn_count: acc.fn_count,
                precision,
                recall,
                f1,
            }
        })
        .collect();
    label_metrics.sort_by(|a, b| b.support.cmp(&a.support));

    let macro_f1 = if label_metrics.is_empty() {
        0.0
    } else {
        label_metrics.iter().map(|m| m.f1).sum::<f64>() / label_metrics.len() as f64
    };

    // Top misclassification pairs
    let mut error_pairs: Vec<ErrorPair> = confusion
        .iter()
        .filter(|((exp, pred), _)| exp != pred)
        .map(|((exp, pred), count)| ErrorPair {
            expected: exp.clone(),
            predicted: pred.clone(),
            count: *count,
        })
        .collect();
    error_pairs.sort_by(|a, b| b.count.cmp(&a.count));
    error_pairs.truncate(10);

    ok_json(&BatchResponse {
        ok: true,
        total_cases: n,
        passed,
        accuracy,
        macro_f1,
        total_latency_ms,
        throughput_docs_per_sec,
        latency: latency_stats,
        label_metrics,
        top_errors: error_pairs,
        cases: case_results,
        error: None,
    })
}

// ============================================================================
// Per-connection handler
// ============================================================================

fn handle_connection(stream: TcpStream, state: Arc<AppState>) {
    let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into());

    let req = match read_http_request(&stream) {
        Ok(Some(r)) => r,
        Ok(None) => return,
        Err(e) => {
            eprintln!("[{peer}] read error: {e}");
            return;
        }
    };

    let response = match (req.method.as_str(), req.path.as_str()) {
        ("OPTIONS", _) => options_response(),
        ("GET", "/") | ("GET", "/index.html") => {
            build_response(200, "OK", "text/html", UI_HTML.as_bytes())
        }
        ("GET", "/api/status") => handle_status(&state),
        ("POST", "/api/classify") => handle_classify(&req.body, &state),
        ("POST", "/api/batch") => handle_batch(&req.body, &state),
        _ => not_found(),
    };

    let mut stream = stream;
    if let Err(e) = stream.write_all(&response) {
        eprintln!("[{peer}] write error: {e}");
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let idx = (sorted.len() - 1) as f64 * p;
    let lo = idx.floor() as usize;
    let hi = idx.ceil() as usize;
    let frac = idx - lo as f64;
    sorted[lo] * (1.0 - frac) + sorted[hi] * frac
}

fn resolve_model_root() -> PathBuf {
    if let Ok(v) = std::env::var("ML_EVAL_MODEL_ROOT") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    // Default: Document_classification/ beside the crate (matches the test path).
    // Works both with `cargo run` (cwd = crate dir) and from the repo root.
    let candidates = [
        Path::new("Document_classification").to_path_buf(),
        Path::new("../Document_classification").to_path_buf(),
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("Document_classification")))
            .unwrap_or_else(|| PathBuf::from("Document_classification")),
    ];
    for c in &candidates {
        if c.is_dir() {
            return c.canonicalize().unwrap_or_else(|_| c.clone());
        }
    }
    candidates[0].clone()
}

// ============================================================================
// main
// ============================================================================

fn main() {
    eprintln!("╔══════════════════════════════════════════════════════╗");
    eprintln!("║  DLP ML Evaluation Portal — DEVELOPMENT USE ONLY     ║");
    eprintln!("║  No authentication. Do not expose outside localhost.  ║");
    eprintln!("╚══════════════════════════════════════════════════════╝");
    eprintln!();

    let model_root = resolve_model_root();
    eprintln!("Model root : {}", model_root.display());

    let config = MlConfig::under(&model_root);

    let (eng, model_sha256, load_error) = if config.artifacts_present() {
        eprintln!("Artifacts  : present — loading engine...");
        match engine::load(&config) {
            Ok(e) => {
                eprintln!("Engine     : {} ({})", e.model_version(), e.graph_kind());
                let sha = engine::model_sha256(&config.model).ok();
                if let Some(ref h) = sha {
                    eprintln!("SHA-256    : {}…{}", &h[..8], &h[h.len() - 8..]);
                }
                (Some(e), sha, None)
            }
            Err(e) => {
                eprintln!("WARNING    : engine load failed: {e}");
                (None, None, Some(e.to_string()))
            }
        }
    } else {
        let msg = format!(
            "artifacts not found under {} — classify/batch will return unavailable",
            model_root.display()
        );
        eprintln!("WARNING    : {msg}");
        eprintln!("           : stage model.onnx + model.onnx.json + tokenizer.json");
        eprintln!("           : set ORT_DYLIB_PATH or place onnxruntime.dll in runtime/");
        (None, None, Some(msg))
    };

    let state = Arc::new(AppState { engine: eng, model_sha256, model_root, load_error });

    let addr = format!("127.0.0.1:{PORT}");
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ERROR: cannot bind to {addr}: {e}");
            std::process::exit(1);
        }
    };

    eprintln!();
    eprintln!("Listening  : http://localhost:{PORT}");
    eprintln!("Open the URL above in your browser.");
    eprintln!();

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let state = Arc::clone(&state);
                std::thread::spawn(move || handle_connection(s, state));
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
}
