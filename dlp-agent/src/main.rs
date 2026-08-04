//! DLP Windows agent — Phase 2 (secure channel only: enrollment + mTLS
//! check-in). No DLP enforcement yet; this is the trusted body that later
//! detection features attach to.
//!
//! Modes:
//!   dlp-agent enroll        enroll once (if not already), then exit
//!   dlp-agent once          ensure enrolled, do a single check-in, exit
//!   dlp-agent run           ensure enrolled, then check in on a loop (fail-secure)
//!   dlp-agent status        print stored identity summary
//!   dlp-agent index-update  check in, fetch a newer index bundle if advertised
//!   dlp-agent scan          score one file against a bundle (audit-mode verdict)
mod checkin;
mod client;
mod enroll;
mod identity;
mod kguard;

// Config, Storage, detection and the USB channel live in the library crate so
// integration tests and the binary share one set of types. Re-import the
// modules at the crate root so the binary submodules keep addressing them as
// `crate::config` / `crate::storage`.
use dlp_agent::{browser_host, clipboard, config, detect, netfilter, storage, usb};

use anyhow::{Context, Result};
use config::Config;
use std::path::PathBuf;
use std::time::Duration;
use storage::Storage;
use usb::UsbIncident;
use x509_cert::der::DecodePem;

const DEFAULT_CONFIG: &str = r"C:\ProgramData\DLPAgent\agent.toml";
/// Backoff when the server is unreachable — the agent keeps enforcing cached
/// policy and retries, never falling open.
const RETRY_SECONDS: u64 = 30;

fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(tracing::Level::INFO)
        .init();

    if let Err(err) = run() {
        tracing::error!("{err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "run".into());
    let args: Vec<String> = std::env::args().skip(2).collect();

    // Help never needs a config file.
    if matches!(mode.as_str(), "help" | "-h" | "--help") {
        print_help();
        return Ok(());
    }
    if mode == "scan" && args.iter().any(|a| a == "-h" || a == "--help") {
        print_scan_help();
        return Ok(());
    }
    if mode == "usb-monitor" && args.iter().any(|a| a == "-h" || a == "--help") {
        print_usb_help();
        return Ok(());
    }
    if mode == "usb-guard" && args.iter().any(|a| a == "-h" || a == "--help") {
        print_usbguard_help();
        return Ok(());
    }
    if mode == "clipboard-monitor" && args.iter().any(|a| a == "-h" || a == "--help") {
        print_clipboard_help();
        return Ok(());
    }
    if mode == "net-monitor" && args.iter().any(|a| a == "-h" || a == "--help") {
        print_net_help();
        return Ok(());
    }
    if mode == "browser-host" && args.iter().any(|a| a == "-h" || a == "--help") {
        print_browserhost_help();
        return Ok(());
    }

    let config_path =
        std::env::var("DLP_AGENT_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG.to_string());
    let cfg = Config::load(&PathBuf::from(config_path)).context("loading config")?;
    let storage = Storage::new(cfg.state_dir.clone());

    match mode.as_str() {
        "enroll" => {
            if storage.has_identity() {
                tracing::info!("already enrolled — nothing to do");
            } else {
                enroll::enroll(&cfg, &storage)?;
            }
        }
        "once" => {
            ensure_enrolled(&cfg, &storage)?;
            checkin::checkin(&cfg, &storage)?;
        }
        "run" => {
            ensure_enrolled(&cfg, &storage)?;
            run_loop(&cfg, &storage);
        }
        "status" => print_status(&storage)?,
        "index-update" => cmd_index_update(&cfg, &storage)?,
        "scan" => cmd_scan(&cfg, &storage, &args)?,
        "usb-monitor" => cmd_usb_monitor(&cfg, &storage, &args)?,
        "usb-guard" => cmd_usb_guard(&cfg, &storage, &args)?,
        "clipboard-monitor" => cmd_clipboard_monitor(&cfg, &storage, &args)?,
        "net-monitor" => cmd_net_monitor(&cfg, &storage, &args)?,
        "browser-host" => cmd_browser_host(&cfg, &storage, &args)?,
        other => {
            eprintln!("unknown mode: {other}");
            print_help();
            std::process::exit(2);
        }
    }
    Ok(())
}

fn ensure_enrolled(cfg: &Config, storage: &Storage) -> Result<()> {
    if !storage.has_identity() {
        tracing::info!("not enrolled yet — enrolling first");
        enroll::enroll(cfg, storage)?;
    }
    Ok(())
}

/// The heartbeat loop. Fail-secure: an unreachable server never stops the
/// agent — it retries and keeps enforcing cached policy.
fn run_loop(cfg: &Config, storage: &Storage) {
    tracing::info!("check-in loop started");
    loop {
        let sleep_for = match checkin::checkin(cfg, storage) {
            Ok(interval) => interval.max(5),
            Err(err) => {
                tracing::warn!("check-in failed ({err:#}); enforcing cached policy, will retry");
                RETRY_SECONDS
            }
        };
        std::thread::sleep(Duration::from_secs(sleep_for));
    }
}

/// The CA the agent trusts for bundle signatures: the anchor pinned at
/// enrollment when enrolled, else the installer-provisioned CA file.
fn load_ca(cfg: &Config, storage: &Storage) -> Result<Vec<u8>> {
    if storage.has_identity() {
        Ok(storage.load_identity()?.1)
    } else {
        std::fs::read(&cfg.ca_cert_path)
            .with_context(|| format!("reading pinned CA {}", cfg.ca_cert_path.display()))
    }
}

/// index-update: one check-in, then fetch + verify + swap the index bundle
/// if the server advertises a newer version. A bundle that fails signature
/// or parse verification NEVER replaces the cached one (fail secure).
fn cmd_index_update(cfg: &Config, storage: &Storage) -> Result<()> {
    ensure_enrolled(cfg, storage)?;
    let outcome = checkin::checkin_full(cfg, storage)?;
    let (identity_pem, ca_pem) = storage.load_identity()?;

    // Current version = whatever the cached bundle verifiably says; a
    // missing or corrupt cache means 0 (forces a refetch).
    let current = storage
        .load_index_bundle()
        .and_then(|bytes| detect::Bundle::load(&bytes, &ca_pem).ok())
        .map(|b| b.version())
        .unwrap_or(0);

    if outcome.index_latest == 0 {
        tracing::info!("server has no index bundle yet");
        return Ok(());
    }
    if outcome.index_latest <= current {
        tracing::info!(version = current, "index bundle already up to date");
        return Ok(());
    }

    tracing::info!(have = current, latest = outcome.index_latest, "fetching index bundle");
    let client = client::checkin_client(&ca_pem, &identity_pem)?;
    let resp = client
        .get(cfg.index_url())
        .send()
        .context("index download request failed")?;
    if !resp.status().is_success() {
        let status = resp.status();
        anyhow::bail!("index download refused [{status}]");
    }
    let bytes = resp.bytes().context("reading index bundle body")?.to_vec();

    // Verify BEFORE replacing — the previous verified bundle stays in place
    // until the new one has passed signature + structural checks.
    let bundle = detect::Bundle::load(&bytes, &ca_pem).context("verifying downloaded bundle")?;
    storage.store_index_bundle(&bytes)?;
    tracing::info!(version = bundle.version(), size = bytes.len(), "index bundle updated");
    Ok(())
}

/// scan: audit-mode verdict for one file. Exit code 0 whenever the scan
/// executes — an unreadable file is a valid verdict, not an error.
fn cmd_scan(cfg: &Config, storage: &Storage, args: &[String]) -> Result<()> {
    let mut bundle_path: Option<String> = None;
    let mut file_path: Option<String> = None;
    let mut json = false;
    let mut report = false;
    let mut channel: Option<String> = None;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--bundle" => bundle_path = it.next().cloned(),
            "--file" => file_path = it.next().cloned(),
            "--json" => json = true,
            "--report" => report = true,
            "--channel" => channel = it.next().cloned(),
            other => {
                eprintln!("unknown scan option: {other}");
                print_scan_help();
                std::process::exit(2);
            }
        }
    }
    let bundle_path = bundle_path.context("scan requires --bundle <path>")?;
    let file_path = file_path.context("scan requires --file <path>")?;

    let ca_pem = load_ca(cfg, storage)?;
    let bundle_bytes = std::fs::read(&bundle_path)
        .with_context(|| format!("reading bundle {bundle_path}"))?;
    let bundle = detect::Bundle::load(&bundle_bytes, &ca_pem).context("loading index bundle")?;

    let verdict = detect::verdict(std::path::Path::new(&file_path), &bundle)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&verdict)?);
    } else {
        print_verdict(&verdict, &bundle);
    }

    if report {
        let channel = channel.context("--report requires --channel <name>")?;
        report_incident(cfg, storage, &channel, &verdict)?;
    }
    Ok(())
}

fn print_verdict(v: &detect::Verdict, bundle: &detect::Bundle) {
    println!("file:       {}", v.file_name);
    println!("sha256:     {}", v.file_sha256);
    println!("bundle:     v{}", bundle.version());
    match &v.extraction {
        detect::Extraction::Ok { format } => println!("extraction: ok ({format})"),
        detect::Extraction::Unreadable { reason } => println!("extraction: unreadable ({reason})"),
    }
    if v.idm.is_empty() {
        println!("idm:        no matches");
    } else {
        println!("idm:        {} document(s) matched", v.idm.len());
        for m in &v.idm {
            println!(
                "  - {:?} containment {:.1}% coverage {:.1}% ({}/{} fingerprints, version {})",
                m.title,
                m.containment * 100.0,
                m.coverage * 100.0,
                m.matched_count,
                m.total_count,
                m.version_id,
            );
        }
    }
    if v.edm.is_empty() {
        println!("edm:        no row hits");
    } else {
        println!("edm:        {} source(s) hit", v.edm.len());
        for s in &v.edm {
            for row in &s.rows_hit {
                println!("  - {:?} row {} ({})", s.name, row.row_id, row.fields.join(", "));
            }
        }
    }
}

#[derive(serde::Serialize)]
struct IncidentRequest<'a> {
    channel: &'a str,
    #[serde(rename = "fileName")]
    file_name: &'a str,
    #[serde(rename = "fileSha256")]
    file_sha256: &'a str,
    verdict: &'a detect::Verdict,
}

/// Report a scan verdict to the server over mTLS (POST /agent/incidents).
fn report_incident(
    cfg: &Config,
    storage: &Storage,
    channel: &str,
    verdict: &detect::Verdict,
) -> Result<()> {
    let body = serde_json::to_string(&IncidentRequest {
        channel,
        file_name: &verdict.file_name,
        file_sha256: &verdict.file_sha256,
        verdict,
    })
    .context("serializing incident")?;
    let id = post_incident_body(cfg, storage, &body)?;
    tracing::info!(incident_id = %id, channel, "incident reported");
    Ok(())
}

/// POST a pre-serialized incident body over mTLS and return the server-assigned
/// id. Reused by the scan command, the USB monitor sink, and the offline-queue
/// flush (they all speak the same wire shape, spec §4).
fn post_incident_body(cfg: &Config, storage: &Storage, body: &str) -> Result<String> {
    let (identity_pem, ca_pem) = storage.load_identity()?;
    let client = client::checkin_client(&ca_pem, &identity_pem)?;
    let resp = client
        .post(cfg.incidents_url())
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .context("incident report failed")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        anyhow::bail!("incident report rejected [{status}]: {text}");
    }
    #[derive(serde::Deserialize)]
    struct IncidentResponse {
        id: String,
    }
    let ir: IncidentResponse = resp.json().context("parsing incident response")?;
    Ok(ir.id)
}

/// Build the wire body (spec §4) for a USB incident that carries a verdict.
fn usb_incident_body(inc: &UsbIncident) -> Option<String> {
    let verdict = inc.verdict.as_ref()?;
    serde_json::to_string(&IncidentRequest {
        channel: &inc.channel,
        file_name: &inc.file_name,
        file_sha256: &inc.file_sha256,
        verdict,
    })
    .ok()
}

/// usb-monitor: run the removable-media device-control + copy-audit loop.
/// Audit-only by default; `--enforce` turns on live device control (gated by
/// the `[usb] enabled` opt-in inside `run_monitor`).
fn cmd_usb_monitor(cfg: &Config, storage: &Storage, args: &[String]) -> Result<()> {
    let mut enforce = false;
    for arg in args {
        match arg.as_str() {
            "--enforce" => enforce = true,
            "-h" | "--help" => {
                print_usb_help();
                return Ok(());
            }
            other => {
                eprintln!("unknown usb-monitor option: {other}");
                print_usb_help();
                std::process::exit(2);
            }
        }
    }

    let queue = usb::queue::IncidentQueue::new(&cfg.state_dir);

    // Flush anything queued while the server was previously unreachable.
    if storage.has_identity() && !queue.is_empty() {
        let flushed = queue.flush(|body| post_incident_body(cfg, storage, body).map(|_| ()));
        if flushed > 0 {
            tracing::info!(flushed, "flushed queued usb incidents");
        }
    }

    // The incident sink: post verdict-bearing incidents over mTLS; on failure
    // (or when unenrolled) queue them on disk, bounded (spec §3.6 edge 11).
    // Metadata-only incidents (too-large, enforcement-failed) are logged.
    let sink = |inc: UsbIncident| match usb_incident_body(&inc) {
        Some(body) => {
            if storage.has_identity() {
                match post_incident_body(cfg, storage, &body) {
                    Ok(id) => tracing::info!(incident_id = %id, kind = ?inc.kind, "usb incident reported"),
                    Err(e) => {
                        tracing::warn!(error = %e, "usb incident post failed — queuing locally");
                        let _ = queue.enqueue(&body);
                    }
                }
            } else {
                tracing::warn!(kind = ?inc.kind, "unenrolled — queuing usb incident locally");
                let _ = queue.enqueue(&body);
            }
        }
        None => tracing::info!(
            kind = ?inc.kind,
            drive = %inc.device.drive_letter,
            note = inc.note.as_deref().unwrap_or(""),
            "usb metadata incident (no verdict; not posted)"
        ),
    };

    usb::run_monitor(cfg, storage, enforce, sink);
    Ok(())
}

/// usb-guard: connect to the kernel minifilter's port (\DlpFltPort) and answer
/// its scan requests. Reuses the SAME incident sink as usb-monitor (mTLS post
/// when enrolled, bounded on-disk queue otherwise), so the whole wire/queue
/// path is shared. Requires the driver to be loaded (operator manual step);
/// this process must be the one that connects (skip-self PID, SPEC §2.4).
fn cmd_usb_guard(cfg: &Config, storage: &Storage, args: &[String]) -> Result<()> {
    for arg in args {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usbguard_help();
                return Ok(());
            }
            other => {
                eprintln!("unknown usb-guard option: {other}");
                print_usbguard_help();
                std::process::exit(2);
            }
        }
    }

    let queue = usb::queue::IncidentQueue::new(&cfg.state_dir);

    // Flush anything queued while previously offline (identical to usb-monitor).
    if storage.has_identity() && !queue.is_empty() {
        let flushed = queue.flush(|body| post_incident_body(cfg, storage, body).map(|_| ()));
        if flushed > 0 {
            tracing::info!(flushed, "flushed queued incidents");
        }
    }

    // Same sink shape as cmd_usb_monitor: post verdict-bearing incidents over
    // mTLS; on failure or when unenrolled, queue them on disk (bounded).
    let sink = |inc: UsbIncident| match usb_incident_body(&inc) {
        Some(body) => {
            if storage.has_identity() {
                match post_incident_body(cfg, storage, &body) {
                    Ok(id) => tracing::info!(incident_id = %id, kind = ?inc.kind, "kguard incident reported"),
                    Err(e) => {
                        tracing::warn!(error = %e, "kguard incident post failed — queuing locally");
                        let _ = queue.enqueue(&body);
                    }
                }
            } else {
                tracing::warn!(kind = ?inc.kind, "unenrolled — queuing kguard incident locally");
                let _ = queue.enqueue(&body);
            }
        }
        None => tracing::info!(
            kind = ?inc.kind,
            drive = %inc.device.drive_letter,
            "kguard metadata incident (no verdict; not posted)"
        ),
    };

    kguard::run(cfg, storage, sink)
}

/// clipboard-monitor: watch the clipboard, inspect copied content against the
/// cached bundle, and (under `--enforce`) clear a sensitive copy. Audit-only by
/// default; reuses the exact incident sink + offline queue as usb-monitor, so
/// clipboard incidents share the whole wire/queue path (channel = "clipboard").
fn cmd_clipboard_monitor(cfg: &Config, storage: &Storage, args: &[String]) -> Result<()> {
    let mut enforce = false;
    for arg in args {
        match arg.as_str() {
            "--enforce" => enforce = true,
            "-h" | "--help" => {
                print_clipboard_help();
                return Ok(());
            }
            other => {
                eprintln!("unknown clipboard-monitor option: {other}");
                print_clipboard_help();
                std::process::exit(2);
            }
        }
    }

    let queue = usb::queue::IncidentQueue::new(&cfg.state_dir);

    // Flush anything queued while previously offline (identical to usb-monitor).
    if storage.has_identity() && !queue.is_empty() {
        let flushed = queue.flush(|body| post_incident_body(cfg, storage, body).map(|_| ()));
        if flushed > 0 {
            tracing::info!(flushed, "flushed queued clipboard incidents");
        }
    }

    // Same sink shape as cmd_usb_monitor: post verdict-bearing incidents over
    // mTLS; on failure or when unenrolled, queue them on disk (bounded).
    let sink = |inc: UsbIncident| match usb_incident_body(&inc) {
        Some(body) => {
            if storage.has_identity() {
                match post_incident_body(cfg, storage, &body) {
                    Ok(id) => tracing::info!(incident_id = %id, kind = ?inc.kind, "clipboard incident reported"),
                    Err(e) => {
                        tracing::warn!(error = %e, "clipboard incident post failed — queuing locally");
                        let _ = queue.enqueue(&body);
                    }
                }
            } else {
                tracing::warn!(kind = ?inc.kind, "unenrolled — queuing clipboard incident locally");
                let _ = queue.enqueue(&body);
            }
        }
        None => tracing::info!(
            kind = ?inc.kind,
            note = inc.note.as_deref().unwrap_or(""),
            "clipboard metadata incident (no verdict; not posted)"
        ),
    };

    clipboard::run_monitor(cfg, storage, enforce, sink);
    Ok(())
}

/// Load + verify the cached index bundle with the trusted CA (mirrors the
/// usb/kguard/clipboard `load_verified_bundle`). None → no-policy.
fn load_verified_bundle(cfg: &Config, storage: &Storage) -> Option<detect::Bundle> {
    let ca_pem = load_ca(cfg, storage).ok()?;
    storage
        .load_index_bundle()
        .and_then(|bytes| detect::Bundle::load(&bytes, &ca_pem).ok())
}

/// net-monitor: run the user-mode WFP network-egress control loop. Audit-only by
/// default (`monitor`); `--enforce <allowlist|blocklist>` turns on live WFP
/// filter installation (admin required; allowlist can brick a machine). Reuses
/// the exact incident sink + offline queue as usb-monitor. Network incidents are
/// metadata-only (no verdict) so the sink LOGS them (channel = "network").
fn cmd_net_monitor(cfg: &Config, storage: &Storage, args: &[String]) -> Result<()> {
    use netfilter::NetMode;

    // Default to the config mode (which itself defaults to `monitor`); the CLI
    // `--enforce <mode>` wins over the config.
    let mut mode = cfg.netfilter.mode;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--enforce" => {
                let val = it.next().map(|s| s.as_str()).unwrap_or("");
                mode = match val {
                    "monitor" => NetMode::Monitor,
                    "allowlist" => NetMode::Allowlist,
                    "blocklist" => NetMode::Blocklist,
                    other => {
                        eprintln!(
                            "net-monitor --enforce expects monitor|allowlist|blocklist, got '{other}'"
                        );
                        print_net_help();
                        std::process::exit(2);
                    }
                };
            }
            "-h" | "--help" => {
                print_net_help();
                return Ok(());
            }
            other => {
                eprintln!("unknown net-monitor option: {other}");
                print_net_help();
                std::process::exit(2);
            }
        }
    }

    let queue = usb::queue::IncidentQueue::new(&cfg.state_dir);
    if storage.has_identity() && !queue.is_empty() {
        let flushed = queue.flush(|body| post_incident_body(cfg, storage, body).map(|_| ()));
        if flushed > 0 {
            tracing::info!(flushed, "flushed queued incidents");
        }
    }

    // Same sink shape as cmd_usb_monitor. Network incidents carry no verdict, so
    // usb_incident_body returns None → they are LOGGED locally (metadata only),
    // never posted (a server-side network-incident schema is a follow-on).
    let sink = |inc: UsbIncident| match usb_incident_body(&inc) {
        Some(body) => {
            if storage.has_identity() {
                match post_incident_body(cfg, storage, &body) {
                    Ok(id) => tracing::info!(incident_id = %id, kind = ?inc.kind, "net incident reported"),
                    Err(e) => {
                        tracing::warn!(error = %e, "net incident post failed — queuing locally");
                        let _ = queue.enqueue(&body);
                    }
                }
            } else {
                tracing::warn!(kind = ?inc.kind, "unenrolled — queuing net incident locally");
                let _ = queue.enqueue(&body);
            }
        }
        None => tracing::info!(
            kind = ?inc.kind,
            app = %inc.device.product_name,
            note = inc.note.as_deref().unwrap_or(""),
            "net metadata incident (no verdict; not posted)"
        ),
    };

    netfilter::run_monitor(cfg, storage, mode, sink);
    Ok(())
}

/// browser-host: the Chrome/Edge native-messaging host. Speaks the 4-byte-LE
/// length-prefixed JSON protocol on stdio, scores each upload with the FROZEN
/// `detect::verdict`/`verdict_text` against the cached bundle, replies
/// allow/block/warn, and raises an incident on a match (channel = "web-upload").
/// Reuses the exact incident sink + offline queue as usb-monitor.
fn cmd_browser_host(cfg: &Config, storage: &Storage, args: &[String]) -> Result<()> {
    for arg in args {
        match arg.as_str() {
            "-h" | "--help" => {
                print_browserhost_help();
                return Ok(());
            }
            other => {
                eprintln!("unknown browser-host option: {other}");
                print_browserhost_help();
                std::process::exit(2);
            }
        }
    }

    let channel = "web-upload";
    // Reuse the shared block thresholds (mirror kguard::should_block).
    let block_at = cfg.kguard.block_at;
    let coverage_block_at = cfg.kguard.coverage_block_at;

    let queue = usb::queue::IncidentQueue::new(&cfg.state_dir);
    if storage.has_identity() && !queue.is_empty() {
        let flushed = queue.flush(|body| post_incident_body(cfg, storage, body).map(|_| ()));
        if flushed > 0 {
            tracing::info!(flushed, "flushed queued incidents");
        }
    }

    // Same sink shape as cmd_usb_monitor: web-upload incidents carry a verdict, so
    // they POST over mTLS when enrolled, else queue locally (bounded).
    let mut sink = |inc: UsbIncident| match usb_incident_body(&inc) {
        Some(body) => {
            if storage.has_identity() {
                match post_incident_body(cfg, storage, &body) {
                    Ok(id) => tracing::info!(incident_id = %id, kind = ?inc.kind, "web-upload incident reported"),
                    Err(e) => {
                        tracing::warn!(error = %e, "web-upload incident post failed — queuing locally");
                        let _ = queue.enqueue(&body);
                    }
                }
            } else {
                tracing::warn!(kind = ?inc.kind, "unenrolled — queuing web-upload incident locally");
                let _ = queue.enqueue(&body);
            }
        }
        None => tracing::info!(kind = ?inc.kind, "web-upload metadata incident (no verdict; not posted)"),
    };

    let bundle = load_verified_bundle(cfg, storage);
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();

    match bundle {
        Some(b) => {
            tracing::info!("browser-host started (bundle cached) — reading native messages");
            browser_host::serve(
                &mut reader,
                &mut writer,
                block_at,
                coverage_block_at,
                channel,
                |t| detect::verdict_text(t, &b),
                |p| detect::verdict(p, &b),
                &mut sink,
            )?;
        }
        None => {
            // No policy bundle: we cannot score. Fail-OPEN (allow) so the browser
            // is never bricked — audit-only until a bundle is present. Honest,
            // documented limitation (a fail-secure knob is a follow-on).
            tracing::warn!(
                "no verified index bundle cached — browser-host allows all uploads (audit-only)"
            );
            let clean = || detect::Verdict {
                file_name: String::new(),
                file_sha256: String::new(),
                extraction: detect::Extraction::Ok { format: "none".into() },
                idm: Vec::new(),
                edm: Vec::new(),
            };
            browser_host::serve(
                &mut reader,
                &mut writer,
                block_at,
                coverage_block_at,
                channel,
                |_t| clean(),
                |_p| Ok(clean()),
                &mut sink,
            )?;
        }
    }
    Ok(())
}

fn print_status(storage: &Storage) -> Result<()> {
    if !storage.has_identity() {
        println!("not enrolled");
        return Ok(());
    }
    let meta = storage.load_meta()?;
    println!("enrolled");
    println!("  agent id:        {}", meta.agent_id);
    println!("  check-in every:  {}s", meta.checkin_interval_seconds);

    // Unseal the identity and show the certificate the server issued.
    if let Ok((identity_pem, _ca)) = storage.load_identity() {
        if let Some(cert_pem) = extract_cert_pem(&identity_pem) {
            match x509_cert::Certificate::from_pem(cert_pem.as_bytes()) {
                Ok(cert) => {
                    let tbs = &cert.tbs_certificate;
                    println!("  certificate:");
                    println!("    subject:       {}", tbs.subject);
                    println!("    issuer:        {}", tbs.issuer);
                    println!("    serial:        {}", tbs.serial_number);
                    println!("    valid until:   {}", tbs.validity.not_after);
                    println!("    key stored:    DPAPI-sealed (machine scope)");
                }
                Err(e) => println!("  (could not parse certificate: {e})"),
            }
        }
    }
    Ok(())
}

/// Pull the certificate PEM block out of the stored key+cert identity bundle.
fn extract_cert_pem(identity: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(identity);
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = s.find(BEGIN)?;
    let end = s.find(END)? + END.len();
    Some(s[start..end].to_string())
}

fn print_help() {
    println!("dlp-agent <enroll|once|run|status|index-update|scan|usb-monitor|usb-guard|clipboard-monitor|net-monitor|browser-host>");
    println!("  scan --bundle <path> --file <path> [--json] [--report --channel <name>]");
    println!("  usb-monitor [--enforce]   watch removable media; audit copies (see --help)");
    println!("  usb-guard                 answer the kernel minifilter's scan port (see --help)");
    println!("  clipboard-monitor [--enforce]  watch the clipboard; audit copies (see --help)");
    println!("  net-monitor [--enforce <monitor|allowlist|blocklist>]  WFP network egress (see --help)");
    println!("  browser-host              Chrome/Edge native-messaging upload host (see --help)");
    println!("  config: $DLP_AGENT_CONFIG or {DEFAULT_CONFIG}");
    println!("  env overrides: DLP_AGENT_SERVER_URL, DLP_AGENT_TOKEN, DLP_AGENT_CA_CERT, DLP_AGENT_STATE_DIR");
}

fn print_usb_help() {
    println!("dlp-agent usb-monitor [--enforce]");
    println!("  Watches for removable-media (USB/SD/MMC) devices, applies the [usb]");
    println!("  policy, and audits files copied to each volume with detect::verdict().");
    println!("  --enforce   apply live device control (read-only / dismount, plus MTP/WPD");
    println!("              deny and USB-tethering block). Requires admin/SYSTEM AND [usb]");
    println!("              enabled=true in config. Default: audit-only (dry-run planning;");
    println!("              nothing on the system is changed).");
    println!("  Device classes (spec §2): mass-storage flows through the [[usb.rules]]");
    println!("  matrix; MTP/WPD phones+cameras use [usb] mtp_action (default block); USB");
    println!("  tethering (RNDIS/NCM) adapters use [usb] tethering_action (default block).");
    println!("  MTP block sets WPD Deny_Read/Deny_Write; tethering block restricts the net");
    println!("  device class. Both are planned (dry-run) by default; live writes need");
    println!("  --enforce + admin and are operator-manual.");
    println!("  Incidents post over mTLS when enrolled, else queue locally (bounded) and");
    println!("  flush on the next run. Runs independently of the check-in loop.");
    println!("  Config: the optional [usb] section (poll_interval_secs, settle_ms,");
    println!("  settle_timeout_secs, max_file_bytes, default_action, mtp_action,");
    println!("  tethering_action, channel_label, rules).");
}

fn print_clipboard_help() {
    println!("dlp-agent clipboard-monitor [--enforce]");
    println!("  Watches the Windows clipboard, inspects copied content against the cached");
    println!("  index bundle, and audits sensitive copies. Text (CF_UNICODETEXT, and");
    println!("  best-effort HTML/RTF) is scored with detect::verdict_text; dropped files");
    println!("  (CF_HDROP) with detect::verdict; images (CF_DIB/CF_BITMAP) cannot be");
    println!("  inspected without OCR and are audited as 'uninspected' (or blocked wholesale");
    println!("  when [clipboard] block_images=true).");
    println!("  --enforce   block a flagged copy by clearing the clipboard (EmptyClipboard),");
    println!("              so the paste yields nothing. Requires [clipboard] enabled=true.");
    println!("              Default: audit-only (dry-run; the clipboard is never changed).");
    println!("  Incidents carry hashes/verdict metadata ONLY — never the copied text — and");
    println!("  post over mTLS when enrolled, else queue locally (bounded). channel=\"clipboard\".");
    println!("  Config: the optional [clipboard] section (enabled, default_action, max_bytes,");
    println!("  block_images, channel_label, block_at, coverage_block_at, fail_block).");
}

fn print_usbguard_help() {
    println!("dlp-agent usb-guard");
    println!("  Connects to the DLP kernel minifilter's communication port (\\DlpFltPort)");
    println!("  and answers its scan requests: for each file the driver reports, score it");
    println!("  with detect::verdict() against the cached bundle, apply the [kguard]");
    println!("  thresholds, and reply allow/block. The driver quarantines on block.");
    println!("  Requires dlpflt.sys to be loaded (see dlp-minifilter/README.md). THIS");
    println!("  process must be the one that connects — the driver skips its own PID to");
    println!("  avoid recursion, so do not proxy the connection.");
    println!("  Incidents post over mTLS when enrolled, else queue locally (bounded).");
    println!("  Config: optional [kguard] section (block_at, coverage_block_at, fail_block,");
    println!("  channel_label).");
}

fn print_net_help() {
    println!("dlp-agent net-monitor [--enforce <monitor|allowlist|blocklist>]");
    println!("  User-mode WFP network-egress control (Tier-2 plan §2). Judges outbound");
    println!("  connections by app-id / remote IP-CIDR / remote port and a built-in");
    println!("  remote-access-tool set (AnyDesk, TeamViewer, VNC, Chrome Remote Desktop,");
    println!("  RDP-out, Splashtop, LogMeIn) — matched PRIMARILY by process image name.");
    println!("  Modes:");
    println!("    monitor   (DEFAULT, audit-only) add NO blocking filters; enumerate and");
    println!("              log the verdict we WOULD apply. Never blocks — cannot brick.");
    println!("    blocklist default-PERMIT; BLOCK only matched dests/apps/remote-tools.");
    println!("    allowlist default-DENY; PERMIT only approved dests/apps, BLOCK the rest.");
    println!("  --enforce <mode>  install LIVE WFP BLOCK/PERMIT filters (FwpmFilterAdd0).");
    println!("              REQUIRES administrator/SYSTEM. A DYNAMIC session is used so all");
    println!("              our filters auto-remove when this process exits.");
    println!("  !! DoS WARNING: 'allowlist' is default-DENY. An incomplete allowlist WILL");
    println!("     break connectivity (a self-inflicted denial of service). Ship 'monitor',");
    println!("     move to 'allowlist' only with a vetted permit set. This is why the");
    println!("     default is audit-only and enforcement must be explicitly requested.");
    println!("  HONEST LIMITS (plan §0): this blocks a process's socket connect. It does");
    println!("     NOT stop a screen already being VIEWED over VNC/AnyDesk (the analog");
    println!("     hole), a privileged/SYSTEM payload that unhooks the agent, or encrypted");
    println!("     exfil to an ALLOWED destination (content-blind). Live filter add + live");
    println!("     process kill are operator-manual (admin/VM); only the pure rule engine,");
    println!("     remote-tool matcher, and WFP filter-spec dry-run are verified in tests.");
    println!("  Incidents are metadata only (app/ip/port/tool) — never packet contents.");
    println!("  Config: the optional [netfilter] section (mode, channel_label,");
    println!("  remote_tool_action, remote_tool_overrides, persist, [[netfilter.rules]]).");
}

fn print_browserhost_help() {
    println!("dlp-agent browser-host");
    println!("  Chrome/Edge native-messaging host for the web-upload channel (Tier-2");
    println!("  plan §3). Speaks the native-messaging protocol on stdio: a 4-byte");
    println!("  little-endian length prefix + UTF-8 JSON. The force-installed MV3");
    println!("  extension intercepts file/drag-drop/fetch uploads and sends them here;");
    println!("  this host scores them with detect::verdict/verdict_text against the cached");
    println!("  bundle and replies allow/block/warn. A block cancels the upload.");
    println!("  Launched by the browser (not run interactively). Register the native-host");
    println!("  manifest per the extension's install docs.");
    println!("  Incidents carry hashes/verdict + url/origin metadata ONLY — never the");
    println!("  uploaded content — and post over mTLS when enrolled (channel=\"web-upload\").");
    println!("  With no cached bundle the host allows all uploads (audit-only) so the");
    println!("  browser is never bricked. True end-to-end needs a real browser (MANUAL).");
    println!("  Thresholds: [kguard] block_at / coverage_block_at.");
}

fn print_scan_help() {
    println!("dlp-agent scan --bundle <path> --file <path> [--json] [--report --channel <name>]");
    println!("  --bundle <path>   signed index bundle (.dlpx) to match against");
    println!("  --file <path>     file to scan");
    println!("  --json            print the full verdict as JSON");
    println!("  --report          POST the verdict to the server (mTLS, requires enrollment)");
    println!("  --channel <name>  channel label for the report, e.g. usb-audit");
    println!("  exit code is 0 whenever the scan executes; an unreadable file is a verdict, not an error");
}

/// Best-effort machine hostname (used as the CSR hint; the server assigns the
/// real identity).
pub fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".into())
}
