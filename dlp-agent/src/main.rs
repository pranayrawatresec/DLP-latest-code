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
//!   dlp-agent decrypt       open a .dlpenc envelope (audited-first, offline keyring)
mod checkin;
mod client;
mod enroll;
mod identity;
mod kguard;
mod service;

// Config, Storage, detection and the USB channel live in the library crate so
// integration tests and the binary share one set of types. Re-import the
// modules at the crate root so the binary submodules keep addressing them as
// `crate::config` / `crate::storage`.
use dlp_agent::{
    browser_host, clipboard, config, crypto, decrypt, detect, exfil, netfilter, notify,
    readdenypolicy, storage, supervise, trustdest, trustedreaders, trustsync, usb,
};

use anyhow::{Context, Result};
use config::Config;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use storage::Storage;
use usb::{ActionTaken, UsbIncident};
use x509_cert::der::DecodePem;

const DEFAULT_CONFIG: &str = r"C:\ProgramData\DLPAgent\agent.toml";
/// Backoff when the server is unreachable — the agent keeps enforcing cached
/// policy and retries, never falling open.
const RETRY_SECONDS: u64 = 30;

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();

    // The SCM launches `dlp-agent service-run` with NO console attached. Do not
    // init console logging on that path — the service dispatcher sets up rolling
    // FILE logging under C:\ProgramData\DLPAgent\logs instead. Every interactive
    // subcommand keeps console logging (below).
    #[cfg(windows)]
    if mode == "service-run" {
        if let Err(e) = service::run_dispatcher() {
            eprintln!("service dispatcher failed: {e:#}");
            std::process::exit(1);
        }
        return;
    }

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
    if mode == "decrypt" && args.iter().any(|a| a == "-h" || a == "--help") {
        print_decrypt_help();
        return Ok(());
    }

    // `toast` is the in-session renderer the Session-0 service spawns via
    // CreateProcessAsUserW. It must run WITHOUT loading config/enrollment (it runs
    // in an arbitrary user's context and only draws a toast), so handle it here.
    if mode == "toast" {
        return cmd_toast(&args);
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
        "decrypt" => cmd_decrypt(&cfg, &storage, &args)?,
        "run-endpoint" => cmd_run_endpoint(&cfg, &storage)?,
        "install-service" => service::install()?,
        "uninstall-service" => service::uninstall()?,
        "service-run" => {
            // On Windows this is intercepted in main() and never reaches here; on
            // other platforms it is meaningless.
            anyhow::bail!("service-run is only invoked by the Windows Service Control Manager")
        }
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
    update_index_bundle(cfg, storage, outcome.index_latest)
}

/// Fetch + verify + swap the index bundle if `index_latest` is newer than the
/// cached one. Shared by `index-update` and the `run-endpoint` check-in worker.
/// A bundle that fails signature/parse NEVER replaces the cached one (fail
/// secure). Requires enrollment (loads the identity for the mTLS download).
fn update_index_bundle(cfg: &Config, storage: &Storage, index_latest: u64) -> Result<()> {
    let (identity_pem, ca_pem) = storage.load_identity()?;

    // Current version = whatever the cached bundle verifiably says; a
    // missing or corrupt cache means 0 (forces a refetch).
    let current = storage
        .load_index_bundle()
        .and_then(|bytes| detect::Bundle::load(&bytes, &ca_pem).ok())
        .map(|b| b.version())
        .unwrap_or(0);

    if index_latest == 0 {
        tracing::info!("server has no index bundle yet");
        return Ok(());
    }
    if index_latest <= current {
        tracing::info!(version = current, "index bundle already up to date");
        return Ok(());
    }

    tracing::info!(have = current, latest = index_latest, "fetching index bundle");
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
    /// What the agent actually did ("blocked" | "audited" | "read_only"). Lets the
    /// console distinguish a real block from an audit-only observation. Optional so
    /// older/scan-path callers stay wire-compatible.
    #[serde(rename = "actionTaken", skip_serializing_if = "Option::is_none")]
    action_taken: Option<&'a str>,
    /// Best-effort interactive user on the endpoint ("who"). Metadata only; never
    /// a credential. Optional.
    #[serde(rename = "osUser", skip_serializing_if = "Option::is_none")]
    os_user: Option<String>,
    /// KEK id a successful seal used (encrypt-on-write M3). FREE-FORM opaque
    /// string. Additive wire field — absent for every unsealed incident.
    #[serde(rename = "keyId", skip_serializing_if = "Option::is_none")]
    key_id: Option<&'a str>,
    /// hex SHA-256 of the sealed `.dlpenc` envelope (successful seals only).
    /// Additive wire field; `fileSha256` stays the plaintext hash.
    #[serde(rename = "sealedSha256", skip_serializing_if = "Option::is_none")]
    sealed_sha256: Option<&'a str>,
}

/// Wire label for an `ActionTaken` (matches the server's accepted values;
/// "encrypted" is additive — an older server stores actionTaken as null).
fn action_taken_label(a: ActionTaken) -> &'static str {
    match a {
        ActionTaken::Blocked => "blocked",
        ActionTaken::Audited => "audited",
        ActionTaken::ReadOnly => "read_only",
        ActionTaken::Encrypted => "encrypted",
    }
}

/// `toast` subcommand: render the endpoint "blocked by DLP" toast in THIS session.
/// Spawned by the Session-0 service (CreateProcessAsUserW) into the user session,
/// or runnable directly. Never fails the process on a toast error — the block it
/// reports already happened; a missing toast must not look like a crash.
fn cmd_toast(args: &[String]) -> Result<()> {
    let mut aumid = String::new();
    let mut title = String::new();
    let mut body = String::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--aumid" => aumid = it.next().cloned().unwrap_or_default(),
            "--title" => title = it.next().cloned().unwrap_or_default(),
            "--body" => body = it.next().cloned().unwrap_or_default(),
            _ => {}
        }
    }
    // The parent encodes body newlines as U+2028 so they survive the command line.
    let body = body.replace('\u{2028}', "\n");
    if aumid.is_empty() {
        aumid = "Resec.DLP.Agent".to_string();
    }
    if let Err(e) = notify::show_toast_from_cli(&title, &body, &aumid) {
        tracing::warn!(error = %e, "toast render failed");
    }
    Ok(())
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
        action_taken: None,
        os_user: None,
        key_id: None,
        sealed_sha256: None,
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
        action_taken: Some(action_taken_label(inc.action_taken)),
        os_user: notify::current_user(),
        key_id: inc.key_id.as_deref(),
        sealed_sha256: inc.sealed_sha256.as_deref(),
    })
    .ok()
}

/// The single funnel every channel's incident sink runs an incident through:
/// (1) fire the endpoint "blocked by DLP" toast — best-effort and internally
/// gated so it only shows on an actual BLOCK (see `notify::on_block_for_incident`),
/// so EVERY channel (usb/clipboard/network/web-upload) notifies uniformly; then
/// (2) build the mTLS wire body. Returns `None` for metadata-only incidents (e.g.
/// network, which carries no verdict) — those are logged locally, not posted.
fn incident_wire_body(cfg: &Config, inc: &UsbIncident) -> Option<String> {
    notify::on_block_for_incident(&cfg.notify, inc);
    usb_incident_body(inc)
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

    // M6: pull the console-authored trusted-destination whitelist + encryption
    // keys over mTLS, then merge the synced destinations into the effective
    // [usb] config so the monitor whitelists + seals exactly what the admin set
    // — with NO local [usb]/[crypto] config required. Best-effort: a sync
    // failure is logged inside and we fall back to the last-persisted whitelist
    // (offline, fail secure). Everything below uses the MERGED config.
    let _ = checkin::sync_trusted_config(cfg, storage);
    let synced = checkin::load_synced_destinations(storage);
    let effective = cfg.with_synced_destinations(&synced);
    let cfg = &effective;

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
    let sink = |inc: UsbIncident| match incident_wire_body(cfg, &inc) {
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

    // Trusted-destination sealer (encrypt-on-write M3/M6). See
    // `build_sealer_keyring` / `make_sealer` for the keyring resolution + seal
    // closure (shared with `run-endpoint`). Fail secure: with no keyring the
    // sealer errors on every call, so files on Encrypt volumes stay plaintext
    // but every one raises an EnforcementFailed incident — never a silent pass.
    let keyring = build_sealer_keyring(cfg, storage);
    let sealer = make_sealer(keyring, agent_id_of(storage));

    // Standalone usb-monitor: wrap the (fixed) merged config so it shares the
    // same `run_monitor` code path as run-endpoint. No in-process guard reads
    // this signal here, so no liveness signal and no stop signal are passed —
    // today's foreground behaviour is preserved exactly.
    let shared = Arc::new(RwLock::new(cfg.clone()));
    usb::run_monitor(&shared, storage, enforce, None, None, sealer, sink);
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

    // M6: same trusted-config sync + merge as usb-monitor so the guard's
    // write-scan whitelist is driven by the console-authored destinations. The
    // guard's decide()/write_scan_override reads cfg.usb via
    // decide/encrypt_params, so feeding kguard::run the MERGED config makes it
    // stand aside for exactly the synced Encrypt destinations. Best-effort;
    // last-persisted whitelist on failure. Everything below uses the MERGED cfg.
    let _ = checkin::sync_trusted_config(cfg, storage);
    let synced = checkin::load_synced_destinations(storage);
    // Read-deny allowlist posture: also pull the sanctioned-reader allowlist so
    // the exfil pusher classifies against the console-authored list.
    let readers = checkin::sync_trusted_readers(cfg, storage);
    let effective = cfg.with_synced_destinations(&synced).with_synced_readers(&readers);
    let cfg = &effective;

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
    let sink = |inc: UsbIncident| match incident_wire_body(cfg, &inc) {
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

    // Standalone usb-guard: wrap the (fixed) merged config to share the guard
    // code path with run-endpoint. It has NO in-process sealer, so it passes NO
    // liveness signal — the guard then treats the sealer as "healthy" and keeps
    // TODAY's allow-pending-seal behaviour for whitelisted Encrypt destinations
    // (deliberately NOT regressed; a standalone guard without a sealer is the
    // operator's debugging tool, and the kernel FailMode remains the backstop).
    let shared = Arc::new(RwLock::new(cfg.clone()));
    kguard::run(&shared, storage, None, None, sink)
}

/// The enrolled agent id used as `origin_agent` in sealed envelopes (never the
/// hostname, spec §4). "unenrolled" until an identity exists.
fn agent_id_of(storage: &Storage) -> String {
    storage
        .load_meta()
        .map(|m| m.agent_id)
        .unwrap_or_else(|_| "unenrolled".to_string())
}

/// Resolve the sealer keyring (encrypt-on-write M3/M6), shared by `usb-monitor`
/// and `run-endpoint`. PREFERS the synced DPAPI keyring at rest (written by
/// `sync_trusted_config`) over the dev `[crypto] keyfile`; the keyfile is only a
/// fallback for when no synced keyring exists yet. `None` ⇒ no usable keyring
/// (sealing then fails secure per call). Errors carry ids/lengths only — NEVER
/// key material.
fn build_sealer_keyring(cfg: &Config, storage: &Storage) -> Option<crypto::Keyring> {
    match storage.load_keyring() {
        Ok(Some(bytes)) => {
            let bytes = zeroize::Zeroizing::new(bytes);
            match crypto::Keyring::from_dev_json(&bytes) {
                Ok(ring) => Some(ring),
                Err(e) => {
                    tracing::warn!(error = %e, "synced keyring unusable — falling back to dev keyfile");
                    load_dev_keyring(&cfg.crypto.keyfile)
                }
            }
        }
        Ok(None) => load_dev_keyring(&cfg.crypto.keyfile),
        Err(e) => {
            tracing::warn!(error = %e, "sealed keyring unreadable — falling back to dev keyfile");
            load_dev_keyring(&cfg.crypto.keyfile)
        }
    }
}

/// Build the injected seal-in-place closure for `usb::run_monitor`
/// (`(path, key_id) → SealOutcome`). `None` keyring ⇒ every call errors (fail
/// secure — the copy auditor keeps the plaintext and raises EnforcementFailed).
fn make_sealer(
    keyring: Option<crypto::Keyring>,
    agent_id: String,
) -> impl Fn(&Path, &str) -> anyhow::Result<usb::SealOutcome> {
    move |path: &Path, key_id: &str| -> anyhow::Result<usb::SealOutcome> {
        let ring = keyring
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no keyring loaded ([crypto] keyfile unset or unreadable)"))?;
        let kek = ring.lookup(key_id).map_err(anyhow::Error::new)?;
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        usb::seal_file_in_place(path, kek, &agent_id, now_unix)
    }
}

/// Deliver one incident through the shared funnel: fire the endpoint toast (gated
/// internally on an actual block), then POST over mTLS when enrolled, else queue
/// on disk (bounded). Metadata-only incidents (no verdict) are logged. Used by
/// the `run-endpoint` worker sinks (the standalone commands keep their inline
/// sinks). `cfg` is a fresh snapshot so live config (notify verbosity, channel)
/// applies.
fn deliver_incident(
    cfg: &Config,
    storage: &Storage,
    queue: &usb::queue::IncidentQueue,
    inc: &UsbIncident,
) {
    match incident_wire_body(cfg, inc) {
        Some(body) => {
            if storage.has_identity() {
                match post_incident_body(cfg, storage, &body) {
                    Ok(id) => {
                        tracing::info!(incident_id = %id, kind = ?inc.kind, "incident reported")
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "incident post failed — queuing locally");
                        let _ = queue.enqueue(&body);
                    }
                }
            } else {
                tracing::warn!(kind = ?inc.kind, "unenrolled — queuing incident locally");
                let _ = queue.enqueue(&body);
            }
        }
        None => tracing::info!(
            kind = ?inc.kind,
            note = inc.note.as_deref().unwrap_or(""),
            "metadata incident (no verdict; not posted)"
        ),
    }
}

/// Load the effective config + storage the way `run()` does — used by the
/// Windows service dispatcher, which has no `run()` context of its own.
fn load_cfg_and_storage() -> Result<(Config, Storage)> {
    let config_path =
        std::env::var("DLP_AGENT_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG.to_string());
    let cfg = Config::load(&PathBuf::from(config_path)).context("loading config")?;
    let storage = Storage::new(cfg.state_dir.clone());
    Ok((cfg, storage))
}

/// run-endpoint: the unified, supervised deployable unit (Windows-only). Runs
/// the kernel guard, the user-mode sealer, the check-in heartbeat, and a
/// periodic whitelist re-sync as coordinated threads in ONE process, sharing ONE
/// live merged-config view and the sealer-liveness signal. Foreground use is for
/// debugging; the Windows service (`install-service` / SCM) runs the same code.
fn cmd_run_endpoint(cfg: &Config, storage: &Storage) -> Result<()> {
    #[cfg(windows)]
    {
        // No console Ctrl-C handler is wired (avoids a new dependency): in the
        // foreground this runs until the process is killed; as a service the SCM
        // supplies the stop signal (see `service.rs`).
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        run_endpoint(cfg, storage, stop)
    }
    #[cfg(not(windows))]
    {
        let _ = (cfg, storage);
        anyhow::bail!("run-endpoint (kernel guard + sealer) is only available on Windows")
    }
}

/// The run-endpoint supervisor (Windows). Spawns and supervises the four worker
/// threads and blocks until `stop` is set (by the SCM control handler, or never
/// in the foreground). A panic in any worker is caught and the worker restarted;
/// a dead sealer thread stops marking itself alive, so the guard fails secure
/// automatically after `sealer_health_timeout_secs`.
#[cfg(windows)]
fn run_endpoint(cfg: &Config, storage: &Storage, stop: Arc<std::sync::atomic::AtomicBool>) -> Result<()> {
    use std::sync::atomic::Ordering;
    use supervise::SealerHealth;

    // Best-effort enrollment; workers queue incidents offline and check-in
    // retries, so an unreachable server here never blocks startup (fail secure).
    if let Err(e) = ensure_enrolled(cfg, storage) {
        tracing::warn!(error = %e, "run-endpoint: enrollment not complete — starting anyway (workers will retry/queue)");
    }

    // Initial merged config from a sync (fail-soft to the last-persisted
    // whitelist), shared live with the guard + sealer and swapped by the resync
    // worker so UI whitelist changes propagate WITHOUT a restart.
    let _ = checkin::sync_trusted_config(cfg, storage);
    let synced = checkin::load_synced_destinations(storage);
    // Read-deny allowlist posture: pull the sanctioned-reader allowlist too, so
    // the guard's exfil pusher classifies against the console-authored list.
    let readers = checkin::sync_trusted_readers(cfg, storage);
    // Read-deny POLICY: pull the console-managed mode/posture/scope/fail, APPLY the
    // driver knobs + volume attach (no CLI), and override the local [kguard] fields
    // so the console is the single source of truth for read-deny.
    let policy = checkin::sync_read_deny_policy(cfg, storage);
    let effective = cfg
        .with_synced_destinations(&synced)
        .with_synced_readers(&readers)
        .with_read_deny_policy(&policy);
    let shared: Arc<RwLock<Config>> = Arc::new(RwLock::new(effective));

    // Sealer liveness: keyring presence is the strong startup signal; liveness is
    // marked by the sealer on every poll. Guard reads both to fail secure.
    let keyring_present = build_sealer_keyring(cfg, storage).is_some();
    let health = Arc::new(SealerHealth::new(keyring_present));

    let base_cfg = cfg.clone();
    let state_dir = cfg.state_dir.clone();

    tracing::info!(keyring_present, "run-endpoint: starting guard + sealer + check-in + resync");

    let mut handles = Vec::new();

    // (a) GUARD — one \DlpFltPort connection (this process is the skip-self PID).
    {
        let shared = shared.clone();
        let health = health.clone();
        let stop_w = stop.clone();
        let state_dir = state_dir.clone();
        // Guard blocks in FilterGetMessage, so it is NOT joined at stop; the
        // process exit on service stop tears it down. It IS restarted on panic /
        // port close by the supervisor.
        let _guard = supervised_thread("guard", stop.clone(), Duration::from_secs(3), move || {
            let storage = Storage::new(state_dir.clone());
            let queue = usb::queue::IncidentQueue::new(&state_dir);
            let shared_s = shared.clone();
            let mut sink = |inc: UsbIncident| {
                let snap = supervise::snapshot_config(&shared_s);
                deliver_incident(&snap, &storage, &queue, &inc);
            };
            if let Err(e) = kguard::run(&shared, &storage, Some(&health), Some(&stop_w), &mut sink) {
                tracing::warn!(error = %e, "guard ended (driver not loaded?) — supervisor will retry");
            }
        });
    }

    // (b) SEALER — usb volume poll+seal loop; marks liveness each poll.
    {
        let shared = shared.clone();
        let health = health.clone();
        let stop_w = stop.clone();
        let state_dir = state_dir.clone();
        handles.push(supervised_thread("sealer", stop.clone(), Duration::from_secs(3), move || {
            let storage = Storage::new(state_dir.clone());
            let queue = usb::queue::IncidentQueue::new(&state_dir);
            // Rebuild the keyring each attempt (a resync may have refreshed keys)
            // and refresh the presence signal accordingly.
            let snap = supervise::snapshot_config(&shared);
            let keyring = build_sealer_keyring(&snap, &storage);
            health.set_keyring_present(keyring.is_some());
            let sealer = make_sealer(keyring, agent_id_of(&storage));
            let shared_s = shared.clone();
            let mut sink = |inc: UsbIncident| {
                let snap = supervise::snapshot_config(&shared_s);
                deliver_incident(&snap, &storage, &queue, &inc);
            };
            // enforce = FALSE — deliberate. The required behaviour is PER-FILE,
            // content-based: on a non-whitelisted stick a clean file must still
            // copy and only sensitive files are blocked (by the kernel guard),
            // and on a whitelisted stick sensitive files are sealed. Device-level
            // enforcement (enforce = true) would apply `default_action` (default
            // ReadOnly) to a whole non-whitelisted device, blocking even clean
            // copies — violating that matrix. Sealing does NOT depend on this flag
            // (the encrypt auditor is created regardless), so run-endpoint keeps
            // device control OFF and lets the guard do the per-file blocking.
            // NOTE: this also leaves the user-mode MTP/USB-tethering device blocks
            // (which live behind `enforce`) OFF — out of scope of the content
            // matrix; revisit if phone/tethering device-control is wanted.
            usb::run_monitor(&shared, &storage, false, Some(&health), Some(&stop_w), sealer, &mut sink);
        }));
    }

    // (c) CHECK-IN — heartbeat + index-update (folds in the old heartbeat task).
    {
        let shared = shared.clone();
        let stop_w = stop.clone();
        let state_dir = state_dir.clone();
        handles.push(supervised_thread("checkin", stop.clone(), Duration::from_secs(5), move || {
            let storage = Storage::new(state_dir.clone());
            loop {
                if stop_w.load(Ordering::Relaxed) {
                    break;
                }
                let snap = supervise::snapshot_config(&shared);
                let interval = match checkin::checkin_full(&snap, &storage) {
                    Ok(outcome) => {
                        if let Err(e) = update_index_bundle(&snap, &storage, outcome.index_latest) {
                            tracing::warn!(error = %e, "index-update failed (will retry next check-in)");
                        }
                        outcome.interval_seconds.max(5)
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "check-in failed; enforcing cached policy, will retry");
                        RETRY_SECONDS
                    }
                };
                sleep_interruptible(interval, &stop_w);
            }
        }));
    }

    // (d) RESYNC — re-pull the whitelist/keys and swap the shared config so both
    // guard and sealer pick up UI changes without a restart.
    {
        let shared = shared.clone();
        let health = health.clone();
        let stop_w = stop.clone();
        let state_dir = state_dir.clone();
        let resync_secs = base_cfg.checkin_interval_seconds.max(30);
        handles.push(supervised_thread("resync", stop.clone(), Duration::from_secs(5), move || {
            let storage = Storage::new(state_dir.clone());
            loop {
                if stop_w.load(Ordering::Relaxed) {
                    break;
                }
                sleep_interruptible(resync_secs, &stop_w);
                if stop_w.load(Ordering::Relaxed) {
                    break;
                }
                let _ = checkin::sync_trusted_config(&base_cfg, &storage);
                let synced = checkin::load_synced_destinations(&storage);
                let readers = checkin::sync_trusted_readers(&base_cfg, &storage);
                let policy = checkin::sync_read_deny_policy(&base_cfg, &storage);
                let new_effective = base_cfg
                    .with_synced_destinations(&synced)
                    .with_synced_readers(&readers)
                    .with_read_deny_policy(&policy);
                health.set_keyring_present(build_sealer_keyring(&base_cfg, &storage).is_some());
                match shared.write() {
                    Ok(mut w) => *w = new_effective,
                    Err(p) => *p.into_inner() = new_effective,
                }
                tracing::info!("resynced trusted config — guard + sealer will use it live");
            }
        }));
    }

    // Block until stop, then let the cooperative workers wind down.
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(200));
    }
    tracing::info!("run-endpoint: stop signalled — waiting for workers");
    for h in handles {
        let _ = h.join();
    }
    tracing::info!("run-endpoint: stopped");
    Ok(())
}

/// Spawn a supervised worker: run `body` in a loop, catching panics and
/// restarting after `restart_delay`, until `stop` is set. `body` is a full
/// attempt (it may itself loop); returning normally also triggers a restart
/// (e.g. the guard reconnecting after a port close). Never lets a worker panic
/// take down the process.
#[cfg(windows)]
fn supervised_thread<F>(
    name: &'static str,
    stop: Arc<std::sync::atomic::AtomicBool>,
    restart_delay: Duration,
    body: F,
) -> std::thread::JoinHandle<()>
where
    F: Fn() + Send + 'static,
{
    use std::sync::atomic::Ordering;
    std::thread::Builder::new()
        .name(format!("dlp-{name}"))
        .spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(&body));
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                match res {
                    Ok(()) => tracing::info!(worker = name, "worker returned — restarting"),
                    Err(_) => tracing::error!(worker = name, "worker PANICKED — restarting (fail secure)"),
                }
                std::thread::sleep(restart_delay);
            }
            tracing::info!(worker = name, "worker exiting (stop signalled)");
        })
        .expect("spawn supervised worker thread")
}

/// Sleep up to `secs`, waking early (in 200ms steps) when `stop` is set, so a
/// service stop is prompt without a per-worker timer.
#[cfg(windows)]
fn sleep_interruptible(secs: u64, stop: &std::sync::atomic::AtomicBool) {
    use std::sync::atomic::Ordering;
    let steps = secs.saturating_mul(5); // 200ms per step
    for _ in 0..steps {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Initialise rolling FILE logging under `C:\ProgramData\DLPAgent\logs` for the
/// service (no console under the SCM). Called once by the service dispatcher.
/// Size-rotates the current log on startup (a full continuous roller would need
/// `tracing-appender`, a dependency we deliberately avoid). Never logs key
/// material or content.
#[cfg(windows)]
pub fn init_file_logging() {
    use std::io::Write;
    use std::sync::Mutex;

    let dir = PathBuf::from(r"C:\ProgramData\DLPAgent\logs");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("dlp-agent.log");

    // Rotate on startup if the current log is large (best-effort).
    const MAX_BYTES: u64 = 5 * 1024 * 1024;
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > MAX_BYTES {
            let _ = std::fs::rename(&path, dir.join("dlp-agent.log.1"));
        }
    }

    match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        Ok(file) => {
            let file = Arc::new(Mutex::new(file));
            // A `Fn() -> impl Write` is a `MakeWriter`; lock per write.
            struct MutexWriter(Arc<Mutex<std::fs::File>>);
            impl Write for MutexWriter {
                fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                    self.0.lock().unwrap_or_else(|p| p.into_inner()).write(buf)
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    self.0.lock().unwrap_or_else(|p| p.into_inner()).flush()
                }
            }
            let make = move || MutexWriter(file.clone());
            tracing_subscriber::fmt()
                .with_target(false)
                .with_ansi(false)
                .with_max_level(tracing::Level::INFO)
                .with_writer(make)
                .init();
            tracing::info!("service file logging initialised at {}", path.display());
        }
        Err(e) => {
            // Fall back to a plain (likely discarded) console subscriber so the
            // process still runs; never abort enforcement over a log file.
            tracing_subscriber::fmt()
                .with_target(false)
                .with_max_level(tracing::Level::INFO)
                .init();
            tracing::warn!(error = %e, "could not open service log file — logging to stderr");
        }
    }
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
    let sink = |inc: UsbIncident| match incident_wire_body(cfg, &inc) {
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
    let sink = |inc: UsbIncident| match incident_wire_body(cfg, &inc) {
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
    let mut sink = |inc: UsbIncident| match incident_wire_body(cfg, &inc) {
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
                |bytes, name| detect::verdict_bytes(bytes, name, &b),
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
                |_b, _n| clean(),
                &mut sink,
            )?;
        }
    }
    Ok(())
}

/// Load a dev keyfile keyring (⚠ DEV ONLY: plaintext KEK material, spec §4.1)
/// as the SEALER fallback when no synced DPAPI keyring exists at rest. Errors
/// are logged as metadata only (never key material); a failure disables sealing
/// (fail secure — files on Encrypt volumes then raise EnforcementFailed rather
/// than pass in plaintext).
fn load_dev_keyring(keyfile: &Option<PathBuf>) -> Option<crypto::Keyring> {
    match keyfile {
        Some(path) => match crypto::Keyring::load_dev_keyfile(path) {
            Ok(ring) => Some(ring),
            Err(e) => {
                tracing::warn!(error = %e, "dev keyfile load failed — sealing disabled (fail secure)");
                None
            }
        },
        None => None,
    }
}

/// Load the keyring for decrypt/seal — offline and cached, NEVER a server
/// round-trip (project decision; matches cached-policy semantics):
/// 1. `[crypto] keyfile` (⚠ DEV ONLY: PLAINTEXT key material, spec §4.1) when
///    configured — wins, and refreshes the DPAPI-sealed at-rest copy;
/// 2. else the DPAPI-sealed keyring at rest (machine scope, M4);
/// 3. else an EMPTY ring — every open then fails `UnknownKeyId`, which the
///    decrypt path surfaces as a `DecryptDenied` incident (fail secure, and
///    the attempt itself is signal).
/// Errors are logged as metadata only — never key material or file contents.
fn load_decrypt_keyring(cfg: &Config, storage: &Storage) -> crypto::Keyring {
    if let Some(path) = &cfg.crypto.keyfile {
        match std::fs::read(path) {
            Ok(bytes) => {
                let bytes = zeroize::Zeroizing::new(bytes);
                match crypto::Keyring::from_dev_json(&bytes) {
                    Ok(ring) => {
                        // Cache at rest so later decrypts work without the dev
                        // keyfile. DPAPI machine scope on Windows; on
                        // non-Windows dev builds this is a plaintext
                        // passthrough (loud warning lives in storage.rs).
                        if let Err(e) = storage.store_keyring(&bytes) {
                            tracing::warn!(error = %e, "could not cache keyring at rest");
                        }
                        return ring;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "dev keyfile unusable — trying sealed keyring")
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "dev keyfile unreadable — trying sealed keyring"),
        }
    }
    match storage.load_keyring() {
        Ok(Some(bytes)) => {
            let bytes = zeroize::Zeroizing::new(bytes);
            match crypto::Keyring::from_dev_json(&bytes) {
                Ok(ring) => return ring,
                Err(e) => tracing::warn!(error = %e, "sealed keyring unusable"),
            }
        }
        Ok(None) => {}
        Err(e) => tracing::warn!(error = %e, "sealed keyring unreadable"),
    }
    tracing::warn!("no keyring available — every decrypt will be denied (fail secure)");
    crypto::Keyring::new("")
}

/// decrypt: open a `.dlpenc` envelope on this enrolled endpoint (encrypt-on-
/// write spec §5.3, M4). Offline-capable: the cached keyring is the only key
/// source. The audit incident (channel "decrypt") is recorded BEFORE the
/// plaintext is written; if it can neither be posted nor queued locally,
/// nothing is written. Unknown/destroyed key ⇒ DecryptDenied incident and a
/// non-zero exit, nothing written.
fn cmd_decrypt(cfg: &Config, storage: &Storage, args: &[String]) -> Result<()> {
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-o" | "--output" => {
                output = Some(PathBuf::from(
                    it.next().context("-o requires a path")?,
                ));
            }
            other if !other.starts_with('-') && input.is_none() => {
                input = Some(PathBuf::from(other));
            }
            other => {
                eprintln!("unknown decrypt option: {other}");
                print_decrypt_help();
                std::process::exit(2);
            }
        }
    }
    let input = input.context("decrypt requires <file.dlpenc>")?;
    let envelope_bytes =
        std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
    let envelope_name = input
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| input.display().to_string());

    let keyring = load_decrypt_keyring(cfg, storage);
    let agent_id = storage
        .load_meta()
        .map(|m| m.agent_id)
        .unwrap_or_else(|_| "unenrolled".to_string());

    // Audit sink: post over mTLS when enrolled; on post failure (or when
    // unenrolled) queue on disk, bounded — same wire/queue path as every other
    // channel. Errors ONLY when both fail; decrypt_envelope then refuses to
    // write the plaintext (no un-audited decrypt, fail secure).
    let queue = usb::queue::IncidentQueue::new(&cfg.state_dir);
    let audit = |inc: &UsbIncident| -> Result<()> {
        let body = usb_incident_body(inc).context("serializing decrypt incident")?;
        if storage.has_identity() {
            match post_incident_body(cfg, storage, &body) {
                Ok(id) => {
                    tracing::info!(incident_id = %id, kind = ?inc.kind, "decrypt incident reported");
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(error = %e, "decrypt incident post failed — queuing locally")
                }
            }
        }
        queue.enqueue(&body).context("queuing decrypt incident locally")
    };

    // Writer: default output name comes from the AUTHENTICATED header — name
    // component only (never a path from the envelope, even an authenticated
    // one), beside the input; refuses to overwrite unless -o chose the target.
    let written: std::cell::RefCell<Option<PathBuf>> = std::cell::RefCell::new(None);
    let write = |header: &crypto::EnvelopeHeader, plaintext: &[u8]| -> Result<()> {
        let out_path = match &output {
            Some(p) => p.clone(),
            None => {
                let name = std::path::Path::new(&header.orig_name)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| {
                        envelope_name.trim_end_matches(".dlpenc").to_string()
                    });
                let candidate = input
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_default()
                    .join(name);
                if candidate.exists() {
                    anyhow::bail!(
                        "refusing to overwrite {} (pass -o to choose a destination)",
                        candidate.display()
                    );
                }
                candidate
            }
        };
        std::fs::write(&out_path, plaintext)
            .with_context(|| format!("writing {}", out_path.display()))?;
        *written.borrow_mut() = Some(out_path);
        Ok(())
    };

    match decrypt::decrypt_envelope(
        &envelope_bytes,
        &envelope_name,
        &keyring,
        &agent_id,
        audit,
        write,
    ) {
        Ok(summary) => {
            let out = written.borrow();
            println!(
                "decrypted:  {}",
                out.as_ref().map(|p| p.display().to_string()).unwrap_or_default()
            );
            println!("orig name:  {}", summary.header.orig_name);
            println!("key id:     {}", summary.header.key_id);
            println!("sealed by:  {} (unix {})", summary.header.origin_agent, summary.header.created_unix);
            println!("sha256:     {}", summary.plaintext_sha256);
            println!("size:       {} bytes", summary.plaintext_len);
            Ok(())
        }
        // Typed failure → non-zero exit via main's error path. Any
        // DecryptDenied incident was already recorded/queued.
        Err(e) => Err(anyhow::Error::new(e)
            .context(format!("decrypt of {} failed", input.display()))),
    }
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
    println!("dlp-agent <enroll|once|run|status|index-update|scan|usb-monitor|usb-guard|clipboard-monitor|net-monitor|browser-host|decrypt|run-endpoint|install-service|uninstall-service>");
    println!("  scan --bundle <path> --file <path> [--json] [--report --channel <name>]");
    println!("  decrypt <file.dlpenc> [-o <out>]   open a sealed envelope; audited (see --help)");
    println!("  usb-monitor [--enforce]   watch removable media; audit copies (see --help)");
    println!("  usb-guard                 answer the kernel minifilter's scan port (see --help)");
    println!("  run-endpoint              unified supervised guard+sealer+check-in+resync (Windows)");
    println!("  install-service           register the Windows service 'DLPAgent' (run-endpoint)");
    println!("  uninstall-service         stop + remove the Windows service 'DLPAgent'");
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

fn print_decrypt_help() {
    println!("dlp-agent decrypt <file.dlpenc> [-o <out>]");
    println!("  Opens a `.dlpenc` envelope sealed by this organisation (encrypt-on-write,");
    println!("  trusted-destination encryption) using the locally cached keyring — OFFLINE");
    println!("  by design: no server round-trip. Keys come from the DPAPI-sealed keyring at");
    println!("  rest (machine scope), or in dev from [crypto] keyfile (plaintext, dev only;");
    println!("  loading it refreshes the sealed cache).");
    println!("  The audit incident (channel \"decrypt\": key id, plaintext hash, agent id,");
    println!("  outcome) is recorded BEFORE the plaintext is written — posted over mTLS when");
    println!("  enrolled, else queued locally (bounded). If it can be neither posted nor");
    println!("  queued, NOTHING is written (fail secure: no un-audited decrypt).");
    println!("  An unknown or crypto-shredded (destroyed) key id is refused: DecryptDenied");
    println!("  incident + non-zero exit, nothing written. Old/foreign sealed media showing");
    println!("  up here is signal, not noise.");
    println!("  -o, --output <out>  write the plaintext to <out> (may overwrite). Default:");
    println!("                      the authenticated original name beside the input file;");
    println!("                      refuses to overwrite an existing file without -o.");
    println!("  Incidents and output carry hashes/ids/metadata only — never key material.");
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
