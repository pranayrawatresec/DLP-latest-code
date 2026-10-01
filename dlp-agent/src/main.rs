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
//!   dlp-agent scan          score one file with BOTH signals (fingerprint + model)
//!   dlp-agent classify      run ONLY the ONNX document classifier on a file/text
//!   dlp-agent ml-status     model/policy/cache/queue/discovery coverage report
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
    bluetooth, browser_host, clipboard, clippolicy, config, crypto, decrypt, detect, exfil,
    livebundle, ml, mlpolicy, netfilter, notify, readdenypolicy, storage, supervise, trustdest,
    trustedreaders, trustsync, usb, usersession,
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


/// Make a dying agent say WHY, in the agent log, before it goes.
///
/// Rust's default panic handler writes to stderr. Under the SCM there is no
/// stderr, so a panicking worker left EXACTLY nothing behind: the log simply
/// stopped mid-line, the SCM reported "terminated unexpectedly", and Windows
/// Error Reporting offered a hex bucket. Diagnosing the watcher's overlapped-I/O
/// corruption from that cost a day of guessing, which is a day too many for a
/// product that runs unattended on other people's machines.
///
/// So every panic is routed through `tracing` — the same rolling file every other
/// event goes to — with its message and source location. A panic that a
/// supervised worker catches is logged twice (here and by the supervisor) and
/// that is the right trade: the duplicate is cheap, the silence was not.
///
/// This cannot catch a stack-buffer-overrun abort (`__fastfail`, 0xC0000409) —
/// the kernel kills the process without unwinding — so it is only half the
/// answer. The other half is not corrupting memory in the first place; see the
/// OVERLAPPED lifetime rules in `ml::watch::run_scope`.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown>".to_string());
        // The payload is a message the code chose, never file content — the
        // ml/ modules never put document text in a panic.
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic payload>".to_string());
        let thread = std::thread::current();
        tracing::error!(
            thread = thread.name().unwrap_or("<unnamed>"),
            location = %location,
            message = %message,
            "PANIC — a worker died; see the location above"
        );
        previous(info);
    }));
}

fn main() {
    install_panic_hook();
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

    // `ml-status --json` is meant to be parsed by fleet tooling, and tracing's
    // default writer is STDOUT: loading the graph logs one INFO line, which would
    // land in front of the JSON document and break every parser. That one
    // invocation logs to stderr instead; every other mode keeps today's console
    // logging byte for byte.
    if mode == "ml-status" && std::env::args().any(|a| a == "--json") {
        tracing_subscriber::fmt()
            .with_target(false)
            .with_max_level(tracing::Level::INFO)
            .with_writer(std::io::stderr)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_target(false)
            .with_max_level(tracing::Level::INFO)
            .init();
    }

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
    if mode == "classify" && args.iter().any(|a| a == "-h" || a == "--help") {
        print_classify_help();
        return Ok(());
    }
    if mode == "ml-status" && args.iter().any(|a| a == "-h" || a == "--help") {
        print_ml_status_help();
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
        "classify" => cmd_classify(&cfg, &args)?,
        "ml-status" => cmd_ml_status(&cfg, &storage, &args)?,
        "usb-monitor" => cmd_usb_monitor(&cfg, &storage, &args)?,
        "usb-guard" => cmd_usb_guard(&cfg, &storage, &args)?,
        "clipboard-monitor" => cmd_clipboard_monitor(&cfg, &storage, &args)?,
        "clipboard-agent" => cmd_clipboard_agent(&cfg, &storage)?,
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

/// scan: THE demo surface — one command that shows BOTH detection signals on one
/// file and says whether the endpoint would treat it as sensitive.
///
/// Fingerprinting (IDM/EDM, needs a signed bundle) and the ONNX document
/// classifier (needs the model artifacts + a live ML policy) are independent and
/// either may be absent, so both halves are OPTIONAL here:
///   * no `--bundle` ⇒ nothing is registered yet on this box; the model still
///     runs and the fingerprint half prints "no bundle loaded". That is the
///     order a site actually installs in — the classifier works on day one,
///     before a single document has been indexed.
///   * `--no-ml` (or an inert console policy, or a missing model) ⇒ the
///     fingerprint verdict prints exactly as it always did.
///
/// The final VERDICT line is `detect::decide()` — the same fusion every channel
/// enforces with — so what this prints is what the endpoint would do, not a
/// second opinion computed for the demo.
///
/// Exit code 0 whenever the scan executes — an unreadable file is a valid
/// verdict, not an error. `--exit-code` opts in to 1 on SENSITIVE for scripting.
fn cmd_scan(cfg: &Config, storage: &Storage, args: &[String]) -> Result<()> {
    let mut bundle_path: Option<String> = None;
    let mut file_path: Option<String> = None;
    let mut json = false;
    let mut report = false;
    let mut channel: Option<String> = None;
    let mut no_ml = false;
    let mut ml_labels: Option<String> = None;
    let mut ml_min_confidence: Option<f64> = None;
    let mut exit_code = false;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--bundle" => bundle_path = it.next().cloned(),
            "--file" => file_path = it.next().cloned(),
            "--json" => json = true,
            "--report" => report = true,
            "--channel" => channel = it.next().cloned(),
            "--no-ml" => no_ml = true,
            "--ml-labels" => ml_labels = it.next().cloned(),
            "--ml-min-confidence" => {
                let raw = it.next().context("--ml-min-confidence needs a value")?;
                ml_min_confidence = Some(parse_confidence(raw, "--ml-min-confidence")?);
            }
            "--exit-code" => exit_code = true,
            other => {
                eprintln!("unknown scan option: {other}");
                print_scan_help();
                std::process::exit(2);
            }
        }
    }
    let file_path = file_path.context("scan requires --file <path>")?;

    // The fingerprint half. Absent bundle = absent signal, NOT an error: the
    // verdict then carries no IDM/EDM matches, which is precisely what the
    // fusion sees on a site that has registered nothing yet.
    let bundle = match &bundle_path {
        Some(p) => {
            let ca_pem = load_ca(cfg, storage)?;
            let bundle_bytes =
                std::fs::read(p).with_context(|| format!("reading bundle {p}"))?;
            Some(detect::Bundle::load(&bundle_bytes, &ca_pem).context("loading index bundle")?)
        }
        None => None,
    };

    // Read the file ONCE and score both signals from the same bytes: two reads
    // could disagree (a file edited mid-scan) and the demo must show one file.
    let path = Path::new(&file_path);
    let content = std::fs::read(path).with_context(|| format!("reading {file_path}"))?;
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| file_path.clone());

    let mut verdict = match &bundle {
        Some(b) => detect::verdict_bytes(&content, &file_name, b),
        None => verdict_without_bundle(&content, &file_name),
    };

    // The classifier half. `ml_note` explains a MISSING `ml` block to the
    // operator; it is CLI text only and never reaches the wire — a verdict with
    // no `ml` field serializes byte-for-byte as a pre-model one.
    let ml_override = ml_labels.is_some() || ml_min_confidence.is_some();
    let ml_note: Option<String> = if no_ml {
        Some("suppressed (--no-ml)".into())
    } else if !cfg.ml.enabled {
        Some("off — [ml] enabled = false in the agent config (local kill switch)".into())
    } else {
        let policy = scan_ml_policy(storage, ml_labels.as_deref(), ml_min_confidence)?;
        mlpolicy::set_active(policy);
        if mlpolicy::enabled() {
            // Loading the graph costs hundreds of milliseconds and ~300 MB, so
            // it happens only once the policy says the answer would be used.
            match load_ml_engine(cfg) {
                Ok(_) => {}
                // An operator who asked for ML explicitly gets the error; an
                // implicitly-classified scan keeps its fingerprint verdict and
                // reports the model as `unavailable`, which is exactly what the
                // endpoint does (the channels then weigh `failBlock`).
                Err(e) if ml_override => return Err(e),
                Err(e) => eprintln!("{e:#}"),
            }
            verdict.ml = detect::decide::ml_for_bytes(&content, &file_name);
            None
        } else {
            Some(
                "inert — the console ML policy is off or has no labels selected \
                 (use --ml-labels for a local demo override)"
                    .into(),
            )
        }
    };

    // The bands the kernel read-scan applies. Stated once here so the printed
    // VERDICT is the decision an enforcing channel would reach, not a new one.
    let bands = detect::Bands::new(cfg.kguard.block_at, cfg.kguard.coverage_block_at);
    let decision = detect::decide(&verdict, &bands);

    if json {
        // The whole verdict, `ml` block included — it already serializes.
        println!("{}", serde_json::to_string_pretty(&verdict)?);
    } else {
        print_verdict(&verdict, bundle.as_ref(), &bands, &decision, ml_note.as_deref());
    }

    if report {
        let channel = channel.context("--report requires --channel <name>")?;
        report_incident(cfg, storage, &channel, &verdict)?;
    }

    // Opt-in only: the default stays 0 so existing scripts that treat a non-zero
    // exit as "the scan broke" keep working.
    if exit_code && decision.sensitive {
        std::process::exit(1);
    }
    Ok(())
}

/// A confidence typed on the command line. Bounded because a threshold outside
/// `0.0..=1.0` is not a stricter policy, it is a policy that can never fire (or
/// always fires) — better refused than silently obeyed.
fn parse_confidence(raw: &str, flag: &str) -> Result<f64> {
    let value: f64 = raw
        .parse()
        .with_context(|| format!("{flag} {raw:?} is not a number"))?;
    anyhow::ensure!(
        value.is_finite() && (0.0..=1.0).contains(&value),
        "{flag} must be a probability in 0.0..=1.0 (got {raw})"
    );
    Ok(value)
}

/// The fingerprint-free half of a verdict: file hash + extraction status, with
/// no IDM/EDM matching because there is no bundle to match against.
///
/// `detect::verdict_bytes` is FROZEN (golden vectors gate it byte-for-byte) and
/// requires a bundle, so the no-bundle demo path builds the same shape here. The
/// empty `idm`/`edm` are not a placeholder — they are the truth on a site that
/// has registered nothing, and the fusion reads them as "no fingerprint signal".
fn verdict_without_bundle(content: &[u8], file_name: &str) -> detect::Verdict {
    use sha2::Digest as _;
    use std::fmt::Write as _;

    let mut file_sha256 = String::with_capacity(64);
    for byte in sha2::Sha256::digest(content) {
        let _ = write!(file_sha256, "{byte:02x}");
    }
    let extraction = match detect::extract_text(content, file_name) {
        Ok(e) => detect::Extraction::Ok { format: e.format },
        Err(unreadable) => detect::Extraction::Unreadable {
            reason: unreadable.reason.code().into(),
        },
    };
    detect::Verdict {
        file_name: file_name.to_string(),
        file_sha256,
        extraction,
        idm: Vec::new(),
        edm: Vec::new(),
        ml: None,
    }
}

/// The ML policy this ONE invocation classifies under: the last-synced console
/// policy from disk, optionally overridden by `--ml-labels` /
/// `--ml-min-confidence`.
///
/// The overrides live in memory for this process only and are NEVER written back
/// to the cache. Policy is the console's to set — an endpoint that could widen
/// its own detection would break the split of authority `mlpolicy` exists to
/// keep — so this is strictly a demo/test affordance for a machine that has not
/// enrolled and therefore has no policy to sync.
fn scan_ml_policy(
    storage: &Storage,
    labels: Option<&str>,
    min_confidence: Option<f64>,
) -> Result<mlpolicy::MlPolicy> {
    let mut policy = checkin::load_ml_policy(storage);

    if let Some(list) = labels {
        let mut rules: Vec<mlpolicy::MlLabelRule> = Vec::new();
        for id in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            // Resolve through the frozen taxonomy so a typo is refused here
            // rather than becoming a label that can never match.
            let (_, label) = ml::labels::by_id(id).with_context(|| {
                format!(
                    "--ml-labels: unknown label id {id:?} — ids are the frozen three-letter \
                     taxonomy codes (ADM STU TCH GOV INS OPS FIN EXM COM POL ANA PUB OOD PER \
                     INT WPN AVI NAV SIG CYB SPC LOG ACQ DIP TRN MNT MED LEG NUC)"
                )
            })?;
            rules.push(mlpolicy::MlLabelRule {
                id: label.id.to_string(),
                min_confidence: None,
            });
        }
        anyhow::ensure!(!rules.is_empty(), "--ml-labels needs at least one label id");
        policy.labels = rules;
        // Selecting labels on the command line implies "classify with them now";
        // without this a demo box with no synced policy stays inert.
        policy.enabled = true;
    }

    if let Some(value) = min_confidence {
        policy.min_confidence = value;
        // A per-label override from the console would silently outrank the value
        // just typed, so clear them: this flag means "this confidence, for every
        // selected label, for this invocation".
        for rule in &mut policy.labels {
            rule.min_confidence = None;
        }
    }

    Ok(policy)
}

/// Where the classifier's artifacts live, translated from the agent's `[ml]`
/// section into the engine's config.
///
/// The sidecar is deliberately NOT configurable: `ml::engine::load` reads the
/// label space, the chunk geometry and the model version from `model.onnx.json`
/// BESIDE the weights, so the two can never drift into a graph being read with
/// another model's labels. `dylib: None` lets the engine resolve ONNX Runtime in
/// its documented order (`<ml root>\runtime\`, then `ORT_DYLIB_PATH`, then the
/// OS loader path).
fn ml_engine_config(cfg: &Config) -> ml::MlConfig {
    let mut sidecar = cfg.ml.model_path.clone().into_os_string();
    sidecar.push(".json");
    ml::MlConfig {
        model: cfg.ml.model_path.clone(),
        sidecar: PathBuf::from(sidecar),
        tokenizer: cfg.ml.tokenizer_path.clone(),
        dylib: None,
        intra_threads: cfg.ml.intra_threads,
        // Both are checked/applied by the engine: `max_chars` must agree with the
        // sidecar (a lower bound would silently shorten documents), `max_chunks`
        // caps inference cost and marks the result when it bites.
        max_chars: cfg.ml.max_chars,
        max_chunks: cfg.ml.max_chunks,
        // The memory dial: how many chunks the encoder holds at once when the
        // split graphs are staged. Ignored by the monolithic graph.
        micro_batch_size: cfg.ml.micro_batch_size,
    }
}

/// Load the classifier for a one-shot CLI command and publish it process-wide.
///
/// Missing artifacts are a configuration mistake an operator can fix, so they get
/// a message naming every expected path — never a panic and never a bare
/// "unavailable". `ml::engine` itself already refuses to panic on a missing ONNX
/// Runtime; this only turns its error into something actionable at a terminal.
fn load_ml_engine(cfg: &Config) -> Result<Arc<ml::MlEngine>> {
    let engine_cfg = ml_engine_config(cfg);

    let missing: Vec<String> = [&engine_cfg.model, &engine_cfg.sidecar, &engine_cfg.tokenizer]
        .iter()
        .filter(|p| !p.is_file())
        .map(|p| p.display().to_string())
        .collect();
    if !missing.is_empty() {
        anyhow::bail!(
            "the ML classifier is not installed on this machine — missing:\n  {}\n\
             Expected: the ONNX graph, its sidecar (the same path + \".json\") and the matching\n\
             tokenizer.json. Point the agent at them with the [ml] section of {} — e.g.\n\
             [ml]\n  model_path = \"...\\\\Document_classification\\\\model\\\\model.onnx\"\n  \
             tokenizer_path = \"...\\\\Document_classification\\\\backbone\\\\tokenizer.json\"",
            missing.join("\n  "),
            config_path_hint()
        );
    }

    let engine = ml::load(&engine_cfg).map_err(|e| {
        anyhow::anyhow!(
            "{e}\n  model:     {}\n  tokenizer: {}\n  \
             ONNX Runtime is resolved from <ml root>\\runtime\\onnxruntime.dll, then $ORT_DYLIB_PATH,\n  \
             then the OS loader path (see the build recipe at the top of src/ml/engine.rs).",
            engine_cfg.model.display(),
            engine_cfg.tokenizer.display()
        )
    })?;
    ml::set_active(engine.clone());
    Ok(engine)
}

/// WHICH PARTS of the ML pipeline a process is responsible for.
///
/// The pipeline has three off-path producers (creation watcher, at-rest walker,
/// on-demand queue) and one consumer (the kernel READ up-call's cache lookup),
/// and the agent is several processes. Handing every process the same set would
/// be a bug, not a simplification — TWO PROCESSES SWEEPING THE SAME DISK is the
/// clearest example: `run-endpoint` and a hand-started `usb-guard` would each
/// walk `C:\Users` at their own rate limit, doubling the load the throttle exists
/// to bound, while producing exactly the same cache entries.
///
/// | process | cache | queue worker | watcher + walker | why |
/// |---|---|---|---|---|
/// | `run-endpoint` | yes | yes | **yes** | the long-lived service; the only process guaranteed to outlive a sweep, and the only one the SCM restarts |
/// | `usb-guard` | yes | yes | no | it runs the kguard message loop, so it is where read-path misses happen and where the self-heal must live; it is also an operator's debugging tool that may be started and killed at will, which is precisely what a multi-hour sweep must not be attached to |
/// | `clipboard-agent`, `browser-host` | yes | no | no | short-lived per-session helpers over stdio/WTS. They never see a kernel up-call, so they need the cache only to READ what other producers deposited. Starting a worker per logon would put N inference threads on one PC |
///
/// The cache handle itself is safe to open in every one of them: it is an
/// append-only log plus an in-memory map, and the record HMAC is what makes a
/// concurrent writer's records verifiable rather than trusted.
#[derive(Clone)]
enum MlPipelineRole {
    /// The service: everything, supervised, until `stop` is set.
    Service { stop: Arc<std::sync::atomic::AtomicBool> },
    /// The kernel guard: cache + on-demand worker, no sweepers.
    Guard,
    /// A short-lived helper: publish the cache for lookups, start nothing.
    LookupOnly,
}

/// The watcher and the walker are started at most once per process. They are
/// long-lived and scope-bound; a second start would double every notification
/// and every sweep. `activate_ml` runs on EVERY resync cycle, so this is what
/// keeps it idempotent.
static ML_SWEEPERS_STARTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Publish the ML policy AND the classifier AND the coverage pipeline for an
/// ENFORCING process.
///
/// THE HALVES MUST BE WIRED TOGETHER — that is why this is one function and
/// not two calls at each site. A live policy with no loaded engine makes every
/// `ml::classify` return [`ml::MlError::NotLoaded`] → `status = "unavailable"`,
/// and `decide::ml_blocks_egress` then honours `fail_block` (default TRUE)
/// regardless of `action = "audit"`. So publishing the policy alone does not
/// leave ML merely inert: it blocks every USB write, clipboard copy and browser
/// upload on the machine. Fail-secure is the right behaviour for a model that
/// genuinely broke; reaching it because nobody loaded the graph is an outage.
///
/// Idempotent, because the resync worker calls it on every cycle: an already
/// published engine is left alone rather than reloaded (~300 MB, hundreds of ms),
/// a policy that has just gone inert drops the engine so a disabled feature does
/// not stay resident on an employee's PC, and the pipeline's threads are started
/// once and then left alone.
///
/// INERT ⇒ NOTHING AT ALL (contract F3). An inert policy returns before the cache
/// is even opened, so an endpoint whose console has not selected a single label
/// behaves byte-for-byte like the agent that predates this feature: no cache
/// file, no threads, no disk traffic. That is what makes the whole thing safe to
/// deploy ahead of the console change that enables it.
fn activate_ml(cfg: &Config, policy: mlpolicy::MlPolicy, role: MlPipelineRole) {
    let inert = policy.is_inert();
    // `denyUnclassified` (contract P2) rides the same policy and must be
    // published with it: `decide::deny_unclassified()` re-checks that the policy
    // is live and that the on-demand worker is running, so publishing it here
    // while the pipeline is still down cannot deny anything.
    let deny_unclassified = policy.deny_unclassified;
    mlpolicy::set_active(policy);
    detect::decide::set_deny_unclassified(deny_unclassified);
    // A machine swept in a PREVIOUS run is still covered — re-arm the interlock
    // from the persisted completion record so a service restart does not silently
    // disarm `denyUnclassified` on an endpoint that has already been classified.
    //
    // MUST be version-aware. A completion record only proves coverage under the
    // MODEL that produced it (`SweepCompletion::covers_model`) — the record
    // itself is correct and `ml-status`/check-in already check it, but this
    // call used to arm on existence alone. After a model upgrade that let
    // `denyUnclassified` enforce a fail-secure deny against coverage the new
    // model never produced. `model_version_for_cache()` is the same authority
    // `finish_sweep` stamps into a fresh completion record: the loaded engine's
    // version when one is live, else the just-published policy's declared
    // version — exactly what this endpoint is about to run classification
    // under.
    let sweep_covers_current_model = ml::walk::load_completion(&cfg.state_dir)
        .is_some_and(|c| c.covers_model(&ml::queue::model_version_for_cache()));
    detect::decide::set_sweep_completed(sweep_covers_current_model);

    // `[ml] enabled = false` is the LOCAL kill switch — it beats the console.
    if !cfg.ml.enabled || inert {
        if ml::active().is_some() {
            tracing::info!(
                local_kill_switch = !cfg.ml.enabled,
                "ML classification no longer live — unloading the classifier"
            );
            ml::unload();
        }
        // The pipeline threads (if any started earlier in this process's life)
        // are left parked rather than torn down: `walk::run` and the watcher both
        // check `mlpolicy::active().is_inert()` and do nothing while it holds, so
        // a parked producer costs a 250 ms poll and nothing else — and a console
        // that turns the feature back on then takes effect without a restart.
        return;
    }

    if ml::active().is_none() {
        match load_ml_engine(cfg) {
            Ok(engine) => tracing::info!(
                model_version = %engine.model_version(),
                "ML classifier loaded — document classification is live on this endpoint"
            ),
            // Loading failed with a live policy. Do NOT bail: the channels' own
            // `unavailable` + `fail_block` handling is exactly the fail-secure path
            // for a broken model, and it is now reached for the real reason.
            Err(e) => tracing::warn!(
                error = %e,
                "ML policy is live but the classifier could not be loaded — \
                 classification reports `unavailable` and egress paths weigh failBlock"
            ),
        }
    }

    // No graph ⇒ no pipeline. Every producer's job ends in `ml::classify`, so
    // without an engine they would read files, extract text and enqueue work only
    // to record a failure — and per contract F2 a failed classification writes no
    // cache entry, so the whole exercise would be pure I/O. The next resync
    // retries the load and starts the pipeline then.
    if ml::active().is_none() {
        return;
    }
    activate_ml_pipeline(cfg, role);
}

/// Open the process-wide verdict cache and start whichever producers this
/// process owns. Safe to call repeatedly; see [`MlPipelineRole`] for the split.
fn activate_ml_pipeline(cfg: &Config, role: MlPipelineRole) {
    // (1) THE CACHE — one open per process, retried on the next resync if it
    // fails. A failure here is not fatal anywhere: with no cache published, every
    // lookup misses, a miss is never "not sensitive" (F1), and every path
    // degrades to exactly its pre-cache behaviour.
    let cache = match ml::queue::verdict_cache() {
        Some(c) => c,
        None => match ml::cache::VerdictCache::open(&cfg.state_dir, cfg.ml.cache_max_entries) {
            Ok(c) => {
                let c = Arc::new(c);
                ml::queue::set_verdict_cache(Some(c.clone()));
                tracing::info!(
                    entries = c.len(),
                    max_entries = cfg.ml.cache_max_entries,
                    "ML verdict cache opened"
                );
                c
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not open the ML verdict cache — the read path stays fingerprint-only"
                );
                return;
            }
        },
    };

    // (2) THE ON-DEMAND WORKER. Not for the per-session helpers: they never see a
    // kernel up-call, so they have nothing to enqueue, and one inference thread
    // per logged-on user is a cost with no counterpart.
    let stop = match &role {
        MlPipelineRole::LookupOnly => return,
        MlPipelineRole::Guard => None,
        MlPipelineRole::Service { stop } => Some(stop.clone()),
    };
    if !ml::queue::running() {
        ml::queue::start(cache, cfg.ml.queue_capacity, stop);
    }

    // (3) THE SWEEPERS — service only, once.
    let MlPipelineRole::Service { stop } = role else {
        return;
    };
    if ML_SWEEPERS_STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    start_ml_sweepers(cfg, stop);
}

/// Start the at-creation watcher and the at-rest walker for the service.
///
/// SCOPES ARE READ ONCE, HERE. They come from [`Config::ml_scopes`], i.e. from
/// the read-deny watch-set the console pushed down, and the threads are bound to
/// them for the life of the process. A later console change to `watchPaths`
/// therefore takes effect on the next service restart, not on the next resync —
/// stated plainly because the alternative (tearing down and rebuilding directory
/// watches mid-sweep) buys very little for a value that changes about once per
/// deployment.
#[cfg(windows)]
fn start_ml_sweepers(cfg: &Config, stop: Arc<std::sync::atomic::AtomicBool>) {
    let scopes = cfg.ml_scopes();
    if scopes.is_empty() {
        tracing::warn!("ML pipeline: no scopes to cover — the watcher and walker will not start");
        return;
    }
    for s in &scopes {
        if s.parent().is_none() {
            // A whole-volume scope. Legal, and the per-file filter still excludes
            // Windows/Program Files/temp/build/cache trees, but it is almost
            // always a `watch_paths = ["\\"]` that was meant to be `"\\Users"`.
            tracing::warn!(
                "ML pipeline: a scope covers an entire volume — expect heavy \
                 notification churn; set [ml] scopes to narrow it"
            );
        }
    }
    // Scope COUNT, never the paths, at info level (house rule).
    tracing::info!(
        scopes = scopes.len(),
        watch = cfg.ml.watch_enabled,
        walk = cfg.ml.walk_enabled,
        "ML coverage pipeline starting"
    );

    // One filter for both producers: same size bound, same exclusions. The agent
    // state dir must be excluded (the verdict log lives there, has a supported
    // extension, and classifying it would make every `put()` notify the watcher —
    // a livelock); the model directory is excluded for the same reason applied to
    // `tokenizer.json`, which is a large JSON file nobody wants classified.
    let mut filter = ml::filter::FilterConfig::with_state_dir(&cfg.state_dir);
    filter.max_file_bytes = cfg.ml.max_file_bytes;
    if let Some(model_dir) = cfg.ml.model_path.parent() {
        filter.exclude_prefix(model_dir);
    }

    // The watcher is built even when disabled-by-config is false, because the
    // walker shares its overflow flags: a scope whose notification buffer
    // overflowed is a scope the walker must re-sweep, and that link is the only
    // thing that keeps "the watcher covers everything the user touches" true
    // across a burst.
    let watcher = ml::watch::CreationWatcher::with_shared_queue(ml::watch::WatchConfig {
        scopes: scopes.clone(),
        filter: filter.clone(),
        ..Default::default()
    })
    .map(Arc::new);
    let Some(watcher) = watcher else {
        tracing::warn!("ML pipeline: no verdict cache published — sweepers not started");
        return;
    };

    if cfg.ml.watch_enabled {
        let w = watcher.clone();
        let s = stop.clone();
        // Detached like the guard thread: the workers honour `stop` and the
        // process exits on service stop, so there is nothing to join for.
        let _watch = supervised_thread("ml-watch", stop.clone(), Duration::from_secs(5), move || {
            // One thread per scope; this body owns them and returns when they do
            // (stop set), which is what lets the supervisor restart the whole set
            // after a panic in any one of them.
            for h in ml::watch::spawn(w.clone(), s.clone()) {
                let _ = h.join();
            }
        });
    }

    if cfg.ml.walk_enabled {
        let mut wcfg = ml::walk::WalkConfig::new(&cfg.state_dir, scopes);
        wcfg.filter = filter;
        // Document tier by default (see [ml] walk_scan_source_files): the
        // watcher above keeps the FULL SUPPORTED_EXTENSIONS set, only the
        // walker's proactive sweep is narrowed. This does not touch what gets
        // classified — only what the background sweep proactively spends its
        // rate-limited budget on before a document is ever touched.
        if !cfg.ml.walk_scan_source_files {
            wcfg.filter.extensions = ml::filter::DOCUMENT_EXTENSIONS;
        }
        wcfg.files_per_minute = cfg.ml.walk_files_per_minute;
        // 0 hours would mean "start the next full sweep the instant this one
        // finished", which is a config typo every time; keep the module default.
        if cfg.ml.walk_interval_hours > 0 {
            wcfg.rescan_interval_secs = cfg.ml.walk_interval_hours.saturating_mul(3_600);
        }
        let flags = watcher.sweep_flags();
        let Some(walker) = ml::walk::Walker::with_shared_queue(wcfg) else {
            tracing::warn!("ML pipeline: no verdict cache published — walker not started");
            return;
        };
        let walker = Arc::new(walker.with_sweep_flags(flags));
        let s = stop.clone();
        let _walk = supervised_thread("ml-walk", stop, Duration::from_secs(5), move || {
            ml::walk::run(walker.clone(), s.clone());
        });
    }
}

/// The sweepers are a Windows service feature: `run-endpoint` — the only role
/// that starts them — already refuses to run anywhere else.
#[cfg(not(windows))]
fn start_ml_sweepers(_cfg: &Config, _stop: Arc<std::sync::atomic::AtomicBool>) {}

/// The config file this process loaded — for error messages that tell an
/// operator WHICH file to edit.
fn config_path_hint() -> String {
    std::env::var("DLP_AGENT_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG.to_string())
}

// ---------------------------------------------------------------------------
// ml-status — "has this endpoint been covered yet?"
// ---------------------------------------------------------------------------

/// The append-only verdict log and its DPAPI-sealed HMAC key, by name.
///
/// RESTATED HERE ON PURPOSE. `ml::cache` keeps these private because nothing
/// inside the agent addresses them by name — every producer and the read path go
/// through `VerdictCache`. This command is the one caller that must look at the
/// files WITHOUT opening the live cache (see [`ml_cache_report`]), so it names
/// them; if they are ever renamed, the report degrades to "no cache on disk",
/// which is a wrong answer in the safe direction (it never claims coverage).
const ML_CACHE_LOG_FILE: &str = "ml-verdicts.log";
const ML_CACHE_KEY_FILE: &str = "ml-cache.key";
/// Replaying a copy of the log costs a copy of the log. Past this size, report
/// the file's size and stop, rather than duplicating hundreds of MB to answer a
/// status question.
const ML_CACHE_REPLAY_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// What this process can honestly say about the verdict cache.
struct MlCacheReport {
    /// `"in-process"` (the cache this process owns), `"disk-replay"` (a copy of
    /// the on-disk log, replayed here) or `"none"`.
    source: &'static str,
    entries: Option<usize>,
    hmac_failures: Option<u64>,
    bytes_on_disk: u64,
    /// Hit/miss/eviction counters. **Only ever `Some` for an in-process cache**:
    /// they are process-lifetime counters that live in memory, so a CLI that
    /// just started has no business printing its own zeroes next to a service
    /// that has served millions of lookups.
    live: Option<ml::CacheStats>,
    note: Option<String>,
}

/// Read the verdict cache's facts WITHOUT TOUCHING THE LIVE ONE.
///
/// `VerdictCache::open` is a read-write operation: it opens the log for append,
/// truncates a torn tail, and — if the sealed HMAC key cannot be read — mints a
/// new key and DELETES the log as unverifiable. Every one of those is correct
/// for the process that owns the cache and unacceptable for a status command
/// that may be run by an operator, at any moment, while the service is mid-write.
///
/// So this copies the log and the key into a temp directory and replays THAT.
/// The copy is a plain read of both files: a status command cannot truncate,
/// compact or re-key the endpoint's durability log, whatever it finds inside.
/// Cost is one file copy, bounded by [`ML_CACHE_REPLAY_MAX_BYTES`].
fn ml_cache_report(cfg: &Config) -> MlCacheReport {
    // The process that owns the cache reads it directly — no copy, and the live
    // counters are real. (Not reachable from the CLI; it keeps one code path for
    // a future `ml-status` served from inside the service.)
    if let Some(c) = ml::queue::verdict_cache() {
        let s = c.stats();
        return MlCacheReport {
            source: "in-process",
            entries: Some(s.entries),
            hmac_failures: Some(s.hmac_failures),
            bytes_on_disk: s.bytes_on_disk,
            live: Some(s),
            note: None,
        };
    }

    let none = |note: &str| MlCacheReport {
        source: "none",
        entries: None,
        hmac_failures: None,
        bytes_on_disk: 0,
        live: None,
        note: Some(note.to_string()),
    };

    let log = cfg.state_dir.join(ML_CACHE_LOG_FILE);
    let key = cfg.state_dir.join(ML_CACHE_KEY_FILE);
    if !log.is_file() {
        return none("no verdict log in the state directory — nothing has classified anything on this endpoint yet");
    }
    let bytes_on_disk = std::fs::metadata(&log).map(|m| m.len()).unwrap_or(0);
    let partial = |note: String| MlCacheReport {
        source: "none",
        entries: None,
        hmac_failures: None,
        bytes_on_disk,
        live: None,
        note: Some(note),
    };
    if !key.is_file() {
        return partial(
            "the sealed HMAC key is missing — entries cannot be verified, so they cannot be counted".into(),
        );
    }
    if bytes_on_disk > ML_CACHE_REPLAY_MAX_BYTES {
        return partial(format!(
            "verdict log is larger than {} MiB — not replayed for a status report",
            ML_CACHE_REPLAY_MAX_BYTES / (1024 * 1024)
        ));
    }

    let tmp = std::env::temp_dir().join(format!("dlp-ml-status-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let replay = (|| -> Result<ml::CacheStats> {
        std::fs::create_dir_all(&tmp)?;
        std::fs::copy(&log, tmp.join(ML_CACHE_LOG_FILE))?;
        std::fs::copy(&key, tmp.join(ML_CACHE_KEY_FILE))?;
        // The configured cap is applied to the copy exactly as the service
        // applies it, so `entries` is what this endpoint would actually hold —
        // not how many records the log happens to contain.
        let c = ml::cache::VerdictCache::open(&tmp, cfg.ml.cache_max_entries)?;
        Ok(c.stats())
    })();
    let _ = std::fs::remove_dir_all(&tmp);

    match replay {
        Ok(s) => MlCacheReport {
            source: "disk-replay",
            entries: Some(s.entries),
            hmac_failures: Some(s.hmac_failures),
            bytes_on_disk,
            live: None,
            note: None,
        },
        Err(e) => partial(format!("verdict log could not be replayed: {e:#}")),
    }
}

/// ml-status: **the pre-flight check for `denyUnclassified`.**
///
/// Turning that flag on before the estate is covered denies the first read of
/// every legacy file on every endpoint — a fleet outage, not a control (see
/// `mlpolicy::MlPolicy::deny_unclassified`). The supported rollout is
/// deploy → sweep → VERIFY → enable, and this command is the verify step: it
/// prints what the model, the policy, the cache, the on-demand queue and the
/// at-rest walker each say on THIS box, and then answers the operator's actual
/// question in one closing sentence.
///
/// It reports; it never enforces and never classifies. The heaviest thing it
/// does is load the graph to confirm the endpoint can (skip with `--no-load`),
/// and replay a COPY of the verdict log (see [`ml_cache_report`]).
///
/// Two counters cannot be read from a terminal at all: the cache's hit/miss
/// ratio and the queue's depth live in the enforcing process's memory. Rather
/// than print a fresh process's zeroes as if they were the endpoint's, this says
/// where they are — and they ride the check-in to the console (`checkin::
/// MlCoverage`), which is where fleet-wide answers belong.
fn cmd_ml_status(cfg: &Config, storage: &Storage, args: &[String]) -> Result<()> {
    let mut json = false;
    let mut load = true;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--no-load" => load = false,
            other => {
                eprintln!("unknown ml-status option: {other}");
                print_ml_status_help();
                std::process::exit(2);
            }
        }
    }

    // The policy the endpoint is ENFORCING: the last one the console pushed,
    // persisted for offline fail-secure operation. Publishing it here is what
    // makes `model_version_for_cache()` and the coverage read agree with what the
    // service would do with the server unreachable.
    let policy = checkin::load_ml_policy(storage);
    mlpolicy::set_active(policy.clone());

    // --- model artifacts -----------------------------------------------------
    let engine_cfg = ml_engine_config(cfg);
    let artifacts = [
        ("graph", engine_cfg.model.clone()),
        ("sidecar", engine_cfg.sidecar.clone()),
        ("tokenizer", engine_cfg.tokenizer.clone()),
    ];
    let missing: Vec<&str> = artifacts
        .iter()
        .filter(|(_, p)| !p.is_file())
        .map(|(n, _)| *n)
        .collect();

    // Loading is the only way to answer "can this endpoint classify at all?" —
    // an installed graph with no ONNX Runtime beside it looks perfect on disk and
    // fails at the first document. It is also the only source of the model
    // version the cache is keyed against, so a `--no-load` run falls back to the
    // policy's declared version and says so.
    let mut load_error: Option<String> = None;
    if load && cfg.ml.enabled && missing.is_empty() {
        if let Err(e) = load_ml_engine(cfg) {
            load_error = Some(format!("{e:#}"));
        }
    }
    let engine = ml::active();
    let model_version = ml::queue::model_version_for_cache();

    // --- the rest of the pipeline -------------------------------------------
    let cache = ml_cache_report(cfg);
    let queue = ml::queue::running().then(ml::queue::stats);
    let completion = ml::walk::load_completion(&cfg.state_dir);
    let checkpoint = ml::walk::load_checkpoint(&cfg.state_dir);
    let scopes = cfg.ml_scopes();
    let covered = completion
        .as_ref()
        .is_some_and(|c| c.covers_model(&model_version));

    // --- the verdict ---------------------------------------------------------
    let (ready, coverage_line) = ml_coverage_verdict(
        cfg,
        &policy,
        engine.is_some(),
        load,
        &model_version,
        completion.as_ref(),
        checkpoint.is_some(),
    );

    if json {
        let out = serde_json::json!({
            "config": config_path_hint(),
            "stateDir": cfg.state_dir.display().to_string(),
            "model": {
                "localSwitch": cfg.ml.enabled,
                "loaded": engine.is_some(),
                "loadAttempted": load,
                "version": model_version,
                "versionSource": if engine.is_some() { "engine" } else { "policy" },
                "graph": engine_cfg.model.display().to_string(),
                "sidecar": engine_cfg.sidecar.display().to_string(),
                "tokenizer": engine_cfg.tokenizer.display().to_string(),
                "missing": missing,
                "loadError": load_error,
            },
            "policy": {
                "enabled": policy.enabled,
                "classesSelected": policy.labels.len(),
                "minConfidence": policy.min_confidence,
                "action": policy.action.to_string(),
                "failBlock": policy.fail_block,
                "denyUnclassified": policy.deny_unclassified,
                "modelVersion": policy.model_version,
                "inert": policy.is_inert(),
            },
            "cache": {
                "source": cache.source,
                "entries": cache.entries,
                "bytesOnDisk": cache.bytes_on_disk,
                "hmacFailures": cache.hmac_failures,
                "hits": cache.live.map(|s| s.hits),
                "misses": cache.live.map(|s| s.misses),
                "evictions": cache.live.map(|s| s.evictions),
                "note": cache.note,
            },
            "queue": match queue {
                Some(q) => serde_json::json!({
                    "running": true,
                    "capacity": q.capacity,
                    "depth": q.depth,
                    "queued": q.queued,
                    "processed": q.classified,
                    "failed": q.failed,
                    "unextractable": q.unextractable,
                    "dropped": q.dropped,
                    "deduped": q.deduped,
                    "readsDenied": q.deny_unclassified,
                }),
                None => serde_json::json!({
                    "running": false,
                    "capacity": cfg.ml.queue_capacity,
                }),
            },
            "discovery": {
                "watchEnabled": cfg.ml.watch_enabled,
                "walkEnabled": cfg.ml.walk_enabled,
                "filesPerMinute": cfg.ml.walk_files_per_minute,
                "scopes": scopes.len(),
                "sweepCompleted": completion.is_some(),
                "completedAt": completion.as_ref().map(|c| c.completed_at),
                "completedAtUtc": completion.as_ref().map(|c| unix_to_utc(c.completed_at)),
                "filesCovered": completion.as_ref().map(|c| c.files_covered()),
                "sweepModelVersion": completion.as_ref().map(|c| c.model_version.clone()),
                "coversCurrentModel": covered,
                "inProgress": checkpoint.is_some(),
                "inProgressCandidates": checkpoint.as_ref().map(|c| c.counts.candidates),
                "pendingDirs": checkpoint
                    .as_ref()
                    .map(|c| c.pending_dirs.len() as u64 + c.spill.count),
                "pendingDirsInMemory": checkpoint.as_ref().map(|c| c.pending_dirs.len()),
                "pendingDirsOnDisk": checkpoint.as_ref().map(|c| c.spill.count),
                // True only in degraded mode: the queue could not be persisted,
                // so a restart re-walks the current scope.
                "pendingTruncated": checkpoint.as_ref().map(|c| c.pending_truncated),
            },
            "readyForDenyUnclassified": ready,
            "coverage": coverage_line,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    println!("config:     {}", config_path_hint());
    println!("state dir:  {}", cfg.state_dir.display());
    println!();

    println!("model:");
    println!(
        "  local switch:   [ml] enabled = {}{}",
        cfg.ml.enabled,
        if cfg.ml.enabled { "" } else { "   (LOCAL KILL SWITCH — nothing classifies here)" }
    );
    for (name, path) in &artifacts {
        println!(
            "  {name:<15} {} {}",
            if path.is_file() { "[present]" } else { "[MISSING]" },
            path.display()
        );
    }
    match (&engine, load, &load_error) {
        (Some(e), _, _) => println!("  status:         loaded — model version {}", e.model_version()),
        (None, false, _) => println!(
            "  status:         not checked (--no-load); version below is the policy's, not the graph's"
        ),
        (None, true, Some(err)) => {
            println!("  status:         NOT LOADED");
            for line in err.lines() {
                println!("                  {line}");
            }
        }
        (None, true, None) if !cfg.ml.enabled => {
            println!("  status:         not loaded — [ml] enabled = false")
        }
        (None, true, None) => println!(
            "  status:         not loaded — artifacts missing: {}",
            missing.join(", ")
        ),
    }
    println!();

    println!("policy (last pushed by the console; enforced offline):");
    println!("  enabled:          {}", policy.enabled);
    println!(
        "  classes selected: {}{}",
        policy.labels.len(),
        if policy.labels.is_empty() { "   (none — the model can flag nothing)" } else { "" }
    );
    println!("  minConfidence:    {:.2}", policy.min_confidence);
    println!("  action:           {}", policy.action);
    println!("  failBlock:        {}", policy.fail_block);
    println!(
        "  denyUnclassified: {}{}",
        policy.deny_unclassified,
        if policy.deny_unclassified {
            "   (read-path misses are DENIED where the on-demand worker runs)"
        } else {
            "   (a read-path miss falls back to fingerprints — no new denials)"
        }
    );
    println!("  modelVersion:     {}", policy.model_version);
    println!();

    println!("cache ({}):", cache.source);
    match cache.entries {
        Some(n) => println!("  entries:        {n}"),
        None => println!("  entries:        —"),
    }
    println!("  bytes on disk:  {}", cache.bytes_on_disk);
    match cache.hmac_failures {
        Some(0) | None => println!("  hmac failures:  {}", opt_num(cache.hmac_failures)),
        Some(n) => println!("  hmac failures:  {n}   *** TAMPER SIGNAL — entries were discarded ***"),
    }
    match &cache.live {
        Some(s) => {
            println!("  hits:           {}", s.hits);
            println!("  misses:         {}", s.misses);
            println!("  evictions:      {}", s.evictions);
        }
        None => println!(
            "  hits/misses/evictions: — (process-lifetime counters; the enforcing process holds them\n                         and reports them to the console on check-in)"
        ),
    }
    if let Some(note) = &cache.note {
        println!("  note:           {note}");
    }
    println!();

    println!("queue (on-demand classifier):");
    match queue {
        Some(q) => {
            println!("  depth:          {} / {}", q.depth, q.capacity);
            println!("  processed:      {}", q.classified);
            println!("  failed:         {}", q.failed);
            println!("  unextractable:  {}", q.unextractable);
            println!(
                "  dropped:        {}{}",
                q.dropped,
                if q.dropped > 0 { "   (queue was full — this endpoint is MISSING COVERAGE)" } else { "" }
            );
            println!("  deduped:        {}", q.deduped);
            println!("  reads denied:   {}", q.deny_unclassified);
        }
        None => {
            println!("  worker:         not running in this process");
            println!("                  (it belongs to the service / usb-guard; capacity {} configured)", cfg.ml.queue_capacity);
        }
    }
    println!();

    println!("discovery (at-rest walker):");
    println!("  watcher:        {}", enabled_word(cfg.ml.watch_enabled));
    println!(
        "  walker:         {} ({} files/min)",
        enabled_word(cfg.ml.walk_enabled),
        cfg.ml.walk_files_per_minute
    );
    println!("  scopes:         {} configured", scopes.len());
    for s in &scopes {
        println!("                  {}", s.display());
    }
    match &completion {
        Some(c) => {
            println!(
                "  last full sweep: {} ({}) — {} files covered, model {}",
                unix_to_utc(c.completed_at),
                age_since(c.completed_at),
                c.files_covered(),
                c.model_version
            );
            if !covered {
                println!(
                    "                  *** that sweep ran under {} but this endpoint now runs {} —\n                      every entry it wrote is STALE and reads as a miss ***",
                    c.model_version, model_version
                );
            }
        }
        None => println!("  last full sweep: NEVER"),
    }
    match &checkpoint {
        Some(cp) => {
            println!(
                "  in progress:    yes — sweep #{}, {} dirs listed, {} files looked at so far",
                cp.sweep_seq, cp.counts.dirs, cp.counts.candidates
            );
            if cp.pending_truncated {
                println!(
                    "  queued dirs:    NOT PERSISTED — a restart re-walks the current scope"
                );
            } else {
                println!(
                    "  queued dirs:    {} still to visit ({} in memory, {} in the sidecar) — a restart resumes here",
                    cp.pending_dirs.len() as u64 + cp.spill.count,
                    cp.pending_dirs.len(),
                    cp.spill.count
                );
            }
        }
        None => println!("  in progress:    no"),
    }
    println!();

    println!("{coverage_line}");
    Ok(())
}

fn enabled_word(on: bool) -> &'static str {
    if on {
        "enabled"
    } else {
        "disabled"
    }
}

fn opt_num(n: Option<u64>) -> String {
    match n {
        Some(v) => v.to_string(),
        None => "—".to_string(),
    }
}

/// The closing sentence: is this endpoint ready for `denyUnclassified`?
///
/// Ordered by what would bite FIRST if the flag were flipped now, so the
/// operator is told the one thing that blocks them rather than a list. Only the
/// last branch is a yes, and it requires a completed full sweep UNDER THE MODEL
/// THE ENDPOINT IS RUNNING — coverage under a superseded model is not coverage,
/// because every entry that sweep wrote reads as stale, i.e. as a miss, i.e. as
/// a denial.
fn ml_coverage_verdict(
    cfg: &Config,
    policy: &mlpolicy::MlPolicy,
    model_loaded: bool,
    load_attempted: bool,
    model_version: &str,
    completion: Option<&ml::walk::SweepCompletion>,
    sweeping: bool,
) -> (bool, String) {
    let progress = if sweeping {
        " a sweep is in progress"
    } else {
        " no sweep is in progress"
    };
    if !cfg.ml.enabled {
        return (false, "coverage: [ml] enabled = false — the local kill switch is on, so this endpoint classifies nothing and caches nothing; denyUnclassified would deny every read of every file here. Do NOT enable it.".into());
    }
    if policy.is_inert() {
        return (false, "coverage: the ML policy is inert (off, or no class selected) — nothing is classified and nothing is cached. denyUnclassified is gated on a live policy and would have no effect; there is nothing to enable yet.".into());
    }
    if !model_loaded && !load_attempted {
        // --no-load: the graph was never tried, so this run cannot say whether
        // the endpoint can classify. Refuse to answer rather than guess in
        // either direction.
        return (false, "coverage: the classifier was not loaded (--no-load), so this report cannot confirm that this endpoint can classify at all. Re-run without --no-load before deciding anything about denyUnclassified.".into());
    }
    if !model_loaded {
        return (false, "coverage: the classifier is NOT LOADED on this endpoint — coverage cannot grow here. Fix the model artifacts / ONNX Runtime first; do NOT enable denyUnclassified.".into());
    }
    if !cfg.ml.walk_enabled {
        return (false, "coverage: the at-rest walker is disabled ([ml] walk_enabled = false), so nothing will ever backfill files that predate the agent. Do NOT enable denyUnclassified on this endpoint.".into());
    }
    match completion {
        None => (
            false,
            format!("coverage: discovery has NOT completed on this endpoint —{progress}. Do NOT enable denyUnclassified yet: every legacy file's first read would be denied."),
        ),
        Some(c) if !c.covers_model(model_version) => (
            false,
            format!(
                "coverage: the last full sweep completed under model {} but this endpoint runs {} — every entry it wrote is stale, so the endpoint is effectively uncovered.{progress}. Do NOT enable denyUnclassified until a sweep completes under {}.",
                c.model_version, model_version, model_version
            ),
        ),
        Some(c) if policy.deny_unclassified => (
            true,
            format!(
                "coverage: denyUnclassified is ALREADY ENABLED, and the evidence supports it — a full sweep completed {} under model {model_version}, covering {} files.",
                age_since(c.completed_at),
                c.files_covered()
            ),
        ),
        Some(c) => (
            true,
            format!(
                "coverage: a full sweep completed {} under model {model_version}, covering {} files — this endpoint is ready for denyUnclassified. Verify the rest of the fleet before enabling it centrally.",
                age_since(c.completed_at),
                c.files_covered()
            ),
        ),
    }
}

/// Unix seconds → `YYYY-MM-DD HH:MM:SSZ`.
///
/// Hand-rolled (Howard Hinnant's civil-from-days) rather than pulling `chrono`
/// in: this is the only place in the agent that formats a wall-clock time, and
/// the dependency tree ships to air-gapped defence sites (CLAUDE.md).
fn unix_to_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// "3h 12m ago" — the form an operator actually reads a coverage timestamp in.
fn age_since(unix_secs: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if unix_secs > now {
        return "in the future (clock skew)".into();
    }
    let s = now - unix_secs;
    if s < 60 {
        format!("{s}s ago")
    } else if s < 3_600 {
        format!("{}m ago", s / 60)
    } else if s < 86_400 {
        format!("{}h {}m ago", s / 3_600, (s % 3_600) / 60)
    } else {
        format!("{}d {}h ago", s / 86_400, (s % 86_400) / 3_600)
    }
}

/// classify: the model ONLY — no bundle, no fingerprinting, no policy verdict.
///
/// The CLI equivalent of the reference pipeline's `predict.py`, and what an
/// operator runs on a VM to answer "is the classifier itself working on this
/// box?" before anyone argues about thresholds. Because it reports the model's
/// raw answer rather than a policy one, it needs no console policy and no
/// enrollment — but it also never says "sensitive": that is `scan`'s job.
///
/// Text sources are mutually exclusive: `--file` (extracted with the SAME
/// `detect::extract_text` the scan path uses, so the supported formats are
/// identical), `--text` (a literal string), `--text-file` (already-plain text).
fn cmd_classify(cfg: &Config, args: &[String]) -> Result<()> {
    let mut file: Option<String> = None;
    let mut text: Option<String> = None;
    let mut text_file: Option<String> = None;
    let mut json = false;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--file" => file = it.next().cloned(),
            "--text" => text = it.next().cloned(),
            "--text-file" => text_file = it.next().cloned(),
            "--json" => json = true,
            other => {
                eprintln!("unknown classify option: {other}");
                print_classify_help();
                std::process::exit(2);
            }
        }
    }

    let sources = [file.is_some(), text.is_some(), text_file.is_some()]
        .iter()
        .filter(|present| **present)
        .count();
    anyhow::ensure!(
        sources == 1,
        "classify needs exactly one of --file <path> | --text <s> | --text-file <path>"
    );

    // NOTE: the extracted text is used and dropped. It is never printed, never
    // logged and never carried into the result — the same rule the whole
    // detection engine obeys.
    let document = if let Some(p) = &file {
        let path = Path::new(p);
        let bytes = std::fs::read(path).with_context(|| format!("reading {p}"))?;
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| p.clone());
        let extracted = detect::extract_text(&bytes, &name).map_err(|u| {
            anyhow::anyhow!("no text could be extracted from {p} ({})", u.reason.code())
        })?;
        extracted.text
    } else if let Some(p) = &text_file {
        std::fs::read_to_string(p).with_context(|| format!("reading {p}"))?
    } else {
        text.unwrap_or_default()
    };

    // Deliberately independent of the console ML policy AND of the `[ml]`
    // local kill switch: this is a diagnostic ("does the model run here, and
    // what does it say?"), never an enforcement decision. Nothing it prints can
    // block anything, so nothing it prints needs a policy behind it.
    let engine = load_ml_engine(cfg)?;
    let prediction = engine
        .classify(&document)
        .map_err(|e| anyhow::anyhow!("classification failed: {e}"))?;

    if json {
        // camelCase, the same vocabulary the verdict's `ml` block uses, so a
        // script can compare the two without a second mapping table.
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "modelVersion": engine.model_version(),
                "labelId": prediction.label_id,
                "labelName": prediction.label_name,
                "labelIndex": prediction.label_index,
                "confidence": prediction.confidence,
                "chunks": prediction.chunks,
                "tokens": prediction.tokens,
            }))?
        );
    } else {
        println!("model:      {}", engine.model_version());
        println!("label:      {} — {}", prediction.label_id, prediction.label_name);
        println!("confidence: {:.2}%", prediction.confidence * 100.0);
        println!("chunks:     {}", prediction.chunks);
        println!("tokens:     {}", prediction.tokens);
    }
    Ok(())
}

/// Print one file's verdict: the fingerprint signal, the model signal, and the
/// fused answer. The last block is the demo — it must be readable across a room.
fn print_verdict(
    v: &detect::Verdict,
    bundle: Option<&detect::Bundle>,
    bands: &detect::Bands,
    decision: &detect::Decision,
    ml_note: Option<&str>,
) {
    println!("file:       {}", v.file_name);
    println!("sha256:     {}", v.file_sha256);
    match bundle {
        Some(b) => println!("bundle:     v{}", b.version()),
        None => println!("bundle:     none"),
    }
    match &v.extraction {
        detect::Extraction::Ok { format } => println!("extraction: ok ({format})"),
        detect::Extraction::Unreadable { reason } => println!("extraction: unreadable ({reason})"),
    }

    // ---- signal 1: fingerprinting (IDM/EDM) ------------------------------
    if bundle.is_none() {
        // Not "clean" — unmeasured. Say so, or a demo with no index reads as a
        // fingerprint pass.
        println!("fingerprinting: no bundle loaded (pass --bundle <path.dlpx> to score IDM/EDM)");
    } else if v.idm.is_empty() {
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
    if bundle.is_some() {
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
        println!(
            "bands:      containment >= {:.2}, coverage >= {:.2} ([kguard])",
            bands.containment_at, bands.coverage_at
        );
    }

    // ---- signal 2: the document classifier --------------------------------
    println!("classification:");
    match &v.ml {
        Some(m) if m.is_ok() => {
            println!(
                "  label:      {} — {}",
                m.label_id.as_deref().unwrap_or("?"),
                m.label_name.as_deref().unwrap_or("?")
            );
            println!("  confidence: {:.2}%", m.confidence * 100.0);
            println!("  chunks:     {} ({} tokens)", m.chunks, m.tokens);
            println!("  model:      {}", m.model_version);
            println!(
                "  sensitive:  {}",
                if m.sensitive {
                    "yes (label selected in policy, at or over its threshold)"
                } else {
                    "no (label not selected, or under its threshold)"
                }
            );
        }
        // A non-ok status is never a clean bill of health: it says the model owed
        // an answer and did not give one, which is what `failBlock` weighs.
        Some(m) => println!(
            "  {} ({}) — model {}",
            m.status,
            m.reason.as_deref().unwrap_or("no reason"),
            m.model_version
        ),
        None => println!("  {}", ml_note.unwrap_or("not run")),
    }

    // ---- the fused answer -------------------------------------------------
    // detect::decide(), unmodified: sensitive = fingerprint OR model. Plain
    // ASCII rules rather than colour — this runs over RDP, through a service
    // log and into a redirect, and it has to stay unmistakable in all three.
    const RULE: &str = "============================================================";
    println!();
    if decision.sensitive {
        println!("{RULE}");
        println!(
            "  VERDICT: SENSITIVE   (signal: {}, severity: {})",
            decision.signal.as_deref().unwrap_or("none"),
            decision.severity.map(|s| s.as_str()).unwrap_or("none"),
        );
        println!("{RULE}");
    } else {
        println!("------------------------------------------------------------");
        println!("  VERDICT: not sensitive");
        println!("------------------------------------------------------------");
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
    // ML classification: this process runs the kguard write-scan decide(), so it
    // needs both the policy and the loaded graph or the second signal is silently
    // absent from every USB write it adjudicates.
    //
    // ROLE = Guard: it also runs the kguard message loop, so it owns the READ
    // path's cache lookup and therefore the on-demand worker that heals a miss.
    // It does NOT get the watcher or the walker — an operator starts and kills
    // this tool at will, and a multi-hour throttled sweep must be attached to the
    // service, not to a debugging session (and never to both at once).
    activate_ml(cfg, checkin::sync_ml_policy(cfg, storage), MlPipelineRole::Guard);
    // Standalone usb-guard (operator debugging tool) has no read-deny policy fetch,
    // so it keeps the back-compat MERGE (local + central) — unchanged behaviour.
    let effective = cfg.with_synced_destinations(&synced).with_synced_readers(&readers, false);
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
    // Clipboard policy: pull + cache so the per-session helper (spawned below) reads
    // the current mode. The helper applies it; run_endpoint (Session 0) can't watch
    // the user's clipboard itself.
    let _ = checkin::sync_clipboard_policy(cfg, storage);
    let effective = cfg
        .with_synced_destinations(&synced)
        .with_synced_readers(&readers, policy.readers_central())
        .with_read_deny_policy(&policy);
    // ML classification: pull + cache the console policy AND load the graph together
    // (see `activate_ml` — publishing one without the other is a fleet-wide block).
    // This is what makes the kguard write-scan classify; the per-session helpers read
    // the cache this call just wrote.
    //
    // ROLE = Service: this process owns the whole coverage pipeline — the verdict
    // cache, the on-demand worker, the at-creation watcher and the at-rest walker.
    // It is the only long-lived one, and the only one whose lifetime a multi-hour
    // sweep can safely be attached to.
    //
    // AFTER `effective`, DELIBERATELY. The pipeline's scopes are derived from
    // `[kguard] watch_paths`, and those are console-authoritative — they arrive on
    // the read-deny policy and are merged in by `with_read_deny_policy`. Activating
    // on the raw `cfg` would bind the watcher and the walker to whatever the local
    // `agent.toml` happened to say, so the estate the pipeline covers and the
    // estate the driver adjudicates reads against would silently differ.
    activate_ml(
        &effective,
        checkin::sync_ml_policy(cfg, storage),
        MlPipelineRole::Service { stop: stop.clone() },
    );
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

    // (a2) DENY-DRAIN — pull the driver's read-deny audit ring (cache-hit denies
    // that never up-call — e.g. a SECOND untrusted process reading an already-
    // flagged file) and raise one incident per distinct denied (process, file), so
    // the audit trail counts every attempt, not just the first.
    {
        let shared = shared.clone();
        let stop_w = stop.clone();
        let state_dir = state_dir.clone();
        handles.push(supervised_thread("deny-drain", stop.clone(), Duration::from_secs(3), move || {
            let storage = Storage::new(state_dir.clone());
            let queue = usb::queue::IncidentQueue::new(&state_dir);
            let report = |pid: u32, file_id: u64, reason: u32| {
                let snap = supervise::snapshot_config(&shared);
                let bluetooth = reason == kguard::DLP_REASON_BLUETOOTH;
                let monitor = bluetooth && snap.kguard.bluetooth_mode == dlp_agent::bluetooth::Mode::Monitor;
                let file_name = format!("read-deny (file id 0x{file_id:x})");
                // A synthetic verdict so this repeat-deny POSTS to the console
                // incident feed (like the first attempt) rather than only logging
                // locally: incident_wire_body drops verdict-less incidents. The file
                // is served from the kernel cache and deliberately NOT re-scanned on
                // the hot path, so there is no content/hash/match detail to carry —
                // extraction is Unreadable and the match lists are empty (the same
                // shape the server already accepts for UnreadableOnRemovable). The
                // first attempt's incident holds the full detection detail; this one
                // records that ANOTHER process (pid) was blocked reading the file.
                let inc = UsbIncident {
                    kind: usb::IncidentKind::Match,
                    channel: if bluetooth { "bluetooth".into() } else { snap.kguard.channel_label.clone() },
                    file_name: file_name.clone(),
                    file_sha256: String::new(),
                    verdict: Some(detect::Verdict {
                        file_name,
                        file_sha256: String::new(),
                        extraction: detect::Extraction::Unreadable {
                            reason: "repeat deny served from kernel cache (not re-scanned)".into(),
                        },
                        idm: Vec::new(),
                        edm: Vec::new(),
                        ml: None,
                    }),
                    device: usb::device::DeviceIdentity {
                        drive_letter: String::new(),
                        vendor_id: String::new(),
                        product_id: String::new(),
                        serial: String::new(),
                        product_name: String::new(),
                        bus_type: if bluetooth { "bluetooth".into() } else { "fixed".into() },
                        removable: false,
                    },
                    action_taken: if monitor { ActionTaken::Audited } else { ActionTaken::Blocked },
                    note: Some(format!("{} pid={pid}", if bluetooth {
                        if monitor { "bluetooth-read-would-block-repeat" } else { "bluetooth-read-denied-repeat" }
                    } else { "exfil-read-denied-repeat" })),
                    key_id: None,
                    sealed_sha256: None,
                };
                deliver_incident(&snap, &storage, &queue, &inc);
            };
            kguard::deny_drain_loop(&stop_w, 2000, report);
        }));
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
                // Refresh the clipboard policy cache so the session supervisor picks
                // up console changes (off<->monitor<->enforce) and respawns the helper.
                let _ = checkin::sync_clipboard_policy(&base_cfg, &storage);
                let new_effective = base_cfg
                    .with_synced_destinations(&synced)
                    .with_synced_readers(&readers, policy.readers_central())
                    .with_read_deny_policy(&policy);
                // Same for ML: a console change (classes added/removed, enabled
                // toggled, denyUnclassified flipped) takes effect WITHOUT a
                // restart. `activate_ml` is idempotent — it reloads nothing when
                // the engine is already up, drops it when the policy goes inert,
                // and starts the coverage pipeline at most once. Fed the MERGED
                // config for the same reason as the startup call: the pipeline's
                // scopes come from the console's read-deny watch-set.
                //
                // Same Service role as startup, so a pipeline that could not start
                // then (cache open failed, model not yet staged) is retried here
                // every cycle instead of staying down until the next reboot.
                activate_ml(
                    &new_effective,
                    checkin::sync_ml_policy(&base_cfg, &storage),
                    MlPipelineRole::Service { stop: stop_w.clone() },
                );
                health.set_keyring_present(build_sealer_keyring(&base_cfg, &storage).is_some());
                match shared.write() {
                    Ok(mut w) => *w = new_effective,
                    Err(p) => *p.into_inner() = new_effective,
                }
                tracing::info!("resynced trusted config — guard + sealer will use it live");
            }
        }));
    }

    // (e) CLIPBOARD SESSION SUPERVISOR — the DLPAgent service runs in Session 0,
    // which has its own clipboard, NOT the interactive user's. So spawn the
    // clipboard helper INTO the user session (WTS + CreateProcessAsUserW) and keep
    // it alive: relaunch on exit (logoff/crash), on session change, or when the
    // policy changes (off<->monitor<->enforce, block_images, fail_block). The child
    // reads the cached clipboard policy the check-in/resync workers keep fresh.
    #[cfg(windows)]
    {
        let stop_w = stop.clone();
        let state_dir = state_dir.clone();
        handles.push(supervised_thread(
            "clipboard-session",
            stop.clone(),
            Duration::from_secs(5),
            move || {
                let storage = Storage::new(state_dir.clone());
                let mut child: Option<usersession::SessionChild> = None;
                // (session, mode, block_images, fail_block) the live child was started with.
                let mut applied: Option<(u32, clippolicy::ClipboardMode, bool, bool)> = None;
                loop {
                    if stop_w.load(Ordering::Relaxed) {
                        break;
                    }
                    let policy = checkin::load_clipboard_policy(&storage);
                    let session = usersession::active_console_session();

                    // Reap a child that has exited (logoff / crash).
                    if let Some(c) = &child {
                        if !c.is_alive() {
                            child = None;
                            applied = None;
                        }
                    }

                    if policy.is_off() || session.is_none() {
                        // No interactive user, or protection off — ensure no child.
                        if let Some(c) = child.take() {
                            c.terminate();
                            applied = None;
                        }
                    } else {
                        let sess = session.unwrap();
                        let want = (sess, policy.mode, policy.block_images, policy.fail_block);
                        let stale = child.is_none()
                            || applied != Some(want)
                            || child.as_ref().map(|c| c.session) != Some(sess);
                        if stale {
                            if let Some(c) = child.take() {
                                c.terminate();
                            }
                            match usersession::spawn_in_session(sess, &["clipboard-agent"]) {
                                Ok(c) => {
                                    tracing::info!(session = sess, mode = %policy.mode, "spawned clipboard helper in user session");
                                    child = Some(c);
                                    applied = Some(want);
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, session = sess, "could not spawn clipboard helper (will retry)");
                                    applied = None;
                                }
                            }
                        }
                    }
                    sleep_interruptible(5, &stop_w);
                }
                if let Some(c) = child.take() {
                    c.terminate();
                }
            },
        ));
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

/// `clipboard-agent`: the per-session clipboard helper the DLPAgent service spawns
/// into the interactive user session (Session 0 can't see the user's clipboard).
/// It reads the console-managed clipboard policy from the local cache and applies
/// it — `off` idles, `monitor` audits a sensitive copy, `enforce` clears the
/// clipboard so the paste yields nothing. Incidents flow through the same mTLS +
/// offline-queue path as the manual `clipboard-monitor`. The Session-0 supervisor
/// restarts this child when the policy changes or the session changes.
fn cmd_clipboard_agent(cfg: &Config, storage: &Storage) -> Result<()> {
    // Console policy is the single source of truth; override the local [clipboard].
    let policy = checkin::load_clipboard_policy(storage);
    let mut eff = cfg.clone();
    policy.apply_to_config(&mut eff);
    let cfg = &eff;

    if policy.is_off() {
        tracing::info!("clipboard-agent: policy is off — idle (no monitoring)");
        return Ok(());
    }
    tracing::info!(mode = %policy.mode, block_images = policy.block_images, "clipboard-agent: starting per-session monitor");

    // ML classification from the CACHE, not a fetch: this is a short-lived
    // per-session helper spawned on every logon, and run_endpoint (Session 0)
    // already refreshes `ml-policy.json` on the check-in cadence. A copy is only
    // sensitive to the model if this process both holds the policy and has the
    // graph loaded.
    // ROLE = LookupOnly: a per-session helper publishes the verdict cache so it
    // can READ what the service's producers deposited, and starts no worker of
    // its own — it never sees a kernel up-call, and one inference thread per
    // logged-on session would be a cost with no counterpart.
    activate_ml(cfg, checkin::load_ml_policy(storage), MlPipelineRole::LookupOnly);

    let queue = usb::queue::IncidentQueue::new(&cfg.state_dir);
    if storage.has_identity() && !queue.is_empty() {
        let flushed = queue.flush(|body| post_incident_body(cfg, storage, body).map(|_| ()));
        if flushed > 0 {
            tracing::info!(flushed, "flushed queued clipboard incidents");
        }
    }
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
                let _ = queue.enqueue(&body);
            }
        }
        None => tracing::info!(kind = ?inc.kind, "clipboard metadata incident (no verdict; not posted)"),
    };

    // enforce=true only in Enforce mode; Monitor classifies + audits but allows.
    clipboard::run_monitor(cfg, storage, policy.enforce(), sink);
    Ok(())
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

    // ML classification from the CACHE (see cmd_clipboard_agent): the browser
    // spawns this host per session over stdio, so it must not add an mTLS round
    // trip to every launch. Without this an upload of an unregistered but
    // sensitively-classified document — the whole reason the model exists — is
    // scored by fingerprinting alone.
    // ROLE = LookupOnly: a per-session helper publishes the verdict cache so it
    // can READ what the service's producers deposited, and starts no worker of
    // its own — it never sees a kernel up-call, and one inference thread per
    // logged-on session would be a cost with no counterpart.
    activate_ml(cfg, checkin::load_ml_policy(storage), MlPipelineRole::LookupOnly);

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

    // The verified index, kept current by the watcher. The browser host lives
    // as long as the browser, so a one-shot load would keep scoring uploads
    // against whatever index existed when the browser was opened — and a host
    // started before any index existed would stay audit-only forever. Each
    // request now takes ONE snapshot and is scored against it.
    let live = livebundle::LiveBundle::start(
        storage.dir(),
        &cfg.ca_cert_path,
        "browser-host",
        livebundle::DEFAULT_POLL_INTERVAL,
    );
    if live.current().is_some() {
        tracing::info!("browser-host started (bundle cached) — reading native messages");
    } else {
        // No policy bundle: we cannot score. Fail-OPEN (allow) so the browser
        // is never bricked — audit-only until a bundle is present, and now the
        // host switches to enforcing by itself once one is downloaded. Honest,
        // documented limitation (a fail-secure knob is a follow-on).
        tracing::warn!(
            "no verified index bundle yet — browser-host allows uploads (audit-only) until one is downloaded"
        );
    }
    let clean = || detect::Verdict {
        file_name: String::new(),
        file_sha256: String::new(),
        extraction: detect::Extraction::Ok { format: "none".into() },
        idm: Vec::new(),
        edm: Vec::new(),
        ml: None,
    };

    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();

    browser_host::serve(
        &mut reader,
        &mut writer,
        block_at,
        coverage_block_at,
        channel,
        |t| match live.current() {
            Some(b) => detect::verdict_text(t, &b),
            None => clean(),
        },
        |p| match live.current() {
            Some(b) => detect::verdict(p, &b),
            None => Ok(clean()),
        },
        |bytes, name| match live.current() {
            Some(b) => detect::verdict_bytes(bytes, name, &b),
            None => clean(),
        },
        &mut sink,
    )?;
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
    println!("dlp-agent <enroll|once|run|status|index-update|scan|classify|ml-status|usb-monitor|usb-guard|clipboard-monitor|net-monitor|browser-host|decrypt|run-endpoint|install-service|uninstall-service>");
    println!("  scan --file <path> [--bundle <path>] [--json] [--exit-code]   BOTH signals + verdict (see --help)");
    println!("  classify --file <path>|--text <s>|--text-file <path> [--json]  the model only (see --help)");
    println!("  ml-status [--json] [--no-load]  ML coverage: is this endpoint ready for denyUnclassified? (see --help)");
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
    println!("dlp-agent scan --file <path> [--bundle <path>] [--json] [--report --channel <name>]");
    println!("                              [--no-ml | --ml-labels <ID,ID,...>] [--ml-min-confidence <f>]");
    println!("                              [--exit-code]");
    println!("  Scores ONE file with BOTH detection signals and prints the fused verdict:");
    println!("  fingerprinting (IDM/EDM, needs a bundle) OR the ONNX document classifier");
    println!("  (needs the model + a live ML policy). OR, never AND: fingerprinting cannot");
    println!("  see an unregistered document, the model cannot name which document leaked.");
    println!("  --file <path>     file to scan (extraction picks the format by extension)");
    println!("  --bundle <path>   signed index bundle (.dlpx) to match against. OPTIONAL:");
    println!("                    without it the fingerprint half prints \"no bundle loaded\"");
    println!("                    and the model runs alone — how a site demonstrates the");
    println!("                    classifier BEFORE any document has been registered.");
    println!("  --json            print the full verdict as JSON (the `ml` block included)");
    println!("  --report          POST the verdict to the server (mTLS, requires enrollment)");
    println!("  --channel <name>  channel label for the report, e.g. usb-audit");
    println!("  --no-ml           do not classify; fingerprint-only, exactly as before the");
    println!("                    model existed");
    println!("  --ml-labels <ID,ID,...>     treat these taxonomy ids as sensitive (FIN,NUC,...)");
    println!("  --ml-min-confidence <f>     confidence floor in 0.0..=1.0 for those labels");
    println!("                    BOTH --ml-* flags OVERRIDE THE CONSOLE POLICY FOR THIS");
    println!("                    INVOCATION ONLY. Nothing is persisted and no endpoint");
    println!("                    setting changes — they exist so a machine that has not");
    println!("                    enrolled (a demo box, a test VM) can still show the second");
    println!("                    signal. On an enrolled endpoint the console policy is the");
    println!("                    authority and these flags do not survive the command.");
    println!("  --exit-code       exit 1 when the verdict is SENSITIVE (for scripts). Default");
    println!("                    is 0 either way; an unreadable file is a verdict, not an error.");
    println!("  Thresholds: [kguard] block_at / coverage_block_at for the fingerprint bands;");
    println!("  the ML thresholds come from the ML policy. Model paths: the [ml] section.");
    println!("  The output carries hashes, labels, scores and counts — never file content.");
}

fn print_classify_help() {
    println!("dlp-agent classify --file <path> | --text <s> | --text-file <path> [--json]");
    println!("  Runs ONLY the ONNX document classifier — no bundle, no fingerprinting, no");
    println!("  policy. This is the CLI equivalent of the reference pipeline's predict.py:");
    println!("  what an operator runs on a VM to prove the model itself works on this box");
    println!("  before anyone argues about thresholds. It reports the model's raw answer, so");
    println!("  it never says \"sensitive\" — that is `scan`, which fuses both signals.");
    println!("  --file <path>       extract text first (same formats as scan: txt/pdf/docx/...)");
    println!("  --text <s>          classify a literal string");
    println!("  --text-file <path>  classify a file that is already plain text");
    println!("  --json              print modelVersion/labelId/labelName/labelIndex/confidence/");
    println!("                      chunks/tokens as JSON (same camelCase as the verdict's ml block)");
    println!("  Exactly one text source is required. The text is classified and dropped: it is");
    println!("  never printed, never logged and never carried into the result.");
    println!("  Config: the [ml] section (model_path, tokenizer_path, intra_threads). The");
    println!("  sidecar is read from beside the weights (model.onnx -> model.onnx.json), and");
    println!("  ONNX Runtime from <ml root>\\runtime\\onnxruntime.dll, then $ORT_DYLIB_PATH.");
}

fn print_ml_status_help() {
    println!("dlp-agent ml-status [--json] [--no-load]");
    println!("  Answers ONE question: has this endpoint been covered by the ML classifier");
    println!("  yet, i.e. is it safe to turn `denyUnclassified` on? Enabling that flag before");
    println!("  the at-rest walker has swept the estate denies the first read of every legacy");
    println!("  file on every PC, so the rollout is deploy -> sweep -> VERIFY -> enable, and");
    println!("  this is the verify step. The closing line states the answer in words.");
    println!("  Reports: model (loaded?, version, artifact paths), policy (classes selected,");
    println!("  minConfidence, action, failBlock, denyUnclassified), verdict cache (entries,");
    println!("  bytes on disk, HMAC failures), on-demand queue, and the walker's completion");
    println!("  record (when the last FULL sweep finished, under which model, files covered).");
    println!("  --json      the same report as JSON, for a fleet tool to gate a rollout on");
    println!("  --no-load   do not load the ONNX graph (fast; then the model version shown is");
    println!("              the policy's declared one, not the graph's own)");
    println!("  Read-only: it classifies nothing, enforces nothing, and never opens the live");
    println!("  verdict log — it replays a COPY, so it cannot truncate or re-key the cache the");
    println!("  service is writing. Hit/miss/queue-depth counters live in the enforcing");
    println!("  process's memory and read as '-' here; they reach the console on check-in.");
    println!("  Prints no file name, no path outside the configured [ml] scopes and model");
    println!("  artifacts, and no content.");
}

/// Best-effort machine hostname (used as the CSR hint; the server assigns the
/// real identity).
pub fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".into())
}
