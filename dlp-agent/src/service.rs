//! Windows Service Control Manager (SCM) integration for the unified
//! `run-endpoint` mode.
//!
//! * `install-service` / `uninstall-service` register/remove the service
//!   (name `DLPAgent`, display "DLP Endpoint Agent", auto-start, LocalSystem,
//!   depends on FltMgr). The registered ImagePath is `<exe> service-run`.
//! * The SCM launches `<exe> service-run`; `main()` routes that to
//!   [`run_dispatcher`], which hands control to the SCM and — via the
//!   `define_windows_service!` entry point — runs the same `run_endpoint`
//!   supervisor the CLI `run-endpoint` uses, wiring the SCM Stop/Shutdown
//!   controls to a graceful stop signal and routing logs to a rolling file.
//!
//! Everything real is `#[cfg(windows)]`; non-Windows builds get stubs so the
//! crate still compiles cross-platform.

use anyhow::Result;

#[cfg(windows)]
pub const SERVICE_NAME: &str = "DLPAgent";
#[cfg(windows)]
pub const SERVICE_DISPLAY: &str = "DLP Endpoint Agent";

/// Register the Windows service (auto-start, LocalSystem, depends on FltMgr).
#[cfg(windows)]
pub fn install() -> Result<()> {
    use std::ffi::OsString;
    use windows_service::service::{
        ServiceAccess, ServiceDependency, ServiceErrorControl, ServiceInfo, ServiceStartType,
        ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;

    let exe = std::env::current_exe()?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        // The SCM appends this to the ImagePath: `<exe> service-run`, which
        // main() routes to the dispatcher.
        launch_arguments: vec![OsString::from("service-run")],
        // Filter Manager must be up before we try to connect to \DlpFltPort.
        dependencies: vec![ServiceDependency::Service(OsString::from("FltMgr"))],
        account_name: None, // None ⇒ LocalSystem
        account_password: None,
    };

    let service = manager.create_service(
        &info,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
    )?;
    let _ = service.set_description(
        "DLP endpoint agent: kernel guard + user-mode sealer + check-in + whitelist re-sync (run-endpoint).",
    );
    println!("installed service '{SERVICE_NAME}' ({SERVICE_DISPLAY}); start type auto, LocalSystem, depends on FltMgr");
    println!("start it with:  sc start {SERVICE_NAME}");
    Ok(())
}

/// Stop (best-effort) and delete the Windows service.
#[cfg(windows)]
pub fn uninstall() -> Result<()> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    )?;
    // Best-effort stop (errors if already stopped — ignored).
    let _ = service.stop();
    service.delete()?;
    println!("uninstalled service '{SERVICE_NAME}'");
    Ok(())
}

/// Entry called from `main()` when the SCM launches `<exe> service-run`. Hands
/// control to the SCM dispatcher; blocks until the service stops.
#[cfg(windows)]
pub fn run_dispatcher() -> Result<()> {
    use windows_service::service_dispatcher;
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

#[cfg(windows)]
windows_service::define_windows_service!(ffi_service_main, service_main);

/// The service entry point invoked by the SCM (via the generated FFI shim).
#[cfg(windows)]
fn service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = run_service() {
        // File logging is up by now; surface the failure there.
        tracing::error!("service failed: {e:#}");
    }
}

/// Set up file logging, register the control handler, report Running, run the
/// `run-endpoint` supervisor until Stop/Shutdown, then report Stopped.
#[cfg(windows)]
fn run_service() -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    // No console under the SCM — route tracing to a rolling file.
    crate::init_file_logging();
    tracing::info!("service starting (run-endpoint under the SCM as LocalSystem)");

    let stop = Arc::new(AtomicBool::new(false));
    let stop_handler = stop.clone();
    let event_handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                stop_handler.store(true, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let (cfg, storage) = crate::load_cfg_and_storage()?;
    let result = crate::run_endpoint(&cfg, &storage, stop);

    // Always report Stopped so the SCM does not mark the service hung.
    let exit = if result.is_ok() { 0 } else { 1 };
    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    });
    result
}

// ---------------------------------------------------------------------------
// Non-Windows stubs so the crate builds cross-platform.
// ---------------------------------------------------------------------------
#[cfg(not(windows))]
pub fn install() -> Result<()> {
    anyhow::bail!("install-service is only available on Windows")
}

#[cfg(not(windows))]
pub fn uninstall() -> Result<()> {
    anyhow::bail!("uninstall-service is only available on Windows")
}

#[cfg(not(windows))]
pub fn run_dispatcher() -> Result<()> {
    anyhow::bail!("the Windows service dispatcher is only available on Windows")
}
