use std::{error::Error, process::Command};

const SERVICE_NAME: &str = "CrystaLAgent";

#[cfg(windows)]
pub fn run_service(cfg: crate::Config::Config) -> Result<(), Box<dyn Error>> {
    use std::sync::{Arc, OnceLock, atomic::AtomicBool};
    use windows_service::service_control_handler::ServiceStatusHandle;
    use windows_service::{define_windows_service, service_control_handler, service_dispatcher};

    static CONFIG: OnceLock<crate::Config::Config> = OnceLock::new();
    static STOP: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    let _ = CONFIG.set(cfg);
    let _ = STOP.set(Arc::new(AtomicBool::new(false)));

    define_windows_service!(ffi_service_main, service_main);
    fn service_main(_args: Vec<std::ffi::OsString>) {
        use std::sync::atomic::Ordering;
        use windows_service::service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        };
        use windows_service::service_control_handler::ServiceControlHandlerResult;
        let status_handle_slot = Arc::new(OnceLock::<ServiceStatusHandle>::new());
        let handler_status = Arc::clone(&status_handle_slot);
        let status = |state, accepted, checkpoint, wait_hint| ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accepted,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint,
            wait_hint,
            process_id: None,
        };
        let Ok(status_handle) =
            service_control_handler::register(SERVICE_NAME, move |control| match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    if let Some(handle) = handler_status.get() {
                        let _ = handle.set_service_status(status(
                            ServiceState::StopPending,
                            ServiceControlAccept::empty(),
                            1,
                            std::time::Duration::from_secs(60),
                        ));
                    }
                    if let Some(stop) = STOP.get() {
                        stop.store(true, Ordering::Relaxed);
                    }
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            })
        else {
            return;
        };
        let _ = status_handle_slot.set(status_handle);
        let _ = status_handle.set_service_status(status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            0,
            std::time::Duration::default(),
        ));
        if let (Some(cfg), Some(stop)) = (CONFIG.get(), STOP.get()) {
            let _ = crate::Agent::run_until(cfg.clone(), stop.clone());
        }
        let _ = status_handle.set_service_status(status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            0,
            std::time::Duration::default(),
        ));
    }
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

#[cfg(not(windows))]
pub fn run_service(_cfg: crate::Config::Config) -> Result<(), Box<dyn Error>> {
    Err("Windows Service is available only on Windows".into())
}

#[cfg(windows)]
pub fn install() -> Result<(), Box<dyn Error>> {
    let exe = std::env::current_exe()?;
    sc(&[
        "create",
        SERVICE_NAME,
        "binPath=",
        &format!("\"{}\" service", exe.display()),
        "start=",
        "auto",
    ])?;
    sc(&["description", SERVICE_NAME, "PBRA endpoint telemetry agent"])?;
    start()
}
#[cfg(not(windows))]
pub fn install() -> Result<(), Box<dyn Error>> {
    Err("Windows Service is available only on Windows".into())
}

#[cfg(windows)]
pub fn uninstall() -> Result<(), Box<dyn Error>> {
    let _ = sc(&["stop", SERVICE_NAME]);
    sc(&["delete", SERVICE_NAME])
}
#[cfg(not(windows))]
pub fn uninstall() -> Result<(), Box<dyn Error>> {
    Err("Windows Service is available only on Windows".into())
}

#[cfg(windows)]
pub fn start() -> Result<(), Box<dyn Error>> {
    sc(&["start", SERVICE_NAME])
}
#[cfg(not(windows))]
pub fn start() -> Result<(), Box<dyn Error>> {
    Err("Windows Service is available only on Windows".into())
}

#[cfg(windows)]
pub fn stop() -> Result<(), Box<dyn Error>> {
    sc(&["stop", SERVICE_NAME])
}
#[cfg(not(windows))]
pub fn stop() -> Result<(), Box<dyn Error>> {
    Err("Windows Service is available only on Windows".into())
}

#[cfg(windows)]
fn sc(args: &[&str]) -> Result<(), Box<dyn Error>> {
    let output = Command::new("sc.exe").args(args).output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr)
            .trim()
            .to_owned()
            .into());
    }
    Ok(())
}
