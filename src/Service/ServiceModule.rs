#[path = "BruteForce/BruteForceService.rs"]
pub mod BruteForce;
#[path = "EventSource/EventSourceService.rs"]
pub mod EventSource;
#[path = "NetworkLogin/NetworkLoginService.rs"]
pub mod NetworkLogin;
#[path = "Process/ProcessTraceService.rs"]
pub mod Process;
#[path = "WindowsServiceManager.rs"]
mod WindowsServiceManager;
pub use WindowsServiceManager::{install, run_service, start, stop, uninstall};
