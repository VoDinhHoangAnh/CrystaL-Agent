#[cfg(windows)]
#[path = "WindowsEventCollector.rs"]
mod WindowsEventCollector;
#[cfg(windows)]
pub use WindowsEventCollector::{collect_event_logs, collect_snapshots};
