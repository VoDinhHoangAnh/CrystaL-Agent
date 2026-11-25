#[allow(unused_imports)]
pub use crate::Model::{ProcessTrace, TcpFlow, TraceEvent};

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct EventSourceStatus {
    pub group: String,
    pub category: String,
    pub channel: String,
    pub channel_present: bool,
    pub sample_found: bool,
    pub access_denied: bool,
}
