use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub const AGENT_VERSION: &str = "0.3.0-rust";
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RawEnvelope {
    pub event_id: String,
    pub agent_id: String,
    pub source: String,
    pub source_event_key: String,
    pub event_time: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub schema_version: u32,
    pub kind: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub snapshot: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xml: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ProcessFacts {
    pub pid: i64,
    #[serde(default)]
    pub ppid: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_guid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_process_guid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_image: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NetworkFacts {
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_ip: Option<String>,
    #[serde(default)]
    pub local_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<String>,
    #[serde(default)]
    pub remote_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default)]
    pub pid: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_guid: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WindowsFacts {
    pub provider: String,
    pub channel: String,
    pub event_code: i64,
    #[serde(default)]
    pub record_id: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computer: Option<String>,
    #[serde(default)]
    pub event_data: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Normalized {
    pub event_id: String,
    pub agent_id: String,
    pub event_type: String,
    pub source: String,
    pub source_event_key: String,
    pub event_time: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    pub snapshot: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessFacts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<ProcessFacts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkFacts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows: Option<WindowsFacts>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub secret_indicator: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Finding {
    pub finding_id: String,
    pub rule_id: String,
    pub points: i32,
    pub severity: String,
    pub reason: String,
    #[serde(default)]
    pub event_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Assessment {
    pub assessment_id: String,
    pub score: i32,
    pub severity: String,
    pub confidence: f64,
    pub track: bool,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PersistInput {
    pub normalized: Normalized,
    #[serde(default)]
    pub process_instance_id: String,
    #[serde(default)]
    pub parent_process_instance_id: String,
    pub assessment: Assessment,
    #[serde(default)]
    pub track_process: bool,
    #[serde(default)]
    pub track_ip: bool,
    #[serde(default)]
    pub ip_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct TrackedEntity {
    pub entity_id: String,
    pub agent_id: String,
    pub entity_type: String,
    pub entity_key: String,
    pub status: String,
    pub severity: String,
    pub score: i32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Checkpoint {
    pub record_id: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CollectorHealth {
    pub collector_id: String,
    pub status: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub events_seen: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ProcessNode {
    pub process_instance_id: String,
    #[serde(default)]
    pub parent_process_instance_id: String,
    pub process: ProcessFacts,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct TraceEvent {
    pub event_id: String,
    pub event_type: String,
    pub source: String,
    pub event_time: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessFacts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkFacts>,
    pub risk_score: i32,
    pub severity: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct TcpFlow {
    pub protocol: String,
    #[serde(default)]
    pub local_ip: Option<String>,
    #[serde(default)]
    pub local_port: u16,
    #[serde(default)]
    pub remote_ip: Option<String>,
    #[serde(default)]
    pub remote_port: u16,
    #[serde(default)]
    pub events: Vec<TraceEvent>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ProcessTrace {
    pub selector: String,
    #[serde(default)]
    pub process_tree: Vec<ProcessNode>,
    #[serde(default)]
    pub events: Vec<TraceEvent>,
    #[serde(default)]
    pub tcp_flows: Vec<TcpFlow>,
}

fn is_false(value: &bool) -> bool {
    !*value
}
