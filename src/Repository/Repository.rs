use crate::Model::{
    CollectorHealth, Normalized, PersistInput, ProcessTrace, RawEnvelope, TrackedEntity,
};
use chrono::{DateTime, Utc};

pub trait Repository {
    fn append_raw(&mut self, raw: RawEnvelope) -> Result<(), String>;
    fn persist(&mut self, input: PersistInput) -> Result<(), String>;
    fn trace_process(&self, selector: &str) -> Result<ProcessTrace, String>;
    fn close_case(&mut self, id: &str, reason: &str) -> Result<(), String>;
    fn stats(&self) -> StoreStats;
}

/// Nơi lưu bản ghi log đã chuẩn hóa theo từng nhóm, tách khỏi kho trạng thái chung.
pub trait LogArchive {
    fn append(&mut self, input: &PersistInput) -> Result<(), String>;
}

#[derive(Default)]
pub struct StoreStats {
    pub raw_count: usize,
    pub analyzed_count: usize,
    pub pending_count: usize,
    pub tracked_count: usize,
    pub last_event: Option<DateTime<Utc>>,
    pub bytes: u64,
    pub collectors: Vec<CollectorHealth>,
    pub tracked: Vec<TrackedEntity>,
}

pub fn event_seen(event: &Normalized, rows: &[PersistInput]) -> bool {
    rows.iter().any(|row| {
        row.normalized.agent_id == event.agent_id
            && row.normalized.source == event.source
            && row.normalized.source_event_key == event.source_event_key
    })
}
