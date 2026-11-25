use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;

use crate::{
    Model::{
        Checkpoint, CollectorHealth, Finding, PersistInput, ProcessNode, ProcessTrace, RawEnvelope,
        TcpFlow, TraceEvent, TrackedEntity,
    },
    Repository::{Repository, StoreStats},
};

#[derive(Clone, Serialize, Deserialize)]
struct RawRecord {
    envelope: RawEnvelope,
    #[serde(default)]
    processed: bool,
    #[serde(default)]
    archive_written: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    processed_at: Option<DateTime<Utc>>,
}
#[derive(Clone, Serialize, Deserialize)]
struct AgentRecord {
    id: String,
    host: String,
    os: String,
    version: String,
    enrolled_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    status: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct Transition {
    id: String,
    entity_id: String,
    from: String,
    to: String,
    actor: String,
    reason: String,
    at: DateTime<Utc>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct AnalyzedRecord {
    pub data: PersistInput,
}

#[derive(Serialize, Deserialize)]
struct Document {
    #[serde(default = "schema_version")]
    schema_version: u32,
    #[serde(default)]
    updated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    agents: Vec<AgentRecord>,
    #[serde(default)]
    raw_events: Vec<RawRecord>,
    #[serde(default)]
    analyzed_events: Vec<AnalyzedRecord>,
    #[serde(default)]
    checkpoints: HashMap<String, Checkpoint>,
    #[serde(default)]
    collectors: HashMap<String, CollectorHealth>,
    #[serde(default)]
    tracked_entities: Vec<TrackedEntity>,
    #[serde(default)]
    findings: HashMap<String, Vec<Finding>>,
    #[serde(default)]
    transitions: Vec<Transition>,
}
impl Default for Document {
    fn default() -> Self {
        Self {
            schema_version: 1,
            updated_at: Some(Utc::now()),
            agents: vec![],
            raw_events: vec![],
            analyzed_events: vec![],
            checkpoints: HashMap::new(),
            collectors: HashMap::new(),
            tracked_entities: vec![],
            findings: HashMap::new(),
            transitions: vec![],
        }
    }
}
fn schema_version() -> u32 {
    1
}

fn raw_record_matches(record: &RawRecord, event: &RawEnvelope) -> bool {
    record.envelope.event_id == event.event_id
        || (record.envelope.agent_id == event.agent_id
            && record.envelope.source == event.source
            && record.envelope.source_event_key == event.source_event_key)
}

pub struct JsonStore {
    path: PathBuf,
    doc: Document,
}
impl JsonStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let tmp = temporary_path(&path);
        let main_doc = read_document(&path);
        let tmp_doc = read_document(&tmp);

        // Sau sự cố giữa lúc ghi, file tạm có thể chứa checkpoint mới hơn file chính.
        let (doc, recover_tmp) = match (main_doc, tmp_doc) {
            (Some(main), Some(temp)) if is_newer(&temp, &main) => (temp, true),
            (Some(main), _) => (main, false),
            (None, Some(temp)) => (temp, true),
            (None, None) if path.exists() || tmp.exists() => {
                return Err("không đọc được cả file trạng thái chính lẫn file tạm".into());
            }
            (None, None) => (Document::default(), false),
        };
        if recover_tmp {
            replace_file(&tmp, &path)?;
        } else if tmp.exists() {
            fs::remove_file(&tmp).map_err(|e| format!("không xóa được file tạm cũ: {e}"))?;
        }
        let mut store = Self { path, doc };
        if !store.path.exists() {
            store.save()?;
        }
        Ok(store)
    }
    pub fn save_health(&mut self, health: CollectorHealth) -> Result<(), String> {
        if self
            .doc
            .collectors
            .get(&health.collector_id)
            .is_some_and(|current| {
                current.status == health.status
                    && current.reason == health.reason
                    && current.events_seen == health.events_seen
                    && current.last_error == health.last_error
            })
        {
            return Ok(());
        }
        self.doc
            .collectors
            .insert(health.collector_id.clone(), health);
        self.save()
    }
    pub fn save_checkpoint(&mut self, id: &str, record_id: i64) -> Result<(), String> {
        self.doc.checkpoints.insert(
            id.into(),
            Checkpoint {
                record_id,
                updated_at: Utc::now(),
            },
        );
        self.save()
    }
    pub fn checkpoint(&self, id: &str) -> i64 {
        self.doc
            .checkpoints
            .get(id)
            .map(|c| c.record_id)
            .unwrap_or(0)
    }
    pub fn category_log_written(&self, event: &RawEnvelope) -> bool {
        self.doc
            .raw_events
            .iter()
            .find(|record| raw_record_matches(record, event))
            .is_some_and(|record| record.archive_written)
    }
    pub fn commit_event(
        &mut self,
        raw: RawEnvelope,
        input: PersistInput,
        checkpoint: Option<(String, i64)>,
        archive_written: bool,
    ) -> Result<(), String> {
        let mut changed = self.insert_raw(raw.clone());
        if archive_written
            && let Some(record) = self
                .doc
                .raw_events
                .iter_mut()
                .find(|record| raw_record_matches(record, &raw))
            && !record.archive_written
        {
            record.archive_written = true;
            changed = true;
        }
        changed |= self.persist_record(input);
        if let Some((channel, record_id)) = checkpoint
            && record_id > self.checkpoint(&channel)
        {
            self.doc.checkpoints.insert(
                channel,
                Checkpoint {
                    record_id,
                    updated_at: Utc::now(),
                },
            );
            changed = true;
        }
        if changed { self.save() } else { Ok(()) }
    }
    fn insert_raw(&mut self, raw: RawEnvelope) -> bool {
        if self
            .doc
            .raw_events
            .iter()
            .any(|record| raw_record_matches(record, &raw))
        {
            return false;
        }
        self.doc.raw_events.push(RawRecord {
            envelope: raw,
            processed: false,
            archive_written: false,
            processed_at: None,
        });
        true
    }
    fn persist_record(&mut self, input: PersistInput) -> bool {
        let key = (
            &input.normalized.agent_id,
            &input.normalized.source,
            &input.normalized.source_event_key,
        );
        if self.doc.analyzed_events.iter().any(|record| {
            record.data.normalized.agent_id == *key.0
                && record.data.normalized.source == *key.1
                && record.data.normalized.source_event_key == *key.2
        }) {
            return false;
        }
        if let Some(raw) = self
            .doc
            .raw_events
            .iter_mut()
            .find(|record| record.envelope.event_id == input.normalized.event_id)
        {
            raw.processed = true;
            raw.processed_at = Some(Utc::now());
        }
        let now = if input.normalized.event_time == DateTime::<Utc>::MIN_UTC {
            input.normalized.observed_at
        } else {
            input.normalized.event_time
        };
        if input.track_process && !input.process_instance_id.is_empty() {
            self.upsert_entity(&input, "process", &input.process_instance_id, now);
        }
        if input.track_ip && !input.ip_key.is_empty() {
            self.upsert_entity(&input, "ip", &input.ip_key, now);
        }
        self.doc
            .analyzed_events
            .push(AnalyzedRecord { data: input });
        true
    }
    pub fn ensure_agent(&mut self, id: &str, host: &str) -> Result<(), String> {
        let now = Utc::now();
        if let Some(a) = self.doc.agents.iter_mut().find(|a| a.id == id) {
            a.last_seen_at = now;
            a.status = "running".into();
        } else {
            self.doc.agents.push(AgentRecord {
                id: id.into(),
                host: host.into(),
                os: std::env::consts::OS.into(),
                version: crate::Model::AGENT_VERSION.into(),
                enrolled_at: now,
                last_seen_at: now,
                status: "running".into(),
            });
        }
        self.save()
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    fn save(&mut self) -> Result<(), String> {
        self.doc.updated_at = Some(Utc::now());
        let tmp = temporary_path(&self.path);
        let data = serde_json::to_vec_pretty(&self.doc).map_err(|e| e.to_string())?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)
            .map_err(|e| e.to_string())?;
        file.write_all(&data).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        replace_file(&tmp, &self.path)
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut tmp = path.to_path_buf();
    tmp.set_extension("json.tmp");
    tmp
}

fn read_document(path: &Path) -> Option<Document> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn is_newer(candidate: &Document, current: &Document) -> bool {
    candidate.updated_at > current.updated_at
}

#[cfg(not(windows))]
fn replace_file(from: &Path, to: &Path) -> Result<(), String> {
    fs::rename(from, to).map_err(|e| e.to_string())
}

#[cfg(windows)]
fn replace_file(from: &Path, to: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    // Giữ thao tác thay file nguyên tử trên Windows và yêu cầu hệ điều hành flush metadata.
    let ok = unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

impl Repository for JsonStore {
    fn append_raw(&mut self, raw: RawEnvelope) -> Result<(), String> {
        if self.insert_raw(raw) {
            self.save()
        } else {
            Ok(())
        }
    }
    fn persist(&mut self, input: PersistInput) -> Result<(), String> {
        if self.persist_record(input) {
            self.save()
        } else {
            Ok(())
        }
    }
    fn trace_process(&self, selector: &str) -> Result<ProcessTrace, String> {
        let mut trace = ProcessTrace {
            selector: selector.into(),
            ..Default::default()
        };
        let pid = selector.parse::<i64>().ok();
        let mut parent_map = HashMap::new();
        let mut included = HashMap::<String, bool>::new();
        let mut nodes = HashMap::<String, ProcessNode>::new();
        let mut seeds = Vec::new();
        for rec in &self.doc.analyzed_events {
            let row = &rec.data;
            if !row.process_instance_id.is_empty() && !row.parent_process_instance_id.is_empty() {
                parent_map.insert(
                    row.process_instance_id.clone(),
                    row.parent_process_instance_id.clone(),
                );
            }
            if let Some(p) = &row.normalized.process {
                let matches = p
                    .process_guid
                    .as_deref()
                    .is_some_and(|g| g.eq_ignore_ascii_case(selector))
                    || pid.is_some_and(|v| v == p.pid);
                if matches {
                    included.insert(row.process_instance_id.clone(), true);
                    seeds.push(row.process_instance_id.clone());
                    nodes.insert(
                        row.process_instance_id.clone(),
                        ProcessNode {
                            process_instance_id: row.process_instance_id.clone(),
                            parent_process_instance_id: row.parent_process_instance_id.clone(),
                            process: p.clone(),
                        },
                    );
                }
            }
        }
        if seeds.is_empty() {
            return Err(format!("no process records found for {selector}"));
        }
        for seed in seeds {
            let mut cursor = parent_map.get(&seed).cloned();
            while let Some(id) = cursor {
                if included.contains_key(&id) {
                    break;
                }
                included.insert(id.clone(), true);
                cursor = parent_map.get(&id).cloned();
            }
        }
        loop {
            let mut changed = false;
            for (child, parent) in &parent_map {
                if included.contains_key(parent) && !included.contains_key(child) {
                    included.insert(child.clone(), true);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        let mut flows: HashMap<String, usize> = HashMap::new();
        for rec in &self.doc.analyzed_events {
            let row = &rec.data;
            if !included.contains_key(&row.process_instance_id) {
                continue;
            }
            let n = &row.normalized;
            let ev = TraceEvent {
                event_id: n.event_id.clone(),
                event_type: n.event_type.clone(),
                source: n.source.clone(),
                event_time: n.event_time,
                process: n.process.clone(),
                network: n.network.clone(),
                risk_score: row.assessment.score,
                severity: row.assessment.severity.clone(),
            };
            trace.events.push(ev.clone());
            if let Some(p) = &n.process {
                nodes.insert(
                    row.process_instance_id.clone(),
                    ProcessNode {
                        process_instance_id: row.process_instance_id.clone(),
                        parent_process_instance_id: row.parent_process_instance_id.clone(),
                        process: p.clone(),
                    },
                );
            }
            if let Some(nw) = &n.network
                && nw.protocol.eq_ignore_ascii_case("tcp")
            {
                let key = format!(
                    "{}:{}|{}:{}",
                    nw.local_ip.as_deref().unwrap_or(""),
                    nw.local_port,
                    nw.remote_ip.as_deref().unwrap_or(""),
                    nw.remote_port
                );
                let idx = *flows.entry(key).or_insert_with(|| {
                    let idx = trace.tcp_flows.len();
                    trace.tcp_flows.push(TcpFlow {
                        protocol: nw.protocol.clone(),
                        local_ip: nw.local_ip.clone(),
                        local_port: nw.local_port,
                        remote_ip: nw.remote_ip.clone(),
                        remote_port: nw.remote_port,
                        events: vec![],
                    });
                    idx
                });
                trace.tcp_flows[idx].events.push(ev);
            }
        }
        trace.process_tree = nodes.into_values().collect();
        trace.process_tree.sort_by_key(|n| n.process.started_at);
        trace.events.sort_by_key(|e| e.event_time);
        for f in &mut trace.tcp_flows {
            f.events.sort_by_key(|e| e.event_time);
        }
        Ok(trace)
    }
    fn close_case(&mut self, id: &str, reason: &str) -> Result<(), String> {
        let entity = self
            .doc
            .tracked_entities
            .iter_mut()
            .find(|e| e.entity_id == id)
            .ok_or("case not found")?;
        let from = entity.status.clone();
        entity.status = "resolved".into();
        self.doc.transitions.push(Transition {
            id: Uuid::new_v4().to_string(),
            entity_id: id.into(),
            from,
            to: "resolved".into(),
            actor: "operator".into(),
            reason: reason.into(),
            at: Utc::now(),
        });
        self.save()
    }
    fn stats(&self) -> StoreStats {
        let bytes = fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        let tracked: Vec<_> = self
            .doc
            .tracked_entities
            .iter()
            .filter(|e| e.status == "open" || e.status == "watching")
            .cloned()
            .collect();
        StoreStats {
            raw_count: self.doc.raw_events.len(),
            analyzed_count: self.doc.analyzed_events.len(),
            pending_count: self.doc.raw_events.iter().filter(|r| !r.processed).count(),
            tracked_count: tracked.len(),
            last_event: self
                .doc
                .analyzed_events
                .iter()
                .map(|e| e.data.normalized.event_time)
                .max(),
            bytes,
            collectors: self.doc.collectors.values().cloned().collect(),
            tracked,
        }
    }
}

impl JsonStore {
    fn upsert_entity(&mut self, input: &PersistInput, kind: &str, key: &str, now: DateTime<Utc>) {
        let name = Uuid::new_v5(
            &Uuid::NAMESPACE_OID,
            format!("{}|{}|{}", input.normalized.agent_id, kind, key).as_bytes(),
        )
        .to_string();
        let status = if input.assessment.score >= 70 {
            "watching"
        } else {
            "open"
        };
        if let Some(entity) = self
            .doc
            .tracked_entities
            .iter_mut()
            .find(|e| e.entity_id == name)
        {
            entity.last_seen = now;
            if input.assessment.score >= entity.score {
                entity.score = input.assessment.score;
                entity.severity = input.assessment.severity.clone();
            }
            if entity.status == "resolved" {
                entity.status = status.into()
            }
            entity.findings.extend(input.assessment.findings.clone());
        } else {
            self.doc.tracked_entities.push(TrackedEntity {
                entity_id: name,
                agent_id: input.normalized.agent_id.clone(),
                entity_type: kind.into(),
                entity_key: key.into(),
                status: status.into(),
                severity: input.assessment.severity.clone(),
                score: input.assessment.score,
                first_seen: now,
                last_seen: now,
                findings: input.assessment.findings.clone(),
            });
        }
    }
    pub fn retain(
        &mut self,
        raw_days: i64,
        norm_days: i64,
        resolved_days: i64,
    ) -> Result<(), String> {
        let now = Utc::now();
        let raw_cut = now - chrono::Duration::days(raw_days);
        let norm_cut = now - chrono::Duration::days(norm_days);
        let res_cut = now - chrono::Duration::days(resolved_days);
        let old_counts = (
            self.doc.raw_events.len(),
            self.doc.analyzed_events.len(),
            self.doc.tracked_entities.len(),
        );
        self.doc
            .raw_events
            .retain(|r| !r.processed || r.envelope.observed_at >= raw_cut);
        self.doc
            .analyzed_events
            .retain(|r| r.data.normalized.event_time >= norm_cut);
        self.doc.tracked_entities.retain(|e| {
            !(matches!(e.status.as_str(), "resolved" | "false_positive") && e.last_seen < res_cut)
        });
        let new_counts = (
            self.doc.raw_events.len(),
            self.doc.analyzed_events.len(),
            self.doc.tracked_entities.len(),
        );
        if old_counts != new_counts {
            self.save()
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_newer_valid_temporary_state() {
        let dir = std::env::temp_dir().join(format!("crystal-store-recovery-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pbra.json");

        let mut store = JsonStore::open(&path).unwrap();
        store.save_checkpoint("System", 100).unwrap();
        let recovered = Document {
            updated_at: Some(Utc::now() + chrono::Duration::seconds(10)),
            checkpoints: HashMap::from([(
                "System".to_owned(),
                Checkpoint {
                    record_id: 101,
                    updated_at: Utc::now(),
                },
            )]),
            ..Document::default()
        };
        fs::write(
            temporary_path(&path),
            serde_json::to_vec(&recovered).unwrap(),
        )
        .unwrap();
        drop(store);

        let reopened = JsonStore::open(&path).unwrap();
        assert_eq!(reopened.checkpoint("System"), 101);
        assert!(!temporary_path(&path).exists());
        drop(reopened);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn repeated_archived_snapshot_does_not_add_another_record() {
        let dir = std::env::temp_dir().join(format!("crystal-snapshot-dedupe-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pbra.json");
        let mut store = JsonStore::open(&path).unwrap();
        let event_time = Utc::now();
        let raw = RawEnvelope {
            event_id: "snapshot-1".into(),
            agent_id: "agent-test".into(),
            source: "snapshot.network".into(),
            source_event_key: "snapshot|tcp|pid-22".into(),
            event_time,
            observed_at: event_time,
            kind: "network".into(),
            snapshot: true,
            ..Default::default()
        };
        let input = PersistInput {
            normalized: crate::Model::Normalized {
                event_id: raw.event_id.clone(),
                agent_id: raw.agent_id.clone(),
                event_type: raw.kind.clone(),
                source: raw.source.clone(),
                source_event_key: raw.source_event_key.clone(),
                event_time,
                observed_at: event_time,
                ..Default::default()
            },
            ..Default::default()
        };
        store
            .commit_event(raw.clone(), input.clone(), None, true)
            .unwrap();
        assert!(store.category_log_written(&raw));

        let mut replay = raw.clone();
        replay.event_id = "snapshot-replayed".into();
        store.commit_event(replay, input, None, true).unwrap();

        let stats = store.stats();
        assert_eq!(stats.raw_count, 1);
        assert_eq!(stats.analyzed_count, 1);
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }
}
