use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;

use crate::{
    Model::{
        Checkpoint, CollectorHealth, Finding, PersistInput, ProcessNode, ProcessTrace, RawEnvelope,
        TcpFlow, TraceEvent, TrackedEntity,
    },
    Repository::{Repository, RepositoryReader, StoreStats},
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
    // Never unlink the lock file: doing so permits locking two different inodes.
    _writer_lock: Option<File>,
    failed: bool,
}

/// Immutable committed snapshot; opening it never creates, deletes or repairs files.
pub struct JsonSnapshot {
    inner: JsonStore,
}
impl JsonSnapshot {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        let doc = read_document(&path)?.ok_or("no readable committed state")?;
        Ok(Self {
            inner: JsonStore {
                path,
                doc,
                _writer_lock: None,
                failed: false,
            },
        })
    }
}
impl RepositoryReader for JsonSnapshot {
    fn trace_process(&self, selector: &str) -> Result<ProcessTrace, String> {
        self.inner.trace_process(selector)
    }
    fn stats(&self) -> StoreStats {
        self.inner.stats()
    }
}
impl JsonStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let requested = path.as_ref();
        let parent = requested
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let path = fs::canonicalize(parent)
            .map_err(|e| e.to_string())?
            .join(requested.file_name().ok_or("state path has no file name")?);
        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let writer_lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(PathBuf::from(lock_name))
            .map_err(|e| format!("open writer lock: {e}"))?;
        writer_lock
            .try_lock()
            .map_err(|e| format!("state writer already active or lock unavailable: {e}"))?;
        let tmp = temporary_path(&path);
        let main_doc = read_document(&path)?;
        let tmp_doc = read_document(&tmp)?;

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
        let mut store = Self {
            path,
            doc,
            _writer_lock: Some(writer_lock),
            failed: false,
        };
        if !store.path.exists() {
            store.save()?;
        }
        Ok(store)
    }
    pub fn save_health(&mut self, health: CollectorHealth) -> Result<(), String> {
        self.writable()?;
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
        self.writable()?;
        if record_id <= self.checkpoint(id) {
            return Ok(());
        }
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
        self.writable()?;
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
        self.writable()?;
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
        self.writable()?;
        let result = self.save_inner();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn writable(&self) -> Result<(), String> {
        if self.failed || self._writer_lock.is_none() {
            Err("writer unavailable after failed commit; drop and reopen to recover".into())
        } else {
            Ok(())
        }
    }
    fn save_inner(&mut self) -> Result<(), String> {
        // Recovery ordering must survive a wall-clock correction backwards.
        let next = self
            .doc
            .updated_at
            .map(|previous| {
                previous
                    .checked_add_signed(chrono::Duration::nanoseconds(1))
                    .ok_or("state timestamp cannot advance")
            })
            .transpose()?;
        self.doc.updated_at = Some(Utc::now().max(next.unwrap_or(DateTime::<Utc>::MIN_UTC)));
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
        drop(file);
        replace_file(&tmp, &self.path)
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

fn read_document(path: &Path) -> Result<Option<Document>, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    let doc: Option<Document> = serde_json::from_slice(&bytes).ok();
    if doc
        .as_ref()
        .is_some_and(|doc| doc.schema_version != schema_version())
    {
        return Err(format!("unsupported state schema at {}", path.display()));
    }
    Ok(doc)
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
    // Windows may deny replacement while a short-lived reader or antivirus has
    // the destination open. Keep the synced temporary state intact on failure.
    for attempt in 0..100 {
        let ok = unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok != 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(5 | 32 | 33)) || attempt == 99 {
            return Err(error.to_string());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    unreachable!()
}

impl Repository for JsonStore {
    fn close_case(&mut self, id: &str, reason: &str) -> Result<(), String> {
        self.close_case_inner(id, reason)
    }
    fn append_raw(&mut self, raw: RawEnvelope) -> Result<(), String> {
        self.writable()?;
        if self.insert_raw(raw) {
            self.save()
        } else {
            Ok(())
        }
    }
    fn persist(&mut self, input: PersistInput) -> Result<(), String> {
        self.writable()?;
        if self.persist_record(input) {
            self.save()
        } else {
            Ok(())
        }
    }
}

impl RepositoryReader for JsonStore {
    fn stats(&self) -> StoreStats {
        self.stats_inner()
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
}
impl JsonStore {
    fn close_case_inner(&mut self, id: &str, reason: &str) -> Result<(), String> {
        self.writable()?;
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
}
impl JsonStore {
    fn stats_inner(&self) -> StoreStats {
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
        self.writable()?;
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

    fn test_path() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("crystal-r1-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir.join("pbra.json")
    }

    #[test]
    fn unsupported_schema_is_preserved() {
        let path = test_path();
        let bytes = br#"{"schema_version":999,"future_data":[1]}"#;
        fs::write(&path, bytes).unwrap();
        assert!(JsonStore::open(&path).is_err());
        assert!(JsonSnapshot::open(&path).is_err());
        assert_eq!(fs::read(path).unwrap(), bytes);
    }

    #[test]
    fn different_state_names_have_independent_temporary_files() {
        let path = test_path();
        let other = path.with_extension("backup");
        assert_ne!(temporary_path(&path), temporary_path(&other));
        let mut first = JsonStore::open(&path).unwrap();
        let mut second = JsonStore::open(&other).unwrap();
        first.save_checkpoint("System", 42).unwrap();
        second.save_checkpoint("System", 99).unwrap();
        assert_eq!(
            JsonSnapshot::open(path).unwrap().inner.checkpoint("System"),
            42
        );
        assert_eq!(
            JsonSnapshot::open(other)
                .unwrap()
                .inner
                .checkpoint("System"),
            99
        );
    }

    #[test]
    fn commit_timestamp_increases_when_clock_goes_backwards() {
        let path = test_path();
        let mut writer = JsonStore::open(&path).unwrap();
        let future = Utc::now() + chrono::Duration::days(1);
        writer.doc.updated_at = Some(future);
        writer.save_checkpoint("System", 42).unwrap();
        assert!(writer.doc.updated_at.unwrap() > future);
    }

    #[test]
    fn writer_exclusion_and_release_preserve_checkpoint() {
        let path = test_path();
        let mut writer = JsonStore::open(&path).unwrap();
        writer.save_checkpoint("Security", 42).unwrap();
        assert!(JsonStore::open(&path).is_err());
        assert!(JsonStore::open(path.parent().unwrap().join(".").join("pbra.json")).is_err());
        let reader = JsonSnapshot::open(&path).unwrap();
        assert_eq!(reader.inner.checkpoint("Security"), 42);
        writer.save_checkpoint("Security", 43).unwrap();
        assert_eq!(reader.inner.checkpoint("Security"), 42); // stable snapshot
        drop(writer);
        let mut reopened = JsonStore::open(&path).unwrap();
        assert_eq!(reopened.checkpoint("Security"), 43);
        reopened.save_checkpoint("Security", 1).unwrap();
        assert_eq!(reopened.checkpoint("Security"), 43);
    }

    #[test]
    fn readers_never_recover_delete_or_create_files() {
        let path = test_path();
        assert!(JsonSnapshot::open(&path).is_err());
        assert!(!path.exists());
        assert!(!path.with_extension("json.lock").exists());
        let mut writer = JsonStore::open(&path).unwrap();
        writer.save_checkpoint("System", 10).unwrap();
        let main = fs::read(&path).unwrap();
        let temporary = temporary_path(&path);
        fs::write(&temporary, b"incomplete").unwrap();
        let reader = JsonSnapshot::open(&path).unwrap();
        reader.stats();
        assert!(reader.trace_process("missing").is_err());
        assert_eq!(fs::read(&path).unwrap(), main);
        assert_eq!(fs::read(&temporary).unwrap(), b"incomplete");
    }

    #[test]
    fn corrupt_state_is_not_replaced_with_empty_storage() {
        let path = test_path();
        fs::write(&path, b"corrupt main").unwrap();
        fs::write(temporary_path(&path), b"corrupt temp").unwrap();
        assert!(JsonStore::open(&path).is_err());
        assert!(JsonSnapshot::open(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"corrupt main");
        assert_eq!(fs::read(temporary_path(&path)).unwrap(), b"corrupt temp");
        // Failed open must release the writer lock.
        fs::write(&path, serde_json::to_vec(&Document::default()).unwrap()).unwrap();
        assert!(JsonStore::open(&path).is_ok());
    }

    #[test]
    fn io_error_is_not_treated_as_missing_state() {
        let path = test_path();
        fs::create_dir(&path).unwrap();
        fs::write(
            temporary_path(&path),
            serde_json::to_vec(&Document::default()).unwrap(),
        )
        .unwrap();
        assert!(JsonStore::open(&path).is_err());
        assert!(path.is_dir());
        assert!(temporary_path(&path).is_file());
    }

    #[test]
    fn failed_commit_requires_reopen_before_retry() {
        let path = test_path();
        let mut writer = JsonStore::open(&path).unwrap();
        fs::create_dir(temporary_path(&path)).unwrap();
        assert!(writer.save_checkpoint("System", 10).is_err());
        fs::remove_dir(temporary_path(&path)).unwrap();
        assert!(writer.save_checkpoint("System", 10).is_err());
        assert!(
            writer
                .commit_event(Default::default(), Default::default(), None, false)
                .is_err()
        );
        drop(writer);
        assert_eq!(JsonStore::open(&path).unwrap().checkpoint("System"), 0);
    }

    #[test]
    fn valid_main_discards_incomplete_or_stale_temporary_state() {
        let path = test_path();
        let mut writer = JsonStore::open(&path).unwrap();
        writer.save_checkpoint("System", 42).unwrap();
        drop(writer);
        for bytes in [
            b"incomplete".to_vec(),
            serde_json::to_vec(&Document {
                updated_at: None,
                ..Document::default()
            })
            .unwrap(),
        ] {
            fs::write(temporary_path(&path), bytes).unwrap();
            let reopened = JsonStore::open(&path).unwrap();
            assert_eq!(reopened.checkpoint("System"), 42);
            assert!(!temporary_path(&path).exists());
        }
    }

    #[test]
    fn temporary_only_state_is_recovered_by_writer_only() {
        let path = test_path();
        let doc = Document {
            checkpoints: HashMap::from([(
                "System".into(),
                Checkpoint {
                    record_id: 42,
                    updated_at: Utc::now(),
                },
            )]),
            ..Document::default()
        };
        fs::write(temporary_path(&path), serde_json::to_vec(&doc).unwrap()).unwrap();
        assert!(JsonSnapshot::open(&path).is_err());
        assert!(!path.exists());
        assert_eq!(JsonStore::open(&path).unwrap().checkpoint("System"), 42);
    }

    #[test]
    fn concurrent_snapshots_preserve_all_committed_events() {
        let path = test_path();
        let mut writer = JsonStore::open(&path).unwrap();
        let reader_path = path.clone();
        let reader = std::thread::spawn(move || {
            for _ in 0..50 {
                let s = JsonSnapshot::open(&reader_path).unwrap().stats();
                assert_eq!(s.raw_count, s.analyzed_count);
            }
        });
        for id in 1..=25 {
            let raw = RawEnvelope {
                event_id: id.to_string(),
                agent_id: "test".into(),
                source: "System".into(),
                source_event_key: format!("System|{id}"),
                ..Default::default()
            };
            let input = PersistInput {
                normalized: crate::Model::Normalized {
                    event_id: raw.event_id.clone(),
                    agent_id: raw.agent_id.clone(),
                    source: raw.source.clone(),
                    source_event_key: raw.source_event_key.clone(),
                    ..Default::default()
                },
                ..Default::default()
            };
            writer
                .commit_event(raw, input, Some(("System".into(), id)), true)
                .unwrap();
        }
        reader.join().unwrap();
        drop(writer);
        let reopened = JsonStore::open(path).unwrap();
        assert_eq!(reopened.stats().raw_count, 25);
        assert_eq!(reopened.stats().analyzed_count, 25);
        assert_eq!(reopened.checkpoint("System"), 25);
    }

    #[test]
    fn child_writer_probe() {
        let Some(path) = std::env::var_os("CRYSTAL_TEST_WRITER_PATH") else {
            return;
        };
        if std::env::var_os("CRYSTAL_TEST_ABORT").is_some() {
            let _writer = JsonStore::open(path).unwrap();
            std::process::exit(0); // bypass Drop, like a terminated service
        }
        assert!(JsonStore::open(path).is_err());
    }

    #[test]
    fn cross_process_exclusion_and_exit_release() {
        let path = test_path();
        let writer = JsonStore::open(&path).unwrap();
        let child = || {
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.args(["--exact", "Store::JsonFileStore::tests::child_writer_probe"])
                .env("CRYSTAL_TEST_WRITER_PATH", &path);
            cmd
        };
        assert!(child().status().unwrap().success());
        drop(writer);
        assert!(
            child()
                .env("CRYSTAL_TEST_ABORT", "1")
                .status()
                .unwrap()
                .success()
        );
        assert!(JsonStore::open(&path).is_ok());
    }

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
