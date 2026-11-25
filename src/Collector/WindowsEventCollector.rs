use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io::Read,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    sync::{Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};

use crate::{
    Config::Config,
    Model::{NetworkFacts, ProcessFacts, RawEnvelope, SCHEMA_VERSION},
    Store::JsonStore,
};

static PREVIOUS_PROCESSES: OnceLock<Mutex<HashMap<i64, ProcessFacts>>> = OnceLock::new();

pub fn collect_event_logs(
    cfg: &Config,
    store: &JsonStore,
    agent_id: &str,
    stop: &AtomicBool,
) -> Result<Vec<RawEnvelope>, String> {
    let mut channels: HashMap<String, Vec<u32>> = HashMap::new();
    for group in &cfg.event_groups {
        let ids = channels.entry(group.channel.clone()).or_default();
        for id in &group.event_ids {
            if !ids.contains(id) {
                ids.push(*id);
            }
        }
    }
    let mut out = Vec::new();
    for (channel, ids) in channels {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let checkpoint = store.checkpoint(&channel);
        let id_query = ids
            .iter()
            .map(|id| format!("EventID={id}"))
            .collect::<Vec<_>>()
            .join(" or ");
        let xpath = if checkpoint > 0 {
            format!("*[System[(EventRecordID > {checkpoint}) and ({id_query})]]")
        } else {
            format!("*[System[({id_query})]]")
        };
        let query = format!("/q:{xpath}");
        let mut command = Command::new("wevtutil.exe");
        command.args(["qe", &channel, &query, "/rd:false", "/c:500", "/f:xml"]);
        let output = run_command_interruptible(command, stop)?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            if detail.to_ascii_lowercase().contains("no events")
                || detail.to_ascii_lowercase().contains("no matching events")
            {
                continue;
            }
            if detail.contains("15007") {
                continue;
            }
            if detail.to_ascii_lowercase().contains("access is denied") {
                return Err(format!("insufficient rights for {channel}"));
            }
            continue;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        for xml in split_events(&text) {
            let record_id = tag_value(&xml, "EventRecordID")
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            if record_id <= checkpoint {
                continue;
            }
            let event_time = tag_value(&xml, "TimeCreated")
                .and_then(|_| attribute_value(&xml, "SystemTime"))
                .and_then(|v| {
                    DateTime::parse_from_rfc3339(&v)
                        .ok()
                        .map(|d| d.with_timezone(&Utc))
                })
                .unwrap_or_else(Utc::now);
            let event_uid = format!(
                "{channel}:{record_id}:{}",
                tag_value(&xml, "EventID").unwrap_or_default()
            );
            out.push(RawEnvelope {
                event_id: event_uid.clone(),
                agent_id: agent_id.into(),
                source: channel.clone(),
                source_event_key: format!("{channel}|{record_id}"),
                event_time,
                observed_at: Utc::now(),
                schema_version: SCHEMA_VERSION,
                kind: "winevent".into(),
                snapshot: false,
                xml: Some(xml),
                payload: None,
            });
        }
    }
    Ok(out)
}

pub fn collect_snapshots(
    cfg: &Config,
    agent_id: &str,
    stop: &AtomicBool,
) -> Result<Vec<RawEnvelope>, String> {
    let script = r#"$p=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine); $n=@(Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object OwningProcess,LocalAddress,LocalPort,RemoteAddress,RemotePort,State); @{processes=$p;tcp=$n} | ConvertTo-Json -Depth 5 -Compress"#;
    let mut command = Command::new("powershell.exe");
    command.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]);
    let output = run_command_interruptible(command, stop)?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("parse PowerShell snapshot JSON: {e}"))?;
    let now = Utc::now();
    let processes = parse_processes(value.get("processes"), cfg);
    let network = parse_network(value.get("tcp"));
    let mut out = Vec::new();
    let state = PREVIOUS_PROCESSES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut previous = state.lock().map_err(|_| "process snapshot lock poisoned")?;
    if !previous.is_empty() {
        for (pid, p) in &processes {
            if !previous.contains_key(pid) {
                let mut p = p.clone();
                p.action = Some("create".into());
                out.push(snapshot_process(agent_id, &p, now));
            }
        }
        for (pid, p) in previous.iter() {
            if !processes.contains_key(pid) {
                let mut p = p.clone();
                p.action = Some("terminate".into());
                p.ended_at = Some(now);
                out.push(snapshot_process(agent_id, &p, now));
            }
        }
    }
    *previous = processes;
    drop(previous);
    for n in network {
        let key = format!(
            "snapshot|tcp|{}|{}|{}|{}|{}|{}",
            n.pid,
            n.local_ip.as_deref().unwrap_or(""),
            n.local_port,
            n.remote_ip.as_deref().unwrap_or(""),
            n.remote_port,
            n.state.as_deref().unwrap_or("")
        );
        out.push(RawEnvelope {
            event_id: uuid::Uuid::new_v4().to_string(),
            agent_id: agent_id.into(),
            source: "snapshot.network".into(),
            source_event_key: key,
            event_time: now,
            observed_at: now,
            schema_version: SCHEMA_VERSION,
            kind: "network".into(),
            snapshot: true,
            xml: None,
            payload: Some(json!({"network":n})),
        });
    }
    Ok(out)
}

fn run_command_interruptible(mut command: Command, stop: &AtomicBool) -> Result<Output, String> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start collector command: {error}"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "collector stdout pipe is unavailable".to_owned())?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| "collector stderr pipe is unavailable".to_owned())?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let started = Instant::now();
    let timeout = Duration::from_secs(120);

    let status = loop {
        if stop.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err("collector command interrupted by service shutdown".into());
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err("collector command exceeded the 120-second timeout".into());
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(format!("wait for collector command: {error}"));
            }
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| "collector stdout reader stopped unexpectedly".to_owned())?
        .map_err(|error| format!("read collector stdout: {error}"))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "collector stderr reader stopped unexpectedly".to_owned())?
        .map_err(|error| format!("read collector stderr: {error}"))?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn parse_processes(value: Option<&Value>, cfg: &Config) -> HashMap<i64, ProcessFacts> {
    as_array(value)
        .into_iter()
        .filter_map(|v| {
            let pid = v.get("ProcessId")?.as_i64()?;
            let image = v
                .get("ExecutablePath")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            let cmd = v
                .get("CommandLine")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            Some((
                pid,
                ProcessFacts {
                    pid,
                    ppid: v
                        .get("ParentProcessId")
                        .and_then(Value::as_i64)
                        .unwrap_or(0),
                    image_name: image
                        .as_deref()
                        .and_then(|s| s.rsplit(['\\', '/']).next())
                        .map(str::to_owned),
                    image_path: image,
                    command_line: if cfg.collect_command_line { cmd } else { None },
                    ..Default::default()
                },
            ))
        })
        .collect()
}
fn parse_network(value: Option<&Value>) -> Vec<NetworkFacts> {
    as_array(value)
        .into_iter()
        .filter_map(|v| {
            Some(NetworkFacts {
                protocol: "tcp".into(),
                direction: None,
                local_ip: v.get("LocalAddress")?.as_str().map(str::to_owned),
                local_port: v.get("LocalPort").and_then(Value::as_u64).unwrap_or(0) as u16,
                remote_ip: v
                    .get("RemoteAddress")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                remote_port: v.get("RemotePort").and_then(Value::as_u64).unwrap_or(0) as u16,
                state: v.get("State").and_then(Value::as_str).map(str::to_owned),
                pid: v.get("OwningProcess").and_then(Value::as_i64).unwrap_or(0),
                ..Default::default()
            })
        })
        .collect()
}
fn as_array(value: Option<&Value>) -> Vec<Value> {
    match value {
        Some(Value::Array(a)) => a.clone(),
        Some(Value::Object(_)) => vec![value.unwrap().clone()],
        _ => vec![],
    }
}
fn snapshot_process(agent_id: &str, p: &ProcessFacts, now: DateTime<Utc>) -> RawEnvelope {
    RawEnvelope {
        event_id: uuid::Uuid::new_v4().to_string(),
        agent_id: agent_id.into(),
        source: "snapshot.process".into(),
        source_event_key: format!(
            "snapshot|process|{}|{}|{}",
            p.pid,
            p.action.as_deref().unwrap_or(""),
            now.timestamp()
        ),
        event_time: now,
        observed_at: now,
        schema_version: SCHEMA_VERSION,
        kind: "process".into(),
        snapshot: true,
        xml: None,
        payload: Some(json!({"process":p})),
    }
}
fn split_events(text: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut cursor = 0;
    while let Some(relative) = text[cursor..].find("<Event") {
        let start = cursor + relative;
        let Some(end_rel) = text[start..].find("</Event>") else {
            break;
        };
        let end = start + end_rel + 8;
        result.push(text[start..end].to_owned());
        cursor = end;
    }
    result
}
fn tag_value(xml: &str, tag: &str) -> Option<String> {
    let start_tag = format!("<{tag}>");
    let end_tag = format!("</{tag}>");
    let start = xml.find(&start_tag)? + start_tag.len();
    let end = start + xml[start..].find(&end_tag)?;
    Some(xml[start..end].trim().to_owned())
}
fn attribute_value(xml: &str, attr: &str) -> Option<String> {
    let idx = xml.find("<TimeCreated")?;
    let head = &xml[idx..xml[idx..].find('>')? + idx];
    let key = format!("{attr}=\"");
    let start = head.find(&key)? + key.len();
    let end = start + head[start..].find('"')?;
    Some(head[start..end].to_owned())
}
