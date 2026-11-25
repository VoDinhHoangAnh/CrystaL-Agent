use chrono::{DateTime, Utc};
use quick_xml::{Reader, events::Event};
use std::collections::HashMap;

use crate::{
    Config::Config,
    Model::{NetworkFacts, Normalized, ProcessFacts, RawEnvelope, SCHEMA_VERSION, WindowsFacts},
    Privacy,
};

type EventFields = HashMap<String, String>;
type ParsedEvent = (EventFields, EventFields);

pub fn normalize(raw: &RawEnvelope, cfg: &Config) -> Normalized {
    let mut out = Normalized {
        event_id: raw.event_id.clone(),
        agent_id: raw.agent_id.clone(),
        event_type: raw.kind.clone(),
        source: raw.source.clone(),
        source_event_key: raw.source_event_key.clone(),
        event_time: raw.event_time,
        observed_at: raw.observed_at,
        schema_version: SCHEMA_VERSION,
        snapshot: raw.snapshot,
        ..Default::default()
    };
    if let Some(xml) = raw.xml.as_deref()
        && let Ok((system, data)) = parse_event_xml(xml)
    {
        let event_id = parse_number(system.get("EventID").map(String::as_str).unwrap_or(""));
        let event_fields = data
            .iter()
            .map(|(k, v)| (k.clone(), Privacy::redact(v).0))
            .collect();
        out.windows = Some(WindowsFacts {
            provider: system.get("Provider").cloned().unwrap_or_default(),
            channel: system.get("Channel").cloned().unwrap_or_default(),
            event_code: event_id,
            record_id: parse_number(
                system
                    .get("EventRecordID")
                    .map(String::as_str)
                    .unwrap_or(""),
            ),
            computer: system.get("Computer").cloned(),
            event_data: event_fields,
        });
        out.event_type = "winevent".into();
        map_event(&mut out, &system, &data, event_id);
    }
    if let Some(payload) = &raw.payload {
        if let Some(value) = payload.get("process")
            && let Ok(p) = serde_json::from_value::<ProcessFacts>(value.clone())
        {
            out.process = Some(p);
            out.event_type = "process".into();
        }
        if let Some(value) = payload.get("network")
            && let Ok(n) = serde_json::from_value::<NetworkFacts>(value.clone())
        {
            out.network = Some(n);
            if out.event_type.is_empty() {
                out.event_type = "network".into();
            }
        }
    }
    if let Some(p) = out.process.as_mut() {
        if !cfg.collect_command_line {
            p.command_line = None;
        }
        if let Some(cmd) = p.command_line.as_deref() {
            let (safe, found) = Privacy::redact(cmd);
            if cfg.redact_command_line || found {
                p.command_line = Some(safe);
            }
            out.secret_indicator = found;
        }
        if p.image_name.is_none() {
            p.image_name = p
                .image_path
                .as_deref()
                .and_then(|s| s.rsplit(['\\', '/']).next())
                .map(str::to_owned);
        }
    }
    out
}

fn parse_event_xml(xml: &str) -> Result<ParsedEvent, Box<dyn std::error::Error>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut stack = Vec::<String>::new();
    let mut system = HashMap::new();
    let mut data = HashMap::new();
    let mut current_name = None;
    loop {
        match reader.read_event()? {
            Event::Start(e) => {
                let tag = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if tag == "Provider"
                    && let Some(attr) = e
                        .attributes()
                        .flatten()
                        .find(|a| a.key.local_name().as_ref() == b"Name")
                {
                    system.insert(
                        "Provider".into(),
                        attr.decode_and_unescape_value(reader.decoder())?
                            .into_owned(),
                    );
                }
                if tag == "Data" {
                    current_name = e
                        .attributes()
                        .flatten()
                        .find(|a| a.key.local_name().as_ref() == b"Name")
                        .map(|a| {
                            a.decode_and_unescape_value(reader.decoder())
                                .map(|v| v.into_owned())
                        })
                        .transpose()?;
                }
                stack.push(tag);
            }
            Event::Empty(e) => {
                let tag = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if tag == "Provider"
                    && let Some(attr) = e
                        .attributes()
                        .flatten()
                        .find(|a| a.key.local_name().as_ref() == b"Name")
                {
                    system.insert(
                        "Provider".into(),
                        attr.decode_and_unescape_value(reader.decoder())?
                            .into_owned(),
                    );
                }
                if tag == "TimeCreated"
                    && let Some(attr) = e
                        .attributes()
                        .flatten()
                        .find(|a| a.key.local_name().as_ref() == b"SystemTime")
                {
                    system.insert(
                        "SystemTime".into(),
                        attr.decode_and_unescape_value(reader.decoder())?
                            .into_owned(),
                    );
                }
            }
            Event::Text(e) => {
                let text = e.decode()?.into_owned();
                if stack.iter().any(|s| s == "EventData")
                    && let Some(key) = &current_name
                {
                    data.insert(key.clone(), text);
                } else if stack.iter().any(|s| s == "System")
                    && let Some(key) = stack.last()
                {
                    system.insert(key.clone(), text);
                }
            }
            Event::End(e) => {
                let tag = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if tag == "Data" {
                    current_name = None;
                }
                stack.pop();
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok((system, data))
}

fn map_event(
    out: &mut Normalized,
    system: &HashMap<String, String>,
    data: &HashMap<String, String>,
    id: i64,
) {
    let provider = system
        .get("Provider")
        .map(String::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let channel = system
        .get("Channel")
        .map(String::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    if provider.contains("sysmon") || channel.contains("sysmon") {
        match id {
            1 => {
                out.event_type = "process".into();
                out.process = Some(ProcessFacts {
                    pid: num(data, "ProcessId"),
                    ppid: num(data, "ParentProcessId"),
                    process_guid: opt(data, "ProcessGuid"),
                    parent_process_guid: opt(data, "ParentProcessGuid"),
                    image_path: opt(data, "Image"),
                    command_line: opt(data, "CommandLine"),
                    user: opt(data, "User"),
                    started_at: parse_time(get(data, "UtcTime")),
                    action: Some("create".into()),
                    sha256: opt(data, "Hashes").and_then(|s| extract_sha(&s)),
                    parent_image: opt(data, "ParentImage"),
                    ..Default::default()
                });
            }
            5 => {
                out.event_type = "process".into();
                out.process = Some(ProcessFacts {
                    pid: num(data, "ProcessId"),
                    process_guid: opt(data, "ProcessGuid"),
                    image_path: opt(data, "Image"),
                    ended_at: parse_time(get(data, "UtcTime")),
                    action: Some("terminate".into()),
                    ..Default::default()
                });
            }
            3 => {
                let n = NetworkFacts {
                    protocol: get(data, "Protocol").to_ascii_lowercase(),
                    direction: Some(
                        match get(data, "Initiated") {
                            "true" => "outbound",
                            "false" => "inbound",
                            _ => "unknown",
                        }
                        .into(),
                    ),
                    local_ip: opt(data, "SourceIp"),
                    local_port: num(data, "SourcePort") as u16,
                    remote_ip: opt(data, "DestinationIp"),
                    remote_port: num(data, "DestinationPort") as u16,
                    pid: num(data, "ProcessId"),
                    process_guid: opt(data, "ProcessGuid"),
                    ..Default::default()
                };
                out.process = Some(ProcessFacts {
                    pid: n.pid,
                    process_guid: n.process_guid.clone(),
                    image_path: opt(data, "Image"),
                    action: Some("network".into()),
                    ..Default::default()
                });
                out.network = Some(n);
                out.event_type = "network".into();
            }
            22 => {
                out.event_type = "network".into();
                let n = NetworkFacts {
                    protocol: "dns".into(),
                    pid: num(data, "ProcessId"),
                    process_guid: opt(data, "ProcessGuid"),
                    ..Default::default()
                };
                out.process = Some(ProcessFacts {
                    pid: n.pid,
                    process_guid: n.process_guid.clone(),
                    image_path: opt(data, "Image"),
                    ..Default::default()
                });
                out.network = Some(n);
            }
            _ => {}
        }
    } else if id == 4688 || id == 4689 {
        let create = id == 4688;
        out.event_type = "process".into();
        out.process = Some(ProcessFacts {
            pid: parse_number(
                data.get(if create { "NewProcessId" } else { "ProcessId" })
                    .map(String::as_str)
                    .unwrap_or(""),
            ),
            ppid: if create { num(data, "ProcessId") } else { 0 },
            image_path: opt(
                data,
                if create {
                    "NewProcessName"
                } else {
                    "ProcessName"
                },
            ),
            command_line: opt(data, "CommandLine"),
            user: opt(data, "SubjectUserName"),
            started_at: if create {
                parse_time(get(system, "SystemTime"))
            } else {
                None
            },
            ended_at: if create {
                None
            } else {
                parse_time(get(system, "SystemTime"))
            },
            action: Some(if create { "create" } else { "terminate" }.into()),
            ..Default::default()
        });
    } else if id == 5156 {
        out.event_type = "network".into();
        let n = NetworkFacts {
            protocol: match get(data, "Protocol") {
                "6" => "tcp",
                "17" => "udp",
                x => x,
            }
            .into(),
            direction: Some(get(data, "Direction").into()),
            local_ip: opt(data, "SourceAddress"),
            local_port: num(data, "SourcePort") as u16,
            remote_ip: opt(data, "DestAddress"),
            remote_port: num(data, "DestPort") as u16,
            pid: num(data, "ProcessId"),
            ..Default::default()
        };
        out.network = Some(n);
    }
}
fn get<'a>(m: &'a HashMap<String, String>, k: &str) -> &'a str {
    m.get(k).map(String::as_str).unwrap_or("")
}
fn opt(m: &HashMap<String, String>, k: &str) -> Option<String> {
    m.get(k).filter(|s| !s.is_empty()).cloned()
}
fn num(m: &HashMap<String, String>, k: &str) -> i64 {
    parse_number(get(m, k))
}
fn parse_number(s: &str) -> i64 {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x") {
        i64::from_str_radix(h, 16).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}
fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s.trim())
        .ok()
        .map(|v| v.with_timezone(&Utc))
}
fn extract_sha(h: &str) -> Option<String> {
    h.split(',').find_map(|p| {
        let (k, v) = p.trim().split_once('=')?;
        k.eq_ignore_ascii_case("SHA256")
            .then(|| v.to_ascii_lowercase())
    })
}
