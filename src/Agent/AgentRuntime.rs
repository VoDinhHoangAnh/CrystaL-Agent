use std::{
    error::Error,
    fs,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use uuid::Uuid;

use crate::Repository::Repository;
use crate::{
    Config::Config,
    Model::{CollectorHealth, PersistInput, RawEnvelope},
    ProcessGraph::ProcessGraph,
    Risk,
    Store::{FileLogArchive, JsonStore},
};

pub fn run(cfg: Config) -> Result<(), Box<dyn Error>> {
    #[cfg(windows)]
    {
        run_until(cfg, Arc::new(AtomicBool::new(false))).map_err(Into::into)
    }
    #[cfg(not(windows))]
    {
        let _ = cfg;
        Err("live Windows collection is available only on Windows".into())
    }
}

pub fn run_until(cfg: Config, stop: Arc<AtomicBool>) -> Result<(), String> {
    fs::create_dir_all(&cfg.data_dir).map_err(|e| e.to_string())?;
    let mut store = JsonStore::open(&cfg.json_path)?;
    let mut log_archive = FileLogArchive::new(
        cfg.log_dir.clone(),
        cfg.fallback_log_dirs.clone(),
        cfg.log_min_free_bytes,
    );
    let id_path = cfg.data_dir.join("agent-id");
    let agent_id = if id_path.is_file() {
        fs::read_to_string(&id_path)
            .map_err(|e| e.to_string())?
            .trim()
            .to_owned()
    } else {
        let id = Uuid::new_v4().to_string();
        fs::write(&id_path, format!("{id}\n")).map_err(|e| e.to_string())?;
        id
    };
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".into());
    store.ensure_agent(&agent_id, &host)?;
    let mut graph = ProcessGraph::default();
    println!(
        "CrystaL Agent starting\nagent_id={agent_id} version={}\ndata_dir={}\njson_state={}\nlog_dir={}\nlog_fallbacks={}\npolicy=observe-only",
        crate::Model::AGENT_VERSION,
        cfg.data_dir.display(),
        cfg.json_path.display(),
        cfg.log_dir.display(),
        cfg.fallback_log_dirs
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(";")
    );
    let mut last_snapshot = std::time::Instant::now() - cfg.snapshot_every;
    let mut last_retention = std::time::Instant::now() - Duration::from_secs(86_400);
    while !stop.load(Ordering::Relaxed) {
        if last_retention.elapsed() >= Duration::from_secs(86_400) {
            store.retain(
                cfg.raw_retention_days,
                cfg.normalized_retention_days,
                cfg.resolved_retention_days,
            )?;
            last_retention = std::time::Instant::now();
        }
        #[cfg(windows)]
        {
            match crate::Collector::collect_event_logs(&cfg, &store, &agent_id, &stop) {
                Ok(records) => {
                    for raw in records {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        if !ingest(&mut store, &mut graph, &mut log_archive, raw, &cfg)? {
                            break;
                        }
                    }
                }
                Err(e) => {
                    let _ = store.save_health(CollectorHealth {
                        collector_id: "eventlog".into(),
                        status: "degraded".into(),
                        reason: "collection_error".into(),
                        events_seen: 0,
                        last_error: Some(e),
                    });
                }
            }
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if last_snapshot.elapsed() >= cfg.snapshot_every {
                match crate::Collector::collect_snapshots(&cfg, &agent_id, &stop) {
                    Ok(records) => {
                        for raw in records {
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                            let _ = ingest(&mut store, &mut graph, &mut log_archive, raw, &cfg)?;
                        }
                    }
                    Err(e) => {
                        let _ = store.save_health(CollectorHealth {
                            collector_id: "snapshot".into(),
                            status: "degraded".into(),
                            reason: "collection_error".into(),
                            events_seen: 0,
                            last_error: Some(e),
                        });
                    }
                }
                last_snapshot = std::time::Instant::now();
            }
        }
        if stop.load(Ordering::Relaxed) {
            break;
        }
        thread::sleep(Duration::from_secs(2));
    }
    Ok(())
}

fn ingest(
    store: &mut JsonStore,
    graph: &mut ProcessGraph,
    log_archive: &mut FileLogArchive,
    raw: RawEnvelope,
    cfg: &Config,
) -> Result<bool, String> {
    let mut n = crate::Normalize::normalize(&raw, cfg);
    let resolution = if let Some(p) = &n.process {
        let t = n.event_time.timestamp_millis();
        graph.resolve(
            p.pid,
            p.process_guid.as_deref().unwrap_or(""),
            p.ppid,
            p.parent_process_guid.as_deref().unwrap_or(""),
            t,
            p.action.as_deref() == Some("terminate"),
        )
    } else if let Some(net) = &n.network {
        graph.resolve(
            net.pid,
            net.process_guid.as_deref().unwrap_or(""),
            0,
            "",
            n.event_time.timestamp_millis(),
            false,
        )
    } else {
        Default::default()
    };
    if n.event_type.is_empty() {
        n.event_type = "event".into();
    }
    let assessment = Risk::analyze(&n, &resolution.instance_id);
    let track_process = assessment.track && !resolution.instance_id.is_empty();
    let ip_key = n
        .network
        .as_ref()
        .and_then(|v| v.remote_ip.clone())
        .filter(|ip| !ip.starts_with("127.") && ip != "::1")
        .unwrap_or_default();
    let track_ip = assessment.track && !ip_key.is_empty();
    let input = PersistInput {
        normalized: n,
        process_instance_id: resolution.instance_id,
        parent_process_instance_id: resolution.parent_id,
        assessment,
        track_process,
        track_ip,
        ip_key,
    };
    let archived = if store.category_log_written(&raw) {
        true
    } else {
        match crate::Repository::LogArchive::append(log_archive, &input) {
            Ok(()) => true,
            Err(error) => {
                eprintln!("category log archive warning: {error}");
                false
            }
        }
    };
    let checkpoint = if archived && !raw.snapshot {
        raw.source_event_key
            .rsplit_once('|')
            .and_then(|(channel, value)| {
                value.parse::<i64>().ok().map(|id| (channel.to_owned(), id))
            })
    } else {
        None
    };
    store.commit_event(raw, input, checkpoint, archived)?;
    Ok(archived)
}

pub fn status(cfg: &Config) -> Result<(), Box<dyn Error>> {
    let store = JsonStore::open(&cfg.json_path)?;
    let s = store.stats();
    println!(
        "logs_dir={} fallback_dirs={} minimum_free_bytes={}",
        cfg.log_dir.display(),
        cfg.fallback_log_dirs
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(";"),
        cfg.log_min_free_bytes
    );
    println!(
        "json={} bytes={} raw={} normalized={} pending={} tracked={} last_event={}",
        cfg.json_path.display(),
        s.bytes,
        s.raw_count,
        s.analyzed_count,
        s.pending_count,
        s.tracked_count,
        s.last_event
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| "none".into())
    );
    for h in s.collectors {
        println!(
            "collector={} status={} events={} error={}",
            h.collector_id,
            h.status,
            h.events_seen,
            h.last_error.unwrap_or_default()
        );
    }
    Ok(())
}
