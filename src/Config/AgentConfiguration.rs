use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct EventGroup {
    pub name: String,
    pub category: String,
    pub channel: String,
    pub event_ids: Vec<u32>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub data_dir: PathBuf,
    pub json_path: PathBuf,
    pub log_dir: PathBuf,
    pub fallback_log_dirs: Vec<PathBuf>,
    pub log_min_free_bytes: u64,
    pub events_file: PathBuf,
    pub event_groups: Vec<EventGroup>,
    pub snapshot_every: Duration,
    pub queue_size: usize,
    pub collect_command_line: bool,
    pub redact_command_line: bool,
    pub raw_retention_days: i64,
    pub normalized_retention_days: i64,
    pub resolved_retention_days: i64,
    pub track_medium: bool,
}

impl Config {
    pub fn load() -> Result<Self, Box<dyn Error>> {
        load_dotenv();
        let events_file = find_events_file();
        let groups = parse_events(&events_file)?;
        let data_dir = match env::var_os("PBRA_DATA_DIR").filter(|value| !value.is_empty()) {
            Some(path) => PathBuf::from(path),
            None => default_data_dir()?,
        };
        let json_path = data_dir.join("pbra.json");
        let log_dir = env::var_os("PBRA_LOG_DIR")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("logs"));
        let fallback_log_dirs = env::var("PBRA_LOG_FALLBACK_DIRS")
            .unwrap_or_default()
            .split(';')
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .collect();
        Ok(Self {
            data_dir,
            json_path,
            log_dir,
            fallback_log_dirs,
            log_min_free_bytes: env_u64("PBRA_LOG_MIN_FREE_BYTES", 536_870_912),
            events_file,
            event_groups: groups,
            snapshot_every: Duration::from_secs(
                env_u64("PBRA_SNAPSHOT_SECONDS", 30).clamp(1, 86_400),
            ),
            queue_size: env_u64("PBRA_QUEUE_SIZE", 1024).clamp(1, 1_000_000) as usize,
            collect_command_line: env_bool("PBRA_COLLECT_CMDLINE", true),
            redact_command_line: env_bool("PBRA_REDACT_CMDLINE", true),
            raw_retention_days: env_i64("PBRA_RAW_RETENTION_DAYS", 14).max(0),
            normalized_retention_days: env_i64("PBRA_NORM_RETENTION_DAYS", 30).max(0),
            resolved_retention_days: env_i64("PBRA_RESOLVED_RETENTION_DAYS", 90).max(0),
            track_medium: env_bool("PBRA_TRACK_MEDIUM", true),
        })
    }
}

fn default_data_dir() -> Result<PathBuf, Box<dyn Error>> {
    #[cfg(windows)]
    {
        let program_data = env::var_os("ProgramData").ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "ProgramData is unavailable; set PBRA_DATA_DIR",
            )
        })?;
        Ok(PathBuf::from(program_data).join("PBRA"))
    }
    #[cfg(not(windows))]
    {
        Ok(env::current_dir()?.join("pb-data"))
    }
}

fn env_bool(key: &str, default: bool) -> bool {
    env::var(key)
        .ok()
        .and_then(|v| v.parse::<bool>().ok())
        .unwrap_or(default)
}
fn env_i64(key: &str, default: i64) -> i64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn load_dotenv() {
    let explicit = env::var_os("PBRA_ENV_FILE").map(PathBuf::from);
    let mut candidates = Vec::new();
    if let Some(path) = explicit {
        candidates.push(path);
    }
    if let Ok(exe) = env::current_exe()
        && let Some(parent) = exe.parent()
    {
        candidates.extend(parent.ancestors().take(8).map(|dir| dir.join(".env")));
    }
    candidates.push(PathBuf::from(".env"));
    for path in candidates {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").unwrap_or(line);
            let Some((key, raw)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = raw.trim().trim_matches(['"', '\'']);
            if !key.is_empty() && env::var_os(key).is_none() {
                unsafe {
                    env::set_var(key, value);
                }
            }
        }
        break;
    }
}

fn find_events_file() -> PathBuf {
    if let Some(path) = env::var_os("PBRA_EVENTS_FILE").filter(|value| !value.is_empty()) {
        return PathBuf::from(path);
    }
    let mut paths = Vec::new();
    if let Ok(exe) = env::current_exe()
        && let Some(parent) = exe.parent()
    {
        paths.extend(
            parent
                .ancestors()
                .take(8)
                .map(|dir| dir.join("events.yaml")),
        );
    }
    paths.push(PathBuf::from("events.yaml"));
    if let Ok(cwd) = env::current_dir() {
        for parent in cwd.ancestors().take(8) {
            paths.push(parent.join("events.yaml"));
        }
    }
    paths
        .into_iter()
        .find(|p| p.is_file())
        .unwrap_or_else(|| Path::new("events.yaml").to_path_buf())
}

fn parse_events(path: &Path) -> Result<Vec<EventGroup>, Box<dyn Error>> {
    let text = fs::read_to_string(path)?;
    let mut groups = Vec::new();
    let mut current: Option<EventGroup> = None;
    for (line_index, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line == "groups:" {
            continue;
        }
        if let Some(value) = line.strip_prefix("- name:") {
            if let Some(group) = current.take() {
                groups.push(group);
            }
            current = Some(EventGroup {
                name: value.trim().trim_matches(['"', '\'']).to_owned(),
                category: String::new(),
                channel: String::new(),
                event_ids: Vec::new(),
            });
            continue;
        }
        let Some(group) = current.as_mut() else {
            return Err(format!("events.yaml line {}: expected '- name:'", line_index + 1).into());
        };
        let Some((key, value)) = line.split_once(':') else {
            return Err(format!("events.yaml line {}: expected key: value", line_index + 1).into());
        };
        match key.trim() {
            "category" => group.category = value.trim().trim_matches(['"', '\'']).to_owned(),
            "channel" => group.channel = value.trim().trim_matches(['"', '\'']).to_owned(),
            "event_ids" => {
                let value = value.trim().trim_start_matches('[').trim_end_matches(']');
                group.event_ids = value
                    .split(',')
                    .filter_map(|part| part.trim().parse().ok())
                    .collect();
            }
            other => {
                return Err(format!(
                    "events.yaml line {}: unsupported field {other}",
                    line_index + 1
                )
                .into());
            }
        }
    }
    if let Some(group) = current {
        groups.push(group);
    }
    if groups.is_empty()
        || groups
            .iter()
            .any(|g| g.name.is_empty() || g.channel.is_empty() || g.event_ids.is_empty())
    {
        return Err("events.yaml has no usable event groups".into());
    }
    Ok(groups)
}
