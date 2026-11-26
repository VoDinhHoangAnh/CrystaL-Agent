use std::{
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::{
    Model::{Assessment, Normalized, PersistInput},
    Repository::LogArchive,
};

pub struct FileLogArchive {
    primary_dir: PathBuf,
    fallback_dirs: Vec<PathBuf>,
    minimum_free_bytes: u64,
}

#[derive(Serialize)]
struct LogRecord<'a> {
    category: &'static str,
    dedupe_key: String,
    event_time: chrono::DateTime<chrono::Utc>,
    observed_at: chrono::DateTime<chrono::Utc>,
    event_type: &'a str,
    source: &'a str,
    event_id: &'a str,
    process_instance_id: &'a str,
    normalized: &'a Normalized,
    assessment: &'a Assessment,
}

impl FileLogArchive {
    pub fn new(primary_dir: PathBuf, fallback_dirs: Vec<PathBuf>, minimum_free_bytes: u64) -> Self {
        Self {
            primary_dir,
            fallback_dirs,
            minimum_free_bytes,
        }
    }

    fn destinations(&self) -> Vec<&Path> {
        let mut paths = Vec::with_capacity(1 + self.fallback_dirs.len());
        paths.push(self.primary_dir.as_path());
        for path in &self.fallback_dirs {
            if !paths.iter().any(|existing| existing == &path.as_path()) {
                paths.push(path.as_path());
            }
        }
        paths
    }
}

impl LogArchive for FileLogArchive {
    fn append(&mut self, input: &PersistInput) -> Result<(), String> {
        let category = category_for(&input.normalized);
        let dedupe_key = dedupe_key(
            &input.normalized.agent_id,
            &input.normalized.source,
            &input.normalized.source_event_key,
        );
        let record = LogRecord {
            category,
            dedupe_key: dedupe_key.clone(),
            event_time: input.normalized.event_time,
            observed_at: input.normalized.observed_at,
            event_type: &input.normalized.event_type,
            source: &input.normalized.source,
            event_id: &input.normalized.event_id,
            process_instance_id: &input.process_instance_id,
            normalized: &input.normalized,
            assessment: &input.assessment,
        };
        let mut line = serde_json::to_vec(&record).map_err(|error| error.to_string())?;
        line.push(b'\n');
        let file_name = format!("{category}.log");
        let mut errors = Vec::new();
        let destinations = self.destinations();

        // Sau khi crash, event chưa checkpoint sẽ nằm ở cuối một trong các file nhóm.
        for directory in &destinations {
            let path = directory.join(&file_name);
            if let Some(existing_key) = last_record_key(&path)?
                && existing_key == dedupe_key
            {
                return sync_existing(&path);
            }
        }

        for directory in destinations {
            if let Err(error) = fs::create_dir_all(directory) {
                errors.push(format!("{}: {error}", directory.display()));
                continue;
            }
            if available_bytes(directory).is_some_and(|free| {
                free < self.minimum_free_bytes.saturating_add(line.len() as u64)
            }) {
                errors.push(format!(
                    "{}: free space is below the configured reserve",
                    directory.display()
                ));
                continue;
            }

            let path = directory.join(&file_name);
            match append_line(&path, &line, &dedupe_key) {
                Ok(()) => return Ok(()),
                Err(error) => errors.push(format!("{}: {error}", path.display())),
            }
        }

        Err(format!(
            "could not append {} log to any configured location: {}",
            category,
            errors.join("; ")
        ))
    }
}

fn append_line(path: &Path, line: &[u8], key: &str) -> Result<(), String> {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(PathBuf::from(lock_path))
        .map_err(|e| e.to_string())?;
    lock.try_lock()
        .map_err(|e| format!("archive writer lock unavailable: {e}"))?;
    // Recheck under ownership: another writer may have appended since the first lookup.
    if last_record_key(path)?.as_deref() == Some(key) {
        return sync_existing(path);
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    if file.metadata().map_err(|error| error.to_string())?.len() > 0 {
        file.seek(SeekFrom::End(-1))
            .map_err(|error| error.to_string())?;
        let mut last_byte = [0];
        file.read_exact(&mut last_byte)
            .map_err(|error| error.to_string())?;
        if last_byte[0] != b'\n' {
            file.write_all(b"\n").map_err(|error| error.to_string())?;
        }
    }
    file.write_all(line).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

fn sync_existing(path: &Path) -> Result<(), String> {
    // A previous append may have reached the page cache before sync failed.
    OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| error.to_string())
}

fn dedupe_key(agent_id: &str, source: &str, source_event_key: &str) -> String {
    format!(
        "{}:{}{}:{}{}:{}",
        agent_id.len(),
        agent_id,
        source.len(),
        source,
        source_event_key.len(),
        source_event_key
    )
}

fn last_record_key(path: &Path) -> Result<Option<String>, String> {
    let Some(line) = read_last_line(path)? else {
        return Ok(None);
    };
    let Ok(record) = serde_json::from_slice::<serde_json::Value>(&line) else {
        return Ok(None);
    };
    if let Some(key) = record.get("dedupe_key").and_then(|value| value.as_str()) {
        return Ok(Some(key.to_owned()));
    }

    // Đọc được cả các dòng đã tạo bởi bản agent trước khi thêm dedupe_key.
    let normalized = record.get("normalized");
    let agent_id = normalized
        .and_then(|value| value.get("agent_id"))
        .and_then(|value| value.as_str());
    let source = normalized
        .and_then(|value| value.get("source"))
        .and_then(|value| value.as_str());
    let source_event_key = normalized
        .and_then(|value| value.get("source_event_key"))
        .and_then(|value| value.as_str());
    Ok(agent_id
        .zip(source)
        .zip(source_event_key)
        .map(|((agent, source), key)| dedupe_key(agent, source, key)))
}

fn read_last_line(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    let mut remaining = file
        .seek(SeekFrom::End(0))
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if remaining == 0 {
        return Ok(None);
    }

    const CHUNK_SIZE: u64 = 8192;
    let mut reversed = Vec::new();
    let mut at_end = true;
    while remaining > 0 {
        let start = remaining.saturating_sub(CHUNK_SIZE);
        file.seek(SeekFrom::Start(start))
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let mut chunk = vec![0; (remaining - start) as usize];
        file.read_exact(&mut chunk)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        for byte in chunk.into_iter().rev() {
            if at_end && byte == b'\n' {
                continue;
            }
            at_end = false;
            if byte == b'\n' {
                reversed.reverse();
                return Ok(Some(reversed));
            }
            reversed.push(byte);
        }
        remaining = start;
    }
    reversed.reverse();
    Ok(Some(reversed))
}

fn category_for(event: &Normalized) -> &'static str {
    let event_code = event.windows.as_ref().map(|facts| facts.event_code);
    if event_code
        .is_some_and(|code| matches!(code, 4624 | 4625 | 4648 | 4740 | 4768 | 4769 | 4771 | 4776))
        || event.windows.as_ref().is_some_and(|facts| {
            facts
                .channel
                .to_ascii_lowercase()
                .contains("terminalservices")
        })
    {
        return "Auth";
    }

    if event
        .windows
        .as_ref()
        .is_some_and(|facts| facts.channel.to_ascii_lowercase().contains("sysmon"))
        || event.source.to_ascii_lowercase().contains("sysmon")
    {
        return "Sysmon";
    }

    if event.network.is_some() || event_code.is_some_and(|code| matches!(code, 5156..=5158)) {
        return "Network";
    }
    // Process, System và các nguồn còn lại được gom vào nhóm endpoint Sysmon.
    "Sysmon"
}

#[cfg(windows)]
fn available_bytes(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut available = 0u64;
    // Chỉ đọc dung lượng còn trống trên volume chứa thư mục log.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    (ok != 0).then_some(available)
}

#[cfg(not(windows))]
fn available_bytes(_path: &Path) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Repository::LogArchive;

    #[test]
    fn archive_lock_prevents_interleaved_writes_and_releases() {
        let directory =
            std::env::temp_dir().join(format!("crystal-archive-lock-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("Sysmon.log");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("Sysmon.log.lock"))
            .unwrap();
        lock.try_lock().unwrap();
        assert!(append_line(&path, b"{\"dedupe_key\":\"one\"}\n", "one").is_err());
        assert!(!path.exists());
        drop(lock);
        append_line(&path, b"{\"dedupe_key\":\"one\"}\n", "one").unwrap();
        append_line(&path, b"{\"dedupe_key\":\"one\"}\n", "one").unwrap();
        assert_eq!(fs::read_to_string(path).unwrap().lines().count(), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn appending_same_event_twice_writes_one_line() {
        let directory =
            std::env::temp_dir().join(format!("crystal-category-log-{}", uuid::Uuid::new_v4()));
        let mut archive = FileLogArchive::new(directory.clone(), vec![], 0);
        let mut event = PersistInput::default();
        event.normalized.agent_id = "agent-test".into();
        event.normalized.source = "Security".into();
        event.normalized.source_event_key = "Security|record-42".into();
        event.normalized.event_id = "event-test-42".into();
        event.normalized.event_type = "winevent".into();
        event.normalized.event_time = chrono::Utc::now();
        event.normalized.observed_at = event.normalized.event_time;

        archive.append(&event).unwrap();
        archive.append(&event).unwrap();

        let contents = fs::read_to_string(directory.join("Sysmon.log")).unwrap();
        assert_eq!(contents.lines().count(), 1);
        fs::remove_dir_all(directory).unwrap();
    }
}
