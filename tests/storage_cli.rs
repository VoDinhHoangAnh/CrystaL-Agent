use std::{fs, path::Path, process::Command};

fn command(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_crystal-agent"))
        .args(args)
        .env("PBRA_DATA_DIR", dir)
        .env(
            "PBRA_EVENTS_FILE",
            Path::new(env!("CARGO_MANIFEST_DIR")).join("events.yaml"),
        )
        .output()
        .unwrap()
}

#[test]
fn status_and_trace_do_not_mutate_storage() {
    let dir = std::env::temp_dir().join(format!("crystal-cli-{}", uuid::Uuid::new_v4()));
    assert!(!command(&dir, &["status"]).status.success());
    assert!(!command(&dir, &["process", "trace", "42"]).status.success());
    assert!(!dir.exists());
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("pbra.json");
    let mut writer = crystal_agent::Store::JsonStore::open(&path).unwrap();
    writer.save_checkpoint("System", 42).unwrap();
    let main = fs::read(&path).unwrap();
    fs::write(dir.join("pbra.json.tmp"), b"partial").unwrap();
    let before = fs::read_dir(&dir).unwrap().count();
    assert!(command(&dir, &["status"]).status.success());
    assert!(!command(&dir, &["process", "trace", "42"]).status.success());
    assert_eq!(fs::read(&path).unwrap(), main);
    assert_eq!(fs::read(dir.join("pbra.json.tmp")).unwrap(), b"partial");
    assert_eq!(fs::read_dir(&dir).unwrap().count(), before);
    drop(writer);
    fs::remove_dir_all(dir).unwrap();
}
