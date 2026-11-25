use crate::{Config::EventGroup, Dto::EventSourceStatus};
use std::process::Command;

pub fn validate_groups(groups: &[EventGroup]) -> Vec<EventSourceStatus> {
    groups.iter().map(validate_group).collect()
}

fn validate_group(group: &EventGroup) -> EventSourceStatus {
    #[cfg(windows)]
    {
        let channel = Command::new("wevtutil.exe")
            .args(["gl", &group.channel])
            .output();
        let channel_present = channel.as_ref().is_ok_and(|output| output.status.success());
        let access_denied = channel.as_ref().is_ok_and(|output| {
            String::from_utf8_lossy(&output.stderr)
                .to_ascii_lowercase()
                .contains("access is denied")
        });
        let sample_found = channel_present
            && Command::new("wevtutil.exe")
                .args(["qe", &group.channel, "/c:1", "/f:text"])
                .output()
                .is_ok_and(|output| output.status.success());
        EventSourceStatus {
            group: group.name.clone(),
            category: group.category.clone(),
            channel: group.channel.clone(),
            channel_present,
            sample_found,
            access_denied,
        }
    }
    #[cfg(not(windows))]
    {
        EventSourceStatus {
            group: group.name.clone(),
            category: group.category.clone(),
            channel: group.channel.clone(),
            channel_present: false,
            sample_found: false,
            access_denied: false,
        }
    }
}
