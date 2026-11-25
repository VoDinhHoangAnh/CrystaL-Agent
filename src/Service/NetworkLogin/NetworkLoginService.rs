use crate::Config::{Config, EventGroup};

const CATEGORY: &str = "network_login";

pub fn event_groups(config: &Config) -> Vec<EventGroup> {
    config
        .event_groups
        .iter()
        .filter(|group| group.category == CATEGORY)
        .cloned()
        .collect()
}
