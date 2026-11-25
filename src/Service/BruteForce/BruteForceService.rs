use crate::Config::{Config, EventGroup};

const CATEGORY: &str = "bruteforce";

pub fn event_groups(config: &Config) -> Vec<EventGroup> {
    config
        .event_groups
        .iter()
        .filter(|group| group.category == CATEGORY)
        .cloned()
        .collect()
}
