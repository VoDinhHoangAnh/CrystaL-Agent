use crate::{
    Config::{Config, EventGroup},
    Dto::ProcessTrace,
    Repository::RepositoryReader,
};

const CATEGORY: &str = "process";

pub fn event_groups(config: &Config) -> Vec<EventGroup> {
    config
        .event_groups
        .iter()
        .filter(|group| group.category == CATEGORY)
        .cloned()
        .collect()
}

pub fn trace_process(
    repository: &impl RepositoryReader,
    selector: &str,
) -> Result<ProcessTrace, String> {
    repository.trace_process(selector)
}
