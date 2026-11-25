use crate::{
    Config::Config,
    Dto::{EventSourceStatus, ProcessTrace},
    Repository::Repository,
    Service,
};

pub fn validate_sources(config: &Config) -> Vec<EventSourceStatus> {
    super::EventSource::validate(&Service::Process::event_groups(config))
}

pub fn trace(repository: &impl Repository, selector: &str) -> Result<ProcessTrace, String> {
    Service::Process::trace_process(repository, selector)
}
