use crate::{
    Config::Config,
    Dto::{EventSourceStatus, ProcessTrace},
    Repository::RepositoryReader,
    Service,
};

pub fn validate_sources(config: &Config) -> Vec<EventSourceStatus> {
    super::EventSource::validate(&Service::Process::event_groups(config))
}

pub fn trace(repository: &impl RepositoryReader, selector: &str) -> Result<ProcessTrace, String> {
    Service::Process::trace_process(repository, selector)
}
