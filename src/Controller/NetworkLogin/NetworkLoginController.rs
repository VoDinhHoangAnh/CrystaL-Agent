use crate::{Config::Config, Dto::EventSourceStatus, Service};

pub fn validate_sources(config: &Config) -> Vec<EventSourceStatus> {
    super::EventSource::validate(&Service::NetworkLogin::event_groups(config))
}
