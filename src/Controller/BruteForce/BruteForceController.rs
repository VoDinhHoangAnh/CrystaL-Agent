use crate::{Config::Config, Dto::EventSourceStatus, Service};

pub fn validate_sources(config: &Config) -> Vec<EventSourceStatus> {
    super::EventSource::validate(&Service::BruteForce::event_groups(config))
}
