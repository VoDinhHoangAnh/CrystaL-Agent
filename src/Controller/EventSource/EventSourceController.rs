use crate::{Config::EventGroup, Dto::EventSourceStatus, Service};

pub fn validate(groups: &[EventGroup]) -> Vec<EventSourceStatus> {
    Service::EventSource::validate_groups(groups)
}
