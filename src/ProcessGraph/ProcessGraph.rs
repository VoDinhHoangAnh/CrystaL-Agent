use std::collections::HashMap;
use uuid::Uuid;

#[derive(Clone, Debug, Default)]
pub struct Resolution {
    pub instance_id: String,
    pub parent_id: String,
    pub missing_parent: bool,
    pub ambiguous_pid: bool,
    pub new_instance: bool,
}

#[derive(Clone, Debug)]
struct Slot {
    id: String,
    pid: i64,
    start: i64,
    end: Option<i64>,
}

#[derive(Default)]
pub struct ProcessGraph {
    by_guid: HashMap<String, String>,
    slots: Vec<Slot>,
}

impl ProcessGraph {
    pub fn resolve(
        &mut self,
        pid: i64,
        guid: &str,
        ppid: i64,
        parent_guid: &str,
        at: i64,
        terminated: bool,
    ) -> Resolution {
        let guid = normalize_guid(guid);
        let parent_guid = normalize_guid(parent_guid);
        let existing = if !guid.is_empty() {
            self.by_guid.get(&guid).cloned()
        } else {
            None
        };
        let (id, ambiguous, is_new) = if let Some(id) = existing {
            (id, false, false)
        } else {
            let matches: Vec<_> = self
                .slots
                .iter()
                .filter(|s| {
                    s.pid == pid
                        && pid != 0
                        && s.start <= at + 2
                        && s.end.is_none_or(|end| at <= end)
                })
                .collect();
            if let Some(slot) = matches.last() {
                (slot.id.clone(), matches.len() > 1, false)
            } else {
                (Uuid::new_v4().to_string(), false, true)
            }
        };
        if is_new {
            self.slots.push(Slot {
                id: id.clone(),
                pid,
                start: at,
                end: terminated.then_some(at),
            });
        } else if terminated && let Some(slot) = self.slots.iter_mut().find(|s| s.id == id) {
            slot.end = Some(at);
        }
        if !guid.is_empty() {
            self.by_guid.insert(guid, id.clone());
        }
        let (parent_id, missing) = self.resolve_parent(ppid, &parent_guid, at);
        Resolution {
            instance_id: id,
            parent_id,
            missing_parent: missing,
            ambiguous_pid: ambiguous,
            new_instance: is_new,
        }
    }

    fn resolve_parent(&mut self, ppid: i64, guid: &str, at: i64) -> (String, bool) {
        if !guid.is_empty() {
            if let Some(id) = self.by_guid.get(guid) {
                return (id.clone(), false);
            }
            let id = Uuid::new_v4().to_string();
            self.by_guid.insert(guid.to_owned(), id.clone());
            self.slots.push(Slot {
                id: id.clone(),
                pid: ppid,
                start: at - 1,
                end: None,
            });
            return (id, true);
        }
        if ppid == 0 {
            return (String::new(), false);
        }
        let found: Vec<_> = self
            .slots
            .iter()
            .filter(|s| s.pid == ppid && s.start <= at && s.end.is_none_or(|e| at <= e))
            .collect();
        if found.len() == 1 {
            return (found[0].id.clone(), false);
        }
        let id = Uuid::new_v4().to_string();
        self.slots.push(Slot {
            id: id.clone(),
            pid: ppid,
            start: at - 1,
            end: None,
        });
        (id, true)
    }
}

fn normalize_guid(value: &str) -> String {
    value.trim().trim_matches(['{', '}']).to_ascii_uppercase()
}
