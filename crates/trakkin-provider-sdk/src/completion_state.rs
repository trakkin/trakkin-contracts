use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::completion::{
    DomainReferences, Identity, Observation, ReadQuality, Subject, bounded_json_size,
};
use crate::completion_operation::{Behavior, FieldObservation, ResourceAccess};

pub const MAXIMUM_STATE_ITEMS: usize = 100_000;
pub const MAXIMUM_REFERENCE_BYTES: usize = 4 * 1024 * 1024;
pub const MAXIMUM_FIELD_OBSERVATION_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub subjects: Vec<Subject>,
    pub observations: Vec<Observation>,
    pub access: Vec<ResourceAccess>,
    #[serde(default)]
    pub references: Vec<DomainReferences>,
    #[serde(default)]
    pub field_observations: Vec<FieldObservation>,
}

impl State {
    pub fn validate(
        &self,
        account: &Identity,
        requested: &[Identity],
        behavior: &Behavior,
    ) -> Result<(), &'static str> {
        behavior
            .validate()
            .map_err(|_| "invalid completion behavior")?;
        if self.subjects.len() > MAXIMUM_STATE_ITEMS
            || self.observations.len() > MAXIMUM_STATE_ITEMS
            || self.access.len() > MAXIMUM_STATE_ITEMS
            || self.references.len() > MAXIMUM_STATE_ITEMS
            || self.field_observations.len() > MAXIMUM_STATE_ITEMS
        {
            return Err("completion state exceeds limits");
        }
        let subjects: BTreeSet<_> = self
            .subjects
            .iter()
            .map(|subject| &subject.identity)
            .collect();
        let requested: BTreeSet<_> = requested.iter().collect();
        if subjects.len() != self.subjects.len()
            || (!requested.is_empty() && subjects != requested)
            || self
                .subjects
                .iter()
                .any(|subject| !behavior.subject_roles.contains(&subject.role))
        {
            return Err("completion subject coverage mismatch");
        }
        let mut observed = BTreeSet::new();
        let mut origins = BTreeSet::new();
        let mut domains = BTreeMap::new();
        for observation in &self.observations {
            observation
                .validate()
                .map_err(|_| "invalid completion observation")?;
            if &observation.account != account
                || !subjects.contains(&observation.subject)
                || observation.behavior_revision != behavior.revision
                || !behavior.units.contains(observation.domain.unit())
                || !origins.insert((
                    &observation.origin,
                    &observation.subject,
                    &observation.field,
                    observation.domain.identity(),
                ))
            {
                return Err("completion observation scope mismatch");
            }
            observed.insert(&observation.subject);
            let domain = domains
                .entry((&observation.subject, observation.domain.identity()))
                .or_insert(Some(&observation.domain));
            if *domain != Some(&observation.domain) {
                *domain = None;
            }
        }
        if observed != subjects {
            return Err("missing completion observations");
        }
        let mut references = BTreeSet::new();
        let mut remaining_units = MAXIMUM_STATE_ITEMS;
        let mut remaining_bytes = MAXIMUM_REFERENCE_BYTES;
        for binding in &self.references {
            let key = (binding.subject(), binding.domain().identity());
            if !references.insert(key)
                || domains.get(&key).copied().flatten() != Some(binding.domain())
            {
                return Err("completion reference domain mismatch");
            }
            remaining_units = remaining_units
                .checked_sub(binding.units().len())
                .ok_or("completion references exceed limits")?;
            for unit in binding.units() {
                remaining_bytes = remaining_bytes
                    .checked_sub(
                        unit.reference.len()
                            + unit.unit.namespace().as_str().len()
                            + unit.unit.value().len(),
                    )
                    .ok_or("completion references exceed limits")?;
            }
        }
        bounded_json_size(&self.field_observations, MAXIMUM_FIELD_OBSERVATION_BYTES)
            .map_err(|_| "native field observations exceed limits")?;
        let mut scopes = BTreeMap::new();
        let mut groups = BTreeMap::new();
        for access in &self.access {
            access
                .validate(behavior)
                .map_err(|_| "invalid completion resource access")?;
            if &access.scope.account != account
                || !subjects.contains(&access.scope.subject)
                || scopes.insert(&access.scope, access).is_some()
            {
                return Err("completion resource access scope mismatch");
            }
            let native = (&access.scope.account, &access.scope.subject, &access.group);
            if groups
                .insert(native, &access.canonical_group)
                .is_some_and(|previous| previous != &access.canonical_group)
            {
                return Err("inconsistent completion canonical groups");
            }
        }
        let completion_scopes: BTreeSet<_> = self
            .observations
            .iter()
            .map(|observation| {
                (
                    &observation.account,
                    &observation.subject,
                    &observation.field,
                )
            })
            .collect();
        let mut field_scopes = BTreeSet::new();
        for observation in &self.field_observations {
            observation
                .validate()
                .map_err(|_| "invalid native field observation")?;
            let access = scopes
                .get(&observation.scope)
                .ok_or("native field access is missing")?;
            if &observation.scope.account != account
                || !subjects.contains(&observation.scope.subject)
                || observation.behavior_revision != behavior.revision
                || !field_scopes.insert(&observation.scope)
                || completion_scopes.contains(&(
                    &observation.scope.account,
                    &observation.scope.subject,
                    &observation.scope.field,
                ))
                || (observation.quality == ReadQuality::Complete && !access.readable)
            {
                return Err("native field observation scope mismatch");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::completion::{Domain, Name, Ordering, Presence, Progress, UnitReference};
    use crate::completion_operation::{BeforeValue, EffectGroup, EffectScope};

    fn name(value: &str) -> Name {
        Name::new(value).unwrap()
    }

    fn identity(value: &str) -> Identity {
        Identity::new(name("test:identity"), value).unwrap()
    }

    fn fixture() -> (State, Behavior) {
        let domain = Domain::new(
            identity("pages"),
            "1",
            name("unit:page"),
            Ordering::Ordered,
            vec![identity("page")],
            true,
        )
        .unwrap();
        let scope = EffectScope {
            account: identity("account"),
            subject: identity("edition"),
            field: name("state:status"),
        };
        let state = State {
            subjects: vec![Subject {
                identity: identity("edition"),
                label: "Edition".to_owned(),
                role: name("subject:edition"),
                classifications: BTreeSet::new(),
            }],
            observations: vec![Observation {
                origin: identity("reader"),
                account: identity("account"),
                subject: identity("edition"),
                field: name("state:completion"),
                behavior_revision: "1".to_owned(),
                remote_revision: Some("native-1".to_owned()),
                acquired_at_milliseconds: 1,
                domain: domain.clone(),
                quality: ReadQuality::Complete,
                presence: Presence::Present(Progress::Prefix { completed: 0 }),
                native_value: serde_json::json!({}),
            }],
            access: vec![ResourceAccess {
                scope: scope.clone(),
                group: name("group:entry"),
                canonical_group: EffectGroup {
                    account: identity("account"),
                    subject: identity("edition"),
                    group: name("group:entry"),
                },
                revision: "access-1".to_owned(),
                readable: true,
                writable: false,
            }],
            references: vec![
                DomainReferences::new(
                    identity("edition"),
                    domain,
                    vec![UnitReference {
                        unit: identity("page"),
                        reference: "book://edition/page".to_owned(),
                    }],
                )
                .unwrap(),
            ],
            field_observations: vec![FieldObservation {
                scope,
                behavior_revision: "1".to_owned(),
                remote_revision: None,
                acquired_at_milliseconds: 1,
                quality: ReadQuality::Complete,
                value: BeforeValue::Known(serde_json::Value::Null),
            }],
        };
        let behavior = Behavior {
            revision: "1".to_owned(),
            subject_roles: BTreeSet::from([name("subject:edition")]),
            units: BTreeSet::from([name("unit:page")]),
            operations: Vec::new(),
        };
        (state, behavior)
    }

    #[test]
    fn state_is_bound_to_account_subjects_and_behavior() {
        let (state, behavior) = fixture();
        state
            .validate(&identity("account"), &[identity("edition")], &behavior)
            .unwrap();
        assert!(
            state
                .validate(&identity("foreign"), &[], &behavior)
                .is_err()
        );
        assert!(
            state
                .validate(&identity("account"), &[identity("other")], &behavior)
                .is_err()
        );
        let mut changed = state.clone();
        changed.observations[0].behavior_revision = "2".to_owned();
        assert!(
            changed
                .validate(&identity("account"), &[], &behavior)
                .is_err()
        );
        let mut changed = state;
        changed.observations.clear();
        assert!(
            changed
                .validate(&identity("account"), &[], &behavior)
                .is_err()
        );
    }

    #[test]
    fn references_and_canonical_groups_must_be_unambiguous() {
        let (state, behavior) = fixture();
        let mut changed = state.clone();
        changed.references.push(changed.references[0].clone());
        assert!(
            changed
                .validate(&identity("account"), &[], &behavior)
                .is_err()
        );
        let mut changed = state.clone();
        changed.access.push(ResourceAccess {
            scope: EffectScope {
                field: name("state:other"),
                ..changed.access[0].scope.clone()
            },
            canonical_group: EffectGroup {
                subject: identity("other"),
                ..changed.access[0].canonical_group.clone()
            },
            ..changed.access[0].clone()
        });
        assert_eq!(
            changed.validate(&identity("account"), &[], &behavior),
            Err("inconsistent completion canonical groups")
        );
        let mut changed = state;
        changed.observations.push(Observation {
            origin: identity("other-reader"),
            domain: Domain::new(
                identity("pages"),
                "2",
                name("unit:page"),
                Ordering::Ordered,
                vec![identity("page")],
                true,
            )
            .unwrap(),
            ..changed.observations[0].clone()
        });
        assert_eq!(
            changed.validate(&identity("account"), &[], &behavior),
            Err("completion reference domain mismatch")
        );
    }

    #[test]
    fn field_evidence_needs_unique_explicit_read_access() {
        let (state, behavior) = fixture();
        let mut changed = state.clone();
        changed
            .field_observations
            .push(changed.field_observations[0].clone());
        assert!(
            changed
                .validate(&identity("account"), &[], &behavior)
                .is_err()
        );
        let mut changed = state.clone();
        changed.access[0].readable = false;
        assert!(
            changed
                .validate(&identity("account"), &[], &behavior)
                .is_err()
        );
        let mut changed = state;
        changed.field_observations[0].scope.field = name("state:completion");
        changed.access[0].scope.field = name("state:completion");
        assert!(
            changed
                .validate(&identity("account"), &[], &behavior)
                .is_err()
        );
    }

    #[test]
    fn wire_state_decoding_enforces_the_same_evidence_contract() {
        let (state, behavior) = fixture();
        let wire = crate::v1::CompletionReadResult::from(state.clone());
        assert_eq!(
            crate::completion_wire::decode_state(
                wire.clone(),
                &identity("account"),
                &[identity("edition")],
                &behavior
            )
            .unwrap(),
            state
        );
        assert!(
            crate::completion_wire::decode_state(
                wire.clone(),
                &identity("foreign"),
                &[],
                &behavior
            )
            .is_err()
        );
        let mut changed = wire.clone();
        changed.observations.push(changed.observations[0].clone());
        assert!(
            crate::completion_wire::decode_state(changed, &identity("account"), &[], &behavior)
                .is_err()
        );
        let mut changed = wire;
        changed.access.clear();
        assert!(
            crate::completion_wire::decode_state(changed, &identity("account"), &[], &behavior)
                .is_err()
        );
    }

    #[test]
    fn typed_and_wire_state_share_json_value_limits() {
        for (value, valid) in [
            ("x".repeat(65_534), true),
            ("x".repeat(65_535), false),
            ("\"".repeat(32_767), true),
            ("\"".repeat(32_768), false),
        ] {
            for explicit_field in [false, true] {
                let (mut state, behavior) = fixture();
                let value = serde_json::Value::String(value.clone());
                if explicit_field {
                    state.field_observations[0].value = BeforeValue::Known(value);
                } else {
                    state.observations[0].native_value = value;
                }
                assert_eq!(
                    state.validate(&identity("account"), &[], &behavior).is_ok(),
                    valid
                );
                assert_eq!(
                    crate::completion_wire::decode_state(
                        state.into(),
                        &identity("account"),
                        &[],
                        &behavior,
                    )
                    .is_ok(),
                    valid
                );
            }
        }
    }

    #[test]
    fn bounded_json_counts_serialized_bytes_without_materializing_a_buffer() {
        let value = serde_json::json!({"escaped": "line\n\"quoted\"", "items": [null, true, 17]});
        let size = serde_json::to_vec(&value).unwrap().len();
        assert_eq!(bounded_json_size(&value, size).unwrap(), size);
        assert!(bounded_json_size(&value, size - 1).is_err());
        assert!(bounded_json_size(&value, 0).is_err());
    }

    #[test]
    fn bounded_json_stops_consuming_input_when_the_budget_is_exhausted() {
        use serde::ser::SerializeSeq;
        use std::cell::Cell;

        struct CountedSequence<'a>(&'a Cell<usize>);

        impl Serialize for CountedSequence<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut sequence = serializer.serialize_seq(Some(1_000_000))?;
                for _ in 0..1_000_000 {
                    self.0.set(self.0.get() + 1);
                    sequence.serialize_element(&true)?;
                }
                sequence.end()
            }
        }

        let consumed = Cell::new(0);
        assert!(bounded_json_size(&CountedSequence(&consumed), 64).is_err());
        assert!(consumed.get() > 0);
        assert!(consumed.get() <= 64);
    }
}
