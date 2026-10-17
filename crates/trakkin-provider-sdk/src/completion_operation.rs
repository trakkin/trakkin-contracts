use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::completion::{Domain, Identity, ModelError, Name, Progress};

pub const MAXIMUM_EFFECTS: usize = 256;
pub const MAXIMUM_COMMAND_BYTES: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectScope {
    pub account: Identity,
    pub subject: Identity,
    pub field: Name,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectGroup {
    pub account: Identity,
    pub subject: Identity,
    pub group: Name,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceAccess {
    pub scope: EffectScope,
    pub group: Name,
    pub canonical_group: EffectGroup,
    pub revision: String,
    pub readable: bool,
    pub writable: bool,
}

impl ResourceAccess {
    pub fn validate(&self, behavior: &Behavior) -> Result<(), OperationError> {
        behavior.validate()?;
        if !valid_revision(&self.revision)
            || self.writable
                && !behavior
                    .operations
                    .iter()
                    .any(|operation| operation.effect_fields.contains(&self.scope.field))
        {
            return Err(OperationError::InvalidAccess);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum BeforeValue {
    Known(serde_json::Value),
    Missing,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    SetCompletion {
        domain: Domain,
        before: Progress,
        after: Progress,
    },
    MergeItems {
        domain: Domain,
        before: BTreeSet<Identity>,
        additions: BTreeSet<Identity>,
    },
    SetValue {
        before: BeforeValue,
        after: serde_json::Value,
    },
    Append {
        value: serde_json::Value,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Effect {
    pub scope: EffectScope,
    pub group: Name,
    pub change: Change,
}

impl Effect {
    pub fn group(&self) -> EffectGroup {
        EffectGroup {
            account: self.scope.account.clone(),
            subject: self.scope.subject.clone(),
            group: self.group.clone(),
        }
    }

    fn validate(&self) -> Result<(), OperationError> {
        match &self.change {
            Change::SetCompletion {
                domain,
                before,
                after,
            } => {
                before.validate(domain)?;
                after.validate(domain)?;
                if std::mem::discriminant(before) != std::mem::discriminant(after) {
                    return Err(OperationError::ChangedRepresentation);
                }
            }
            Change::MergeItems {
                domain,
                before,
                additions,
            } => {
                Progress::Items {
                    completed: before.clone(),
                }
                .validate(domain)?;
                Progress::Items {
                    completed: additions.clone(),
                }
                .validate(domain)?;
            }
            Change::SetValue { .. } | Change::Append { .. } => {}
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionKind {
    Conditional,
    MonotoneMerge,
    BestEffort,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Protection {
    Conditional {
        token: String,
        groups: BTreeSet<EffectGroup>,
    },
    MonotoneMerge,
    BestEffort,
}

impl Protection {
    pub fn kind(&self) -> ProtectionKind {
        match self {
            Self::Conditional { .. } => ProtectionKind::Conditional,
            Self::MonotoneMerge => ProtectionKind::MonotoneMerge,
            Self::BestEffort => ProtectionKind::BestEffort,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Replay {
    Unsupported,
    Deduplicated {
        key: Identity,
        scope: Identity,
        valid_until_milliseconds: i64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationCapability {
    pub class: Name,
    pub effect_fields: BTreeSet<Name>,
    pub protection: BTreeSet<ProtectionKind>,
    pub deduplication: bool,
    pub reconciliation: BTreeSet<Name>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Behavior {
    pub revision: String,
    pub subject_roles: BTreeSet<Name>,
    pub units: BTreeSet<Name>,
    pub operations: Vec<OperationCapability>,
}

impl Behavior {
    pub fn validate(&self) -> Result<(), OperationError> {
        if !valid_revision(&self.revision) || self.operations.len() > MAXIMUM_EFFECTS {
            return Err(OperationError::InvalidBehavior);
        }
        let mut classes = BTreeSet::new();
        for operation in &self.operations {
            if !classes.insert(&operation.class)
                || operation.effect_fields.is_empty()
                || operation.protection.is_empty()
            {
                return Err(OperationError::InvalidBehavior);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub method: Name,
    pub parameters: serde_json::Value,
}

impl fmt::Debug for Command {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Command")
            .field("method", &self.method)
            .field("parameters", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedOperation {
    pub identity: Identity,
    pub class: Name,
    pub behavior_revision: String,
    pub prepared_at_milliseconds: i64,
    pub expires_at_milliseconds: i64,
    pub effects: Vec<Effect>,
    pub protection: Protection,
    pub replay: Replay,
    pub reconciliation: Option<Name>,
    pub command: Command,
}

impl PreparedOperation {
    pub fn validate(&self, behavior: &Behavior) -> Result<(), OperationError> {
        behavior.validate()?;
        if self.behavior_revision != behavior.revision {
            return Err(OperationError::ChangedBehavior);
        }
        let capability = behavior
            .operations
            .iter()
            .find(|capability| capability.class == self.class)
            .ok_or(OperationError::UnsupportedOperation)?;
        if self.expires_at_milliseconds <= self.prepared_at_milliseconds
            || self.effects.is_empty()
            || self.effects.len() > MAXIMUM_EFFECTS
        {
            return Err(OperationError::InvalidPreparation);
        }
        if serde_json::to_vec(&self.command)
            .map_err(|_| OperationError::InvalidPreparation)?
            .len()
            > MAXIMUM_COMMAND_BYTES
        {
            return Err(OperationError::InvalidPreparation);
        }
        let mut scopes = BTreeSet::new();
        for effect in &self.effects {
            effect.validate()?;
            if !scopes.insert(&effect.scope) {
                return Err(OperationError::DuplicateEffect);
            }
            if !capability.effect_fields.contains(&effect.scope.field) {
                return Err(OperationError::UndeclaredEffect);
            }
            let domain = match &effect.change {
                Change::SetCompletion { domain, .. } | Change::MergeItems { domain, .. } => {
                    Some(domain)
                }
                _ => None,
            };
            if domain.is_some_and(|domain| !behavior.units.contains(domain.unit())) {
                return Err(OperationError::UnsupportedUnit);
            }
        }
        if !capability.protection.contains(&self.protection.kind()) {
            return Err(OperationError::UnsupportedProtection);
        }
        match &self.protection {
            Protection::Conditional { token, groups } => {
                if !valid_revision(token) || *groups != self.effect_groups() {
                    return Err(OperationError::IncompleteProtection);
                }
            }
            Protection::MonotoneMerge => {
                if !self
                    .effects
                    .iter()
                    .all(|effect| matches!(effect.change, Change::MergeItems { .. }))
                {
                    return Err(OperationError::UnsafeMerge);
                }
            }
            Protection::BestEffort => {}
        }
        if let Replay::Deduplicated {
            valid_until_milliseconds,
            ..
        } = &self.replay
            && (!capability.deduplication
                || *valid_until_milliseconds <= self.prepared_at_milliseconds)
        {
            return Err(OperationError::InvalidReplay);
        }
        if self
            .reconciliation
            .as_ref()
            .is_some_and(|method| !capability.reconciliation.contains(method))
        {
            return Err(OperationError::UnsupportedReconciliation);
        }
        Ok(())
    }

    pub fn effect_groups(&self) -> BTreeSet<EffectGroup> {
        self.effects.iter().map(Effect::group).collect()
    }
}

fn valid_revision(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestLifecycle {
    NotDispatched,
    MayStillExecute,
    Terminal {
        evidence_kind: Name,
        evidence: Identity,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKnowledge {
    Unknown,
    NotApplied,
    Applied,
    PartiallyApplied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Satisfaction {
    Unknown,
    Satisfied,
    Unsatisfied,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectOutcome {
    pub scope: EffectScope,
    pub knowledge: EffectKnowledge,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptOutcome {
    pub operation: Identity,
    pub attempt: Identity,
    pub lifecycle: RequestLifecycle,
    pub effects: Vec<EffectOutcome>,
    pub satisfaction: Satisfaction,
}

impl AttemptOutcome {
    pub fn validate_for(
        &self,
        operation: &PreparedOperation,
        attempt: &Identity,
    ) -> Result<(), OperationError> {
        let scopes: BTreeSet<_> = operation
            .effects
            .iter()
            .map(|effect| &effect.scope)
            .collect();
        if self.operation != operation.identity
            || self.attempt != *attempt
            || self.effects.len() != scopes.len()
            || self
                .effects
                .iter()
                .map(|effect| &effect.scope)
                .collect::<BTreeSet<_>>()
                != scopes
            || (self.lifecycle == RequestLifecycle::NotDispatched
                && self
                    .effects
                    .iter()
                    .any(|effect| effect.knowledge != EffectKnowledge::NotApplied))
        {
            return Err(OperationError::InvalidOutcome);
        }
        Ok(())
    }

    pub fn requires_barrier(&self) -> bool {
        self.lifecycle == RequestLifecycle::MayStillExecute
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OperationError {
    #[error(transparent)]
    InvalidModel(#[from] ModelError),
    #[error("invalid or duplicate operation capability")]
    InvalidBehavior,
    #[error("resource access has an invalid revision or unsupported writable field")]
    InvalidAccess,
    #[error("preparation uses a different behavior revision")]
    ChangedBehavior,
    #[error("unsupported operation class")]
    UnsupportedOperation,
    #[error("preparation has invalid bounds, expiry, or command")]
    InvalidPreparation,
    #[error("preparation contains duplicate effect scopes")]
    DuplicateEffect,
    #[error("preparation contains an undeclared effect field")]
    UndeclaredEffect,
    #[error("completion unit is not supported by this behavior")]
    UnsupportedUnit,
    #[error("a completion setter changes the native representation")]
    ChangedRepresentation,
    #[error("protection is not supported by this operation class")]
    UnsupportedProtection,
    #[error("conditional protection does not cover every effect group")]
    IncompleteProtection,
    #[error("monotone protection requires all effects to be item merges")]
    UnsafeMerge,
    #[error("deduplication is unsupported or its guarantee has expired")]
    InvalidReplay,
    #[error("reconciliation method is not supported by this operation class")]
    UnsupportedReconciliation,
    #[error("attempt outcome has inconsistent identities, effects, or lifecycle")]
    InvalidOutcome,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::completion::Ordering;

    fn name(value: &str) -> Name {
        Name::new(value).unwrap()
    }
    fn identity(value: &str) -> Identity {
        Identity::new(name("fixture:id"), value).unwrap()
    }

    fn fixture() -> (Behavior, PreparedOperation) {
        let scope = EffectScope {
            account: identity("account"),
            subject: identity("edition"),
            field: name("state:completion"),
        };
        let domain = Domain::new(
            identity("pages"),
            "1",
            name("unit:page"),
            Ordering::Ordered,
            vec![identity("1"), identity("2")],
            true,
        )
        .unwrap();
        let behavior = Behavior {
            revision: "1".to_owned(),
            subject_roles: BTreeSet::from([name("subject:edition")]),
            units: BTreeSet::from([name("unit:page")]),
            operations: vec![OperationCapability {
                class: name("operation:set"),
                effect_fields: BTreeSet::from([scope.field.clone(), name("state:history")]),
                protection: BTreeSet::from([
                    ProtectionKind::Conditional,
                    ProtectionKind::MonotoneMerge,
                    ProtectionKind::BestEffort,
                ]),
                deduplication: true,
                reconciliation: BTreeSet::from([name("reconcile:receipt")]),
            }],
        };
        let operation = PreparedOperation {
            identity: identity("operation"),
            class: name("operation:set"),
            behavior_revision: "1".to_owned(),
            prepared_at_milliseconds: 10,
            expires_at_milliseconds: 20,
            effects: vec![Effect {
                scope,
                group: name("group:entry"),
                change: Change::SetCompletion {
                    domain,
                    before: Progress::Prefix { completed: 0 },
                    after: Progress::Prefix { completed: 1 },
                },
            }],
            protection: Protection::BestEffort,
            replay: Replay::Unsupported,
            reconciliation: None,
            command: Command {
                method: name("native:set-pages"),
                parameters: serde_json::json!({"pages": 1}),
            },
        };
        (behavior, operation)
    }

    #[test]
    fn prepared_operation_retains_typed_effects_and_native_command() {
        let (behavior, operation) = fixture();
        operation.validate(&behavior).unwrap();
        let encoded = serde_json::to_vec(&operation).unwrap();
        let decoded: PreparedOperation = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, operation);
    }

    #[test]
    fn conditional_protection_must_cover_incidental_effect_groups() {
        let (behavior, mut operation) = fixture();
        operation.protection = Protection::Conditional {
            token: "revision".to_owned(),
            groups: operation.effect_groups(),
        };
        operation.validate(&behavior).unwrap();
        operation.effects.push(Effect {
            scope: EffectScope {
                account: identity("account"),
                subject: identity("history"),
                field: name("state:history"),
            },
            group: name("group:history"),
            change: Change::Append {
                value: serde_json::json!({"event": "completed"}),
            },
        });
        assert_eq!(
            operation.validate(&behavior),
            Err(OperationError::IncompleteProtection)
        );
    }

    #[test]
    fn a_setter_or_incidental_append_cannot_claim_monotone_protection() {
        let (behavior, mut operation) = fixture();
        operation.protection = Protection::MonotoneMerge;
        assert_eq!(
            operation.validate(&behavior),
            Err(OperationError::UnsafeMerge)
        );
    }

    #[test]
    fn unknown_units_duplicate_scopes_and_changed_behavior_are_rejected() {
        let (mut behavior, mut operation) = fixture();
        behavior.units.clear();
        assert_eq!(
            operation.validate(&behavior),
            Err(OperationError::UnsupportedUnit)
        );
        behavior.units.insert(name("unit:page"));
        operation.effects.push(operation.effects[0].clone());
        assert_eq!(
            operation.validate(&behavior),
            Err(OperationError::DuplicateEffect)
        );
        operation.effects.pop();
        operation.behavior_revision = "2".to_owned();
        assert_eq!(
            operation.validate(&behavior),
            Err(OperationError::ChangedBehavior)
        );
    }

    #[test]
    fn deduplication_requires_declared_support_and_a_future_expiry() {
        let (mut behavior, mut operation) = fixture();
        operation.replay = Replay::Deduplicated {
            key: identity("key"),
            scope: identity("scope"),
            valid_until_milliseconds: 10,
        };
        assert_eq!(
            operation.validate(&behavior),
            Err(OperationError::InvalidReplay)
        );
        operation.replay = Replay::Deduplicated {
            key: identity("key"),
            scope: identity("scope"),
            valid_until_milliseconds: 15,
        };
        operation.validate(&behavior).unwrap();
        behavior.operations[0].deduplication = false;
        assert_eq!(
            operation.validate(&behavior),
            Err(OperationError::InvalidReplay)
        );
    }

    #[test]
    fn satisfaction_never_proves_termination_or_causation() {
        let (_, operation) = fixture();
        let outcome = AttemptOutcome {
            operation: operation.identity.clone(),
            attempt: identity("attempt"),
            lifecycle: RequestLifecycle::MayStillExecute,
            effects: vec![EffectOutcome {
                scope: operation.effects[0].scope.clone(),
                knowledge: EffectKnowledge::Unknown,
            }],
            satisfaction: Satisfaction::Satisfied,
        };
        outcome
            .validate_for(&operation, &identity("attempt"))
            .unwrap();
        assert!(outcome.requires_barrier());
        assert_eq!(outcome.effects[0].knowledge, EffectKnowledge::Unknown);
        assert_eq!(
            serde_json::from_slice::<AttemptOutcome>(&serde_json::to_vec(&outcome).unwrap())
                .unwrap(),
            outcome
        );
    }

    #[test]
    fn terminal_request_can_retain_unknown_effects_and_unsatisfied_intention() {
        let (_, operation) = fixture();
        let outcome = AttemptOutcome {
            operation: operation.identity.clone(),
            attempt: identity("attempt"),
            lifecycle: RequestLifecycle::Terminal {
                evidence_kind: name("evidence:receipt"),
                evidence: identity("receipt"),
            },
            effects: vec![EffectOutcome {
                scope: operation.effects[0].scope.clone(),
                knowledge: EffectKnowledge::Unknown,
            }],
            satisfaction: Satisfaction::Unsatisfied,
        };
        outcome
            .validate_for(&operation, &identity("attempt"))
            .unwrap();
        assert!(!outcome.requires_barrier());
    }

    #[test]
    fn undispatched_outcome_cannot_claim_applied_effects() {
        let (_, operation) = fixture();
        let outcome = AttemptOutcome {
            operation: operation.identity.clone(),
            attempt: identity("attempt"),
            lifecycle: RequestLifecycle::NotDispatched,
            effects: vec![EffectOutcome {
                scope: operation.effects[0].scope.clone(),
                knowledge: EffectKnowledge::Applied,
            }],
            satisfaction: Satisfaction::Unknown,
        };
        assert_eq!(
            outcome.validate_for(&operation, &identity("attempt")),
            Err(OperationError::InvalidOutcome)
        );
    }

    #[test]
    fn outcome_scopes_are_complete_and_unique() {
        let (_, operation) = fixture();
        let mut outcome = AttemptOutcome {
            operation: operation.identity.clone(),
            attempt: identity("attempt"),
            lifecycle: RequestLifecycle::MayStillExecute,
            effects: vec![],
            satisfaction: Satisfaction::Unknown,
        };
        assert_eq!(
            outcome.validate_for(&operation, &identity("attempt")),
            Err(OperationError::InvalidOutcome)
        );
        let effect = EffectOutcome {
            scope: operation.effects[0].scope.clone(),
            knowledge: EffectKnowledge::Unknown,
        };
        outcome.effects = vec![effect.clone(), effect];
        assert_eq!(
            outcome.validate_for(&operation, &identity("attempt")),
            Err(OperationError::InvalidOutcome)
        );
    }

    #[test]
    fn native_command_parameters_are_not_debug_logged() {
        let command = Command {
            method: name("native:set"),
            parameters: serde_json::json!({"private": "not-for-logs"}),
        };
        assert!(!format!("{command:?}").contains("not-for-logs"));
    }
}
