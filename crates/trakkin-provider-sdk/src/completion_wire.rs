use std::collections::BTreeSet;

use crate::{completion as model, completion_operation as operation, v1 as wire};

const MAXIMUM_COLLECTION_ITEMS: usize = 100_000;
const MAXIMUM_JSON_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WireError {
    #[error(transparent)]
    InvalidModel(#[from] model::ModelError),
    #[error(transparent)]
    InvalidOperation(#[from] operation::OperationError),
    #[error("required completion wire field is missing: {0}")]
    Missing(&'static str),
    #[error("completion wire enum value is unspecified or unknown: {0}")]
    InvalidEnum(&'static str),
    #[error("completion wire set contains duplicates: {0}")]
    Duplicate(&'static str),
    #[error("completion wire value exceeds its size limit")]
    LimitExceeded,
    #[error("completion wire native value is not valid JSON")]
    InvalidJson,
}

fn required<T>(value: Option<T>, field: &'static str) -> Result<T, WireError> {
    value.ok_or(WireError::Missing(field))
}

fn decode_set<T, U: Ord>(
    values: Vec<T>,
    convert: impl Fn(T) -> Result<U, WireError>,
    field: &'static str,
) -> Result<BTreeSet<U>, WireError> {
    if values.len() > MAXIMUM_COLLECTION_ITEMS {
        return Err(WireError::LimitExceeded);
    }
    let mut decoded = BTreeSet::new();
    for value in values {
        if !decoded.insert(convert(value)?) {
            return Err(WireError::Duplicate(field));
        }
    }
    Ok(decoded)
}

fn decode_names(
    values: Vec<String>,
    field: &'static str,
) -> Result<BTreeSet<model::Name>, WireError> {
    decode_set(values, |value| Ok(model::Name::new(value)?), field)
}

fn decode_json(bytes: &[u8]) -> Result<serde_json::Value, WireError> {
    if bytes.len() > MAXIMUM_JSON_BYTES {
        return Err(WireError::LimitExceeded);
    }
    serde_json::from_slice(bytes).map_err(|_| WireError::InvalidJson)
}

fn encode_json(value: serde_json::Value) -> Vec<u8> {
    value.to_string().into_bytes()
}

pub fn account_identity(account: &wire::Key) -> Result<model::Identity, WireError> {
    crate::validation::key(account, "account")
        .map_err(|_| WireError::InvalidModel(model::ModelError::InvalidIdentity))?;
    if account.namespace.len() > 4096 || account.value.len() > 4096 {
        return Err(WireError::LimitExceeded);
    }
    let value = serde_json::to_string(&(account.namespace.as_str(), account.value.as_slice()))
        .map_err(|_| WireError::InvalidJson)?;
    Ok(model::Identity::new(
        model::Name::new("provider:account")?,
        value,
    )?)
}

impl TryFrom<wire::CompletionIdentity> for model::Identity {
    type Error = WireError;

    fn try_from(value: wire::CompletionIdentity) -> Result<Self, Self::Error> {
        Ok(Self::new(model::Name::new(value.namespace)?, value.value)?)
    }
}

impl From<model::Identity> for wire::CompletionIdentity {
    fn from(value: model::Identity) -> Self {
        Self {
            namespace: value.namespace().as_str().to_owned(),
            value: value.value().to_owned(),
        }
    }
}

impl TryFrom<wire::CompletionSubject> for model::Subject {
    type Error = WireError;

    fn try_from(value: wire::CompletionSubject) -> Result<Self, Self::Error> {
        Ok(Self {
            identity: required(value.identity, "subject.identity")?.try_into()?,
            classifications: decode_names(value.classifications, "subject.classifications")?,
            role: model::Name::new(value.role)?,
            label: value.label,
        })
    }
}

impl From<model::Subject> for wire::CompletionSubject {
    fn from(value: model::Subject) -> Self {
        Self {
            identity: Some(value.identity.into()),
            classifications: value
                .classifications
                .into_iter()
                .map(|name| name.as_str().to_owned())
                .collect(),
            role: value.role.as_str().to_owned(),
            label: value.label,
        }
    }
}

impl TryFrom<wire::CompletionDomain> for model::Domain {
    type Error = WireError;

    fn try_from(value: wire::CompletionDomain) -> Result<Self, Self::Error> {
        let ordering = match wire::CompletionOrdering::try_from(value.ordering) {
            Ok(wire::CompletionOrdering::Ordered) => model::Ordering::Ordered,
            Ok(wire::CompletionOrdering::Unordered) => model::Ordering::Unordered,
            _ => return Err(WireError::InvalidEnum("domain.ordering")),
        };
        if value.units.len() > MAXIMUM_COLLECTION_ITEMS {
            return Err(WireError::LimitExceeded);
        }
        Ok(Self::new(
            required(value.identity, "domain.identity")?.try_into()?,
            value.revision,
            model::Name::new(value.unit)?,
            ordering,
            value
                .units
                .into_iter()
                .map(model::Identity::try_from)
                .collect::<Result<_, _>>()?,
            value.closed,
        )?)
    }
}

impl From<model::Domain> for wire::CompletionDomain {
    fn from(value: model::Domain) -> Self {
        Self {
            identity: Some(value.identity().clone().into()),
            revision: value.revision().to_owned(),
            unit: value.unit().as_str().to_owned(),
            ordering: match value.ordering() {
                model::Ordering::Ordered => wire::CompletionOrdering::Ordered as i32,
                model::Ordering::Unordered => wire::CompletionOrdering::Unordered as i32,
            },
            units: value.units().iter().cloned().map(Into::into).collect(),
            closed: value.closed(),
        }
    }
}

impl TryFrom<wire::CompletionItems> for BTreeSet<model::Identity> {
    type Error = WireError;

    fn try_from(value: wire::CompletionItems) -> Result<Self, Self::Error> {
        decode_set(
            value.completed,
            model::Identity::try_from,
            "items.completed",
        )
    }
}

impl From<BTreeSet<model::Identity>> for wire::CompletionItems {
    fn from(value: BTreeSet<model::Identity>) -> Self {
        Self {
            completed: value.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<wire::CompletionProgress> for model::Progress {
    type Error = WireError;

    fn try_from(value: wire::CompletionProgress) -> Result<Self, Self::Error> {
        use wire::completion_progress::Value;
        Ok(match required(value.value, "progress.value")? {
            Value::Items(items) => Self::Items {
                completed: items.try_into()?,
            },
            Value::Prefix(completed) => Self::Prefix { completed },
            Value::Cardinality(completed) => Self::Cardinality { completed },
        })
    }
}

impl From<model::Progress> for wire::CompletionProgress {
    fn from(value: model::Progress) -> Self {
        use wire::completion_progress::Value;
        Self {
            value: Some(match value {
                model::Progress::Items { completed } => Value::Items(completed.into()),
                model::Progress::Prefix { completed } => Value::Prefix(completed),
                model::Progress::Cardinality { completed } => Value::Cardinality(completed),
            }),
        }
    }
}

impl TryFrom<wire::CompletionObservation> for model::Observation {
    type Error = WireError;

    fn try_from(value: wire::CompletionObservation) -> Result<Self, Self::Error> {
        use wire::completion_observation::Presence;
        let quality = match wire::CompletionReadQuality::try_from(value.quality) {
            Ok(wire::CompletionReadQuality::Complete) => model::ReadQuality::Complete,
            Ok(wire::CompletionReadQuality::Partial) => model::ReadQuality::Partial,
            Ok(wire::CompletionReadQuality::Unreadable) => model::ReadQuality::Unreadable,
            Ok(wire::CompletionReadQuality::Stale) => model::ReadQuality::Stale,
            _ => return Err(WireError::InvalidEnum("observation.quality")),
        };
        let decoded = Self {
            origin: required(value.origin, "observation.origin")?.try_into()?,
            account: required(value.account, "observation.account")?.try_into()?,
            subject: required(value.subject, "observation.subject")?.try_into()?,
            behavior_revision: value.behavior_revision,
            remote_revision: value.remote_revision,
            acquired_at_milliseconds: value.acquired_at_milliseconds,
            domain: required(value.domain, "observation.domain")?.try_into()?,
            quality,
            presence: match required(value.presence, "observation.presence")? {
                Presence::Present(progress) => model::Presence::Present(progress.try_into()?),
                Presence::Missing(()) => model::Presence::Missing,
                Presence::Cleared(()) => model::Presence::Cleared,
                Presence::MeaningfulAbsence(()) => model::Presence::MeaningfulAbsence,
            },
            native_value: decode_json(&value.native_value_json)?,
        };
        decoded.validate()?;
        Ok(decoded)
    }
}

impl From<model::Observation> for wire::CompletionObservation {
    fn from(value: model::Observation) -> Self {
        use wire::completion_observation::Presence;
        Self {
            origin: Some(value.origin.into()),
            account: Some(value.account.into()),
            subject: Some(value.subject.into()),
            behavior_revision: value.behavior_revision,
            remote_revision: value.remote_revision,
            acquired_at_milliseconds: value.acquired_at_milliseconds,
            domain: Some(value.domain.into()),
            quality: match value.quality {
                model::ReadQuality::Complete => wire::CompletionReadQuality::Complete as i32,
                model::ReadQuality::Partial => wire::CompletionReadQuality::Partial as i32,
                model::ReadQuality::Unreadable => wire::CompletionReadQuality::Unreadable as i32,
                model::ReadQuality::Stale => wire::CompletionReadQuality::Stale as i32,
            },
            presence: Some(match value.presence {
                model::Presence::Present(progress) => Presence::Present(progress.into()),
                model::Presence::Missing => Presence::Missing(()),
                model::Presence::Cleared => Presence::Cleared(()),
                model::Presence::MeaningfulAbsence => Presence::MeaningfulAbsence(()),
            }),
            native_value_json: encode_json(value.native_value),
        }
    }
}

impl TryFrom<wire::CompletionEffectScope> for operation::EffectScope {
    type Error = WireError;
    fn try_from(value: wire::CompletionEffectScope) -> Result<Self, Self::Error> {
        Ok(Self {
            account: required(value.account, "scope.account")?.try_into()?,
            subject: required(value.subject, "scope.subject")?.try_into()?,
            field: model::Name::new(value.field)?,
        })
    }
}

impl From<operation::EffectScope> for wire::CompletionEffectScope {
    fn from(value: operation::EffectScope) -> Self {
        Self {
            account: Some(value.account.into()),
            subject: Some(value.subject.into()),
            field: value.field.as_str().to_owned(),
        }
    }
}

impl TryFrom<wire::CompletionEffectGroup> for operation::EffectGroup {
    type Error = WireError;
    fn try_from(value: wire::CompletionEffectGroup) -> Result<Self, Self::Error> {
        Ok(Self {
            account: required(value.account, "group.account")?.try_into()?,
            subject: required(value.subject, "group.subject")?.try_into()?,
            group: model::Name::new(value.group)?,
        })
    }
}

impl From<operation::EffectGroup> for wire::CompletionEffectGroup {
    fn from(value: operation::EffectGroup) -> Self {
        Self {
            account: Some(value.account.into()),
            subject: Some(value.subject.into()),
            group: value.group.as_str().to_owned(),
        }
    }
}

pub fn decode_access(
    value: wire::CompletionResourceAccess,
    behavior: &operation::Behavior,
) -> Result<operation::ResourceAccess, WireError> {
    let decoded = operation::ResourceAccess {
        scope: required(value.scope, "access.scope")?.try_into()?,
        group: model::Name::new(value.group)?,
        canonical_group: required(value.canonical_group, "access.canonical_group")?.try_into()?,
        revision: value.revision,
        readable: value.readable,
        writable: value.writable,
    };
    decoded.validate(behavior)?;
    Ok(decoded)
}

impl From<operation::ResourceAccess> for wire::CompletionResourceAccess {
    fn from(value: operation::ResourceAccess) -> Self {
        Self {
            scope: Some(value.scope.into()),
            group: value.group.as_str().to_owned(),
            canonical_group: Some(value.canonical_group.into()),
            revision: value.revision,
            readable: value.readable,
            writable: value.writable,
        }
    }
}

fn decode_protection_kind(value: i32) -> Result<operation::ProtectionKind, WireError> {
    Ok(match wire::CompletionProtectionKind::try_from(value) {
        Ok(wire::CompletionProtectionKind::Conditional) => operation::ProtectionKind::Conditional,
        Ok(wire::CompletionProtectionKind::MonotoneMerge) => {
            operation::ProtectionKind::MonotoneMerge
        }
        Ok(wire::CompletionProtectionKind::BestEffort) => operation::ProtectionKind::BestEffort,
        _ => return Err(WireError::InvalidEnum("capability.protection")),
    })
}

impl TryFrom<wire::CompletionBehavior> for operation::Behavior {
    type Error = WireError;
    fn try_from(value: wire::CompletionBehavior) -> Result<Self, Self::Error> {
        if value.operations.len() > operation::MAXIMUM_EFFECTS {
            return Err(WireError::LimitExceeded);
        }
        let operations = value
            .operations
            .into_iter()
            .map(|capability| {
                Ok(operation::OperationCapability {
                    class: model::Name::new(capability.class)?,
                    effect_fields: decode_names(
                        capability.effect_fields,
                        "capability.effect_fields",
                    )?,
                    protection: decode_set(
                        capability.protection,
                        decode_protection_kind,
                        "capability.protection",
                    )?,
                    deduplication: capability.deduplication,
                    reconciliation: decode_names(
                        capability.reconciliation,
                        "capability.reconciliation",
                    )?,
                })
            })
            .collect::<Result<_, WireError>>()?;
        let decoded = Self {
            revision: value.revision,
            subject_roles: decode_names(value.subject_roles, "behavior.subject_roles")?,
            units: decode_names(value.units, "behavior.units")?,
            operations,
        };
        decoded.validate()?;
        Ok(decoded)
    }
}

impl From<operation::Behavior> for wire::CompletionBehavior {
    fn from(value: operation::Behavior) -> Self {
        Self {
            revision: value.revision,
            subject_roles: value
                .subject_roles
                .into_iter()
                .map(|name| name.as_str().to_owned())
                .collect(),
            units: value
                .units
                .into_iter()
                .map(|name| name.as_str().to_owned())
                .collect(),
            operations: value
                .operations
                .into_iter()
                .map(|capability| wire::CompletionOperationCapability {
                    class: capability.class.as_str().to_owned(),
                    effect_fields: capability
                        .effect_fields
                        .into_iter()
                        .map(|name| name.as_str().to_owned())
                        .collect(),
                    protection: capability
                        .protection
                        .into_iter()
                        .map(|kind| match kind {
                            operation::ProtectionKind::Conditional => {
                                wire::CompletionProtectionKind::Conditional as i32
                            }
                            operation::ProtectionKind::MonotoneMerge => {
                                wire::CompletionProtectionKind::MonotoneMerge as i32
                            }
                            operation::ProtectionKind::BestEffort => {
                                wire::CompletionProtectionKind::BestEffort as i32
                            }
                        })
                        .collect(),
                    deduplication: capability.deduplication,
                    reconciliation: capability
                        .reconciliation
                        .into_iter()
                        .map(|name| name.as_str().to_owned())
                        .collect(),
                })
                .collect(),
        }
    }
}

fn decode_before(value: wire::CompletionBeforeValue) -> Result<operation::BeforeValue, WireError> {
    use wire::completion_before_value::Value;
    Ok(match required(value.value, "before.value")? {
        Value::KnownJson(bytes) => operation::BeforeValue::Known(decode_json(&bytes)?),
        Value::Missing(()) => operation::BeforeValue::Missing,
        Value::Unknown(()) => operation::BeforeValue::Unknown,
    })
}

impl From<operation::BeforeValue> for wire::CompletionBeforeValue {
    fn from(value: operation::BeforeValue) -> Self {
        use wire::completion_before_value::Value;
        Self {
            value: Some(match value {
                operation::BeforeValue::Known(value) => Value::KnownJson(encode_json(value)),
                operation::BeforeValue::Missing => Value::Missing(()),
                operation::BeforeValue::Unknown => Value::Unknown(()),
            }),
        }
    }
}

fn decode_effect(value: wire::CompletionEffect) -> Result<operation::Effect, WireError> {
    use wire::completion_effect::Change;
    Ok(operation::Effect {
        scope: required(value.scope, "effect.scope")?.try_into()?,
        group: model::Name::new(value.group)?,
        change: match required(value.change, "effect.change")? {
            Change::SetCompletion(value) => operation::Change::SetCompletion {
                domain: required(value.domain, "setter.domain")?.try_into()?,
                before: required(value.before, "setter.before")?.try_into()?,
                after: required(value.after, "setter.after")?.try_into()?,
            },
            Change::MergeItems(value) => operation::Change::MergeItems {
                domain: required(value.domain, "merge.domain")?.try_into()?,
                before: required(value.before, "merge.before")?.try_into()?,
                additions: required(value.additions, "merge.additions")?.try_into()?,
            },
            Change::SetValue(value) => operation::Change::SetValue {
                before: decode_before(required(value.before, "setter.before")?)?,
                after: decode_json(&value.after_json)?,
            },
            Change::AppendJson(bytes) => operation::Change::Append {
                value: decode_json(&bytes)?,
            },
        },
    })
}

impl From<operation::Effect> for wire::CompletionEffect {
    fn from(value: operation::Effect) -> Self {
        use wire::completion_effect::Change;
        Self {
            scope: Some(value.scope.into()),
            group: value.group.as_str().to_owned(),
            change: Some(match value.change {
                operation::Change::SetCompletion {
                    domain,
                    before,
                    after,
                } => Change::SetCompletion(wire::CompletionSetter {
                    domain: Some(domain.into()),
                    before: Some(before.into()),
                    after: Some(after.into()),
                }),
                operation::Change::MergeItems {
                    domain,
                    before,
                    additions,
                } => Change::MergeItems(wire::CompletionMerge {
                    domain: Some(domain.into()),
                    before: Some(before.into()),
                    additions: Some(additions.into()),
                }),
                operation::Change::SetValue { before, after } => {
                    Change::SetValue(wire::CompletionValueSetter {
                        before: Some(before.into()),
                        after_json: encode_json(after),
                    })
                }
                operation::Change::Append { value } => Change::AppendJson(encode_json(value)),
            }),
        }
    }
}

fn decode_protection(
    value: wire::CompletionProtection,
) -> Result<operation::Protection, WireError> {
    use wire::completion_protection::Value;
    Ok(match required(value.value, "protection.value")? {
        Value::Conditional(value) => operation::Protection::Conditional {
            token: value.token,
            groups: decode_set(
                value.groups,
                operation::EffectGroup::try_from,
                "protection.groups",
            )?,
        },
        Value::MonotoneMerge(()) => operation::Protection::MonotoneMerge,
        Value::BestEffort(()) => operation::Protection::BestEffort,
    })
}

impl From<operation::Protection> for wire::CompletionProtection {
    fn from(value: operation::Protection) -> Self {
        use wire::completion_protection::Value;
        Self {
            value: Some(match value {
                operation::Protection::Conditional { token, groups } => {
                    Value::Conditional(wire::CompletionConditionalProtection {
                        token,
                        groups: groups.into_iter().map(Into::into).collect(),
                    })
                }
                operation::Protection::MonotoneMerge => Value::MonotoneMerge(()),
                operation::Protection::BestEffort => Value::BestEffort(()),
            }),
        }
    }
}

fn decode_replay(value: wire::CompletionReplay) -> Result<operation::Replay, WireError> {
    use wire::completion_replay::Value;
    Ok(match required(value.value, "replay.value")? {
        Value::Unsupported(()) => operation::Replay::Unsupported,
        Value::Deduplicated(value) => operation::Replay::Deduplicated {
            key: required(value.key, "replay.key")?.try_into()?,
            scope: required(value.scope, "replay.scope")?.try_into()?,
            valid_until_milliseconds: value.valid_until_milliseconds,
        },
    })
}

impl From<operation::Replay> for wire::CompletionReplay {
    fn from(value: operation::Replay) -> Self {
        use wire::completion_replay::Value;
        Self {
            value: Some(match value {
                operation::Replay::Unsupported => Value::Unsupported(()),
                operation::Replay::Deduplicated {
                    key,
                    scope,
                    valid_until_milliseconds,
                } => Value::Deduplicated(wire::CompletionDeduplication {
                    key: Some(key.into()),
                    scope: Some(scope.into()),
                    valid_until_milliseconds,
                }),
            }),
        }
    }
}

pub fn decode_prepared(
    value: wire::PreparedCompletionOperation,
    behavior: &operation::Behavior,
) -> Result<operation::PreparedOperation, WireError> {
    if value.effects.len() > operation::MAXIMUM_EFFECTS {
        return Err(WireError::LimitExceeded);
    }
    let command = required(value.command, "operation.command")?;
    let decoded = operation::PreparedOperation {
        identity: required(value.identity, "operation.identity")?.try_into()?,
        class: model::Name::new(value.class)?,
        behavior_revision: value.behavior_revision,
        prepared_at_milliseconds: value.prepared_at_milliseconds,
        expires_at_milliseconds: value.expires_at_milliseconds,
        effects: value
            .effects
            .into_iter()
            .map(decode_effect)
            .collect::<Result<_, _>>()?,
        protection: decode_protection(required(value.protection, "operation.protection")?)?,
        replay: decode_replay(required(value.replay, "operation.replay")?)?,
        reconciliation: value.reconciliation.map(model::Name::new).transpose()?,
        command: operation::Command {
            method: model::Name::new(command.method)?,
            parameters: decode_json(&command.parameters_json)?,
        },
    };
    decoded.validate(behavior)?;
    Ok(decoded)
}

impl From<operation::PreparedOperation> for wire::PreparedCompletionOperation {
    fn from(value: operation::PreparedOperation) -> Self {
        Self {
            identity: Some(value.identity.into()),
            class: value.class.as_str().to_owned(),
            behavior_revision: value.behavior_revision,
            prepared_at_milliseconds: value.prepared_at_milliseconds,
            expires_at_milliseconds: value.expires_at_milliseconds,
            effects: value.effects.into_iter().map(Into::into).collect(),
            protection: Some(value.protection.into()),
            replay: Some(value.replay.into()),
            reconciliation: value.reconciliation.map(|name| name.as_str().to_owned()),
            command: Some(wire::CompletionCommand {
                method: value.command.method.as_str().to_owned(),
                parameters_json: encode_json(value.command.parameters),
            }),
        }
    }
}

pub fn decode_outcome(
    value: wire::CompletionAttemptOutcome,
    prepared: &operation::PreparedOperation,
    attempt: &model::Identity,
) -> Result<operation::AttemptOutcome, WireError> {
    use wire::completion_attempt_outcome::Lifecycle;
    if value.effects.len() > operation::MAXIMUM_EFFECTS {
        return Err(WireError::LimitExceeded);
    }
    let effects = value
        .effects
        .into_iter()
        .map(|effect| {
            Ok(operation::EffectOutcome {
                scope: required(effect.scope, "outcome.effect.scope")?.try_into()?,
                knowledge: match wire::CompletionEffectKnowledge::try_from(effect.knowledge) {
                    Ok(wire::CompletionEffectKnowledge::Unknown) => {
                        operation::EffectKnowledge::Unknown
                    }
                    Ok(wire::CompletionEffectKnowledge::NotApplied) => {
                        operation::EffectKnowledge::NotApplied
                    }
                    Ok(wire::CompletionEffectKnowledge::Applied) => {
                        operation::EffectKnowledge::Applied
                    }
                    Ok(wire::CompletionEffectKnowledge::PartiallyApplied) => {
                        operation::EffectKnowledge::PartiallyApplied
                    }
                    _ => return Err(WireError::InvalidEnum("outcome.effect.knowledge")),
                },
            })
        })
        .collect::<Result<_, WireError>>()?;
    let decoded = operation::AttemptOutcome {
        operation: required(value.operation, "outcome.operation")?.try_into()?,
        attempt: required(value.attempt, "outcome.attempt")?.try_into()?,
        lifecycle: match required(value.lifecycle, "outcome.lifecycle")? {
            Lifecycle::NotDispatched(()) => operation::RequestLifecycle::NotDispatched,
            Lifecycle::MayStillExecute(()) => operation::RequestLifecycle::MayStillExecute,
            Lifecycle::Terminal(value) => operation::RequestLifecycle::Terminal {
                evidence_kind: model::Name::new(value.kind)?,
                evidence: required(value.identity, "outcome.terminal.identity")?.try_into()?,
            },
        },
        effects,
        satisfaction: match wire::CompletionSatisfaction::try_from(value.satisfaction) {
            Ok(wire::CompletionSatisfaction::Unknown) => operation::Satisfaction::Unknown,
            Ok(wire::CompletionSatisfaction::Satisfied) => operation::Satisfaction::Satisfied,
            Ok(wire::CompletionSatisfaction::Unsatisfied) => operation::Satisfaction::Unsatisfied,
            _ => return Err(WireError::InvalidEnum("outcome.satisfaction")),
        },
    };
    decoded.validate_for(prepared, attempt)?;
    Ok(decoded)
}

impl From<operation::AttemptOutcome> for wire::CompletionAttemptOutcome {
    fn from(value: operation::AttemptOutcome) -> Self {
        use wire::completion_attempt_outcome::Lifecycle;
        Self {
            operation: Some(value.operation.into()),
            attempt: Some(value.attempt.into()),
            lifecycle: Some(match value.lifecycle {
                operation::RequestLifecycle::NotDispatched => Lifecycle::NotDispatched(()),
                operation::RequestLifecycle::MayStillExecute => Lifecycle::MayStillExecute(()),
                operation::RequestLifecycle::Terminal {
                    evidence_kind,
                    evidence,
                } => Lifecycle::Terminal(wire::CompletionTerminalEvidence {
                    kind: evidence_kind.as_str().to_owned(),
                    identity: Some(evidence.into()),
                }),
            }),
            effects: value
                .effects
                .into_iter()
                .map(|effect| wire::CompletionEffectOutcome {
                    scope: Some(effect.scope.into()),
                    knowledge: match effect.knowledge {
                        operation::EffectKnowledge::Unknown => {
                            wire::CompletionEffectKnowledge::Unknown as i32
                        }
                        operation::EffectKnowledge::NotApplied => {
                            wire::CompletionEffectKnowledge::NotApplied as i32
                        }
                        operation::EffectKnowledge::Applied => {
                            wire::CompletionEffectKnowledge::Applied as i32
                        }
                        operation::EffectKnowledge::PartiallyApplied => {
                            wire::CompletionEffectKnowledge::PartiallyApplied as i32
                        }
                    },
                })
                .collect(),
            satisfaction: match value.satisfaction {
                operation::Satisfaction::Unknown => wire::CompletionSatisfaction::Unknown as i32,
                operation::Satisfaction::Satisfied => {
                    wire::CompletionSatisfaction::Satisfied as i32
                }
                operation::Satisfaction::Unsatisfied => {
                    wire::CompletionSatisfaction::Unsatisfied as i32
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    fn identity(value: &str) -> model::Identity {
        model::Identity::new(model::Name::new("fixture:id").unwrap(), value).unwrap()
    }

    #[test]
    fn account_identity_is_stable_binary_safe_and_namespaced() {
        let first = wire::Key {
            namespace: "provider.account".to_owned(),
            value: vec![0, 255, 1],
        };
        let identity = account_identity(&first).unwrap();
        assert_eq!(identity, account_identity(&first).unwrap());
        assert_eq!(identity.namespace().as_str(), "provider:account");
        for key in [
            wire::Key {
                namespace: "other.account".to_owned(),
                ..first.clone()
            },
            wire::Key {
                value: vec![0, 255, 2],
                ..first.clone()
            },
        ] {
            assert_ne!(identity, account_identity(&key).unwrap());
        }
        let reconstructed: (String, Vec<u8>) = serde_json::from_str(identity.value()).unwrap();
        assert_eq!(reconstructed, (first.namespace, first.value));
    }

    #[test]
    fn account_identity_rejects_empty_and_unbounded_keys() {
        for account in [
            wire::Key {
                namespace: String::new(),
                value: vec![1],
            },
            wire::Key {
                namespace: "provider.account".to_owned(),
                value: Vec::new(),
            },
            wire::Key {
                namespace: "provider.account".to_owned(),
                value: vec![255; 4097],
            },
        ] {
            assert!(account_identity(&account).is_err());
        }
    }

    fn observation() -> model::Observation {
        model::Observation {
            origin: identity("origin"),
            account: identity("account"),
            subject: identity("recording"),
            behavior_revision: "1".to_owned(),
            remote_revision: Some("remote-1".to_owned()),
            acquired_at_milliseconds: 100,
            domain: model::Domain::new(
                identity("release"),
                "1",
                model::Name::new("unit:track").unwrap(),
                model::Ordering::Ordered,
                vec![identity("track")],
                true,
            )
            .unwrap(),
            quality: model::ReadQuality::Complete,
            presence: model::Presence::Present(model::Progress::Items {
                completed: BTreeSet::from([identity("track")]),
            }),
            native_value: serde_json::json!({"plays": 3}),
        }
    }

    fn prepared() -> (operation::Behavior, operation::PreparedOperation) {
        let source = observation();
        let scope = operation::EffectScope {
            account: source.account,
            subject: source.subject,
            field: model::Name::new("state:completion").unwrap(),
        };
        let class = model::Name::new("operation:merge").unwrap();
        let behavior = operation::Behavior {
            revision: "1".to_owned(),
            subject_roles: BTreeSet::from([model::Name::new("subject:recording").unwrap()]),
            units: BTreeSet::from([source.domain.unit().clone()]),
            operations: vec![operation::OperationCapability {
                class: class.clone(),
                effect_fields: BTreeSet::from([scope.field.clone()]),
                protection: BTreeSet::from([operation::ProtectionKind::MonotoneMerge]),
                deduplication: false,
                reconciliation: BTreeSet::new(),
            }],
        };
        let prepared = operation::PreparedOperation {
            identity: identity("operation"),
            class,
            behavior_revision: "1".to_owned(),
            prepared_at_milliseconds: 10,
            expires_at_milliseconds: 20,
            effects: vec![operation::Effect {
                scope,
                group: model::Name::new("group:entry").unwrap(),
                change: operation::Change::MergeItems {
                    domain: source.domain,
                    before: BTreeSet::new(),
                    additions: BTreeSet::from([identity("track")]),
                },
            }],
            protection: operation::Protection::MonotoneMerge,
            replay: operation::Replay::Unsupported,
            reconciliation: None,
            command: operation::Command {
                method: model::Name::new("native:merge").unwrap(),
                parameters: serde_json::json!({"item": "track"}),
            },
        };
        (behavior, prepared)
    }

    #[test]
    fn resource_access_roundtrips_explicit_aliases_and_read_only_scopes() {
        let (behavior, prepared) = prepared();
        let effect = &prepared.effects[0];
        let access = operation::ResourceAccess {
            scope: effect.scope.clone(),
            group: effect.group.clone(),
            canonical_group: operation::EffectGroup {
                account: identity("canonical-account"),
                subject: identity("canonical-subject"),
                group: model::Name::new("canonical:completion").unwrap(),
            },
            revision: "access-1".to_owned(),
            readable: true,
            writable: true,
        };
        let encoded: wire::CompletionResourceAccess = access.clone().into();
        let bytes = encoded.encode_to_vec();
        assert_eq!(
            decode_access(
                wire::CompletionResourceAccess::decode(bytes.as_slice()).unwrap(),
                &behavior
            )
            .unwrap(),
            access
        );
        assert_ne!(access.scope.account, access.canonical_group.account);
        let mut read_only = access;
        read_only.scope.field = model::Name::new("state:read-only").unwrap();
        read_only.writable = false;
        assert!(decode_access(read_only.clone().into(), &behavior).is_ok());
        read_only.writable = true;
        assert_eq!(
            decode_access(read_only.into(), &behavior),
            Err(WireError::InvalidOperation(
                operation::OperationError::InvalidAccess
            ))
        );
    }

    #[test]
    fn resource_access_rejects_missing_identities_and_invalid_revisions() {
        let (behavior, prepared) = prepared();
        let effect = &prepared.effects[0];
        let valid: wire::CompletionResourceAccess = operation::ResourceAccess {
            scope: effect.scope.clone(),
            group: effect.group.clone(),
            canonical_group: effect.group(),
            revision: "1".to_owned(),
            readable: true,
            writable: true,
        }
        .into();
        for revision in [String::new(), "x".repeat(4097)] {
            assert!(
                decode_access(
                    wire::CompletionResourceAccess {
                        revision,
                        ..valid.clone()
                    },
                    &behavior
                )
                .is_err()
            );
        }
        assert!(
            decode_access(
                wire::CompletionResourceAccess {
                    scope: None,
                    ..valid.clone()
                },
                &behavior
            )
            .is_err()
        );
        assert!(
            decode_access(
                wire::CompletionResourceAccess {
                    canonical_group: None,
                    ..valid
                },
                &behavior
            )
            .is_err()
        );
    }

    #[test]
    fn prepared_effects_round_trip_and_validate_against_declared_behavior() {
        let (behavior, prepared) = prepared();
        assert_eq!(
            operation::Behavior::try_from(wire::CompletionBehavior::from(behavior.clone()))
                .unwrap(),
            behavior
        );
        let encoded = wire::PreparedCompletionOperation::from(prepared.clone()).encode_to_vec();
        let decoded = wire::PreparedCompletionOperation::decode(encoded.as_slice()).unwrap();
        assert_eq!(
            decode_prepared(decoded.clone(), &behavior).unwrap(),
            prepared
        );
        let mut changed = behavior;
        changed.revision = "2".to_owned();
        assert_eq!(
            decode_prepared(decoded, &changed),
            Err(WireError::InvalidOperation(
                operation::OperationError::ChangedBehavior
            ))
        );
    }

    #[test]
    fn outcome_decode_correlates_attempts_and_retains_uncertainty() {
        let (_, prepared) = prepared();
        let attempt = identity("attempt");
        let outcome = operation::AttemptOutcome {
            operation: prepared.identity.clone(),
            attempt: attempt.clone(),
            lifecycle: operation::RequestLifecycle::MayStillExecute,
            effects: vec![operation::EffectOutcome {
                scope: prepared.effects[0].scope.clone(),
                knowledge: operation::EffectKnowledge::Unknown,
            }],
            satisfaction: operation::Satisfaction::Satisfied,
        };
        let encoded = wire::CompletionAttemptOutcome::from(outcome.clone()).encode_to_vec();
        let decoded = wire::CompletionAttemptOutcome::decode(encoded.as_slice()).unwrap();
        assert_eq!(
            decode_outcome(decoded.clone(), &prepared, &attempt).unwrap(),
            outcome
        );
        assert!(
            decode_outcome(decoded.clone(), &prepared, &attempt)
                .unwrap()
                .requires_barrier()
        );
        assert_eq!(
            decode_outcome(decoded.clone(), &prepared, &identity("wrong-attempt")),
            Err(WireError::InvalidOperation(
                operation::OperationError::InvalidOutcome
            ))
        );
        let mut missing = decoded;
        missing.lifecycle = None;
        assert_eq!(
            decode_outcome(missing, &prepared, &attempt),
            Err(WireError::Missing("outcome.lifecycle"))
        );
    }

    #[test]
    fn observation_round_trips_through_protobuf_without_semantic_loss() {
        let original = observation();
        let encoded = wire::CompletionObservation::from(original.clone()).encode_to_vec();
        let decoded = wire::CompletionObservation::decode(encoded.as_slice()).unwrap();
        assert_eq!(model::Observation::try_from(decoded).unwrap(), original);
    }

    #[test]
    fn unknown_enums_missing_presence_and_duplicates_are_rejected() {
        let mut source = wire::CompletionObservation::from(observation());
        source.quality = 0;
        assert_eq!(
            model::Observation::try_from(source.clone()),
            Err(WireError::InvalidEnum("observation.quality"))
        );
        source.quality = wire::CompletionReadQuality::Complete as i32;
        source.presence = None;
        assert_eq!(
            model::Observation::try_from(source),
            Err(WireError::Missing("observation.presence"))
        );
        let unit = wire::CompletionIdentity::from(identity("track"));
        assert_eq!(
            BTreeSet::<model::Identity>::try_from(wire::CompletionItems {
                completed: vec![unit.clone(), unit]
            }),
            Err(WireError::Duplicate("items.completed"))
        );
    }

    #[test]
    fn wire_decode_enforces_progress_domain_and_absence_quality() {
        let mut source = wire::CompletionObservation::from(observation());
        source.presence = Some(wire::completion_observation::Presence::Present(
            model::Progress::Prefix { completed: 2 }.into(),
        ));
        assert_eq!(
            model::Observation::try_from(source.clone()),
            Err(WireError::InvalidModel(
                model::ModelError::ProgressOutOfBounds
            ))
        );
        source.quality = wire::CompletionReadQuality::Partial as i32;
        source.presence = Some(wire::completion_observation::Presence::MeaningfulAbsence(()));
        assert_eq!(
            model::Observation::try_from(source),
            Err(WireError::InvalidModel(
                model::ModelError::IncompleteAbsence
            ))
        );
    }

    #[test]
    fn invalid_native_json_is_bounded_and_not_reflected_in_errors() {
        assert_eq!(
            decode_json(b"secret response body"),
            Err(WireError::InvalidJson)
        );
        assert_eq!(
            decode_json(&vec![b' '; MAXIMUM_JSON_BYTES + 1]),
            Err(WireError::LimitExceeded)
        );
    }
}
