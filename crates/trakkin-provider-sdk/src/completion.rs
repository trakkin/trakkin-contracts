use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub const MAXIMUM_DOMAIN_UNITS: usize = 100_000;
pub const MAXIMUM_REVISION_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Name(String);

impl Name {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let Some((namespace, name)) = value.split_once(':') else {
            return Err(ModelError::InvalidName);
        };
        if namespace.is_empty()
            || name.is_empty()
            || value.len() > 256
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'.' | b'/' | b'_' | b'-')
            })
        {
            return Err(ModelError::InvalidName);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Name {
    type Error = ModelError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Name> for String {
    fn from(value: Name) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "IdentityData", into = "IdentityData")]
pub struct Identity {
    namespace: Name,
    value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityData {
    namespace: Name,
    value: String,
}

impl Identity {
    pub fn new(namespace: Name, value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
            return Err(ModelError::InvalidIdentity);
        }
        Ok(Self { namespace, value })
    }

    pub fn namespace(&self) -> &Name {
        &self.namespace
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

impl TryFrom<IdentityData> for Identity {
    type Error = ModelError;

    fn try_from(value: IdentityData) -> Result<Self, Self::Error> {
        Self::new(value.namespace, value.value)
    }
}

impl From<Identity> for IdentityData {
    fn from(value: Identity) -> Self {
        Self {
            namespace: value.namespace,
            value: value.value,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub identity: Identity,
    pub classifications: BTreeSet<Name>,
    pub role: Name,
    pub label: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ordering {
    Ordered,
    Unordered,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "DomainData", into = "DomainData")]
pub struct Domain {
    identity: Identity,
    revision: String,
    unit: Name,
    ordering: Ordering,
    units: Vec<Identity>,
    closed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DomainData {
    identity: Identity,
    revision: String,
    unit: Name,
    ordering: Ordering,
    units: Vec<Identity>,
    closed: bool,
}

impl Domain {
    pub fn new(
        identity: Identity,
        revision: impl Into<String>,
        unit: Name,
        ordering: Ordering,
        mut units: Vec<Identity>,
        closed: bool,
    ) -> Result<Self, ModelError> {
        let revision = revision.into();
        if revision.is_empty() || revision.len() > MAXIMUM_REVISION_BYTES {
            return Err(ModelError::InvalidRevision);
        }
        if units.len() > MAXIMUM_DOMAIN_UNITS {
            return Err(ModelError::DomainTooLarge);
        }
        if units.iter().collect::<BTreeSet<_>>().len() != units.len() {
            return Err(ModelError::DuplicateUnit);
        }
        if ordering == Ordering::Unordered {
            units.sort();
        }
        Ok(Self {
            identity,
            revision,
            unit,
            ordering,
            units,
            closed,
        })
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub fn unit(&self) -> &Name {
        &self.unit
    }

    pub fn ordering(&self) -> Ordering {
        self.ordering
    }

    pub fn units(&self) -> &[Identity] {
        &self.units
    }

    pub fn closed(&self) -> bool {
        self.closed
    }
}

impl TryFrom<DomainData> for Domain {
    type Error = ModelError;

    fn try_from(value: DomainData) -> Result<Self, Self::Error> {
        Self::new(
            value.identity,
            value.revision,
            value.unit,
            value.ordering,
            value.units,
            value.closed,
        )
    }
}

impl From<Domain> for DomainData {
    fn from(value: Domain) -> Self {
        Self {
            identity: value.identity,
            revision: value.revision,
            unit: value.unit,
            ordering: value.ordering,
            units: value.units,
            closed: value.closed,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Progress {
    Items { completed: BTreeSet<Identity> },
    Prefix { completed: u32 },
    Cardinality { completed: u32 },
}

impl Progress {
    pub fn validate(&self, domain: &Domain) -> Result<(), ModelError> {
        match self {
            Self::Items { completed } => {
                let known: BTreeSet<_> = domain.units.iter().collect();
                if !completed.iter().all(|unit| known.contains(unit)) {
                    return Err(ModelError::UnknownUnit);
                }
            }
            Self::Prefix { completed } => {
                if domain.ordering != Ordering::Ordered {
                    return Err(ModelError::UnorderedPrefix);
                }
                if *completed as usize > domain.units.len() {
                    return Err(ModelError::ProgressOutOfBounds);
                }
            }
            Self::Cardinality { completed } => {
                if !domain.closed {
                    return Err(ModelError::OpenCardinality);
                }
                if *completed as usize > domain.units.len() {
                    return Err(ModelError::ProgressOutOfBounds);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadQuality {
    Complete,
    Partial,
    Unreadable,
    Stale,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Presence {
    Present(Progress),
    Cleared,
    Missing,
    MeaningfulAbsence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub origin: Identity,
    pub account: Identity,
    pub subject: Identity,
    pub behavior_revision: String,
    pub remote_revision: Option<String>,
    pub acquired_at_milliseconds: i64,
    pub domain: Domain,
    pub quality: ReadQuality,
    pub presence: Presence,
    pub native_value: serde_json::Value,
}

impl Observation {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.behavior_revision.is_empty()
            || self.behavior_revision.len() > MAXIMUM_REVISION_BYTES
            || self.remote_revision.as_ref().is_some_and(|revision| {
                revision.is_empty() || revision.len() > MAXIMUM_REVISION_BYTES
            })
        {
            return Err(ModelError::InvalidRevision);
        }
        if let Presence::Present(progress) = &self.presence {
            progress.validate(&self.domain)?;
        }
        if self.presence == Presence::MeaningfulAbsence && self.quality != ReadQuality::Complete {
            return Err(ModelError::IncompleteAbsence);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ModelError {
    #[error("name must be a bounded namespaced identifier")]
    InvalidName,
    #[error("identity must be nonempty, bounded, and contain no control characters")]
    InvalidIdentity,
    #[error("revision must be nonempty and bounded")]
    InvalidRevision,
    #[error("domain exceeds the supported unit limit")]
    DomainTooLarge,
    #[error("domain contains duplicate units")]
    DuplicateUnit,
    #[error("progress references an unknown unit")]
    UnknownUnit,
    #[error("prefix progress requires an ordered domain")]
    UnorderedPrefix,
    #[error("cardinality requires a closed finite domain")]
    OpenCardinality,
    #[error("progress exceeds the declared domain")]
    ProgressOutOfBounds,
    #[error("incomplete reads cannot establish meaningful absence")]
    IncompleteAbsence,
    #[error("progress domains differ in identity, revision, unit, ordering, or extent")]
    IncompatibleDomain,
}

pub fn require_same_domain(left: &Domain, right: &Domain) -> Result<(), ModelError> {
    if left != right {
        return Err(ModelError::IncompatibleDomain);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(value: &str) -> Name {
        Name::new(value).unwrap()
    }

    fn identity(value: &str) -> Identity {
        Identity::new(name("fixture:unit"), value).unwrap()
    }

    fn domain(unit: &str, ordering: Ordering, closed: bool) -> Domain {
        Domain::new(
            identity("domain"),
            "revision-1",
            name(unit),
            ordering,
            vec![identity("first"), identity("second")],
            closed,
        )
        .unwrap()
    }

    #[test]
    fn classifications_accept_additional_media_without_an_enum() {
        for classification in [
            "media:book",
            "media:music",
            "media:movie",
            "media:show",
            "media:anime",
            "media:manga",
            "media:audiobook",
            "example:interactive-fiction",
        ] {
            let subject = Subject {
                identity: identity(classification),
                classifications: BTreeSet::from([name(classification)]),
                role: name("subject:edition"),
                label: classification.to_owned(),
            };
            let encoded = serde_json::to_value(&subject).unwrap();
            assert_eq!(serde_json::from_value::<Subject>(encoded).unwrap(), subject);
        }
    }

    #[test]
    fn invalid_domain_cannot_bypass_validation_through_deserialization() {
        let valid = domain("unit:chapter", Ordering::Ordered, true);
        let mut encoded = serde_json::to_value(&valid).unwrap();
        encoded["units"][1] = encoded["units"][0].clone();
        assert!(serde_json::from_value::<Domain>(encoded).is_err());
        assert!(Name::new("chapter").is_err());
        assert!(Name::new("unit:chapter\n").is_err());
    }

    #[test]
    fn chapter_volume_and_domain_revisions_are_not_interchangeable() {
        let chapters = domain("unit:chapter", Ordering::Ordered, true);
        let volumes = domain("unit:volume", Ordering::Ordered, true);
        assert_eq!(
            require_same_domain(&chapters, &volumes),
            Err(ModelError::IncompatibleDomain)
        );
        let mut changed = chapters.clone();
        changed.revision = "revision-2".to_owned();
        assert_eq!(
            require_same_domain(&chapters, &changed),
            Err(ModelError::IncompatibleDomain)
        );
    }

    #[test]
    fn unordered_domain_normalizes_declaration_order() {
        let original = domain("unit:track", Ordering::Unordered, true);
        let reordered = Domain::new(
            original.identity.clone(),
            original.revision.clone(),
            original.unit.clone(),
            Ordering::Unordered,
            original.units.iter().rev().cloned().collect(),
            true,
        )
        .unwrap();
        assert_eq!(original, reordered);
    }

    #[test]
    fn progress_rejects_unordered_prefix_unknown_items_and_out_of_bounds_counts() {
        let unordered = domain("unit:track", Ordering::Unordered, true);
        assert_eq!(
            Progress::Prefix { completed: 1 }.validate(&unordered),
            Err(ModelError::UnorderedPrefix)
        );
        assert_eq!(
            Progress::Cardinality { completed: 3 }.validate(&unordered),
            Err(ModelError::ProgressOutOfBounds)
        );
        assert_eq!(
            Progress::Items {
                completed: BTreeSet::from([identity("missing")])
            }
            .validate(&unordered),
            Err(ModelError::UnknownUnit)
        );
        let open = domain("unit:chapter", Ordering::Ordered, false);
        assert_eq!(
            Progress::Cardinality { completed: 1 }.validate(&open),
            Err(ModelError::OpenCardinality)
        );
    }

    #[test]
    fn incomplete_read_cannot_prove_absence() {
        let mut observation = Observation {
            origin: identity("origin"),
            account: identity("account"),
            subject: identity("edition"),
            behavior_revision: "1".to_owned(),
            remote_revision: None,
            acquired_at_milliseconds: 1,
            domain: domain("unit:page", Ordering::Ordered, true),
            quality: ReadQuality::Partial,
            presence: Presence::MeaningfulAbsence,
            native_value: serde_json::Value::Null,
        };
        assert_eq!(observation.validate(), Err(ModelError::IncompleteAbsence));
        observation.presence = Presence::Missing;
        assert!(observation.validate().is_ok());
    }
}
