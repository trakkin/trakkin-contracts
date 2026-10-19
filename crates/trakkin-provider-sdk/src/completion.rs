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

    pub fn validate_units(&self, units: &BTreeSet<Identity>) -> Result<(), ModelError> {
        let known: BTreeSet<_> = self.units.iter().collect();
        if !units.iter().all(|unit| known.contains(unit)) {
            return Err(ModelError::UnknownUnit);
        }
        Ok(())
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
                domain.validate_units(completed)?;
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
pub struct UnitReference {
    pub unit: Identity,
    pub reference: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "DomainReferencesData")]
pub struct DomainReferences {
    subject: Identity,
    domain: Domain,
    units: Vec<UnitReference>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DomainReferencesData {
    subject: Identity,
    domain: Domain,
    units: Vec<UnitReference>,
}

impl DomainReferences {
    pub fn new(
        subject: Identity,
        domain: Domain,
        mut units: Vec<UnitReference>,
    ) -> Result<Self, ModelError> {
        if units.len() != domain.units().len() {
            return Err(ModelError::InvalidReferenceBinding);
        }
        let mut bytes = 0_usize;
        let mut identities = BTreeSet::new();
        let mut references = BTreeSet::new();
        for binding in &units {
            bytes = bytes
                .checked_add(
                    binding.reference.len()
                        + binding.unit.namespace().as_str().len()
                        + binding.unit.value().len(),
                )
                .filter(|size| *size <= 4 * 1024 * 1024)
                .ok_or(ModelError::InvalidReferenceBinding)?;
            if binding.reference.is_empty()
                || binding.reference.len() > 4096
                || binding.reference.chars().any(char::is_control)
                || !identities.insert(&binding.unit)
                || !references.insert(&binding.reference)
            {
                return Err(ModelError::InvalidReferenceBinding);
            }
        }
        if identities != domain.units().iter().collect() {
            return Err(ModelError::InvalidReferenceBinding);
        }
        units.sort_by(|left, right| left.unit.cmp(&right.unit));
        Ok(Self {
            subject,
            domain,
            units,
        })
    }

    pub fn subject(&self) -> &Identity {
        &self.subject
    }
    pub fn domain(&self) -> &Domain {
        &self.domain
    }
    pub fn units(&self) -> &[UnitReference] {
        &self.units
    }

    pub fn into_parts(self) -> (Identity, Domain, Vec<UnitReference>) {
        (self.subject, self.domain, self.units)
    }
}

impl TryFrom<DomainReferencesData> for DomainReferences {
    type Error = ModelError;

    fn try_from(value: DomainReferencesData) -> Result<Self, Self::Error> {
        Self::new(value.subject, value.domain, value.units)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub origin: Identity,
    pub account: Identity,
    pub subject: Identity,
    pub field: Name,
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
    #[error(
        "native references must bind every domain unit exactly once with bounded distinct references"
    )]
    InvalidReferenceBinding,
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

pub fn bounded_json_size(value: &impl Serialize, limit: usize) -> Result<usize, serde_json::Error> {
    struct JsonSize {
        bytes: usize,
        limit: usize,
    }

    impl std::io::Write for JsonSize {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .filter(|size| *size <= self.limit)
                .ok_or_else(|| {
                    std::io::Error::other("serialized completion data exceeds limits")
                })?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut size = JsonSize { bytes: 0, limit };
    serde_json::to_writer(&mut size, value)?;
    Ok(size.bytes)
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
    fn reference_bindings_bound_aggregate_identity_bytes() {
        let units: Vec<_> = (0..1025)
            .map(|index| identity(&format!("unit-{index}")))
            .collect();
        let domain = Domain::new(
            identity("domain"),
            "revision",
            name("media:page"),
            Ordering::Ordered,
            units.clone(),
            true,
        )
        .unwrap();
        let references = units
            .into_iter()
            .enumerate()
            .map(|(index, unit)| UnitReference {
                unit,
                reference: format!("{index:04}{}", "x".repeat(4092)),
            })
            .collect();
        assert_eq!(
            DomainReferences::new(identity("subject"), domain, references),
            Err(ModelError::InvalidReferenceBinding)
        );
    }

    #[test]
    fn reference_bindings_require_exact_unique_units_and_bounded_references() {
        let domain = domain("media:page", Ordering::Ordered, true);
        let first = UnitReference {
            unit: identity("first"),
            reference: "book://first".to_owned(),
        };
        let second = UnitReference {
            unit: identity("second"),
            reference: "book://second".to_owned(),
        };
        let valid = DomainReferences::new(
            identity("subject"),
            domain.clone(),
            vec![second.clone(), first.clone()],
        )
        .unwrap();
        assert_eq!(valid.units()[0], first);
        for units in [
            vec![first.clone()],
            vec![first.clone(), first.clone()],
            vec![
                first.clone(),
                UnitReference {
                    unit: identity("foreign"),
                    ..second.clone()
                },
            ],
            vec![
                first.clone(),
                UnitReference {
                    reference: first.reference.clone(),
                    ..second.clone()
                },
            ],
            vec![
                first.clone(),
                UnitReference {
                    reference: String::new(),
                    ..second.clone()
                },
            ],
            vec![
                first.clone(),
                UnitReference {
                    reference: "x".repeat(4097),
                    ..second.clone()
                },
            ],
            vec![
                first.clone(),
                UnitReference {
                    reference: "book://second\n".to_owned(),
                    ..second
                },
            ],
        ] {
            assert_eq!(
                DomainReferences::new(identity("subject"), domain.clone(), units),
                Err(ModelError::InvalidReferenceBinding)
            );
        }
        let mut json = serde_json::to_value(&valid).unwrap();
        json["units"][1]["reference"] = serde_json::json!("book://first");
        assert!(serde_json::from_value::<DomainReferences>(json).is_err());
        assert_eq!(
            serde_json::from_value::<DomainReferences>(serde_json::to_value(&valid).unwrap())
                .unwrap(),
            valid
        );
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
    fn borrowed_unit_selections_validate_without_assuming_domain_order() {
        let declared = vec![identity("z"), identity("a"), identity("m")];
        for ordering in [Ordering::Ordered, Ordering::Unordered] {
            let domain = Domain::new(
                identity("chapters"),
                "1",
                Name::new("unit:chapter").unwrap(),
                ordering,
                declared.clone(),
                false,
            )
            .unwrap();
            domain.validate_units(&BTreeSet::new()).unwrap();
            domain
                .validate_units(&BTreeSet::from([identity("a"), identity("z")]))
                .unwrap();
            assert_eq!(
                domain.validate_units(&BTreeSet::from([identity("a"), identity("missing")])),
                Err(ModelError::UnknownUnit)
            );
            if ordering == Ordering::Ordered {
                assert_eq!(domain.units(), declared.as_slice());
            }
        }
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
            field: Name::new("state:completion").unwrap(),
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
