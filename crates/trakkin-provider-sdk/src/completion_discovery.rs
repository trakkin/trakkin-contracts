use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::completion::{Identity, Name, Subject};
use crate::completion_operation::{Behavior, OperationError};

pub const MAXIMUM_FIELDS: usize = 32;
pub const MAXIMUM_PAGE_SIZE: u32 = 100;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Field {
    pub field: Name,
    pub group: Name,
    pub unit_kinds: BTreeSet<Name>,
    pub readable: bool,
    pub writable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Library {
    pub account: Identity,
    pub behavior: Behavior,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Descriptor {
    pub subject: Subject,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Page {
    pub library: Library,
    pub subjects: Vec<Descriptor>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DiscoveryError {
    #[error("completion discovery metadata exceeds its collection limit")]
    LimitExceeded,
    #[error("completion discovery metadata contradicts its account or behavior")]
    InvalidMetadata,
    #[error(transparent)]
    InvalidBehavior(#[from] OperationError),
}

impl Library {
    pub fn validate(&self, account: &Identity) -> Result<(), DiscoveryError> {
        if self.account != *account {
            return Err(DiscoveryError::InvalidMetadata);
        }
        self.behavior.validate()?;
        validate_fields(&self.fields, &self.behavior)
    }
}

pub fn validate_request(page_size: u32, cursor: Option<&str>) -> Result<(), DiscoveryError> {
    if !(1..=MAXIMUM_PAGE_SIZE).contains(&page_size)
        || cursor.is_some_and(|cursor| cursor.is_empty() || cursor.len() > 4096)
    {
        return Err(DiscoveryError::InvalidMetadata);
    }
    Ok(())
}

impl Page {
    pub fn validate(
        &self,
        account: &Identity,
        page_size: u32,
        cursor: Option<&str>,
    ) -> Result<(), DiscoveryError> {
        validate_request(page_size, cursor)?;
        if self.subjects.len() > page_size as usize {
            return Err(DiscoveryError::LimitExceeded);
        }
        if self.next_cursor.as_deref().is_some_and(|next| {
            next.is_empty() || next.len() > 4096 || Some(next) == cursor || self.subjects.is_empty()
        }) {
            return Err(DiscoveryError::InvalidMetadata);
        }
        self.library.validate(account)?;
        let mut seen = BTreeSet::new();
        for descriptor in &self.subjects {
            if !seen.insert(&descriptor.subject.identity)
                || descriptor.subject.label.len() > 4096
                || descriptor.subject.label.chars().any(char::is_control)
                || !self
                    .library
                    .behavior
                    .subject_roles
                    .contains(&descriptor.subject.role)
                || descriptor.fields.is_empty()
            {
                return Err(DiscoveryError::InvalidMetadata);
            }
            validate_fields(&descriptor.fields, &self.library.behavior)?;
            for field in &descriptor.fields {
                let declared = self
                    .library
                    .fields
                    .iter()
                    .find(|declared| declared.field == field.field)
                    .ok_or(DiscoveryError::InvalidMetadata)?;
                if field.group != declared.group
                    || field.readable && !declared.readable
                    || field.writable && !declared.writable
                    || !field.unit_kinds.is_subset(&declared.unit_kinds)
                {
                    return Err(DiscoveryError::InvalidMetadata);
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn validate_fields(fields: &[Field], behavior: &Behavior) -> Result<(), DiscoveryError> {
    if fields.len() > MAXIMUM_FIELDS {
        return Err(DiscoveryError::LimitExceeded);
    }
    let mut seen = BTreeSet::new();
    for field in fields {
        if !seen.insert(&field.field)
            || field.unit_kinds.is_empty()
            || !field.unit_kinds.is_subset(&behavior.units)
            || !(field.readable || field.writable)
            || (field.writable
                && !behavior
                    .operations
                    .iter()
                    .any(|operation| operation.effect_fields.contains(&field.field)))
        {
            return Err(DiscoveryError::InvalidMetadata);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::completion_operation::{OperationCapability, ProtectionKind};

    fn name(value: &str) -> Name {
        Name::new(value).unwrap()
    }

    fn library() -> Library {
        Library {
            account: Identity::new(name("test:account"), "reader").unwrap(),
            behavior: Behavior {
                revision: "1".to_owned(),
                subject_roles: BTreeSet::from([name("subject:edition")]),
                units: BTreeSet::from([name("unit:chapter")]),
                operations: Vec::new(),
            },
            fields: vec![Field {
                field: name("state:completion"),
                group: name("group:entry"),
                unit_kinds: BTreeSet::from([name("unit:chapter")]),
                readable: true,
                writable: false,
            }],
        }
    }

    #[test]
    fn library_metadata_is_account_bound_and_independent_of_subject_discovery() {
        let library = library();
        library.validate(&library.account).unwrap();
        let foreign = Identity::new(name("test:account"), "other").unwrap();
        assert_eq!(
            library.validate(&foreign),
            Err(DiscoveryError::InvalidMetadata)
        );
        assert_eq!(
            serde_json::from_value::<Library>(serde_json::to_value(&library).unwrap()).unwrap(),
            library
        );
    }

    #[test]
    fn fields_require_unique_names_declared_units_and_an_access_mode() {
        let valid = library();
        let mut changed = valid.clone();
        changed.fields.push(changed.fields[0].clone());
        assert_eq!(
            changed.validate(&valid.account),
            Err(DiscoveryError::InvalidMetadata)
        );
        for units in [BTreeSet::new(), BTreeSet::from([name("unit:track")])] {
            let mut changed = valid.clone();
            changed.fields[0].unit_kinds = units;
            assert_eq!(
                changed.validate(&valid.account),
                Err(DiscoveryError::InvalidMetadata)
            );
        }
        let mut changed = valid.clone();
        changed.fields[0].readable = false;
        assert_eq!(
            changed.validate(&valid.account),
            Err(DiscoveryError::InvalidMetadata)
        );
    }

    #[test]
    fn typed_pages_preserve_account_pagination_and_capability_boundaries() {
        let library = library();
        let descriptor = Descriptor {
            subject: Subject {
                identity: Identity::new(name("test:subject"), "edition").unwrap(),
                label: "Edition".to_owned(),
                role: name("subject:edition"),
                classifications: BTreeSet::new(),
            },
            fields: library.fields.clone(),
        };
        let valid = Page {
            library,
            subjects: vec![descriptor],
            next_cursor: None,
        };
        valid.validate(&valid.library.account, 1, None).unwrap();
        let mut changed = valid.clone();
        changed.subjects.push(changed.subjects[0].clone());
        assert_eq!(
            changed.validate(&valid.library.account, 2, None),
            Err(DiscoveryError::InvalidMetadata)
        );
        assert_eq!(
            changed.validate(&valid.library.account, 1, None),
            Err(DiscoveryError::LimitExceeded)
        );
        for cursor in ["", "current"] {
            let mut changed = valid.clone();
            changed.next_cursor = Some(cursor.to_owned());
            assert_eq!(
                changed.validate(&valid.library.account, 1, Some("current")),
                Err(DiscoveryError::InvalidMetadata)
            );
        }
        let mut changed = valid.clone();
        changed.subjects[0].fields[0].group = name("group:other");
        assert_eq!(
            changed.validate(&valid.library.account, 1, None),
            Err(DiscoveryError::InvalidMetadata)
        );
        let mut changed = valid.clone();
        changed.subjects[0].subject.role = name("subject:recording");
        assert_eq!(
            changed.validate(&valid.library.account, 1, None),
            Err(DiscoveryError::InvalidMetadata)
        );
        let mut empty = valid.clone();
        empty.subjects.clear();
        empty.validate(&valid.library.account, 1, None).unwrap();
        empty.next_cursor = Some("next".to_owned());
        assert_eq!(
            empty.validate(&valid.library.account, 1, None),
            Err(DiscoveryError::InvalidMetadata)
        );
    }

    #[test]
    fn subject_fields_cannot_expand_library_permissions_or_unit_kinds() {
        let mut library = library();
        library.behavior.units.insert(name("unit:volume"));
        library.behavior.operations.push(OperationCapability {
            class: name("operation:set"),
            effect_fields: BTreeSet::from([library.fields[0].field.clone()]),
            protection: BTreeSet::from([ProtectionKind::BestEffort]),
            deduplication: false,
            reconciliation: BTreeSet::new(),
        });
        let valid = Page {
            subjects: vec![Descriptor {
                subject: Subject {
                    identity: Identity::new(name("test:subject"), "edition").unwrap(),
                    label: "Edition".to_owned(),
                    role: name("subject:edition"),
                    classifications: BTreeSet::new(),
                },
                fields: library.fields.clone(),
            }],
            library,
            next_cursor: None,
        };
        valid.validate(&valid.library.account, 1, None).unwrap();
        let mut changed = valid.clone();
        changed.subjects[0].fields[0].writable = true;
        assert_eq!(
            changed.validate(&valid.library.account, 1, None),
            Err(DiscoveryError::InvalidMetadata)
        );
        let mut changed = valid.clone();
        changed.subjects[0].fields[0]
            .unit_kinds
            .insert(name("unit:volume"));
        assert_eq!(
            changed.validate(&valid.library.account, 1, None),
            Err(DiscoveryError::InvalidMetadata)
        );
        let mut changed = valid;
        changed.library.fields[0].readable = false;
        changed.library.fields[0].writable = true;
        assert_eq!(
            changed.validate(&changed.library.account, 1, None),
            Err(DiscoveryError::InvalidMetadata)
        );
    }

    #[test]
    fn writable_fields_require_a_declared_operation_effect() {
        let mut library = library();
        library.fields[0].writable = true;
        assert_eq!(
            library.validate(&library.account),
            Err(DiscoveryError::InvalidMetadata)
        );
        library.behavior.operations.push(OperationCapability {
            class: name("operation:set"),
            effect_fields: BTreeSet::from([library.fields[0].field.clone()]),
            protection: BTreeSet::from([ProtectionKind::BestEffort]),
            deduplication: false,
            reconciliation: BTreeSet::new(),
        });
        library.validate(&library.account).unwrap();
        library.behavior.operations[0].effect_fields = BTreeSet::from([name("state:status")]);
        assert_eq!(
            library.validate(&library.account),
            Err(DiscoveryError::InvalidMetadata)
        );
    }
}
