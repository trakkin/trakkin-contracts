use crate::{v1::MAXIMUM_MAPPING_UNIT_KEY_BYTES, validation::ValidationError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingUnitKey<'a> {
    value: &'a str,
    namespace: &'a str,
    opaque: &'a str,
}

impl<'a> MappingUnitKey<'a> {
    pub fn parse(value: &'a str) -> Result<Self, ValidationError> {
        if value.trim().is_empty() {
            return Err(ValidationError::Empty("mapping unit key"));
        }
        let invalid = || ValidationError::Invalid("mapping unit key");
        if value.len() > MAXIMUM_MAPPING_UNIT_KEY_BYTES {
            return Err(invalid());
        }
        let (namespace, opaque) = value.split_once("://").ok_or_else(invalid)?;
        let mut bytes = namespace.bytes();
        if !bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || opaque.is_empty()
            || opaque.chars().any(|character| {
                character.is_control()
                    || character.is_whitespace()
                    || matches!(character, ',' | '<' | '>' | '[' | ']')
            })
        {
            return Err(invalid());
        }
        Ok(Self {
            value,
            namespace,
            opaque,
        })
    }

    pub fn as_str(self) -> &'a str {
        self.value
    }

    pub fn namespace(self) -> &'a str {
        self.namespace
    }

    pub fn opaque(self) -> &'a str {
        self.opaque
    }
}
