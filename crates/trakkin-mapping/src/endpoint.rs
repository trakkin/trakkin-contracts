use std::{fmt, str::FromStr};

use crate::{MappingError, PortableSelector};

const MAX_ENDPOINT_BYTES: usize = 4_096;
const MAX_NAMESPACE_BYTES: usize = 253;
const MAX_NAMESPACE_LABEL_BYTES: usize = 63;
const MAX_VALUE_BYTES: usize = 1_024;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PortableEndpoint {
    normalized: String,
    namespace: String,
    value: Vec<u8>,
    selector: Option<PortableSelector>,
}

impl PortableEndpoint {
    pub fn from_parts(
        namespace: &str,
        value: &[u8],
        selector: Option<&str>,
    ) -> Result<Self, MappingError> {
        let encoded_value = encode_value(value);
        let endpoint = match selector {
            Some(selector) => format!("{namespace}://{encoded_value}[{selector}]"),
            None => format!("{namespace}://{encoded_value}"),
        };
        Self::parse(&endpoint)
    }

    pub fn parse(input: &str) -> Result<Self, MappingError> {
        if !input.is_ascii() {
            return Err(MappingError::new(
                "endpoint_ascii",
                "portable endpoints must contain only ASCII text",
            ));
        }
        if input.len() > MAX_ENDPOINT_BYTES {
            return Err(MappingError::new(
                "endpoint_too_long",
                "portable endpoint text exceeds 4096 bytes",
            ));
        }
        if input.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(MappingError::new(
                "endpoint_whitespace",
                "portable endpoints cannot contain whitespace",
            ));
        }

        let (reference, raw_selector) = split_selector(input)?;
        let (namespace, encoded_value) = reference.split_once("://").ok_or_else(|| {
            MappingError::new(
                "reference_invalid",
                "portable references require a namespace and :// value delimiter",
            )
        })?;
        validate_namespace(namespace)?;
        let value = decode_value(encoded_value)?;
        let normalized_value = encode_value(&value);
        let selector = raw_selector.map(PortableSelector::parse).transpose()?;
        let normalized = match &selector {
            Some(selector) => {
                format!("{namespace}://{normalized_value}[{}]", selector.as_str())
            }
            None => format!("{namespace}://{normalized_value}"),
        };

        Ok(Self {
            normalized,
            namespace: namespace.to_owned(),
            value,
            selector,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    #[must_use]
    pub fn selector(&self) -> Option<&PortableSelector> {
        self.selector.as_ref()
    }
}

impl fmt::Display for PortableEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.normalized)
    }
}

impl FromStr for PortableEndpoint {
    type Err = MappingError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

fn split_selector(input: &str) -> Result<(&str, Option<&str>), MappingError> {
    match input.find('[') {
        Some(start) => {
            if !input.ends_with(']') || input[start + 1..input.len() - 1].contains(['[', ']']) {
                return Err(MappingError::new(
                    "reference_delimiter",
                    "portable endpoint selectors require one trailing bracket pair",
                ));
            }
            let selector = &input[start + 1..input.len() - 1];
            if selector.is_empty() {
                return Err(MappingError::new(
                    "selector_invalid",
                    "portable endpoint selectors cannot be empty",
                ));
            }
            Ok((&input[..start], Some(selector)))
        }
        None if input.contains(']') => Err(MappingError::new(
            "reference_delimiter",
            "portable endpoint contains an unmatched selector delimiter",
        )),
        None => Ok((input, None)),
    }
}

fn validate_namespace(namespace: &str) -> Result<(), MappingError> {
    if namespace.len() > MAX_NAMESPACE_BYTES
        || namespace
            .split('.')
            .any(|label| label.len() > MAX_NAMESPACE_LABEL_BYTES)
    {
        return Err(MappingError::new(
            "namespace_too_long",
            "portable reference namespace or label exceeds its byte limit",
        ));
    }
    if namespace.is_empty()
        || namespace.split('.').any(|label| {
            label.is_empty()
                || !label.starts_with(|character: char| character.is_ascii_lowercase())
                || !label.ends_with(|character: char| {
                    character.is_ascii_lowercase() || character.is_ascii_digit()
                })
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return Err(MappingError::new(
            "namespace_invalid",
            "portable reference namespace is invalid",
        ));
    }
    Ok(())
}

fn decode_value(input: &str) -> Result<Vec<u8>, MappingError> {
    if input.is_empty() {
        return Err(MappingError::new(
            "reference_value_empty",
            "portable reference value cannot be empty",
        ));
    }

    let bytes = input.as_bytes();
    let mut value = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(MappingError::new(
                    "percent_encoding",
                    "portable reference percent escape is incomplete",
                ));
            }
            let high = decode_hex(bytes[index + 1])?;
            let low = decode_hex(bytes[index + 2])?;
            value.push((high << 4) | low);
            index += 3;
            continue;
        }
        if !is_unreserved(bytes[index]) {
            return Err(MappingError::new(
                "reference_value_invalid",
                "portable reference value contains an unescaped byte",
            ));
        }
        value.push(bytes[index]);
        index += 1;
    }
    if value.len() > MAX_VALUE_BYTES {
        return Err(MappingError::new(
            "reference_value_too_long",
            "decoded portable reference value exceeds 1024 bytes",
        ));
    }
    Ok(value)
}

fn encode_value(value: &[u8]) -> String {
    let mut encoded = String::new();
    for byte in value {
        if is_unreserved(*byte) {
            encoded.push(char::from(*byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn decode_hex(byte: u8) -> Result<u8, MappingError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(MappingError::new(
            "percent_encoding",
            "portable reference percent escape contains a non-hexadecimal digit",
        )),
    }
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/')
}

#[cfg(test)]
#[path = "endpoint_tests.rs"]
mod tests;
