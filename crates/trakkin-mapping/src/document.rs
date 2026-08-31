use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{MappingError, PortableEndpoint};

const MAPPING_SCHEMA: &str = "trakkin.mapping/v1";
const MAX_REVISION: u64 = 9_007_199_254_740_991;
const MAX_MAPPING_ROWS: usize = 10_000;
const MAX_ROW_ENDPOINTS: usize = 32;
const MAX_CANONICAL_BYTES: usize = 5 * 1_024 * 1_024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappingDocument {
    revision: u64,
    mappings: Vec<Vec<PortableEndpoint>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDocument {
    schema: String,
    revision: u64,
    mappings: Vec<Vec<String>>,
}

impl MappingDocument {
    pub fn from_mappings(revision: u64, mappings: Vec<Vec<String>>) -> Result<Self, MappingError> {
        Self::from_raw(RawDocument {
            schema: MAPPING_SCHEMA.to_owned(),
            revision,
            mappings,
        })
    }

    pub fn from_json(input: &str) -> Result<Self, MappingError> {
        let raw = serde_json::from_str(input)
            .map_err(|error| decode_error(error.to_string(), "duplicate_member"))?;
        Self::from_raw(raw)
    }

    pub fn from_yaml(input: &str) -> Result<Self, MappingError> {
        reject_yaml_syntax(input)?;
        reject_yaml_endpoint_types(input)?;
        let raw = serde_yaml::from_str(input)
            .map_err(|error| decode_error(error.to_string(), "duplicate_key"))?;
        Self::from_raw(raw)
    }

    #[must_use]
    pub fn schema(&self) -> &'static str {
        MAPPING_SCHEMA
    }

    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn mappings(&self) -> &[Vec<PortableEndpoint>] {
        &self.mappings
    }

    #[must_use]
    pub fn canonical_json(&self) -> Vec<u8> {
        serde_json::to_vec(&self.canonical_value(true)).expect("typed mapping document serializes")
    }

    #[must_use]
    pub fn canonical_yaml(&self) -> String {
        let mut output = format!(
            "schema: {MAPPING_SCHEMA}\nrevision: {}\nmappings:\n",
            self.revision
        );
        for row in &self.mappings {
            let endpoints = row
                .iter()
                .map(|endpoint| {
                    serde_json::to_string(endpoint.as_str()).expect("endpoint string serializes")
                })
                .collect::<Vec<_>>()
                .join(", ");
            output.push_str("  - [");
            output.push_str(&endpoints);
            output.push_str("]\n");
        }
        output
    }

    #[must_use]
    pub fn content_hash(&self) -> String {
        hash(&self.canonical_json())
    }

    #[must_use]
    pub fn semantic_fingerprint(&self) -> String {
        let bytes = serde_json::to_vec(&self.canonical_value(false))
            .expect("typed mapping semantics serialize");
        hash(&bytes)
    }

    fn from_raw(raw: RawDocument) -> Result<Self, MappingError> {
        if raw.schema != MAPPING_SCHEMA {
            return Err(MappingError::new(
                "unsupported_schema",
                "mapping document schema is unsupported",
            ));
        }
        if raw.revision == 0 || raw.revision > MAX_REVISION {
            return Err(MappingError::new(
                "revision_out_of_range",
                "mapping document revision is outside the supported range",
            ));
        }
        if raw.mappings.is_empty() {
            return Err(MappingError::new(
                "mapping_required",
                "mapping document requires at least one mapping row",
            ));
        }
        if raw.mappings.len() > MAX_MAPPING_ROWS {
            return Err(MappingError::new(
                "mapping_row_limit",
                "mapping document exceeds 10000 mapping rows",
            ));
        }
        let mut mappings = Vec::with_capacity(raw.mappings.len());
        for raw_row in raw.mappings {
            if !(2..=MAX_ROW_ENDPOINTS).contains(&raw_row.len()) {
                return Err(MappingError::new(
                    "row_endpoint_count",
                    "mapping rows require between 2 and 32 endpoints",
                ));
            }
            let mut row = raw_row
                .iter()
                .map(|endpoint| PortableEndpoint::parse(endpoint))
                .collect::<Result<Vec<_>, _>>()?;
            row.sort_unstable();
            if row.windows(2).any(|endpoints| endpoints[0] == endpoints[1]) {
                return Err(MappingError::new(
                    "duplicate_endpoint",
                    "mapping row contains a duplicate endpoint",
                ));
            }
            mappings.push(row);
        }
        mappings.sort_unstable();
        if mappings.windows(2).any(|rows| rows[0] == rows[1]) {
            return Err(MappingError::new(
                "duplicate_mapping",
                "mapping document contains a duplicate row",
            ));
        }
        let document = Self {
            revision: raw.revision,
            mappings,
        };
        if document.canonical_json().len() > MAX_CANONICAL_BYTES {
            return Err(MappingError::new(
                "document_too_large",
                "canonical mapping document exceeds 5 MiB",
            ));
        }
        Ok(document)
    }

    fn canonical_value(&self, include_revision: bool) -> Value {
        let mappings = self
            .mappings
            .iter()
            .map(|row| {
                Value::Array(
                    row.iter()
                        .map(|endpoint| Value::String(endpoint.to_string()))
                        .collect(),
                )
            })
            .collect();
        let mut fields = BTreeMap::new();
        fields.insert("mappings", Value::Array(mappings));
        if include_revision {
            fields.insert("revision", Value::from(self.revision));
        }
        fields.insert("schema", Value::String(MAPPING_SCHEMA.to_owned()));
        Value::Object(
            fields
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }
}

fn decode_error(message: String, duplicate_code: &'static str) -> MappingError {
    let code = if message.contains("duplicate field") || message.contains("duplicate entry") {
        duplicate_code
    } else if message.contains("unknown field") {
        "unknown_field"
    } else if message.contains("missing field") {
        "missing_field"
    } else if message.contains("revision") || message.contains("u64") {
        "revision_type"
    } else if message.contains("mappings") || message.contains("string") {
        "endpoint_type"
    } else {
        "invalid_document"
    };
    MappingError::new(code, message)
}

fn reject_yaml_syntax(input: &str) -> Result<(), MappingError> {
    for line in input.lines() {
        if line.trim_start().starts_with("<<:") {
            return Err(MappingError::new(
                "yaml_merge",
                "YAML merge keys are not supported in mapping documents",
            ));
        }

        let mut double_quoted = false;
        let mut single_quoted = false;
        let mut escaped = false;
        for character in line.chars() {
            if escaped {
                escaped = false;
                continue;
            }
            if double_quoted && character == '\\' {
                escaped = true;
                continue;
            }
            if !single_quoted && character == '"' {
                double_quoted = !double_quoted;
                continue;
            }
            if !double_quoted && character == '\'' {
                single_quoted = !single_quoted;
                continue;
            }
            if double_quoted || single_quoted {
                continue;
            }
            match character {
                '&' | '*' => {
                    return Err(MappingError::new(
                        "yaml_alias",
                        "YAML aliases are not supported in mapping documents",
                    ));
                }
                '!' => {
                    return Err(MappingError::new(
                        "yaml_tag",
                        "YAML tags are not supported in mapping documents",
                    ));
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn reject_yaml_endpoint_types(input: &str) -> Result<(), MappingError> {
    let value: serde_yaml::Value = serde_yaml::from_str(input)
        .map_err(|error| decode_error(error.to_string(), "duplicate_key"))?;
    let Some(mappings) = value
        .as_mapping()
        .and_then(|document| document.get("mappings"))
        .and_then(serde_yaml::Value::as_sequence)
    else {
        return Ok(());
    };
    for row in mappings {
        let Some(endpoints) = row.as_sequence() else {
            continue;
        };
        if endpoints
            .iter()
            .any(|endpoint| !matches!(endpoint, serde_yaml::Value::String(_)))
        {
            return Err(MappingError::new(
                "endpoint_type",
                "mapping endpoints must be YAML strings",
            ));
        }
    }
    Ok(())
}

fn hash(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{digest:x}")
}

#[cfg(test)]
#[path = "document_tests.rs"]
mod tests;
