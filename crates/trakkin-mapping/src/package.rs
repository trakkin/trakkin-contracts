use std::collections::{BTreeMap, BTreeSet};

use semver::{Version, VersionReq};
use serde::Deserialize;

use crate::{MappingDocument, MappingError};

const PACKAGE_SCHEMA: &str = "trakkin.mapping-package/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappingPackage {
    documents: Vec<PackageDocument>,
    roots: Vec<String>,
    parents: BTreeMap<String, Vec<String>>,
    license_expression: String,
    attribution: Vec<PackageAttribution>,
    signatures: Vec<PackageSignature>,
    forge: Option<ForgeProvenance>,
    requirements: PackageRequirements,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageDocument {
    pub path: String,
    pub hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageAttribution {
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageSignature {
    pub kind: String,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgeProvenance {
    pub commit: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageRequirements {
    pub mapping_schema: String,
    pub resolver: String,
    pub coordinate_registry_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageCompatibility {
    mapping_schema: String,
    resolver_version: String,
    coordinate_registry_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPackage {
    document_hashes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPackage {
    schema: String,
    documents: Vec<RawPackageDocument>,
    roots: Vec<String>,
    parents: BTreeMap<String, Vec<String>>,
    #[serde(rename = "licenseExpression")]
    license_expression: String,
    attribution: Vec<RawPackageAttribution>,
    signatures: Vec<RawPackageSignature>,
    forge: Option<RawForgeProvenance>,
    requires: RawPackageRequirements,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPackageDocument {
    path: String,
    hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPackageAttribution {
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPackageSignature {
    kind: String,
    digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawForgeProvenance {
    commit: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawPackageRequirements {
    mapping_schema: String,
    resolver: String,
    coordinate_registry_digest: String,
}

impl MappingPackage {
    pub fn from_json(input: &str) -> Result<Self, MappingError> {
        let raw: RawPackage = serde_json::from_str(input).map_err(|error| {
            MappingError::new(
                "invalid_package",
                format!("invalid package manifest: {error}"),
            )
        })?;
        if raw.schema != PACKAGE_SCHEMA {
            return Err(MappingError::new(
                "unsupported_package_schema",
                "mapping package schema is unsupported",
            ));
        }
        if raw.documents.is_empty() {
            return Err(MappingError::new(
                "package_document_required",
                "mapping package requires at least one document",
            ));
        }

        let mut document_paths = BTreeSet::new();
        let mut document_hashes = BTreeSet::new();
        let mut documents = Vec::with_capacity(raw.documents.len());
        for document in raw.documents {
            validate_path(&document.path)?;
            validate_content_hash(&document.hash)?;
            if !document_paths.insert(document.path.clone()) {
                return Err(MappingError::new(
                    "duplicate_package_path",
                    "mapping package contains a duplicate document path",
                ));
            }
            if !document_hashes.insert(document.hash.clone()) {
                return Err(MappingError::new(
                    "duplicate_package_document",
                    "mapping package contains a duplicate document hash",
                ));
            }
            documents.push(PackageDocument {
                path: document.path,
                hash: document.hash,
            });
        }
        documents.sort_unstable_by(|left, right| left.path.cmp(&right.path));

        let roots = normalize_hashes(raw.roots)?;
        let mut parents = BTreeMap::new();
        for (child, parent_hashes) in raw.parents {
            validate_content_hash(&child)?;
            parents.insert(child, normalize_hashes(parent_hashes)?);
        }
        validate_lineage(&parents)?;

        spdx::Expression::parse(&raw.license_expression).map_err(|error| {
            MappingError::new(
                "invalid_package_license",
                format!("invalid SPDX license expression: {error}"),
            )
        })?;
        if raw
            .attribution
            .iter()
            .any(|entry| entry.name.trim().is_empty())
        {
            return Err(MappingError::new(
                "invalid_package_attribution",
                "mapping package attribution names cannot be blank",
            ));
        }

        let signatures = raw
            .signatures
            .into_iter()
            .map(|signature| {
                if signature.kind.trim().is_empty() {
                    return Err(MappingError::new(
                        "invalid_package_signature",
                        "mapping package signature kind cannot be blank",
                    ));
                }
                validate_content_hash(&signature.digest)?;
                if !document_hashes.contains(&signature.digest) {
                    return Err(MappingError::new(
                        "invalid_package_signature",
                        "mapping package signature digest does not name a packaged document",
                    ));
                }
                Ok(PackageSignature {
                    kind: signature.kind,
                    digest: signature.digest,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let forge = raw
            .forge
            .map(|forge| {
                if forge.commit.is_empty()
                    || !forge
                        .commit
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                {
                    return Err(MappingError::new(
                        "invalid_package_provenance",
                        "mapping package forge commit must be lowercase hexadecimal",
                    ));
                }
                Ok(ForgeProvenance {
                    commit: forge.commit,
                })
            })
            .transpose()?;

        validate_content_hash(&raw.requires.coordinate_registry_digest)?;
        let normalized_resolver = normalize_version_requirement(&raw.requires.resolver)?;

        Ok(Self {
            documents,
            roots,
            parents,
            license_expression: raw.license_expression,
            attribution: raw
                .attribution
                .into_iter()
                .map(|entry| PackageAttribution { name: entry.name })
                .collect(),
            signatures,
            forge,
            requirements: PackageRequirements {
                mapping_schema: raw.requires.mapping_schema,
                resolver: normalized_resolver,
                coordinate_registry_digest: raw.requires.coordinate_registry_digest,
            },
        })
    }

    pub fn verify(
        &self,
        documents: &BTreeMap<String, MappingDocument>,
        compatibility: &PackageCompatibility,
    ) -> Result<VerifiedPackage, MappingError> {
        let mut reasons = Vec::new();
        if self.requirements.mapping_schema != compatibility.mapping_schema {
            reasons.push("mapping_schema".to_owned());
        }
        let resolver_version =
            Version::parse(&compatibility.resolver_version).map_err(|error| {
                MappingError::new(
                    "invalid_package_compatibility",
                    format!("invalid installed resolver version: {error}"),
                )
            })?;
        let resolver_requirement =
            VersionReq::parse(&self.requirements.resolver).map_err(|error| {
                MappingError::new(
                    "invalid_package_compatibility",
                    format!("invalid package resolver requirement: {error}"),
                )
            })?;
        if !resolver_requirement.matches(&resolver_version) {
            reasons.push("resolver".to_owned());
        }
        if self.requirements.coordinate_registry_digest != compatibility.coordinate_registry_digest
        {
            reasons.push("coordinate_registry".to_owned());
        }
        if !reasons.is_empty() {
            return Err(MappingError::with_details(
                "package_incompatible",
                "mapping package requirements are incompatible",
                reasons,
            ));
        }

        if documents.len() != self.documents.len() {
            return Err(MappingError::new(
                "package_document_set_mismatch",
                "mapping package documents do not match the manifest",
            ));
        }
        let mut verified_hashes = Vec::with_capacity(self.documents.len());
        for expected in &self.documents {
            let document = documents.get(&expected.path).ok_or_else(|| {
                MappingError::new(
                    "package_document_missing",
                    "mapping package document is missing",
                )
            })?;
            let actual_hash = document.content_hash();
            if actual_hash != expected.hash {
                return Err(MappingError::new(
                    "package_hash_mismatch",
                    "mapping package document hash does not match the manifest",
                ));
            }
            verified_hashes.push(actual_hash);
        }

        Ok(VerifiedPackage {
            document_hashes: verified_hashes,
        })
    }

    #[must_use]
    pub fn documents(&self) -> &[PackageDocument] {
        &self.documents
    }

    #[must_use]
    pub fn roots(&self) -> &[String] {
        &self.roots
    }

    #[must_use]
    pub fn parents(&self) -> &BTreeMap<String, Vec<String>> {
        &self.parents
    }

    #[must_use]
    pub fn license_expression(&self) -> &str {
        &self.license_expression
    }

    #[must_use]
    pub fn attribution(&self) -> &[PackageAttribution] {
        &self.attribution
    }

    #[must_use]
    pub fn signatures(&self) -> &[PackageSignature] {
        &self.signatures
    }

    #[must_use]
    pub fn forge(&self) -> Option<&ForgeProvenance> {
        self.forge.as_ref()
    }

    #[must_use]
    pub fn requirements(&self) -> &PackageRequirements {
        &self.requirements
    }
}

impl PackageCompatibility {
    #[must_use]
    pub fn new(
        mapping_schema: impl Into<String>,
        resolver_version: impl Into<String>,
        coordinate_registry_digest: impl Into<String>,
    ) -> Self {
        Self {
            mapping_schema: mapping_schema.into(),
            resolver_version: resolver_version.into(),
            coordinate_registry_digest: coordinate_registry_digest.into(),
        }
    }
}

impl VerifiedPackage {
    #[must_use]
    pub fn document_hashes(&self) -> &[String] {
        &self.document_hashes
    }
}

fn validate_path(path: &str) -> Result<(), MappingError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.split('/').any(|segment| {
            segment.is_empty() || segment == "." || segment == ".." || segment.contains('\0')
        })
    {
        return Err(MappingError::new(
            "invalid_package_path",
            "mapping package document path must be a safe relative path",
        ));
    }
    Ok(())
}

pub fn validate_content_hash(hash: &str) -> Result<(), MappingError> {
    let Some(hex) = hash.strip_prefix("sha256:") else {
        return Err(MappingError::new(
            "invalid_content_hash",
            "mapping content hash must use sha256",
        ));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(MappingError::new(
            "invalid_content_hash",
            "mapping content hash must contain 64 lowercase hexadecimal digits",
        ));
    }
    Ok(())
}

fn normalize_hashes(mut hashes: Vec<String>) -> Result<Vec<String>, MappingError> {
    for hash in &hashes {
        validate_content_hash(hash)?;
    }
    hashes.sort_unstable();
    if hashes.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(MappingError::new(
            "duplicate_content_hash",
            "mapping package contains a duplicate content hash",
        ));
    }
    Ok(hashes)
}

fn normalize_version_requirement(requirement: &str) -> Result<String, MappingError> {
    let normalized = requirement
        .replace(',', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(", ");
    VersionReq::parse(&normalized).map_err(|error| {
        MappingError::new(
            "invalid_package_compatibility",
            format!("invalid package resolver requirement: {error}"),
        )
    })?;
    Ok(normalized)
}

fn validate_lineage(parents: &BTreeMap<String, Vec<String>>) -> Result<(), MappingError> {
    fn visit(
        hash: &str,
        parents: &BTreeMap<String, Vec<String>>,
        visiting: &mut BTreeSet<String>,
        visited: &mut BTreeSet<String>,
    ) -> Result<(), MappingError> {
        if visited.contains(hash) {
            return Ok(());
        }
        if !visiting.insert(hash.to_owned()) {
            return Err(MappingError::new(
                "lineage_cycle",
                "mapping package parent graph contains a cycle",
            ));
        }
        if let Some(parent_hashes) = parents.get(hash) {
            for parent in parent_hashes {
                if parent == hash {
                    return Err(MappingError::new(
                        "lineage_cycle",
                        "mapping package revision cannot parent itself",
                    ));
                }
                if parents.contains_key(parent) {
                    visit(parent, parents, visiting, visited)?;
                }
            }
        }
        visiting.remove(hash);
        visited.insert(hash.to_owned());
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for hash in parents.keys() {
        visit(hash, parents, &mut visiting, &mut visited)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "package_tests.rs"]
mod tests;
