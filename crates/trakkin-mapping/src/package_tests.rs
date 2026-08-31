use std::collections::BTreeMap;

use crate::{MappingDocument, MappingPackage, PackageCompatibility};
use serde_json::Value;

const VECTORS: &str = include_str!("../tests/fixtures.mapping/v1/lifecycle/vectors.json");
const REGISTRY_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn production_package_verifies_documents_and_provenance() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("lifecycle vectors should parse");
    let vector = vector_by_id(&vectors, "PACKAGE-MANIFEST-VALID-001");
    let action = vector.get("action").expect("package action");
    let manifest = expanded_manifest(&vectors, vector);
    let package = MappingPackage::from_json(&manifest.to_string())
        .expect("valid package manifest should parse");

    let mut documents = BTreeMap::new();
    for fixture in action
        .get("documentFixtures")
        .and_then(Value::as_array)
        .expect("package document fixtures")
    {
        let path = fixture
            .get("path")
            .and_then(Value::as_str)
            .expect("document path");
        let document = MappingDocument::from_json(
            &fixture
                .get("portableBody")
                .expect("portable body")
                .to_string(),
        )
        .expect("package document should parse");
        assert_eq!(
            fixture.get("expectedHash").and_then(Value::as_str),
            Some(document.content_hash().as_str())
        );
        documents.insert(path.to_owned(), document);
    }

    let canonical_before = documents
        .values()
        .map(MappingDocument::canonical_json)
        .collect::<Vec<_>>();
    let verified = package
        .verify(
            &documents,
            &PackageCompatibility::new("trakkin.mapping/v1", "1.0.0", REGISTRY_DIGEST),
        )
        .expect("compatible package should verify");
    assert_eq!(
        verified.document_hashes(),
        &["sha256:3c292a44994f0bd715e8629e672db7e90d830a0c348bde69154e626cea4edfac"]
    );
    assert_eq!(package.license_expression(), "MIT");
    assert_eq!(package.attribution()[0].name, "Example Mapping Authors");
    assert_eq!(package.signatures()[0].kind, "sigstore");
    assert_eq!(
        package.forge().expect("forge provenance").commit,
        "0123456789abcdef"
    );
    assert_eq!(
        documents
            .values()
            .map(MappingDocument::canonical_json)
            .collect::<Vec<_>>(),
        canonical_before
    );
}

#[test]
fn production_package_reports_every_compatibility_reason() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("lifecycle vectors should parse");
    let valid = vector_by_id(&vectors, "PACKAGE-MANIFEST-VALID-001");
    let incompatible = vector_by_id(&vectors, "PACKAGE-COMPATIBILITY-REJECT-001");
    let mut manifest = expanded_manifest(&vectors, valid);
    manifest["requires"] = incompatible
        .get("action")
        .and_then(|action| action.get("requires"))
        .expect("incompatible requirements")
        .clone();
    let package = MappingPackage::from_json(&manifest.to_string())
        .expect("incompatible manifest should remain structurally valid");

    let error = package
        .verify(
            &BTreeMap::new(),
            &PackageCompatibility::new("trakkin.mapping/v1", "1.0.0", REGISTRY_DIGEST),
        )
        .expect_err("incompatible package should fail before document verification");
    assert_eq!(error.code(), "package_incompatible");
    assert_eq!(
        error.details(),
        &["mapping_schema", "resolver", "coordinate_registry"]
    );
}

#[test]
fn production_package_rejects_hash_and_path_mismatches() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("lifecycle vectors should parse");
    let valid = vector_by_id(&vectors, "PACKAGE-MANIFEST-VALID-001");
    let package = MappingPackage::from_json(&expanded_manifest(&vectors, valid).to_string())
        .expect("valid package manifest should parse");
    let document = MappingDocument::from_json(
        r#"{"schema":"trakkin.mapping/v1","revision":1,"mappings":[["example.media:a","example.media:b"]]}"#,
    )
    .expect("different document should parse");
    let documents = BTreeMap::from([("mappings/signal.json".to_owned(), document)]);
    assert_eq!(
        package
            .verify(
                &documents,
                &PackageCompatibility::new("trakkin.mapping/v1", "1.0.0", REGISTRY_DIGEST),
            )
            .expect_err("mismatched document should fail")
            .code(),
        "package_hash_mismatch"
    );

    let mut manifest = expanded_manifest(&vectors, valid);
    manifest["documents"][0]["path"] = Value::String("../signal.json".to_owned());
    assert_eq!(
        MappingPackage::from_json(&manifest.to_string())
            .expect_err("unsafe package path should fail")
            .code(),
        "invalid_package_path"
    );
}

fn vector_by_id<'a>(vectors: &'a Value, id: &str) -> &'a Value {
    vectors
        .get("vectors")
        .and_then(Value::as_array)
        .and_then(|vectors| {
            vectors
                .iter()
                .find(|vector| vector.get("id").and_then(Value::as_str) == Some(id))
        })
        .unwrap_or_else(|| panic!("missing vector: {id}"))
}

fn expanded_manifest(vectors: &Value, vector: &Value) -> Value {
    let mut manifest = vector
        .get("action")
        .and_then(|action| action.get("manifest"))
        .expect("package manifest")
        .clone();
    let hashes = vectors
        .get("hashes")
        .and_then(Value::as_object)
        .expect("fixture hashes");
    expand_hash_placeholders(&mut manifest, hashes);
    manifest
}

fn expand_hash_placeholders(value: &mut Value, hashes: &serde_json::Map<String, Value>) {
    match value {
        Value::Array(values) => {
            for value in values {
                expand_hash_placeholders(value, hashes);
            }
        }
        Value::Object(fields) => {
            for value in fields.values_mut() {
                expand_hash_placeholders(value, hashes);
            }
        }
        Value::String(text) => {
            if let Some(name) = text.strip_prefix('$')
                && let Some(hash) = hashes.get(name).and_then(Value::as_str)
            {
                *text = hash.to_owned();
            }
        }
        _ => {}
    }
}
