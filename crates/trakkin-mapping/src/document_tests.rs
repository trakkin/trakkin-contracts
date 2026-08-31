use crate::MappingDocument;
use serde_json::Value;

const JSON: &str = include_str!("../tests/fixtures.mapping/v1/canonical/equivalent.json");
const YAML: &str = include_str!("../tests/fixtures.mapping/v1/canonical/equivalent.yaml");
const EXPECTED_HASH: &str =
    "sha256:3c292a44994f0bd715e8629e672db7e90d830a0c348bde69154e626cea4edfac";
const VECTORS: &str = include_str!("../tests/fixtures.mapping/v1/canonical/vectors.json");

#[test]
fn production_json_and_yaml_have_equal_canonical_output() {
    let json = MappingDocument::from_json(JSON).expect("JSON fixture should parse");
    let yaml = MappingDocument::from_yaml(YAML).expect("YAML fixture should parse");

    assert_eq!(json, yaml);
    assert_eq!(json.content_hash(), EXPECTED_HASH);
    assert_eq!(json.canonical_json(), yaml.canonical_json());
    assert_eq!(json.canonical_yaml(), format!("{}\n", YAML.trim_end()));
}

#[test]
fn production_document_parser_matches_model_and_syntax_errors() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("format vectors should parse");
    let invalid = vectors
        .get("invalid")
        .and_then(Value::as_array)
        .expect("invalid vectors");

    for id in [
        "FMT-I-JSON-UNKNOWN-FIELD-001",
        "FMT-I-SCHEMA-MISSING-001",
        "FMT-I-SCHEMA-UNKNOWN-001",
        "FMT-I-REVISION-ZERO-001",
        "FMT-I-REVISION-FRACTION-001",
        "FMT-I-REVISION-MAX-001",
        "FMT-I-MAPPINGS-EMPTY-001",
        "FMT-I-ROW-SINGLETON-001",
        "FMT-I-ROW-TOO-WIDE-001",
        "FMT-I-ROW-DUPLICATE-ENDPOINT-001",
        "FMT-I-BODY-DUPLICATE-ROW-001",
    ] {
        let vector = vector_by_id(invalid, id);
        let input = serde_json::to_string(vector.get("input").expect("JSON input"))
            .expect("JSON vector serialization");
        let error = MappingDocument::from_json(&input).expect_err("document should fail");
        assert_eq!(error.code(), expected_error(vector), "{id}");
    }

    let duplicate = vector_by_id(invalid, "FMT-I-JSON-DUPLICATE-KEY-001");
    let error = MappingDocument::from_json(
        duplicate
            .get("input")
            .and_then(Value::as_str)
            .expect("duplicate JSON input"),
    )
    .expect_err("duplicate JSON member should fail");
    assert_eq!(error.code(), expected_error(duplicate));

    for id in [
        "FMT-I-YAML-DUPLICATE-KEY-001",
        "FMT-I-YAML-ALIAS-001",
        "FMT-I-YAML-TAG-001",
        "FMT-I-YAML-MERGE-001",
        "FMT-I-YAML-NONSTRING-ENDPOINT-001",
    ] {
        let vector = vector_by_id(invalid, id);
        let error = MappingDocument::from_yaml(
            vector
                .get("input")
                .and_then(Value::as_str)
                .expect("YAML input"),
        )
        .expect_err("YAML document should fail");
        assert_eq!(error.code(), expected_error(vector), "{id}");
    }
}

#[test]
fn production_document_normalizes_rows_and_separates_hashes() {
    let first = MappingDocument::from_json(
        r#"{"schema":"trakkin.mapping/v1","revision":1,"mappings":[["z.example:item","a.example:item"],["b.example:item","a.example:item"]]}"#,
    )
    .expect("revision one should parse");
    let second = MappingDocument::from_json(
        r#"{"schema":"trakkin.mapping/v1","revision":2,"mappings":[["a.example:item","b.example:item"],["a.example:item","z.example:item"]]}"#,
    )
    .expect("revision two should parse");

    assert_eq!(first.mappings()[0][0].as_str(), "a.example:item");
    assert_eq!(first.mappings()[0][1].as_str(), "b.example:item");
    assert_ne!(first.content_hash(), second.content_hash());
    assert_eq!(first.semantic_fingerprint(), second.semantic_fingerprint());
}

#[test]
fn production_document_parser_enforces_generated_boundaries() {
    let accepted = document_json_with_canonical_size(5 * 1_024 * 1_024);
    let document = MappingDocument::from_json(&accepted).expect("5 MiB document should parse");
    assert_eq!(document.canonical_json().len(), 5 * 1_024 * 1_024);

    let rejected = document_json_with_canonical_size(5 * 1_024 * 1_024 + 1);
    assert_eq!(
        MappingDocument::from_json(&rejected)
            .expect_err("document above 5 MiB should fail")
            .code(),
        "document_too_large"
    );

    let mappings = vec![vec!["rows.example:a", "rows.example:b"]; 10_001];
    let input = serde_json::json!({
        "schema": "trakkin.mapping/v1",
        "revision": 1,
        "mappings": mappings,
    });
    assert_eq!(
        MappingDocument::from_json(&input.to_string())
            .expect_err("10001 rows should fail")
            .code(),
        "mapping_row_limit"
    );

    let endpoints = (0..32)
        .map(|index| format!("rows.example:item/{index}"))
        .collect::<Vec<_>>();
    let input = serde_json::json!({
        "schema": "trakkin.mapping/v1",
        "revision": 9_007_199_254_740_991_u64,
        "mappings": [endpoints],
    });
    MappingDocument::from_json(&input.to_string())
        .expect("maximum revision and row width should parse");
}

fn vector_by_id<'a>(vectors: &'a [Value], id: &str) -> &'a Value {
    vectors
        .iter()
        .find(|vector| vector.get("id").and_then(Value::as_str) == Some(id))
        .unwrap_or_else(|| panic!("missing vector: {id}"))
}

fn expected_error(vector: &Value) -> &str {
    vector
        .get("error")
        .and_then(Value::as_str)
        .expect("expected error code")
}

fn document_json_with_canonical_size(target: usize) -> String {
    let mappings = (0..10_000)
        .map(|index| {
            vec![
                format!("size.example:a/{index:05}/"),
                format!("size.example:b/{index:05}"),
            ]
        })
        .collect::<Vec<_>>();
    let mut value = serde_json::json!({
        "schema": "trakkin.mapping/v1",
        "revision": 1,
        "mappings": mappings,
    });
    let current = serde_json::to_vec(&value)
        .expect("generated boundary document should serialize")
        .len();
    let mut remaining = target
        .checked_sub(current)
        .expect("target should fit generated document structure");
    for row in value
        .get_mut("mappings")
        .and_then(Value::as_array_mut)
        .expect("generated mappings")
    {
        let endpoint = row
            .get_mut(0)
            .expect("generated row endpoint")
            .as_str()
            .expect("generated endpoint text")
            .to_owned();
        let value_length = endpoint
            .split_once(':')
            .expect("generated endpoint reference")
            .1
            .len();
        let added = remaining.min(1_024 - value_length);
        *row.get_mut(0).expect("generated row endpoint") =
            Value::String(format!("{endpoint}{}", "x".repeat(added)));
        remaining -= added;
        if remaining == 0 {
            break;
        }
    }
    assert_eq!(remaining, 0, "target size should fit endpoint value bounds");

    let input =
        serde_json::to_string(&value).expect("generated boundary document should serialize");
    assert_eq!(input.len(), target);
    input
}
