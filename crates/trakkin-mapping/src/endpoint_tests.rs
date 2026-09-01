use serde_json::Value;

use crate::PortableEndpoint;

const VECTORS: &str = include_str!("../tests/fixtures.mapping/v1/canonical/vectors.json");

#[test]
fn production_endpoint_parser_matches_explicit_vectors() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("format vectors should parse");
    for vector in vectors
        .get("valid")
        .and_then(Value::as_array)
        .expect("valid vectors")
    {
        let Some(input) = vector.get("input").and_then(Value::as_str) else {
            continue;
        };
        let endpoint = PortableEndpoint::parse(input)
            .unwrap_or_else(|error| panic!("{} failed: {error}", vector_id(vector)));
        assert_eq!(
            endpoint.as_str(),
            vector
                .get("normalized")
                .and_then(Value::as_str)
                .expect("endpoint vector should have normalized text"),
            "{}",
            vector_id(vector)
        );
        if vector.get("resolution").and_then(Value::as_str) == Some("unsupported") {
            assert!(!endpoint.selector().expect("selector").supported());
        }
    }

    for vector in vectors
        .get("invalid")
        .and_then(Value::as_array)
        .expect("invalid vectors")
    {
        let Some(input) = vector.get("input").and_then(Value::as_str) else {
            continue;
        };
        if input.contains('\n') || input.starts_with('{') {
            continue;
        }
        let error = PortableEndpoint::parse(input)
            .unwrap_err_or_else(|| panic!("{} should fail", vector_id(vector)));
        assert_eq!(
            error.code(),
            vector
                .get("error")
                .and_then(Value::as_str)
                .expect("error code"),
            "{}",
            vector_id(vector)
        );
    }
}

#[test]
fn production_reference_parser_round_trips_every_byte() {
    for byte in u8::MIN..=u8::MAX {
        let endpoint = PortableEndpoint::parse(&format!("bytes.example://%{byte:02x}"))
            .expect("byte endpoint should parse");
        assert_eq!(endpoint.value(), &[byte]);
        let expected =
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            };
        assert_eq!(endpoint.as_str(), format!("bytes.example://{expected}"));
    }
}

#[test]
fn production_endpoint_parser_enforces_generated_boundaries() {
    let namespace = dns_name(253);
    let coordinate = dns_name(253);
    let encoded_value = "%00".repeat(1_024);
    let selection = std::iter::once("1000".to_owned())
        .chain((100..227).map(|value| value.to_string()))
        .collect::<Vec<_>>()
        .join(",");
    let accepted = format!("{namespace}://{encoded_value}[{coordinate}:{selection}]");
    assert_eq!(accepted.len(), 4_096);
    PortableEndpoint::parse(&accepted).expect("4096-byte endpoint should parse");

    let rejected = accepted.replacen("1000", "10000", 1);
    assert_eq!(rejected.len(), 4_097);
    assert_eq!(
        PortableEndpoint::parse(&rejected)
            .expect_err("4097-byte endpoint should fail")
            .code(),
        "endpoint_too_long"
    );

    PortableEndpoint::parse(&format!("value.example://{}", "x".repeat(1_024)))
        .expect("1024-byte value should parse");
    assert_eq!(
        PortableEndpoint::parse(&format!("value.example://{}", "x".repeat(1_025)))
            .expect_err("1025-byte value should fail")
            .code(),
        "reference_value_too_long"
    );
    assert_eq!(
        PortableEndpoint::parse(&format!("{}.example://item", "a".repeat(64)))
            .expect_err("64-byte namespace label should fail")
            .code(),
        "namespace_too_long"
    );
    assert_eq!(
        PortableEndpoint::parse(&format!("{}a://item", dns_name(253)))
            .expect_err("254-byte namespace should fail")
            .code(),
        "namespace_too_long"
    );
}

trait ResultExt<T, E> {
    fn unwrap_err_or_else(self, fallback: impl FnOnce() -> E) -> E;
}

impl<T, E> ResultExt<T, E> for Result<T, E> {
    fn unwrap_err_or_else(self, fallback: impl FnOnce() -> E) -> E {
        match self {
            Ok(_) => fallback(),
            Err(error) => error,
        }
    }
}

fn vector_id(vector: &Value) -> &str {
    vector.get("id").and_then(Value::as_str).expect("vector ID")
}

fn dns_name(length: usize) -> String {
    let mut labels = Vec::new();
    let mut remaining = length;
    while remaining > 63 {
        labels.push("a".repeat(63));
        remaining -= 64;
    }
    labels.push("a".repeat(remaining));
    labels.join(".")
}
