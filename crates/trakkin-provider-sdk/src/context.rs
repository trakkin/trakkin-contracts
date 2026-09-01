use std::collections::HashSet;

use tonic::{Request, metadata::AsciiMetadataValue};

pub const CORRELATION_ID_HEADER: &str = "x-trakkin-correlation-id";
pub const TRACEPARENT_HEADER: &str = "traceparent";
pub const TRACESTATE_HEADER: &str = "tracestate";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvocationContext {
    correlation_id: AsciiMetadataValue,
    traceparent: Option<AsciiMetadataValue>,
    tracestate: Option<AsciiMetadataValue>,
}

impl InvocationContext {
    pub fn new(
        correlation_id: &str,
        traceparent: Option<&str>,
        tracestate: Option<&str>,
    ) -> Result<Self, InvalidInvocationContext> {
        validate_identifier(correlation_id, "correlation ID", 128)?;
        let correlation_id = AsciiMetadataValue::try_from(correlation_id)
            .map_err(|_| InvalidInvocationContext::InvalidCorrelationId)?;
        let traceparent = traceparent
            .map(|value| {
                validate_traceparent(value)?;
                AsciiMetadataValue::try_from(value)
                    .map_err(|_| InvalidInvocationContext::InvalidTraceparent)
            })
            .transpose()?;
        let tracestate = tracestate
            .map(|value| {
                validate_tracestate(value)?;
                AsciiMetadataValue::try_from(value)
                    .map_err(|_| InvalidInvocationContext::InvalidTracestate)
            })
            .transpose()?;
        if tracestate.is_some() && traceparent.is_none() {
            return Err(InvalidInvocationContext::TracestateWithoutTraceparent);
        }
        Ok(Self {
            correlation_id,
            traceparent,
            tracestate,
        })
    }

    pub fn correlation_id(&self) -> &str {
        self.correlation_id
            .to_str()
            .expect("validated ASCII metadata")
    }

    pub fn traceparent(&self) -> Option<&str> {
        self.traceparent
            .as_ref()
            .map(|value| value.to_str().expect("validated ASCII metadata"))
    }

    pub fn tracestate(&self) -> Option<&str> {
        self.tracestate
            .as_ref()
            .map(|value| value.to_str().expect("validated ASCII metadata"))
    }

    pub fn apply<T>(&self, request: &mut Request<T>) {
        request
            .metadata_mut()
            .insert(CORRELATION_ID_HEADER, self.correlation_id.clone());
        if let Some(traceparent) = &self.traceparent {
            request
                .metadata_mut()
                .insert(TRACEPARENT_HEADER, traceparent.clone());
        }
        if let Some(tracestate) = &self.tracestate {
            request
                .metadata_mut()
                .insert(TRACESTATE_HEADER, tracestate.clone());
        }
    }
}

fn validate_identifier(
    value: &str,
    field: &'static str,
    maximum_length: usize,
) -> Result<(), InvalidInvocationContext> {
    if value.is_empty()
        || value.len() > maximum_length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(match field {
            "correlation ID" => InvalidInvocationContext::InvalidCorrelationId,
            _ => unreachable!("identifier field is known"),
        });
    }
    Ok(())
}

fn validate_traceparent(value: &str) -> Result<(), InvalidInvocationContext> {
    let bytes = value.as_bytes();
    if bytes.len() != 55
        || bytes[2] != b'-'
        || bytes[35] != b'-'
        || bytes[52] != b'-'
        || !lower_hex(&bytes[0..2])
        || !lower_hex(&bytes[3..35])
        || !lower_hex(&bytes[36..52])
        || !lower_hex(&bytes[53..55])
        || &bytes[0..2] == b"ff"
        || bytes[3..35].iter().all(|byte| *byte == b'0')
        || bytes[36..52].iter().all(|byte| *byte == b'0')
    {
        return Err(InvalidInvocationContext::InvalidTraceparent);
    }
    Ok(())
}

fn validate_tracestate(value: &str) -> Result<(), InvalidInvocationContext> {
    if value.is_empty() || value.len() > 512 {
        return Err(InvalidInvocationContext::InvalidTracestate);
    }
    let mut keys = HashSet::new();
    let mut count = 0;
    for member in value.split(',') {
        count += 1;
        let member = member.trim_matches([' ', '\t']);
        let Some((key, value)) = member.split_once('=') else {
            return Err(InvalidInvocationContext::InvalidTracestate);
        };
        if count > 32
            || !valid_tracestate_key(key)
            || !keys.insert(key)
            || value.is_empty()
            || value.len() > 256
            || value.starts_with([' ', '\t'])
            || value.ends_with([' ', '\t'])
            || !value
                .bytes()
                .all(|byte| (0x20..=0x7e).contains(&byte) && !matches!(byte, b',' | b'='))
        {
            return Err(InvalidInvocationContext::InvalidTracestate);
        }
    }
    Ok(())
}

fn lower_hex(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn valid_tracestate_key(key: &str) -> bool {
    let valid_tail = |byte: &u8| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'_' | b'-' | b'*' | b'/')
    };
    let valid_simple = |part: &str, maximum: usize, first_can_be_digit: bool| {
        let bytes = part.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= maximum
            && (bytes[0].is_ascii_lowercase() || (first_can_be_digit && bytes[0].is_ascii_digit()))
            && bytes[1..].iter().all(valid_tail)
    };
    match key.split_once('@') {
        Some((tenant, system)) => {
            !system.contains('@')
                && valid_simple(tenant, 241, true)
                && valid_simple(system, 14, false)
        }
        None => valid_simple(key, 256, false),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidInvocationContext {
    #[error("correlation ID must be a bounded ASCII identifier")]
    InvalidCorrelationId,
    #[error("traceparent must be bounded ASCII metadata")]
    InvalidTraceparent,
    #[error("tracestate must be bounded ASCII metadata")]
    InvalidTracestate,
    #[error("tracestate requires traceparent")]
    TracestateWithoutTraceparent,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_context_applies_bounded_metadata() {
        let context = InvocationContext::new(
            "request:123",
            Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
            Some("vendor=value"),
        )
        .unwrap();
        let mut request = Request::new(());
        context.apply(&mut request);

        assert_eq!(
            request.metadata().get(CORRELATION_ID_HEADER).unwrap(),
            "request:123"
        );
        assert_eq!(context.correlation_id(), "request:123");
        assert!(context.traceparent().is_some());
        assert_eq!(context.tracestate(), Some("vendor=value"));
    }

    #[test]
    fn invocation_context_rejects_unsafe_metadata() {
        assert_eq!(
            InvocationContext::new("secret value", None, None),
            Err(InvalidInvocationContext::InvalidCorrelationId)
        );
        assert_eq!(
            InvocationContext::new("request-1", None, Some("vendor=value")),
            Err(InvalidInvocationContext::TracestateWithoutTraceparent)
        );
        assert_eq!(
            InvocationContext::new("request-1", Some("abc"), None),
            Err(InvalidInvocationContext::InvalidTraceparent)
        );
        assert_eq!(
            InvocationContext::new(
                "request-1",
                Some("00-00000000000000000000000000000000-00f067aa0ba902b7-01"),
                None,
            ),
            Err(InvalidInvocationContext::InvalidTraceparent)
        );
        assert_eq!(
            InvocationContext::new(
                "request-1",
                Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
                Some("Vendor=value"),
            ),
            Err(InvalidInvocationContext::InvalidTracestate)
        );
    }
}
