mod bootstrap;
pub mod validation;

pub use bootstrap::*;

pub const PROTOCOL_MAJOR: u32 = 1;
pub const PROTOCOL_MINOR: u32 = 0;

#[allow(clippy::large_enum_variant)]
pub mod v1 {
    tonic::include_proto!("trakkin.adapter.v1");
}

pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("trakkin_adapter");

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtocolNegotiationError {
    #[error("protocol range is missing a minimum version")]
    MissingMinimum,
    #[error("protocol range is missing a maximum version")]
    MissingMaximum,
    #[error("protocol range is inverted")]
    InvertedRange,
    #[error("adapter and host do not share a protocol major version")]
    IncompatibleMajor,
    #[error("adapter and host do not share a protocol minor version")]
    IncompatibleMinor,
}

pub fn current_protocol_version() -> v1::ProtocolVersion {
    v1::ProtocolVersion {
        major: PROTOCOL_MAJOR,
        minor: PROTOCOL_MINOR,
    }
}

pub fn negotiate_protocol(
    supported: &v1::ProtocolRange,
) -> Result<v1::ProtocolVersion, ProtocolNegotiationError> {
    let minimum = supported
        .minimum
        .as_ref()
        .ok_or(ProtocolNegotiationError::MissingMinimum)?;
    let maximum = supported
        .maximum
        .as_ref()
        .ok_or(ProtocolNegotiationError::MissingMaximum)?;

    if (minimum.major, minimum.minor) > (maximum.major, maximum.minor) {
        return Err(ProtocolNegotiationError::InvertedRange);
    }
    let current = current_protocol_version();
    let current_tuple = (current.major, current.minor);
    if current.major < minimum.major || current.major > maximum.major {
        return Err(ProtocolNegotiationError::IncompatibleMajor);
    }
    if current_tuple < (minimum.major, minimum.minor)
        || current_tuple > (maximum.major, maximum.minor)
    {
        return Err(ProtocolNegotiationError::IncompatibleMinor);
    }

    Ok(current)
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
