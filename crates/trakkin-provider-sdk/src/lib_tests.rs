use prost::Message;
use prost_types::FileDescriptorSet;

use crate::{
    FILE_DESCRIPTOR_SET, PROTOCOL_MAJOR, PROTOCOL_MINOR, ProtocolNegotiationError,
    current_protocol_version, negotiate_protocol,
    v1::{ProtocolRange, ProtocolVersion},
};

#[test]
fn descriptor_contains_single_adapter_service() {
    let descriptor = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).unwrap();
    let services = descriptor
        .file
        .iter()
        .flat_map(|file| file.service.iter())
        .collect::<Vec<_>>();
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].name.as_deref(), Some("AdapterService"));

    let methods = services[0]
        .method
        .iter()
        .filter_map(|method| method.name.as_deref())
        .collect::<Vec<_>>();
    assert_eq!(
        methods,
        [
            "Handshake",
            "Health",
            "DescribeConnection",
            "ValidateConnection",
            "ListAuthenticationMethods",
            "StartAuthentication",
            "ContinueAuthentication",
            "CancelAuthentication",
            "OpenConnection",
            "DiscoverSources",
            "ReadCatalog",
            "ReadState",
            "ReadTargetedState",
            "WriteTargetedState",
            "LookupPortableReferences",
            "ResolvePortableEndpoints",
            "ReadAsset",
            "CancelOperation",
            "Shutdown",
        ]
    );
    let descriptor_text = format!("{descriptor:?}");
    for forbidden in [
        "ReviewService",
        "EventService",
        "WriteCurrentState",
        "MappingInterface",
    ] {
        assert!(!descriptor_text.contains(forbidden), "found {forbidden}");
    }
}

#[test]
fn protocol_selects_the_current_version_from_a_compatible_range() {
    assert_eq!(current_protocol_version().major, PROTOCOL_MAJOR);
    assert_eq!(current_protocol_version().minor, PROTOCOL_MINOR);
    let selected = negotiate_protocol(&ProtocolRange {
        minimum: Some(ProtocolVersion { major: 1, minor: 0 }),
        maximum: Some(ProtocolVersion { major: 1, minor: 0 }),
    })
    .unwrap();
    assert_eq!(selected, current_protocol_version());

    let error = negotiate_protocol(&ProtocolRange {
        minimum: Some(ProtocolVersion { major: 1, minor: 1 }),
        maximum: Some(ProtocolVersion { major: 1, minor: 2 }),
    })
    .unwrap_err();
    assert_eq!(error, ProtocolNegotiationError::IncompatibleMinor);

    let selected = negotiate_protocol(&ProtocolRange {
        minimum: Some(ProtocolVersion { major: 1, minor: 0 }),
        maximum: Some(ProtocolVersion { major: 1, minor: 1 }),
    })
    .unwrap();
    assert_eq!(selected, current_protocol_version());

    let error = negotiate_protocol(&ProtocolRange {
        minimum: Some(ProtocolVersion { major: 2, minor: 0 }),
        maximum: Some(ProtocolVersion { major: 2, minor: 1 }),
    })
    .unwrap_err();
    assert_eq!(error, ProtocolNegotiationError::IncompatibleMajor);
}
