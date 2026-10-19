use prost::Message;
use prost_types::FileDescriptorSet;

use crate::{
    FILE_DESCRIPTOR_SET, PROTOCOL_MAJOR, PROTOCOL_MINOR, ProtocolNegotiationError,
    current_protocol_version, negotiate_protocol,
    v1::{ProtocolRange, ProtocolVersion},
};

#[test]
fn descriptor_contains_provider_contracts() {
    let descriptor = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).unwrap();
    let services = descriptor
        .file
        .iter()
        .flat_map(|file| file.service.iter())
        .collect::<Vec<_>>();
    assert_eq!(services.len(), 2);

    for adapter in descriptor
        .file
        .iter()
        .filter(|file| file.package.as_deref() == Some("trakkin.adapter.v1"))
    {
        for message in &adapter.message_type {
            let field_numbers = message
                .field
                .iter()
                .map(|field| field.number.unwrap())
                .collect::<Vec<_>>();
            let expected = (1..=field_numbers.len() as i32).collect::<Vec<_>>();
            assert_eq!(field_numbers, expected, "{:?} field tags", message.name);
        }
        for enumeration in &adapter.enum_type {
            let value_numbers = enumeration
                .value
                .iter()
                .map(|value| value.number.unwrap())
                .collect::<Vec<_>>();
            let expected = (0..value_numbers.len() as i32).collect::<Vec<_>>();
            assert_eq!(
                value_numbers, expected,
                "{:?} enum values",
                enumeration.name
            );
        }
    }

    let adapter_service = services
        .iter()
        .find(|service| service.name.as_deref() == Some("AdapterService"))
        .unwrap();
    let methods = adapter_service
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
            "ReadAsset",
            "CancelOperation",
            "Shutdown",
        ]
    );
    let descriptor_text = format!("{descriptor:?}");
    for forbidden in ["ReviewService", "EventService", "WriteCurrentState"] {
        assert!(!descriptor_text.contains(forbidden), "found {forbidden}");
    }

    let bootstrap = descriptor
        .file
        .iter()
        .find(|file| file.package.as_deref() == Some("trakkin.bootstrap.v1"))
        .unwrap();
    let messages = bootstrap
        .message_type
        .iter()
        .filter_map(|message| message.name.as_deref())
        .collect::<Vec<_>>();
    assert_eq!(messages, ["LaunchRequest", "ReadyMessage"]);

    let completion = services
        .iter()
        .find(|service| service.name.as_deref() == Some("CompletionService"))
        .unwrap();
    assert_eq!(
        completion
            .method
            .iter()
            .filter_map(|method| method.name.as_deref())
            .collect::<Vec<_>>(),
        [
            "DescribeCompletionLibrary",
            "DiscoverCompletionSubjects",
            "DescribeCompletion",
            "ReadCompletion",
            "ResolveCompletionDestinations",
            "PrepareCompletion",
            "ExecuteCompletion",
            "ReconcileCompletion",
        ]
    );
}

#[test]
fn completion_wire_preserves_zero_progress_and_explicit_presence() {
    use crate::v1::{
        CompletionObservation, CompletionProgress, completion_observation, completion_progress,
    };

    for value in [
        completion_progress::Value::Prefix(0),
        completion_progress::Value::Cardinality(0),
    ] {
        let progress = CompletionProgress { value: Some(value) };
        let decoded = CompletionProgress::decode(progress.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, progress);
        assert_ne!(decoded, CompletionProgress::default());
    }
    for presence in [
        completion_observation::Presence::Missing(()),
        completion_observation::Presence::Cleared(()),
        completion_observation::Presence::MeaningfulAbsence(()),
    ] {
        let observation = CompletionObservation {
            presence: Some(presence),
            ..Default::default()
        };
        assert_eq!(
            CompletionObservation::decode(observation.encode_to_vec().as_slice()).unwrap(),
            observation
        );
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
