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
    for required in ["AdapterService", "CompletionService"] {
        assert!(
            services
                .iter()
                .any(|service| service.name.as_deref() == Some(required)),
            "missing service {required}"
        );
    }

    let bootstrap = descriptor
        .file
        .iter()
        .find(|file| file.package.as_deref() == Some("trakkin.bootstrap.v1"))
        .unwrap();
    for required in ["LaunchRequest", "ReadyMessage"] {
        assert!(
            bootstrap
                .message_type
                .iter()
                .any(|message| message.name.as_deref() == Some(required)),
            "missing bootstrap message {required}"
        );
    }
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
