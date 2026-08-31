use crate::{
    v1::{
        AccountSnapshot, AdapterError, AuthenticationStatus, CancelAuthenticationResponse,
        CancelAuthenticationResult, CancelOperationResponse, CancelOperationResult, CatalogBatch,
        ConfigurationValueKind, ConnectionCapabilities, ContentHash,
        ContinueAuthenticationResponse, CoordinateBacking, CoordinateBinding,
        DescribeConnectionResponse, DiscoverSourcesResponse, DiscoverSourcesResult,
        EndpointLookupCandidate, EndpointLookupCapability, EndpointLookupMatched, FieldProblem,
        HealthResponse, HealthStatus, Key, ListAuthenticationMethodsResponse, LookupAmbiguous,
        LookupCandidate, LookupCapability, LookupEvidence, LookupPortableReferencesResponse,
        LookupPortableReferencesResult, OpenConnectionResponse, OpenConnectionResult,
        PortableEndpoint, PortableEndpointResolution, PortableReference,
        PortableReferenceLookupResult, ProviderItem, ReadAssetResponse, ReadAssetResult,
        ReadCancelled, ReadCatalogRequest, ReadCatalogResponse, ReadCompleted, ReadMode,
        ReadStateRequest, ReadStateResponse, ReadTargetedStateRequest, ReadTargetedStateResponse,
        ResolvePortableEndpointsRequest, ResolvePortableEndpointsResponse,
        ResolvePortableEndpointsResult, SourceAvailability, SourceCapabilities, SourceMembership,
        SourceSnapshot, StartAuthenticationResponse, StateBatch, StateField, StateFieldDescriptor,
        StateFieldNumericRange, StateFieldQuantizer, StatePresence, SubjectReference,
        TargetedStateClear, TargetedStateFieldEffectKind, TargetedStateFieldObservation,
        TargetedStateFieldWriteCapability, TargetedStateMembershipEffect,
        TargetedStateReadAmbiguous, TargetedStateReadCapability, TargetedStateReadIndeterminate,
        TargetedStateReadMatched, TargetedStateReadNotFound, TargetedStateReadUnsupported,
        TargetedStateWriteCapability, TargetedStateWriteCausation, TargetedStateWriteCertainty,
        TargetedStateWriteFieldEffect, TargetedStateWriteIdempotencyMode, TargetedStateWriteIntent,
        TargetedStateWritePreconditionMode, TargetedStateWriteRetryDisposition,
        TargetedStateWriteStatus, Term, ValidateConnectionResponse, ValidateConnectionResult,
        Value, WriteTargetedStateRequest, WriteTargetedStateResponse,
        cancel_authentication_response, cancel_operation_response, describe_connection_response,
        discover_sources_response, list_authentication_methods_response,
        lookup_portable_references_response, open_connection_response,
        portable_endpoint_resolution, portable_reference_lookup_result, read_asset_response,
        read_catalog_response, read_state_response, read_targeted_state_response,
        resolve_portable_endpoints_response, subject_reference, targeted_state_write_intent,
        validate_connection_response, value,
    },
    validation::{self, CatalogStreamValidator, ValidationError},
};
use prost::Message;
use sha2::{Digest, Sha256};

fn key(value: &str) -> Key {
    Key {
        namespace: "fixture".to_owned(),
        value: value.as_bytes().to_vec(),
    }
}
fn term(name: &str) -> Term {
    Term {
        namespace: "trakkin".to_owned(),
        name: name.to_owned(),
    }
}

fn reference(value: &str) -> PortableReference {
    PortableReference {
        namespace: "example.media".to_owned(),
        value: value.as_bytes().to_vec(),
    }
}

fn endpoint(value: &str, selector: &str) -> PortableEndpoint {
    PortableEndpoint {
        reference: Some(reference(value)),
        selector: selector.to_owned(),
    }
}

fn item(value: &str) -> ProviderItem {
    ProviderItem {
        key: Some(key(value)),
        kind: Some(term("movie")),
        display_name: value.to_owned(),
        portable_references: vec![reference(value)],
        ..ProviderItem::default()
    }
}

#[test]
fn source_capabilities_require_complete_numeric_translation_metadata() {
    let descriptor = StateFieldDescriptor {
        field: Some(Term {
            namespace: "dev.trakkin.state".to_owned(),
            name: "progress".to_owned(),
        }),
        unit: Some(Term {
            namespace: "dev.trakkin.state".to_owned(),
            name: "episode".to_owned(),
        }),
        value_kind: ConfigurationValueKind::Integer as i32,
        rating_scale: None,
        numeric_range: Some(StateFieldNumericRange {
            minimum: "0".to_owned(),
            maximum: "12".to_owned(),
            step: "1".to_owned(),
        }),
        quantizer: StateFieldQuantizer::Exact as i32,
    };
    validation::source_capabilities(&SourceCapabilities {
        state_fields: vec![descriptor.clone()],
        ..SourceCapabilities::default()
    })
    .expect("complete numeric translation metadata is valid");

    let mut missing_quantizer = descriptor.clone();
    missing_quantizer.quantizer = StateFieldQuantizer::Unspecified as i32;
    assert_eq!(
        validation::source_capabilities(&SourceCapabilities {
            state_fields: vec![missing_quantizer],
            ..SourceCapabilities::default()
        }),
        Err(ValidationError::Invalid(
            "state field numeric range and quantizer"
        ))
    );

    let mut missing_range = descriptor;
    missing_range.numeric_range = None;
    assert_eq!(
        validation::source_capabilities(&SourceCapabilities {
            state_fields: vec![missing_range],
            ..SourceCapabilities::default()
        }),
        Err(ValidationError::Invalid(
            "state field numeric range and quantizer"
        ))
    );
}

#[test]
fn catalog_stream_requires_contiguous_batches_and_one_terminal_event() {
    let mut validator = CatalogStreamValidator::default();
    validator
        .accept(&ReadCatalogResponse {
            event: Some(read_catalog_response::Event::Batch(CatalogBatch {
                sequence: 0,
                item_upserts: vec![item("signal")],
                ..CatalogBatch::default()
            })),
        })
        .unwrap();
    validator
        .accept(&ReadCatalogResponse {
            event: Some(read_catalog_response::Event::Completed(ReadCompleted {
                next_cursor: b"cursor-1".to_vec(),
                evidence_revision: b"revision-1".to_vec(),
                observed_time_milliseconds: 1_893_456_245_000,
            })),
        })
        .unwrap();
    assert!(validator.finish().is_ok());

    let mut missing = CatalogStreamValidator::default();
    missing
        .accept(&ReadCatalogResponse {
            event: Some(read_catalog_response::Event::Batch(CatalogBatch {
                sequence: 0,
                ..CatalogBatch::default()
            })),
        })
        .unwrap();
    assert_eq!(missing.finish(), Err(ValidationError::MissingTerminal));
}

#[test]
fn account_source_plurality_and_read_modes_are_validated() {
    let accounts = vec![
        AccountSnapshot {
            key: Some(key("account-a")),
            display_name: "Account A".to_owned(),
        },
        AccountSnapshot {
            key: Some(key("account-b")),
            display_name: "Account B".to_owned(),
        },
    ];
    let open = OpenConnectionResponse {
        outcome: Some(open_connection_response::Outcome::Result(
            OpenConnectionResult {
                accounts: accounts.clone(),
                capabilities: Some(ConnectionCapabilities {
                    reference_lookup: Some(LookupCapability {
                        reference_namespaces: vec!["example.media".to_owned()],
                        maximum_batch_size: 20,
                    }),
                    endpoint_lookup: None,
                }),
                secret_patches: Vec::new(),
            },
        )),
    };
    validation::open_connection_response(&open).unwrap();

    let source = SourceSnapshot {
        key: Some(key("source-a")),
        account_key: accounts[1].key.clone(),
        display_name: "Source A".to_owned(),
        kind: Some(term("library")),
        availability: SourceAvailability::Available as i32,
        capabilities: Some(SourceCapabilities::default()),
    };
    validation::discover_sources_response(
        &accounts
            .iter()
            .map(|account| account.key.clone().unwrap())
            .collect::<Vec<_>>(),
        &DiscoverSourcesResponse {
            outcome: Some(discover_sources_response::Outcome::Result(
                DiscoverSourcesResult {
                    sources: vec![source],
                    secret_patches: Vec::new(),
                },
            )),
        },
    )
    .unwrap();

    validation::read_catalog_request(&ReadCatalogRequest {
        operation_id: b"read-1".to_vec(),
        source_key: Some(key("source-a")),
        mode: ReadMode::Incremental as i32,
        prior_cursor: b"cursor-1".to_vec(),
        preferred_batch_size: 100,
    })
    .unwrap();
    validation::read_state_request(&ReadStateRequest {
        operation_id: b"read-2".to_vec(),
        source_key: Some(key("source-a")),
        mode: ReadMode::Full as i32,
        prior_cursor: Vec::new(),
        preferred_batch_size: 100,
    })
    .unwrap();
}

#[test]
fn connection_lookup_capabilities_are_absent_or_usable() {
    validation::open_connection_response(&OpenConnectionResponse {
        outcome: Some(open_connection_response::Outcome::Result(
            OpenConnectionResult::default(),
        )),
    })
    .unwrap();

    let unusable_reference_lookup = OpenConnectionResponse {
        outcome: Some(open_connection_response::Outcome::Result(
            OpenConnectionResult {
                capabilities: Some(ConnectionCapabilities {
                    reference_lookup: Some(LookupCapability::default()),
                    endpoint_lookup: None,
                }),
                ..OpenConnectionResult::default()
            },
        )),
    };
    assert_eq!(
        validation::open_connection_response(&unusable_reference_lookup),
        Err(ValidationError::Invalid("lookup capability"))
    );

    let unusable_endpoint_lookup = OpenConnectionResponse {
        outcome: Some(open_connection_response::Outcome::Result(
            OpenConnectionResult {
                capabilities: Some(ConnectionCapabilities {
                    reference_lookup: None,
                    endpoint_lookup: Some(EndpointLookupCapability::default()),
                }),
                ..OpenConnectionResult::default()
            },
        )),
    };
    assert_eq!(
        validation::open_connection_response(&unusable_endpoint_lookup),
        Err(ValidationError::Invalid("endpoint lookup capability"))
    );
}

#[test]
fn connection_setup_errors_are_exclusive_with_payloads() {
    let error = AdapterError {
        code: "setup_failed".to_owned(),
        safe_message: "Connection setup failed".to_owned(),
        ..AdapterError::default()
    };

    validation::describe_connection_response(&DescribeConnectionResponse {
        outcome: Some(describe_connection_response::Outcome::Error(error.clone())),
    })
    .unwrap();
    validation::validate_connection_response(&ValidateConnectionResponse {
        outcome: Some(validate_connection_response::Outcome::Error(error.clone())),
    })
    .unwrap();
    validation::list_authentication_methods_response(&ListAuthenticationMethodsResponse {
        outcome: Some(list_authentication_methods_response::Outcome::Error(
            error.clone(),
        )),
    })
    .unwrap();
    validation::open_connection_response(&OpenConnectionResponse {
        outcome: Some(open_connection_response::Outcome::Error(error)),
    })
    .unwrap();

    assert_eq!(
        validation::describe_connection_response(&DescribeConnectionResponse::default()),
        Err(ValidationError::Missing("connection description outcome"))
    );

    validation::validate_connection_response(&ValidateConnectionResponse {
        outcome: Some(validate_connection_response::Outcome::Result(
            ValidateConnectionResult {
                field_problems: vec![FieldProblem {
                    path: "server_url".to_owned(),
                    code: "invalid_url".to_owned(),
                    message: "Server URL is invalid".to_owned(),
                }],
            },
        )),
    })
    .expect("field problems are a validation result, not an adapter failure");
}

#[test]
fn unary_operation_responses_require_closed_outcomes() {
    let error = AdapterError {
        code: "operation_failed".to_owned(),
        safe_message: "Adapter operation failed".to_owned(),
        ..AdapterError::default()
    };

    validation::discover_sources_response(
        &[],
        &DiscoverSourcesResponse {
            outcome: Some(discover_sources_response::Outcome::Error(error.clone())),
        },
    )
    .unwrap();
    validation::lookup_response(
        &[],
        &LookupPortableReferencesResponse {
            outcome: Some(lookup_portable_references_response::Outcome::Error(
                error.clone(),
            )),
        },
    )
    .unwrap();
    validation::resolve_endpoints_response(
        &[],
        &ResolvePortableEndpointsResponse {
            outcome: Some(resolve_portable_endpoints_response::Outcome::Error(
                error.clone(),
            )),
        },
        4096,
    )
    .unwrap();
    validation::asset_response(
        &ReadAssetResponse {
            outcome: Some(read_asset_response::Outcome::Error(error)),
        },
        4096,
        &["image/jpeg".to_owned()],
    )
    .unwrap();

    assert_eq!(
        validation::discover_sources_response(&[], &DiscoverSourcesResponse::default()),
        Err(ValidationError::Missing("source discovery outcome"))
    );
    assert_eq!(
        validation::lookup_response(&[], &LookupPortableReferencesResponse::default()),
        Err(ValidationError::Missing(
            "portable reference lookup outcome"
        ))
    );
    assert_eq!(
        validation::resolve_endpoints_response(
            &[],
            &ResolvePortableEndpointsResponse::default(),
            4096,
        ),
        Err(ValidationError::Missing("endpoint resolution outcome"))
    );
    assert_eq!(
        validation::asset_response(
            &ReadAssetResponse::default(),
            4096,
            &["image/jpeg".to_owned()],
        ),
        Err(ValidationError::Missing("asset read outcome"))
    );
}

#[test]
fn authentication_prompt_and_state_cancellation_are_validated() {
    let step = StartAuthenticationResponse {
        authentication_id: "auth-1".to_owned(),
        status: AuthenticationStatus::InputRequired as i32,
        prompt: Some(Default::default()),
        ..StartAuthenticationResponse::default()
    };
    validation::start_authentication_response(&step).unwrap();
    validation::continue_authentication_response(&ContinueAuthenticationResponse {
        authentication_id: "auth-2".to_owned(),
        status: AuthenticationStatus::Waiting as i32,
        ..ContinueAuthenticationResponse::default()
    })
    .unwrap();

    let mut validator = validation::StateStreamValidator::default();
    validator
        .accept(&ReadStateResponse {
            event: Some(read_state_response::Event::Batch(StateBatch {
                sequence: 0,
                ..StateBatch::default()
            })),
        })
        .unwrap();
    validator
        .accept(&ReadStateResponse {
            event: Some(read_state_response::Event::Cancelled(ReadCancelled {})),
        })
        .unwrap();
    assert!(validator.finish().is_ok());
}

#[test]
fn status_coupled_errors_and_cancellation_outcomes_are_validated() {
    let error = AdapterError {
        code: "temporarily_unavailable".to_owned(),
        safe_message: "the adapter is temporarily unavailable".to_owned(),
        retryable: true,
        ..AdapterError::default()
    };

    for status in [
        HealthStatus::Ready,
        HealthStatus::Degraded,
        HealthStatus::NotReady,
    ] {
        let expects_error = status != HealthStatus::Ready;
        let response = HealthResponse {
            status: status as i32,
            error: expects_error.then(|| error.clone()),
        };
        validation::health_response(&response).unwrap();

        let contradictory = HealthResponse {
            status: status as i32,
            error: (!expects_error).then(|| error.clone()),
        };
        assert!(validation::health_response(&contradictory).is_err());
    }

    for status in [
        AuthenticationStatus::Waiting,
        AuthenticationStatus::InputRequired,
        AuthenticationStatus::Completed,
        AuthenticationStatus::Cancelled,
        AuthenticationStatus::Expired,
        AuthenticationStatus::Failed,
    ] {
        let expects_error = status == AuthenticationStatus::Failed;
        let step = StartAuthenticationResponse {
            authentication_id: "auth-1".to_owned(),
            status: status as i32,
            prompt: (status == AuthenticationStatus::InputRequired).then_some(Default::default()),
            error: expects_error.then(|| error.clone()),
            ..StartAuthenticationResponse::default()
        };
        validation::start_authentication_response(&step).unwrap();

        let contradictory = StartAuthenticationResponse {
            error: (!expects_error).then(|| error.clone()),
            ..step
        };
        assert!(validation::start_authentication_response(&contradictory).is_err());
    }

    validation::cancel_authentication_response(&CancelAuthenticationResponse {
        outcome: Some(cancel_authentication_response::Outcome::Result(
            CancelAuthenticationResult {},
        )),
    })
    .unwrap();
    validation::cancel_authentication_response(&CancelAuthenticationResponse {
        outcome: Some(cancel_authentication_response::Outcome::Error(
            error.clone(),
        )),
    })
    .unwrap();
    validation::cancel_operation_response(&CancelOperationResponse {
        outcome: Some(cancel_operation_response::Outcome::Result(
            CancelOperationResult {},
        )),
    })
    .unwrap();
    validation::cancel_operation_response(&CancelOperationResponse {
        outcome: Some(cancel_operation_response::Outcome::Error(error)),
    })
    .unwrap();
    assert_eq!(
        validation::cancel_authentication_response(&CancelAuthenticationResponse::default()),
        Err(ValidationError::Missing(
            "authentication cancellation outcome"
        ))
    );
    assert_eq!(
        validation::cancel_operation_response(&CancelOperationResponse::default()),
        Err(ValidationError::Missing("operation cancellation outcome"))
    );
}

#[test]
fn ambiguous_lookup_requires_multiple_valid_candidates() {
    let requested = reference("signal");
    let candidate = LookupCandidate {
        provider_item: Some(item("signal-a")),
        evidence: Some(LookupEvidence {
            adapter_revision: b"lookup-1".to_vec(),
            observed_time_milliseconds: 1_893_456_245_000,
            expires_time_milliseconds: None,
            matched_references: vec![requested.clone()],
        }),
    };
    let response = LookupPortableReferencesResponse {
        outcome: Some(lookup_portable_references_response::Outcome::Result(
            LookupPortableReferencesResult {
                results: vec![PortableReferenceLookupResult {
                    requested: Some(requested.clone()),
                    outcome: Some(portable_reference_lookup_result::Outcome::Ambiguous(
                        LookupAmbiguous {
                            candidates: vec![candidate],
                        },
                    )),
                }],
            },
        )),
    };
    assert_eq!(
        validation::lookup_response(&[requested], &response),
        Err(ValidationError::InsufficientCandidates)
    );
}

#[test]
fn asset_validation_enforces_bound_content_type_length_and_hash() {
    let content = b"fixture-image".to_vec();
    let response = ReadAssetResponse {
        outcome: Some(read_asset_response::Outcome::Result(ReadAssetResult {
            full_length: content.len() as u64,
            hash: Some(ContentHash {
                algorithm: Some(term("sha256")),
                digest: Sha256::digest(&content).to_vec(),
            }),
            content,
            content_type: "image/jpeg".to_owned(),
            cache_control: "private, max-age=300".to_owned(),
        })),
    };
    validation::asset_response(&response, 1024, &["image/jpeg".to_owned()]).unwrap();
    assert!(matches!(
        validation::asset_response(&response, 4, &["image/jpeg".to_owned()]),
        Err(ValidationError::AssetTooLarge { .. })
    ));
    let mut invalid_cache_control = response.clone();
    if let Some(read_asset_response::Outcome::Result(result)) =
        invalid_cache_control.outcome.as_mut()
    {
        result.cache_control.clear();
    }
    assert_eq!(
        validation::asset_response(&invalid_cache_control, 1024, &["image/jpeg".to_owned()]),
        Err(ValidationError::Invalid("asset cache control"))
    );
    if let Some(read_asset_response::Outcome::Result(result)) =
        invalid_cache_control.outcome.as_mut()
    {
        result.cache_control = "private\r\nx-injected: true".to_owned();
    }
    assert_eq!(
        validation::asset_response(&invalid_cache_control, 1024, &["image/jpeg".to_owned()]),
        Err(ValidationError::Invalid("asset cache control"))
    );
}

#[test]
fn protocol_one_validates_coordinate_backings_and_bounded_endpoint_lookup() {
    let requested = endpoint("title-total", "episode:1..12");
    let bindings = [
        ("children", CoordinateBacking::Materialized),
        ("virtual-cour", CoordinateBacking::Virtual),
        ("title-total", CoordinateBacking::Aggregate),
    ]
    .into_iter()
    .map(|(value, backing)| CoordinateBinding {
        endpoint: Some(endpoint(value, "episode:1..12")),
        subject: Some(SubjectReference {
            subject: Some(subject_reference::Subject::ProviderItemKey(key(value))),
        }),
        backing: backing as i32,
        evidence_revision: b"coordinates-r1".to_vec(),
    })
    .collect::<Vec<_>>();
    let mut validator = CatalogStreamValidator::default();
    validator
        .accept(&ReadCatalogResponse {
            event: Some(read_catalog_response::Event::Batch(CatalogBatch {
                sequence: 0,
                coordinate_binding_upserts: bindings.clone(),
                ..CatalogBatch::default()
            })),
        })
        .unwrap();
    validator
        .accept(&ReadCatalogResponse {
            event: Some(read_catalog_response::Event::Completed(ReadCompleted {
                next_cursor: b"cursor-1".to_vec(),
                evidence_revision: b"catalog-r1".to_vec(),
                observed_time_milliseconds: 1_893_456_245_000,
            })),
        })
        .unwrap();
    validator.finish().unwrap();

    let request = ResolvePortableEndpointsRequest {
        operation_id: b"endpoint-lookup-1".to_vec(),
        endpoints: vec![requested.clone()],
        maximum_response_bytes: 4096,
    };
    validation::resolve_endpoints_request(&request).unwrap();
    let response = ResolvePortableEndpointsResponse {
        outcome: Some(resolve_portable_endpoints_response::Outcome::Result(
            ResolvePortableEndpointsResult {
                results: vec![PortableEndpointResolution {
                    requested: Some(requested.clone()),
                    outcome: Some(portable_endpoint_resolution::Outcome::Matched(
                        EndpointLookupMatched {
                            candidate: Some(EndpointLookupCandidate {
                                provider_item: Some(item("title-total")),
                                binding: Some(bindings[2].clone()),
                                evidence: Some(LookupEvidence {
                                    adapter_revision: b"lookup-r1".to_vec(),
                                    observed_time_milliseconds: 1_893_456_245_000,
                                    expires_time_milliseconds: Some(1_893_456_305_000),
                                    matched_references: vec![reference("title-total")],
                                }),
                            }),
                        },
                    )),
                }],
            },
        )),
    };
    validation::resolve_endpoints_response(
        &request.endpoints,
        &response,
        request.maximum_response_bytes,
    )
    .unwrap();
    assert!(matches!(
        validation::resolve_endpoints_response(&request.endpoints, &response, 1),
        Err(ValidationError::EndpointResponseTooLarge { .. })
    ));

    let capabilities = OpenConnectionResponse {
        outcome: Some(open_connection_response::Outcome::Result(
            OpenConnectionResult {
                capabilities: Some(ConnectionCapabilities {
                    reference_lookup: None,
                    endpoint_lookup: Some(EndpointLookupCapability {
                        reference_namespaces: vec!["example.media".to_owned()],
                        coordinate_ids: vec!["episode".to_owned()],
                        maximum_batch_size: 20,
                        maximum_response_bytes: 65_536,
                    }),
                }),
                ..OpenConnectionResult::default()
            },
        )),
    };
    validation::open_connection_response(&capabilities).unwrap();

    let mut invalid_capabilities = capabilities;
    let Some(open_connection_response::Outcome::Result(result)) =
        invalid_capabilities.outcome.as_mut()
    else {
        unreachable!();
    };
    result
        .capabilities
        .as_mut()
        .unwrap()
        .endpoint_lookup
        .as_mut()
        .unwrap()
        .coordinate_ids = vec!["unknown".to_owned()];
    assert_eq!(
        validation::open_connection_response(&invalid_capabilities),
        Err(ValidationError::Invalid("endpoint lookup coordinate ID"))
    );
}

#[test]
fn targeted_state_read_is_bounded_and_preserves_membership_evidence() {
    let capability = TargetedStateReadCapability {
        maximum_fields: 1,
        maximum_response_bytes: 4096,
    };
    let field = StateField {
        field: Some(Term {
            namespace: "dev.trakkin.state".to_owned(),
            name: "watched".to_owned(),
        }),
        unit: None,
    };
    let subject = SubjectReference {
        subject: Some(subject_reference::Subject::ProviderItemKey(key(
            "quiet-signal",
        ))),
    };
    let request = ReadTargetedStateRequest {
        operation_id: b"targeted-read-1".to_vec(),
        source_key: Some(key("receiving-list")),
        subject: Some(subject.clone()),
        fields: vec![field.clone()],
        maximum_response_bytes: 4096,
        reconciliation_idempotency_key: Vec::new(),
    };
    validation::targeted_state_read_request(&request, &capability).unwrap();
    let mut excessive_fields = request.clone();
    excessive_fields.fields.push(StateField {
        field: Some(Term {
            namespace: "dev.trakkin.state".to_owned(),
            name: "completion".to_owned(),
        }),
        unit: None,
    });
    assert_eq!(
        validation::targeted_state_read_request(&excessive_fields, &capability),
        Err(ValidationError::Invalid("targeted state read field limit"))
    );

    let matched = ReadTargetedStateResponse {
        outcome: Some(read_targeted_state_response::Outcome::Matched(
            TargetedStateReadMatched {
                membership: SourceMembership::Absent as i32,
                fields: vec![TargetedStateFieldObservation {
                    field: Some(field.clone()),
                    presence: StatePresence::Absent as i32,
                    value: None,
                }],
                provider_revision: b"provider-r1".to_vec(),
                observed_time_milliseconds: 1_893_456_245_000,
                expires_time_milliseconds: Some(1_893_456_305_000),
                precondition: b"expected-absent-r1".to_vec(),
                write_causation: None,
            },
        )),
    };
    validation::read_targeted_state_response(&request, &matched).unwrap();
    let mut reconciliation_request = request.clone();
    reconciliation_request.reconciliation_idempotency_key = vec![7; 16];
    validation::targeted_state_read_request(&reconciliation_request, &capability).unwrap();
    let mut oversized_key = reconciliation_request.clone();
    oversized_key.reconciliation_idempotency_key.push(7);
    assert_eq!(
        validation::targeted_state_read_request(&oversized_key, &capability),
        Err(ValidationError::Invalid(
            "targeted state reconciliation idempotency key"
        ))
    );
    validation::read_targeted_state_response(&reconciliation_request, &matched).unwrap();
    let mut reconciled = matched.clone();
    let read_targeted_state_response::Outcome::Matched(reconciled_match) =
        reconciled.outcome.as_mut().unwrap()
    else {
        unreachable!();
    };
    reconciled_match.write_causation = Some(TargetedStateWriteCausation {
        idempotency_key: reconciliation_request
            .reconciliation_idempotency_key
            .clone(),
        receipt: b"receipt-r1".to_vec(),
        provider_revision: reconciled_match.provider_revision.clone(),
    });
    validation::read_targeted_state_response(&reconciliation_request, &reconciled).unwrap();
    assert_eq!(
        validation::read_targeted_state_response(&request, &reconciled),
        Err(ValidationError::Invalid(
            "unsolicited targeted state write causation"
        ))
    );
    let mut mismatched_key = reconciled.clone();
    let read_targeted_state_response::Outcome::Matched(mismatched_match) =
        mismatched_key.outcome.as_mut().unwrap()
    else {
        unreachable!();
    };
    mismatched_match
        .write_causation
        .as_mut()
        .unwrap()
        .idempotency_key = vec![8; 16];
    assert_eq!(
        validation::read_targeted_state_response(&reconciliation_request, &mismatched_key),
        Err(ValidationError::Invalid("targeted state write causation"))
    );
    let mut empty_receipt = reconciled.clone();
    let read_targeted_state_response::Outcome::Matched(empty_receipt_match) =
        empty_receipt.outcome.as_mut().unwrap()
    else {
        unreachable!();
    };
    empty_receipt_match
        .write_causation
        .as_mut()
        .unwrap()
        .receipt
        .clear();
    assert_eq!(
        validation::read_targeted_state_response(&reconciliation_request, &empty_receipt),
        Err(ValidationError::Invalid("targeted state write causation"))
    );
    let mut invalid_causation = reconciled;
    let read_targeted_state_response::Outcome::Matched(invalid_match) =
        invalid_causation.outcome.as_mut().unwrap()
    else {
        unreachable!();
    };
    invalid_match
        .write_causation
        .as_mut()
        .unwrap()
        .provider_revision = b"other-revision".to_vec();
    assert_eq!(
        validation::read_targeted_state_response(&reconciliation_request, &invalid_causation),
        Err(ValidationError::Invalid("targeted state write causation"))
    );

    let outcomes = [
        ReadTargetedStateResponse {
            outcome: Some(read_targeted_state_response::Outcome::Unsupported(
                TargetedStateReadUnsupported {},
            )),
        },
        ReadTargetedStateResponse {
            outcome: Some(read_targeted_state_response::Outcome::NotFound(
                TargetedStateReadNotFound {},
            )),
        },
        ReadTargetedStateResponse {
            outcome: Some(read_targeted_state_response::Outcome::Ambiguous(
                TargetedStateReadAmbiguous {
                    candidates: vec![
                        subject.clone(),
                        SubjectReference {
                            subject: Some(subject_reference::Subject::ProviderItemKey(key(
                                "quiet-signal-alt",
                            ))),
                        },
                    ],
                },
            )),
        },
        ReadTargetedStateResponse {
            outcome: Some(read_targeted_state_response::Outcome::Indeterminate(
                TargetedStateReadIndeterminate {
                    error: Some(crate::v1::AdapterError {
                        code: "temporarily_unavailable".to_owned(),
                        safe_message: "targeted state is temporarily unavailable".to_owned(),
                        retryable: true,
                        ..Default::default()
                    }),
                },
            )),
        },
    ];
    for response in outcomes {
        validation::read_targeted_state_response(&request, &response).unwrap();
    }

    let mut inconsistent = matched;
    let read_targeted_state_response::Outcome::Matched(inconsistent_match) =
        inconsistent.outcome.as_mut().unwrap()
    else {
        unreachable!();
    };
    inconsistent_match.fields[0].presence = StatePresence::Present as i32;
    inconsistent_match.fields[0].value = Some(Value {
        value: Some(value::Value::Boolean(true)),
    });
    assert_eq!(
        validation::read_targeted_state_response(&request, &inconsistent),
        Err(ValidationError::Invalid(
            "absent membership with present state"
        ))
    );
    assert!(matches!(
        validation::read_targeted_state_response(
            &ReadTargetedStateRequest {
                maximum_response_bytes: 1,
                ..request.clone()
            },
            &inconsistent,
        ),
        Err(ValidationError::TargetedStateResponseTooLarge { .. })
    ));

    let incomplete = TargetedStateReadCapability::default();
    assert_eq!(
        validation::targeted_state_read_request(&request, &incomplete),
        Err(ValidationError::Invalid("targeted state read limits"))
    );
}

#[test]
fn targeted_state_write_capability_is_closed_and_bounded() {
    let incomplete = TargetedStateWriteCapability::default();
    assert_eq!(
        validation::targeted_state_write_capability(&incomplete),
        Err(ValidationError::Invalid("targeted state write capability"))
    );

    let field = StateField {
        field: Some(Term {
            namespace: "dev.trakkin.state".to_owned(),
            name: "watched".to_owned(),
        }),
        unit: None,
    };
    let subject = SubjectReference {
        subject: Some(subject_reference::Subject::ProviderItemKey(key(
            "quiet-signal",
        ))),
    };
    let mut capability = TargetedStateWriteCapability {
        fields: vec![TargetedStateFieldWriteCapability {
            field: Some(field.clone()),
            set_supported: true,
            clear_supported: true,
        }],
        may_create_source_membership: true,
        precondition_mode: TargetedStateWritePreconditionMode::ProviderToken as i32,
        idempotency_mode: TargetedStateWriteIdempotencyMode::StableKey as i32,
        maximum_fields: 1,
        maximum_request_bytes: 4096,
        maximum_response_bytes: 4096,
        maximum_receipt_bytes: 64,
    };
    validation::targeted_state_write_capability(&capability).unwrap();

    let request = WriteTargetedStateRequest {
        operation_id: b"targeted-write-1".to_vec(),
        source_key: Some(key("receiving-list")),
        subject: Some(subject),
        idempotency_key: b"sync-action-empty".to_vec(),
        expected_membership: SourceMembership::Absent as i32,
        precondition: b"expected-absent-r1".to_vec(),
        allow_create_membership: true,
        intents: vec![TargetedStateWriteIntent {
            field: Some(field.clone()),
            operation: Some(targeted_state_write_intent::Operation::Set(Value {
                value: Some(value::Value::Boolean(true)),
            })),
        }],
        maximum_receipt_bytes: 64,
        maximum_response_bytes: 4096,
    };
    capability.maximum_request_bytes = request.encoded_len() as u64;
    validation::targeted_state_write_request(&request, &capability).unwrap();

    let mut one_byte_too_small = capability.clone();
    one_byte_too_small.maximum_request_bytes -= 1;
    assert!(matches!(
        validation::targeted_state_write_request(&request, &one_byte_too_small),
        Err(ValidationError::TargetedStateWriteRequestTooLarge { .. })
    ));

    let mut too_many_fields = request.clone();
    too_many_fields.intents.push(TargetedStateWriteIntent {
        field: Some(StateField {
            field: Some(Term {
                namespace: "dev.trakkin.state".to_owned(),
                name: "completed".to_owned(),
            }),
            unit: None,
        }),
        operation: Some(targeted_state_write_intent::Operation::Clear(
            TargetedStateClear {},
        )),
    });
    assert_eq!(
        validation::targeted_state_write_request(&too_many_fields, &capability),
        Err(ValidationError::Invalid("targeted state write field limit"))
    );

    let mut clear_request = request.clone();
    clear_request.expected_membership = SourceMembership::Present as i32;
    clear_request.allow_create_membership = false;
    clear_request.intents[0].operation = Some(targeted_state_write_intent::Operation::Clear(
        TargetedStateClear {},
    ));
    capability.maximum_request_bytes = clear_request.encoded_len() as u64;
    validation::targeted_state_write_request(&clear_request, &capability).unwrap();

    let mut set_only = capability.clone();
    set_only.fields[0].clear_supported = false;
    assert_eq!(
        validation::targeted_state_write_request(&clear_request, &set_only),
        Err(ValidationError::Invalid(
            "targeted state write clear capability"
        ))
    );
    let mut clear_only = capability;
    clear_only.fields[0].set_supported = false;
    assert_eq!(
        validation::targeted_state_write_request(&request, &clear_only),
        Err(ValidationError::Invalid(
            "targeted state write set capability"
        ))
    );
}

#[test]
fn targeted_state_write_outcomes_accept_only_valid_status_certainty_retry_combinations() {
    let field = StateField {
        field: Some(Term {
            namespace: "dev.trakkin.state".to_owned(),
            name: "watched".to_owned(),
        }),
        unit: None,
    };
    let request = WriteTargetedStateRequest {
        operation_id: b"targeted-write-1".to_vec(),
        source_key: Some(key("receiving-list")),
        subject: Some(SubjectReference {
            subject: Some(subject_reference::Subject::ProviderItemKey(key(
                "quiet-signal",
            ))),
        }),
        idempotency_key: b"sync-action-empty".to_vec(),
        expected_membership: SourceMembership::Absent as i32,
        precondition: b"expected-absent-r1".to_vec(),
        allow_create_membership: true,
        intents: vec![TargetedStateWriteIntent {
            field: Some(field.clone()),
            operation: Some(targeted_state_write_intent::Operation::Set(Value {
                value: Some(value::Value::Boolean(true)),
            })),
        }],
        maximum_receipt_bytes: 64,
        maximum_response_bytes: 4096,
    };
    let capability = TargetedStateWriteCapability {
        fields: vec![TargetedStateFieldWriteCapability {
            field: Some(field.clone()),
            set_supported: true,
            clear_supported: true,
        }],
        may_create_source_membership: true,
        precondition_mode: TargetedStateWritePreconditionMode::ProviderToken as i32,
        idempotency_mode: TargetedStateWriteIdempotencyMode::StableKey as i32,
        maximum_fields: 1,
        maximum_request_bytes: request.encoded_len() as u64,
        maximum_response_bytes: 4096,
        maximum_receipt_bytes: 64,
    };
    for (status, certainty, retry) in [
        (
            TargetedStateWriteStatus::Applied,
            TargetedStateWriteCertainty::ConfirmedApplied,
            TargetedStateWriteRetryDisposition::NotRetryable,
        ),
        (
            TargetedStateWriteStatus::NoOp,
            TargetedStateWriteCertainty::ConfirmedNotApplied,
            TargetedStateWriteRetryDisposition::NotRetryable,
        ),
        (
            TargetedStateWriteStatus::Rejected,
            TargetedStateWriteCertainty::ConfirmedNotApplied,
            TargetedStateWriteRetryDisposition::NotRetryable,
        ),
        (
            TargetedStateWriteStatus::Failed,
            TargetedStateWriteCertainty::ConfirmedNotApplied,
            TargetedStateWriteRetryDisposition::SafeSameKey,
        ),
        (
            TargetedStateWriteStatus::Failed,
            TargetedStateWriteCertainty::ConfirmedNotApplied,
            TargetedStateWriteRetryDisposition::NotRetryable,
        ),
        (
            TargetedStateWriteStatus::Indeterminate,
            TargetedStateWriteCertainty::Unknown,
            TargetedStateWriteRetryDisposition::ReconcileFirst,
        ),
    ] {
        let response = write_response(&field, status, certainty, retry);
        validation::targeted_state_write_response(&request, &capability, &response).unwrap();

        let mut contradictory = response;
        if contradictory.error.is_some() {
            contradictory.error = None;
        } else {
            contradictory.error = Some(AdapterError {
                code: "unexpected_error".to_owned(),
                safe_message: "the successful write returned an error".to_owned(),
                ..AdapterError::default()
            });
        }
        assert!(
            validation::targeted_state_write_response(&request, &capability, &contradictory)
                .is_err()
        );
    }

    let invalid = write_response(
        &field,
        TargetedStateWriteStatus::Applied,
        TargetedStateWriteCertainty::Unknown,
        TargetedStateWriteRetryDisposition::ReconcileFirst,
    );
    assert_eq!(
        validation::targeted_state_write_response(&request, &capability, &invalid),
        Err(ValidationError::Invalid(
            "targeted state write outcome combination"
        ))
    );

    let mut oversized_receipt = write_response(
        &field,
        TargetedStateWriteStatus::Applied,
        TargetedStateWriteCertainty::ConfirmedApplied,
        TargetedStateWriteRetryDisposition::NotRetryable,
    );
    oversized_receipt.receipt = vec![0; 65];
    assert!(matches!(
        validation::targeted_state_write_response(&request, &capability, &oversized_receipt),
        Err(ValidationError::TargetedStateWriteReceiptTooLarge { .. })
    ));

    let mut oversized_response = write_response(
        &field,
        TargetedStateWriteStatus::Applied,
        TargetedStateWriteCertainty::ConfirmedApplied,
        TargetedStateWriteRetryDisposition::NotRetryable,
    );
    oversized_response.provider_revision = vec![0; 4096];
    assert!(matches!(
        validation::targeted_state_write_response(&request, &capability, &oversized_response),
        Err(ValidationError::TargetedStateWriteResponseTooLarge { .. })
    ));
}

fn write_response(
    field: &StateField,
    status: TargetedStateWriteStatus,
    certainty: TargetedStateWriteCertainty,
    retry: TargetedStateWriteRetryDisposition,
) -> WriteTargetedStateResponse {
    let (membership_effect, field_effects, provider_revision, successor_precondition, receipt) =
        match status {
            TargetedStateWriteStatus::Applied => (
                TargetedStateMembershipEffect::Created,
                vec![TargetedStateWriteFieldEffect {
                    field: Some(field.clone()),
                    effect: TargetedStateFieldEffectKind::Set as i32,
                    value: Some(Value {
                        value: Some(value::Value::Boolean(true)),
                    }),
                }],
                b"provider-r2".to_vec(),
                b"state-token-r2".to_vec(),
                b"receipt-r1".to_vec(),
            ),
            TargetedStateWriteStatus::NoOp => (
                TargetedStateMembershipEffect::Unchanged,
                vec![TargetedStateWriteFieldEffect {
                    field: Some(field.clone()),
                    effect: TargetedStateFieldEffectKind::Unchanged as i32,
                    value: None,
                }],
                b"provider-r1".to_vec(),
                b"expected-absent-r1".to_vec(),
                Vec::new(),
            ),
            TargetedStateWriteStatus::Rejected | TargetedStateWriteStatus::Failed => (
                TargetedStateMembershipEffect::Unchanged,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            TargetedStateWriteStatus::Indeterminate => (
                TargetedStateMembershipEffect::Unknown,
                vec![TargetedStateWriteFieldEffect {
                    field: Some(field.clone()),
                    effect: TargetedStateFieldEffectKind::Unknown as i32,
                    value: None,
                }],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            TargetedStateWriteStatus::Unspecified => unreachable!(),
        };
    let error = matches!(
        status,
        TargetedStateWriteStatus::Rejected
            | TargetedStateWriteStatus::Failed
            | TargetedStateWriteStatus::Indeterminate
    )
    .then(|| crate::v1::AdapterError {
        code: "fixture_write_outcome".to_owned(),
        safe_message: "fixture targeted write outcome".to_owned(),
        retryable: status != TargetedStateWriteStatus::Rejected,
        ..Default::default()
    });
    WriteTargetedStateResponse {
        status: status as i32,
        certainty: certainty as i32,
        retry_disposition: retry as i32,
        membership_effect: membership_effect as i32,
        field_effects,
        provider_revision,
        successor_precondition,
        receipt,
        error,
    }
}
