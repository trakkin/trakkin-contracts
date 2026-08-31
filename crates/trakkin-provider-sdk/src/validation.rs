use std::collections::HashSet;

use prost::Message;
use sha2::{Digest, Sha256};
use trakkin_mapping::PortableEndpoint as MappingEndpoint;

use crate::v1::{
    AccountSnapshot, AdapterError, AuthenticationPrompt, AuthenticationStatus,
    CancelAuthenticationResponse, CancelOperationResponse, CatalogBatch,
    ContinueAuthenticationResponse, CoordinateBacking, CoordinateBinding, CoordinateBindingKey,
    DescribeConnectionResponse, DiscoverSourcesResponse, EndpointLookupCandidate, HealthResponse,
    HealthStatus, Key, ListAuthenticationMethodsResponse, LookupCandidate,
    LookupPortableReferencesResponse, OpenConnectionResponse, PortableEndpoint, PortableReference,
    ProviderItem, ReadAssetResponse, ReadCatalogRequest, ReadCatalogResponse, ReadCompleted,
    ReadFailed, ReadHeartbeat, ReadMode, ReadStateRequest, ReadStateResponse,
    ReadTargetedStateRequest, ReadTargetedStateResponse, ResolvePortableEndpointsRequest,
    ResolvePortableEndpointsResponse, SourceCapabilities, SourceMembership, SourceSnapshot,
    StartAuthenticationResponse, StateBatch, StateField, StateFieldDescriptor, StateFieldQuantizer,
    StatePresence, SubjectReference, TargetedStateFieldEffectKind, TargetedStateMembershipEffect,
    TargetedStateReadCapability, TargetedStateWriteCapability, TargetedStateWriteCertainty,
    TargetedStateWriteIdempotencyMode, TargetedStateWritePreconditionMode,
    TargetedStateWriteRetryDisposition, TargetedStateWriteStatus, Term, ValidateConnectionResponse,
    WriteTargetedStateRequest, WriteTargetedStateResponse, cancel_authentication_response,
    cancel_operation_response, describe_connection_response, discover_sources_response,
    list_authentication_methods_response, lookup_portable_references_response,
    open_connection_response, portable_endpoint_resolution, portable_reference_lookup_result,
    read_asset_response, read_catalog_response, read_state_response, read_targeted_state_response,
    resolve_portable_endpoints_response, subject_reference, targeted_state_write_intent,
    validate_connection_response,
};

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ValidationError {
    #[error("{0} is missing")]
    Missing(&'static str),
    #[error("{0} must not be empty")]
    Empty(&'static str),
    #[error("{0} is invalid")]
    Invalid(&'static str),
    #[error("stream batch sequence {actual} does not match expected {expected}")]
    InvalidSequence { expected: u64, actual: u64 },
    #[error("stream emitted an event after its terminal event")]
    EventAfterTerminal,
    #[error("stream ended without a terminal event")]
    MissingTerminal,
    #[error("lookup result count does not match the request")]
    LookupResultCount,
    #[error("lookup result does not match its requested reference")]
    LookupReferenceMismatch,
    #[error("endpoint result count does not match the request")]
    EndpointResultCount,
    #[error("endpoint result does not match its requested endpoint")]
    EndpointMismatch,
    #[error("endpoint response length {actual} exceeds maximum {maximum}")]
    EndpointResponseTooLarge { actual: usize, maximum: u64 },
    #[error("targeted state field count does not match the request")]
    TargetedStateFieldCount,
    #[error("targeted state field does not match its requested field")]
    TargetedStateFieldMismatch,
    #[error("targeted state response length {actual} exceeds maximum {maximum}")]
    TargetedStateResponseTooLarge { actual: usize, maximum: u64 },
    #[error("targeted state write request length {actual} exceeds maximum {maximum}")]
    TargetedStateWriteRequestTooLarge { actual: usize, maximum: u64 },
    #[error("targeted state write field count does not match the request")]
    TargetedStateWriteFieldCount,
    #[error("targeted state write field does not match its requested field")]
    TargetedStateWriteFieldMismatch,
    #[error("targeted state write response length {actual} exceeds maximum {maximum}")]
    TargetedStateWriteResponseTooLarge { actual: usize, maximum: u64 },
    #[error("targeted state write receipt length {actual} exceeds maximum {maximum}")]
    TargetedStateWriteReceiptTooLarge { actual: usize, maximum: u64 },
    #[error("ambiguous lookup must return at least two candidates")]
    InsufficientCandidates,
    #[error("adapter error response contains successful payload data")]
    ErrorWithPayload,
    #[error("asset content length {actual} exceeds maximum {maximum}")]
    AssetTooLarge { actual: usize, maximum: u64 },
    #[error("asset full length does not match returned content")]
    AssetLengthMismatch,
    #[error("asset content type is not allowed")]
    AssetContentType,
    #[error("asset SHA-256 hash is invalid")]
    AssetHash,
    #[error("duplicate {0}")]
    Duplicate(&'static str),
    #[error("source refers to an account not returned by the open connection")]
    UnknownAccount,
}

pub fn key(key: &Key, field: &'static str) -> Result<(), ValidationError> {
    non_empty_text(&key.namespace, field)?;
    if key.value.is_empty() {
        return Err(ValidationError::Empty(field));
    }
    Ok(())
}

pub fn term(term: &Term, field: &'static str) -> Result<(), ValidationError> {
    non_empty_text(&term.namespace, field)?;
    non_empty_text(&term.name, field)
}

pub fn portable_reference(
    reference: &PortableReference,
    field: &'static str,
) -> Result<(), ValidationError> {
    non_empty_text(&reference.namespace, field)?;
    if reference.value.is_empty() {
        return Err(ValidationError::Empty(field));
    }
    Ok(())
}

pub fn portable_endpoint(
    endpoint: &PortableEndpoint,
    field: &'static str,
) -> Result<(), ValidationError> {
    let reference = endpoint
        .reference
        .as_ref()
        .ok_or(ValidationError::Missing(field))?;
    portable_reference(reference, field)?;
    if endpoint.selector.is_empty() {
        return Err(ValidationError::Empty(field));
    }
    let parsed = MappingEndpoint::from_parts(
        &reference.namespace,
        &reference.value,
        Some(&endpoint.selector),
    )
    .map_err(|_| ValidationError::Invalid(field))?;
    if parsed.selector().map(|selector| selector.as_str()) != Some(endpoint.selector.as_str()) {
        return Err(ValidationError::Invalid(field));
    }
    Ok(())
}

pub fn adapter_error(error: &AdapterError) -> Result<(), ValidationError> {
    non_empty_text(&error.code, "adapter error code")?;
    non_empty_text(&error.safe_message, "adapter safe message")?;
    if error.safe_message.len() > 2048 || error.safe_message.chars().any(char::is_control) {
        return Err(ValidationError::Invalid("adapter safe message"));
    }
    for problem in &error.field_problems {
        non_empty_text(&problem.path, "field problem path")?;
        non_empty_text(&problem.code, "field problem code")?;
        non_empty_text(&problem.message, "field problem message")?;
    }
    Ok(())
}

pub fn health_response(response: &HealthResponse) -> Result<(), ValidationError> {
    let status = HealthStatus::try_from(response.status)
        .map_err(|_| ValidationError::Invalid("health status"))?;
    match (status, response.error.as_ref()) {
        (HealthStatus::Ready, None) => Ok(()),
        (HealthStatus::Ready, Some(_)) => Err(ValidationError::ErrorWithPayload),
        (HealthStatus::Degraded | HealthStatus::NotReady, Some(error)) => adapter_error(error),
        (HealthStatus::Degraded | HealthStatus::NotReady, None) => {
            Err(ValidationError::Missing("health error"))
        }
        (HealthStatus::Unspecified, _) => Err(ValidationError::Invalid("health status")),
    }
}

pub fn cancel_authentication_response(
    response: &CancelAuthenticationResponse,
) -> Result<(), ValidationError> {
    match response.outcome.as_ref() {
        Some(cancel_authentication_response::Outcome::Result(_)) => Ok(()),
        Some(cancel_authentication_response::Outcome::Error(error)) => adapter_error(error),
        None => Err(ValidationError::Missing(
            "authentication cancellation outcome",
        )),
    }
}

pub fn cancel_operation_response(
    response: &CancelOperationResponse,
) -> Result<(), ValidationError> {
    match response.outcome.as_ref() {
        Some(cancel_operation_response::Outcome::Result(_)) => Ok(()),
        Some(cancel_operation_response::Outcome::Error(error)) => adapter_error(error),
        None => Err(ValidationError::Missing("operation cancellation outcome")),
    }
}

pub fn describe_connection_response(
    response: &DescribeConnectionResponse,
) -> Result<(), ValidationError> {
    match response.outcome.as_ref() {
        Some(describe_connection_response::Outcome::Result(_)) => Ok(()),
        Some(describe_connection_response::Outcome::Error(error)) => adapter_error(error),
        None => Err(ValidationError::Missing("connection description outcome")),
    }
}

pub fn validate_connection_response(
    response: &ValidateConnectionResponse,
) -> Result<(), ValidationError> {
    match response.outcome.as_ref() {
        Some(validate_connection_response::Outcome::Result(_)) => Ok(()),
        Some(validate_connection_response::Outcome::Error(error)) => adapter_error(error),
        None => Err(ValidationError::Missing("connection validation outcome")),
    }
}

pub fn list_authentication_methods_response(
    response: &ListAuthenticationMethodsResponse,
) -> Result<(), ValidationError> {
    match response.outcome.as_ref() {
        Some(list_authentication_methods_response::Outcome::Result(_)) => Ok(()),
        Some(list_authentication_methods_response::Outcome::Error(error)) => adapter_error(error),
        None => Err(ValidationError::Missing("authentication methods outcome")),
    }
}

pub fn source_capabilities(capabilities: &SourceCapabilities) -> Result<(), ValidationError> {
    if let Some(catalog) = &capabilities.catalog
        && !catalog.full
        && !catalog.incremental
    {
        return Err(ValidationError::Invalid("catalog read capability"));
    }
    if let Some(state) = &capabilities.state
        && !state.full
        && !state.incremental
    {
        return Err(ValidationError::Invalid("state read capability"));
    }
    for field in &capabilities.state_fields {
        state_field_descriptor(field)?;
    }
    if let Some(assets) = &capabilities.assets {
        if assets.maximum_bytes == 0 {
            return Err(ValidationError::Invalid("asset maximum bytes"));
        }
        let mut content_types = HashSet::new();
        for content_type in &assets.content_types {
            non_empty_text(content_type, "asset content type")?;
            if !content_types.insert(content_type) {
                return Err(ValidationError::Duplicate("asset content type"));
            }
        }
    }
    if let Some(coordinates) = &capabilities.coordinates {
        validate_coordinate_ids(&coordinates.coordinate_ids, "source coordinate ID")?;
    }
    if let Some(targeted) = &capabilities.targeted_state_read {
        targeted_state_read_capability(targeted)?;
    }
    if let Some(targeted) = &capabilities.targeted_state_write {
        targeted_state_write_capability(targeted)?;
    }
    Ok(())
}

pub fn state_field_descriptor(descriptor: &StateFieldDescriptor) -> Result<(), ValidationError> {
    term(
        descriptor
            .field
            .as_ref()
            .ok_or(ValidationError::Missing("state field descriptor field"))?,
        "state field descriptor field",
    )?;
    if let Some(unit) = &descriptor.unit {
        term(unit, "state field descriptor unit")?;
    }
    let quantizer = StateFieldQuantizer::try_from(descriptor.quantizer)
        .map_err(|_| ValidationError::Invalid("state field quantizer"))?;
    match (&descriptor.numeric_range, quantizer) {
        (None, StateFieldQuantizer::Unspecified) => Ok(()),
        (Some(range), quantizer) if quantizer != StateFieldQuantizer::Unspecified => {
            non_empty_text(&range.minimum, "state field numeric minimum")?;
            non_empty_text(&range.maximum, "state field numeric maximum")?;
            non_empty_text(&range.step, "state field numeric step")
        }
        _ => Err(ValidationError::Invalid(
            "state field numeric range and quantizer",
        )),
    }
}

pub fn targeted_state_read_capability(
    capability: &TargetedStateReadCapability,
) -> Result<(), ValidationError> {
    if capability.maximum_fields == 0 || capability.maximum_response_bytes == 0 {
        return Err(ValidationError::Invalid("targeted state read limits"));
    }
    Ok(())
}

pub fn targeted_state_write_capability(
    capability: &TargetedStateWriteCapability,
) -> Result<(), ValidationError> {
    let precondition_mode =
        TargetedStateWritePreconditionMode::try_from(capability.precondition_mode)
            .map_err(|_| ValidationError::Invalid("targeted state write precondition mode"))?;
    let idempotency_mode = TargetedStateWriteIdempotencyMode::try_from(capability.idempotency_mode)
        .map_err(|_| ValidationError::Invalid("targeted state write idempotency mode"))?;
    if capability.fields.is_empty()
        || precondition_mode == TargetedStateWritePreconditionMode::Unspecified
        || idempotency_mode == TargetedStateWriteIdempotencyMode::Unspecified
        || capability.maximum_fields == 0
        || capability.maximum_request_bytes == 0
        || capability.maximum_response_bytes == 0
        || capability.maximum_receipt_bytes == 0
        || capability.maximum_receipt_bytes > capability.maximum_response_bytes
    {
        return Err(ValidationError::Invalid("targeted state write capability"));
    }
    let mut fields = HashSet::new();
    for field_capability in &capability.fields {
        let field = field_capability
            .field
            .as_ref()
            .ok_or(ValidationError::Missing(
                "targeted state write capability field",
            ))?;
        validate_state_field(field)?;
        if !field_capability.set_supported && !field_capability.clear_supported {
            return Err(ValidationError::Invalid(
                "targeted state write field capability",
            ));
        }
        if !fields.insert(field.encode_to_vec()) {
            return Err(ValidationError::Duplicate(
                "targeted state write capability field",
            ));
        }
    }
    Ok(())
}

pub fn start_authentication_response(
    response: &StartAuthenticationResponse,
) -> Result<(), ValidationError> {
    authentication_response(
        &response.authentication_id,
        response.status,
        response.prompt.as_ref(),
        &response.accounts,
        response.error.as_ref(),
    )
}

pub fn continue_authentication_response(
    response: &ContinueAuthenticationResponse,
) -> Result<(), ValidationError> {
    authentication_response(
        &response.authentication_id,
        response.status,
        response.prompt.as_ref(),
        &response.accounts,
        response.error.as_ref(),
    )
}

fn authentication_response(
    authentication_id: &str,
    status: i32,
    prompt: Option<&AuthenticationPrompt>,
    accounts: &[AccountSnapshot],
    error: Option<&AdapterError>,
) -> Result<(), ValidationError> {
    non_empty_text(authentication_id, "authentication ID")?;
    let status = AuthenticationStatus::try_from(status)
        .map_err(|_| ValidationError::Invalid("authentication status"))?;
    if status == AuthenticationStatus::Unspecified {
        return Err(ValidationError::Invalid("authentication status"));
    }
    for account in accounts {
        account_snapshot(account)?;
    }
    if let Some(error) = error {
        adapter_error(error)?;
        if status != AuthenticationStatus::Failed {
            return Err(ValidationError::ErrorWithPayload);
        }
    } else if status == AuthenticationStatus::Failed {
        return Err(ValidationError::Missing("authentication failure error"));
    }
    if status == AuthenticationStatus::InputRequired && prompt.is_none() {
        return Err(ValidationError::Missing("authentication prompt"));
    }
    Ok(())
}

pub fn open_connection_response(response: &OpenConnectionResponse) -> Result<(), ValidationError> {
    let result = match response.outcome.as_ref() {
        Some(open_connection_response::Outcome::Result(result)) => result,
        Some(open_connection_response::Outcome::Error(error)) => return adapter_error(error),
        None => return Err(ValidationError::Missing("open connection outcome")),
    };

    let mut account_keys = HashSet::new();
    for account in &result.accounts {
        account_snapshot(account)?;
        if !account_keys.insert(account.key.as_ref().expect("validated key")) {
            return Err(ValidationError::Duplicate("account key"));
        }
    }
    if let Some(capabilities) = &result.capabilities
        && let Some(lookup) = &capabilities.reference_lookup
    {
        if lookup.maximum_batch_size == 0 || lookup.reference_namespaces.is_empty() {
            return Err(ValidationError::Invalid("lookup capability"));
        }
        let mut namespaces = HashSet::new();
        for namespace in &lookup.reference_namespaces {
            non_empty_text(namespace, "lookup reference namespace")?;
            if !namespaces.insert(namespace) {
                return Err(ValidationError::Duplicate("lookup reference namespace"));
            }
        }
    }
    if let Some(capabilities) = &result.capabilities
        && let Some(lookup) = &capabilities.endpoint_lookup
    {
        if lookup.maximum_batch_size == 0
            || lookup.maximum_response_bytes == 0
            || lookup.reference_namespaces.is_empty()
            || lookup.coordinate_ids.is_empty()
        {
            return Err(ValidationError::Invalid("endpoint lookup capability"));
        }
        validate_unique_text(
            &lookup.reference_namespaces,
            "endpoint lookup reference namespace",
        )?;
        validate_coordinate_ids(&lookup.coordinate_ids, "endpoint lookup coordinate ID")?;
    }
    Ok(())
}

pub fn discover_sources_response(
    account_keys: &[Key],
    response: &DiscoverSourcesResponse,
) -> Result<(), ValidationError> {
    let result = match response.outcome.as_ref() {
        Some(discover_sources_response::Outcome::Result(result)) => result,
        Some(discover_sources_response::Outcome::Error(error)) => return adapter_error(error),
        None => return Err(ValidationError::Missing("source discovery outcome")),
    };

    let accounts = account_keys.iter().collect::<HashSet<_>>();
    let mut source_keys = HashSet::new();
    for source in &result.sources {
        source_snapshot(source)?;
        if !accounts.contains(source.account_key.as_ref().expect("validated account key")) {
            return Err(ValidationError::UnknownAccount);
        }
        if !source_keys.insert(source.key.as_ref().expect("validated source key")) {
            return Err(ValidationError::Duplicate("source key"));
        }
    }
    Ok(())
}

pub fn read_catalog_request(request: &ReadCatalogRequest) -> Result<(), ValidationError> {
    read_request(
        &request.operation_id,
        request.source_key.as_ref(),
        request.mode,
        &request.prior_cursor,
        request.preferred_batch_size,
    )
}

pub fn read_state_request(request: &ReadStateRequest) -> Result<(), ValidationError> {
    read_request(
        &request.operation_id,
        request.source_key.as_ref(),
        request.mode,
        &request.prior_cursor,
        request.preferred_batch_size,
    )
}

fn read_request(
    operation_id: &[u8],
    source_key: Option<&Key>,
    mode: i32,
    prior_cursor: &[u8],
    preferred_batch_size: u32,
) -> Result<(), ValidationError> {
    if operation_id.is_empty() {
        return Err(ValidationError::Empty("read operation ID"));
    }
    key(
        source_key.ok_or(ValidationError::Missing("read source key"))?,
        "read source key",
    )?;
    if preferred_batch_size == 0 {
        return Err(ValidationError::Invalid("preferred batch size"));
    }
    match ReadMode::try_from(mode).map_err(|_| ValidationError::Invalid("read mode"))? {
        ReadMode::Full if prior_cursor.is_empty() => Ok(()),
        ReadMode::Incremental if !prior_cursor.is_empty() => Ok(()),
        ReadMode::Full | ReadMode::Incremental | ReadMode::Unspecified => {
            Err(ValidationError::Invalid("read mode cursor"))
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct CatalogStreamValidator {
    next_sequence: u64,
    terminal: bool,
}

impl CatalogStreamValidator {
    pub fn accept(&mut self, event: &ReadCatalogResponse) -> Result<(), ValidationError> {
        if self.terminal {
            return Err(ValidationError::EventAfterTerminal);
        }
        match event
            .event
            .as_ref()
            .ok_or(ValidationError::Missing("catalog read event"))?
        {
            read_catalog_response::Event::Heartbeat(heartbeat) => validate_heartbeat(heartbeat),
            read_catalog_response::Event::Batch(batch) => {
                validate_catalog_batch(batch, self.next_sequence)?;
                self.next_sequence += 1;
                Ok(())
            }
            read_catalog_response::Event::Completed(completed) => {
                validate_completed(completed)?;
                self.terminal = true;
                Ok(())
            }
            read_catalog_response::Event::Failed(failed) => {
                validate_failed(failed)?;
                self.terminal = true;
                Ok(())
            }
            read_catalog_response::Event::Cancelled(_) => {
                self.terminal = true;
                Ok(())
            }
        }
    }

    pub fn finish(self) -> Result<(), ValidationError> {
        if self.terminal {
            Ok(())
        } else {
            Err(ValidationError::MissingTerminal)
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct StateStreamValidator {
    next_sequence: u64,
    terminal: bool,
}

impl StateStreamValidator {
    pub fn accept(&mut self, event: &ReadStateResponse) -> Result<(), ValidationError> {
        if self.terminal {
            return Err(ValidationError::EventAfterTerminal);
        }
        match event
            .event
            .as_ref()
            .ok_or(ValidationError::Missing("state read event"))?
        {
            read_state_response::Event::Heartbeat(heartbeat) => validate_heartbeat(heartbeat),
            read_state_response::Event::Batch(batch) => {
                validate_state_batch(batch, self.next_sequence)?;
                self.next_sequence += 1;
                Ok(())
            }
            read_state_response::Event::Completed(completed) => {
                validate_completed(completed)?;
                self.terminal = true;
                Ok(())
            }
            read_state_response::Event::Failed(failed) => {
                validate_failed(failed)?;
                self.terminal = true;
                Ok(())
            }
            read_state_response::Event::Cancelled(_) => {
                self.terminal = true;
                Ok(())
            }
        }
    }

    pub fn finish(self) -> Result<(), ValidationError> {
        if self.terminal {
            Ok(())
        } else {
            Err(ValidationError::MissingTerminal)
        }
    }
}

pub fn lookup_response(
    request: &[PortableReference],
    response: &LookupPortableReferencesResponse,
) -> Result<(), ValidationError> {
    let result = match response.outcome.as_ref() {
        Some(lookup_portable_references_response::Outcome::Result(result)) => result,
        Some(lookup_portable_references_response::Outcome::Error(error)) => {
            return adapter_error(error);
        }
        None => {
            return Err(ValidationError::Missing(
                "portable reference lookup outcome",
            ));
        }
    };
    if request.len() != result.results.len() {
        return Err(ValidationError::LookupResultCount);
    }
    for (requested, result) in request.iter().zip(&result.results) {
        portable_reference(requested, "lookup request reference")?;
        let echoed = result
            .requested
            .as_ref()
            .ok_or(ValidationError::Missing("lookup result reference"))?;
        portable_reference(echoed, "lookup result reference")?;
        if echoed != requested {
            return Err(ValidationError::LookupReferenceMismatch);
        }
        match result
            .outcome
            .as_ref()
            .ok_or(ValidationError::Missing("lookup outcome"))?
        {
            portable_reference_lookup_result::Outcome::Matched(matched) => {
                validate_candidate(
                    matched
                        .candidate
                        .as_ref()
                        .ok_or(ValidationError::Missing("matched lookup candidate"))?,
                )?;
            }
            portable_reference_lookup_result::Outcome::NotFound(_)
            | portable_reference_lookup_result::Outcome::Unsupported(_) => {}
            portable_reference_lookup_result::Outcome::Ambiguous(ambiguous) => {
                if ambiguous.candidates.len() < 2 {
                    return Err(ValidationError::InsufficientCandidates);
                }
                for candidate in &ambiguous.candidates {
                    validate_candidate(candidate)?;
                }
            }
        }
    }
    Ok(())
}

pub fn resolve_endpoints_request(
    request: &ResolvePortableEndpointsRequest,
) -> Result<(), ValidationError> {
    if request.operation_id.is_empty() {
        return Err(ValidationError::Empty("endpoint resolution operation ID"));
    }
    if request.endpoints.is_empty() {
        return Err(ValidationError::Empty("endpoint resolution request"));
    }
    if request.maximum_response_bytes == 0 {
        return Err(ValidationError::Invalid(
            "endpoint resolution maximum response bytes",
        ));
    }
    let mut endpoints = HashSet::new();
    for endpoint in &request.endpoints {
        portable_endpoint(endpoint, "endpoint resolution request endpoint")?;
        if !endpoints.insert(endpoint) {
            return Err(ValidationError::Duplicate(
                "endpoint resolution request endpoint",
            ));
        }
    }
    Ok(())
}

pub fn resolve_endpoints_response(
    request: &[PortableEndpoint],
    response: &ResolvePortableEndpointsResponse,
    maximum_response_bytes: u64,
) -> Result<(), ValidationError> {
    let encoded_length = response.encoded_len();
    if encoded_length as u64 > maximum_response_bytes {
        return Err(ValidationError::EndpointResponseTooLarge {
            actual: encoded_length,
            maximum: maximum_response_bytes,
        });
    }
    let result = match response.outcome.as_ref() {
        Some(resolve_portable_endpoints_response::Outcome::Result(result)) => result,
        Some(resolve_portable_endpoints_response::Outcome::Error(error)) => {
            return adapter_error(error);
        }
        None => return Err(ValidationError::Missing("endpoint resolution outcome")),
    };
    if request.len() != result.results.len() {
        return Err(ValidationError::EndpointResultCount);
    }
    for (requested, result) in request.iter().zip(&result.results) {
        portable_endpoint(requested, "requested endpoint")?;
        let echoed = result
            .requested
            .as_ref()
            .ok_or(ValidationError::Missing("endpoint result request"))?;
        portable_endpoint(echoed, "endpoint result request")?;
        if echoed != requested {
            return Err(ValidationError::EndpointMismatch);
        }
        match result
            .outcome
            .as_ref()
            .ok_or(ValidationError::Missing("endpoint resolution outcome"))?
        {
            portable_endpoint_resolution::Outcome::Matched(matched) => {
                validate_endpoint_candidate(
                    matched
                        .candidate
                        .as_ref()
                        .ok_or(ValidationError::Missing("matched endpoint candidate"))?,
                    requested,
                )?;
            }
            portable_endpoint_resolution::Outcome::NotFound(_)
            | portable_endpoint_resolution::Outcome::Unsupported(_) => {}
            portable_endpoint_resolution::Outcome::Ambiguous(ambiguous) => {
                if ambiguous.candidates.len() < 2 {
                    return Err(ValidationError::InsufficientCandidates);
                }
                for candidate in &ambiguous.candidates {
                    validate_endpoint_candidate(candidate, requested)?;
                }
            }
        }
    }
    Ok(())
}

pub fn targeted_state_read_request(
    request: &ReadTargetedStateRequest,
    capability: &TargetedStateReadCapability,
) -> Result<(), ValidationError> {
    targeted_state_read_capability(capability)?;
    if request.operation_id.is_empty() {
        return Err(ValidationError::Empty("targeted state read operation ID"));
    }
    key(
        request
            .source_key
            .as_ref()
            .ok_or(ValidationError::Missing("targeted state read source key"))?,
        "targeted state read source key",
    )?;
    validate_subject(
        request
            .subject
            .as_ref()
            .ok_or(ValidationError::Missing("targeted state read subject"))?,
    )?;
    if request.fields.is_empty() {
        return Err(ValidationError::Empty("targeted state read fields"));
    }
    if request.fields.len() > capability.maximum_fields as usize {
        return Err(ValidationError::Invalid("targeted state read field limit"));
    }
    if request.maximum_response_bytes == 0
        || request.maximum_response_bytes > capability.maximum_response_bytes
    {
        return Err(ValidationError::Invalid(
            "targeted state read response limit",
        ));
    }
    if !request.reconciliation_idempotency_key.is_empty()
        && request.reconciliation_idempotency_key.len() != 16
    {
        return Err(ValidationError::Invalid(
            "targeted state reconciliation idempotency key",
        ));
    }
    let mut fields = HashSet::new();
    for field in &request.fields {
        validate_state_field(field)?;
        if !fields.insert(field.encode_to_vec()) {
            return Err(ValidationError::Duplicate("targeted state read field"));
        }
    }
    Ok(())
}

pub fn read_targeted_state_response(
    request: &ReadTargetedStateRequest,
    response: &ReadTargetedStateResponse,
) -> Result<(), ValidationError> {
    let encoded_length = response.encoded_len();
    if encoded_length as u64 > request.maximum_response_bytes {
        return Err(ValidationError::TargetedStateResponseTooLarge {
            actual: encoded_length,
            maximum: request.maximum_response_bytes,
        });
    }
    match response
        .outcome
        .as_ref()
        .ok_or(ValidationError::Missing("targeted state read outcome"))?
    {
        read_targeted_state_response::Outcome::Matched(matched) => {
            let membership = SourceMembership::try_from(matched.membership)
                .map_err(|_| ValidationError::Invalid("targeted state membership"))?;
            if membership == SourceMembership::Unspecified {
                return Err(ValidationError::Invalid("targeted state membership"));
            }
            if matched.fields.len() != request.fields.len() {
                return Err(ValidationError::TargetedStateFieldCount);
            }
            for (requested, observation) in request.fields.iter().zip(&matched.fields) {
                let field = observation
                    .field
                    .as_ref()
                    .ok_or(ValidationError::Missing("targeted state field"))?;
                validate_state_field(field)?;
                if field != requested {
                    return Err(ValidationError::TargetedStateFieldMismatch);
                }
                let presence = StatePresence::try_from(observation.presence)
                    .map_err(|_| ValidationError::Invalid("targeted state presence"))?;
                if presence == StatePresence::Unspecified {
                    return Err(ValidationError::Invalid("targeted state presence"));
                }
                if (presence == StatePresence::Present) != observation.value.is_some() {
                    return Err(ValidationError::Invalid("targeted state presence value"));
                }
                if membership == SourceMembership::Absent && presence == StatePresence::Present {
                    return Err(ValidationError::Invalid(
                        "absent membership with present state",
                    ));
                }
                if observation
                    .value
                    .as_ref()
                    .is_some_and(|value| value.value.is_none())
                {
                    return Err(ValidationError::Missing("targeted state value"));
                }
            }
            if matched.provider_revision.is_empty() {
                return Err(ValidationError::Empty("targeted state provider revision"));
            }
            match (
                request.reconciliation_idempotency_key.as_slice(),
                matched.write_causation.as_ref(),
            ) {
                ([], None) => {}
                ([], Some(_)) => {
                    return Err(ValidationError::Invalid(
                        "unsolicited targeted state write causation",
                    ));
                }
                (_, Some(causation))
                    if causation.idempotency_key == request.reconciliation_idempotency_key
                        && !causation.receipt.is_empty()
                        && causation.provider_revision == matched.provider_revision => {}
                (_, Some(_)) => {
                    return Err(ValidationError::Invalid("targeted state write causation"));
                }
                (_, None) => {}
            }
            if matched
                .expires_time_milliseconds
                .is_some_and(|expires| expires <= matched.observed_time_milliseconds)
            {
                return Err(ValidationError::Invalid("targeted state expiry"));
            }
        }
        read_targeted_state_response::Outcome::Unsupported(_)
        | read_targeted_state_response::Outcome::NotFound(_) => {}
        read_targeted_state_response::Outcome::Ambiguous(ambiguous) => {
            if ambiguous.candidates.len() < 2 {
                return Err(ValidationError::InsufficientCandidates);
            }
            let mut candidates = HashSet::new();
            for candidate in &ambiguous.candidates {
                validate_subject(candidate)?;
                if !candidates.insert(candidate.encode_to_vec()) {
                    return Err(ValidationError::Duplicate(
                        "targeted state ambiguous candidate",
                    ));
                }
            }
        }
        read_targeted_state_response::Outcome::Indeterminate(indeterminate) => {
            adapter_error(
                indeterminate
                    .error
                    .as_ref()
                    .ok_or(ValidationError::Missing(
                        "targeted state indeterminate error",
                    ))?,
            )?;
        }
    }
    Ok(())
}

pub fn targeted_state_write_request(
    request: &WriteTargetedStateRequest,
    capability: &TargetedStateWriteCapability,
) -> Result<(), ValidationError> {
    targeted_state_write_capability(capability)?;
    if request.operation_id.is_empty() {
        return Err(ValidationError::Empty("targeted state write operation ID"));
    }
    key(
        request
            .source_key
            .as_ref()
            .ok_or(ValidationError::Missing("targeted state write source key"))?,
        "targeted state write source key",
    )?;
    validate_subject(
        request
            .subject
            .as_ref()
            .ok_or(ValidationError::Missing("targeted state write subject"))?,
    )?;
    if request.idempotency_key.is_empty() {
        return Err(ValidationError::Empty(
            "targeted state write idempotency key",
        ));
    }
    let expected_membership = SourceMembership::try_from(request.expected_membership)
        .map_err(|_| ValidationError::Invalid("targeted state write expected membership"))?;
    if !matches!(
        expected_membership,
        SourceMembership::Present | SourceMembership::Absent
    ) {
        return Err(ValidationError::Invalid(
            "targeted state write expected membership",
        ));
    }
    let precondition_mode =
        TargetedStateWritePreconditionMode::try_from(capability.precondition_mode)
            .map_err(|_| ValidationError::Invalid("targeted state write precondition mode"))?;
    match precondition_mode {
        TargetedStateWritePreconditionMode::ProviderToken if request.precondition.is_empty() => {
            return Err(ValidationError::Empty("targeted state write precondition"));
        }
        TargetedStateWritePreconditionMode::HostRecheckOnly if !request.precondition.is_empty() => {
            return Err(ValidationError::Invalid(
                "host-only targeted state write precondition",
            ));
        }
        TargetedStateWritePreconditionMode::ProviderToken
        | TargetedStateWritePreconditionMode::HostRecheckOnly => {}
        TargetedStateWritePreconditionMode::Unspecified => unreachable!("validated capability"),
    }
    if request.allow_create_membership != (expected_membership == SourceMembership::Absent)
        || (request.allow_create_membership && !capability.may_create_source_membership)
    {
        return Err(ValidationError::Invalid(
            "targeted state write membership creation",
        ));
    }
    if request.intents.is_empty() {
        return Err(ValidationError::Empty("targeted state write intents"));
    }
    if request.intents.len() > capability.maximum_fields as usize {
        return Err(ValidationError::Invalid("targeted state write field limit"));
    }
    let mut fields = HashSet::new();
    for intent in &request.intents {
        let field = intent
            .field
            .as_ref()
            .ok_or(ValidationError::Missing("targeted state write field"))?;
        validate_state_field(field)?;
        if !fields.insert(field.encode_to_vec()) {
            return Err(ValidationError::Duplicate("targeted state write field"));
        }
        let field_capability = capability
            .fields
            .iter()
            .find(|field_capability| field_capability.field.as_ref() == Some(field))
            .ok_or(ValidationError::Invalid(
                "targeted state write field capability",
            ))?;
        match intent
            .operation
            .as_ref()
            .ok_or(ValidationError::Missing("targeted state write operation"))?
        {
            targeted_state_write_intent::Operation::Set(value) => {
                if !field_capability.set_supported {
                    return Err(ValidationError::Invalid(
                        "targeted state write set capability",
                    ));
                }
                validate_value(value, "targeted state write set value")?;
            }
            targeted_state_write_intent::Operation::Clear(_) => {
                if !field_capability.clear_supported {
                    return Err(ValidationError::Invalid(
                        "targeted state write clear capability",
                    ));
                }
            }
        }
    }
    if request.maximum_receipt_bytes == 0
        || request.maximum_receipt_bytes > capability.maximum_receipt_bytes
    {
        return Err(ValidationError::Invalid(
            "targeted state write receipt limit",
        ));
    }
    if request.maximum_response_bytes == 0
        || request.maximum_response_bytes > capability.maximum_response_bytes
        || request.maximum_receipt_bytes > request.maximum_response_bytes
    {
        return Err(ValidationError::Invalid(
            "targeted state write response limit",
        ));
    }
    let encoded_length = request.encoded_len();
    if encoded_length as u64 > capability.maximum_request_bytes {
        return Err(ValidationError::TargetedStateWriteRequestTooLarge {
            actual: encoded_length,
            maximum: capability.maximum_request_bytes,
        });
    }
    Ok(())
}

pub fn targeted_state_write_response(
    request: &WriteTargetedStateRequest,
    capability: &TargetedStateWriteCapability,
    response: &WriteTargetedStateResponse,
) -> Result<(), ValidationError> {
    targeted_state_write_request(request, capability)?;
    let encoded_length = response.encoded_len();
    if encoded_length as u64 > request.maximum_response_bytes {
        return Err(ValidationError::TargetedStateWriteResponseTooLarge {
            actual: encoded_length,
            maximum: request.maximum_response_bytes,
        });
    }
    if response.receipt.len() as u64 > request.maximum_receipt_bytes {
        return Err(ValidationError::TargetedStateWriteReceiptTooLarge {
            actual: response.receipt.len(),
            maximum: request.maximum_receipt_bytes,
        });
    }
    let status = TargetedStateWriteStatus::try_from(response.status)
        .map_err(|_| ValidationError::Invalid("targeted state write status"))?;
    let certainty = TargetedStateWriteCertainty::try_from(response.certainty)
        .map_err(|_| ValidationError::Invalid("targeted state write certainty"))?;
    let retry = TargetedStateWriteRetryDisposition::try_from(response.retry_disposition)
        .map_err(|_| ValidationError::Invalid("targeted state write retry disposition"))?;
    let valid_combination = matches!(
        (status, certainty, retry),
        (
            TargetedStateWriteStatus::Applied,
            TargetedStateWriteCertainty::ConfirmedApplied,
            TargetedStateWriteRetryDisposition::NotRetryable
        ) | (
            TargetedStateWriteStatus::NoOp,
            TargetedStateWriteCertainty::ConfirmedNotApplied,
            TargetedStateWriteRetryDisposition::NotRetryable
        ) | (
            TargetedStateWriteStatus::Rejected,
            TargetedStateWriteCertainty::ConfirmedNotApplied,
            TargetedStateWriteRetryDisposition::NotRetryable
        ) | (
            TargetedStateWriteStatus::Failed,
            TargetedStateWriteCertainty::ConfirmedNotApplied,
            TargetedStateWriteRetryDisposition::SafeSameKey
                | TargetedStateWriteRetryDisposition::NotRetryable
        ) | (
            TargetedStateWriteStatus::Indeterminate,
            TargetedStateWriteCertainty::Unknown,
            TargetedStateWriteRetryDisposition::ReconcileFirst
        )
    );
    if !valid_combination {
        return Err(ValidationError::Invalid(
            "targeted state write outcome combination",
        ));
    }
    if retry == TargetedStateWriteRetryDisposition::SafeSameKey
        && TargetedStateWriteIdempotencyMode::try_from(capability.idempotency_mode)
            .map_err(|_| ValidationError::Invalid("targeted state write idempotency mode"))?
            != TargetedStateWriteIdempotencyMode::StableKey
    {
        return Err(ValidationError::Invalid(
            "targeted state write retry idempotency",
        ));
    }
    if matches!(
        status,
        TargetedStateWriteStatus::Rejected
            | TargetedStateWriteStatus::Failed
            | TargetedStateWriteStatus::Indeterminate
    ) {
        adapter_error(
            response
                .error
                .as_ref()
                .ok_or(ValidationError::Missing("targeted state write error"))?,
        )?;
    } else if response.error.is_some() {
        return Err(ValidationError::ErrorWithPayload);
    }

    validate_targeted_state_write_effects(request, response, status)?;
    let membership_effect = TargetedStateMembershipEffect::try_from(response.membership_effect)
        .map_err(|_| ValidationError::Invalid("targeted state membership effect"))?;
    let expected_membership = SourceMembership::try_from(request.expected_membership)
        .map_err(|_| ValidationError::Invalid("targeted state write expected membership"))?;
    let expected_effect = match status {
        TargetedStateWriteStatus::Applied if expected_membership == SourceMembership::Absent => {
            TargetedStateMembershipEffect::Created
        }
        TargetedStateWriteStatus::Applied
        | TargetedStateWriteStatus::NoOp
        | TargetedStateWriteStatus::Rejected
        | TargetedStateWriteStatus::Failed => TargetedStateMembershipEffect::Unchanged,
        TargetedStateWriteStatus::Indeterminate => TargetedStateMembershipEffect::Unknown,
        TargetedStateWriteStatus::Unspecified => unreachable!("validated outcome combination"),
    };
    if membership_effect != expected_effect {
        return Err(ValidationError::Invalid("targeted state membership effect"));
    }

    if matches!(
        status,
        TargetedStateWriteStatus::Applied | TargetedStateWriteStatus::NoOp
    ) {
        if response.provider_revision.is_empty() {
            return Err(ValidationError::Empty(
                "targeted state write provider revision",
            ));
        }
        if TargetedStateWritePreconditionMode::try_from(capability.precondition_mode)
            .map_err(|_| ValidationError::Invalid("targeted state write precondition mode"))?
            == TargetedStateWritePreconditionMode::ProviderToken
            && response.successor_precondition.is_empty()
        {
            return Err(ValidationError::Empty(
                "targeted state write successor precondition",
            ));
        }
    }
    if status == TargetedStateWriteStatus::Applied && response.receipt.is_empty() {
        return Err(ValidationError::Empty("targeted state write receipt"));
    }
    Ok(())
}

fn validate_targeted_state_write_effects(
    request: &WriteTargetedStateRequest,
    response: &WriteTargetedStateResponse,
    status: TargetedStateWriteStatus,
) -> Result<(), ValidationError> {
    if matches!(
        status,
        TargetedStateWriteStatus::Rejected | TargetedStateWriteStatus::Failed
    ) {
        return if response.field_effects.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::ErrorWithPayload)
        };
    }
    if response.field_effects.len() != request.intents.len() {
        return Err(ValidationError::TargetedStateWriteFieldCount);
    }
    for (intent, effect) in request.intents.iter().zip(&response.field_effects) {
        let field = effect.field.as_ref().ok_or(ValidationError::Missing(
            "targeted state write effect field",
        ))?;
        validate_state_field(field)?;
        if intent.field.as_ref() != Some(field) {
            return Err(ValidationError::TargetedStateWriteFieldMismatch);
        }
        let effect_kind = TargetedStateFieldEffectKind::try_from(effect.effect)
            .map_err(|_| ValidationError::Invalid("targeted state write field effect"))?;
        match (status, intent.operation.as_ref(), effect_kind) {
            (
                TargetedStateWriteStatus::Applied,
                Some(targeted_state_write_intent::Operation::Set(intended)),
                TargetedStateFieldEffectKind::Set,
            ) if effect.value.as_ref() == Some(intended) => {
                validate_value(intended, "targeted state write effect value")?;
            }
            (
                TargetedStateWriteStatus::Applied,
                Some(targeted_state_write_intent::Operation::Clear(_)),
                TargetedStateFieldEffectKind::Cleared,
            ) if effect.value.is_none() => {}
            (TargetedStateWriteStatus::NoOp, _, TargetedStateFieldEffectKind::Unchanged)
                if effect.value.is_none() => {}
            (TargetedStateWriteStatus::Indeterminate, _, TargetedStateFieldEffectKind::Unknown)
                if effect.value.is_none() => {}
            _ => {
                return Err(ValidationError::Invalid(
                    "targeted state write field effect",
                ));
            }
        }
    }
    Ok(())
}

pub fn asset_response(
    response: &ReadAssetResponse,
    maximum_bytes: u64,
    allowed_content_types: &[String],
) -> Result<(), ValidationError> {
    let result = match response.outcome.as_ref() {
        Some(read_asset_response::Outcome::Result(result)) => result,
        Some(read_asset_response::Outcome::Error(error)) => return adapter_error(error),
        None => return Err(ValidationError::Missing("asset read outcome")),
    };
    if result.content.is_empty() {
        return Err(ValidationError::Empty("asset content"));
    }
    if result.content.len() as u64 > maximum_bytes {
        return Err(ValidationError::AssetTooLarge {
            actual: result.content.len(),
            maximum: maximum_bytes,
        });
    }
    if result.full_length != result.content.len() as u64 {
        return Err(ValidationError::AssetLengthMismatch);
    }
    if !allowed_content_types
        .iter()
        .any(|content_type| content_type == &result.content_type)
    {
        return Err(ValidationError::AssetContentType);
    }
    if result.cache_control.is_empty()
        || result.cache_control.len() > 1024
        || !result.cache_control.is_ascii()
        || result.cache_control.chars().any(char::is_control)
    {
        return Err(ValidationError::Invalid("asset cache control"));
    }
    let hash = result
        .hash
        .as_ref()
        .ok_or(ValidationError::Missing("asset hash"))?;
    let algorithm = hash
        .algorithm
        .as_ref()
        .ok_or(ValidationError::Missing("asset hash algorithm"))?;
    if algorithm.namespace != "trakkin" || algorithm.name != "sha256" {
        return Err(ValidationError::AssetHash);
    }
    if hash.digest.as_slice() != Sha256::digest(&result.content).as_slice() {
        return Err(ValidationError::AssetHash);
    }
    Ok(())
}

fn validate_catalog_batch(batch: &CatalogBatch, expected: u64) -> Result<(), ValidationError> {
    if batch.sequence != expected {
        return Err(ValidationError::InvalidSequence {
            expected,
            actual: batch.sequence,
        });
    }
    for item in &batch.item_upserts {
        validate_provider_item(item)?;
    }
    for deleted in &batch.item_deletes {
        key(deleted, "deleted provider item key")?;
    }
    for relation in &batch.relation_upserts {
        key(
            relation
                .key
                .as_ref()
                .ok_or(ValidationError::Missing("catalog relation key"))?,
            "catalog relation key",
        )?;
        if let Some(parent) = &relation.parent_key {
            key(parent, "catalog relation parent key")?;
        }
        if let Some(item) = &relation.provider_item_key {
            key(item, "catalog relation provider item key")?;
        }
        term(
            relation
                .kind
                .as_ref()
                .ok_or(ValidationError::Missing("catalog relation kind"))?,
            "catalog relation kind",
        )?;
    }
    for deleted in &batch.relation_deletes {
        key(deleted, "deleted catalog relation key")?;
    }
    for binding in &batch.coordinate_binding_upserts {
        validate_coordinate_binding(binding)?;
    }
    for binding in &batch.coordinate_binding_deletes {
        validate_coordinate_binding_key(binding)?;
    }
    Ok(())
}

fn validate_state_batch(batch: &StateBatch, expected: u64) -> Result<(), ValidationError> {
    if batch.sequence != expected {
        return Err(ValidationError::InvalidSequence {
            expected,
            actual: batch.sequence,
        });
    }
    for observation in &batch.observations {
        let subject = observation
            .subject
            .as_ref()
            .ok_or(ValidationError::Missing("state subject"))?;
        match subject
            .subject
            .as_ref()
            .ok_or(ValidationError::Missing("state subject reference"))?
        {
            crate::v1::subject_reference::Subject::ProviderItemKey(value) => {
                key(value, "state provider item key")?;
            }
            crate::v1::subject_reference::Subject::CatalogRelationKey(value) => {
                key(value, "state catalog relation key")?;
            }
        }
        let field = observation
            .field
            .as_ref()
            .ok_or(ValidationError::Missing("state field"))?;
        validate_state_field(field)?;
        if observation.observation.is_none() {
            return Err(ValidationError::Missing("state observation operation"));
        }
    }
    Ok(())
}

fn validate_state_field(field: &StateField) -> Result<(), ValidationError> {
    term(
        field
            .field
            .as_ref()
            .ok_or(ValidationError::Missing("state field term"))?,
        "state field term",
    )?;
    if let Some(unit) = &field.unit {
        term(unit, "state unit")?;
    }
    Ok(())
}

fn validate_value(value: &crate::v1::Value, field: &'static str) -> Result<(), ValidationError> {
    if value.value.is_none() {
        Err(ValidationError::Missing(field))
    } else {
        Ok(())
    }
}

fn validate_provider_item(item: &ProviderItem) -> Result<(), ValidationError> {
    key(
        item.key
            .as_ref()
            .ok_or(ValidationError::Missing("provider item key"))?,
        "provider item key",
    )?;
    term(
        item.kind
            .as_ref()
            .ok_or(ValidationError::Missing("provider item kind"))?,
        "provider item kind",
    )?;
    non_empty_text(&item.display_name, "provider item display name")?;
    for reference in &item.portable_references {
        portable_reference(reference, "provider item portable reference")?;
    }
    Ok(())
}

fn validate_candidate(candidate: &LookupCandidate) -> Result<(), ValidationError> {
    validate_provider_item(
        candidate
            .provider_item
            .as_ref()
            .ok_or(ValidationError::Missing("lookup provider item"))?,
    )?;
    let evidence = candidate
        .evidence
        .as_ref()
        .ok_or(ValidationError::Missing("lookup evidence"))?;
    if evidence.adapter_revision.is_empty() {
        return Err(ValidationError::Empty("lookup adapter revision"));
    }
    for reference in &evidence.matched_references {
        portable_reference(reference, "lookup matched reference")?;
    }
    Ok(())
}

fn validate_endpoint_candidate(
    candidate: &EndpointLookupCandidate,
    requested: &PortableEndpoint,
) -> Result<(), ValidationError> {
    validate_provider_item(
        candidate
            .provider_item
            .as_ref()
            .ok_or(ValidationError::Missing("endpoint lookup provider item"))?,
    )?;
    let binding = candidate
        .binding
        .as_ref()
        .ok_or(ValidationError::Missing("endpoint lookup binding"))?;
    validate_coordinate_binding(binding)?;
    if binding.endpoint.as_ref() != Some(requested) {
        return Err(ValidationError::EndpointMismatch);
    }
    validate_lookup_evidence(
        candidate
            .evidence
            .as_ref()
            .ok_or(ValidationError::Missing("endpoint lookup evidence"))?,
    )
}

fn validate_coordinate_binding(binding: &CoordinateBinding) -> Result<(), ValidationError> {
    validate_coordinate_binding_key(&CoordinateBindingKey {
        endpoint: binding.endpoint.clone(),
        subject: binding.subject.clone(),
    })?;
    let backing = CoordinateBacking::try_from(binding.backing)
        .map_err(|_| ValidationError::Invalid("coordinate backing"))?;
    if backing == CoordinateBacking::Unspecified {
        return Err(ValidationError::Invalid("coordinate backing"));
    }
    if binding.evidence_revision.is_empty() {
        return Err(ValidationError::Empty("coordinate evidence revision"));
    }
    Ok(())
}

fn validate_coordinate_binding_key(binding: &CoordinateBindingKey) -> Result<(), ValidationError> {
    portable_endpoint(
        binding
            .endpoint
            .as_ref()
            .ok_or(ValidationError::Missing("coordinate binding endpoint"))?,
        "coordinate binding endpoint",
    )?;
    validate_subject(
        binding
            .subject
            .as_ref()
            .ok_or(ValidationError::Missing("coordinate binding subject"))?,
    )
}

fn validate_subject(subject: &SubjectReference) -> Result<(), ValidationError> {
    match subject.subject.as_ref().ok_or(ValidationError::Missing(
        "coordinate binding subject reference",
    ))? {
        subject_reference::Subject::ProviderItemKey(value) => {
            key(value, "coordinate provider item key")
        }
        subject_reference::Subject::CatalogRelationKey(value) => {
            key(value, "coordinate catalog relation key")
        }
    }
}

fn validate_lookup_evidence(evidence: &crate::v1::LookupEvidence) -> Result<(), ValidationError> {
    if evidence.adapter_revision.is_empty() {
        return Err(ValidationError::Empty("lookup adapter revision"));
    }
    if evidence
        .expires_time_milliseconds
        .is_some_and(|expires| expires <= evidence.observed_time_milliseconds)
    {
        return Err(ValidationError::Invalid("lookup evidence expiry"));
    }
    for reference in &evidence.matched_references {
        portable_reference(reference, "lookup matched reference")?;
    }
    Ok(())
}

fn account_snapshot(account: &AccountSnapshot) -> Result<(), ValidationError> {
    key(
        account
            .key
            .as_ref()
            .ok_or(ValidationError::Missing("account key"))?,
        "account key",
    )?;
    non_empty_text(&account.display_name, "account display name")
}

fn source_snapshot(source: &SourceSnapshot) -> Result<(), ValidationError> {
    key(
        source
            .key
            .as_ref()
            .ok_or(ValidationError::Missing("source key"))?,
        "source key",
    )?;
    key(
        source
            .account_key
            .as_ref()
            .ok_or(ValidationError::Missing("source account key"))?,
        "source account key",
    )?;
    non_empty_text(&source.display_name, "source display name")?;
    term(
        source
            .kind
            .as_ref()
            .ok_or(ValidationError::Missing("source kind"))?,
        "source kind",
    )?;
    source_capabilities(
        source
            .capabilities
            .as_ref()
            .ok_or(ValidationError::Missing("source capabilities"))?,
    )
}

fn validate_heartbeat(heartbeat: &ReadHeartbeat) -> Result<(), ValidationError> {
    if heartbeat.operation_id.is_empty() {
        return Err(ValidationError::Empty("read heartbeat operation ID"));
    }
    Ok(())
}

fn validate_completed(completed: &ReadCompleted) -> Result<(), ValidationError> {
    if completed.next_cursor.is_empty() {
        return Err(ValidationError::Empty("read next cursor"));
    }
    if completed.evidence_revision.is_empty() {
        return Err(ValidationError::Empty("read evidence revision"));
    }
    Ok(())
}

fn validate_failed(failed: &ReadFailed) -> Result<(), ValidationError> {
    adapter_error(
        failed
            .error
            .as_ref()
            .ok_or(ValidationError::Missing("read failure error"))?,
    )
}

fn non_empty_text(value: &str, field: &'static str) -> Result<(), ValidationError> {
    if value.is_empty() {
        Err(ValidationError::Empty(field))
    } else if value.chars().any(char::is_control) {
        Err(ValidationError::Invalid(field))
    } else {
        Ok(())
    }
}

fn validate_unique_text(values: &[String], field: &'static str) -> Result<(), ValidationError> {
    let mut unique = HashSet::new();
    for value in values {
        non_empty_text(value, field)?;
        if !unique.insert(value) {
            return Err(ValidationError::Duplicate(field));
        }
    }
    Ok(())
}

fn validate_coordinate_ids(values: &[String], field: &'static str) -> Result<(), ValidationError> {
    validate_unique_text(values, field)?;
    for coordinate_id in values {
        let selection = if coordinate_id == "time" { "PT1S" } else { "1" };
        let selector = format!("{coordinate_id}:{selection}");
        MappingEndpoint::from_parts("trakkin.invalid", b"capability", Some(&selector))
            .map_err(|_| ValidationError::Invalid(field))?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "validation_tests.rs"]
mod tests;
