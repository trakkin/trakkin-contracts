# trakkin-provider-sdk

## Completion discovery

`DescribeCompletionLibrary` describes the opened account's completion behavior
and supported fields, groups, unit kinds, and read/write capabilities. It must not
enumerate native entries or acquire their progress.

`DiscoverCompletionSubjects` separately returns paginated native subject
descriptors. Subjects are identified by native identities, never display labels.
Discovery does not return completion values, mutable native revisions, or commands.
Cursors must remain bound to the opened account, source, and requested page size.

Use `validate_discovery_request`, `validate_completion_library`, and
`validate_completion_subject_page` from `completion_wire` to enforce account,
capability, identity, cursor, and response-size constraints. Requests allow 1 to
100 subjects per page; providers may return smaller pages and must explicitly
report unsupported limits rather than silently truncate a library.

`completion_discovery` owns the typed `Library`, `Field`, `Descriptor`, and `Page`
models. Validate libraries against the opened account and pages against that
account, page size, and cursor. Subject fields may narrow library capabilities,
never expand them. The wire validators delegate to these same semantic rules;
hosts should also validate typed results from sessions that bypass the wire codec.

Discovery metadata is advisory, not authorization to mutate native state. Current
completion reads, prepared-operation validation, explicit permissions, and the
existing execution and reconciliation contracts remain necessary.

Library description is the single source of completion behavior. The completion
workflow is describe/discover, read, prepare, execute, and reconcile. Preparation
must resolve the exact native identities in its intentions and verify their
current account, source membership, domain, and baseline without writing. It
must reject unavailable destinations, never select a candidate or match a title.
There is no separate behavior-description or destination-resolution RPC.

## Completion state

`completion_state::State` owns completion observations, explicit native field
observations, resource access, and domain references. Its validator binds evidence
to the opened account, requested subjects, and declared behavior, and rejects
ambiguous reference domains, inconsistent canonical groups, and overlapping or
unsupported field evidence. Collection and aggregate evidence limits apply to
typed sessions as well as process-backed providers.

`completion_wire::decode_state` performs bounded collection conversion and invokes
that same validator. Use `completion::bounded_json_size` when measuring serialized
completion evidence without allocating a second buffer. Valid state is evidence,
not write authorization; freshness, mappings, policy permissions, consent, and
outstanding-request barriers remain host responsibilities.

## Provider capability scope

The contract retains additive item merges, disclosed append effects, monotone
merge protection, and scoped native deduplication metadata. These model plausible
chapter, track, reading-history, and listening-history APIs even when no current
provider advertises them. Monotone protection is valid only when every effect is
an additive item merge; an incidental append or setter invalidates that claim.

Contract representation is not host execution support. Each host write profile
still needs explicit admission, permissions, and provider-specific evidence.
Deduplication metadata describes a native guarantee for an exact scope and time
window; it does not grant authorization to retry an operation.

## Native outcome evidence

`AttemptOutcome::validate_for` checks the shape and identity of an observation,
including the host's initial `NotDispatched` state. `validate_attempt_outcome`
validates native reports and transitions from a previous native observation:
native reports cannot claim `NotDispatched`, terminal lifecycle cannot regress,
and established application evidence cannot be weakened. Current satisfaction
may change independently of historical effect knowledge or request lifecycle.

Hosts and providers should use the shared transition validator rather than
implementing separate evidence rules. It does not establish native truth, release
host barriers, authorize mutation, or make a recorded operation replayable.
