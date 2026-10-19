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

Discovery metadata is advisory, not authorization to mutate native state. Current
completion reads, prepared-operation validation, explicit permissions, and the
existing execution and reconciliation contracts remain necessary.
