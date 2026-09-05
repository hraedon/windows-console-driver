# Transaction-record schema

The executor emits one JSON object for every terminal transaction. The wire
envelope has exactly five top-level keys because `windows-evidence-lab`
consumes it directly:

```text
state, verdict, envelope_result, events, provenance
```

New records use [transaction-record-schema-v1.json](transaction-record-schema-v1.json).
The schema stamp is deliberately inside `provenance`:

```json
{
  "provenance": {
    "$schema": "docs/transaction-record-schema-v1.json",
    "schema_version": 1
  }
}
```

Version 1 makes a resolved tri-state envelope complete by requiring
`unresolved` and `delta` (an empty array is valid when no fact changed). An
`indeterminate` transaction that stops before the post-oracle may instead
carry an empty `envelope_result`; `verified` and `disproven` records may not.
The schema also keeps the existing event and provenance fields closed at their
known boundaries while leaving observer-specific values under `console`,
`steps`, and `cleanup` opaque.

## Compatibility policy

The six committed records under `docs/estate-window-2/records/` and the two
window-3 records predate schema stamping. They are immutable evidence and are
not rewritten. Window 4 contains six native-v1 records, including one retained
pre-fix trace whose screenshot names collided and its trace-complete rerun.
`transaction-record-schema-v0.json` documents the old shape;
`wcd.record_schema.load_record()` accepts that shape automatically only for
the eight canonical committed evidence filenames (or when a caller explicitly
opts into `allow_legacy=True`). An arbitrary unstamped payload—even one placed
beside those records—is rejected, so a missing stamp cannot silently bypass
version checks.

The compatibility harness validates every committed record in its original
form and validates generated records against v1. CI additionally checks both
schema documents against JSON Schema Draft 2020-12 and validates the artifacts
with the standard `jsonschema` implementation. A future schema revision must
add a new versioned document and an intentional reader path; it must not
retrofit fields into banked evidence.

The CLI validates the executor's returned v1 record before writing stdout or
`--out`. At that point the executor has already completed its terminal cleanup;
schema rejection therefore cannot skip cleanup, and malformed output cannot
cross the WEL wire boundary.

## Known binding limit

Version 1 identifies the capability and run sheet but does not store the
capability revision or a content digest. A record therefore cannot, by itself,
authenticate which revision of a mutable capability file produced it. The
current qualification matrix is maintained in
`docs/capability-qualification.md`; a future record-schema revision should add
an immutable capability-spec binding without changing frozen v1.
