# Transaction-record schema

The executor emits one JSON object for every terminal transaction. The wire
envelope has exactly five top-level keys because `windows-evidence-lab`
consumes it directly:

```text
state, verdict, envelope_result, events, provenance
```

New records use [transaction-record-schema-v2.json](transaction-record-schema-v2.json).
The schema stamp is deliberately inside `provenance`:

```json
{
  "provenance": {
    "$schema": "docs/transaction-record-schema-v2.json",
    "schema_version": 2
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

## Version 2: the capability-spec binding

Version 2 adds the two provenance fields version 1 lacked:

- `capability_revision` — the `revision` declared by the capability document
  that was executed, a positive integer;
- `capability_sha256` — a lowercase SHA-256 over that document's **exact
  text** as it arrived at the driver (the WEL plan's `capability` string, or
  the file the controller read), not a re-serialization of the parsed object.

The executor mints v2 exactly when its caller supplied that text (`wcd
exec-transaction` always does); a direct library call that never named the
content still mints v1, because a binding must digest content somebody
actually launched. `wcd.record_schema.validate_record()` refuses a v2 record
whose `capability_sha256` is not the digest of the `capability_text` the
caller supplies, or whose `capability_revision` disagrees with the document
that text parses to — the digest is recomputed from the content, never
borrowed from the record.

The same revision closes the second v1 gap: a stdin plan's `machine` and
`identity` used to be provenance-only — recorded, then ignored while the
executor targeted the estate's own configuration. From v2 the plan's target
must **agree** with the estate (`machine` equals `vm_name`; `identity` equals
the estate's declared `identity_role`, in WEL's logical vocabulary) or the
CLI refuses before any transport work. The agreement is enforced where the
two configurations meet — the driver — because WEL cannot see the estate file
and the estate cannot see WEL's scenario.

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
version checks. Native-v1 banked records are unchanged: they validate against
[transaction-record-schema-v1.json](transaction-record-schema-v1.json) under
their own stamp, and v1 validation semantics are frozen.

The compatibility harness validates every committed record in its original
form and validates generated records against the current schema version. CI
additionally checks the schema documents against JSON Schema Draft 2020-12
and validates the artifacts with the standard `jsonschema` implementation. A
future schema revision must add a new versioned document and an intentional
reader path; it must not retrofit fields into banked evidence.

The CLI validates the executor's returned v2 record — including its
capability binding, against the exact text this process executed — before
writing stdout or `--out`. At that point the executor has already completed
its terminal cleanup; schema rejection therefore cannot skip cleanup, and
malformed output cannot cross the WEL wire boundary.

## The v1 binding limit (closed by v2)

Version 1 identified the capability and run sheet but did not store the
capability revision or a content digest, and a record therefore could not, by
itself, authenticate which revision of a mutable capability file produced it
(the gap this file used to document). The same went for the plan's
machine/identity, which execution ignored in favour of the estate file. Both
are bound as of version 2, above. The qualification matrix stays in
`docs/capability-qualification.md`.
