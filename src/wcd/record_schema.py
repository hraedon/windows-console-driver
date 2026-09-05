"""Validation and compatibility policy for transaction records.

The executor's five top-level keys are a wire contract with
``windows-evidence-lab`` and therefore stay unchanged.  Version 1 stamps the
record inside ``provenance``.  Records committed before that stamp are not
rewritten: :func:`load_record` recognizes only the repository's committed
estate evidence locations as legacy input and validates them against v0.

This module intentionally has no third-party dependency.  The JSON Schema
documents under ``docs/`` are the machine-readable contract; these checks are
the small runtime compatibility harness used by tests and importers that
cannot assume a JSON-Schema package is installed.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Final, Literal, NoReturn

RecordVersion = Literal[0, 1]

RECORD_SCHEMA_VERSION: Final[int] = 1
RECORD_SCHEMA_REF: Final[str] = "docs/transaction-record-schema-v1.json"
LEGACY_SCHEMA_VERSION: Final[int] = 0

_TOP_LEVEL_KEYS: Final[frozenset[str]] = frozenset(
    {"state", "verdict", "envelope_result", "events", "provenance"}
)
_STATES: Final[frozenset[str]] = frozenset(
    {"prepared", "armed", "commit_attempted", "verified", "disproven", "indeterminate"}
)
_TERMINAL_STATES: Final[frozenset[str]] = frozenset(
    {"verified", "disproven", "indeterminate"}
)
_ENVELOPE_STATUSES: Final[frozenset[str]] = frozenset(
    {"satisfied", "disproven", "indeterminate"}
)
_DELTA_KINDS: Final[frozenset[str]] = frozenset({"added", "changed", "removed"})
_BASE_PROVENANCE_KEYS: Final[frozenset[str]] = frozenset(
    {"capability", "run_sheet", "transaction_id", "console", "steps", "cleanup", "notes"}
)
_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_LEGACY_RECORDS: Final[frozenset[Path]] = frozenset(
    (_REPO_ROOT / "docs" / window / "records" / name).resolve()
    for window, name in (
        ("estate-window-2", "r1-migtable.json"),
        ("estate-window-2", "r2-record.json"),
        ("estate-window-2", "r3-record.json"),
        ("estate-window-2", "r4-record.json"),
        ("estate-window-2", "r5m-record.json"),
        ("estate-window-2", "r5u-record.json"),
        ("estate-window-3", "r2-psorder-window3-record.json"),
        ("estate-window-3", "r3-window3-record.json"),
    )
)


class RecordSchemaError(ValueError):
    """A transaction record is malformed or uses an unsupported version."""


def _fail(path: str, message: str) -> NoReturn:
    raise RecordSchemaError(f"{path}: {message}")


def _object(value: object, path: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        _fail(path, "must be an object")
    return value


def _keys(
    value: Mapping[str, object],
    expected: frozenset[str],
    path: str,
    *,
    required: frozenset[str] | None = None,
) -> None:
    unexpected = set(value) - expected
    missing = (required if required is not None else expected) - set(value)
    if unexpected:
        _fail(path, f"unknown field(s): {', '.join(sorted(unexpected))}")
    if missing:
        _fail(path, f"missing field(s): {', '.join(sorted(missing))}")


def _string(value: object, path: str) -> None:
    if not isinstance(value, str):
        _fail(path, "must be a string")


def _string_list(value: object, path: str) -> None:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        _fail(path, "must be an array of strings")


def _validate_delta(value: object, path: str) -> None:
    if not isinstance(value, list):
        _fail(path, "must be an array")
    items: list[object] = value
    for index, item in enumerate(items):
        entry = _object(item, f"{path}[{index}]")
        _keys(entry, frozenset({"key", "kind", "before", "after"}), f"{path}[{index}]")
        _string(entry["key"], f"{path}[{index}].key")
        if not isinstance(entry["kind"], str) or entry["kind"] not in _DELTA_KINDS:
            _fail(f"{path}[{index}].kind", "must be added, changed, or removed")


def _validate_envelope(value: object, *, legacy: bool, state: str) -> None:
    envelope = _object(value, "envelope_result")
    if not envelope:
        if state == "indeterminate":
            return
        _fail("envelope_result", "may be empty only for an indeterminate early stop")
    required = {"status", "satisfied", "violated", "unclassified", "characterization"}
    if not legacy:
        required.update({"unresolved", "delta"})
    allowed = frozenset(required | {"unresolved", "delta"})
    _keys(envelope, allowed, "envelope_result", required=frozenset(required))
    if not isinstance(envelope["status"], str) or envelope["status"] not in _ENVELOPE_STATUSES:
        _fail("envelope_result.status", "must be satisfied, disproven, or indeterminate")
    for key in ("satisfied", "violated", "unclassified"):
        _string_list(envelope[key], f"envelope_result.{key}")
    if "unresolved" in envelope:
        _string_list(envelope["unresolved"], "envelope_result.unresolved")
    _string(envelope["characterization"], "envelope_result.characterization")
    if "delta" in envelope:
        _validate_delta(envelope["delta"], "envelope_result.delta")


def _validate_events(value: object) -> None:
    if not isinstance(value, list):
        _fail("events", "must be an array")
    items: list[object] = value
    for index, item in enumerate(items):
        event = _object(item, f"events[{index}]")
        _keys(
            event,
            frozenset({"sequence", "from_state", "to_state", "reason"}),
            f"events[{index}]",
        )
        sequence = event["sequence"]
        if type(sequence) is not int or sequence < 1:
            _fail(f"events[{index}].sequence", "must be a positive integer")
        if (
            event["from_state"] is not None
            and (
                not isinstance(event["from_state"], str)
                or event["from_state"] not in _STATES
            )
        ):
            _fail(f"events[{index}].from_state", "is not a transaction state")
        if not isinstance(event["to_state"], str) or event["to_state"] not in _STATES:
            _fail(f"events[{index}].to_state", "is not a transaction state")
        _string(event["reason"], f"events[{index}].reason")


def _validate_provenance(value: object, *, legacy: bool) -> None:
    provenance = _object(value, "provenance")
    allowed = _BASE_PROVENANCE_KEYS | frozenset({"$schema", "schema_version"})
    required = _BASE_PROVENANCE_KEYS if legacy else allowed
    _keys(provenance, allowed, "provenance", required=required)
    stamped = "$schema" in provenance or "schema_version" in provenance
    if legacy:
        if stamped:
            _fail("provenance", "legacy records must not carry a partial schema stamp")
    else:
        if provenance.get("$schema") != RECORD_SCHEMA_REF:
            _fail("provenance.$schema", f"must be {RECORD_SCHEMA_REF!r}")
        if provenance.get("schema_version") != RECORD_SCHEMA_VERSION:
            _fail("provenance.schema_version", "must be 1")
    _string(provenance["capability"], "provenance.capability")
    _string(provenance["run_sheet"], "provenance.run_sheet")
    _string(provenance["transaction_id"], "provenance.transaction_id")
    _object(provenance["console"], "provenance.console")
    if not isinstance(provenance["steps"], list):
        _fail("provenance.steps", "must be an array")
    _object(provenance["cleanup"], "provenance.cleanup")
    _string_list(provenance["notes"], "provenance.notes")


def _is_committed_legacy_source(source: str | Path | None) -> bool:
    if source is None:
        return False
    return Path(source).resolve(strict=False) in _LEGACY_RECORDS


def validate_record(
    record: Mapping[str, object],
    *,
    source: str | Path | None = None,
    allow_legacy: bool = False,
) -> RecordVersion:
    """Validate a record and return its version.

    A record is v1 when its provenance contains the complete schema stamp.
    Unstamped records are accepted only when ``allow_legacy`` is explicit or
    when ``source`` identifies committed estate-window-2/3 evidence.  This
    prevents an arbitrary unversioned payload from quietly becoming a legacy
    record while retaining read access to immutable evidence.
    """
    if not isinstance(record, dict):
        _fail("record", "must be an object")
    _keys(record, _TOP_LEVEL_KEYS, "record")
    state = record["state"]
    if not isinstance(state, str) or state not in _TERMINAL_STATES:
        _fail("state", "must be verified, disproven, or indeterminate")
    _string(record["verdict"], "verdict")
    if len(record["verdict"]) > 512:
        _fail("verdict", "must be at most 512 characters")

    provenance = _object(record["provenance"], "provenance")
    stamped = "$schema" in provenance or "schema_version" in provenance
    if stamped:
        if "$schema" not in provenance or "schema_version" not in provenance:
            _fail(
                "provenance",
                "partial schema stamp; both $schema and schema_version are required",
            )
        version: RecordVersion = 1
    elif allow_legacy or _is_committed_legacy_source(source):
        version = 0
    else:
        _fail("provenance", "missing schema stamp; legacy input requires an explicit source")
    _validate_envelope(record["envelope_result"], legacy=version == 0, state=state)
    _validate_events(record["events"])
    _validate_provenance(record["provenance"], legacy=version == 0)
    return version


def load_record(path: str | Path) -> tuple[dict[str, object], RecordVersion]:
    """Load and validate one JSON record, applying the committed-legacy rule."""
    record_path = Path(path)
    try:
        value = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecordSchemaError(f"{record_path}: cannot read JSON record: {exc}") from exc
    if not isinstance(value, dict):
        _fail(str(record_path), "must contain a JSON object")
    return value, validate_record(value, source=record_path)
