"""Compatibility and wire-contract tests for transaction records."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from wcd.envelope import AssertionResult, FactDelta
from wcd.exec_transaction import RunProvenance, _emit
from wcd.record_schema import (
    RECORD_SCHEMA_REF,
    RecordSchemaError,
    load_record,
    validate_record,
)
from wcd.transaction import Transaction

ROOT = Path(__file__).parents[1]
RECORDS = ROOT / "docs"


def _generated_record() -> dict[str, object]:
    transaction = Transaction("zz-transaction")
    transaction.prepare(
        pre_oracle_done=True,
        lease_held=True,
        context_asserted=True,
        recovery_declared=True,
    )
    transaction.arm()
    transaction.commit("zz-commit", declared=True)
    transaction.resolve(envelope_satisfied=True, reproduce_satisfied=True)
    return _emit(
        transaction,
        AssertionResult(
            status="satisfied",
            satisfied=("require[0]",),
            violated=(),
            unresolved=(),
            unclassified=(),
            characterization="satisfied",
            delta=FactDelta(),
        ),
        RunProvenance(),
        [],
        "zz.capability",
        "zz.run_sheet",
    )


def _early_stop_record() -> dict[str, object]:
    transaction = Transaction("zz-early-stop")
    transaction.prepare(
        pre_oracle_done=True,
        lease_held=True,
        context_asserted=True,
        recovery_declared=True,
    )
    transaction.mark_indeterminate("zz pre-oracle stop")
    return _emit(
        transaction,
        None,
        RunProvenance(),
        [],
        "zz.capability",
        "zz.run_sheet",
    )


def test_generated_record_is_v1_and_preserves_five_top_level_wire_keys() -> None:
    record = _generated_record()

    assert set(record) == {"state", "verdict", "envelope_result", "events", "provenance"}
    assert validate_record(record) == 1
    provenance = record["provenance"]
    assert isinstance(provenance, dict)
    assert provenance["$schema"] == RECORD_SCHEMA_REF
    assert provenance["schema_version"] == 1

    schema = json.loads((ROOT / RECORD_SCHEMA_REF).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(record)


def test_committed_records_are_read_without_rewriting_them() -> None:
    paths = sorted(RECORDS.glob("estate-window-*/records/*.json"))
    assert paths
    before = {path: path.read_bytes() for path in paths}

    versions = {path: load_record(path)[1] for path in paths}

    assert sum(version == 0 for version in versions.values()) == 8
    assert sum(version == 1 for version in versions.values()) == 6
    assert all(path.read_bytes() == content for path, content in before.items())
    assert all(
        ("schema_version" not in json.loads(path.read_text())["provenance"])
        == (version == 0)
        for path, version in versions.items()
    )

    validators = {}
    for version in (0, 1):
        schema = json.loads(
            (ROOT / "docs" / f"transaction-record-schema-v{version}.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(schema)
        validators[version] = Draft202012Validator(schema)
    for path, version in versions.items():
        validators[version].validate(json.loads(path.read_text(encoding="utf-8")))


def test_legacy_shape_requires_explicit_compatibility_context() -> None:
    record = json.loads(
        (RECORDS / "estate-window-2" / "records" / "r1-migtable.json").read_text()
    )

    with pytest.raises(RecordSchemaError, match="missing schema stamp"):
        validate_record(record)
    assert validate_record(record, allow_legacy=True) == 0


def test_v1_rejects_partial_or_wrong_stamp() -> None:
    record = _generated_record()
    provenance = record["provenance"]
    assert isinstance(provenance, dict)
    provenance.pop("schema_version")
    with pytest.raises(RecordSchemaError, match="schema stamp"):
        validate_record(record)

    record = _generated_record()
    provenance = record["provenance"]
    assert isinstance(provenance, dict)
    provenance["schema_version"] = 99
    with pytest.raises(RecordSchemaError, match="must be 1"):
        validate_record(record)


def test_v1_requires_tri_state_envelope_fields() -> None:
    record = _generated_record()
    envelope = record["envelope_result"]
    assert isinstance(envelope, dict)
    envelope.pop("unresolved")
    with pytest.raises(RecordSchemaError, match=r"envelope_result.*unresolved"):
        validate_record(record)


def test_v1_allows_empty_envelope_only_for_indeterminate_early_stop() -> None:
    record = _early_stop_record()
    assert validate_record(record) == 1
    schema = json.loads((ROOT / RECORD_SCHEMA_REF).read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(record)

    record["state"] = "verified"
    with pytest.raises(RecordSchemaError, match="may be empty only"):
        validate_record(record)
    assert list(Draft202012Validator(schema).iter_errors(record))


def test_legacy_auto_detection_is_scoped_to_repository_evidence(tmp_path: Path) -> None:
    record = json.loads(
        (RECORDS / "estate-window-2" / "records" / "r1-migtable.json").read_text()
    )
    lookalike = tmp_path / "docs" / "estate-window-2" / "records" / "record.json"
    lookalike.parent.mkdir(parents=True)
    lookalike.write_text(json.dumps(record), encoding="utf-8")

    with pytest.raises(RecordSchemaError, match="missing schema stamp"):
        load_record(lookalike)

    unknown_banked_name = RECORDS / "estate-window-2" / "records" / "unknown.json"
    with pytest.raises(RecordSchemaError, match="missing schema stamp"):
        validate_record(record, source=unknown_banked_name)
