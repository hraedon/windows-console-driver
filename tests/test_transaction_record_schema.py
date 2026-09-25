"""Compatibility and wire-contract tests for transaction records."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from wcd.envelope import AssertionResult, FactDelta
from wcd.exec_transaction import RunProvenance, _emit
from wcd.record_schema import (
    RECORD_SCHEMA_REF,
    V1_RECORD_SCHEMA_REF,
    RecordSchemaError,
    load_record,
    validate_record,
)
from wcd.transaction import Transaction

ROOT = Path(__file__).parents[1]
RECORDS = ROOT / "docs"

# One synthetic capability document whose exact text is the binding input.
_CAPABILITY_DOCUMENT: dict[str, object] = {
    "$schema": "docs/capability-schema-v0.json",
    "id": "zz.capability.binding",
    "revision": 3,
}
_CAPABILITY_TEXT = json.dumps(_CAPABILITY_DOCUMENT)
_CAPABILITY_DIGEST = hashlib.sha256(_CAPABILITY_TEXT.encode("utf-8")).hexdigest()


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


def _bound_record() -> dict[str, object]:
    """A v2 record: the same terminal transaction, minted with the binding.

    The binding is what ``execute_transaction`` computes when its caller
    supplied the exact capability text -- the document's declared revision and
    a SHA-256 over that text -- so this fixture is constructed the same way,
    from the same inputs.
    """
    record = _generated_record()
    provenance = record["provenance"]
    assert isinstance(provenance, dict)
    provenance["$schema"] = RECORD_SCHEMA_REF
    provenance["schema_version"] = 2
    provenance["capability_revision"] = _CAPABILITY_DOCUMENT["revision"]
    provenance["capability_sha256"] = _CAPABILITY_DIGEST
    return record


def test_generated_record_is_v1_and_preserves_five_top_level_wire_keys() -> None:
    record = _generated_record()

    assert set(record) == {"state", "verdict", "envelope_result", "events", "provenance"}
    assert validate_record(record) == 1
    provenance = record["provenance"]
    assert isinstance(provenance, dict)
    # No capability text was supplied, so there is no content to bind and the
    # executor stamps the frozen v1 document rather than minting an unbacked
    # v2 binding.
    assert provenance["$schema"] == V1_RECORD_SCHEMA_REF
    assert provenance["schema_version"] == 1

    schema = json.loads((ROOT / V1_RECORD_SCHEMA_REF).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(record)


def test_bound_record_is_v2_and_carries_the_capability_binding() -> None:
    record = _bound_record()

    assert set(record) == {"state", "verdict", "envelope_result", "events", "provenance"}
    assert validate_record(record) == 2
    provenance = record["provenance"]
    assert isinstance(provenance, dict)
    assert provenance["$schema"] == RECORD_SCHEMA_REF
    assert provenance["schema_version"] == 2
    assert provenance["capability_revision"] == 3
    assert provenance["capability_sha256"] == _CAPABILITY_DIGEST

    schema = json.loads((ROOT / RECORD_SCHEMA_REF).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(record)


def test_v2_without_the_binding_fields_is_refused() -> None:
    record = _bound_record()
    provenance = record["provenance"]
    assert isinstance(provenance, dict)
    provenance.pop("capability_sha256")
    with pytest.raises(RecordSchemaError, match="capability_sha256"):
        validate_record(record)

    record = _bound_record()
    provenance = record["provenance"]
    assert isinstance(provenance, dict)
    provenance.pop("capability_revision")
    with pytest.raises(RecordSchemaError, match="capability_revision"):
        validate_record(record)


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("capability_revision", 0, "positive integer"),
        ("capability_revision", -1, "positive integer"),
        ("capability_revision", True, "positive integer"),
        ("capability_revision", "3", "positive integer"),
        ("capability_sha256", "z" * 64, "SHA-256"),
        ("capability_sha256", "A" * 64, "SHA-256"),
        ("capability_sha256", "0" * 63, "SHA-256"),
    ],
)
def test_v2_refuses_malformed_binding_values(
    field: str, value: object, reason: str
) -> None:
    record = _bound_record()
    provenance = record["provenance"]
    assert isinstance(provenance, dict)
    provenance[field] = value
    with pytest.raises(RecordSchemaError, match=reason):
        validate_record(record)


def test_v2_refuses_a_stamp_that_mixes_the_versions() -> None:
    record = _bound_record()
    provenance = record["provenance"]
    assert isinstance(provenance, dict)
    provenance["$schema"] = V1_RECORD_SCHEMA_REF
    with pytest.raises(RecordSchemaError, match="must be 1"):
        validate_record(record)

    record = _bound_record()
    provenance = record["provenance"]
    assert isinstance(provenance, dict)
    provenance["$schema"] = "docs/transaction-record-schema-v99.json"
    with pytest.raises(RecordSchemaError, match=r"must be .*schema-v1"):
        validate_record(record)


def test_v2_with_matching_capability_text_validates() -> None:
    assert validate_record(_bound_record(), capability_text=_CAPABILITY_TEXT) == 2


def test_v2_refuses_a_record_whose_digest_does_not_match_the_capability_content() -> None:
    # The record binds the digest of one document; the caller supplies the
    # text of another. The binding is the ONLY claim that this record was
    # produced by that content, so a mismatch is a refusal, not a warning.
    other_text = json.dumps({**_CAPABILITY_DOCUMENT, "intent": "a different document"})
    with pytest.raises(RecordSchemaError, match="does not match the capability content"):
        validate_record(_bound_record(), capability_text=other_text)


def test_v2_refuses_a_record_whose_revision_disagrees_with_the_capability_document() -> None:
    # Digest of the real text, revision of a different one: the two binding
    # fields must agree with the SAME document or the record is not about it.
    record = _bound_record()
    provenance = record["provenance"]
    assert isinstance(provenance, dict)
    provenance["capability_revision"] = 4
    with pytest.raises(RecordSchemaError, match="does not match the capability document"):
        validate_record(record, capability_text=_CAPABILITY_TEXT)


def test_v2_content_check_refuses_text_that_is_not_a_capability_document() -> None:
    with pytest.raises(RecordSchemaError, match="capability_text"):
        validate_record(_bound_record(), capability_text="{zz not json")
    with pytest.raises(RecordSchemaError, match=r"capability_text\.revision"):
        validate_record(_bound_record(), capability_text=json.dumps({"id": "zz.no-revision"}))


def test_v1_records_ignore_the_capability_text_check() -> None:
    # Frozen semantics: a v1 record never carried a binding, so supplying the
    # capability content neither validates nor invalidates it. The v1 corpus
    # must keep verifying exactly as committed.
    assert validate_record(_generated_record(), capability_text=_CAPABILITY_TEXT) == 1


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


def test_committed_records_are_read_without_rewriting_them() -> None:
    # Request-level evidence records (pilot-style work-order captures, e.g.
    # R10) are not transaction records: they carry request-shaped fields and
    # no transaction-record envelope. They live under records/ so the
    # claim-registry citation test can resolve them, and are excluded from
    # this transaction-record wire-contract sweep deliberately.
    request_records = {"r10-record.json"}
    paths = sorted(
        path
        for path in RECORDS.glob("estate-window-*/records/*.json")
        if path.name not in request_records
    )
    assert paths
    before = {path: path.read_bytes() for path in paths}

    versions = {path: load_record(path)[1] for path in paths}

    # Counts of the banked corpus, pinned so that adding a record is a
    # deliberate act and so that BOTH generations stay represented -- the
    # point of the sweep is that v0 records keep being readable without being
    # rewritten, which stops being tested the moment the last one is migrated.
    # Bump these when an estate window banks a new record (window 6 took v1
    # from 6 to 7; window 7 took it from 7 to 8; window 10 banked the first
    # TWO v2 records, the verified run and the pre-commit abort beside it;
    # window 11 took v2 from 2 to 4 with the same pair; window 12 banked the
    # fifth, the WEL-hosted lane's verified run; window 13 banked the sixth,
    # the same lane re-run under a domain_operator-only backend).
    assert sum(version == 0 for version in versions.values()) == 8
    assert sum(version == 1 for version in versions.values()) == 8
    assert sum(version == 2 for version in versions.values()) == 6
    assert all(path.read_bytes() == content for path, content in before.items())
    assert all(
        ("schema_version" not in json.loads(path.read_text())["provenance"])
        == (version == 0)
        for path, version in versions.items()
    )

    validators = {}
    for version in (0, 1, 2):
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
    schema = json.loads((ROOT / V1_RECORD_SCHEMA_REF).read_text(encoding="utf-8"))
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
