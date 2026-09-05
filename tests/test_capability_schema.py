"""Draft 2020-12 validation for every shipped capability document."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "docs" / "capability-schema-v0.json"
CAPABILITIES = tuple(sorted((REPO_ROOT / "capabilities").glob("*.json")))


def _read(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _validator() -> Draft202012Validator:
    schema = _read(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _assert_invalid(document: dict[str, Any]) -> None:
    assert list(_validator().iter_errors(document))


def test_every_shipped_capability_validates_against_v0_schema() -> None:
    validator = _validator()
    assert CAPABILITIES, "the schema test must cover at least one capability"
    for path in CAPABILITIES:
        assert not list(validator.iter_errors(_read(path))), path.name


def test_qualification_ledger_tracks_every_current_capability_revision() -> None:
    ledger = (REPO_ROOT / "docs" / "capability-qualification.md").read_text(
        encoding="utf-8"
    )
    for path in CAPABILITIES:
        capability = _read(path)
        row_prefix = f"| `{capability['id']}` | {capability['revision']} |"
        assert row_prefix in ledger, f"qualification ledger drift for {path.name}"


def test_schema_rejects_unknown_document_and_envelope_keys() -> None:
    capability = _read(CAPABILITIES[0])

    unknown_top_level = copy.deepcopy(capability)
    unknown_top_level["typo"] = True
    _assert_invalid(unknown_top_level)

    unknown_envelope = copy.deepcopy(capability)
    unknown_envelope["envelope"]["require"][0]["predciate"] = unknown_envelope[
        "envelope"
    ]["require"][0].pop("predicate")
    _assert_invalid(unknown_envelope)


def test_schema_rejects_malformed_parameter_and_observer_shapes() -> None:
    scripts = _read(REPO_ROOT / "capabilities" / "gpmc.author_scripts_entry.json")
    malformed_parameter = copy.deepcopy(scripts)
    malformed_parameter["parameters"]["properties"]["script1_name"]["unexpected"] = True
    _assert_invalid(malformed_parameter)

    migration = _read(REPO_ROOT / "capabilities" / "setup.author_migration_table.json")
    malformed_observer = copy.deepcopy(migration)
    malformed_observer["fact_plan"]["observers"][0]["params"]["relpath"] = (
        "also-present"
    )
    _assert_invalid(malformed_observer)

    folder = _read(REPO_ROOT / "capabilities" / "gpmc.author_folder_redirection.json")
    wrong_observer_parameter = copy.deepcopy(folder)
    wrong_observer_parameter["fact_plan"]["observers"][1]["params"] = {
        "path": "User\\Documents & Settings\\fdeploy.ini"
    }
    _assert_invalid(wrong_observer_parameter)


def test_schema_rejects_a_clause_free_envelope() -> None:
    capability = _read(CAPABILITIES[0])
    capability["envelope"]["require"] = []
    capability["envelope"]["forbid"] = []
    capability["envelope"]["derive"] = []
    _assert_invalid(capability)
