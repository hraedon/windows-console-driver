"""Tests for the Fact model and the declared-category table."""

from __future__ import annotations

from datetime import datetime

import pytest

from gpo_observers.facts import (
    KNOWN_CATEGORIES,
    VOLATILE_SUBCATEGORIES,
    FactError,
    FactSet,
    declared_category,
    make_fact,
)


def test_known_categories_are_complete() -> None:
    assert {
        "structural",
        "volatile",
        "file_mtime",
        "content",
        "identity",
        "unclassified",
    } == KNOWN_CATEGORIES
    assert {"timestamps", "replication_metadata"} == VOLATILE_SUBCATEGORIES


@pytest.mark.parametrize(
    ("key", "expected_category", "expected_subcategory"),
    [
        ("gpo_identity.guid", "identity", None),
        ("gpo_identity.domain_dns", "identity", None),
        ("version.displayName", "identity", None),
        ("ad.gPCMachineExtensionNames", "structural", None),
        ("ad.versionNumber", "structural", None),
        ("ad.whenChanged", "volatile", "timestamps"),
        ("ad.uSNChanged", "volatile", "replication_metadata"),
        ("version.raw", "structural", None),
        ("version.machine", "structural", None),
        ("version.user", "structural", None),
        ("version.ad_versionNumber", "structural", None),
        ("scripts_ini.machine.present", "content", None),
        ("scripts_ini.ps.machine.present", "content", None),
        ("scripts_ini.machine.encoding.bom", "content", None),
        ("scripts_ini.ps.machine.encoding.total_bytes", "content", None),
        ("scripts_ini.machine.Startup.0.script", "content", None),
        ("scripts_ini.ps.machine.Startup.0.parameters", "content", None),
        ("scripts_ini.machine.Startup.0.raw", "content", None),
        ("scripts_ini.machine.Startup.0.prop.ExecutionMode", "content", None),
        ("scripts_ini.ps.machine.orphan.0.script", "content", None),
        ("scripts_ini.machine.config_shape", "content", None),
        ("scripts_ini.ps.machine.config_shape", "content", None),
        ("scripts_ini.machine.policy.RunLogonScriptsSync", "content", None),
        ("scripts_ini.ps.machine.scripts_config.StartExecutePSFirst", "content", None),
        ("sysvol.passes_match", "structural", None),
        ("sysvol.Machine/whatever.bin.mtime", "file_mtime", None),
        ("scope.extension_lists.machine", "structural", None),
        ("scope.policies.gpc_guids", "structural", None),
        ("scope.sysvol_relpaths", "structural", None),
        # Deliberate: per-file fingerprint keys have no declared category.
        ("sysvol.Backup.xml.sha256", "unclassified", None),
        ("sysvol.Machine/keepme.txt.bytes", "unclassified", None),
        # Deliberate: unknown keys default to unclassified.
        ("totally.unknown.key", "unclassified", None),
    ],
)
def test_declared_categories(
    key: str, expected_category: str, expected_subcategory: str | None
) -> None:
    category, subcategory = declared_category(key)
    assert category == expected_category
    assert subcategory == expected_subcategory


def test_make_fact_fills_declared_category() -> None:
    fact = make_fact("ad.whenChanged", "2026-09-01T10:00:00.0000000Z")
    assert fact.key == "ad.whenChanged"
    assert fact.category == "volatile"
    assert fact.volatile_subcategory == "timestamps"
    assert make_fact("version.displayName", "New Group Policy Object").category == "identity"
    assert make_fact("sysvol.Machine/x.txt.sha256", "a" * 64).category == "unclassified"


def test_make_fact_rejects_non_json_values() -> None:
    with pytest.raises(FactError):
        make_fact("ad.flags", {1, 2})
    with pytest.raises(FactError):
        make_fact("ad.flags", datetime.now())
    with pytest.raises(FactError):
        make_fact("ad.flags", float("nan"))
    with pytest.raises(FactError):
        make_fact("ad.flags", float("inf"))
    with pytest.raises(FactError):
        make_fact("ad.flags", object())


def test_make_fact_accepts_json_values() -> None:
    fact = make_fact(
        "scope.policies.gpc_guids",
        ["{11111111-2222-3333-4444-555555555555}", "{99999999-8888-7777-6666-555555555555}"],
    )
    assert isinstance(fact.value, list)
    assert fact.value[0].startswith("{")
    assert make_fact("ad.flags", 0).value == 0
    assert make_fact("ad.gPCUserExtensionNames", None).value is None


def test_make_fact_rejects_empty_key() -> None:
    with pytest.raises(FactError):
        make_fact("", 1)


def test_factset_alias_is_a_dict_of_facts() -> None:
    facts: FactSet = {}
    fact = make_fact("version.machine", 1)
    facts[fact.key] = fact
    assert facts["version.machine"].value == 1
