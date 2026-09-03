"""Tests for the R3/R4 observers: GptTmpl.inf and fdeploy.ini parsers.

Fixtures are byte-exact synthetic files (UTF-16LE BOM + CRLF, the shapes the
native writers are expected to produce); the parsers' real work is the R4/R5
captures' answer, never an assumption baked in here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gpo_observers import fdeploy_ini, gpttmpl_inf
from gpo_observers.facts import declared_category

FIXTURES = Path(__file__).parent / "fixtures" / "r3-r4"


@pytest.fixture(scope="module")
def gpttmpl_bytes() -> bytes:
    return (FIXTURES / "GptTmpl.inf").read_bytes()


@pytest.fixture(scope="module")
def fdeploy_bytes() -> bytes:
    return (FIXTURES / "fdeploy.ini").read_bytes()


class TestGptTmpl:
    def test_encoding_facts(self, gpttmpl_bytes: bytes) -> None:
        tree = gpttmpl_inf.gpttmpl_fact_tree(gpttmpl_bytes)
        assert tree["encoding"]["bom"] == "utf16le"
        assert tree["encoding"]["crlf_only"] is True

    def test_registry_keys_carry_propagation_codes(self, gpttmpl_bytes: bytes) -> None:
        tree = gpttmpl_inf.gpttmpl_fact_tree(gpttmpl_bytes)
        keys = tree["registry_keys"]
        assert [k["key_path"] for k in keys] == [
            "MACHINE\\SOFTWARE\\zzStudioAlpha",
            "MACHINE\\SOFTWARE\\zzStudioBravo",
            "MACHINE\\SOFTWARE\\zzStudioCharlie",
        ]
        # The fixture models the *native shape*, not the R4 answer: the codes
        # here are synthetic and distinct so a parser mixup is visible.
        assert [k["propagation_code"] for k in keys] == [2, 1, 0]
        assert all(k["shape"] == "quoted_csv" for k in keys)
        assert all(k["sddl"] == "D:PAR(A;OICI;FA;;;BA)" for k in keys)

    def test_file_security_same_vocabulary(self, gpttmpl_bytes: bytes) -> None:
        tree = gpttmpl_inf.gpttmpl_fact_tree(gpttmpl_bytes)
        (entry,) = tree["file_security"]
        assert entry["key_path"] == "C:\\zzStudioData"
        assert entry["propagation_code"] == 1

    def test_group_membership_keyed_by_raw_key(self, gpttmpl_bytes: bytes) -> None:
        # Keyed by whatever the file carries -- SID or name is the R4 answer.
        tree = gpttmpl_inf.gpttmpl_fact_tree(gpttmpl_bytes)
        assert tree["group_membership"] == {
            "*S-1-5-32-544__Members": "*S-1-5-21-1111111111-2222222222-3333333333-512"
        }

    def test_system_access_key_values(self, gpttmpl_bytes: bytes) -> None:
        tree = gpttmpl_inf.gpttmpl_fact_tree(gpttmpl_bytes)
        assert tree["system_access"]["LockoutBadCount"] == "13"

    def test_service_general_stays_bare_csv(self, gpttmpl_bytes: bytes) -> None:
        tree = gpttmpl_inf.gpttmpl_fact_tree(gpttmpl_bytes)
        (entry,) = tree["service_general"]
        assert entry["shape"] == "quoted_csv"
        assert entry["fields"] == ["wuauserv", "3", "2"]

    def test_bomless_utf8_decodes_with_none_bom(self) -> None:
        raw = b"[Unicode]\r\nUnicode=yes\r\n"
        tree = gpttmpl_inf.gpttmpl_fact_tree(raw)
        assert tree["encoding"]["bom"] == "none"

    def test_key_value_shape_recorded_per_section(self, gpttmpl_bytes: bytes) -> None:
        tree = gpttmpl_inf.gpttmpl_fact_tree(gpttmpl_bytes)
        by_name = {s["name"]: s for s in tree["sections"]}
        assert by_name["System Access"]["key_value_shape"] is True
        assert by_name["Registry Keys"]["key_value_shape"] is False


class TestFdeploy:
    def test_encoding_facts(self, fdeploy_bytes: bytes) -> None:
        tree = fdeploy_ini.fdeploy_fact_tree(fdeploy_bytes)
        assert tree["encoding"]["bom"] == "utf16le"
        assert tree["encoding"]["crlf_only"] is True

    def test_entries_carry_section_key_value(self, fdeploy_bytes: bytes) -> None:
        tree = fdeploy_ini.fdeploy_fact_tree(fdeploy_bytes)
        entries = tree["entries"]
        assert entries[0]["section"] == "Initialize"
        assert entries[0]["key"] == "SidsAddedByGPMC"
        assert entries[1]["section"] == "{25537BA6-77A8-11D2-9B6C-0000F8080861}"
        assert "%username%" in entries[1]["value"]


class TestFactCategories:
    def test_new_fact_families_declared_content(self) -> None:
        for key in (
            "gpttmpl.present",
            "gpttmpl.encoding.bom",
            "gpttmpl.registry_keys.0.propagation_code",
            "fdeploy.present",
            "fdeploy.entries.0.value",
            "migtable.mapping.0.source.name",
        ):
            category, _ = declared_category(key)
            assert category == "content", key
