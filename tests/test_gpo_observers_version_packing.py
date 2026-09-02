"""Tests for GPT.INI / AD versionNumber packing and GPT.INI parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from gpo_observers import version_packing
from gpo_observers.facts import declared_category

GPO_ROOT = Path(__file__).parent / "fixtures" / "gpo-tree" / "11111111-2222-3333-4444-555555555555"


class TestUnpack:
    def test_fixture_version_65537_is_machine_1_user_1(self) -> None:
        assert version_packing.unpack(65537) == (1, 1)
        assert version_packing.unpack(0x00010001) == (1, 1)

    def test_upper_half_is_user_lower_is_machine(self) -> None:
        # 0xFFFF0000: user 65535, machine 0.
        assert version_packing.unpack(0xFFFF0000) == (0, 65535)
        assert version_packing.unpack(0x0001FFFF) == (65535, 1)
        assert version_packing.unpack(0x0002000A) == (10, 2)

    def test_edges(self) -> None:
        assert version_packing.unpack(0) == (0, 0)
        assert version_packing.unpack(0xFFFFFFFF) == (65535, 65535)

    @pytest.mark.parametrize("version", [-1, 0x100000000, 2**40])
    def test_out_of_range_raises(self, version: int) -> None:
        with pytest.raises(ValueError):
            version_packing.unpack(version)


class TestPack:
    def test_pack_is_the_inverse_of_unpack(self) -> None:
        for version in (0, 1, 65537, 0xFFFF0000, 0x0001FFFF, 0xFFFFFFFF):
            machine, user = version_packing.unpack(version)
            assert version_packing.pack(machine, user) == version

    def test_pack_validates_halves(self) -> None:
        with pytest.raises(ValueError):
            version_packing.pack(0x10000, 0)
        with pytest.raises(ValueError):
            version_packing.pack(0, -1)
        assert version_packing.pack(1, 1) == 65537


class TestGptIniParsing:
    def test_fixture_gpt_ini(self) -> None:
        data = (GPO_ROOT / "GPT.INI").read_bytes()
        text, bom_kind, bom_width = version_packing.decode_gpt_ini_bytes(data)
        assert bom_kind == "utf-16le"
        assert bom_width == 2
        gpt = version_packing.parse_gpt_ini_text(text)
        assert gpt.general_present is True
        assert gpt.version_raw == "65537"
        assert gpt.version == 65537
        assert gpt.display_name == "New Group Policy Object"
        assert version_packing.unpack(gpt.version) == (1, 1)

    def test_gpt_ini_facts_mark_display_name_as_identity(self) -> None:
        data = (GPO_ROOT / "GPT.INI").read_bytes()
        text, _kind, _width = version_packing.decode_gpt_ini_bytes(data)
        facts = version_packing.gpt_ini_facts(version_packing.parse_gpt_ini_text(text))
        assert facts["version.raw"] == "65537"
        assert facts["version.machine"] == 1
        assert facts["version.user"] == 1
        assert facts["version.displayName"] == "New Group Policy Object"
        for key, value in facts.items():
            category, subcategory = declared_category(key)
            if key == "version.displayName":
                assert category == "identity"
            else:
                assert category == "structural", (key, value)
            assert subcategory is None

    def test_ascii_gpt_ini(self) -> None:
        text = "[General]\r\nVersion=131073\r\ndisplayName=Synthetic GPO\r\n"
        gpt = version_packing.parse_gpt_ini_text(text)
        assert gpt.version == 131073
        assert version_packing.unpack(gpt.version) == (1, 2)

    def test_keys_are_case_insensitive(self) -> None:
        text = "[general]\r\nVERSION=2\r\nDISPLAYNAME=Case Test\r\n"
        gpt = version_packing.parse_gpt_ini_text(text)
        assert gpt.version == 2
        assert gpt.display_name == "Case Test"

    def test_missing_general_section_still_finds_version(self) -> None:
        text = "Version=65537\r\n"
        gpt = version_packing.parse_gpt_ini_text(text)
        assert gpt.general_present is False
        assert gpt.version == 65537

    def test_missing_version(self) -> None:
        gpt = version_packing.parse_gpt_ini_text("[General]\r\ndisplayName=X\r\n")
        assert gpt.version_raw is None
        assert gpt.version is None
        assert gpt.display_name == "X"

    def test_non_numeric_version_keeps_raw(self) -> None:
        gpt = version_packing.parse_gpt_ini_text("[General]\r\nVersion=not-a-number\r\n")
        assert gpt.version_raw == "not-a-number"
        assert gpt.version is None

    def test_other_sections_are_ignored(self) -> None:
        text = "[General]\r\nVersion=65537\r\n[Other]\r\nVersion=1\r\n"
        gpt = version_packing.parse_gpt_ini_text(text)
        assert gpt.version == 65537

    def test_utf8_bom_decode(self) -> None:
        data = b"\xef\xbb\xbf" + b"[General]\r\nVersion=3\r\n"
        text, kind, width = version_packing.decode_gpt_ini_bytes(data)
        assert (kind, width) == ("utf-8", 3)
        assert version_packing.parse_gpt_ini_text(text).version == 3

    def test_cp1252_fallback(self) -> None:
        data = b"[General]\r\nVersion=3\r\n; caf\xe9\r\n"
        text, kind, width = version_packing.decode_gpt_ini_bytes(data)
        assert (kind, width) == ("none", 0)
        assert "caf\xe9" in text
