"""Tests for the bytes-level scripts.ini / psscripts.ini parser.

Covers the R2 question space: UTF-16LE BOM vs ASCII vs UTF-8-BOM vs BOM-less,
CRLF vs LF, the [Policy] vs [ScriptsConfig] config-section shapes, split vs
positional entry styles, and defensive handling of malformed content.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gpo_observers import scripts_ini
from gpo_observers.facts import declared_category

FIXTURES = Path(__file__).parent / "fixtures" / "gpo-tree"
GPO_ROOT = FIXTURES / "11111111-2222-3333-4444-555555555555"
VARIANTS = FIXTURES / "_variants"


def _utf16le(text: str) -> bytes:
    return b"\xff\xfe" + text.encode("utf-16-le")


class TestEncodingFacts:
    def test_main_scripts_ini_is_utf16le_with_crlf(self) -> None:
        path = GPO_ROOT / "Machine" / "Scripts" / "scripts.ini"
        data = path.read_bytes()
        document = scripts_ini.parse_scripts_ini(data)
        assert document.bom.kind == "utf-16le"
        assert document.bom.width == 2
        # 8 lines, every one CRLF-terminated.
        assert document.cr_count == 8
        assert document.lf_count == 8
        assert document.total_bytes == len(data)
        assert document.total_bytes == path.stat().st_size
        assert document.fallback_codec is None

    def test_bom_less_ascii_lf_variant(self) -> None:
        document = scripts_ini.parse_scripts_ini((VARIANTS / "scripts_ascii_lf.ini").read_bytes())
        assert document.bom.kind == "none"
        assert document.bom.width == 0
        assert document.cr_count == 0
        assert document.lf_count == 3

    def test_utf8_bom_crlf_variant_decodes_non_ascii(self) -> None:
        document = scripts_ini.parse_scripts_ini(
            (VARIANTS / "scripts_utf8bom_crlf.ini").read_bytes()
        )
        assert document.bom.kind == "utf-8"
        assert document.bom.width == 3
        assert document.cr_count == 3
        startup = document.section("Startup")
        assert startup is not None
        entry = startup.entry(0)
        assert entry is not None
        assert entry.script == "d\u00e9cor-setup.cmd"

    def test_cp1252_fallback_is_recorded(self) -> None:
        data = b"[Startup]\r\n0CmdLine=caf\xe9.cmd\r\n"
        document = scripts_ini.parse_scripts_ini(data)
        assert document.bom.kind == "none"
        assert document.fallback_codec == "cp1252"
        startup = document.section("Startup")
        assert startup is not None
        entry = startup.entry(0)
        assert entry is not None
        assert entry.script == "caf\xe9.cmd"


class TestEntrySemantics:
    def test_split_style_entries(self) -> None:
        document = scripts_ini.parse_scripts_ini(
            (GPO_ROOT / "Machine" / "Scripts" / "scripts.ini").read_bytes()
        )
        startup = document.section("Startup")
        assert startup is not None
        first = startup.entry(0)
        second = startup.entry(1)
        assert first is not None and second is not None
        assert first.script == "agent-startup.cmd"
        assert first.parameters == "/quiet"
        assert first.style == "split"
        assert first.raw_line == "0CmdLine=agent-startup.cmd"
        assert first.props == {"CmdLine": "agent-startup.cmd", "Parameters": "/quiet"}
        # "1Parameters=" is an explicitly empty parameter list.
        assert second.script == "collect-evidence.vbs"
        assert second.parameters == ""
        assert second.raw_line == "1CmdLine=collect-evidence.vbs"

    def test_shutdown_section(self) -> None:
        document = scripts_ini.parse_scripts_ini(
            (GPO_ROOT / "Machine" / "Scripts" / "scripts.ini").read_bytes()
        )
        shutdown = document.section("shutdown")  # case-insensitive lookup
        assert shutdown is not None
        assert shutdown.name == "Shutdown"
        entry = shutdown.entry(0)
        assert entry is not None
        assert entry.script == "agent-shutdown.cmd"
        # "0Parameters=" with no value: explicitly empty parameters.
        assert entry.parameters == ""

    def test_missing_parameters_line_is_none_not_empty(self) -> None:
        document = scripts_ini.parse_scripts_ini(
            _utf16le("[Shutdown]\r\n0CmdLine=only.cmd\r\n")
        )
        shutdown = document.section("Shutdown")
        assert shutdown is not None
        entry = shutdown.entry(0)
        assert entry is not None
        assert entry.script == "only.cmd"
        assert entry.parameters is None

    def test_positional_style_entries(self) -> None:
        document = scripts_ini.parse_scripts_ini((VARIANTS / "scripts_ascii_lf.ini").read_bytes())
        logon = document.section("Logon")
        assert logon is not None
        first = logon.entry(0)
        second = logon.entry(1)
        assert first is not None and second is not None
        assert first.style == "positional"
        assert first.script == "logon-map-drives.cmd"
        assert first.parameters == "/verbose"
        assert first.raw_line == "0=logon-map-drives.cmd,/verbose"
        assert first.props == {}
        # "1=logon-audit.vbs," has an explicit trailing empty parameter.
        assert second.script == "logon-audit.vbs"
        assert second.parameters == ""

    def test_positional_without_comma_is_all_script(self) -> None:
        document = scripts_ini.parse_scripts_ini(_utf16le("[Logon]\r\n0=solo.cmd\r\n"))
        logon = document.section("Logon")
        entry = logon.entry(0) if logon else None
        assert entry is not None
        assert entry.script == "solo.cmd"
        assert entry.parameters is None

    def test_positional_empty_value(self) -> None:
        document = scripts_ini.parse_scripts_ini(_utf16le("[Logon]\r\n0=\r\n"))
        logon = document.section("Logon")
        entry = logon.entry(0) if logon else None
        assert entry is not None
        assert entry.script is None
        assert entry.parameters is None

    def test_first_comma_splits_and_rest_stays_in_parameters(self) -> None:
        document = scripts_ini.parse_scripts_ini(
            _utf16le("[Logon]\r\n0=tool.cmd,-a x,y\r\n")
        )
        logon = document.section("Logon")
        entry = logon.entry(0) if logon else None
        assert entry is not None
        assert entry.script == "tool.cmd"
        assert entry.parameters == "-a x,y"

    def test_mixed_styles_prefer_split_fields(self) -> None:
        document = scripts_ini.parse_scripts_ini(
            _utf16le("[Startup]\r\n0=legacy.cmd,x\r\n0CmdLine=new.cmd\r\n")
        )
        startup = document.section("Startup")
        entry = startup.entry(0) if startup else None
        assert entry is not None
        assert entry.style == "mixed"
        assert entry.script == "new.cmd"
        assert entry.raw_line == "0CmdLine=new.cmd"

    def test_sections_are_case_insensitive_and_case_is_preserved(self) -> None:
        document = scripts_ini.parse_scripts_ini(_utf16le("[STARTUP]\r\n0CmdLine=a.cmd\r\n"))
        assert document.section("startup") is not None
        assert document.section("Startup") is not None
        assert document.section("STARTUP") is not None
        assert document.sections[0].name == "STARTUP"

    def test_duplicate_sections_merge(self) -> None:
        document = scripts_ini.parse_scripts_ini(
            _utf16le("[Startup]\r\n0CmdLine=a.cmd\r\n[Startup]\r\n1CmdLine=b.cmd\r\n")
        )
        assert len(document.sections) == 1
        startup = document.section("Startup")
        assert startup is not None
        assert startup.entry(0) is not None
        assert startup.entry(1) is not None

    def test_keys_before_any_section_are_kept_as_orphans(self) -> None:
        document = scripts_ini.parse_scripts_ini(_utf16le("0=stray.cmd\r\n[Startup]\r\n"))
        orphans = document.section("")
        assert orphans is not None
        entry = orphans.entry(0)
        assert entry is not None
        assert entry.script == "stray.cmd"

    def test_unparsed_lines_are_recorded(self) -> None:
        document = scripts_ini.parse_scripts_ini(
            _utf16le("[Startup]\r\nnot-a-key-value\r\n0CmdLine=a.cmd\r\n")
        )
        assert document.unparsed_lines == ("not-a-key-value",)

    def test_comments_and_blank_lines_are_skipped(self) -> None:
        document = scripts_ini.parse_scripts_ini(
            _utf16le("; comment\r\n\r\n[Startup]\r\n; another\r\n0CmdLine=a.cmd\r\n")
        )
        startup = document.section("Startup")
        assert startup is not None
        assert len(startup.entries) == 1
        assert startup.other_keys == ()

    def test_non_entry_keys_are_recorded(self) -> None:
        document = scripts_ini.parse_scripts_ini(
            _utf16le("[Startup]\r\n0CmdLine=a.cmd\r\nSomeKey=some value\r\n")
        )
        startup = document.section("Startup")
        assert startup is not None
        assert startup.other_keys == (("SomeKey", "some value"),)


class TestConfigSectionShapes:
    def test_scripts_config_shape_in_main_fixture(self) -> None:
        document = scripts_ini.parse_scripts_ini(
            (GPO_ROOT / "Machine" / "Scripts" / "psscripts.ini").read_bytes()
        )
        shape = scripts_ini.analyze_config_sections(document)
        assert shape.shape == "scripts_config"
        assert shape.scripts_config.present is True
        assert shape.scripts_config.section_name == "ScriptsConfig"
        assert shape.scripts_config.values == {
            "StartExecutePSFirst": "true",
            "EndExecutePSFirst": "false",
        }
        assert shape.policy.present is False
        assert shape.policy.values == {
            "RunLogonScriptsSync": None,
            "RunLogoffScriptsSync": None,
            "LegacyScriptsFirst": None,
            "PowerShellOrder": None,
        }

    def test_policy_shape_in_variant_fixture(self) -> None:
        document = scripts_ini.parse_scripts_ini((VARIANTS / "psscripts_policy.ini").read_bytes())
        assert document.bom.kind == "utf-16le"
        shape = scripts_ini.analyze_config_sections(document)
        assert shape.shape == "policy"
        assert shape.policy.present is True
        assert shape.policy.section_name == "Policy"
        assert shape.policy.values == {
            "RunLogonScriptsSync": "1",
            "RunLogoffScriptsSync": "0",
            "LegacyScriptsFirst": "1",
            "PowerShellOrder": "RunPowerShellLast",
        }
        assert shape.scripts_config.present is False

    def test_both_shapes_present(self) -> None:
        text = (
            "[Policy]\r\nRunLogonScriptsSync=1\r\n"
            "[ScriptsConfig]\r\nStartExecutePSFirst=false\r\n"
        )
        document = scripts_ini.parse_scripts_ini(_utf16le(text))
        assert scripts_ini.analyze_config_sections(document).shape == "both"

    def test_no_config_section(self) -> None:
        document = scripts_ini.parse_scripts_ini(
            (VARIANTS / "scripts_ascii_lf.ini").read_bytes()
        )
        assert scripts_ini.analyze_config_sections(document).shape == "none"

    def test_modeled_keys_are_case_insensitive(self) -> None:
        text = "[policy]\r\nrunlogonscriptssync=1\r\npowershellorder=NotConfigured\r\n"
        document = scripts_ini.parse_scripts_ini(_utf16le(text))
        shape = scripts_ini.analyze_config_sections(document)
        assert shape.shape == "policy"
        assert shape.policy.values["RunLogonScriptsSync"] == "1"
        assert shape.policy.values["PowerShellOrder"] == "NotConfigured"

    def test_extra_keys_in_config_section_are_recorded(self) -> None:
        text = "[Policy]\r\nRunLogonScriptsSync=1\r\nSomethingElse=x\r\n"
        document = scripts_ini.parse_scripts_ini(_utf16le(text))
        shape = scripts_ini.analyze_config_sections(document)
        assert shape.policy.extra_keys == (("SomethingElse", "x"),)


class TestFactKeys:
    def test_scripts_ini_fact_keys_and_categories(self) -> None:
        document = scripts_ini.parse_scripts_ini(
            (GPO_ROOT / "Machine" / "Scripts" / "scripts.ini").read_bytes()
        )
        facts = scripts_ini.scripts_ini_facts(document, side="machine")
        assert facts["scripts_ini.machine.present"] is True
        assert facts["scripts_ini.machine.encoding.bom"] == "utf-16le"
        assert facts["scripts_ini.machine.encoding.bom_width"] == 2
        assert facts["scripts_ini.machine.encoding.total_bytes"] > 0
        assert facts["scripts_ini.machine.Startup.0.script"] == "agent-startup.cmd"
        assert facts["scripts_ini.machine.Startup.0.raw"] == "0CmdLine=agent-startup.cmd"
        assert facts["scripts_ini.machine.config_shape"] == "none"
        for key in facts:
            category, _ = declared_category(key)
            assert category == "content", key

    def test_psscripts_fact_keys_use_ps_prefix(self) -> None:
        document = scripts_ini.parse_scripts_ini(
            (VARIANTS / "psscripts_policy.ini").read_bytes()
        )
        facts = scripts_ini.psscripts_ini_facts(document, side="machine")
        assert facts["scripts_ini.ps.machine.present"] is True
        assert facts["scripts_ini.ps.machine.Startup.0.script"] == "bootstrap-evidence.ps1"
        assert facts["scripts_ini.ps.machine.Startup.0.prop.ExecutionMode"] == "1"
        assert facts["scripts_ini.ps.machine.Startup.0.prop.NoProfile"] == "1"
        assert facts["scripts_ini.ps.machine.config_shape"] == "policy"
        assert facts["scripts_ini.ps.machine.policy.PowerShellOrder"] == "RunPowerShellLast"
        for key in facts:
            category, _ = declared_category(key)
            assert category == "content", key

    def test_absent_facts_are_stable_keys_with_nulls(self) -> None:
        absent = scripts_ini.absent_scripts_ini_facts(side="machine")
        assert absent["scripts_ini.machine.present"] is False
        assert absent["scripts_ini.machine.encoding.bom"] is None
        assert absent["scripts_ini.machine.encoding.total_bytes"] is None
        assert absent["scripts_ini.machine.config_shape"] == "none"
        assert absent["scripts_ini.machine.policy.LegacyScriptsFirst"] is None
        assert "scripts_ini.machine.Startup.0.script" not in absent
        present = scripts_ini.scripts_ini_facts(
            scripts_ini.parse_scripts_ini(
                (GPO_ROOT / "Machine" / "Scripts" / "scripts.ini").read_bytes()
            ),
            side="machine",
        )
        # Every stable key in the present set also exists in the absent set.
        stable = [key for key in present if ".Startup." not in key and ".Shutdown." not in key]
        assert set(stable) <= set(absent)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\xff\xfe",
        b"\xef\xbb\xbf",
        b"[Startup",
        b"=value-only\r\n",
    ],
)
def test_defensive_against_degenerate_bytes(data: bytes) -> None:
    document = scripts_ini.parse_scripts_ini(data)
    assert document.total_bytes == len(data)
