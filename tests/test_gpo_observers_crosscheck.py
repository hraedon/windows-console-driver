"""Optional cross-check: gpo_observers vs gpo_studio.script_policy.

The two implementations are independent; where they agree on the same
fixture bytes, that agreement is evidence, and where they disagree, one of
them is wrong. This comparison lives in the TEST only -- the observer
implementation never imports the product. gpo_studio is not installed in the
repo venv (and must not be pip-installed into it); the test looks for it in
the environment or in a sibling checkout and skips when unavailable.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "gpo-tree"
GPO_ROOT = FIXTURES / "11111111-2222-3333-4444-555555555555"
VARIANTS = FIXTURES / "_variants"


def _load_script_policy() -> ModuleType | None:
    if importlib.util.find_spec("gpo_studio") is not None:
        from importlib import import_module

        module = import_module("gpo_studio.script_policy")
        return module
    sibling = Path(__file__).resolve().parents[2] / "gpo-studio" / "src"
    if (sibling / "gpo_studio").is_dir():
        sys.path.insert(0, str(sibling))
        try:
            from importlib import import_module

            return import_module("gpo_studio.script_policy")
        except ImportError:
            sys.path.pop(0)
    return None


SCRIPT_POLICY = _load_script_policy()

pytestmark = pytest.mark.skipif(
    SCRIPT_POLICY is None, reason="gpo_studio is not importable; cross-check skipped"
)

_BOOL_TRUE = {"1", "true", "yes"}


def _gpo_bool(raw: str | None) -> bool:
    return raw is not None and raw.strip().lower() in _BOOL_TRUE


def _decode(path: Path) -> str:
    from gpo_observers import scripts_ini

    document = scripts_ini.parse_scripts_ini(path.read_bytes())
    return document.text


def test_agreement_on_legacy_scripts_ini() -> None:
    assert SCRIPT_POLICY is not None
    from gpo_observers import scripts_ini

    path = GPO_ROOT / "Machine" / "Scripts" / "scripts.ini"
    mine = scripts_ini.parse_scripts_ini(path.read_bytes())
    theirs = SCRIPT_POLICY.parse_script_policy_ini(_decode(path), powershell=False)

    for section_name, my_section in (
        ("startup", mine.section("Startup")),
        ("shutdown", mine.section("Shutdown")),
    ):
        assert my_section is not None
        their_entries = getattr(theirs, section_name)
        assert len(their_entries) == len(my_section.entries)
        for my_entry, their_entry in zip(my_section.entries, their_entries, strict=True):
            assert their_entry.order == my_entry.index + 1
            assert their_entry.original_name == my_entry.script
            # gpo_studio models a missing Parameters as "".
            expected_parameters = my_entry.parameters if my_entry.parameters is not None else ""
            assert their_entry.parameters == expected_parameters


def test_agreement_on_psscripts_policy_variant() -> None:
    assert SCRIPT_POLICY is not None
    from gpo_observers import scripts_ini

    path = VARIANTS / "psscripts_policy.ini"
    mine = scripts_ini.parse_scripts_ini(path.read_bytes())
    theirs = SCRIPT_POLICY.parse_script_policy_ini(_decode(path), powershell=True)

    my_startup = mine.section("Startup")
    assert my_startup is not None
    assert len(theirs.powershell_startup) == len(my_startup.entries)
    for my_entry, their_entry in zip(my_startup.entries, theirs.powershell_startup, strict=True):
        assert their_entry.original_name == my_entry.script
        assert their_entry.parameters == (my_entry.parameters or "")
        execution_raw = my_entry.props.get("ExecutionMode", "0")
        assert their_entry.execution == ("asynchronous" if execution_raw == "1" else "synchronous")
        assert their_entry.no_profile == _gpo_bool(my_entry.props.get("NoProfile", "0"))
        assert their_entry.non_interactive == _gpo_bool(my_entry.props.get("NonInteractive", "1"))

    # [Policy] section: same booleans, same order semantics.
    assert theirs.run_logon_scripts_sync == _gpo_bool(
        mine.section("Policy").key("RunLogonScriptsSync") if mine.section("Policy") else None
    )
    assert theirs.run_logoff_scripts_sync == _gpo_bool(
        mine.section("Policy").key("RunLogoffScriptsSync") if mine.section("Policy") else None
    )
    assert theirs.legacy_scripts_first == _gpo_bool(
        mine.section("Policy").key("LegacyScriptsFirst") if mine.section("Policy") else None
    )
    order_raw = (
        mine.section("Policy").key("PowerShellOrder") if mine.section("Policy") else None
    )
    assert order_raw is not None
    assert theirs.powershell_order == SCRIPT_POLICY._INI_TO_ORDER.get(order_raw)


def test_agreement_on_psscripts_scripts_config_variant() -> None:
    assert SCRIPT_POLICY is not None
    from gpo_observers import scripts_ini

    path = GPO_ROOT / "Machine" / "Scripts" / "psscripts.ini"
    mine = scripts_ini.parse_scripts_ini(path.read_bytes())
    theirs = SCRIPT_POLICY.parse_script_policy_ini(_decode(path), powershell=True)

    # gpo_studio models only the [Policy] shape, so it must report the
    # defaults for a [ScriptsConfig]-shaped file; the entries must still
    # agree exactly.
    my_startup = mine.section("Startup")
    assert my_startup is not None
    assert len(theirs.powershell_startup) == len(my_startup.entries)
    for my_entry, their_entry in zip(my_startup.entries, theirs.powershell_startup, strict=True):
        assert their_entry.original_name == my_entry.script
        assert their_entry.parameters == (my_entry.parameters or "")
    assert theirs.run_logon_scripts_sync is False
    assert theirs.legacy_scripts_first is True
    assert theirs.powershell_order == "not_configured"

    # ... while the observer records the [ScriptsConfig] shape key-by-key.
    shape = scripts_ini.analyze_config_sections(mine)
    assert shape.shape == "scripts_config"
    assert shape.scripts_config.values["StartExecutePSFirst"] == "true"


def test_agreement_on_positional_style_is_not_expected() -> None:
    assert SCRIPT_POLICY is not None
    from gpo_observers import scripts_ini

    # The bare-index positional style ("0=script,params") is part of the
    # observer's defensive parse; gpo_studio does not model it, which is
    # exactly why the observer parses defensively and records raw lines.
    path = VARIANTS / "scripts_ascii_lf.ini"
    mine = scripts_ini.parse_scripts_ini(path.read_bytes())
    theirs = SCRIPT_POLICY.parse_script_policy_ini(_decode(path), powershell=False)
    my_logon = mine.section("Logon")
    assert my_logon is not None
    assert my_logon.entry(0).script == "logon-map-drives.cmd"
    assert list(theirs.logon) == []
