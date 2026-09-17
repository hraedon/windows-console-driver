"""Structural checks for the estate bring-up/teardown operator tools.

The tools' live paths are operator-only (never a default-suite test against
a real host, per both repos' rules); what the suite pins here is structure:
the scripts parse under the only PowerShell on these machines (5.1), stay
pure ASCII, and carry the standing disciplines -- the disposable-guest name
guard, the index-not-character error contract on the secret typing path,
and the named-environment-variable secret route (no literal secret names).
"""

from __future__ import annotations

import re
from pathlib import Path

import ps_scripts
import pytest

TOOLS_DIR = ps_scripts.REPO_ROOT / "tools"
BRINGUP = TOOLS_DIR / "estate_bringup.ps1"
TEARDOWN = TOOLS_DIR / "estate_teardown.ps1"


@pytest.mark.parametrize("tool", [BRINGUP, TEARDOWN], ids=["bringup", "teardown"])
def test_tool_parses_under_windows_powershell_51(tool: Path) -> None:
    ps_scripts.parse_check(tool)


@pytest.mark.parametrize("tool", [BRINGUP, TEARDOWN], ids=["bringup", "teardown"])
def test_tool_is_pure_ascii(tool: Path) -> None:
    ps_scripts.assert_ascii_only(tool)


@pytest.mark.parametrize("tool", [BRINGUP, TEARDOWN], ids=["bringup", "teardown"])
def test_tool_takes_the_disposable_guest_name_guard(tool: Path) -> None:
    text = tool.read_text(encoding="ascii")
    assert "^[Ll]ab[A-Za-z0-9]{1,12}$" in text


def test_bringup_reports_indexes_never_characters_on_the_secret_path() -> None:
    text = BRINGUP.read_text(encoding="ascii")
    assert "character index" in text
    # The discipline the unlock path set in PR #7: the failure names the
    # index and the count, never the character.
    assert "the character itself is not reported" in text


def test_bringup_reads_secrets_only_through_the_named_env_var() -> None:
    text = BRINGUP.read_text(encoding="ascii")
    assert "GetEnvironmentVariable($estateTable['password_env'])" in text
    # No literal secret variable name baked into the tool: the estate file
    # names it, the tool resolves whatever it names.
    assert "WCD_LAB_PASSWORD" not in text


def test_bringup_keeps_guest_scripts_as_strings_not_scriptblocks() -> None:
    # A scriptblock cannot survive the controller -> host hop as data (the
    # remoting serialization refuses it); the tool must compile strings in
    # the host runspace instead. The pattern is the guard against quietly
    # reintroducing the broken shape.
    text = BRINGUP.read_text(encoding="ascii")
    assert "[scriptblock]::Create($scriptText)" in text


def test_teardown_shuts_down_guest_initiated_not_stop_vm_force() -> None:
    text = TEARDOWN.read_text(encoding="ascii")
    code = re.sub(r"<#.*?#>", "", text, flags=re.DOTALL)  # drop comment-based help
    assert "shutdown.exe /s" in code
    assert "Stop-VM" not in code
