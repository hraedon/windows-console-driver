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
REVERT = TOOLS_DIR / "estate_revert_member.ps1"


@pytest.mark.parametrize(
    "tool", [BRINGUP, TEARDOWN, REVERT], ids=["bringup", "teardown", "revert"]
)
def test_tool_parses_under_windows_powershell_51(tool: Path) -> None:
    ps_scripts.parse_check(tool)


@pytest.mark.parametrize(
    "tool", [BRINGUP, TEARDOWN, REVERT], ids=["bringup", "teardown", "revert"]
)
def test_tool_is_pure_ascii(tool: Path) -> None:
    ps_scripts.assert_ascii_only(tool)


@pytest.mark.parametrize(
    "tool", [BRINGUP, TEARDOWN, REVERT], ids=["bringup", "teardown", "revert"]
)
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


def test_bringup_repairs_the_member_clock_not_just_the_dc() -> None:
    # Window 12 measured a revert-based lane resetting the MEMBER clock to
    # the checkpoint era while this tool's repair was DC-scoped; the canary
    # caught it as kerberos red with every NTLM path green. The member step
    # must keep the DC step's tz-safe Set-Date form and tolerance gate.
    text = BRINGUP.read_text(encoding="ascii")
    code = re.sub(r"<#.*?#>", "", text, flags=re.DOTALL)  # drop comment-based help
    member_step = code[code.index("member-clock") : code.index("console-session")]
    assert "Set-Date -Date ($utcNow.ToLocalTime" in member_step
    assert "$ClockToleranceSec" in member_step


def test_teardown_shuts_down_guest_initiated_not_stop_vm_force() -> None:
    text = TEARDOWN.read_text(encoding="ascii")
    code = re.sub(r"<#.*?#>", "", text, flags=re.DOTALL)  # drop comment-based help
    assert "shutdown.exe /s" in code
    assert "Stop-VM" not in code


def test_revert_tool_restores_headless_then_syncs_the_clock_then_verifies() -> None:
    """Window 19: a revert brings back the checkpoint era's clock and nothing
    on the lab re-syncs it; the tool's time sync must follow the restore and
    precede the read-only secure-channel verification."""
    text = REVERT.read_text(encoding="ascii")
    restore = text.index("Restore-VMSnapshot -VMSnapshot $s -Confirm:$false")
    sync = text.index("Set-Date -Date ($hostUtc + $offset)")
    verify = text.index('"secure_channel=$(Test-ComputerSecureChannel)"')
    assert restore < sync < verify
    # Verification is read-only: the tool never repairs on its own.
    assert "-Repair" not in text.replace("Test-ComputerSecureChannel -Repair (estate", "")


def test_revert_tool_refuses_a_checkpoint_older_than_the_machine_password() -> None:
    text = REVERT.read_text(encoding="ascii")
    precheck = text.index("CompareOrdinal($pwdLastSet, $created)")
    assert precheck < text.index("Restore-VMSnapshot -VMSnapshot $s -Confirm:$false")
    assert "[switch] $Force" in text
    assert "GetEnvironmentVariable($estateTable['password_env'])" in text


def test_bringup_reports_the_machine_key_fault_instead_of_waiting_it_out() -> None:
    text = BRINGUP.read_text(encoding="ascii")
    assert "'credential_invalid'" in text
    assert "$invalidStreak -ge 3" in text
    assert "machine-key fault" in text


def test_revert_tool_requires_rotation_disabled_unless_forced() -> None:
    """Round-2 review (Sol N1): observing DisablePasswordChange is not enough;
    the normal path refuses a member with rotation on."""
    text = REVERT.read_text(encoding="ascii")
    refusal = text.index("if ($disable -ne '1')")
    assert refusal < text.index("Restore-VMSnapshot -VMSnapshot $s -Confirm:$false")
    assert "machine-password rotation is enabled on the member" in text
    # The comment no longer claims a DC guard the code does not have.
    assert "never the DC" not in text
