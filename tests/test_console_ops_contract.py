"""Contract tests for the console-ops embedded scripts (wcd.console_ops).

The real console path needs a lab host (Msvm_Keyboard, PSDirect); what CAN
be verified here is the discipline of the embedded PowerShell itself:

- Structure: both console scripts bind their VM name with ``param()`` (never
  interpolating ``$args`` into a WQL filter) and parse under Windows
  PowerShell 5.1 as pure ASCII, like the rest of the script families.
- The secret discipline: the unlock script's VK mapper reports an unmappable
  character by INDEX, never the character, because every throw message
  becomes a REPL response line and can reach provenance. Verified
  structurally (PowerShell AST: no throw statement and no expandable string
  anywhere in the unlock/credential path references ``$ch``/``$Plain``/the
  REPL's ``$secret``) and functionally (the real unlock script runs under
  PowerShell 5.1 with the CIM cmdlets shadowed by stub functions -- no host,
  no elevation, no injection -- and an unmappable character surfaces only as
  an index while the secret reaches neither output stream).
"""

import re
from pathlib import Path

import ps_scripts
import pytest

from wcd import console_ops

REPL_PATH = ps_scripts.REPO_ROOT / "tools" / "session_repl.ps1"

# CIM stubs: PowerShell resolves a FUNCTION before a cmdlet of the same name,
# so prepending these shadows the CIM calls for the stubbed functional runs.
_CIM_STUBS = r"""
# Test harness prelude: shadow the CIM cmdlets so the script's input path
# runs with no host, no elevation, and no injection. Everything succeeds.
function Get-CimInstance { [pscustomobject]@{ ElementName = 'stub' } }
function Get-CimAssociatedInstance { [pscustomobject]@{ stub = $true } }
function Invoke-CimMethod { [pscustomobject]@{ ReturnValue = 0 } }
function Start-Sleep { }
"""

_AST_FACTS_COMMAND = (
    "$tokens = $null; $errors = $null\n"
    "$ast = [System.Management.Automation.Language.Parser]::ParseFile("
    "{path}, [ref]$tokens, [ref]$errors)\n"
    "foreach ($e in @($errors)) { "
    "Write-Output ('PARSEERROR| ' + $e.Extent.StartLineNumber + ': ' + $e.Message) }\n"
    "foreach ($n in $ast.FindAll({ $args[0] -is "
    "[System.Management.Automation.Language.ThrowStatement] }, $true)) { "
    "Write-Output ('THROW| ' + $n.Extent.Text.Replace(\"`r\", ' ').Replace(\"`n\", ' ')) }\n"
    "foreach ($n in $ast.FindAll({ $args[0] -is "
    "[System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true)) { "
    "Write-Output ('EXPANDABLE| ' + $n.Extent.Text.Replace(\"`r\", ' ').Replace(\"`n\", ' ')) }\n"
)


def _write_script(tmp_path: Path, name: str, source: str) -> Path:
    path = tmp_path / name
    path.write_text(source, encoding="ascii")
    return path


def ast_facts(path: Path) -> tuple[list[str], list[str], list[str]]:
    """Parse a script with the 5.1 AST; return (parse errors, throws, expandables)."""
    proc = ps_scripts.run_powershell_command(
        _AST_FACTS_COMMAND.replace("{path}", ps_scripts.ps_single_quote(str(path)))
    )
    assert proc.returncode == 0, proc.stderr
    parse_errors: list[str] = []
    throws: list[str] = []
    expandables: list[str] = []
    for line in proc.stdout.splitlines():
        if line.startswith("PARSEERROR| "):
            parse_errors.append(line)
        elif line.startswith("THROW| "):
            throws.append(line[len("THROW| ") :])
        elif line.startswith("EXPANDABLE| "):
            expandables.append(line[len("EXPANDABLE| ") :])
    return parse_errors, throws, expandables


def first_significant_line(script: str) -> str:
    """The first statement line: blanks and comments do not count."""
    for line in script.strip().splitlines():
        text = line.strip()
        if text and not text.startswith("#"):
            return text
    return ""


# --- Structural checks on the embedded script sources -------------------------


@pytest.mark.parametrize(
    ("name", "source"),
    [
        ("unlock.ps1", console_ops._UNLOCK_SCRIPT),
        ("wake_display.ps1", console_ops._WAKE_DISPLAY_SCRIPT),
    ],
)
def test_console_scripts_parse_under_windows_powershell_51(
    tmp_path: Path, name: str, source: str
) -> None:
    assert source.isascii(), f"{name} must stay pure ASCII (PS 5.1 reads BOM-less as ANSI)"
    ps_scripts.parse_check(_write_script(tmp_path, name, source))


def test_both_console_scripts_declare_param_first() -> None:
    assert first_significant_line(console_ops._WAKE_DISPLAY_SCRIPT).startswith("param(")
    assert first_significant_line(console_ops._UNLOCK_SCRIPT).startswith("param(")


def test_wake_script_binds_vm_by_param_and_never_interpolates_args_into_wql() -> None:
    wake = console_ops._WAKE_DISPLAY_SCRIPT
    # $args is an array: interpolating it into a WQL filter only ever worked
    # for a one-element argument. The file's convention is param() bindings.
    assert "$args" not in wake
    assert "param([string] $Vm)" in wake
    assert "ElementName='$Vm'" in wake
    # Same convention for the unlock script.
    assert "$args" not in console_ops._UNLOCK_SCRIPT
    assert "ElementName='$Vm'" in console_ops._UNLOCK_SCRIPT


def test_vk_mapper_error_reports_the_index_never_the_character() -> None:
    unlock = console_ops._UNLOCK_SCRIPT
    throw_lines = [line.strip() for line in unlock.splitlines() if "no VK mapping" in line]
    assert len(throw_lines) == 1
    throw_line = throw_lines[0]
    assert "$ch" not in throw_line, throw_line
    assert "$Plain" not in throw_line, throw_line
    assert "index" in throw_line, throw_line
    # The message can only point at a position if the loop carries one.
    assert re.search(r"for \(\$i = 0; \$i -lt \$Plain\.Length; \$i\+\+\)", unlock)


def test_no_throw_or_expandable_string_in_the_credential_path_carries_the_secret(
    tmp_path: Path,
) -> None:
    # Every throw message becomes a REPL response line (`error = $_.Exception.
    # Message`) and _stdout_of wraps it into TransportError text that can reach
    # provenance -- so no thrown message or expandable string anywhere in the
    # unlock/credential path may reference the secret's variables.
    cases: list[tuple[str, str, tuple[str, ...]]] = [
        ("unlock.ps1", console_ops._UNLOCK_SCRIPT, ("$ch", "$Plain")),
        ("wake_display.ps1", console_ops._WAKE_DISPLAY_SCRIPT, ("$Plain",)),
        ("session_repl.ps1", REPL_PATH.read_text(encoding="utf-8"), ("$secret", "$Plain")),
    ]
    for name, source, forbidden in cases:
        parse_errors, throws, expandables = ast_facts(_write_script(tmp_path, name, source))
        assert parse_errors == [], name
        leaky_throws = [t for t in throws if any(f in t for f in forbidden)]
        assert leaky_throws == [], (name, leaky_throws)
        leaky_strings = [s for s in expandables if any(f in s for f in forbidden)]
        assert leaky_strings == [], (name, leaky_strings)


# --- Functional check, no elevation: the real unlock script with stubbed CIM --


def _stubbed_unlock_script(tmp_path: Path) -> Path:
    marker = "param([string] $Vm, [string] $Plain)"
    assert marker in console_ops._UNLOCK_SCRIPT
    body = console_ops._UNLOCK_SCRIPT.replace(marker, "", 1)
    harness = marker + "\n" + _CIM_STUBS + body
    return _write_script(tmp_path, "unlock_stubbed.ps1", harness)


def test_unlock_run_with_an_unmappable_character_reports_index_only(tmp_path: Path) -> None:
    path = _stubbed_unlock_script(tmp_path)
    secret = "Ab1|ef"  # '|' carries no VK mapping and stays pure ASCII
    proc = ps_scripts.run_script(path, ["-Vm", "LabStub01", "-Plain", secret])
    combined = proc.stdout + proc.stderr
    # The failure names the position, never the character:
    assert "no VK mapping for character index 3" in combined
    assert proc.returncode != 0
    # ...and neither the secret nor any of its characters reaches output.
    assert secret not in combined
    assert "|" not in combined


def test_unlock_run_with_a_fully_mapped_secret_completes(tmp_path: Path) -> None:
    path = _stubbed_unlock_script(tmp_path)
    secret = "Ab1!xY2"  # every character has a VK mapping (incl. shifted '!')
    proc = ps_scripts.run_script(path, ["-Vm", "LabStub01", "-Plain", secret])
    assert proc.returncode == 0, proc.stderr
    assert "TypeCtrlAltDel: 0" in proc.stdout
    assert "unlock sequence sent" in proc.stdout
    assert secret not in proc.stdout
