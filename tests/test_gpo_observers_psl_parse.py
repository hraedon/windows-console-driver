"""Structural validation of the PowerShell snippets.

Parse-only: every snippet is written to a temporary .ps1 and parsed with the
machine's Windows PowerShell 5.1 parser. No GPO cmdlet is executed -- there
are no GPO targets here; real behavior is Phase-2 estate-window work (contract
section 13).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from gpo_observers.psl import PSL_SNIPPETS

POWERSHELL = shutil.which("powershell.exe")

pytestmark = pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell not available")


def _parse_errors(script_path: Path) -> list[str]:
    assert POWERSHELL is not None
    command = (
        "$errs = $null\n"
        "$tokens = $null\n"
        f"$null = [System.Management.Automation.Language.Parser]::ParseFile("
        f"'{script_path}', [ref]$tokens, [ref]$errs)\n"
        "if ($errs.Count -eq 0) { 'OK' } else { $errs | ForEach-Object { $_.Message } }\n"
    )
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        return [f"powershell exited {result.returncode}: {result.stderr.strip()}"]
    if result.stdout.strip() == "OK":
        return []
    return result.stdout.strip().splitlines()


@pytest.mark.parametrize("name", sorted(PSL_SNIPPETS))
def test_snippet_parses_under_windows_powershell_51(tmp_path: Path, name: str) -> None:
    source = PSL_SNIPPETS[name]
    script_path = tmp_path / f"{name}.ps1"
    # Snippets must be pure ASCII so file encoding can never change meaning.
    script_path.write_text(source, encoding="ascii")
    errors = _parse_errors(script_path)
    assert errors == [], f"{name} failed to parse: {errors}"


@pytest.mark.parametrize("name", sorted(PSL_SNIPPETS))
def test_snippet_structure_is_ps51_safe(name: str) -> None:
    source = PSL_SNIPPETS[name]
    assert source.isascii(), name
    # PS 7 syntax that would break 5.1: the null-coalescing operator and the
    # ternary operator. Inline regex flags like "(?im)" are fine.
    assert "??" not in source, name
    assert re.search(r"\s\?\s", source) is None, name
    # Strict error handling and the JSON envelope contract.
    assert "$ErrorActionPreference = 'Stop'" in source, name
    assert "ConvertTo-Json" in source, name
    assert "exit 0" in source, name
    assert "exit 2" in source, name
    # One error envelope per snippet, whatever internal try/finally blocks
    # the snippet needs.
    assert source.count("catch {") == 1, name
    # A param block opens the script.
    assert re.search(r"^param\(", source, re.MULTILINE) is not None, name


def test_envelope_shape_is_single_json_object_per_snippet() -> None:
    for name, source in PSL_SNIPPETS.items():
        # The success and failure paths each emit exactly one object, and no
        # other Write-Output-style emission exists.
        success_lines = [line for line in source.splitlines() if "ok = $true" in line]
        failure_lines = [line for line in source.splitlines() if "ok = $false" in line]
        assert len(success_lines) == 1, name
        assert len(failure_lines) == 1, name
        for line in success_lines + failure_lines:
            assert "ConvertTo-Json" in line, name


def test_no_locale_dependent_formatting() -> None:
    for name, source in PSL_SNIPPETS.items():
        # Culture-sensitive default sorts and formatting are banned.
        assert "Sort-Object" not in source, name
        assert "Get-Culture" not in source, name
        assert "Get-UICulture" not in source, name
        # Every culture reference is the explicit invariant culture; nothing
        # formats through the host's current culture.
        assert source.count("InvariantCulture") == source.count(
            "[System.Globalization.CultureInfo]::InvariantCulture"
        ), name
        assert "CurrentCulture" not in source, name
        assert "CurrentUICulture" not in source, name
