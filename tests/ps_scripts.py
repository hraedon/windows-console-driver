"""Shared drivers for contract tests that exercise the PowerShell scripts.

Everything here is deliberately boring: run a script file with Windows
PowerShell 5.1 (the only PowerShell on the lab and controller machines),
parse-check it with the 5.1 language parser, and keep a few honesty guards
(ASCII-only sources, single-line JSON on stdout) in one audited place.
"""

import json
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GUEST_DIR = REPO_ROOT / "guest"
HELPER_PATH = GUEST_DIR / "helper.ps1"
HYPERV_INPUT_PATH = GUEST_DIR / "hyperv-input.ps1"
# The windows-evidence-lab analyzer settings, reused so the exclusions (and the
# reasons attached to them) stay identical across the script families.
WEL_ANALYZER_SETTINGS = Path(r"C:\projects\windows-evidence-lab\PSScriptAnalyzerSettings.psd1")
_POWERSHELL_FALLBACK = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
POWERSHELL = shutil.which("powershell") or _POWERSHELL_FALLBACK


def ps_single_quote(value: str) -> str:
    """Quote a path for embedding in a PowerShell single-quoted string."""
    return "'" + value.replace("'", "''") + "'"


def run_powershell_command(
    command: str,
    timeout: float = 120.0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def run_script(
    script: Path,
    args: list[str] | None = None,
    stdin: str = "",
    env: dict[str, str] | None = None,
    timeout: float = 120.0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            *(args or []),
        ],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=env,
        check=False,
    )


def parse_check(script: Path) -> None:
    """Parse with the Windows PowerShell 5.1 language parser; zero errors required."""
    command = (
        "$tokens = $null; $errors = $null\n"
        "[void][System.Management.Automation.Language.Parser]::ParseFile("
        f"{ps_single_quote(str(script))}, [ref]$tokens, [ref]$errors)\n"
        "foreach ($e in @($errors)) { "
        "Write-Output ($e.Extent.StartLineNumber.ToString() + ': ' + $e.Message) }"
    )
    proc = run_powershell_command(command)
    problems = [line for line in proc.stdout.splitlines() if line.strip()]
    assert not problems, f"{script.name} failed the PowerShell 5.1 parse check: {problems}"


def assert_ascii_only(script: Path) -> None:
    """Guest scripts are pure ASCII, on purpose.

    windows-evidence-lab lesson (PSScriptAnalyzerSettings.psd1): PowerShell 5.1
    reads a BOM-less file as ANSI, so non-ASCII bytes are silently mangled the
    moment 5.1 -- the only PowerShell on these machines -- runs the file.
    Pure ASCII makes the question moot rather than merely answered.
    """
    content = script.read_bytes()
    non_ascii = sorted({byte for byte in content if byte >= 128})
    assert not non_ascii, (
        f"{script.name} contains non-ASCII bytes {non_ascii}; keep guest scripts "
        "pure ASCII (PS 5.1 reads BOM-less files as ANSI)"
    )


def assert_single_line_json(proc: subprocess.CompletedProcess[str]) -> dict[str, object]:
    """Stdout must be exactly one JSON document; stderr is never parsed."""
    assert proc.returncode in (0, 2, 3), f"exit {proc.returncode}; stderr: {proc.stderr!r}"
    assert proc.stdout.strip(), f"helper produced no stdout; stderr: {proc.stderr!r}"
    lines = proc.stdout.strip().splitlines()
    assert len(lines) == 1, f"stdout must be exactly one JSON line, got {len(lines)}: {lines[:3]!r}"
    payload = json.loads(lines[0])
    assert isinstance(payload, dict)
    return payload


def psscriptanalyzer_available() -> bool:
    probe = run_powershell_command(
        "if (Get-Module -ListAvailable PSScriptAnalyzer) { 'AVAILABLE' } else { 'MISSING' }",
        timeout=60.0,
    )
    return "AVAILABLE" in probe.stdout


def scriptanalyzer_findings(script: Path) -> list[str]:
    """Run PSScriptAnalyzer (Error+Warning) with the WEL settings; return findings."""
    settings = WEL_ANALYZER_SETTINGS if WEL_ANALYZER_SETTINGS.exists() else None
    settings_part = f" -Settings {ps_single_quote(str(settings))}" if settings else ""
    command = (
        "$findings = Invoke-ScriptAnalyzer -Path "
        + ps_single_quote(str(script))
        + settings_part
        + " -Severity Error,Warning\n"
        "foreach ($f in @($findings)) { "
        "Write-Output ($f.Line.ToString() + ' ' + $f.RuleName + ': ' + $f.Message) }"
    )
    proc = run_powershell_command(command)
    return [line for line in proc.stdout.splitlines() if line.strip()]
