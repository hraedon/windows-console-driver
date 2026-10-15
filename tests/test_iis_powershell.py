"""Exercise the shipped read helper against enum/flags fakes, including the trap."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from test_iis_evidence import CONFIG, LOCATION

PS = shutil.which("powershell") or shutil.which("pwsh")
ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(PS is None, reason="PowerShell is unavailable")


def test_enum_value_trap_is_empty_but_helper_returns_both_scopes(tmp_path: Path) -> None:
    config = tmp_path / "applicationHost.config"
    config.write_bytes(CONFIG)
    script = ROOT / "tools/guest_scripts/read_iis_security_value.ps1"
    script.read_bytes().decode("ascii")
    driver = tmp_path / "driver.ps1"
    driver.write_text(f"""
$ErrorActionPreference = 'Stop'
function Import-Module {{ param($Name, $ErrorAction) }}
Add-Type 'public enum SyntheticEpa {{ None, Allow, Require }}'
Add-Type '[System.Flags] public enum SyntheticSsl {{ None=0, Ssl=8, Ssl128=256 }}'
$naive = ([SyntheticEpa]::Require).Value
if ($null -ne $naive) {{ throw 'Fixture no longer exposes the .Value trap' }}
function Get-WebConfigurationProperty {{
    param($PSPath, $Filter, $Name)
    if ($PSPath -ne 'IIS:\\Sites\\{LOCATION}') {{ throw 'Wrong read scope' }}
    switch ($Name) {{
        tokenChecking {{ return [SyntheticEpa]::Require }}
        sslFlags {{ return ([SyntheticSsl]::Ssl -bor [SyntheticSsl]::Ssl128) }}
        enabled {{ return [pscustomobject]@{{ Value = $true }} }}
        '.' {{ [pscustomobject]@{{ value = 'Negotiate' }}; [pscustomobject]@{{ value = 'NTLM' }} }}
    }}
}}
& '{script.as_posix()}' -Location '{LOCATION}' -ConfigPath '{config.as_posix()}'
""", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k.lower() != "psmodulepath"}
    proc = subprocess.run([str(PS), "-NoProfile", "-NonInteractive", "-File", str(driver)],
                          capture_output=True, text=True, timeout=60, env=env)
    assert proc.returncode == 0, proc.stderr
    row = json.loads(proc.stdout)["locations"][0]
    assert row["effective"]["error"] is None
    for scope in ("effective", "committed"):
        assert row[scope]["token_checking"] == "Require"
        assert row[scope]["ssl_flags"] == ["Ssl", "Ssl128"]
        assert row[scope]["enabled"] is True
    assert row["effective"]["providers"] == ["Negotiate", "NTLM"]
