"""Plan 035 operator tool: parse-check, place or run against the guest.

usage:
  place.py <estate.toml> parse <script.ps1>
      parse with the GUEST's own PowerShell 5.1 parser (surface-onboarding rule)
  place.py <estate.toml> place <local> <guest_dir> <guest_name>
      MUTATING: create a new guest directory and write one file into it
  place.py <estate.toml> run <script.ps1> [args...]
      run a guest script (e.g. collect.ps1) and print its output
"""

import base64
import hashlib
import sys
from pathlib import Path

from wcd.cli import _default_transport
from wcd.estate import load_estate

PARSE = r"""param([string]$Text)
$tokens=$null;$errors=$null
[void][System.Management.Automation.Language.Parser]::ParseInput($Text,[ref]$tokens,[ref]$errors)
"psversion=$($PSVersionTable.PSVersion)"
"parse_errors=$(@($errors).Count)"
foreach($e in @($errors)){ "error=" + $e.Extent.StartLineNumber + ": " + $e.Message }"""

PLACE = r"""param([string]$Dir,[string]$Name,[string]$B64)
$ErrorActionPreference='Stop'
if (Test-Path -LiteralPath $Dir) { throw "stage $Dir already exists" }
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$p = Join-Path $Dir $Name
[IO.File]::WriteAllBytes($p, [Convert]::FromBase64String($B64))
"path=$p"
"bytes=$((Get-Item -LiteralPath $p).Length)"
"sha256=$((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant())"
"""


def main() -> None:
    transport = _default_transport(load_estate(sys.argv[1]))
    verb = sys.argv[2]
    try:
        if verb == "parse":
            text = Path(sys.argv[3]).read_text(encoding="utf-8-sig")
            print(transport.guest(PARSE, [text], timeout=120))
        elif verb == "place":
            data = Path(sys.argv[3]).read_bytes()
            print(f"local_sha256={hashlib.sha256(data).hexdigest()} bytes={len(data)}")
            args = [sys.argv[4], sys.argv[5], base64.b64encode(data).decode()]
            print(transport.guest(PLACE, args, timeout=180))
        elif verb == "run":
            print(transport.guest(Path(sys.argv[3]).read_text(), sys.argv[4:], timeout=300))
        else:
            raise SystemExit(f"unknown verb {verb!r}")
    finally:
        transport.close()


if __name__ == "__main__":
    main()
