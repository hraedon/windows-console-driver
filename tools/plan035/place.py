"""Plan 035 operator tool (not committed): parse-check a guest script with the
guest's own PowerShell 5.1 parser, and/or place a local file in the guest.
usage: place.py <estate.toml> parse <script.ps1> | place <local> <guest_dir> <guest_name> | run <ps1-text-file> [args...]
"""
import base64, hashlib, sys
from pathlib import Path
from wcd.cli import _default_transport
from wcd.estate import load_estate
t = _default_transport(load_estate(sys.argv[1]))
try:
    if sys.argv[2] == "parse":
        text = Path(sys.argv[3]).read_text(encoding="utf-8-sig")
        script = r"""param([string]$Text)
$tokens=$null;$errors=$null
[void][System.Management.Automation.Language.Parser]::ParseInput($Text,[ref]$tokens,[ref]$errors)
"psversion=$($PSVersionTable.PSVersion)"
"parse_errors=$(@($errors).Count)"
foreach($e in @($errors)){ "error=" + $e.Extent.StartLineNumber + ": " + $e.Message }"""
        print(t.guest(script, [text], timeout=120))
    elif sys.argv[2] == "place":
        data = Path(sys.argv[3]).read_bytes()
        script = r"""param([string]$Dir,[string]$Name,[string]$B64)
$ErrorActionPreference='Stop'
if (Test-Path -LiteralPath $Dir) { throw "stage $Dir already exists" }
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$p = Join-Path $Dir $Name
[IO.File]::WriteAllBytes($p, [Convert]::FromBase64String($B64))
"path=$p"
"bytes=$((Get-Item -LiteralPath $p).Length)"
"sha256=$((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant())"
"""
        print("local_sha256=" + hashlib.sha256(data).hexdigest() + " bytes=" + str(len(data)))
        print(t.guest(script, [sys.argv[4], sys.argv[5], base64.b64encode(data).decode()], timeout=180))
    elif sys.argv[2] == "run":
        print(t.guest(Path(sys.argv[3]).read_text(), sys.argv[4:], timeout=300))
finally:
    try: t.close()
    except Exception: pass
