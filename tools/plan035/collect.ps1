# Plan 035 operator tool (window 19): zip a guest directory INCLUDING Hidden files
# (GPME writes scripts.ini Hidden; Compress-Archive and Get-ChildItem without -Force
# skip them) and emit per-file sha256 plus the zip as base64. Run via place.py run.
param([string]$Root)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = Join-Path $env:TEMP ('plan035-collect-' + [guid]::NewGuid().ToString() + '.zip')
[IO.Compression.ZipFile]::CreateFromDirectory($Root, $zip)
"zip_sha256=$((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant())"
Get-ChildItem -Recurse -File -Force -LiteralPath $Root | ForEach-Object { "file=" + $_.FullName.Substring($Root.Length) + " attrs=" + $_.Attributes + " sha256=" + (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + " bytes=" + $_.Length }
"b64=" + [Convert]::ToBase64String([IO.File]::ReadAllBytes($zip))
Remove-Item -LiteralPath $zip -Force
