# Cleanup script: remove a directory tree (R1's staging dir); report, never throw.
param([string]$Path)
$ErrorActionPreference = 'Continue'
if (Test-Path -LiteralPath $Path) {
    Remove-Item -Recurse -Force -LiteralPath $Path
    "removed_dir=$Path"
} else {
    "absent_dir=$Path"
}
