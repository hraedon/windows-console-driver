# Cleanup script (Plan 035 review): remove ONLY a staging directory this
# transaction created -- a leaf under C:\gpo-studio\wcd-stage whose
# .wcd-owner marker names the GPO GUID this transaction owns. Refuses the
# root itself, out-of-root paths, reparse points, a missing or foreign marker.
# Report, never throw.
param([string]$StageName, [string]$Guid)
$ErrorActionPreference = 'Continue'
$root = 'C:\gpo-studio\wcd-stage'
$parsed = [Guid]::Empty
if (-not [Guid]::TryParse($Guid, [ref]$parsed) -or $parsed -eq [Guid]::Empty) { "clean_skipped=no_owned_guid"; return }
if ($StageName -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$' -or $StageName -match '^\.+$' -or $StageName -eq 'incoming') { "clean_refused=bad_leaf_name"; return }
try {
    if (-not (Test-Path -LiteralPath $root)) { "clean_skipped=no_staging_root"; return }
    $rootFull = [IO.Path]::GetFullPath((Get-Item -LiteralPath $root -Force).FullName).TrimEnd('\')
    $stage = [IO.Path]::GetFullPath((Join-Path $rootFull $StageName))
    if ([IO.Path]::GetDirectoryName($stage).TrimEnd('\') -ne $rootFull) { "clean_refused=outside_root"; return }
    if (-not (Test-Path -LiteralPath $stage)) { "absent_dir=$StageName"; return }
    $item = Get-Item -LiteralPath $stage -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { "clean_refused=reparse_point"; return }
    $marker = Join-Path $stage '.wcd-owner'
    if (-not (Test-Path -LiteralPath $marker)) { "clean_refused=no_owner_marker"; return }
    if ((Get-Content -LiteralPath $marker -Raw).Trim() -ne $parsed.ToString()) { "clean_refused=foreign_owner"; return }
    Remove-Item -LiteralPath $stage -Recurse -Force
    "removed_dir=$StageName"
} catch {
    "clean_error=$($_.Exception.Message -replace '[\r\n]', ' ')"
}
