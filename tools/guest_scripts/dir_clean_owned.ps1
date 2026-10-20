# Cleanup script (Plan 035 review): remove ONLY a staging directory this
# transaction created -- a leaf under the fixed staging root whose .wcd-owner
# marker names the GPO GUID this transaction owns. Refuses the root itself,
# out-of-root paths, a missing or foreign marker, and a reparse point ANYWHERE
# on the path: the leaf, the root, or any ancestor of the root, re-checked
# here at cleanup time because the root could have been swapped for a
# junction after setup checked it (round-2 review). Report, never throw.
#
# $Root is a TEST SEAM only: the run-sheets pass exactly two arguments, so a
# transaction always cleans under C:\gpo-studio\wcd-stage.
param([string]$StageName, [string]$Guid, [string]$Root = 'C:\gpo-studio\wcd-stage')
$ErrorActionPreference = 'Continue'

function Test-ReparseChain {
    # True when $Path or any existing ancestor of it is a reparse point.
    param([string]$Path)
    $current = $Path
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $attrs = (Get-Item -LiteralPath $current -Force).Attributes
            if ($attrs -band [IO.FileAttributes]::ReparsePoint) { return $true }
        }
        $parent = Split-Path -Parent $current
        if (-not $parent -or $parent -eq $current) { break }
        $current = $parent
    }
    return $false
}

$parsed = [Guid]::Empty
if (-not [Guid]::TryParse($Guid, [ref]$parsed) -or $parsed -eq [Guid]::Empty) { "clean_skipped=no_owned_guid"; return }
if ($StageName -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$' -or $StageName -match '^\.+$' -or $StageName -eq 'incoming') { "clean_refused=bad_leaf_name"; return }
try {
    if (-not (Test-Path -LiteralPath $Root)) { "clean_skipped=no_staging_root"; return }
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    if (Test-ReparseChain $rootFull) { "clean_refused=root_reparse_point"; return }
    $stage = [IO.Path]::GetFullPath((Join-Path $rootFull $StageName))
    if ([IO.Path]::GetDirectoryName($stage).TrimEnd('\', '/') -ne $rootFull) { "clean_refused=outside_root"; return }
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
