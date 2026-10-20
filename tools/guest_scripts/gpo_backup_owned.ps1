# Cleanup-time evidence preservation (Plan 035 review): back up ONLY the GPO
# this transaction created (by its captured GUID) into a NEW directory under a
# fixed root, owned by that GUID. The caller names a leaf, never a path; the
# script refuses the root itself, anything outside it, an existing directory
# and a reparse-point root. Emits the backup path and a hash line per scripts
# INI found in the backup (Hidden files included), so the record binds the
# bytes the operator later collects. Report, never throw.
param([string]$Guid, [string]$Name)
$ErrorActionPreference = 'Continue'
$root = 'C:\gpo-studio\wcd-backup'
$parsed = [Guid]::Empty
if (-not [Guid]::TryParse($Guid, [ref]$parsed) -or $parsed -eq [Guid]::Empty) { "backup_skipped=no_owned_guid"; return }
if ($Name -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$' -or $Name -match '^\.+$') { "backup_refused=bad_leaf_name"; return }
try {
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    $rootItem = Get-Item -LiteralPath $root -Force
    if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { "backup_refused=root_is_reparse_point"; return }
    $rootFull = [IO.Path]::GetFullPath($rootItem.FullName).TrimEnd('\')
    $target = [IO.Path]::GetFullPath((Join-Path $rootFull $Name))
    if ([IO.Path]::GetDirectoryName($target).TrimEnd('\') -ne $rootFull) { "backup_refused=outside_root"; return }
    if (Test-Path -LiteralPath $target) { "backup_refused=target_exists"; return }
    New-Item -ItemType Directory -Path $target | Out-Null
    Set-Content -LiteralPath (Join-Path $target '.wcd-owner') -Value $parsed.ToString() -Encoding ASCII
    Backup-GPO -Guid $parsed -Path $target -Comment "wcd transaction capture: $parsed" -ErrorAction Stop | Out-Null
    "backup=$target"
    Get-ChildItem -LiteralPath $target -Recurse -File -Force |
        Where-Object { $_.Name -in @('scripts.ini', 'psscripts.ini') } |
        ForEach-Object {
            $rel = $_.FullName.Substring($_.FullName.IndexOf('DomainSysvol\GPO\') + 17) -replace '\\', '/'
            $sha = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            "ini=$rel sha256=$sha bytes=$($_.Length) attrs=$(([string]$_.Attributes) -replace ' ', '')"
        }
} catch {
    "backup_error=$($_.Exception.Message -replace '[\r\n]', ' ')"
}
