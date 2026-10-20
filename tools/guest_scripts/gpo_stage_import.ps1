# Setup script (Plan 035 WP-2, revision 2): import a GPMC backup bundle into
# the GPO this transaction ALREADY created (gpo_create ran first, so its GUID
# is captured before anything here can fail). The bundle must have been
# placed by the operator at C:\gpo-studio\wcd-stage\incoming\<BundleName>; it
# is refused unless it hashes to BundleSha256. It is expanded into a NEW
# directory C:\gpo-studio\wcd-stage\<StageName> stamped with an ownership
# marker (the owned GPO GUID) that dir_clean_owned requires before deleting.
# Leaf names only; the root itself, out-of-root paths and reparse points are
# refused. Output: backup_id, bundle_sha256, registry_pol_sha256, stage.
param([string]$Guid, [string]$StageName, [string]$BundleName, [string]$BundleSha256)
$ErrorActionPreference = 'Stop'
function Test-ReparseChain {
    # True when $Path or any existing ancestor of it is a reparse point
    # (round-2 review: a junction at C:\gpo-studio itself passes a root-only
    # check and the lexical containment test).
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

$root = 'C:\gpo-studio\wcd-stage'
$parsed = [Guid]$Guid
foreach ($leaf in @($StageName, $BundleName)) {
    if ($leaf -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$' -or $leaf -match '^\.+$') { throw "bad leaf name '$leaf'" }
}
if ($StageName -eq 'incoming') { throw 'stage name may not be the incoming directory' }
$rootItem = Get-Item -LiteralPath $root -Force
if (Test-ReparseChain $rootItem.FullName) { throw 'staging root or one of its ancestors is a reparse point' }
$rootFull = [IO.Path]::GetFullPath($rootItem.FullName).TrimEnd('\')
$bundle = [IO.Path]::GetFullPath((Join-Path (Join-Path $rootFull 'incoming') $BundleName))
if ([IO.Path]::GetDirectoryName($bundle).TrimEnd('\') -ne (Join-Path $rootFull 'incoming')) { throw 'bundle outside incoming' }
if (-not (Test-Path -LiteralPath $bundle -PathType Leaf)) { throw "bundle $BundleName is not in the incoming directory" }
$actual = (Get-FileHash -LiteralPath $bundle -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $BundleSha256.ToLowerInvariant()) { throw "bundle hash mismatch: expected $BundleSha256, found $actual" }
$stage = [IO.Path]::GetFullPath((Join-Path $rootFull $StageName))
if ([IO.Path]::GetDirectoryName($stage).TrimEnd('\') -ne $rootFull) { throw 'stage outside the staging root' }
if (Test-Path -LiteralPath $stage) { throw "stage $StageName already exists" }
New-Item -ItemType Directory -Path $stage | Out-Null
Set-Content -LiteralPath (Join-Path $stage '.wcd-owner') -Value $parsed.ToString() -Encoding ASCII
$expanded = Join-Path $stage 'expanded'
Expand-Archive -LiteralPath $bundle -DestinationPath $expanded
$manifest = [xml](Get-Content -LiteralPath (Join-Path $expanded 'manifest.xml') -Raw)
$ns = New-Object System.Xml.XmlNamespaceManager($manifest.NameTable)
$ns.AddNamespace('m', 'http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest')
$idNode = $manifest.SelectSingleNode('/m:Backups/m:BackupInst/m:ID', $ns)
if ($null -eq $idNode) { throw 'manifest.xml names no backup instance' }
$backupId = [Guid]$idNode.InnerText.Trim('{}')
$gpo = Get-GPO -Guid $parsed
Import-GPO -BackupId $backupId -Path $expanded -TargetGuid $parsed -Domain $gpo.DomainName -Confirm:$false | Out-Null
"backup_id=$backupId"
"bundle_sha256=$actual"
"stage=$stage"
$pol = "\\$($gpo.DomainName)\SYSVOL\$($gpo.DomainName)\Policies\{$parsed}\Machine\Registry.pol"
if (Test-Path -LiteralPath $pol) {
    "registry_pol_sha256=$((Get-FileHash -LiteralPath $pol -Algorithm SHA256).Hash.ToLowerInvariant())"
} else {
    "registry_pol_sha256=absent"
}
