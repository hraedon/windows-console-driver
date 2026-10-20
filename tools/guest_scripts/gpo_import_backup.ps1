# Setup script (Plan 035 WP-2): create the disposable unlinked evidence GPO and
# import a GPMC backup bundle into it -- the guest-side import step an
# observe-only transaction over an imported GPO needs.
#
# The bundle is placed in the guest by the operator BEFORE the transaction
# (a controller-side push, recorded in the window NOTES); this script refuses
# unless the file at BundlePath hashes to BundleSha256, so the record's
# arguments bind the exact bytes that were imported. The import mirrors
# gpo-studio's firewall lane write leg: Expand-Archive, read the backup id
# from manifest.xml, New-GPO, Import-GPO -BackupId -TargetGuid.
#
# Output contract: guid=<id> (parsed by the run-sheet executor) plus
# provenance lines (domain, backup_id, bundle_sha256, registry_pol_sha256).
param(
    [string]$Name,
    [string]$Comment,
    [string]$BundlePath,
    [string]$BundleSha256,
    [string]$StageDir
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $BundlePath -PathType Leaf)) {
    throw "bundle $BundlePath is not present in the guest; place it before the transaction"
}
$actual = (Get-FileHash -LiteralPath $BundlePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $BundleSha256.ToLowerInvariant()) {
    throw "bundle hash mismatch: expected $BundleSha256, found $actual"
}
$existing = Get-GPO -Name $Name -ErrorAction SilentlyContinue
if ($existing) { throw "GPO $Name already exists; cleanup discipline violated" }

$expanded = Join-Path $StageDir 'expanded'
if (Test-Path -LiteralPath $expanded) { throw "stage $expanded already exists" }
Expand-Archive -LiteralPath $BundlePath -DestinationPath $expanded
$manifest = [xml](Get-Content -LiteralPath (Join-Path $expanded 'manifest.xml') -Raw)
$ns = New-Object System.Xml.XmlNamespaceManager($manifest.NameTable)
$ns.AddNamespace('m', 'http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest')
$idNode = $manifest.SelectSingleNode('/m:Backups/m:BackupInst/m:ID', $ns)
if ($null -eq $idNode) { throw 'manifest.xml names no backup instance' }
$backupId = [Guid]$idNode.InnerText.Trim('{}')

$gpo = New-GPO -Name $Name -Comment $Comment
"guid=$($gpo.Id)"
"domain=$($gpo.DomainName)"
Import-GPO -BackupId $backupId -Path $expanded -TargetGuid $gpo.Id -Domain $gpo.DomainName -Confirm:$false | Out-Null
"backup_id=$backupId"
"bundle_sha256=$actual"
$pol = "\\$($gpo.DomainName)\SYSVOL\$($gpo.DomainName)\Policies\{$($gpo.Id)}\Machine\Registry.pol"
if (Test-Path -LiteralPath $pol) {
    "registry_pol_sha256=$((Get-FileHash -LiteralPath $pol -Algorithm SHA256).Hash.ToLowerInvariant())"
} else {
    "registry_pol_sha256=absent"
}
