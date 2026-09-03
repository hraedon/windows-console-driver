"""PowerShell 5.1 collection snippets, one per R2 observer.

Each constant is a complete, self-contained snippet that an injected
transport runs in the guest. Every snippet writes exactly one JSON object to
stdout -- ``{"ok": true, "data": ...}`` or ``{"ok": false, "error": ...}`` --
and exits 0 on success or 2 on error. They are strict (``Stop`` error
preference, failures are reported, never skipped), locale-independent
(explicit invariant formatting, ordinal comparisons), and Windows PowerShell
5.1 compatible: no ``??`` operator, no ternaries, no PS 7-only cmdlets.

Division of labor (the independence rule): the guest only transports bytes
and trivially extractable raw values. All parsing -- scripts.ini semantics,
GPT.INI unpacking, fingerprint comparison beyond the in-guest two-pass
cross-check -- is the controller's Python job. The one exception is the
SYSVOL fingerprint, which compares its two independently coded enumeration
passes in-script, because the comparison is the observation.
"""

from __future__ import annotations

from collections.abc import Mapping

GPO_IDENTITY = r"""\
param(
    [Parameter(Mandatory = $true)]
    [string]$GpoGuid,

    [Parameter(Mandatory = $false)]
    [string]$DomainDns = ''
)

# Emits the GPO identity as normalized JSON. The GUID is re-parsed so the
# fact is canonical ('D' format, culture-invariant), not whatever spelling
# the parameter used.
$ErrorActionPreference = 'Stop'

try {
    $parsed = [System.Guid]::Parse($GpoGuid)
    $data = @{
        gpo_guid   = $parsed.ToString('D')
        domain_dns = $DomainDns
    }
    @{ ok = $true; data = $data } | ConvertTo-Json -Depth 4 -Compress
    exit 0
} catch {
    @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Depth 4 -Compress
    exit 2
}
"""

SYSVOL_TREE_FINGERPRINT = r"""\
param(
    [Parameter(Mandatory = $true)]
    [string]$SysvolPath
)

# Two independently coded enumeration passes over the same tree, compared
# in-script: one implementation comparing itself to itself proves nothing.
# Pass 1 uses the PowerShell provider (Get-ChildItem -Force -Recurse) plus
# Get-FileHash. Pass 2 uses .NET directory enumeration plus explicit binary
# reads hashed through SHA256. -Force is required on pass 1: GPMC marks
# several SYSVOL files hidden, and an enumeration that silently misses them
# would agree with a broken collector.
$ErrorActionPreference = 'Stop'

function Get-PassOneEntries {
    param([string]$Root)
    $entries = New-Object 'System.Collections.Generic.List[object]'
    $files = @(Get-ChildItem -LiteralPath $Root -Force -Recurse -File)
    foreach ($file in $files) {
        $relative = $file.FullName.Substring($Root.Length).Replace('\', '/')
        if ($relative.StartsWith('/')) { $relative = $relative.Substring(1) }
        $hash = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256
        $entries.Add(@{
            relpath = $relative
            sha256  = $hash.Hash.ToLowerInvariant()
            bytes   = [long]$file.Length
        })
    }
    return $entries
}

function Get-PassTwoEntries {
    param([string]$Root)
    $entries = New-Object 'System.Collections.Generic.List[object]'
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $paths = [System.IO.Directory]::EnumerateFiles(
            $Root, '*', [System.IO.SearchOption]::AllDirectories)
        foreach ($fullPath in $paths) {
            $relative = $fullPath.Substring($Root.Length).Replace('\', '/')
            if ($relative.StartsWith('/')) { $relative = $relative.Substring(1) }
            $bytes = [System.IO.File]::ReadAllBytes($fullPath)
            $digest = $sha.ComputeHash($bytes)
            $hex = [System.BitConverter]::ToString($digest).Replace('-', '')
            $entries.Add(@{
                relpath = $relative
                sha256  = $hex.ToLowerInvariant()
                bytes   = $bytes.LongLength
            })
        }
    } finally {
        $sha.Dispose()
    }
    return $entries
}

try {
    if (-not [System.IO.Directory]::Exists($SysvolPath)) {
        throw ('GPO SYSVOL directory not found: ' + $SysvolPath)
    }
    $root = [System.IO.Path]::GetFullPath($SysvolPath)
    if (-not $root.EndsWith('\')) { $root = $root + '\' }

    $passOne = @(Get-PassOneEntries -Root $root)
    $passTwo = @(Get-PassTwoEntries -Root $root)

    $passTwoByRel = @{}
    foreach ($entry in $passTwo) { $passTwoByRel[$entry.relpath] = $entry }

    $passesMatch = ($passOne.Count -eq $passTwo.Count)
    foreach ($entry in $passOne) {
        if (-not $passesMatch) { break }
        $other = $passTwoByRel[$entry.relpath]
        if ($null -eq $other) { $passesMatch = $false; break }
        if ($other.sha256 -ne $entry.sha256) { $passesMatch = $false; break }
        if ($other.bytes -ne $entry.bytes) { $passesMatch = $false; break }
    }

    $data = @{
        files          = $passOne
        passes_match   = $passesMatch
        pass_one_count = $passOne.Count
        pass_two_count = $passTwo.Count
    }
    @{ ok = $true; data = $data } | ConvertTo-Json -Depth 6 -Compress
    exit 0
} catch {
    @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Depth 6 -Compress
    exit 2
}
"""

AD_ATTRIBUTES = r"""\
param(
    [Parameter(Mandatory = $true)]
    [string]$GpoGuid,

    [Parameter(Mandatory = $false)]
    [string]$Server = ''
)

# Selected GPC attributes as name/value pairs. Values are stringified except
# the integer attributes; whenChanged is emitted in round-trip 'o' format
# with an explicit invariant culture, uSNChanged through an invariant
# ToString, so no host locale can reach the output.
$ErrorActionPreference = 'Stop'

try {
    $attributeNames = @(
        'gPCMachineExtensionNames',
        'gPCUserExtensionNames',
        'versionNumber',
        'gPCFunctionalityVersion',
        'flags',
        'whenChanged',
        'uSNChanged'
    )
    $intNames = @('versionNumber', 'gPCFunctionalityVersion', 'flags')
    # MEASURED 2026-09-03 (first live run): Get-ADObject -Identity does not
    # resolve a bare or braced GUID on Server 2025; the full DN does. The
    # domain DN comes from the root DSE (a trivially extractable raw value).
    $domainDn = (Get-ADRootDSE).defaultNamingContext
    $gpcIdentity = 'CN={' + $GpoGuid + '},CN=Policies,CN=System,' + $domainDn
    $getParams = @{ Identity = $gpcIdentity; Properties = $attributeNames }
    if ($Server -ne '') { $getParams['Server'] = $Server }
    $gpc = Get-ADObject @getParams
    if ($null -eq $gpc) { throw ('GPC object not found: ' + $GpoGuid) }

    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    $values = @{}
    foreach ($name in $attributeNames) {
        $property = $gpc.PSObject.Properties[$name]
        if ($null -eq $property -or $null -eq $property.Value) {
            $values[$name] = $null
        } elseif ($intNames -contains $name) {
            $values[$name] = [int]$property.Value
        } elseif ($name -eq 'whenChanged') {
            $values[$name] = $property.Value.ToString('o', $invariant)
        } elseif ($name -eq 'uSNChanged') {
            $values[$name] = [Convert]::ToString([long]$property.Value, $invariant)
        } else {
            $values[$name] = [string]$property.Value
        }
    }

    @{ ok = $true; data = $values } | ConvertTo-Json -Depth 4 -Compress
    exit 0
} catch {
    @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Depth 4 -Compress
    exit 2
}
"""

VERSION_VALUES = r"""\
param(
    [Parameter(Mandatory = $true)]
    [string]$GptIniPath,

    [Parameter(Mandatory = $true)]
    [string]$GpoGuid,

    [Parameter(Mandatory = $false)]
    [string]$Server = ''
)

# Transport only: the raw GPT.INI bytes (base64), the raw Version string a
# regex can lift without interpretation, and the AD versionNumber. Unpacking
# the packed 32-bit version happens in the controller's Python normalizer,
# never here.
$ErrorActionPreference = 'Stop'

function Get-DecoderFromBom {
    param([byte[]]$Bytes)
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) {
        return [System.Text.Encoding]::Unicode
    }
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF) {
        return [System.Text.Encoding]::BigEndianUnicode
    }
    if ($Bytes.Length -ge 3) {
        if ($Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
            return [System.Text.Encoding]::UTF8
        }
    }
    return [System.Text.Encoding]::UTF8
}

try {
    if (-not [System.IO.File]::Exists($GptIniPath)) {
        throw ('GPT.INI not found: ' + $GptIniPath)
    }
    $raw = [System.IO.File]::ReadAllBytes($GptIniPath)
    $decoder = Get-DecoderFromBom -Bytes $raw
    $text = $decoder.GetString($raw)

    $versionRaw = $null
    $versionMatch = [regex]::Match($text, '(?im)^\s*Version\s*=\s*([0-9]+)\s*$')
    if ($versionMatch.Success) { $versionRaw = $versionMatch.Groups[1].Value }

    # Same measured Identity rule as ad_attributes: full DN, root-DSE domain.
    $domainDn = (Get-ADRootDSE).defaultNamingContext
    $adParams = @{
        Identity  = 'CN={' + $GpoGuid + '},CN=Policies,CN=System,' + $domainDn
        Properties = @('versionNumber')
    }
    if ($Server -ne '') { $adParams['Server'] = $Server }
    $gpc = Get-ADObject @adParams
    if ($null -eq $gpc) { throw ('GPC object not found: ' + $GpoGuid) }
    $adVersion = $null
    $property = $gpc.PSObject.Properties['versionNumber']
    if ($null -ne $property -and $null -ne $property.Value) {
        $adVersion = [int]$property.Value
    }

    $data = @{
        gpt_ini_b64       = [Convert]::ToBase64String($raw)
        gpt_version_raw   = $versionRaw
        ad_version_number = $adVersion
    }
    @{ ok = $true; data = $data } | ConvertTo-Json -Depth 4 -Compress
    exit 0
} catch {
    @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Depth 4 -Compress
    exit 2
}
"""

SCRIPTS_INI_RAW = r"""\
param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptsDir
)

# Bytes only. Parsing scripts.ini / psscripts.ini is the controller's job;
# this snippet never interprets the files it reads. Either file may be
# absent; absence is reported as null, not as an error. The whole Scripts
# directory may be absent too -- a freshly created GPO carries no
# Machine\Scripts at all (measured 2026-09-03, first live run) -- and that
# is the pre-authoring state, reported as nulls, never an error.
$ErrorActionPreference = 'Stop'

try {
    $scriptsB64 = $null
    $psScriptsB64 = $null

    $scriptsPath = Join-Path -Path $ScriptsDir -ChildPath 'scripts.ini'
    if ([System.IO.File]::Exists($scriptsPath)) {
        $scriptsB64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($scriptsPath))
    }

    $psScriptsPath = Join-Path -Path $ScriptsDir -ChildPath 'psscripts.ini'
    if ([System.IO.File]::Exists($psScriptsPath)) {
        $psScriptsB64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($psScriptsPath))
    }

    $data = @{
        scripts_ini_b64   = $scriptsB64
        psscripts_ini_b64 = $psScriptsB64
    }
    @{ ok = $true; data = $data } | ConvertTo-Json -Depth 4 -Compress
    exit 0
} catch {
    @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Depth 4 -Compress
    exit 2
}
"""

SCOPE_FORBID = r"""\
param(
    [Parameter(Mandatory = $true)]
    [string]$GpoGuid,

    [Parameter(Mandatory = $true)]
    [string]$DomainDns,

    [Parameter(Mandatory = $true)]
    [string]$SysvolGpoPath
)

# Blast-radius inputs for the forbid clauses:
# - the GPC extension lists (forbidden-GUID absence),
# - every GPC GUID directly under CN=Policies,CN=System (object-set
#   stability),
# - every path under the Policies directory, relative to that directory, so
#   the controller can verify containment under this GPO's GUID directory.
# The Policies directory is taken as the parent of the GPO SYSVOL directory
# (standard layout: <domain>\Policies\{guid}).
$ErrorActionPreference = 'Stop'

try {
    $extensionProps = @('gPCMachineExtensionNames', 'gPCUserExtensionNames')
    # Same measured Identity rule as ad_attributes: full DN, root-DSE domain.
    $domainDn = (Get-ADRootDSE).defaultNamingContext
    $gpc = Get-ADObject -Identity ('CN={' + $GpoGuid + '},CN=Policies,CN=System,' + $domainDn) `
        -Properties $extensionProps
    if ($null -eq $gpc) { throw ('GPC object not found: ' + $GpoGuid) }

    $machineList = $null
    $userList = $null
    $property = $gpc.PSObject.Properties['gPCMachineExtensionNames']
    if ($null -ne $property -and $null -ne $property.Value) {
        $machineList = [string]$property.Value
    }
    $property = $gpc.PSObject.Properties['gPCUserExtensionNames']
    if ($null -ne $property -and $null -ne $property.Value) {
        $userList = [string]$property.Value
    }

    $dcParts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($label in $DomainDns.Split('.')) {
        $dcParts.Add(('DC=' + $label))
    }
    $policiesBase = 'CN=Policies,CN=System,' + ($dcParts -join ',')

    $guids = New-Object 'System.Collections.Generic.List[string]'
    $containerParams = @{
        SearchBase  = $policiesBase
        SearchScope = 'OneLevel'
        LDAPFilter  = '(objectClass=groupPolicyContainer)'
    }
    $containers = @(Get-ADObject @containerParams)
    foreach ($container in $containers) {
        $guids.Add([string]$container.Name)
    }
    $orderedGuids = $guids.ToArray()
    [Array]::Sort($orderedGuids, [System.StringComparer]::OrdinalIgnoreCase)

    if (-not [System.IO.Directory]::Exists($SysvolGpoPath)) {
        throw ('GPO SYSVOL directory not found: ' + $SysvolGpoPath)
    }
    # MEASURED 2026-09-03 (second estate window): enumerating the PARENT
    # Policies directory lists every GPO's tree, so containment under THIS
    # GPO's GUID could never hold on a populated SYSVOL. The blast radius a
    # transaction can touch is its OWN GPO directory; sibling GPOs are
    # covered by the AD object-set check (policies_gpc_guids). Paths are
    # relative to the GPO directory itself.
    $gpoDir = [System.IO.Path]::GetFullPath($SysvolGpoPath)
    if (-not $gpoDir.EndsWith('\')) { $gpoDir = $gpoDir + '\' }

    $relpaths = New-Object 'System.Collections.Generic.List[string]'
    $items = @(Get-ChildItem -LiteralPath $gpoDir -Force -Recurse)
    foreach ($item in $items) {
        $relative = $item.FullName.Substring($gpoDir.Length).Replace('\', '/')
        if ($relative.StartsWith('/')) { $relative = $relative.Substring(1) }
        if ($relative -eq '') { continue }
        $relpaths.Add($relative)
    }
    $orderedRel = $relpaths.ToArray()
    [Array]::Sort($orderedRel, [System.StringComparer]::OrdinalIgnoreCase)

    $data = @{
        extension_list_machine = $machineList
        extension_list_user    = $userList
        policies_gpc_guids     = $orderedGuids
        sysvol_relpaths        = $orderedRel
    }
    @{ ok = $true; data = $data } | ConvertTo-Json -Depth 5 -Compress
    exit 0
} catch {
    @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Depth 5 -Compress
    exit 2
}
"""

PSL_SNIPPETS: Mapping[str, str] = {
    "gpo_identity": GPO_IDENTITY,
    "sysvol_tree_fingerprint": SYSVOL_TREE_FINGERPRINT,
    "ad_attributes": AD_ATTRIBUTES,
    "version_values": VERSION_VALUES,
    "scripts_ini_raw": SCRIPTS_INI_RAW,
    "scope_forbid": SCOPE_FORBID,
}
