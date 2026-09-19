# certtmpl.msc surface prep: enumerate the forest Certificate Templates
# container and certify the named target template plus the named source
# template it was duplicated from. Output contract: container.* /
# per-object / target.* / source.* key=value lines on stdout, records
# sorted by name (ordinal). Any failure -- including a container above the
# object bound -- emits one error=<message> line and exits 2: fail closed,
# never a partial or silently truncated observation. The guest only
# transports; the controller (gpo_observers.certtmpl) recomputes the
# counts and digests from the records and refuses disagreement.
#
# MEASURED ENCODING (live read-only pass against a Server 2025 forest,
# 2026-09-19): template objects under CN=Certificate Templates,... are
# class pKICertificateTemplate and carry NO msPKI-Validity-Period /
# msPKI-Validity-PeriodUnits attributes (Get-ADObject rejects those
# property names). Validity is stored as two 8-byte blobs,
# pKIExpirationPeriod and pKIOverlapPeriod, each a little-endian signed
# int64 of NEGATIVE 100-nanosecond ticks (a duration; a "year" is exactly
# 365 days, so the 5*365d blob is byte-identical to what multiple real
# templates carry). The blobs transport as UPPERCASE hex strings; the
# controller decodes days with pure integer arithmetic
# (-ticks) // 864000000000 because floats lose precision above ~9e15
# ticks. Absent or null blobs transport as ''.
param([string]$Template, [string]$DomainDns, [string]$Source)
$ErrorActionPreference = 'Stop'

$objectBound = 512

function Get-Prop($Obj, [string]$Name) {
    # Absent and empty attributes both transport as '' (the line protocol
    # has no null spelling); CR/LF are flattened so one attribute can never
    # forge two lines.
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return '' }
    return ([string]$p.Value -replace '[\r\n]', ' ')
}

function Get-PropHex($Obj, [string]$Name) {
    # An 8-byte duration blob transports as UPPERCASE hex (16 chars, no
    # separators); an absent or null attribute transports as '' -- the
    # same absence convention as Get-Prop.
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return '' }
    return [BitConverter]::ToString([byte[]]$p.Value).Replace('-', '')
}

function Get-TextSha256 {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $hex = [System.BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '')
        return $hex.ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

try {
    if ($Template -eq '' -or $DomainDns -eq '' -or $Source -eq '') {
        throw 'Template, DomainDns and Source parameters are required'
    }

    # Forest DN derived from the domain DNS name (single-domain-forest
    # assumption, same derivation shape as the scope_forbid snippet);
    # identifiers arrive as parameters and are never interpolated.
    $dcParts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($label in $DomainDns.Split('.')) {
        $dcParts.Add(('DC=' + $label))
    }
    $templateBase = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,' + ($dcParts -join ',')

    $containerPresent = $false
    try {
        Get-ADObject -Identity $templateBase -ErrorAction Stop | Out-Null
        $containerPresent = $true
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        $containerPresent = $false
    }

    $objects = @()
    if ($containerPresent) {
        # Bounded fetch. displayName rides along in the property set but is
        # deliberately NOT emitted: no fact key consumes it yet, and the
        # observer discipline is to transport only what a fact evaluates.
        # The validity property names are the MEASURED set: the DN-form
        # msPKI-Validity-Period / msPKI-Validity-PeriodUnits attributes do
        # not exist on 2025-forest pKICertificateTemplate objects, so they
        # are not requested (Get-ADObject would reject the property names).
        $objects = @(Get-ADObject -SearchBase $templateBase -SearchScope OneLevel `
            -LDAPFilter '(objectClass=*)' -ErrorAction Stop `
            -Properties cn, displayName, pKIExpirationPeriod, pKIOverlapPeriod, `
                msPKI-Template-Schema-Version, msPKI-Certificate-Name-Flag, `
                msPKI-Private-Key-Flag, nTSecurityDescriptor)
    }
    if ($objects.Count -gt $objectBound) {
        throw ('container object count ' + $objects.Count + ' exceeds bound ' + $objectBound)
    }

    if ($containerPresent) { 'container.present=1' } else { 'container.present=0' }

    $byName = @{}
    $unnamedCount = 0
    foreach ($o in $objects) {
        $cn = Get-Prop -Obj $o -Name 'cn'
        if ($cn -eq '') {
            # Name unreadable: the object is unmeasurable beyond its
            # existence, so it contributes a bare name= line and the
            # unnamed count, never guessed attribute lines.
            $unnamedCount += 1
            continue
        }
        if ($byName.ContainsKey($cn)) {
            throw ('duplicate template name: ' + $cn)
        }
        # VERIFIED against .NET Framework 4.8 reflection (no live AD run
        # yet): PS 5.1's ActiveDirectorySecurity exposes
        # GetSecurityDescriptorSddlForm(AccessControlSections) -- there is
        # no GetSddlForm on this type, and the AccessSections enum the .NET
        # docs name does not resolve under 5.1. 'All' =
        # Owner|Group|Access|Audit: the pre/post digest must see
        # owner/group/DACL edits, and sections the caller cannot read
        # serialize as absent -- deterministically, which is all the
        # comparison needs.
        $sddl = $o.nTSecurityDescriptor.GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]::All)
        $byName[$cn] = @{
            expiration_period  = Get-PropHex -Obj $o -Name 'pKIExpirationPeriod'
            overlap_period     = Get-PropHex -Obj $o -Name 'pKIOverlapPeriod'
            schema_version     = Get-Prop -Obj $o -Name 'msPKI-Template-Schema-Version'
            cert_name_flag     = Get-Prop -Obj $o -Name 'msPKI-Certificate-Name-Flag'
            key_flag           = Get-Prop -Obj $o -Name 'msPKI-Private-Key-Flag'
            sddl_len           = [string]$sddl.Length
            sddl_sha256        = Get-TextSha256 -Text $sddl
        }
    }

    # Casefold (case-insensitive) matching, mirroring AD name semantics and
    # the controller's refusal discipline: exactly one match echoes the
    # block, zero matches echo present=0 with no detail lines, and more
    # than one match refuses the whole observation. Checked before any
    # record emission so a refusal never emits a half observation.
    $templateFold = $Template.ToLowerInvariant()
    $sourceFold = $Source.ToLowerInvariant()
    $targetMatches = @()
    $sourceMatches = @()
    foreach ($n in $byName.Keys) {
        $folded = $n.ToLowerInvariant()
        if ($folded -eq $templateFold) { $targetMatches += $n }
        if ($folded -eq $sourceFold) { $sourceMatches += $n }
    }
    if ($targetMatches.Count -gt 1) {
        throw ('target name matches more than one template: ' + $Template)
    }
    if ($sourceMatches.Count -gt 1) {
        throw ('source name matches more than one template: ' + $Source)
    }
    $targetCn = $null
    $sourceCn = $null
    if ($targetMatches.Count -eq 1) { $targetCn = $targetMatches[0] }
    if ($sourceMatches.Count -eq 1) { $sourceCn = $sourceMatches[0] }

    # Unnamed records first (the empty name sorts first ordinally), then
    # the named records in ordinal name order.
    for ($i = 0; $i -lt $unnamedCount; $i++) { 'name=' }

    $names = @($byName.Keys)
    [Array]::Sort($names, [System.StringComparer]::Ordinal)
    foreach ($n in $names) {
        $r = $byName[$n]
        'name=' + $n
        'expiration_period=' + $r['expiration_period']
        'overlap_period=' + $r['overlap_period']
        'schema_version=' + $r['schema_version']
        'cert_name_flag=' + $r['cert_name_flag']
        'key_flag=' + $r['key_flag']
        'sddl_len=' + $r['sddl_len']
        'sddl_sha256=' + $r['sddl_sha256']
    }

    # Membership digests (LF-joined sorted names, UTF-8, lowercase hex) so
    # pre/post comparison detects ANY membership change without committing
    # real template names. -ne is case-insensitive, matching AD name
    # semantics; the digest itself stays ordinal over the stored spelling.
    $otherNames = New-Object 'System.Collections.Generic.List[string]'
    foreach ($n in $names) {
        if ($n -ne $Template) { $otherNames.Add($n) }
    }
    'container.object_count=' + $objects.Count
    'container.names_sha256=' + (Get-TextSha256 -Text ($names -join "`n"))
    'container.other_names_sha256=' + (Get-TextSha256 -Text ($otherNames -join "`n"))
    'container.other_count=' + $otherNames.Count
    'container.unnamed_count=' + $unnamedCount

    if ($null -eq $targetCn) {
        'target.present=0'
    } else {
        $t = $byName[$targetCn]
        'target.present=1'
        'target.name=' + $targetCn
        'target.expiration_period=' + $t['expiration_period']
        'target.overlap_period=' + $t['overlap_period']
        'target.schema_version=' + $t['schema_version']
        'target.cert_name_flag=' + $t['cert_name_flag']
        'target.key_flag=' + $t['key_flag']
        'target.sddl_len=' + $t['sddl_len']
        'target.sddl_sha256=' + $t['sddl_sha256']
    }

    # The source block transports the SAME attribute set as the target
    # block (descriptor digest included) so the two blocks share one
    # protocol shape; the controller validates both identically but emits
    # facts only for the source attributes the fidelity claim needs --
    # source.sddl_len / source.sddl_sha256 cross the wire, then stop there.
    if ($null -eq $sourceCn) {
        'source.present=0'
    } else {
        $s = $byName[$sourceCn]
        'source.present=1'
        'source.name=' + $sourceCn
        'source.expiration_period=' + $s['expiration_period']
        'source.overlap_period=' + $s['overlap_period']
        'source.schema_version=' + $s['schema_version']
        'source.cert_name_flag=' + $s['cert_name_flag']
        'source.key_flag=' + $s['key_flag']
        'source.sddl_len=' + $s['sddl_len']
        'source.sddl_sha256=' + $s['sddl_sha256']
    }
    exit 0
} catch {
    'error=' + ($_.Exception.Message -replace '[\r\n]', ' ')
    exit 2
}
