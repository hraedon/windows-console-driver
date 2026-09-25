# certsrv.msc surface oracle: certify the CA's officer-rights configuration.
#
# Output contract: deterministic key=value lines on stdout. Any failure emits
# one error=<message> line and exits 2 -- fail closed, never a partial or
# silently truncated observation. The guest only TRANSPORTS; the controller
# (gpo_observers.officerrights) recomputes what can be recomputed and refuses
# disagreement.
#
# Three things make this collector unlike the others in this directory.
#
# 1. IT READS A DIFFERENT MACHINE THAN THE ONE IT RUNS ON. The gesture drives
#    a console on the console guest; the mutation lands in the CA guest's
#    registry. Measured 2026-09-21: OpenRemoteBaseKey from the console guest
#    reads the CA's CertSvc configuration key, raw REG_BINARY included, so
#    the oracle needs no second PSDirect channel -- but the machine it read
#    is a fact in its own right and is emitted as ca.host, because a fact set
#    that does not name its subject cannot be checked against the plan.
#
# 2. THE VALUE IT CERTIFIES DOES NOT EXIST BEFOREHAND. On an unrestricted CA
#    there is no OfficerRights value at all (certutil -getreg answers
#    0x80070002 ERROR_FILE_NOT_FOUND). Absence is therefore a first-class
#    observation, proven by the VALUE-NAME LIST rather than by a failed read:
#    a read that errors cannot distinguish "not there" from "could not look".
#
# 3. IT READS THE SAME THING TWICE THROUGH TWO APIS. The registry read gives
#    presence, length and digest of the opaque bytes. certutil -getreg asks
#    the CA's own RPC surface and, when the value exists, decodes it into
#    named rows. The two answer through different stacks, so a disagreement
#    is visible instead of being averaged away. The bytes themselves are
#    never transported -- only length and digest, as the template surface
#    handles nTSecurityDescriptor.
#
# 4. IT DERIVES THE FOREST'S CA HOSTS FROM THE DIRECTORY (revision 2). The
#    CaHost parameter is an echo: every read above aims at the machine the
#    plan named, so a plan that names the WRONG CA drives gesture and oracle
#    alike with the same wrong argument and the echo agrees all the way
#    down. The directory is the independent source: every enterprise CA
#    publishes a pKIEnrollmentService object under CN=Enrollment Services,
#    each carrying dNSHostName. The host set is ENUMERATED here -- a class
#    search, not a bind to any name the plan supplied -- and transported
#    whole (count, ';'-joined list, digest); the controller compares the
#    plan's argument against the derived set and refuses a non-member
#    BEFORE any mutation. The guest still only transports: the membership
#    decision is the controller's, so the refusal can name both the plan's
#    host and the derived set.
param([string]$CaHost, [string]$CaName)
$ErrorActionPreference = 'Stop'

function Get-TextSha256 {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '')).ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-BytesSha256 {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '')).ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Write-Line {
    param([string]$Key, $Value)
    # CR/LF are flattened so one value can never forge two lines.
    "{0}={1}" -f $Key, (([string]$Value) -replace '[\r\n]', ' ')
}

try {
    if ($CaHost -eq '' -or $CaName -eq '') {
        throw 'CaHost and CaName are both required'
    }

    Write-Line 'ca.host' $CaHost
    Write-Line 'ca.name' $CaName
    Write-Line 'collector.ran_on' $env:COMPUTERNAME

    # -- 1. the CA's configuration key, read remotely -----------------------
    $keyPath = "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName"
    $base = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $CaHost)
    } catch {
        throw "remote registry on '$CaHost' refused: $($_.Exception.Message)"
    }
    $key = $base.OpenSubKey($keyPath)
    if ($null -eq $key) { throw "CA configuration key '$keyPath' not found on '$CaHost'" }
    Write-Line 'config.key_present' 'True'

    # Absence is proven from the NAME LIST, not from a failed read.
    $names = @($key.GetValueNames() | Sort-Object -CaseSensitive)
    Write-Line 'config.value_count' $names.Count
    Write-Line 'config.value_names_sha256' (Get-TextSha256 ($names -join "`n"))

    # -- 2. OfficerRights: the value under test -----------------------------
    $present = $names -contains 'OfficerRights'
    Write-Line 'officerrights.present' $present
    if ($present) {
        $bytes = [byte[]]$key.GetValue('OfficerRights')
        Write-Line 'officerrights.kind'   $key.GetValueKind('OfficerRights')
        Write-Line 'officerrights.bytes'  $bytes.Length
        Write-Line 'officerrights.sha256' (Get-BytesSha256 $bytes)
    } else {
        Write-Line 'officerrights.kind'   ''
        Write-Line 'officerrights.bytes'  0
        Write-Line 'officerrights.sha256' ''
    }

    # -- 3. the same value through the CA's own RPC surface -----------------
    # An independent stack, not a second look down the same one. When the
    # value exists certutil decodes it into named rows; the decoded TEXT is
    # digested (normalised: trimmed, blank lines dropped, CertUtil's own
    # trailer removed) so a semantic change is visible without transporting
    # principal names.
    $config = "$CaHost\$CaName"
    # 2>&1 is safe here MEASURED on this build: certutil writes its failure
    # text to stdout even on error. A native-command write to real stderr under
    # EAP=Stop is terminating in PS 5.1 -- if that mode ever appears it surfaces
    # as a fail-closed collector refusal, not a false observation.
    $raw = (& certutil.exe -config $config -getreg 'CA\OfficerRights' 2>&1 | Out-String)
    Write-Line 'officerrights.certutil_rc' $LASTEXITCODE
    if ($LASTEXITCODE -eq 0) {
        $lines = @($raw -split "`r?`n" |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -ne '' -and $_ -notmatch '^CertUtil:' -and $_ -notmatch '^HKEY_' })
        Write-Line 'officerrights.decoded_present' 'True'
        Write-Line 'officerrights.decoded_rows'    $lines.Count
        Write-Line 'officerrights.decoded_sha256'  (Get-TextSha256 ($lines -join "`n"))
    } else {
        Write-Line 'officerrights.decoded_present' 'False'
        Write-Line 'officerrights.decoded_rows'    0
        Write-Line 'officerrights.decoded_sha256'  ''
    }

    # -- 4. forbid scopes: what this capability must NOT move ---------------
    # The base role assignment. Managers are granted on the Security tab and
    # this capability only RESTRICTS an existing one, so the descriptor must
    # be shown not to have moved -- the page even says so ("configured on the
    # Security tab"), which is a claim worth checking rather than believing.
    $sec = [byte[]]$key.GetValue('Security')
    if ($null -eq $sec) { throw "CA configuration on '$CaHost' has no Security value" }
    Write-Line 'security.bytes'  $sec.Length
    Write-Line 'security.sha256' (Get-BytesSha256 $sec)

    # The published-template list, read from AD rather than from the CA: a
    # third channel, and the authoritative one for publication. Restricting a
    # manager must not publish or unpublish anything.
    $root = ([ADSI]'LDAP://RootDSE').configurationNamingContext
    $esDn = "LDAP://CN=$CaName,CN=Enrollment Services,CN=Public Key Services,CN=Services,$root"
    $es = [ADSI]$esDn
    if ($null -eq $es.Path) { throw "enrollment-services object for '$CaName' not found in AD" }
    $published = @()
    if ($null -ne $es.Properties['certificateTemplates']) {
        $published = @($es.Properties['certificateTemplates'] | ForEach-Object { [string]$_ } | Sort-Object -CaseSensitive)
    }
    Write-Line 'published.count'       $published.Count
    Write-Line 'published.names_sha256' (Get-TextSha256 ($published -join "`n"))

    # -- 5. the forest's CA hosts, derived from the directory ---------------
    # Revision 2. The echo check the controller already performs (ca.host vs
    # the plan's argument) catches a garbled or misrouted read; it cannot
    # catch a plan that itself names the wrong CA, because both sides of it
    # are the same argument. This enumeration takes NO input from the plan:
    # it searches the class itself and derives the host set the forest
    # actually publishes. dNSHostName is single-valued on pKIEnrollmentService;
    # an object that does not carry exactly one refuses the observation
    # rather than silently shrinking the derived set.
    $searcher = New-Object System.DirectoryServices.DirectorySearcher(
        ([ADSI]"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$root"))
    $searcher.Filter = '(objectClass=pKIEnrollmentService)'
    [void]$searcher.PropertiesToLoad.Add('dNSHostName')
    $caHosts = @()
    try {
        foreach ($result in @($searcher.FindAll())) {
            $nameValues = @($result.Properties['dNSHostName'])
            if ($nameValues.Count -ne 1 -or ([string]$nameValues[0]) -eq '') {
                throw ('enrollment-services object without exactly one dNSHostName: ' + $result.Path)
            }
            $caHosts += ([string]$nameValues[0])
        }
    } finally {
        $searcher.Dispose()
    }
    $caHosts = @($caHosts | Sort-Object -CaseSensitive -Unique)
    Write-Line 'ca.directory.count'       $caHosts.Count
    Write-Line 'ca.directory.hosts'       ($caHosts -join ';')
    Write-Line 'ca.directory.hosts_sha256' (Get-TextSha256 ($caHosts -join "`n"))

    $key.Dispose()
    $base.Dispose()
} catch {
    "error=$(($_.Exception.Message) -replace '[\r\n]', ' ')"
    exit 2
}
