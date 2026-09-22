# Cleanup script: remove the OfficerRights value the gesture created from the
# CA guest's CertSvc configuration, restoring the pre-state -- which on this
# surface is the value's ABSENCE, not a prior value.
#
# Run from the CONSOLE guest against the CA guest's registry, the same remote
# path the observer reads through. No checkpoint revert can reach this
# mutation: the console guest's checkpoint is the wrong machine, and the CA
# guest's would be a far heavier instrument than the change deserves.
#
# Strict absence is re-queried through BOTH read channels, and that is not
# belt-and-braces. If the registry says the value is gone and certutil still
# decodes it, the running CertSvc is holding a cached copy -- which answers
# the service-restart question this capability could not settle off-window,
# and does so as a recorded residual rather than a silent pass.
#
# Output contract: removed=/absent_registry=/absent_certutil=/residual= lines.
# Any failure emits one error=<message> line and exits 2.
param([string]$CaHost, [string]$CaName)
$ErrorActionPreference = 'Stop'

function Write-Line {
    param([string]$Key, $Value)
    "{0}={1}" -f $Key, (([string]$Value) -replace '[\r\n]', ' ')
}

try {
    if ($CaHost -eq '' -or $CaName -eq '') {
        throw 'CaHost and CaName are both required'
    }
    $keyPath = "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName"

    # Writable open: the read path the observer uses is read-only, so this
    # asks for its own access rather than assuming the observer's handle
    # would have carried it.
    $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $CaHost)
    $key = $base.OpenSubKey($keyPath, $true)
    if ($null -eq $key) { throw "CA configuration key '$keyPath' not found on '$CaHost'" }

    $before = ($key.GetValueNames() -contains 'OfficerRights')
    Write-Line 'present_before' $before
    if ($before) {
        $key.DeleteValue('OfficerRights', $false)
        Write-Line 'removed' 'True'
    } else {
        # Nothing to remove is a legitimate cleanup outcome (an aborted run
        # that never crossed its commit point), not an error.
        Write-Line 'removed' 'False'
    }

    # Channel 1: the value-name list.
    $key.Close()
    $key = $base.OpenSubKey($keyPath)
    $absentRegistry = -not ($key.GetValueNames() -contains 'OfficerRights')
    Write-Line 'absent_registry' $absentRegistry

    # Channel 2: the CA's own RPC surface.
    # See officerrights_collect.ps1: certutil's error text goes to stdout on
    # this build; real stderr under EAP=Stop would throw (fail-closed).
    & certutil.exe -config "$CaHost\$CaName" -getreg 'CA\OfficerRights' 2>&1 | Out-Null
    $absentCertutil = ($LASTEXITCODE -ne 0)
    Write-Line 'absent_certutil' $absentCertutil
    Write-Line 'certutil_rc' $LASTEXITCODE

    if ($absentRegistry -and -not $absentCertutil) {
        Write-Line 'residual' 'certsvc_cached_officerrights'
    } elseif (-not $absentRegistry) {
        Write-Line 'residual' 'officerrights_still_present'
    } else {
        Write-Line 'residual' ''
    }

    $key.Dispose()
    $base.Dispose()
} catch {
    "error=$(($_.Exception.Message) -replace '[\r\n]', ' ')"
    exit 2
}
