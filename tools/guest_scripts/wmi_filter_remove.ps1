# Cleanup script: remove the WMI filter (msWMI-Som object) carrying the
# named msWMI-Name, then re-query and report; report, never throw. The
# re-query doubles as the strict-absence evidence for the capability's
# programmatic_requery cleanup channel: absent=... only after the directory
# itself answers with no matching object.
param([string]$Name)
$ErrorActionPreference = 'Continue'
try {
    $domainDn = (Get-ADRootDSE).defaultNamingContext
    $somBase = 'CN=SOM,CN=WMIPolicy,CN=System,' + $domainDn
    try {
        Get-ADObject -Identity $somBase -ErrorAction Stop | Out-Null
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        "absent=$Name"
        exit 0
    }
    $hits = @(Get-ADObject -SearchBase $somBase -SearchScope OneLevel `
        -LDAPFilter '(objectClass=*)' -Properties msWMI-Name -ErrorAction Stop |
        Where-Object { $_.'msWMI-Name' -eq $Name })
    if ($hits.Count -eq 0) {
        "absent=$Name"
        exit 0
    }
    foreach ($h in $hits) {
        Remove-ADObject -Identity $h.DistinguishedName -Confirm:$false -ErrorAction Stop
    }
    $left = @(Get-ADObject -SearchBase $somBase -SearchScope OneLevel `
        -LDAPFilter '(objectClass=*)' -Properties msWMI-Name -ErrorAction Stop |
        Where-Object { $_.'msWMI-Name' -eq $Name })
    if ($left.Count -eq 0) {
        "removed=$Name"
    } else {
        "remove_incomplete=$Name count=$($left.Count)"
    }
} catch {
    "remove_error=$($_.Exception.Message -replace '[\r\n]', ' ')"
}
