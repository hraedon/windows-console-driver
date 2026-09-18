# Cleanup script: remove the duplicated certificate template
# (pKICertificateTemplate object) carrying the recorded CN under the forest
# configuration partition, then re-query and report; report, never throw.
# The re-query doubles as the strict-absence evidence for the capability's
# programmatic_requery cleanup channel: absent=/removed= only after the
# directory itself answers with no matching object, and the query names the
# RECORDED template name (the wmi GUID-discipline analog: never a wildcard
# that would count unrelated templates as residue). Removal is
# directory-side only: the template lives in the configuration partition,
# which a guest checkpoint revert cannot reach.
param([string]$Template)
$ErrorActionPreference = 'Continue'
try {
    $configNc = (Get-ADRootDSE).configurationNamingContext
    $templateBase = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,' + $configNc
    try {
        Get-ADObject -Identity $templateBase -ErrorAction Stop | Out-Null
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        "absent=$Template"
        exit 0
    }
    $hits = @(Get-ADObject -SearchBase $templateBase -SearchScope OneLevel `
        -LDAPFilter '(objectClass=*)' -Properties cn -ErrorAction Stop |
        Where-Object { $_.cn -eq $Template })
    if ($hits.Count -eq 0) {
        "absent=$Template"
        exit 0
    }
    foreach ($h in $hits) {
        Remove-ADObject -Identity $h.DistinguishedName -Confirm:$false -ErrorAction Stop
    }
    $left = @(Get-ADObject -SearchBase $templateBase -SearchScope OneLevel `
        -LDAPFilter '(objectClass=*)' -Properties cn -ErrorAction Stop |
        Where-Object { $_.cn -eq $Template })
    if ($left.Count -eq 0) {
        "removed=$Template"
    } else {
        "remove_incomplete=$Template count=$($left.Count)"
    }
} catch {
    "remove_error=$($_.Exception.Message -replace '[\r\n]', ' ')"
}
