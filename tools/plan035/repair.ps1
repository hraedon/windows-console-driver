param($vm, $user, $pw, $admin, $dcFqdn)
# Plan 035 window-19 member repair (operator tool, MUTATING: NICs, clock, machine password).
# usage: run_with_guest_secret.py <estate.toml> repair.ps1 "LAB\claude" "LAB\Administrator" <dc fqdn>
# After the checkpoint revert
# the member holds a machine-account key older than AD's (AD pwdLastSet
# 2026-10-16 > checkpoint 2026-09-20), so every Kerberos logon to it fails.
# Open a PSDirect session on CACHED credentials with the member's NICs
# disconnected, reconnect, fix the clock from host UTC, repair the channel.
$ErrorActionPreference = 'Stop'
$sec = ConvertTo-SecureString $pw -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($user, $sec)
$adminCred = New-Object System.Management.Automation.PSCredential($admin, $sec)
$nics = @(Get-VMNetworkAdapter -VMName $vm | Select-Object Name, SwitchName)
foreach ($n in $nics) { "nic_before=" + $n.Name + " switch=" + $n.SwitchName }
$s = $null
try {
    Get-VMNetworkAdapter -VMName $vm | Disconnect-VMNetworkAdapter
    "nics_disconnected=1"
    Start-Sleep -Seconds 10
    $s = New-PSSession -VMName $vm -Credential $cred
    "cached_session=opened"
} finally {
    foreach ($n in $nics) {
        Get-VMNetworkAdapter -VMName $vm -Name $n.Name | Connect-VMNetworkAdapter -SwitchName $n.SwitchName
    }
    foreach ($n in @(Get-VMNetworkAdapter -VMName $vm)) { "nic_after=" + $n.Name + " switch=" + $n.SwitchName + " connected=" + $n.Connected }
}
Start-Sleep -Seconds 20
$out = Invoke-Command -Session $s -ArgumentList ((Get-Date).ToUniversalTime().ToString('o')) -ScriptBlock {
    param($hostUtc)
    $before = (Get-Date).ToUniversalTime()
    $target = [DateTime]::Parse($hostUtc, $null, [Globalization.DateTimeStyles]::RoundtripKind)
    $offset = (Get-Date) - (Get-Date).ToUniversalTime()
    Set-Date -Date ($target + $offset) | Out-Null
    "guest_utc_before=" + $before.ToString('o')
    "guest_utc_after=" + (Get-Date).ToUniversalTime().ToString('o')
}
$out
$out2 = Invoke-Command -Session $s -ArgumentList $adminCred, $dcFqdn -ScriptBlock {
    param($c, $dc)
    "repair=" + (Test-ComputerSecureChannel -Server $dc -Repair -Credential $c)
    "verify=" + (Test-ComputerSecureChannel -Server $dc)
    klist purge -li 0x3e7 | Out-Null
    "nltest=" + ((nltest /sc_query:ad.labdomain.dev 2>&1) -join ' | ')
}
$out2
try { Remove-PSSession $s } catch { "remove_session_nre=ignored" }
