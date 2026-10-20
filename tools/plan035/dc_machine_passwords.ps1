# Plan 035 operator tool (window 19), READ-ONLY: every computer account pwdLastSet plus
# the DC Netlogon password-change settings and time source. Compare against
# Get-VMSnapshot creation times: a member whose pwdLastSet is newer than its
# checkpoint cannot take a Kerberos logon after a revert to it.
param($vm, $user, $pw, $dc)
$ErrorActionPreference = 'Stop'
$cred = New-Object System.Management.Automation.PSCredential($user, (ConvertTo-SecureString $pw -AsPlainText -Force))
Invoke-Command -VMName $dc -Credential $cred -ScriptBlock {
  Get-ADComputer -Filter * -Properties pwdLastSet,whenCreated,OperatingSystem | ForEach-Object { "computer=" + $_.Name + " pwdLastSet=" + [DateTime]::FromFileTimeUtc($_.pwdLastSet).ToString('yyyy-MM-ddTHH:mmZ') + " created=" + $_.whenCreated.ToUniversalTime().ToString('yyyy-MM-dd') }
  $p = Get-ADDefaultDomainPasswordPolicy; "maxpwdage=" + $p.MaxPasswordAge
  "dc_disable_pwchange=" + (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ErrorAction SilentlyContinue).DisablePasswordChange
  "dc_maxpwage_reg=" + (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ErrorAction SilentlyContinue).MaximumPasswordAge
  "w32tm=" + ((w32tm /query /source) -join ' ')
}
