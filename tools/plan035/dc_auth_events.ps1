# Plan 035 operator tool (window 19), READ-ONLY: list the DC Kerberos/NTLM events of the
# last 90 minutes. Run on the host via run_with_guest_secret.py <estate> <this> <user> <dc>.
param($vm, $user, $pw, $dc)
$ErrorActionPreference = 'Stop'
$sec = ConvertTo-SecureString $pw -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($user, $sec)
Invoke-Command -VMName $dc -Credential $cred -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768,4769,4771,4776,4625; StartTime=(Get-Date).AddMinutes(-90)} -MaxEvents 40 -ErrorAction SilentlyContinue | ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}; foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    "ev " + $_.TimeCreated.ToUniversalTime().ToString('HH:mm:ss') + " id=" + $_.Id + " acct=" + $d['TargetUserName'] + " ws=" + $d['Workstation'] + $d['IpAddress'] + " status=" + $d['Status'] + $d['ErrorCode'] + " svc=" + $d['ServiceName']
  }
}
