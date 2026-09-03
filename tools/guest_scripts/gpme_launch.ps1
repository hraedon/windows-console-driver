# Setup script: deep-launch GPME straight onto a GPO in the console session
# (scheduled task, Interactive + Highest => elevated token on the console
# desktop, no UAC mid-flight).
# MEASURED 2026-09-03 (second estate window): the /gpobject:"domain\{guid}"
# form raises a "Group Policy Error" dialog on Server 2025 and mmc exits; the
# LDAP-path form opens the editor onto the GPO reliably.
param([string]$Guid, [string]$Domain)
$ErrorActionPreference = 'Stop'
$dcParts = foreach ($label in $Domain.Split('.')) { "DC=$label" }
$ldap = 'LDAP://CN={' + $Guid + '},CN=Policies,CN=System,' + ($dcParts -join ',')
$arg = '/gpobject:"' + $ldap + '"'
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\gpedit.msc" -Argument $arg
$principal = New-ScheduledTaskPrincipal -UserId 'LAB\claude' -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 'WCDLaunchGPME' -Action $action -Principal $principal `
    -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 'WCDLaunchGPME'
"launched=1"
