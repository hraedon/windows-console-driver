# Cleanup script: unregister the editor launch task; report, never throw.
param([string]$TaskName)
$ErrorActionPreference = 'Continue'
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
"unregistered=$TaskName"
