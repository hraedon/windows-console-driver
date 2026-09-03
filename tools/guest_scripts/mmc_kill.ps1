# Cleanup/setup script: close every mmc window (the editor the GPO is under).
$ErrorActionPreference = 'Continue'
Get-Process mmc -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2
$killed = @(Get-Process mmc -ErrorAction SilentlyContinue).Count
"remaining=$killed"
