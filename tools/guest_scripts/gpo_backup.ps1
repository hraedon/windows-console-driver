# Cleanup-time evidence preservation: back the GPO up before removal
# (the multi-CSE reference corpus, R5). Output: backup=<path>.
param([string]$Name, [string]$BackupPath)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $BackupPath | Out-Null
Backup-GPO -Name $Name -Path $BackupPath -Comment "wcd transaction capture: $Name" | Out-Null
"backup=$BackupPath"
