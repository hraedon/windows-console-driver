# Cleanup script: strict absence re-query over the zz-studio-evidence-* family.
$ErrorActionPreference = 'Continue'
$left = @(Get-GPO -All | Where-Object { $_.DisplayName -like 'zz-studio-evidence-*' })
"remaining=$($left.Count)"
foreach ($g in $left) { "present=$($g.DisplayName)" }
