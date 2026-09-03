# Setup script: create the disposable unlinked evidence GPO.
# Output contract: guid=<id> lines (parsed by the run-sheet executor).
param([string]$Name, [string]$Comment)
$ErrorActionPreference = 'Stop'
$existing = Get-GPO -Name $Name -ErrorAction SilentlyContinue
if ($existing) { throw "GPO $Name already exists; cleanup discipline violated" }
$gpo = New-GPO -Name $Name -Comment $Comment
"guid=$($gpo.Id)"
"domain=$($gpo.DomainName)"
