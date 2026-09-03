# R1 operation-under-test script: author the migration table through the GPMC
# COM API (the exact fallback path the work order specifies for mtedit.exe),
# then Save. Output contract: saved=<path>.
param([string]$Path)
$ErrorActionPreference = 'Stop'
$root = Split-Path $Path -Parent
New-Item -ItemType Directory -Force -Path $root | Out-Null

$gpm = New-Object -ComObject GPMgmt.GPM
$c = $gpm.GetConstants()
$mt = $gpm.CreateMigrationTable()
$mt.AddEntry('LAB\zz-studio-src-group', $c.EntryTypeGlobalGroup, 'LAB\zz-studio-dst-group')
$mt.AddEntry('LAB\zz-studio-src-user', $c.EntryTypeUser, 'LAB\zz-studio-dst-user')
$mt.AddEntry('\\zz-studio-src\share', $c.EntryTypeUNCPath, '\\zz-studio-dst\share')
# MEASURED 2026-09-03 on Server 2025: there is no EntryTypeDomainLocalGroup
# (EntryTypeLocalGroup=2 is the domain-local type), and "same as source" is
# expressed by passing the source name as the destination -- an empty
# destination string throws E_INVALIDARG for this entry type.
$mt.AddEntry('LAB\zz-studio-src-local', $c.EntryTypeLocalGroup, 'LAB\zz-studio-src-local')
$mt.Save($Path)
"saved=$Path"
