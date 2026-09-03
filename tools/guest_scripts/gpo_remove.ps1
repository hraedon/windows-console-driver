# Cleanup script: remove the named GPO; report, never throw.
param([string]$Name)
$ErrorActionPreference = 'Continue'
try {
    Remove-GPO -Name $Name -ErrorAction Stop
    "removed=$Name"
} catch {
    "remove_error=$($_.Exception.Message -replace '[\r\n]', ' ')"
}
