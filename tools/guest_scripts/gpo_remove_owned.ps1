# Cleanup script: remove ONLY the GPO this transaction created, by the GUID
# setup captured right after New-GPO (Plan 035 review). The run-sheet passes
# {out.setup.gpo.guid}; when setup never produced one, that reference does not
# resolve, the step fails before this script runs, and no GPO is removed --
# a name-based removal could delete a pre-existing GPO the transaction refused
# to overwrite. Report, never throw.
param([string]$Guid)
$ErrorActionPreference = 'Continue'
$parsed = [Guid]::Empty
if (-not [Guid]::TryParse($Guid, [ref]$parsed) -or $parsed -eq [Guid]::Empty) {
    "remove_skipped=no_owned_guid"
    return
}
try {
    Remove-GPO -Guid $parsed -ErrorAction Stop
    "removed_guid=$parsed"
} catch {
    "remove_error=$($_.Exception.Message -replace '[\r\n]', ' ')"
}
