#requires -Version 5
<#
.SYNOPSIS
    Estate teardown: the "leave the estate as found" half of the ritual.

.DESCRIPTION
    tools/estate_teardown.ps1 shuts the console VM (and optionally the DC)
    down the way the estate expects: guest-initiated shutdown.exe /s over
    PowerShell Direct, NOT Stop-VM -- a locked console needs Stop-VM -Force,
    which discards the session state the guest should save itself (the
    measured close path of every window since 8). It waits for the Off
    state, reports one line per VM, and touches nothing else (LabCA01's
    running-but-idle state, for instance, is the operator's business).

    The estate file and secret discipline are estate_bringup.ps1's: the
    same local/estate.toml shape, the same named environment variable, the
    same disposable-guest name guard.

    Exit codes: 0 both shut down, 3 a VM did not reach Off in time,
    2 configuration/usage error.

.NOTES
    Operator tool; the suite tests structure only, never a live host.
#>
[CmdletBinding()]
param(
    # Estate file to read. Defaults to this checkout's local/estate.toml.
    [string] $EstateFile,

    # Also shut down the DC (dc_vm_name from the estate file).
    [switch] $IncludeDc,

    # How long to wait for each guest to reach Off, in seconds.
    [int] $ShutdownTimeoutSec = 300
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $EstateFile) { $EstateFile = Join-Path $repoRoot 'local\estate.toml' }

function Get-EstateConfig {
    param([string] $Path)
    if (-not (Test-Path $Path)) {
        throw "estate file not found: $Path (pass -EstateFile; local/estate.toml is gitignored)"
    }
    $table = @{}
    $inEstate = $false
    foreach ($raw in Get-Content $Path) {
        $line = $raw.Trim()
        if ($line -eq '') { continue }
        if ($line -match '^\[(.+)\]$') { $inEstate = ($Matches[1] -eq 'estate'); continue }
        if (-not $inEstate -or $line.StartsWith('#')) { continue }
        if ($line -match '^([A-Za-z0-9_]+)\s*=\s*"((?:[^"\\]|\\.)*)"\s*(?:#.*)?$') {
            $table[$Matches[1]] = $Matches[2].Replace('\\', '\')
        } elseif ($line -match "^([A-Za-z0-9_]+)\s*=\s*'([^']*)'\s*(?:#.*)?$") {
            $table[$Matches[1]] = $Matches[2]
        } else {
            throw "estate file line is not a simple quoted key: $line"
        }
    }
    return $table
}

$estateTable = Get-EstateConfig -Path $EstateFile
foreach ($required in 'host', 'vm_name', 'domain', 'username', 'password_env') {
    if (-not $estateTable.ContainsKey($required)) {
        Write-Output "fail: estate file $EstateFile lacks key '$required'"
        exit 2
    }
}
$EstateHost = $estateTable['host']
$ConsoleVm = $estateTable['vm_name']
$EstateDomain = $estateTable['domain']
$EstateUser = $estateTable['username']
$GuestSecret = [Environment]::GetEnvironmentVariable($estateTable['password_env'])
if (-not $GuestSecret) {
    Write-Output ("fail: environment variable '{0}' is not set" -f $estateTable['password_env'])
    exit 2
}
$DcVm = if ($estateTable.ContainsKey('dc_vm_name')) { $estateTable['dc_vm_name'] } else { '' }

$vms = @($ConsoleVm)
if ($IncludeDc) {
    if (-not $DcVm) {
        Write-Output 'fail: -IncludeDc but no dc_vm_name in the estate file'
        exit 2
    }
    $vms += $DcVm
}
foreach ($vm in $vms) {
    if ($vm -cnotmatch '^[Ll]ab[A-Za-z0-9]{1,12}$') {
        Write-Output ("fail: VM name '{0}' is refused; disposable guests only" -f $vm)
        exit 2
    }
}

$GuestAccount = "{0}\{1}" -f $EstateDomain, $EstateUser
$hostSession = New-PSSession -ComputerName $EstateHost
$failed = $false
try {
    foreach ($vm in $vms) {
        $state = Invoke-Command -Session $hostSession -ArgumentList $vm -ScriptBlock {
            param($v) "$((Get-VM -Name $v -ErrorAction SilentlyContinue).State)"
        }
        if ($state -eq 'Off') {
            Write-Output "${vm}: already Off"
            continue
        }
        if ($state -ne 'Running') {
            Write-Output "${vm}: state $state (not Running); leaving it alone"
            continue
        }
        $request = Invoke-Command -Session $hostSession -ArgumentList $vm, $GuestAccount, $GuestSecret -ScriptBlock {
            param($v, $account, $secret)
            $ErrorActionPreference = 'Stop'
            $cred = [System.Management.Automation.PSCredential]::new(
                $account, (ConvertTo-SecureString $secret -AsPlainText -Force))
            $guest = New-PSSession -VMName $v -Credential $cred -ErrorAction Stop
            try {
                return Invoke-Command -Session $guest -ScriptBlock {
                    shutdown.exe /s /t 15 /d p:4:1 | Out-Null
                    'requested'
                }
            } catch {
                return "psdirect-failed: $($_.Exception.Message.Split([char]10)[0])"
            } finally {
                if ($guest) { try { Remove-PSSession $guest -ErrorAction SilentlyContinue } catch { } }
            }
        }
        if ("$request" -eq 'requested') {
            Write-Output "${vm}: guest shutdown requested"
        } else {
            Write-Output "fail: ${vm}: $request"
            $failed = $true
            continue
        }
        $deadline = (Get-Date).AddSeconds($ShutdownTimeoutSec)
        do {
            Start-Sleep -Seconds 15
            $state = Invoke-Command -Session $hostSession -ArgumentList $vm -ScriptBlock {
                param($v) "$((Get-VM -Name $v -ErrorAction SilentlyContinue).State)"
            }
        } while ($state -ne 'Off' -and (Get-Date) -lt $deadline)
        if ($state -eq 'Off') {
            Write-Output "${vm}: Off"
        } else {
            Write-Output "fail: ${vm}: still $state after $ShutdownTimeoutSec s"
            $failed = $true
        }
    }
} finally {
    if ($hostSession) { Remove-PSSession $hostSession -ErrorAction SilentlyContinue }
}

if ($failed) { exit 3 }
exit 0
