#requires -Version 5
<#
.SYNOPSIS
    Revert the console member to its recovery checkpoint, then re-sync its
    clock and verify its secure channel before anything else touches it.
.DESCRIPTION
    Estate window 19 (2026-10-20) measured two faults a checkpoint revert
    restores along with the guest:

    1. THE CLOCK. The guest comes back at the checkpoint era's time (30 days
       stale in window 19). Host time synchronization is off on every lab VM
       and the member's w32time source is unreachable, so nothing corrects it.
       Kerberos fails beyond MaxClockSkew (300 s) while NTLM paths stay green.
    2. THE MACHINE KEY. The KDC encrypts service tickets with the member's
       CURRENT machine key. If the member rotated its machine password after
       the checkpoint was minted (AD pwdLastSet newer than the checkpoint), the
       reverted member holds an older key and EVERY Kerberos logon to it fails:
       PSDirect answers "The credential is invalid" for every account.

    This tool therefore:
      [1/4] PRE-CHECK (read-only, member still healthy): reads the checkpoint's
            creation time on the host, and AD pwdLastSet plus
            DisablePasswordChange through the member. A pwdLastSet newer than
            the checkpoint, or rotation not disabled, REFUSES the revert
            (exit 3) unless -Force: the first would break the member now, the
            second at the next rotation.
      [2/4] REVERT: Restore-VMSnapshot -Confirm:$false (the window-9 rule).
      [3/4] TIME SYNC: as soon as PSDirect answers, Set-Date from the host's
            UTC (tz-safe: the host UTC is converted to guest-local inside the
            guest). A refusal with "The credential is invalid" is reported as
            the machine-key fault, at once, instead of waiting out a boot
            timeout.
      [4/4] VERIFY: Test-ComputerSecureChannel (read-only) and the clock delta.
    Then run tools/estate_bringup.ps1 (console logon, helper) and the canary.

    Exit codes follow the canary: 0 ready for bring-up, 3 a precondition or
    verification failed, 2 configuration/usage error.

    SECRETS. The guest password is read from the environment variable the
    estate file NAMES (password_env); the optional host trio likewise. No
    secret reaches argv, output, or a file.
    GUARD RAILS. The VM name must match ^[Ll]ab[A-Za-z0-9]{1,12}$ (disposable
    guests only). The tool reverts the VM the estate file names as vm_name;
    nothing in the tool itself tells a DC from a member, so pointing the
    estate file at the DC is the operator's error to avoid. The member must
    also have machine-password rotation disabled (DisablePasswordChange=1):
    with rotation on, the checkpoint goes stale at the next rotation, so the
    revert is refused unless -Force.
.NOTES
    Operator tool; the suite pins its structure only (ASCII, parse under
    PowerShell 5.1, the guard, the ordering of revert and time sync).
#>
[CmdletBinding()]
param(
    # Path to the estate TOML (flat [estate] table of quoted strings).
    [string] $EstateFile,
    # Seconds to wait for PowerShell Direct after the revert.
    [int] $BootTimeoutSec = 300,
    # Revert even when the pre-check says the checkpoint predates the
    # member's last machine-password change (the member will need repair).
    [switch] $Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $EstateFile) { $EstateFile = Join-Path $repoRoot 'local\estate.toml' }

function Get-EstateConfig {
    param([string] $Path)
    if (-not (Test-Path $Path)) { throw "estate file not found: $Path" }
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
foreach ($required in 'host', 'vm_name', 'domain', 'username', 'password_env', 'checkpoint_name') {
    if (-not $estateTable.ContainsKey($required)) {
        Write-Output "fail: estate file $EstateFile lacks key '$required'"
        exit 2
    }
}
$EstateHost = $estateTable['host']
$Vm = $estateTable['vm_name']
$Checkpoint = $estateTable['checkpoint_name']
$GuestAccount = "{0}\{1}" -f $estateTable['domain'], $estateTable['username']
$GuestSecret = [Environment]::GetEnvironmentVariable($estateTable['password_env'])
if (-not $GuestSecret) {
    Write-Output ("fail: environment variable '{0}' is not set" -f $estateTable['password_env'])
    exit 2
}
if ($Vm -cnotmatch '^[Ll]ab[A-Za-z0-9]{1,12}$') {
    Write-Output ("fail: VM name '{0}' is refused; disposable guests only" -f $Vm)
    exit 2
}

$hostParams = @{ ComputerName = $EstateHost }
$hostTrio = @('host_user_domain', 'host_username', 'host_password_env')
$hostTrioPresent = @($hostTrio | Where-Object { $estateTable.ContainsKey($_) })
if ($hostTrioPresent.Count -gt 0) {
    if ($hostTrioPresent.Count -ne 3) {
        Write-Output 'fail: host credential keys are all-or-none'
        exit 2
    }
    $hostSecret = [Environment]::GetEnvironmentVariable($estateTable['host_password_env'])
    if (-not $hostSecret) {
        Write-Output ("fail: environment variable '{0}' (host secret) is not set" -f $estateTable['host_password_env'])
        exit 2
    }
    $hostParams['Credential'] = [System.Management.Automation.PSCredential]::new(
        ("{0}\{1}" -f $estateTable['host_user_domain'], $estateTable['host_username']),
        (ConvertTo-SecureString $hostSecret -AsPlainText -Force))
    $hostParams['Authentication'] = 'Negotiate'
}
$hostSession = New-PSSession @hostParams

function Invoke-GuestScript {
    # One PSDirect op opened INSIDE the host runspace (the two-hop rule); the
    # script travels as a STRING and output is captured before teardown.
    param([string] $ScriptText, [object[]] $ScriptArgs = @())
    $raw = Invoke-Command -Session $hostSession -ArgumentList $Vm, $GuestAccount, $GuestSecret, $ScriptText, $ScriptArgs -ScriptBlock {
        param($vm, $account, $secret, $scriptText, $scriptArgs)
        $ErrorActionPreference = 'Stop'
        $cred = [System.Management.Automation.PSCredential]::new(
            $account, (ConvertTo-SecureString $secret -AsPlainText -Force))
        $session = New-PSSession -VMName $vm -Credential $cred -ErrorAction Stop
        try {
            $block = [scriptblock]::Create($scriptText)
            if ($scriptArgs) { Invoke-Command -Session $session -ScriptBlock $block -ArgumentList $scriptArgs }
            else { Invoke-Command -Session $session -ScriptBlock $block }
        } finally {
            try { Remove-PSSession $session -ErrorAction SilentlyContinue } catch { }
        }
    }
    , $raw
}

$exitCode = 0
try {
    # --- [1/4] pre-check (read-only) ------------------------------------------
    $created = Invoke-Command -Session $hostSession -ArgumentList $Vm, $Checkpoint -ScriptBlock {
        param($vm, $cp)
        $s = @(Get-VMSnapshot -VMName $vm -Name $cp -ErrorAction SilentlyContinue)
        if ($s.Count -ne 1) { '' } else { $s[0].CreationTime.ToUniversalTime().ToString('o') }
    }
    if (-not $created) {
        Write-Output "fail: [1/4] checkpoint '$Checkpoint' not found exactly once on $Vm"
        exit 3
    }
    $preScript = @'
$c = Get-ADComputer -Identity $env:COMPUTERNAME -Properties pwdLastSet
"pwd_last_set=$([DateTime]::FromFileTimeUtc([Int64]$c.pwdLastSet).ToString('o'))"
"disable_password_change=$((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters').DisablePasswordChange)"
'@
    $pre = Invoke-GuestScript -ScriptText $preScript
    $pwdLastSet = (($pre | Where-Object { $_ -like 'pwd_last_set=*' }) -replace '^pwd_last_set=', '')
    $disable = (($pre | Where-Object { $_ -like 'disable_password_change=*' }) -replace '^disable_password_change=', '')
    Write-Output "[1/4] pre-check: checkpoint $Checkpoint created $created; machine pwdLastSet $pwdLastSet; DisablePasswordChange=$disable"
    if ([string]::CompareOrdinal($pwdLastSet, $created) -gt 0) {
        if (-not $Force) {
            Write-Output 'fail: [1/4] the member changed its machine password AFTER the checkpoint: a revert restores a key the KDC no longer uses and every Kerberos logon to the member fails. Re-mint the checkpoint (rotation disabled first), or pass -Force and repair afterwards.'
            exit 3
        }
        Write-Output '[1/4] pre-check: stale machine key overridden by -Force; expect to repair the secure channel'
    }
    if ($disable -ne '1') {
        if (-not $Force) {
            Write-Output "fail: [1/4] machine-password rotation is enabled on the member (DisablePasswordChange=$disable): the checkpoint goes stale at the next rotation. Set DisablePasswordChange=1 and re-mint the checkpoint, or pass -Force."
            exit 3
        }
        Write-Output '[1/4] pre-check: rotation enabled, overridden by -Force'
    }

    # --- [2/4] revert ------------------------------------------------------------
    Invoke-Command -Session $hostSession -ArgumentList $Vm, $Checkpoint -ScriptBlock {
        param($vm, $cp)
        $s = Get-VMSnapshot -VMName $vm -Name $cp
        Restore-VMSnapshot -VMSnapshot $s -Confirm:$false
    } | Out-Null
    $state = Invoke-Command -Session $hostSession -ArgumentList $Vm -ScriptBlock { param($vm) "$((Get-VM -Name $vm).State)" }
    Write-Output "[2/4] revert: $Vm restored to $Checkpoint (state $state)"

    # --- [3/4] time sync, as soon as PSDirect answers ---------------------------
    $syncScript = @'
param($hostUtc)
$before = [int]([DateTime]::UtcNow - $hostUtc).TotalSeconds
$offset = (Get-Date) - (Get-Date).ToUniversalTime()
Set-Date -Date ($hostUtc + $offset) | Out-Null
"delta_before_s=$before"
"delta_after_s=$([int]([DateTime]::UtcNow - $hostUtc).TotalSeconds)"
'@
    $deadline = (Get-Date).AddSeconds($BootTimeoutSec)
    $sync = $null
    $invalidStreak = 0
    while (-not $sync) {
        try {
            $hostUtc = Invoke-Command -Session $hostSession { [DateTime]::UtcNow }
            $sync = Invoke-GuestScript -ScriptText $syncScript -ScriptArgs @($hostUtc)
        } catch {
            $message = "$($_.Exception.Message)"
            if ($message -match 'credential is invalid') { $invalidStreak++ } else { $invalidStreak = 0 }
            if ($invalidStreak -ge 3) {
                Write-Output 'fail: [3/4] PSDirect refuses the estate credential after the revert ("The credential is invalid"): the reverted member holds an older machine key than AD. Repair: open a session on cached credentials with the member NICs disconnected, reconnect, Set-Date, Test-ComputerSecureChannel -Repair (estate window 19 NOTES).'
                exit 3
            }
            if ((Get-Date) -ge $deadline) {
                Write-Output "fail: [3/4] $Vm never answered PowerShell Direct within $BootTimeoutSec s"
                exit 3
            }
            Start-Sleep -Seconds 10
        }
    }
    foreach ($line in $sync) { Write-Output "       $line" }
    Write-Output '[3/4] time-sync: member clock set from host UTC'

    # --- [4/4] verify (read-only) -------------------------------------------------
    $verifyScript = @'
param($hostUtc)
"secure_channel=$(Test-ComputerSecureChannel)"
"delta_s=$([int]([DateTime]::UtcNow - $hostUtc).TotalSeconds)"
'@
    $hostUtc = Invoke-Command -Session $hostSession { [DateTime]::UtcNow }
    $verify = Invoke-GuestScript -ScriptText $verifyScript -ScriptArgs @($hostUtc)
    foreach ($line in $verify) { Write-Output "       $line" }
    $channel = (($verify | Where-Object { $_ -like 'secure_channel=*' }) -replace '^secure_channel=', '')
    $delta = [int]((($verify | Where-Object { $_ -like 'delta_s=*' }) -replace '^delta_s=', ''))
    if ($channel -ne 'True' -or [Math]::Abs($delta) -gt 300) {
        Write-Output "fail: [4/4] verify: secure_channel=$channel delta=${delta}s"
        $exitCode = 3
    } else {
        Write-Output '[4/4] verify: secure channel healthy, clock within MaxClockSkew'
        Write-Output 'estate-revert-member: READY -- finish with tools/estate_bringup.ps1, then wcd estate-canary'
    }
} finally {
    try { Remove-PSSession $hostSession -ErrorAction SilentlyContinue } catch { }
}
exit $exitCode
