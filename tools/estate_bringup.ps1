#requires -Version 5
<#
.SYNOPSIS
    Estate bring-up: the recurring pre-window ritual, automated and idempotent.

.DESCRIPTION
    tools/estate_bringup.ps1 takes the lab from "machines Off" (or drifted)
    to "lane-ready" in the order the failures actually occur, one line per
    step, fail closed. Every step checks first and acts only when needed, so
    re-running against an already-healthy estate changes nothing.

    The ritual is the one measured across windows 7 and 8 (see
    docs/estate-window-8/NOTES.md), previously executed as ad-hoc scripts:

    1. DC BOOT      Start the DC if Off, wait for PowerShell Direct.
    2. DC CLOCK     Compare the DC clock against the host. Beyond Kerberos
                    MaxClockSkew (300s measured, R7) -- the trap that recurs
                    on EVERY DC restore -- repair it: Set-Date from the
                    host's UTC (converted to DC-local, so the DC timezone
                    does not matter), nltest /dsregdns, restart NetLogon,
                    re-verify. This failure hides from NTLM probes, which is
                    exactly why it survives a green canary.
    3. MEMBER BOOT  Start the console VM if Off, wait for PowerShell Direct.
    4. MEMBER CLOCK Same probe and same tolerance against the console VM.
                    Window 12 measured that a revert-based lane resets the
                    MEMBER clock to the checkpoint era exactly as every DC
                    restore always has (~44 h stale), while this tool's
                    repair was DC-scoped -- the canary caught it as kerberos
                    red with every NTLM path green. The member repair is
                    Set-Date only: no dsregdns, no NetLogon restart (the
                    member is not the KDC; the 2026-09-22 repair went green
                    on the canary with Set-Date alone).
    5. MEMBER DOMAIN  nltest /dsgetdc from the member; a dead locator gets
                    one nltest /sc_reset attempt before failing. A member
                    reboot is deliberately NOT automatic: it would kill the
                    console session this tool establishes in the next step,
                    and that trade is the operator's to make.
    6. CONSOLE      Establish the interactive console session if there is
                    none: CAD -> username -> TAB -> password -> ENTER via
                    Msvm_Keyboard injection (the measured logon path), then
                    re-check quser/LogonUI. The Server Manager WAC/Arc
                    promo dialog that appears on fresh logons is
                    non-blocking once GPMC launches (window 8) and is left
                    alone.
    7. HELPER       The WCDHelper scheduled task: present and not disabled
                    -> report only. Missing (or -RedeployHelper) -> two-hop
                    deploy of guest/helper.ps1 (controller -> host staging ->
                    guest), task registered with the measured principal
                    (domain user, Interactive, Highest), then a context
                    smoke request through the task itself.

    Exit codes follow the canary: 0 ready, 3 a precondition failed, 2
    configuration/usage error.

    SECRETS. The guest password is read from the environment variable the
    estate file NAMES (password_env); the optional host credential trio
    likewise. No secret reaches argv, output, or a file. The logon injection
    path reports character INDEXES on mapping failures, never characters.

    REMOTING SHAPE. The guest password travels controller -> host over the
    host session's encrypted channel as a PSCredential (the same route every
    window-8 repair script used), and guest scripts travel as STRINGS that
    the host runspace compiles -- a scriptblock cannot survive the
    controller -> host hop as data, so nothing in this tool tries. Guest
    output is always captured BEFORE session teardown because
    Remove-PSSession throws a terminating NRE after successful work
    ~25-50% of the time on this estate.

    GUARD RAILS. VM names must match ^[Ll]ab[A-Za-z0-9]{1,12}$ (disposable
    guests only, the convention guest/hyperv-input.ps1 enforces -- this tool
    boots machines and injects logons, so it takes the guard). The DC
    fallback account defaults to the estate's measured NetBIOS form
    (LAB\Administrator, window-8 NOTES): a DC restored to an older baseline
    predates the current domain password, and the bootstrap Administrator
    secret still opens it.

.NOTES
    Live path is an operator tool; the suite tests its structure only
    (ASCII, parse under PowerShell 5.1), never against a live host.
#>
[CmdletBinding()]
param(
    # Estate file to read. Defaults to this checkout's local/estate.toml
    # (gitignored; names the real host).
    [string] $EstateFile,

    # Kerberos MaxClockSkew in seconds; beyond it a guest clock is repaired.
    [int] $ClockToleranceSec = 300,

    # How long to wait for each guest to answer PowerShell Direct after
    # Start-VM, in seconds.
    [int] $BootTimeoutSec = 600,

    # Seconds to wait after ENTER at the logon UI before re-checking.
    [int] $LogonSettleSec = 45,

    # Skip the DC entirely (steps 1-2); for work that does not need AD.
    [switch] $SkipDc,

    # Redeploy guest/helper.ps1 and re-register the task even if present.
    [switch] $RedeployHelper,

    # The DC PSDirect fallback when the domain account predates a restored
    # baseline's password: the bootstrap Administrator, NetBIOS form.
    [string] $FallbackAccount = 'LAB\Administrator'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $EstateFile) { $EstateFile = Join-Path $repoRoot 'local\estate.toml' }

# --- estate file (flat [estate] table of quoted strings; our config shape) ----

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
            # TOML basic string; our file escapes backslashes only.
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
    Write-Output ("fail: environment variable '{0}' is not set; the estate file names secrets, it never carries them" -f $estateTable['password_env'])
    exit 2
}
$HelperTask = if ($estateTable.ContainsKey('helper_task')) { $estateTable['helper_task'] } else { 'WCDHelper' }
$HelperDir = if ($estateTable.ContainsKey('helper_dir')) { $estateTable['helper_dir'] } else { 'C:\lab\wcd' }
$DcVm = if ($estateTable.ContainsKey('dc_vm_name')) { $estateTable['dc_vm_name'] } else { '' }

foreach ($vm in @($ConsoleVm) + $(if ($DcVm) { @($DcVm) } else { @() })) {
    if ($vm -cnotmatch '^[Ll]ab[A-Za-z0-9]{1,12}$') {
        Write-Output ("fail: VM name '{0}' is refused; disposable guests only (^[Ll]ab[A-Za-z0-9]{{1,12}}$), the guard guest/hyperv-input.ps1 enforces" -f $vm)
        exit 2
    }
}
if (-not $SkipDc -and -not $DcVm) {
    Write-Output 'fail: no dc_vm_name in the estate file and -SkipDc not given; name the DC or skip it'
    exit 2
}

# --- host session (explicit trio when the estate names one, integrated otherwise)

$hostParams = @{ ComputerName = $EstateHost }
$hostTrio = @('host_user_domain', 'host_username', 'host_password_env')
$hostTrioPresent = @($hostTrio | Where-Object { $estateTable.ContainsKey($_) })
if ($hostTrioPresent.Count -gt 0) {
    if ($hostTrioPresent.Count -ne 3) {
        Write-Output ("fail: host credential keys in {0} are all-or-none; missing: {1}" -f $EstateFile, (($hostTrio | Where-Object { $estateTable.ContainsKey($_) -eq $false }) -join ', '))
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
    Write-Output "host: WinRM to $EstateHost with the estate's explicit host credential"
} else {
    Write-Output "host: WinRM to $EstateHost with the controller's integrated credential"
}
$hostSession = New-PSSession @hostParams
$failed = $false

# The primary guest account (DNS-domain form) and the measured fallback,
# lifted into a script-scope working variable the guest-op function closes over.
$GuestAccount = "{0}\{1}" -f $EstateDomain, $EstateUser
$DcFallbackAccount = $FallbackAccount

function Invoke-GuestScript {
    # One guest op, end to end, on a VM: open a PSDirect session INSIDE the
    # host runspace (the two-hop rule), try the domain account then the
    # fallback, compile the STRING script in the host runspace (scriptblocks
    # cannot cross the wire as data), capture output BEFORE teardown (the
    # Remove-PSSession NRE trap), and prefix which account answered.
    param(
        [string] $Vm,
        [string] $ScriptText,
        [object[]] $ScriptArgs = @()
    )
    $raw = Invoke-Command -Session $hostSession -ArgumentList $Vm, $GuestAccount, $DcFallbackAccount, $GuestSecret, $ScriptText, $ScriptArgs -ScriptBlock {
        param($vm, $account, $fallback, $secret, $scriptText, $scriptArgs)
        $ErrorActionPreference = 'Stop'
        $build = {
            param($name, $secretValue)
            [System.Management.Automation.PSCredential]::new(
                $name, (ConvertTo-SecureString $secretValue -AsPlainText -Force))
        }
        $session = $null
        $accountUsed = $account
        try { $session = New-PSSession -VMName $vm -Credential (& $build $account $secret) -ErrorAction Stop }
        catch {
            $accountUsed = $fallback
            $session = New-PSSession -VMName $vm -Credential (& $build $fallback $secret) -ErrorAction Stop
        }
        try {
            $block = [scriptblock]::Create($scriptText)
            $out = if ($scriptArgs) { Invoke-Command -Session $session -ScriptBlock $block -ArgumentList $scriptArgs }
                   else { Invoke-Command -Session $session -ScriptBlock $block }
            return @("account=$accountUsed") + @($out)
        } finally {
            if ($session) { try { Remove-PSSession $session -ErrorAction SilentlyContinue } catch { } }
        }
    }
    , $raw
}

function Wait-GuestPsDirect {
    param([string] $Vm, [int] $TimeoutSec)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ($true) {
        Start-Sleep -Seconds 20
        try {
            $probe = Invoke-GuestScript -Vm $Vm -ScriptText '"up=$([DateTime]::UtcNow.ToString("u"))"'
            return (($probe | Where-Object { $_ -like 'up=*' }) -join '')
        } catch {
            if ((Get-Date) -ge $deadline) { return $null }
        }
    }
}

function Get-VmState {
    param([string] $Vm)
    return Invoke-Command -Session $hostSession -ArgumentList $Vm -ScriptBlock {
        param($vm)
        "$((Get-VM -Name $vm -ErrorAction SilentlyContinue).State)"
    }
}

# Session facts: quser + LogonUI, single probe. A failed quser IS the answer
# (no session), so its stderr folds into the line instead of killing EAP.
$SessionFactsScript = @'
$ErrorActionPreference = 'Continue'
$q = (quser 2>&1 | Out-String).Trim()
"quser=$($q -replace [Environment]::NewLine, ' | ')"
"logonui=$([bool](Get-Process LogonUI -ErrorAction SilentlyContinue))"
'@

function Test-ConsoleSession {
    # True when the facts lines show a live console session.
    param([string[]] $Lines)
    $quserLine = (($Lines | Where-Object { $_ -like 'quser=*' }) -replace '^quser=', '')
    $logonUi = (($Lines | Where-Object { $_ -like 'logonui=*' }) -replace 'logonui=', '')
    $hasSession = (($quserLine -match 'console') -or
        ($quserLine -ne '' -and $quserLine -notmatch 'No User exists' -and $logonUi -ne 'True'))
    return $hasSession
}

try {
    # --- [1/7] DC boot ----------------------------------------------------------
    if ($SkipDc) {
        Write-Output '[1/7] dc-boot: skipped (-SkipDc)'
    } else {
        $state = Get-VmState -Vm $DcVm
        if ($state -ne 'Running') {
            Invoke-Command -Session $hostSession -ArgumentList $DcVm -ScriptBlock {
                param($vm) Start-VM -Name $vm
            } | Out-Null
            Write-Output ("[1/7] dc-boot: {0} was {1}; started, waiting for PowerShell Direct" -f $DcVm, $state)
        } else {
            Write-Output "[1/7] dc-boot: $DcVm already Running"
        }
        $up = Wait-GuestPsDirect -Vm $DcVm -TimeoutSec $BootTimeoutSec
        if (-not $up) {
            Write-Output "fail: $DcVm never answered PowerShell Direct within $BootTimeoutSec s"
            $failed = $true
        } else {
            Write-Output "[1/7] dc-boot: $DcVm answered"
        }
    }

    # --- [2/7] DC clock -----------------------------------------------------------
    if ($SkipDc) {
        Write-Output '[2/7] dc-clock: skipped (-SkipDc)'
    } elseif (-not $failed) {
        $clockScript = @'
param($utcNow)
"delta_s=$([int](([DateTime]::UtcNow) - $utcNow).TotalSeconds)"
"dc_utc=$([DateTime]::UtcNow.ToString('u'))"
"tz=$((Get-TimeZone).Id)"
"w32tm=$((w32tm /query /source) 2>&1)"
'@
        $hostUtc = Invoke-Command -Session $hostSession { [DateTime]::UtcNow }
        try {
            $clock = Invoke-GuestScript -Vm $DcVm -ScriptText $clockScript -ScriptArgs @($hostUtc)
        } catch {
            Write-Output ("fail: dc-clock: probe threw: {0}" -f "$($_.Exception.Message)".Split([char]10)[0])
            $clock = $null
        }
        if (-not $clock) {
            $failed = $true
        } else {
        $deltaLine = ($clock | Where-Object { $_ -like 'delta_s=*' })
        $delta = [int]($deltaLine -replace 'delta_s=', '')
        foreach ($line in ($clock | Where-Object { $_ -notlike 'account=*' })) { Write-Output "       $line" }
        if ([Math]::Abs($delta) -le $ClockToleranceSec) {
            Write-Output "[2/7] dc-clock: within tolerance (delta ${delta}s; MaxClockSkew ${ClockToleranceSec}s); no repair"
        } else {
            Write-Output ("[2/7] dc-clock: delta ${delta}s exceeds MaxClockSkew ${ClockToleranceSec}s -- repairing (Set-Date from host UTC, dsregdns, NetLogon restart)")
            $repairScript = @'
param($utcNow)
# ToLocalTime lands the host's UTC instant correctly whatever timezone the
# DC runs (it is UTC here, but the tool does not assume that); +2s transit.
Set-Date -Date ($utcNow.ToLocalTime().AddSeconds(2)) | Out-Null
"after=$([DateTime]::UtcNow.ToString('u'))"
nltest /dsregdns | Out-Null
Restart-Service NetLogon -Force
Start-Sleep -Seconds 15
"scver=$((nltest /sc_verify:$env:USERDNSDOMAIN 2>&1 | Select-Object -First 2) -join ' | ')"
"dsdc=$((nltest /dsgetdc:$env:USERDNSDOMAIN 2>&1 | Select-Object -First 2) -join ' | ')"
"delta_s=$([int](([DateTime]::UtcNow) - $utcNow).TotalSeconds)"
'@
            try {
                $repair = Invoke-GuestScript -Vm $DcVm -ScriptText $repairScript -ScriptArgs @($hostUtc)
            } catch {
                Write-Output ("fail: dc-clock repair threw: {0}" -f "$($_.Exception.Message)".Split([char]10)[0])
                $repair = @()
            }
            foreach ($line in ($repair | Where-Object { $_ -notlike 'account=*' })) { Write-Output "       $line" }
            $after = ($repair | Where-Object { $_ -like 'delta_s=*' })
            $deltaAfter = [int]($after -replace 'delta_s=', '')
            if ([Math]::Abs($deltaAfter) -gt $ClockToleranceSec) {
                Write-Output "fail: DC clock still ${deltaAfter}s off after repair; diagnose manually before any lane"
                $failed = $true
            } else {
                Write-Output "[2/7] dc-clock: repaired (delta now ${deltaAfter}s)"
            }
        }
        }
    } else {
        Write-Output '[2/7] dc-clock: skipped (earlier failure)'
    }

    # --- [3/7] console VM boot ------------------------------------------------------
    if ($failed) {
        Write-Output '[3/7] member-boot: skipped (earlier failure)'
    } else {
        $state = Get-VmState -Vm $ConsoleVm
        if ($state -ne 'Running') {
            Invoke-Command -Session $hostSession -ArgumentList $ConsoleVm -ScriptBlock {
                param($vm) Start-VM -Name $vm
            } | Out-Null
            Write-Output ("[3/7] member-boot: {0} was {1}; started, waiting for PowerShell Direct" -f $ConsoleVm, $state)
        } else {
            Write-Output "[3/7] member-boot: $ConsoleVm already Running"
        }
        $up = Wait-GuestPsDirect -Vm $ConsoleVm -TimeoutSec $BootTimeoutSec
        if (-not $up) {
            Write-Output "fail: $ConsoleVm never answered PowerShell Direct within $BootTimeoutSec s"
            $failed = $true
        } else {
            Write-Output '[3/7] member-boot: console VM answered'
        }
    }

    # --- [4/7] member clock ---------------------------------------------------------
    # Window 12: a revert-based lane resets the MEMBER clock to the checkpoint
    # era exactly as every DC restore always has; the canary reddens kerberos
    # while every NTLM path (including this tool's own PSDirect probes) stays
    # green. Same probe, same tolerance, same tz-safe Set-Date as the DC step;
    # deliberately NO dsregdns / NetLogon restart -- the member is not the
    # KDC, and the 2026-09-22 repair went green with Set-Date alone.
    if ($failed) {
        Write-Output '[4/7] member-clock: skipped (earlier failure)'
    } else {
        $memberClockScript = @'
param($utcNow)
"delta_s=$([int](([DateTime]::UtcNow) - $utcNow).TotalSeconds)"
"member_utc=$([DateTime]::UtcNow.ToString('u'))"
"tz=$((Get-TimeZone).Id)"
'@
        $hostUtc = Invoke-Command -Session $hostSession { [DateTime]::UtcNow }
        try {
            $clock = Invoke-GuestScript -Vm $ConsoleVm -ScriptText $memberClockScript -ScriptArgs @($hostUtc)
        } catch {
            Write-Output ("fail: member-clock: probe threw: {0}" -f "$($_.Exception.Message)".Split([char]10)[0])
            $clock = $null
        }
        if (-not $clock) {
            $failed = $true
        } else {
            $deltaLine = ($clock | Where-Object { $_ -like 'delta_s=*' })
            $delta = [int]($deltaLine -replace 'delta_s=', '')
            foreach ($line in ($clock | Where-Object { $_ -notlike 'account=*' })) { Write-Output "       $line" }
            if ([Math]::Abs($delta) -le $ClockToleranceSec) {
                Write-Output "[4/7] member-clock: within tolerance (delta ${delta}s; MaxClockSkew ${ClockToleranceSec}s); no repair"
            } else {
                Write-Output ("[4/7] member-clock: delta ${delta}s exceeds MaxClockSkew ${ClockToleranceSec}s -- repairing (Set-Date from host UTC)")
                $memberRepairScript = @'
param($utcNow)
# ToLocalTime lands the host's UTC instant correctly whatever timezone the
# guest runs; +2s transit.
Set-Date -Date ($utcNow.ToLocalTime().AddSeconds(2)) | Out-Null
"after=$([DateTime]::UtcNow.ToString('u'))"
"delta_s=$([int](([DateTime]::UtcNow) - $utcNow).TotalSeconds)"
'@
                try {
                    $repair = Invoke-GuestScript -Vm $ConsoleVm -ScriptText $memberRepairScript -ScriptArgs @($hostUtc)
                } catch {
                    Write-Output ("fail: member-clock repair threw: {0}" -f "$($_.Exception.Message)".Split([char]10)[0])
                    $repair = @()
                }
                foreach ($line in ($repair | Where-Object { $_ -notlike 'account=*' })) { Write-Output "       $line" }
                $after = ($repair | Where-Object { $_ -like 'delta_s=*' })
                $deltaAfter = [int]($after -replace 'delta_s=', '')
                if ([Math]::Abs($deltaAfter) -gt $ClockToleranceSec) {
                    Write-Output "fail: member clock still ${deltaAfter}s off after repair; diagnose manually before any lane"
                    $failed = $true
                } else {
                    Write-Output "[4/7] member-clock: repaired (delta now ${deltaAfter}s)"
                }
            }
        }
    }

    # --- [5/7] member domain health (before the session: a reboot fix would kill it) ---
    $netBios = ''
    if ($failed) {
        Write-Output '[5/7] member-domain: skipped (earlier failure)'
    } else {
        $locatorScript = @'
$ErrorActionPreference = 'Continue'
"netbios=$env:USERDOMAIN"
$n = (nltest "/dsgetdc:$env:USERDNSDOMAIN" 2>&1 | Out-String).Trim()
"dsdc=$($n -replace [Environment]::NewLine, ' | ')"
'@
        $dom = Invoke-GuestScript -Vm $ConsoleVm -ScriptText $locatorScript
        $netBios = (($dom | Where-Object { $_ -like 'netbios=*' }) -replace 'netbios=', '')
        $dsdcLine = (($dom | Where-Object { $_ -like 'dsdc=*' }) -replace '^dsdc=', '')
        # Server 2025 nltest success marker (measured 2026-09-17): no
        # "Found DC:" line, but always "The command completed successfully".
        if ($dsdcLine -match 'command completed successfully') {
            Write-Output "[5/7] member-domain: locator answers from $ConsoleVm (NetBIOS domain $netBios)"
        } else {
            $shortDc = if ($dsdcLine.Length -gt 120) { $dsdcLine.Substring(0, 120) + '...' } else { $dsdcLine
            }
            Write-Output ("[5/7] member-domain: locator NOT answering ({0}); one nltest /sc_reset attempt" -f $shortDc)
            $resetScript = @'
nltest "/sc_reset:$env:USERDNSDOMAIN" | Out-Null
Start-Sleep -Seconds 5
$n = (nltest "/dsgetdc:$env:USERDNSDOMAIN" 2>&1 | Out-String).Trim()
"dsdc=$($n -replace [Environment]::NewLine, ' | ')"
'@
            $reset = Invoke-GuestScript -Vm $ConsoleVm -ScriptText $resetScript
            $after = (($reset | Where-Object { $_ -like 'dsdc=*' }) -replace '^dsdc=', '')
            if ($after -match 'command completed successfully') {
                Write-Output '[5/7] member-domain: sc_reset restored the locator'
            } else {
                $short = if ($after.Length -gt 120) { $after.Substring(0, 120) + '...' } else { $after }
                Write-Output ("fail: member locator still dead after sc_reset: {0} -- a member reboot likely needed (deliberately not automatic: it would kill the console session)" -f $short)
                $failed = $true
            }
        }
    }

    # --- [6/7] console session --------------------------------------------------------
    if ($failed) {
        Write-Output '[6/7] console-session: skipped (earlier failure)'
    } else {
        $sess = Invoke-GuestScript -Vm $ConsoleVm -ScriptText $SessionFactsScript
        if (Test-ConsoleSession -Lines $sess) {
            $quserLine = (($sess | Where-Object { $_ -like 'quser=*' }) -replace '^quser=', '')
            Write-Output "[6/7] console-session: active ($quserLine)"
        } else {
            $logonUi = (($sess | Where-Object { $_ -like 'logonui=*' }) -replace 'logonui=', '')
            if ($logonUi -ne 'True') {
                $quserLine = (($sess | Where-Object { $_ -like 'quser=*' }) -replace '^quser=', '')
                Write-Output ("fail: console state unreadable (quser='{0}', logonui={1}); look at the VM manually" -f $quserLine, $logonUi)
                $failed = $true
            } else {
                Write-Output '[6/7] console-session: none (logon UI up); injecting the CAD logon sequence'
                # Host-side key injection, the measured path. Errors carry
                # character INDEXES only, never characters: the second typed
                # string is the secret.
                $inject = Invoke-Command -Session $hostSession -ArgumentList $ConsoleVm, $GuestAccount, $GuestSecret -ScriptBlock {
                    param($vm, $accountForm, $plain)
                    $ErrorActionPreference = 'Stop'
                    $ns = 'root\virtualization\v2'
                    $vmObj = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "ElementName='$vm'"
                    if (-not $vmObj) { throw "VM '$vm' not found" }
                    $kb = Get-CimAssociatedInstance -InputObject $vmObj -ResultClassName Msvm_Keyboard | Select-Object -First 1
                    function Press([uint32]$vk) {
                        $r = Invoke-CimMethod -InputObject $kb -MethodName PressKey -Arguments @{ keyCode = $vk }
                        if ($r.ReturnValue -ne 0) { throw "PressKey($vk) failed: $($r.ReturnValue)" }
                    }
                    function Release([uint32]$vk) {
                        $r = Invoke-CimMethod -InputObject $kb -MethodName ReleaseKey -Arguments @{ keyCode = $vk }
                        if ($r.ReturnValue -ne 0) { throw "ReleaseKey($vk) failed: $($r.ReturnValue)" }
                    }
                    $map = @{
                        ' ' = 0x20; '-' = 0xBD; '=' = 0xBB; '[' = 0xDB; ']' = 0xDD; '\' = 0xDC
                        ';' = 0xBA; "'" = 0xDE; ',' = 0xBC; '.' = 0xBE; '/' = 0xBF; '`' = 0xC0
                        '!' = @(0x31, $true); '@' = @(0x32, $true); '#' = @(0x33, $true)
                        '$' = @(0x34, $true); '%' = @(0x35, $true); '^' = @(0x36, $true)
                        '&' = @(0x37, $true); '*' = @(0x38, $true); '(' = @(0x39, $true)
                        ')' = @(0x30, $true); '_' = @(0xBD, $true); '+' = @(0xBB, $true)
                    }
                    function TypeText([string]$s) {
                        $chars = $s.ToCharArray()
                        for ([int]$i = 0; $i -lt $chars.Count; $i++) {
                            $ch = $chars[$i]
                            $vk = [uint32]0; $shift = $false
                            if ($ch -ge 'a' -and $ch -le 'z') { $vk = [uint32](0x41 + [int]($ch - [char]'a')) }
                            elseif ($ch -ge 'A' -and $ch -le 'Z') { $vk = [uint32](0x41 + [int]($ch - [char]'A')); $shift = $true }
                            elseif ($ch -ge '0' -and $ch -le '9') { $vk = [uint32](0x30 + [int]($ch - [char]'0')) }
                            elseif ($map.ContainsKey([string]$ch)) {
                                $entry = $map[[string]$ch]
                                if ($entry -is [array]) { $vk = [uint32]$entry[0]; $shift = [bool]$entry[1] }
                                else { $vk = [uint32]$entry }
                            } else { throw "no VK mapping for character index $i (of $($chars.Count)); the character itself is not reported" }
                            if ($shift) { Press 0x10 }
                            Press $vk; Release $vk
                            if ($shift) { Release 0x10 }
                            Start-Sleep -Milliseconds 40
                        }
                    }
                    $r = Invoke-CimMethod -InputObject $kb -MethodName TypeCtrlAltDel
                    "cad=$($r.ReturnValue)"
                    Start-Sleep -Seconds 6
                    TypeText $accountForm
                    'typed account'
                    Press 0x09; Release 0x09
                    Start-Sleep -Milliseconds 300
                    TypeText $plain
                    'typed secret'
                    Start-Sleep -Milliseconds 300
                    Press 0x0D; Release 0x0D
                    'enter sent'
                }
                foreach ($line in $inject) { Write-Output "       $line" }
                Start-Sleep -Seconds $LogonSettleSec
                $sess2 = Invoke-GuestScript -Vm $ConsoleVm -ScriptText $SessionFactsScript
                if (Test-ConsoleSession -Lines $sess2) {
                    $q2 = (($sess2 | Where-Object { $_ -like 'quser=*' }) -replace '^quser=', '')
                    Write-Output "[6/7] console-session: established after injection ($q2)"
                } else {
                    Write-Output 'fail: console session not established after injection; check the console thumbnail -- a password-era mismatch is the usual cause'
                    $failed = $true
                }
            }
        }
    }

    # --- [7/7] helper task --------------------------------------------------------------
    if ($failed) {
        Write-Output '[7/7] helper: skipped (earlier failure)'
    } else {
        $taskScript = @'
param($taskName)
$t = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($t) { "present=1 state=$($t.State)" } else { 'present=0' }
'@
        $task = Invoke-GuestScript -Vm $ConsoleVm -ScriptText $taskScript -ScriptArgs @($HelperTask)
        $taskLine = ($task | Where-Object { $_ -like 'present=*' })
        if ((-not $RedeployHelper) -and ($taskLine -match 'present=1')) {
            if ($taskLine -match 'state=Disabled') {
                Write-Output "fail: task $HelperTask present but Disabled; re-enable it before a lane"
                $failed = $true
            } else {
                Write-Output ("[7/7] helper: task {0} present ({1})" -f $HelperTask, ($taskLine -replace 'present=1 ', ''))
            }
        } else {
            $why = if ($RedeployHelper) { 'forced (-RedeployHelper)' } else { 'missing' }
            if ([string]::IsNullOrEmpty($netBios)) { $netBios = 'LAB' }
            Write-Output "[7/7] helper: task $HelperTask $why; deploying guest/helper.ps1 (two-hop) and re-registering (principal $netBios\$EstateUser)"
            $helperSource = Join-Path $repoRoot 'guest\helper.ps1'
            if (-not (Test-Path $helperSource)) {
                Write-Output "fail: helper source not found: $helperSource"
                $failed = $true
            } else {
                # Hop 1: controller -> host staging.
                Invoke-Command -Session $hostSession { New-Item -ItemType Directory -Force -Path 'C:\wcd-staging' | Out-Null }
                Copy-Item -ToSession $hostSession -Path $helperSource -Destination 'C:\wcd-staging\helper.ps1' -Force
                # Hop 2: host staging -> guest copy, register with the
                # measured principal (domain user, Interactive, Highest),
                # context smoke through the task itself. The copy rides the
                # guest session opened INSIDE the host runspace (two-hop
                # rule); the register script travels as a string, like every
                # other guest script here.
                $deployScript = @'
param($taskName, $helperDir, $nbDomain, $user)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $helperDir | Out-Null
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass ' +
    "-File $helperDir\helper.ps1 " +
    "-RequestFile $helperDir\request.json -ResponseFile $helperDir\response.json")
$principal = New-ScheduledTaskPrincipal -UserId "$nbDomain\$user" -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal `
    -Settings $settings -Force | Out-Null
'registered'
Set-Content -Path "$helperDir\request.json" -Value '{"action":"context"}' -Encoding ascii
Start-ScheduledTask -TaskName $taskName
$deadline = (Get-Date).AddSeconds(30)
while (-not (Test-Path "$helperDir\response.json") -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 300
}
if (Test-Path "$helperDir\response.json") { 'smoke=context-answered' } else { 'smoke=timeout' }
'@
                $deploy = $null
                try {
                $deploy = Invoke-Command -Session $hostSession `
                    -ArgumentList $ConsoleVm, $GuestAccount, $GuestSecret, $HelperDir, $deployScript, @($HelperTask, $HelperDir, $netBios, $EstateUser) -ScriptBlock {
                    param($vm, $account, $secret, $helperDir, $scriptText, $scriptArgs)
                    $ErrorActionPreference = 'Stop'
                    $cred = [System.Management.Automation.PSCredential]::new(
                        $account, (ConvertTo-SecureString $secret -AsPlainText -Force))
                    $guest = New-PSSession -VMName $vm -Credential $cred -ErrorAction Stop
                    try {
                        # The destination directory must exist BEFORE the
                        # copy: Copy-Item does not create remote intermediate
                        # directories (measured 2026-09-17, first live deploy).
                        Invoke-Command -Session $guest -ArgumentList $helperDir -ScriptBlock {
                            param($dir)
                            New-Item -ItemType Directory -Force -Path $dir | Out-Null
                        }
                        Copy-Item -ToSession $guest -Path 'C:\wcd-staging\helper.ps1' `
                            -Destination "$helperDir\helper.ps1" -Force
                        $block = [scriptblock]::Create($scriptText)
                        return Invoke-Command -Session $guest -ScriptBlock $block -ArgumentList $scriptArgs
                    } finally {
                        try { Remove-PSSession $guest -ErrorAction SilentlyContinue } catch { }
                    }
                }
                } catch {
                    Write-Output ("fail: helper deploy threw: {0}" -f "$($_.Exception.Message)".Split([char]10)[0])
                }
                foreach ($line in @($deploy)) { Write-Output "       $line" }
                if (@($deploy) -contains 'smoke=context-answered') {
                    Write-Output '[7/7] helper: deployed, registered, and the context smoke answered'
                } else {
                    Write-Output 'fail: helper deploy did not complete; check the task last result before a lane'
                    $failed = $true
                }
            }
        }
    }
} finally {
    if ($hostSession) { Remove-PSSession $hostSession -ErrorAction SilentlyContinue }
}

if ($failed) {
    Write-Output 'estate-bringup: NOT READY (see fail: lines above)'
    exit 3
}
Write-Output "estate-bringup: READY -- finish with: wcd estate-canary --estate $EstateFile"
exit 0
