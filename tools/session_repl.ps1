#requires -Version 5
<#
.SYNOPSIS
    Persistent controller-side session REPL: one pwsh process holding the host
    WinRM session; every guest op nests PSDirect inside a host Invoke-Command.

.DESCRIPTION
    tools/session_repl.ps1 is the real transport behind wcd.transport. One
    JSON request line in, one JSON response line out. The host WinRM session
    is opened once and reused; guest operations nest the PSDirect session
    INSIDE a host Invoke-Command block (the two-hop rule from the first
    estate window: `New-PSSession -VMName` resolves the VM through the local
    Hyper-V WMI, so it must run ON the host -- a guest session object cannot
    survive the Invoke-Command that created it, so each guest op pays the
    nested open/close; the persistent host session is what the REPL saves).

    PROTOCOL. stdin: one JSON object per line:
      {"op":"ping",  "id":"..."}
      {"op":"host",  "id":"...", "script":"<ps1 text>", "args":[...], "timeout_s":120}
        -- runs on the Hyper-V host session (Msvm_Keyboard, checkpoints).
      {"op":"guest", "id":"...", "script":"<ps1 text>", "args":[...], "timeout_s":240}
        -- runs in the guest through PSDirect (setup, oracle snippets, audit).
      {"op":"helper","id":"...", "request":{...}, "timeout_s":240}
        -- the helper file-IPC dance inside the guest's console session:
           write request.json, Start-ScheduledTask WCDHelper, poll for the
           response file, read the task's LastTaskResult as the exit code.
    stdout: exactly one JSON line per request:
      {"ok":true,  "id":"...", "kind":"...", "stdout":"...", ...}
      {"ok":false, "id":"...", "kind":"...", "error":"..."}
    stderr is diagnostics and never parsed.

    SECRETS. The password never appears on argv or in this file: the launcher
    names an environment variable (-PasswordEnv) whose value the PSCredential
    is built from, exactly the WEL credential-broker discipline.

    This script never interprets surface state; it is plumbing.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $HostName,
    [Parameter(Mandatory = $true)] [string] $VmName,
    [Parameter(Mandatory = $true)] [string] $Domain,
    [Parameter(Mandatory = $true)] [string] $Username,
    [Parameter(Mandatory = $true)] [string] $PasswordEnv
)

$ErrorActionPreference = 'Stop'

try { [Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }
try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }

function Write-ResponseLine {
    param([hashtable] $Object)
    $json = ConvertTo-Json -InputObject $Object -Compress -Depth 8
    [Console]::Out.WriteLine($json)
    [Console]::Out.Flush()
}

function Join-OutputText {
    param($Output)
    if ($null -eq $Output) { return '' }
    if ($Output -is [string]) { return $Output }
    return (@($Output) | ForEach-Object { "$_" }) -join [Environment]::NewLine
}

function New-LabCredential {
    param([string] $DomainName, [string] $UserName, [string] $EnvName)
    $secret = [Environment]::GetEnvironmentVariable($EnvName)
    if (-not $secret) {
        throw "environment variable $EnvName is not set (credential-broker discipline)"
    }
    return [System.Management.Automation.PSCredential]::new(
        "$DomainName\$UserName", (ConvertTo-SecureString $secret -AsPlainText -Force))
}

# FRESH HOST SESSION PER REQUEST. The long-lived reused host session was the
# one variable behind a ~25-50% transient NRE in nested PSDirect opens
# (measured 2026-09-03: the same nested call is 6/6 reliable from a fresh
# process, ~50% reliable through a reused session). The REPL keeps protocol
# continuity; sessions are per-request and disposed in finally.
$script:Credential = New-LabCredential -DomainName $Domain -UserName $Username -EnvName $PasswordEnv

function Get-HostSession {
    return New-PSSession -ComputerName $HostName `
        -SessionOption (New-PSSessionOption -OpenTimeout 30000) -ErrorAction Stop
}

function Remove-HostSessionSafe {
    param($Session)
    if ($null -ne $Session) {
        try { Remove-PSSession $Session -ErrorAction SilentlyContinue } catch { }
    }
}

# The nested PSDirect blocks run on the HOST, so they see $VmName/$cred via
# -ArgumentList, never through the script text.
$GUEST_RUNNER = {
    param($Credential, $Vm, $ScriptText, $ScriptArgs)
    $ErrorActionPreference = 'Stop'
    # Nested PSDirect opens fail transiently (~1 in 4, measured 2026-09-03):
    # "Object reference not set" from the Hyper-V WMI layer. Retrying the
    # SESSION OPEN is safe by construction (no guest work has run yet).
    $guest = $null
    $lastErr = $null
    for ($i = 1; $i -le 4; $i++) {
        try {
            $guest = New-PSSession -VMName $Vm -Credential $Credential -ErrorAction Stop
            break
        } catch {
            $lastErr = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
            Start-Sleep -Seconds (2 * $i)
        }
    }
    if ($null -eq $guest) { throw "PSDirect open failed after 4 attempts: $lastErr" }
    $result = $null
    try {
        $block = [scriptblock]::Create($ScriptText)
        if ($null -ne $ScriptArgs -and @($ScriptArgs).Count -gt 0) {
            $result = Invoke-Command -Session $guest -ScriptBlock $block -ArgumentList $ScriptArgs -ErrorAction Stop
        } else {
            $result = Invoke-Command -Session $guest -ScriptBlock $block -ErrorAction Stop
        }
    } finally {
        # MEASURED 2026-09-03: Remove-PSSession on a PSDirect session throws a
        # terminating NullReferenceException intermittently (a Hyper-V/WinRM
        # teardown race) AFTER the guest work succeeded. -ErrorAction
        # SilentlyContinue does NOT suppress it; try/catch does. The result is
        # captured before this point, so teardown can never discard output.
        try { Remove-PSSession $guest -ErrorAction SilentlyContinue } catch { }
    }
    return $result
}

$HELPER_RUNNER = {
    param($Credential, $Vm, $ReqJson, $Timeout)
    $ErrorActionPreference = 'Stop'
    # Nested PSDirect opens fail transiently (~1 in 4, measured 2026-09-03):
    # "Object reference not set" from the Hyper-V WMI layer. Retrying the
    # SESSION OPEN is safe by construction (no guest work has run yet).
    $guest = $null
    $lastErr = $null
    for ($i = 1; $i -le 4; $i++) {
        try {
            $guest = New-PSSession -VMName $Vm -Credential $Credential -ErrorAction Stop
            break
        } catch {
            $lastErr = $_.Exception.Message
            Start-Sleep -Seconds (2 * $i)
        }
    }
    if ($null -eq $guest) { throw "PSDirect open failed after 4 attempts: $lastErr" }
    $result = $null
    try {
        $result = Invoke-Command -Session $guest -ScriptBlock {
            param($ReqJson, $Timeout)
            $ErrorActionPreference = 'Stop'
            Remove-Item 'C:\lab\wcd\response.json' -ErrorAction SilentlyContinue
            [IO.File]::WriteAllText('C:\lab\wcd\request.json', $ReqJson,
                [System.Text.UTF8Encoding]::new($false))
            Start-ScheduledTask -TaskName 'WCDHelper'
            $deadline = (Get-Date).AddSeconds($Timeout)
            while ((Get-Date) -lt $deadline) {
                $f = Get-Item 'C:\lab\wcd\response.json' -ErrorAction SilentlyContinue
                if ($f -and $f.Length -gt 0) { break }
                Start-Sleep -Milliseconds 500
            }
            $f = Get-Item 'C:\lab\wcd\response.json' -ErrorAction SilentlyContinue
            if (-not $f -or $f.Length -eq 0) {
                @{ ok = $false; error = "helper produced no response within ${Timeout}s" }
            } else {
                Start-Sleep -Milliseconds 300   # let the task transition out of Running
                $exitCode = $null
                try {
                    $info = Get-ScheduledTaskInfo -TaskName 'WCDHelper' -ErrorAction Stop
                    $exitCode = $info.LastTaskResult
                } catch { }
                @{
                    ok = $true
                    response_text = [System.Text.Encoding]::UTF8.GetString(
                        [IO.File]::ReadAllBytes('C:\lab\wcd\response.json'))
                    exit_code = $exitCode
                }
            }
        } -ArgumentList $ReqJson, $Timeout -ErrorAction Stop
    } finally {
        # Same PSDirect teardown race as GUEST_RUNNER (see the note there).
        try { Remove-PSSession $guest -ErrorAction SilentlyContinue } catch { }
    }
    return $result
}

function Invoke-RemoteOp {
    param([string] $Kind, [string] $Id, [string] $ScriptText, [object[]] $OpArgs, [int] $TimeoutS)
    $session = $null
    try {
        $session = Get-HostSession
        $out = Invoke-Command -Session $session -ScriptBlock $GUEST_RUNNER `
            -ArgumentList $script:Credential, $VmName, $ScriptText, @($OpArgs) -ErrorAction Stop
        Write-ResponseLine @{ ok = $true; id = $Id; kind = $Kind; stdout = (Join-OutputText $out) }
    } catch {
        Write-ResponseLine @{ ok = $false; id = $Id; kind = $Kind; error = $_.Exception.Message; etype = $_.Exception.GetType().FullName; estack = "$($_.ScriptStackTrace)"; estack_remote = "$($_.Exception.StackTrace)" }
    } finally {
        Remove-HostSessionSafe $session
    }
}

function Invoke-HelperOp {
    param([string] $Id, [object] $Request, [int] $TimeoutS)
    $session = $null
    try {
        $session = Get-HostSession
        $requestJson = ConvertTo-Json -InputObject $Request -Compress -Depth 12
        $result = Invoke-Command -Session $session -ScriptBlock $HELPER_RUNNER `
            -ArgumentList $script:Credential, $VmName, $requestJson, $TimeoutS -ErrorAction Stop
        if ($result.ok) {
            Write-ResponseLine @{
                ok = $true; id = $Id; kind = 'helper'
                response = $result.response_text
                exit_code = $result.exit_code
            }
        } else {
            Write-ResponseLine @{ ok = $false; id = $Id; kind = 'helper'; error = "$($result.error)" }
        }
    } catch {
        Write-ResponseLine @{ ok = $false; id = $Id; kind = 'helper'; error = $_.Exception.Message; etype = $_.Exception.GetType().FullName; estack = "$($_.ScriptStackTrace)" }
    } finally {
        Remove-HostSessionSafe $session
    }
}

# startup: no session pre-open; first request proves the route.

while ($true) {
    $line = [Console]::In.ReadLine()
    if ($null -eq $line) { break }
    if (-not $line.Trim()) { continue }
    $request = $null
    try {
        $request = ConvertFrom-Json -InputObject $line
    } catch {
        Write-ResponseLine @{ ok = $false; id = $null; kind = 'protocol'; error = "bad request JSON: $($_.Exception.Message)" }
        continue
    }
    $op = "$($request.op)"
    $id = "$($request.id)"
    $timeoutS = 120
    if ($request.PSObject.Properties['timeout_s'] -and $request.timeout_s) { $timeoutS = [int]$request.timeout_s }

    switch ($op) {
        'ping' {
            Write-ResponseLine @{ ok = $true; id = $id; kind = 'ping'; stdout = 'pong' }
        }
        'host' {
            $opArgs = @()
            if ($request.PSObject.Properties['args'] -and $request.args) { $opArgs = @($request.args) }
            $session = $null
            try {
                $session = Get-HostSession
                $block = [scriptblock]::Create("$($request.script)")
                $out = Invoke-Command -Session $session -ScriptBlock $block -ArgumentList $opArgs -ErrorAction Stop
                Write-ResponseLine @{ ok = $true; id = $id; kind = 'host'; stdout = (Join-OutputText $out) }
            } catch {
                Write-ResponseLine @{ ok = $false; id = $id; kind = 'host'; error = $_.Exception.Message; etype = $_.Exception.GetType().FullName; estack = "$($_.ScriptStackTrace)" }
            } finally {
                Remove-HostSessionSafe $session
            }
        }
        'guest' {
            $opArgs = @()
            if ($request.PSObject.Properties['args'] -and $request.args) { $opArgs = @($request.args) }
            Invoke-RemoteOp -Kind 'guest' -Id $id -ScriptText "$($request.script)" -OpArgs $opArgs -TimeoutS $timeoutS
        }
        'helper' {
            Invoke-HelperOp -Id $id -Request $request.request -TimeoutS $timeoutS
        }
        'shutdown' {
            Write-ResponseLine @{ ok = $true; id = $id; kind = 'shutdown'; stdout = 'bye' }
            break
        }
        default {
            Write-ResponseLine @{ ok = $false; id = $id; kind = 'protocol'; error = "unknown op '$op'" }
        }
    }
}
