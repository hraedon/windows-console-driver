"""Console assurance ops: lock detection, unlock, reboot readiness, audit.

These are the promoted form of the first estate window's ad-hoc scripts
(``C:\\temp\\lab``): the console session on the disposable lab guest locks
and blanks on its own schedule, and every transaction's prepare phase needs
a verified unlocked console before any gesture. Everything here is
mechanism, never interpretation: the ops return facts and state
classifications, and the caller decides.

- :func:`lock_state` -- classify the console: ``unlocked`` / ``locked`` /
  ``display_blanked`` / ``no_session`` / ``unknown``, from LogonUI presence
  and the console session's state (PSDirect side), plus the helper's own
  foreground read when the session is up.
- :func:`wake_display` -- host-side ``Msvm_Keyboard`` NumLock tap to bring a
  blanked display back (measured: the display blanks before the lock fires).
- :func:`unlock_console` -- the credential path that never touches the
  guest: host-side ``TypeCtrlAltDel``, then the password typed per character
  through the VK map (this build's ``Msvm_Keyboard`` has no TypeText), then
  Enter. The secret travels only through process memory on the controller
  and the host; it never appears in a helper request, an evidence artifact,
  or a log.
- :func:`wait_console_unlocked` -- poll :func:`lock_state` until unlocked;
  timeout is reported as data (``unknown``), never a retry loop past it.
- :func:`read_lock_audit` -- the 4800/4801 (workstation lock/unlock) trail,
  read once to explain the re-lock pattern; auditing was armed in the first
  window.
- :func:`reboot_readiness` -- the measured PSDirect-blackout gate: after a
  guest reboot, PowerShell Direct answers nothing for a long window
  (measured 25-60 minutes in the first estate window). The gate reports
  pending-reboot markers and classifies an unreachable guest as
  ``booting_blackout`` (wait patiently) rather than an error to retry.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .estate import EstateConfig
from .transport import SessionTransport

LOCK_TIMEOUT_DEFAULT_S = 90.0

_CONSOLE_PROBE = r"""
$ErrorActionPreference = 'Stop'
$logonui = [bool](Get-Process LogonUI -ErrorAction SilentlyContinue)
$sessions = @(quser 2>&1 | ForEach-Object { "$_" })
$activeConsole = $false
foreach ($line in $sessions) {
    if ($line -match '^\s*\S+\s+console\s+\d+\s+Active') { $activeConsole = $true }
}
$inactivity = $null
try {
    $inactivity = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name InactivityTimeoutSecs -ErrorAction Stop).InactivityTimeoutSecs
} catch { }
@{
    logonui_running = $logonui
    console_session_active = $activeConsole
    inactivity_timeout_secs = $inactivity
    quser = $sessions
} | ConvertTo-Json -Compress -Depth 4
"""

_LOCK_AUDIT_PROBE = r"""
$ErrorActionPreference = 'Stop'
$events = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4800,4801)} -MaxEvents 60 `
    -ErrorAction SilentlyContinue)
$out = @(foreach ($e in $events) {
    @{
        id = $e.Id
        time = $e.TimeCreated.ToString('o')
        target = ($e.Properties | Select-Object -First 1).Value
    }
})
@{ count = $out.Count; events = $out } | ConvertTo-Json -Compress -Depth 5
"""

_REBOOT_PROBE = r"""
$ErrorActionPreference = 'Stop'
$pending = $false
$reasons = @()
foreach ($key in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
)) {
    if (Test-Path $key) {
        if ($key -like '*Session Manager') {
            $v = (Get-ItemProperty $key -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)
            if ($v -and $v.PendingFileRenameOperations) { $pending = $true; $reasons += 'PendingFileRenameOperations' }
        } else {
            $pending = $true; $reasons += (Split-Path $key -Leaf)
        }
    }
}
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
@{ reboot_pending = $pending; reasons = $reasons; last_boot = $boot.ToString('o') } |
    ConvertTo-Json -Compress -Depth 4
"""

_WAKE_DISPLAY_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ns = 'root\virtualization\v2'
$vm = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "ElementName='$args'"
$kb = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_Keyboard | Select-Object -First 1
if (-not $kb) { throw "no Msvm_Keyboard for $args" }
$r = Invoke-CimMethod -InputObject $kb -MethodName PressKey -Arguments @{ keyCode = [uint16]0x90 }
"PressKey NumLock: $($r.ReturnValue)"
$r2 = Invoke-CimMethod -InputObject $kb -MethodName ReleaseKey -Arguments @{ keyCode = [uint16]0x90 }
"ReleaseKey NumLock: $($r2.ReturnValue)"
"""

_UNLOCK_SCRIPT = r"""
# Ctrl+Alt+Del, then the password per character, then Enter -- all through
# the host-side Msvm_Keyboard. The plain secret arrives as an in-memory
# argument and is never written anywhere by this script.
param([string] $Vm, [string] $Plain)
$ErrorActionPreference = 'Stop'
$ns = 'root\virtualization\v2'
$vm = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter "ElementName='$Vm'"
$kb = Get-CimAssociatedInstance -InputObject $vm -ResultClassName Msvm_Keyboard | Select-Object -First 1
if (-not $kb) { throw "no Msvm_Keyboard for $Vm" }

function Press([uint32]$vk) {
    $r = Invoke-CimMethod -InputObject $kb -MethodName PressKey -Arguments @{ keyCode = $vk }
    if ($r.ReturnValue -ne 0) { throw "PressKey($vk) failed: $($r.ReturnValue)" }
}
function Release([uint32]$vk) {
    $r = Invoke-CimMethod -InputObject $kb -MethodName ReleaseKey -Arguments @{ keyCode = $vk }
    if ($r.ReturnValue -ne 0) { throw "ReleaseKey($vk) failed: $($r.ReturnValue)" }
}

$VK_SHIFT = [uint32]0x10
$vkMap = @{
    ' ' = 0x20; '-' = 0xBD; '=' = 0xBB; '[' = 0xDB; ']' = 0xDD; '\' = 0xDC
    ';' = 0xBA; "'" = 0xDE; ',' = 0xBC; '.' = 0xBE; '/' = 0xBF; '`' = 0xC0
    '!' = @(0x31, $true); '@' = @(0x32, $true); '#' = @(0x33, $true)
    '$' = @(0x34, $true); '%' = @(0x35, $true); '^' = @(0x36, $true)
    '&' = @(0x37, $true); '*' = @(0x38, $true); '(' = @(0x39, $true)
    ')' = @(0x30, $true); '_' = @(0xBD, $true); '+' = @(0xBB, $true)
    ':' = @(0xBA, $true); '"' = @(0xDE, $true); '<' = @(0xBC, $true)
    '>' = @(0xBE, $true); '?' = @(0xBF, $true); '~' = @(0xC0, $true)
}

$r = Invoke-CimMethod -InputObject $kb -MethodName TypeCtrlAltDel
"TypeCtrlAltDel: $($r.ReturnValue)"
Start-Sleep -Seconds 5

foreach ($ch in $Plain.ToCharArray()) {
    $vk = $null; $shift = $false
    if ($ch -ge 'a' -and $ch -le 'z') { $vk = [uint32](0x41 + [int]([char]$ch - [char]'a')) }
    elseif ($ch -ge 'A' -and $ch -le 'Z') { $vk = [uint32](0x41 + [int]([char]$ch - [char]'A')); $shift = $true }
    elseif ($ch -ge '0' -and $ch -le '9') { $vk = [uint32](0x30 + [int]([char]$ch - [char]'0')) }
    elseif ($vkMap.ContainsKey([string]$ch)) {
        $entry = $vkMap[[string]$ch]
        if ($entry -is [array]) { $vk = [uint32]$entry[0]; $shift = [bool]$entry[1] }
        else { $vk = [uint32]$entry }
    } else { throw "no VK mapping for '$ch'" }
    if ($shift) { Press $VK_SHIFT }
    Press $vk; Release $vk
    if ($shift) { Release $VK_SHIFT }
}
Start-Sleep -Seconds 1
Press 0x0D; Release 0x0D
"unlock sequence sent"
"""

# Msvm_Keyboard PressKey/ReleaseKey return codes (measured): 0 = ok,
# 32775 = "the operation failed" (seen when the vmcs refuses a key during a
# resolution change). Anything else is reported, not retried, here.


@dataclass(frozen=True, slots=True)
class ConsoleState:
    """One console classification, with the facts it was derived from."""

    state: str  # unlocked | locked | display_blanked | no_session | unknown
    logonui_running: bool
    console_session_active: bool
    helper_responds: bool
    notes: tuple[str, ...]


def lock_state(t: SessionTransport, *, probe_helper: bool = True) -> ConsoleState:
    """Classify the console from PSDirect facts (and the helper when up)."""
    probe = json.loads(t.guest(_CONSOLE_PROBE))
    logonui = bool(probe.get("logonui_running"))
    console_active = bool(probe.get("console_session_active"))
    notes: list[str] = []
    helper_responds = False
    if probe_helper and console_active and not logonui:
        try:
            result = t.helper({"action": "context"}, timeout=60)
            helper_responds = result.outcome == "ok"
            if not helper_responds and result.error:
                notes.append(f"helper context error: {result.error}")
        except Exception as exc:
            notes.append(f"helper context failed: {exc}")
    if not console_active:
        state = "no_session"
    elif logonui:
        state = "locked"
    elif helper_responds or not probe_helper:
        state = "unlocked"
    else:
        state = "unknown"
    return ConsoleState(
        state=state,
        logonui_running=logonui,
        console_session_active=console_active,
        helper_responds=helper_responds,
        notes=tuple(notes),
    )


def wake_display(t: SessionTransport, *, vm_name: str | None = None) -> str:
    """NumLock tap through the host-side Msvm_Keyboard (blank-display wake)."""
    return t.host(_WAKE_DISPLAY_SCRIPT, [vm_name or t.vm_name], timeout=60)


def unlock_console(t: SessionTransport, estate: EstateConfig, *, vm_name: str | None = None) -> str:
    """Host-side credential unlock: Ctrl+Alt+Del, password, Enter."""
    return t.host(_UNLOCK_SCRIPT, [vm_name or estate.vm_name, estate.resolved_password()], timeout=120)


def wait_console_unlocked(
    t: SessionTransport,
    estate: EstateConfig,
    *,
    timeout_s: float = LOCK_TIMEOUT_DEFAULT_S,
    poll_s: float = 8.0,
) -> ConsoleState:
    """Wake/unlock as needed, then verify; returns the final ConsoleState."""
    import time

    deadline = time.monotonic() + timeout_s
    while True:
        state = lock_state(t)
        if state.state in ("unlocked", "no_session"):
            return state
        if state.state == "locked":
            unlock_console(t, estate)
            time.sleep(6.0)
        elif state.state == "unknown":
            wake_display(t)
            time.sleep(4.0)
        else:
            time.sleep(poll_s)
        if time.monotonic() >= deadline:
            return lock_state(t)


@dataclass(frozen=True, slots=True)
class LockAudit:
    """The 4800/4801 trail, read once."""

    count: int
    events: tuple[dict[str, object], ...]


def read_lock_audit(t: SessionTransport) -> LockAudit:
    """Workstation lock/unlock events (4800/4801); auditing armed 2026-09-02."""
    payload = json.loads(t.guest(_LOCK_AUDIT_PROBE))
    events = payload.get("events")
    if not isinstance(events, list):
        events = []
    return LockAudit(count=int(payload.get("count", 0)), events=tuple(events))


@dataclass(frozen=True, slots=True)
class RebootReadiness:
    """Pending-reboot facts and the PSDirect-blackout classification."""

    reachable: bool
    reboot_pending: bool
    reasons: tuple[str, ...]
    last_boot: str
    classification: str  # ready | reboot_pending | booting_blackout | unreachable


def reboot_readiness(t: SessionTransport) -> RebootReadiness:
    """Classify whether the guest is transaction-ready or mid-blackout."""
    try:
        payload = json.loads(t.guest(_REBOOT_PROBE, timeout=90))
    except Exception:
        return RebootReadiness(
            reachable=False,
            reboot_pending=False,
            reasons=(),
            last_boot="",
            classification="booting_blackout",
        )
    pending = bool(payload.get("reboot_pending"))
    reasons = tuple(payload.get("reasons") or ())
    boot = str(payload.get("last_boot", ""))
    return RebootReadiness(
        reachable=True,
        reboot_pending=pending,
        reasons=reasons,
        last_boot=boot,
        classification="reboot_pending" if pending else "ready",
    )
