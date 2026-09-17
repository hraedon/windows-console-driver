"""Estate health canary: read-only pre-flight checks before a lane or window.

Every estate window so far has discovered silent drift mid-lane (an expired
domain password, a missing checkpoint, a dead helper task) at the moment it
broke a transaction. The canary makes that drift a pre-flight fact instead:
one read-only pass over the exact seams a transaction will depend on, one
precise line per check, fail closed. Nothing here mutates the estate -- no
wake, no unlock, no task start -- and nothing here runs as part of the
default test suite against a live host; the unit tests drive a scripted
fake transport, exactly like the executor's own tests.

Checks (in dependency order; a check whose dependency failed is reported as
a failed ``skipped`` line rather than attempted, so an unreachable guest
costs one probe, not five timeouts):

- ``host_winrm``      -- a host op answers (the transport's own WinRM route).
- ``guest_psdirect``  -- the guest answers over PSDirect with the estate
                         credential (and the VM reports a Running state).
- ``checkpoint``      -- the executor's own recovery guard: the exact
                         configured checkpoint exists on the host.
- ``domain_account``  -- the estate account is enabled and its password is
                         not expired (the 2026-09-15 drift, made a canary
                         line).
- ``dc_locator``      -- ``nltest /dsgetdc:`` answers from the guest (the
                         DC-locator DNS canary for the clock trap).
- ``kerberos``        -- the DC clock is within Kerberos MaxClockSkew of the
                         guest (read straight from the DC over LDAP at the
                         DNS-server address) and ``klist`` can mint a fresh
                         ticket for the domain. Every other guest check rides
                         NTLM or DNS, which stay green under clock skew while
                         GPMC dies -- this is the check that does not.
- ``helper_task``     -- the console helper's scheduled task exists.
- ``console_session`` -- an active console session is present (quser facts
                         only; the helper is not probed here).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .console_ops import lock_state
from .estate import EstateConfig
from .exec_transaction import checkpoint_exists
from .transport import SessionTransport

# Every probe below is read-only. Identifiers (VM name, account name, domain)
# arrive as script args, never interpolated into script text.
_VM_STATE_SCRIPT = (
    "$vm = Get-VM -Name $args[0] -ErrorAction SilentlyContinue; "
    "if ($null -eq $vm) { 'state=missing' } else { \"state=$($vm.State)\" }"
)

_GUEST_ALIVE_SCRIPT = (
    "$ErrorActionPreference = 'Stop'; "
    "$os = Get-CimInstance Win32_OperatingSystem; "
    "\"alive=1 boot=$($os.LastBootUpTime.ToString('s'))\""
)

_AD_ACCOUNT_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$u = Get-ADUser -Identity $args[0] -Properties Enabled, PasswordExpired
"enabled=$($u.Enabled)"
"password_expired=$($u.PasswordExpired)"
"""

_DC_LOCATOR_SCRIPT = r"""
# The domain binds to a named variable first: a colon-glued $args[0] in
# argument position parses as '<domain>[0]' (measured live, first canary run),
# which nltest answers with ERROR_INVALID_DOMAINNAME.
$domain = [string]$args[0]
$out = @(nltest "/dsgetdc:$domain" 2>&1 | ForEach-Object { "$_" })
"rc=$LASTEXITCODE"
@($out | Where-Object { $_ -and $_.Trim() }) | Select-Object -First 4
"""

# The Kerberos-sensitive probe. Two facts one line apart: the DC's own clock
# (rootDSE currentTime over LDAP, addressed by the guest's DNS-server
# address -- in this estate that IS the DC, so deleted DC-locator records
# cannot hide the skew) versus the guest clock; then a fresh ticket mint for
# the domain as this identity, which is the exact exchange a skewed KDC
# rejects and a locator-less client cannot find. Both are read-only.
_KERBEROS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$domain = [string]$args[0]
$delta = 'unreadable'
$servers = @(Get-DnsClientServerAddress -AddressFamily IPv4 |
    Where-Object { $_.ServerAddresses } |
    ForEach-Object { $_.ServerAddresses } | Select-Object -Unique)
foreach ($addr in $servers) {
    try {
        $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$addr/rootDSE")
        $t = $root.Properties['currentTime'].Value
        if ($null -ne $t) {
            $delta = ('{0:F0}' -f ((Get-Date) - [DateTime]$t).TotalSeconds)
            break
        }
    } catch { }
}
"dc_time_delta_s=$delta"
$kout = @(klist get "krbtgt/$domain" 2>&1 | ForEach-Object { "$_" })
"klist_rc=$LASTEXITCODE"
@($kout | Where-Object { $_ -and $_.Trim() }) | Select-Object -First 3
"""

_HELPER_TASK_SCRIPT = (
    "$t = Get-ScheduledTask -TaskName $args[0] -ErrorAction SilentlyContinue; "
    "if ($null -eq $t) { 'present=0' } else { \"present=1 state=$($t.State)\" }"
)

_HOST_TIMEOUT_S = 45.0
_GUEST_TIMEOUT_S = 90.0

# Kerberos MaxClockSkew, measured on this estate (R7 secedit export: 5
# minutes). Beyond it the KDC rejects tickets while NTLM paths keep answering
# -- exactly the failure this check exists to catch pre-flight.
_MAX_CLOCK_SKEW_S = 300


@dataclass(frozen=True, slots=True)
class CanaryCheck:
    """One named check with exactly one precise verdict line."""

    name: str
    ok: bool
    detail: str


@dataclass(frozen=True, slots=True)
class CanaryReport:
    """The canary's full pass: every check, plus the overall verdict."""

    checks: tuple[CanaryCheck, ...]

    @property
    def ok(self) -> bool:
        return all(check.ok for check in self.checks)


def run_estate_canary(transport: SessionTransport, estate: EstateConfig) -> CanaryReport:
    """Run every check read-only; never raise past a failing probe."""
    checks: list[CanaryCheck] = []

    def record(name: str, ok: bool, detail: str) -> None:
        checks.append(CanaryCheck(name=name, ok=ok, detail=detail))

    # -- host WinRM -------------------------------------------------------------
    vm_state = ""
    try:
        state_line = transport.host(_VM_STATE_SCRIPT, [estate.vm_name], timeout=_HOST_TIMEOUT_S)
        match = re.search(r"state=(\w+)", state_line)
        vm_state = match.group(1) if match else "unknown"
        record("host_winrm", True, f"host op answered over WinRM; vm state {vm_state}")
    except Exception as exc:  # a canary fails closed, it never raises
        record("host_winrm", False, f"host WinRM unreachable via {estate.host}: {_short(exc)}")
        for name in (
            "guest_psdirect",
            "checkpoint",
            "domain_account",
            "dc_locator",
            "kerberos",
            "helper_task",
            "console_session",
        ):
            record(name, False, "skipped: host WinRM unreachable")
        return CanaryReport(checks=tuple(checks))

    # -- guest PSDirect -----------------------------------------------------------
    guest_available = False
    if vm_state != "Running":
        record(
            "guest_psdirect",
            False,
            f"vm {estate.vm_name} state is {vm_state}; PSDirect not attempted "
            "(start the guest before the lane)",
        )
    else:
        try:
            transport.guest(_GUEST_ALIVE_SCRIPT, timeout=_GUEST_TIMEOUT_S)
            guest_available = True
            record("guest_psdirect", True, f"guest answered over PSDirect; vm state {vm_state}")
        except Exception as exc:
            record(
                "guest_psdirect",
                False,
                f"PSDirect to {estate.vm_name} failed with the estate credential: {_short(exc)}",
            )

    # -- checkpoint (host-side; the executor's own guard) ------------------------
    if not estate.checkpoint_name:
        record(
            "checkpoint",
            False,
            "no recovery checkpoint configured in the estate file (checkpoint_name is empty)",
        )
    else:
        try:
            present = checkpoint_exists(transport, estate)
            record(
                "checkpoint",
                present,
                f"recovery checkpoint {estate.checkpoint_name!r} "
                + ("present on host" if present else "NOT present on host"),
            )
        except Exception as exc:
            record("checkpoint", False, f"checkpoint probe failed: {_short(exc)}")

    if not guest_available:
        for name in ("domain_account", "dc_locator", "kerberos", "helper_task", "console_session"):
            record(name, False, "skipped: guest PSDirect unavailable")
        return CanaryReport(checks=tuple(checks))

    # -- domain account state ------------------------------------------------------
    try:
        out = transport.guest(
            _AD_ACCOUNT_SCRIPT, [estate.username], timeout=_GUEST_TIMEOUT_S
        )
        enabled = _line_value(out, "enabled")
        expired = _line_value(out, "password_expired")
        if enabled != "true" or expired != "false":
            problem = []
            if enabled != "true":
                problem.append(f"enabled={enabled or 'unreadable'}")
            if expired != "false":
                problem.append(f"password_expired={expired or 'unreadable'}")
            record(
                "domain_account",
                False,
                f"account {estate.username}: {', '.join(problem)} (reset password / "
                "enable account before the lane)",
            )
        else:
            record("domain_account", True, f"account {estate.username}: enabled, password valid")
    except Exception as exc:
        record("domain_account", False, f"account probe failed: {_short(exc)}")

    # -- DC locator (the clock-trap DNS canary) -------------------------------------
    try:
        out = transport.guest(_DC_LOCATOR_SCRIPT, [estate.domain], timeout=_GUEST_TIMEOUT_S)
        rc = _line_value(out, "rc")
        if rc == "0":
            record("dc_locator", True, f"nltest /dsgetdc:{estate.domain} answered (rc=0)")
        else:
            first = _first_content_line(out)
            record(
                "dc_locator",
                False,
                f"nltest /dsgetdc:{estate.domain} rc={rc or 'unreadable'}: {first} "
                "(check guest time and DC-locator DNS after any DC boot/restore)",
            )
    except Exception as exc:
        record("dc_locator", False, f"dc locator probe failed: {_short(exc)}")

    # -- Kerberos (the one auth path GPMC needs that NTLM checks cannot see) ---
    try:
        out = transport.guest(_KERBEROS_SCRIPT, [estate.domain], timeout=_GUEST_TIMEOUT_S)
        raw_delta = _line_value(out, "dc_time_delta_s")
        klist_rc = _line_value(out, "klist_rc")
        delta: int | None = None
        try:
            delta = int(float(raw_delta))
        except ValueError:
            delta = None
        if delta is None:
            record(
                "kerberos",
                False,
                "DC time unreadable over LDAP from the guest's DNS servers; the "
                "DC may be down or LDAP blocked -- Kerberos health cannot be "
                "assumed (fix before the lane)",
            )
        elif abs(delta) > _MAX_CLOCK_SKEW_S:
            direction = "behind" if delta > 0 else "ahead of"
            record(
                "kerberos",
                False,
                f"DC clock is {abs(delta)}s {direction} the guest (Kerberos "
                f"MaxClockSkew {_MAX_CLOCK_SKEW_S}s): Kerberos/GPMC will fail "
                "while NTLM paths stay green -- seed the DC clock from the host "
                "(Set-Date), nltest /dsregdns, restart NetLogon",
            )
        elif klist_rc != "0":
            first = _kerberos_detail_line(out)
            record(
                "kerberos",
                False,
                f"klist mint for krbtgt/{estate.domain} failed "
                f"(rc={klist_rc or 'unreadable'}): {first}",
            )
        else:
            record(
                "kerberos",
                True,
                f"DC clock within {abs(delta)}s; klist minted krbtgt/{estate.domain} "
                "(rc=0)",
            )
    except Exception as exc:
        record("kerberos", False, f"kerberos probe failed: {_short(exc)}")

    # -- helper task -----------------------------------------------------------------
    try:
        out = transport.guest(
            _HELPER_TASK_SCRIPT, [estate.helper_task], timeout=_GUEST_TIMEOUT_S
        )
        state = _line_value(out, "state") or "unknown"
        if re.search(r"present=1", out) and state != "disabled":
            record(
                "helper_task",
                True,
                f"scheduled task {estate.helper_task!r} present (state {state})",
            )
        elif re.search(r"present=1", out):
            record(
                "helper_task",
                False,
                f"scheduled task {estate.helper_task!r} is {state}; the console "
                "helper cannot start (re-enable it before the lane)",
            )
        else:
            record(
                "helper_task",
                False,
                f"scheduled task {estate.helper_task!r} NOT found in the guest",
            )
    except Exception as exc:
        record("helper_task", False, f"helper task probe failed: {_short(exc)}")

    # -- console session (quser facts only; the helper is deliberately not probed) ---
    try:
        console = lock_state(transport, probe_helper=False)
        if console.console_session_active:
            record("console_session", True, f"console session active (state {console.state})")
        else:
            record(
                "console_session",
                False,
                f"no active console session (state {console.state}); establish the "
                "console session before the lane",
            )
    except Exception as exc:
        record("console_session", False, f"console probe failed: {_short(exc)}")

    return CanaryReport(checks=tuple(checks))


def _line_value(out: str, key: str) -> str:
    """The value of the first ``key=value`` line, lowercased; '' when absent."""
    match = re.search(rf"{key}=(\S+)", out)
    return match.group(1).lower() if match else ""


def _first_content_line(out: str) -> str:
    for line in out.splitlines():
        text = line.strip()
        if text and not text.startswith("rc="):
            return text[:120]
    return "no output"


def _kerberos_detail_line(out: str) -> str:
    """The first klist output line, skipping the probe's own metric lines."""
    for line in out.splitlines():
        text = line.strip()
        if text and not re.match(r"^(dc_time_delta_s|klist_rc)=", text):
            return text[:120]
    return "no output"


def _short(exc: Exception) -> str:
    """A bounded, single-line rendering of a probe failure."""
    text = " ".join(str(exc).split())
    return text[:200]
