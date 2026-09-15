"""Unit tests for the estate health canary (WI-L1).

Everything here drives a scripted fake transport -- the live path is an
operator tool, never a default-suite test, per both repos' rules. The fakes
route on script-content markers exactly like the executor's own
FakeTransport, so each test scripts only the seam it is failing.
"""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest

from wcd.estate import EstateConfig
from wcd.estate_canary import run_estate_canary
from wcd.transport import TransportError

# Synthetic identifiers only (zz- convention); the estate names no real host.
_ESTATE = EstateConfig(
    host="zz-hyperv",
    vm_name="zz-vm",
    domain="zzlab.invalid",
    username="zz-operator",
    password_env="WCD_LAB_PASSWORD",
    checkpoint_name="zz-checkpoint-current",
    helper_task="WCDHelper",
)

_CHECK_ORDER = (
    "host_winrm",
    "guest_psdirect",
    "checkpoint",
    "domain_account",
    "dc_locator",
    "helper_task",
    "console_session",
)

Responder = Callable[[str, list[object]], str]


class FakeCanaryTransport:
    """Scripted stand-in: every probe answers a configurable canned line."""

    def __init__(
        self,
        *,
        vm_state: str = "Running",
        checkpoint_count: int = 1,
        enabled: str = "True",
        password_expired: str = "False",
        nltest_rc: str = "0",
        nltest_lines: str = "",
        helper_present: bool = True,
        helper_state: str = "Ready",
        console_active: bool = True,
        host_error: Exception | None = None,
        alive_error: Exception | None = None,
    ) -> None:
        self.vm_state = vm_state
        self.checkpoint_count = checkpoint_count
        self.enabled = enabled
        self.password_expired = password_expired
        self.nltest_rc = nltest_rc
        self.nltest_lines = nltest_lines
        self.helper_present = helper_present
        self.helper_state = helper_state
        self.console_active = console_active
        self.host_error = host_error
        self.alive_error = alive_error
        self.guest_calls: list[str] = []
        self.host_calls: list[str] = []

    @property
    def vm_name(self) -> str:
        return _ESTATE.vm_name

    def host(self, script: str, args: list[object] | None = None, *, timeout: float = 120.0) -> str:
        self.host_calls.append(script)
        if self.host_error is not None:
            raise self.host_error
        if "Get-VM -Name" in script:
            return f"state={self.vm_state}\n"
        if "Get-VMSnapshot" in script:
            return f"count={self.checkpoint_count}\n"
        raise AssertionError(f"unscripted host call: {script[:120]!r}")

    def guest(
        self, script: str, args: list[object] | None = None, *, timeout: float = 180.0
    ) -> str:
        self.guest_calls.append(script)
        if "Win32_OperatingSystem" in script and "alive=1" in script:
            if self.alive_error is not None:
                raise self.alive_error
            return "alive=1 boot=2026-01-01T00:00:00\n"
        if "Get-ADUser" in script:
            return f"enabled={self.enabled}\npassword_expired={self.password_expired}\n"
        if "nltest" in script:
            return f"rc={self.nltest_rc}\n{self.nltest_lines}"
        if "Get-ScheduledTask" in script:
            if not self.helper_present:
                return "present=0\n"
            return f"present=1 state={self.helper_state}\n"
        if "logonui_running" in script:
            return json.dumps(
                {
                    "logonui_running": False,
                    "console_session_active": self.console_active,
                    "inactivity_timeout_secs": 0,
                    "quser": [],
                }
            )
        raise AssertionError(f"unscripted guest call: {script[:120]!r}")


def _details(report) -> dict[str, str]:
    return {c.name: c.detail for c in report.checks}


def _names(report) -> list[str]:
    return [c.name for c in report.checks]


def test_green_estate_all_checks_pass_in_order() -> None:
    report = run_estate_canary(FakeCanaryTransport(), _ESTATE)
    assert report.ok is True
    assert _names(report) == list(_CHECK_ORDER)
    assert all(c.detail and not c.detail.startswith("skipped") for c in report.checks)


def test_missing_checkpoint_fails_with_its_name() -> None:
    report = run_estate_canary(FakeCanaryTransport(checkpoint_count=0), _ESTATE)
    assert report.ok is False
    details = _details(report)
    assert "NOT present on host" in details["checkpoint"]
    assert "zz-checkpoint-current" in details["checkpoint"]
    # Every other check still ran and stayed green.
    assert _names(report) == list(_CHECK_ORDER)
    assert sum(1 for c in report.checks if c.ok) == 6


def test_empty_checkpoint_name_is_a_config_failure_not_a_probe() -> None:
    estate = EstateConfig(
        host="zz-hyperv",
        vm_name="zz-vm",
        domain="zzlab.invalid",
        username="zz-operator",
        password_env="WCD_LAB_PASSWORD",
        checkpoint_name="",
    )
    report = run_estate_canary(FakeCanaryTransport(), estate)
    assert report.ok is False
    assert "no recovery checkpoint configured" in _details(report)["checkpoint"]


def test_vm_off_fails_psdirect_and_skips_guest_checks() -> None:
    fake = FakeCanaryTransport(vm_state="Off")
    report = run_estate_canary(fake, _ESTATE)
    assert report.ok is False
    details = _details(report)
    assert "state is Off" in details["guest_psdirect"]
    for name in ("domain_account", "dc_locator", "helper_task", "console_session"):
        assert details[name].startswith("skipped: guest PSDirect unavailable")
    # Host-side checks still ran and stayed green.
    assert fake.host_calls  # vm state + checkpoint probes crossed
    assert fake.guest_calls == []  # nothing was attempted against the dead guest


def test_expired_password_fails_the_domain_account_check() -> None:
    report = run_estate_canary(FakeCanaryTransport(password_expired="True"), _ESTATE)
    assert report.ok is False
    detail = _details(report)["domain_account"]
    assert "password_expired=true" in detail


def test_disabled_account_fails_the_domain_account_check() -> None:
    report = run_estate_canary(FakeCanaryTransport(enabled="False"), _ESTATE)
    assert report.ok is False
    detail = _details(report)["domain_account"]
    assert "enabled=false" in detail


def test_dc_locator_failure_reports_rc_and_the_dns_hint() -> None:
    report = run_estate_canary(
        FakeCanaryTransport(
            nltest_rc="45",
            nltest_lines="Getting DC name failed... Cannot find DC.\n",
        ),
        _ESTATE,
    )
    assert report.ok is False
    detail = _details(report)["dc_locator"]
    assert "rc=45" in detail
    assert "Cannot find DC" in detail
    # The standing DC clock/DNS trap is named in the line.
    assert "DC-locator DNS" in detail


def test_disabled_helper_task_fails_even_though_present() -> None:
    """Presence is not usability: a disabled helper cannot start mid-lane."""
    report = run_estate_canary(FakeCanaryTransport(helper_state="Disabled"), _ESTATE)
    assert report.ok is False
    detail = _details(report)["helper_task"]
    assert "disabled" in detail
    assert "re-enable" in detail


def test_missing_helper_task_fails_precisely() -> None:
    report = run_estate_canary(FakeCanaryTransport(helper_present=False), _ESTATE)
    assert report.ok is False
    detail = _details(report)["helper_task"]
    assert "NOT found" in detail
    assert "WCDHelper" in detail


def test_no_console_session_fails_without_probing_the_helper() -> None:
    fake = FakeCanaryTransport(console_active=False)
    report = run_estate_canary(fake, _ESTATE)
    assert report.ok is False
    detail = _details(report)["console_session"]
    assert "no active console session" in detail
    # The canary is read-only: the console check reads quser facts only and
    # never crosses into a helper request.
    assert not any("action" in s for s in fake.guest_calls)


def test_host_unreachable_fails_closed_and_skips_everything_else() -> None:
    fake = FakeCanaryTransport(host_error=TransportError("zz: connection refused"))
    report = run_estate_canary(fake, _ESTATE)
    assert report.ok is False
    details = _details(report)
    assert "host WinRM unreachable" in details["host_winrm"]
    for name in _CHECK_ORDER[1:]:
        assert details[name].startswith("skipped:")
    assert fake.guest_calls == []


def test_guest_probe_failure_skips_only_later_guest_checks() -> None:
    fake = FakeCanaryTransport(
        alive_error=TransportError("zz: PSDirect open failed after 4 attempts")
    )
    report = run_estate_canary(fake, _ESTATE)
    assert report.ok is False
    details = _details(report)
    assert "PSDirect" in details["guest_psdirect"]
    # Host-side checks stayed green.
    assert "present on host" in details["checkpoint"]
    # Exactly one guest probe was attempted -- the failed one.
    assert len(fake.guest_calls) == 1


def test_probe_exception_becomes_a_failing_line_never_a_raise() -> None:
    class Boom(FakeCanaryTransport):
        def guest(self, script, args=None, *, timeout: float = 180.0):  # type: ignore[no-untyped-def]
            if "Get-ADUser" in script:
                raise RuntimeError("zz: module missing")
            return super().guest(script, args, timeout=timeout)

    report = run_estate_canary(Boom(), _ESTATE)
    assert report.ok is False
    assert "account probe failed" in _details(report)["domain_account"]


@pytest.mark.parametrize(
    "field",
    [
        "vm_state",
        "checkpoint_count",
        "enabled",
        "password_expired",
        "nltest_rc",
        "helper_present",
        "console_active",
    ],
)
def test_every_single_check_alone_can_redden_the_report(field: str) -> None:
    variants = {
        "vm_state": {"vm_state": "Off"},
        "checkpoint_count": {"checkpoint_count": 0},
        "enabled": {"enabled": "False"},
        "password_expired": {"password_expired": "True"},
        "nltest_rc": {"nltest_rc": "1722"},
        "helper_present": {"helper_present": False},
        "console_active": {"console_active": False},
    }
    report = run_estate_canary(FakeCanaryTransport(**variants[field]), _ESTATE)
    assert report.ok is False, field
