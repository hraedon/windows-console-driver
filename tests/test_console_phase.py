"""Unit coverage for the console/reboot classification state machine.

The embedded PowerShell needs a lab host; the CLASSIFICATION logic does not:
these tests drive ``lock_state`` / ``wait_console_unlocked`` / ``reboot_readiness``
with a stub transport, pinning the enum vocabulary (WI-001):

- ``ConsolePhase`` has exactly the four producible states -- ``display_blanked``
  is gone from the vocabulary (a blank display classifies UNKNOWN, and the
  wake-display remedy is dispatched on UNKNOWN);
- ``RebootPhase`` has exactly the three producible states -- ``unreachable``
  is gone (an unprobeable guest is BOOTING_BLACKOUT with reachable=False);
- ``wait_console_unlocked`` returns ``no_session`` at once (a failure for
  every interactive caller, never something to poll out) and dispatches the
  remedies on LOCKED (unlock) and UNKNOWN (wake).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import pytest

import wcd.console_ops as console_ops
from wcd.console_ops import (
    ConsolePhase,
    RebootPhase,
    lock_state,
    reboot_readiness,
    wait_console_unlocked,
)


class _HelperReply:
    def __init__(self, outcome: str, error: str | None = None) -> None:
        self.outcome = outcome
        self.error = error


@dataclass
class StubTransport:
    """Just enough transport for classification: a scripted probe sequence."""

    probes: list[dict[str, Any]]
    helper_outcomes: list[str] = field(default_factory=lambda: ["ok"])
    helper_raises: bool = False
    guest_raises: bool = False
    guest_calls: int = 0

    def guest(self, script: str, *args: Any, **_kw: Any) -> str:
        index = min(self.guest_calls, len(self.probes) - 1)
        self.guest_calls += 1
        if self.guest_raises:
            raise RuntimeError("psdirect refused")
        return json.dumps(self.probes[index])

    def helper(self, request: dict[str, Any], **_kw: Any) -> _HelperReply:
        # The helper answers within the same classification round as the
        # guest probe that just ran (guest_calls was already incremented).
        index = min(max(self.guest_calls - 1, 0), len(self.helper_outcomes) - 1)
        if self.helper_raises:
            raise RuntimeError("helper channel down")
        return _HelperReply(self.helper_outcomes[index])


NO_SESSION_PROBE = {"logonui_running": False, "console_session_active": False}
LOCKED_PROBE = {"logonui_running": True, "console_session_active": True}
ACTIVE_PROBE = {"logonui_running": False, "console_session_active": True}


@pytest.fixture()
def remedies(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace the two host-side remedies with call markers."""
    calls: list[str] = []
    monkeypatch.setattr(
        console_ops, "unlock_console", lambda *a, **k: calls.append("unlock") or "ok"
    )
    monkeypatch.setattr(
        console_ops, "wake_display", lambda *a, **k: calls.append("wake") or "ok"
    )
    return calls


# --- the vocabulary itself ------------------------------------------------------


def test_console_phase_has_exactly_the_producible_states() -> None:
    assert {phase.value for phase in ConsolePhase} == {
        "unlocked",
        "locked",
        "no_session",
        "unknown",
    }
    assert not hasattr(ConsolePhase, "DISPLAY_BLANKED"), (
        "display_blanked was documented historically but never produced; a blank "
        "display classifies unknown, which is what the wake remedy keys on"
    )


def test_reboot_phase_has_exactly_the_producible_states() -> None:
    assert {phase.value for phase in RebootPhase} == {
        "ready",
        "reboot_pending",
        "booting_blackout",
    }
    assert not hasattr(RebootPhase, "UNREACHABLE")


@pytest.mark.parametrize(
    ("probes", "helper_outcomes", "probe_helper", "expected"),
    [
        ([NO_SESSION_PROBE], ["ok"], True, ConsolePhase.NO_SESSION),
        ([LOCKED_PROBE], ["ok"], True, ConsolePhase.LOCKED),
        ([ACTIVE_PROBE], ["ok"], True, ConsolePhase.UNLOCKED),
        ([ACTIVE_PROBE], ["error"], True, ConsolePhase.UNKNOWN),
        ([ACTIVE_PROBE], ["ok"], False, ConsolePhase.UNLOCKED),
    ],
)
def test_lock_state_produces_only_the_enum_vocabulary(
    probes: list[dict[str, Any]],
    helper_outcomes: list[str],
    probe_helper: bool,
    expected: ConsolePhase,
) -> None:
    state = lock_state(
        StubTransport(probes, helper_outcomes=helper_outcomes), probe_helper=probe_helper
    )
    assert state.state is expected
    # StrEnum: the classification still serializes and interpolates as its value.
    assert f"{state.state}" == state.state.value
    import json as _json

    assert _json.dumps({"state": state.state}) == f'{{"state": "{state.state.value}"}}'


def test_lock_state_notes_a_failing_helper_channel() -> None:
    state = lock_state(StubTransport([ACTIVE_PROBE], helper_raises=True))
    assert state.state is ConsolePhase.UNKNOWN
    assert any("helper context failed" in note for note in state.notes)


# --- wait_console_unlocked semantics --------------------------------------------


def test_no_session_returns_at_once_without_either_remedy(remedies: list[str]) -> None:
    """The decision WI-001 pins: no_session is a failure for every interactive
    caller, returned immediately -- there is nothing to wake, unlock or poll."""
    transport = StubTransport([NO_SESSION_PROBE])
    result = wait_console_unlocked(transport, object(), timeout_s=90)  # type: ignore[arg-type]
    assert result.state is ConsolePhase.NO_SESSION
    assert remedies == []
    assert transport.guest_calls == 1, "one classification, no retries, no remedies"


def test_locked_dispatches_the_credential_unlock(
    remedies: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("time.sleep", lambda _s: None)
    transport = StubTransport([LOCKED_PROBE, ACTIVE_PROBE])
    result = wait_console_unlocked(transport, object(), timeout_s=30)  # type: ignore[arg-type]
    assert result.state is ConsolePhase.UNLOCKED
    assert remedies == ["unlock"]


def test_unknown_dispatches_the_display_wake(
    remedies: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("time.sleep", lambda _s: None)
    # Helper answers only after the wake: blank display, then unlocked.
    transport = StubTransport([ACTIVE_PROBE, ACTIVE_PROBE], helper_outcomes=["error", "ok"])
    result = wait_console_unlocked(transport, object(), timeout_s=30)  # type: ignore[arg-type]
    assert result.state is ConsolePhase.UNLOCKED
    assert remedies == ["wake"]


def test_timeout_reports_the_final_classification_as_data(
    remedies: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # A deadline of 0 expires right after the first remedy attempt; the final
    # lock_state call reports whatever the console actually is, never a raise.
    monkeypatch.setattr("time.sleep", lambda _s: None)
    monkeypatch.setattr("time.monotonic", lambda: 0.0)
    transport = StubTransport([LOCKED_PROBE, LOCKED_PROBE])
    result = wait_console_unlocked(transport, object(), timeout_s=0)  # type: ignore[arg-type]
    assert result.state is ConsolePhase.LOCKED


# --- reboot readiness -----------------------------------------------------------


def test_reboot_readiness_classifies_an_unprobeable_guest_as_blackout() -> None:
    readiness = reboot_readiness(StubTransport([], guest_raises=True))
    assert readiness.classification is RebootPhase.BOOTING_BLACKOUT
    assert readiness.reachable is False


def test_reboot_readiness_reports_pending_markers() -> None:
    pending = reboot_readiness(
        StubTransport([{"reboot_pending": True, "reasons": ["pending rename"], "last_boot": "x"}])
    )
    assert pending.classification is RebootPhase.REBOOT_PENDING
    assert pending.reachable is True
    ready = reboot_readiness(
        StubTransport([{"reboot_pending": False, "reasons": [], "last_boot": "x"}])
    )
    assert ready.classification is RebootPhase.READY
