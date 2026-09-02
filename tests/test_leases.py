"""Lease and interactive-context assertion tests: contract section 7 rules, by name.

- exclusivity: a second concurrent acquire for the same target is refused with
  a typed error naming the current holder;
- release frees the target, and only the lease object itself can release it;
- TTL: ``expires_at`` comes from the injected clock, expiry unblocks the
  target (liveness for a holder that died), and no test ever waits;
- context assertions deep-compare session/user/desktop/foreground and report
  *every* differing field, because a mismatch is never a retry.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from wcd.leases import (
    ContextMismatch,
    ForegroundContext,
    InteractiveContext,
    Lease,
    LeaseHeldError,
    LeaseNotHeldError,
    LeaseRegistry,
    assert_context,
    context_mismatches,
)


@dataclass
class FakeClock:
    """Injectable clock; ``advance`` stands in for elapsed time."""

    now: float = 1000.0
    steps: list[float] = field(default_factory=list)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.steps.append(seconds)
        self.now += seconds


# --- Exclusivity ---------------------------------------------------------------


def test_second_concurrent_acquire_is_refused_naming_the_holder() -> None:
    """Contract section 7: the lease is exclusive while the transaction runs."""
    registry = LeaseRegistry()
    registry.acquire("desktop-1", "wcd-driver")
    with pytest.raises(LeaseHeldError) as excinfo:
        registry.acquire("desktop-1", "someone-else")
    assert excinfo.value.target_id == "desktop-1"
    assert excinfo.value.holder == "wcd-driver"
    assert "wcd-driver" in str(excinfo.value)
    assert registry.holder_of("desktop-1") == "wcd-driver"


def test_different_targets_do_not_conflict() -> None:
    registry = LeaseRegistry()
    first = registry.acquire("desktop-1", "driver-a")
    second = registry.acquire("desktop-2", "driver-b")
    assert first.holder == "driver-a"
    assert second.holder == "driver-b"


def test_release_frees_the_target() -> None:
    registry = LeaseRegistry()
    lease = registry.acquire("desktop-1", "wcd-driver")
    registry.release(lease)
    assert registry.holder_of("desktop-1") is None
    reacquired = registry.acquire("desktop-1", "next-transaction")
    assert reacquired.holder == "next-transaction"


def test_only_the_lease_object_itself_can_release() -> None:
    registry = LeaseRegistry()
    lease = registry.acquire("desktop-1", "wcd-driver")
    forged = Lease(
        target_id=lease.target_id,
        holder=lease.holder,
        acquired_at=lease.acquired_at,
        expires_at=lease.expires_at,
    )
    with pytest.raises(LeaseNotHeldError):
        registry.release(forged)  # an equal copy is not the lease
    assert registry.holder_of("desktop-1") == "wcd-driver"
    registry.release(lease)
    with pytest.raises(LeaseNotHeldError):
        registry.release(lease)  # double release


@pytest.mark.parametrize(
    "target_id, holder, ttl",
    [
        ("", "driver", None),
        ("desktop-1", "", None),
        ("desktop-1", "driver", 0),
        ("desktop-1", "driver", -5),
    ],
)
def test_acquire_input_validation(target_id: str, holder: str, ttl: float | None) -> None:
    with pytest.raises(ValueError):
        LeaseRegistry().acquire(target_id, holder, ttl_seconds=ttl)


# --- TTL and the injected clock -------------------------------------------------


def test_ttl_sets_expires_at_from_the_injected_clock() -> None:
    clock = FakeClock(now=1000.0)
    registry = LeaseRegistry(clock=clock)
    lease = registry.acquire("desktop-1", "wcd-driver", ttl_seconds=30)
    assert lease.acquired_at == 1000.0
    assert lease.expires_at == 1030.0
    assert registry.is_active(lease)


def test_expired_lease_stops_being_active_and_unblocks_the_target() -> None:
    """No background timer exists (pure logic), so liveness is enforced at
    acquire/check time: a holder that died without releasing must not block
    the desktop forever, and the stale holder learns it at its next check."""
    clock = FakeClock(now=1000.0)
    registry = LeaseRegistry(clock=clock)
    stale = registry.acquire("desktop-1", "wcd-driver", ttl_seconds=30)
    clock.advance(29)
    assert registry.is_active(stale)
    clock.advance(1)  # exactly at expires_at -> expired
    assert not registry.is_active(stale)
    assert registry.holder_of("desktop-1") is None
    replacement = registry.acquire("desktop-1", "next-transaction", ttl_seconds=30)
    assert replacement.holder == "next-transaction"
    assert not registry.is_active(stale)


def test_lease_without_ttl_never_expires() -> None:
    clock = FakeClock(now=1000.0)
    registry = LeaseRegistry(clock=clock)
    lease = registry.acquire("desktop-1", "wcd-driver")
    assert lease.expires_at is None
    clock.advance(10**9)
    assert registry.is_active(lease)
    with pytest.raises(LeaseHeldError):
        registry.acquire("desktop-1", "intruder")


# --- Interactive context assertions ---------------------------------------------


def _context(
    *,
    session_id: int = 1,
    user: str = "lab-user",
    desktop: str = "Default",
    hwnd: int = 0x10010,
    pid: int = 4242,
    process: str = "mmc.exe",
    fingerprint: str = "digest-1",
) -> InteractiveContext:
    return InteractiveContext(
        session_id=session_id,
        user=user,
        desktop=desktop,
        foreground=ForegroundContext(hwnd=hwnd, pid=pid, process=process, fingerprint=fingerprint),
    )


def test_matching_context_assertion_passes() -> None:
    assert_context(_context(), _context())
    assert context_mismatches(_context(), _context()) == ()


@pytest.mark.parametrize(
    "observed, expected_field",
    [
        (_context(session_id=2), "session_id"),
        (_context(user="other-user"), "user"),
        (_context(desktop="Secure Desktop"), "desktop"),  # named unsupported state, section 7
    ],
)
def test_each_session_field_is_reported_by_path(
    observed: InteractiveContext, expected_field: str
) -> None:
    mismatches = context_mismatches(_context(), observed)
    assert [mismatch.field for mismatch in mismatches] == [expected_field]


@pytest.mark.parametrize(
    "observed, expected_field",
    [
        (_context(hwnd=99), "foreground.hwnd"),
        (_context(pid=99), "foreground.pid"),
        (_context(process="explorer.exe"), "foreground.process"),
        (_context(fingerprint="digest-2"), "foreground.fingerprint"),
    ],
)
def test_each_foreground_field_is_reported_by_path(
    observed: InteractiveContext, expected_field: str
) -> None:
    mismatches = context_mismatches(_context(), observed)
    assert [mismatch.field for mismatch in mismatches] == [expected_field]
    assert mismatches[0].expected != mismatches[0].observed


def test_missing_foreground_on_either_side_is_the_foreground_field() -> None:
    no_foreground = InteractiveContext(
        session_id=1, user="lab-user", desktop="Default", foreground=None
    )
    mismatches = context_mismatches(_context(), no_foreground)
    assert [mismatch.field for mismatch in mismatches] == ["foreground"]


def test_every_differing_field_is_listed_together() -> None:
    """A context assertion lists ALL mismatches, so reconciliation sees the
    whole deviation (e.g. an RDP reconnect changes several at once)."""
    observed = _context(
        session_id=3, user="someone", desktop="Winlogon", hwnd=1, pid=2, fingerprint="other"
    )
    fields = [mismatch.field for mismatch in context_mismatches(_context(), observed)]
    assert fields == [
        "session_id",
        "user",
        "desktop",
        "foreground.hwnd",
        "foreground.pid",
        "foreground.fingerprint",
    ]


def test_context_mismatch_error_carries_the_fields() -> None:
    observed = _context(user="someone", hwnd=42)
    with pytest.raises(ContextMismatch) as excinfo:
        assert_context(_context(), observed)
    assert excinfo.value.fields == ("user", "foreground.hwnd")
    assert "user" in str(excinfo.value)
    assert "foreground.hwnd" in str(excinfo.value)
