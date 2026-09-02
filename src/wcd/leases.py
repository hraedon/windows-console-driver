"""Exclusive interactive-session lease and context assertions (contract section 7).

While a transaction is live, **nothing else -- human or agent -- manipulates
that desktop**. This module is the pure, in-memory model of that promise:

- :meth:`LeaseRegistry.acquire` is exclusive: a second concurrent acquire for
  the same target is refused with :class:`LeaseHeldError`, which names the
  current holder (so the refusal is actionable, not just an error).
- :meth:`LeaseRegistry.release` frees the target; you must present the very
  lease object you were given (identity, not an equal copy).
- With a TTL, the lease exposes ``expires_at``; an expired lease no longer
  blocks a new acquire. That is a deliberate liveness choice: the registry has
  no background timer and no I/O, so a holder that died without releasing must
  not block the desktop forever -- instead the new holder takes over and the
  stale holder discovers the loss at its next :meth:`LeaseRegistry.is_active`
  check. Clock is injected per registry, so tests never wait.

Before every commit point the driver takes a **fresh interactive context
assertion** and requires an exact match against the expected context:
``session_id`` + ``user`` + ``desktop`` + foreground ``{hwnd, pid, process,
fingerprint}``. :func:`assert_context` deep-compares field by field and raises
:class:`ContextMismatch` listing *every* differing field -- a mismatch is never
a retry, it invalidates the pending operation (-> indeterminate upstream).
Named unsupported states (Secure Desktop/UAC, RDP reconnect, session switch,
resolution change, helper restart in another session) all appear through this
one mechanism: as context mismatches.

Pure logic only: no I/O, no clocks of its own beyond the injected one.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass


class LeaseError(Exception):
    """Base class for lease and context-assertion errors."""


class LeaseHeldError(LeaseError):
    """A second concurrent acquire was refused; the target is exclusive."""

    def __init__(self, target_id: str, holder: str) -> None:
        super().__init__(f"target {target_id!r} is exclusively held by {holder!r}")
        self.target_id = target_id
        self.holder = holder


class LeaseNotHeldError(LeaseError):
    """A release (or other lease presentation) named a lease not actually held."""

    def __init__(self, target_id: str, reason: str) -> None:
        super().__init__(f"no such held lease for target {target_id!r}: {reason}")
        self.target_id = target_id


@dataclass(frozen=True)
class Lease:
    """One acquired lease. ``expires_at`` is set only when a TTL was given."""

    target_id: str
    holder: str
    acquired_at: float
    expires_at: float | None


class LeaseRegistry:
    """In-memory registry of exclusive leases, keyed by target id.

    ``clock`` is injected (default :func:`time.monotonic`); expiry is checked
    against it at acquire/active-check time, never in the background.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._leases: dict[str, Lease] = {}

    def acquire(
        self, target_id: str, holder: str, *, ttl_seconds: float | None = None
    ) -> Lease:
        """Acquire the exclusive lease for ``target_id``.

        Refuses with :class:`LeaseHeldError` (naming the current holder) while
        an unexpired lease exists. A TTL-expired lease is superseded: the new
        acquire succeeds and the stale holder's lease stops being active.
        """
        if not target_id:
            raise ValueError("target_id must be non-empty")
        if not holder:
            raise ValueError("holder must be non-empty")
        if ttl_seconds is not None and ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive when given")
        current = self._leases.get(target_id)
        if current is not None and self._is_live(current):
            raise LeaseHeldError(target_id, current.holder)
        now = self._clock()
        lease = Lease(
            target_id=target_id,
            holder=holder,
            acquired_at=now,
            expires_at=None if ttl_seconds is None else now + ttl_seconds,
        )
        self._leases[target_id] = lease
        return lease

    def release(self, lease: Lease) -> None:
        """Free ``target_id``. Only the lease object itself may release it."""
        current = self._leases.get(lease.target_id)
        if current is not lease:
            raise LeaseNotHeldError(
                lease.target_id,
                "the registry holds a different lease or none; present the lease "
                "object you were given",
            )
        del self._leases[lease.target_id]

    def holder_of(self, target_id: str) -> str | None:
        """The current live holder of ``target_id``, or ``None``."""
        current = self._leases.get(target_id)
        if current is not None and self._is_live(current):
            return current.holder
        return None

    def is_active(self, lease: Lease) -> bool:
        """True when ``lease`` is the registered lease and not TTL-expired."""
        return self._leases.get(lease.target_id) is lease and self._is_live(lease)

    def _is_live(self, lease: Lease) -> bool:
        return lease.expires_at is None or self._clock() < lease.expires_at


# --- Interactive context assertions -------------------------------------------


@dataclass(frozen=True)
class ForegroundContext:
    """The foreground-window part of an interactive context."""

    hwnd: int
    pid: int
    process: str
    fingerprint: str


@dataclass(frozen=True)
class InteractiveContext:
    """The full interactive context required to match before a commit point."""

    session_id: int
    user: str
    desktop: str | None
    foreground: ForegroundContext | None


@dataclass(frozen=True)
class ContextFieldMismatch:
    """One differing context field, with both values."""

    field: str
    expected: object
    observed: object


class ContextMismatch(LeaseError):
    """An interactive context assertion failed; carries every differing field."""

    def __init__(self, mismatches: tuple[ContextFieldMismatch, ...]) -> None:
        self.mismatches = mismatches
        fields = ", ".join(mismatch.field for mismatch in mismatches)
        super().__init__(f"interactive context mismatch in: {fields}")

    @property
    def fields(self) -> tuple[str, ...]:
        return tuple(mismatch.field for mismatch in self.mismatches)


def context_mismatches(
    expected: InteractiveContext, observed: InteractiveContext
) -> tuple[ContextFieldMismatch, ...]:
    """Deep-compare two context records; return every differing field.

    Field paths are stable and deterministic: ``session_id``, ``user``,
    ``desktop``, ``foreground`` (when one side has a foreground window and the
    other does not), and ``foreground.hwnd`` / ``foreground.pid`` /
    ``foreground.process`` / ``foreground.fingerprint``.
    """
    mismatches: list[ContextFieldMismatch] = []
    if expected.session_id != observed.session_id:
        mismatches.append(
            ContextFieldMismatch("session_id", expected.session_id, observed.session_id)
        )
    if expected.user != observed.user:
        mismatches.append(ContextFieldMismatch("user", expected.user, observed.user))
    if expected.desktop != observed.desktop:
        mismatches.append(ContextFieldMismatch("desktop", expected.desktop, observed.desktop))
    if (expected.foreground is None) != (observed.foreground is None):
        mismatches.append(
            ContextFieldMismatch("foreground", expected.foreground, observed.foreground)
        )
    elif expected.foreground is not None and observed.foreground is not None:
        a = expected.foreground
        b = observed.foreground
        for name, expected_value, observed_value in (
            ("foreground.hwnd", a.hwnd, b.hwnd),
            ("foreground.pid", a.pid, b.pid),
            ("foreground.process", a.process, b.process),
            ("foreground.fingerprint", a.fingerprint, b.fingerprint),
        ):
            if expected_value != observed_value:
                mismatches.append(
                    ContextFieldMismatch(name, expected_value, observed_value)
                )
    return tuple(mismatches)


def assert_context(expected: InteractiveContext, observed: InteractiveContext) -> None:
    """Raise :class:`ContextMismatch` unless the contexts match exactly."""
    mismatches = context_mismatches(expected, observed)
    if mismatches:
        raise ContextMismatch(mismatches)
