"""Exclusive interactive-session lease and context assertions (contract section 7).

While a transaction is live, cooperating WCD processes must not manipulate the
same desktop concurrently. This module provides both the pure in-memory model
and the kernel-backed registry used by real executor processes (human/unrelated
tool exclusion remains an estate precondition checked indirectly through fresh
interactive-context assertions):

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
- :class:`FileLeaseRegistry` applies the same ownership API to an OS file lock,
  so independent CLI processes contend and process death releases the lock.

Before every commit point the driver takes a **fresh interactive context
assertion** and requires an exact match against the expected context:
``session_id`` + ``user`` + ``desktop`` + foreground ``{hwnd, pid, process,
fingerprint}``. :func:`assert_context` deep-compares field by field and raises
:class:`ContextMismatch` listing *every* differing field -- a mismatch is never
a retry, it invalidates the pending operation (-> indeterminate upstream).
Named unsupported states (Secure Desktop/UAC, RDP reconnect, session switch,
resolution change, helper restart in another session) all appear through this
one mechanism: as context mismatches.

The in-memory registry and context comparison remain pure; the file registry is
the small deployment boundary that owns the kernel lock.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


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


class FileLeaseRegistry:
    """Kernel-backed lease registry shared by independent controller processes.

    One stable lock file is used per target.  The operating system owns the
    actual byte-range/advisory lock, so a crashed process releases exclusivity
    automatically; the file itself is only durable holder metadata.
    """

    def __init__(
        self,
        directory: str | Path | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._clock = clock
        self._directory = (
            Path(directory)
            if directory is not None
            else Path(tempfile.gettempdir()) / "windows-console-driver" / "leases"
        )
        self._held: dict[str, tuple[Lease, BinaryIO]] = {}

    def acquire(
        self, target_id: str, holder: str, *, ttl_seconds: float | None = None
    ) -> Lease:
        if not target_id:
            raise ValueError("target_id must be non-empty")
        if not holder:
            raise ValueError("holder must be non-empty")
        if ttl_seconds is not None:
            raise ValueError("kernel-backed leases do not support TTLs")
        current = self._held.get(target_id)
        if current is not None:
            raise LeaseHeldError(target_id, current[0].holder)

        self._directory.mkdir(parents=True, exist_ok=True)
        path = self._path_for(target_id)
        handle = path.open("a+b")
        try:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            _lock_handle(handle)
        except OSError as exc:
            handle.close()
            raise LeaseHeldError(target_id, _read_holder(path) or "another process") from exc

        lease = Lease(
            target_id=target_id,
            holder=holder,
            acquired_at=self._clock(),
            expires_at=None,
        )
        metadata = json.dumps({"holder": holder, "pid": os.getpid()}).encode("utf-8")
        handle.seek(1)
        handle.truncate()
        handle.write(metadata)
        handle.flush()
        self._held[target_id] = (lease, handle)
        return lease

    def release(self, lease: Lease) -> None:
        current = self._held.get(lease.target_id)
        if current is None or current[0] is not lease:
            raise LeaseNotHeldError(
                lease.target_id,
                "the registry holds a different lease or none; present the lease "
                "object you were given",
            )
        handle = current[1]
        try:
            _unlock_handle(handle)
        finally:
            handle.close()
            del self._held[lease.target_id]

    def holder_of(self, target_id: str) -> str | None:
        current = self._held.get(target_id)
        if current is not None:
            return current[0].holder
        path = self._path_for(target_id)
        if not path.exists():
            return None
        handle = path.open("a+b")
        try:
            try:
                _lock_handle(handle)
            except OSError:
                return _read_holder(path) or "another process"
            _unlock_handle(handle)
            return None
        finally:
            handle.close()

    def is_active(self, lease: Lease) -> bool:
        current = self._held.get(lease.target_id)
        return current is not None and current[0] is lease and not current[1].closed

    def _path_for(self, target_id: str) -> Path:
        digest = hashlib.sha256(target_id.encode("utf-8")).hexdigest()
        return self._directory / f"{digest}.lock"


def _lock_handle(handle: BinaryIO) -> None:
    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        fcntl = importlib.import_module("fcntl")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock_handle(handle: BinaryIO) -> None:
    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl = importlib.import_module("fcntl")
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _read_holder(path: Path) -> str | None:
    try:
        # Byte zero is the locked region. Read metadata from byte one so a
        # contender can identify the holder without touching the held byte.
        with path.open("rb") as handle:
            handle.seek(1)
            payload = json.loads(handle.read().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    holder = payload.get("holder") if isinstance(payload, dict) else None
    return holder if isinstance(holder, str) and holder else None


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
