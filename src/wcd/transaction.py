"""The transaction state machine (docs/contract.md section 2), pure logic.

The evidence runtime owns the verified transaction; this module is the
controller-side mirror of its state machine, so the console driver can be
tested against the same rules without Windows (contract section 13)::

    prepared -> armed -> commit-attempted -> verified | disproven | indeterminate

The rules this module enforces, by name:

- **prepared** requires the four preconditions recorded as flags:
  ``pre_oracle_done`` (pre-state oracle complete), ``lease_held`` (exclusive
  interactive-session lease), ``context_asserted`` (interactive context
  matched), ``recovery_declared`` (recovery strategy declared and demonstrated
  present). A prepare with any of them missing is refused, and the transaction
  stays unprepared.
- **armed** means the capability invocation has started and only pre-commit
  interactions have occurred.
- **commit-attempted** is crossed by the first declared commit point (or any
  potentially mutating action). It is *terminal for replay*: a capability is
  never replayed from the beginning after this point, because its UI state is
  unknown and its effects may be partially durable. The only legal
  continuations are oracle resolution or reconciliation.
- **crossing an undeclared boundary is a hard stop**: :meth:`Transaction.commit`
  with ``declared=False`` raises :class:`UndeclaredMutation` (a
  :class:`wcd.profiles.ProfileInvalid`) *and* forces the machine into its
  ``indeterminate`` terminal state. The raise is the guard outcome; the state
  change is the hard stop -- a caller that catches the error still holds a
  machine that can only be reconciled.
- **verified requires (envelope result satisfied) AND (reproduce satisfied)**.
  An envelope violation resolves to *disproven* -- a result, not a failure --
  with the characterized delta recorded. Envelope satisfied but reproduction
  failed is *indeterminate*, per the convergence contract.
- **indeterminate exposes reconcile_required**: it blocks unsafe retries and
  maps to the WEL journal's reconciliation gate.

EVENTS ARE TIMESTAMP-FREE, BY DESIGN
    :meth:`Transaction.events` yields :class:`TransitionEvent` records carrying
    only sequence, from-state, to-state, and reason -- no clock dependency of
    any kind. Time belongs to the evidence runtime's journal, which owns
    clock discipline for the whole lane; a state machine that stamps its own
    events would create a second, weaker clock nobody reconciles. Journal
    mapping joins on ``sequence``.

NO I/O
    Every input is a flag, a string, or a boolean the caller derived from
    observation elsewhere. The machine never reads a clock, a file, a socket,
    or a screen.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal, NoReturn

from wcd.profiles import ProfileInvalid

TransactionState = Literal[
    "prepared", "armed", "commit_attempted", "verified", "disproven", "indeterminate"
]

TERMINAL_STATES: Final[frozenset[str]] = frozenset(
    {"verified", "disproven", "indeterminate"}
)


@dataclass(frozen=True)
class TransitionEvent:
    """One accepted state transition, suitable for journal mapping.

    Deliberately timestamp-free: the journal owns time (see module docstring).
    """

    sequence: int
    from_state: TransactionState | None
    to_state: TransactionState
    reason: str


@dataclass(frozen=True)
class GuardOutcome:
    """One refused transition, recorded as data on the machine.

    ``guard`` names the rule that refused ("prepare", "state", "terminal",
    "replay_forbidden", "undeclared_mutation") and ``reason`` says why. Refusals
    raise typed errors *and* are recorded here, so a journal can show both the
    refusal and the fact that nothing moved.
    """

    guard: str
    reason: str


class TransactionError(Exception):
    """Base class for transaction state-machine errors."""


class GuardRefused(TransactionError):
    """A transition was refused by a guard; the machine did not move."""

    def __init__(self, guard: str, reason: str) -> None:
        super().__init__(f"guard {guard!r} refused: {reason}")
        self.guard = guard
        self.reason = reason

    @property
    def outcome(self) -> GuardOutcome:
        return GuardOutcome(guard=self.guard, reason=self.reason)


class ReplayForbidden(GuardRefused):
    """A capability was replayed (re-armed/re-committed) after commit-attempted.

    Contract section 2: after commit-attempted the UI state is unknown and
    effects may be partially durable; the only legal continuations are oracle
    resolution or reconciliation. Never allowed, whatever the caller believes
    about idempotence.
    """

    def __init__(self, reason: str) -> None:
        super().__init__("replay_forbidden", reason)


class UndeclaredMutation(ProfileInvalid, GuardRefused):
    """A commit boundary the profile did not declare was crossed.

    Subclasses both error families deliberately: it is a
    :class:`wcd.profiles.ProfileInvalid` finding (the profile gets corrected)
    raised as a guard refusal, and crossing it forces the transaction to its
    indeterminate terminal state (contract sections 2 and 6 rule 2).
    """

    def __init__(self, boundary: str, reason: str) -> None:
        self.boundary = boundary
        GuardRefused.__init__(self, "undeclared_mutation", reason)


class Transaction:
    """The prepared -> armed -> commit-attempted -> resolved state machine."""

    def __init__(self, transaction_id: str | None = None) -> None:
        self.transaction_id = transaction_id
        self._state: TransactionState | None = None
        self._events: list[TransitionEvent] = []
        self._refusals: list[GuardOutcome] = []
        self._characterization: str | None = None
        self._indeterminate_reason: str | None = None

    # -- observations ---------------------------------------------------------

    @property
    def state(self) -> TransactionState | None:
        """The current state; ``None`` until prepare succeeds."""
        return self._state

    @property
    def events(self) -> tuple[TransitionEvent, ...]:
        """Every accepted transition, in order (timestamp-free)."""
        return tuple(self._events)

    @property
    def refusals(self) -> tuple[GuardOutcome, ...]:
        """Every refused transition, in order."""
        return tuple(self._refusals)

    @property
    def reconcile_required(self) -> bool:
        """True when the machine is indeterminate and must be reconciled."""
        return self._state == "indeterminate"

    @property
    def is_terminal(self) -> bool:
        """True once the machine reached verified/disproven/indeterminate."""
        return self._state in TERMINAL_STATES

    @property
    def characterization(self) -> str | None:
        """The characterized delta recorded on a disproven resolution."""
        return self._characterization

    @property
    def indeterminate_reason(self) -> str | None:
        """The reason recorded when the machine went indeterminate."""
        return self._indeterminate_reason

    # -- transitions ----------------------------------------------------------

    def prepare(
        self,
        *,
        pre_oracle_done: bool,
        lease_held: bool,
        context_asserted: bool,
        recovery_declared: bool,
        reason: str = "",
    ) -> TransitionEvent:
        """Record the four preconditions; refuse if any is missing."""
        if self._state is not None:
            self._refuse("state", f"prepare requires a fresh transaction; state is {self._state!r}")
        flags = {
            "pre_oracle_done": pre_oracle_done,
            "lease_held": lease_held,
            "context_asserted": context_asserted,
            "recovery_declared": recovery_declared,
        }
        missing = [name for name, flag in flags.items() if not flag]
        if missing:
            self._refuse("prepare", f"missing precondition(s): {', '.join(missing)}")
        return self._transition(
            "prepared",
            reason
            or "preconditions recorded: pre_oracle_done, lease_held, context_asserted, "
            "recovery_declared",
        )

    def arm(self, reason: str = "") -> TransitionEvent:
        """Start the capability invocation; only pre-commit work may follow."""
        if self._state == "prepared":
            return self._transition("armed", reason or "capability invocation started")
        if self._state is None:
            self._refuse("state", "arm before prepare")
        if self._state == "armed":
            self._refuse("state", "already armed")
        assert self._state is not None  # commit_attempted or terminal
        self._refuse_replay(
            f"cannot re-arm from {self._state!r}: after commit-attempted a capability is "
            "never replayed from the beginning"
        )

    def commit(self, boundary: str, *, declared: bool, reason: str = "") -> TransitionEvent:
        """Cross a commit boundary.

        ``boundary`` names the commit point (e.g. the capability's
        ``first_commit_point``); ``declared`` is the caller's check of the
        crossing against the driver profile's classification (``commit_point``
        or ``potentially_mutating``). An undeclared crossing raises
        :class:`UndeclaredMutation` and forces an indeterminate terminal state
        -- the hard stop.
        """
        if not declared:
            if self._state is None:
                self._refuse("state", "cannot cross a boundary before prepare")
            if self._state in TERMINAL_STATES:
                self._refuse("terminal", f"terminal state {self._state!r} accepts no crossings")
            assert self._state is not None
            stop_reason = (
                reason
                or f"boundary {boundary!r} is not declared by the profile (profile-invalid "
                "finding; the profile gets corrected)"
            )
            self._refusals.append(
                GuardOutcome(guard="undeclared_mutation", reason=stop_reason)
            )
            self._transition(
                "indeterminate",
                f"UNDECLARED MUTATION at boundary {boundary!r}: hard stop, "
                "transaction is indeterminate",
            )
            self._indeterminate_reason = stop_reason
            raise UndeclaredMutation(boundary, stop_reason)
        if self._state == "armed":
            return self._transition(
                "commit_attempted", reason or f"crossed commit point {boundary!r}"
            )
        if self._state == "commit_attempted":
            self._refuse(
                "state",
                "already commit-attempted; further mutations are part of the same attempt and "
                "the only legal continuations are oracle resolution or reconciliation",
            )
        if self._state == "prepared":
            self._refuse("state", "commit before arm")
        if self._state is None:
            self._refuse("state", "commit before prepare")
        self._refuse_replay(f"cannot commit from terminal state {self._state!r}")

    def resolve(
        self,
        *,
        envelope_satisfied: bool,
        reproduce_satisfied: bool,
        characterization: str = "",
        reason: str = "",
    ) -> TransitionEvent:
        """Resolve the post-state oracle from commit-attempted.

        verified requires the envelope satisfied AND reproduction satisfied.
        Envelope violated -> disproven (record ``characterization`` -- the
        characterized delta is what makes disproven a *result*). Envelope
        satisfied but reproduction failed -> indeterminate: a state that will
        not reproduce cannot be claimed either way.
        """
        if self._state != "commit_attempted":
            self._refuse(
                "state",
                f"resolve requires commit-attempted; state is {self._state!r}",
            )
        if envelope_satisfied and reproduce_satisfied:
            return self._transition(
                "verified", reason or "envelope satisfied and reproduction verified"
            )
        if not envelope_satisfied:
            self._characterization = characterization
            return self._transition(
                "disproven", reason or "envelope violated (characterized delta recorded)"
            )
        stop_reason = reason or "reproduction failed after the envelope was satisfied"
        event = self._transition("indeterminate", stop_reason)
        self._indeterminate_reason = stop_reason
        return event

    def mark_indeterminate(self, reason: str) -> TransitionEvent:
        """Force indeterminate from any live state (e.g. a context mismatch).

        Contract section 7: any deviation in the interactive context before a
        commit point invalidates the pending operation -> indeterminate, never
        a retry.
        """
        if self._state is None:
            self._refuse("state", "nothing prepared; there is no transaction to make indeterminate")
        if self._state in TERMINAL_STATES:
            self._refuse("terminal", f"terminal state {self._state!r} accepts no transitions")
        event = self._transition("indeterminate", reason)
        self._indeterminate_reason = reason
        return event

    # -- internals ------------------------------------------------------------

    def _transition(self, to_state: TransactionState, reason: str) -> TransitionEvent:
        event = TransitionEvent(
            sequence=len(self._events) + 1,
            from_state=self._state,
            to_state=to_state,
            reason=reason,
        )
        self._events.append(event)
        self._state = to_state
        return event

    def _refuse(self, guard: str, reason: str) -> NoReturn:
        self._refusals.append(GuardOutcome(guard=guard, reason=reason))
        raise GuardRefused(guard, reason)

    def _refuse_replay(self, reason: str) -> NoReturn:
        self._refusals.append(GuardOutcome(guard="replay_forbidden", reason=reason))
        raise ReplayForbidden(reason)
