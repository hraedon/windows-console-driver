"""Transaction state machine tests: contract section 2 rules, by name.

Every test below names the section-2 rule it pins. The machine is pure: no
clock, no I/O; events are timestamp-free and the journal owns time.
"""

from __future__ import annotations

import dataclasses

import pytest

from wcd.profiles import ProfileInvalid
from wcd.transaction import (
    GuardRefused,
    ReplayForbidden,
    Transaction,
    TransitionEvent,
    UndeclaredMutation,
)


def _prepared() -> Transaction:
    transaction = Transaction()
    transaction.prepare(
        pre_oracle_done=True,
        lease_held=True,
        context_asserted=True,
        recovery_declared=True,
    )
    return transaction


def _armed() -> Transaction:
    transaction = _prepared()
    transaction.arm()
    return transaction


def _commit_attempted() -> Transaction:
    transaction = _armed()
    transaction.commit("startup-scripts-dialog-ok", declared=True)
    return transaction


def test_prepared_to_verified_happy_path_and_event_chain() -> None:
    """Contract section 2: prepared -> armed -> commit-attempted -> verified,
    where verified requires (envelope result satisfied) AND (reproduce
    satisfied)."""
    transaction = _commit_attempted()
    event = transaction.resolve(envelope_satisfied=True, reproduce_satisfied=True)
    assert event.to_state == "verified"
    assert transaction.state == "verified"
    assert transaction.is_terminal
    assert not transaction.reconcile_required
    assert [e.to_state for e in transaction.events] == [
        "prepared",
        "armed",
        "commit_attempted",
        "verified",
    ]
    assert [e.from_state for e in transaction.events] == [
        None,
        "prepared",
        "armed",
        "commit_attempted",
    ]


@pytest.mark.parametrize(
    "missing",
    ["pre_oracle_done", "lease_held", "context_asserted", "recovery_declared"],
)
def test_prepare_requires_all_four_preconditions_by_name(missing: str) -> None:
    """Contract section 2, prepared: pre-state oracle complete, exclusive lease
    held, interactive context asserted, recovery declared. A missing
    precondition is refused by name and the transaction stays unprepared."""
    transaction = Transaction()
    flags = {
        "pre_oracle_done": True,
        "lease_held": True,
        "context_asserted": True,
        "recovery_declared": True,
    }
    flags[missing] = False
    with pytest.raises(GuardRefused) as excinfo:
        transaction.prepare(**flags)  # type: ignore[arg-type]
    assert excinfo.value.guard == "prepare"
    assert missing in excinfo.value.reason
    assert transaction.state is None
    assert transaction.refusals[-1].guard == "prepare"


def test_prepare_all_missing_lists_every_precondition() -> None:
    transaction = Transaction()
    with pytest.raises(GuardRefused) as excinfo:
        transaction.prepare(
            pre_oracle_done=False,
            lease_held=False,
            context_asserted=False,
            recovery_declared=False,
        )
    reason = excinfo.value.reason
    for name in ("pre_oracle_done", "lease_held", "context_asserted", "recovery_declared"):
        assert name in reason


def test_out_of_order_transitions_are_state_guard_refusals() -> None:
    transaction = Transaction()
    with pytest.raises(GuardRefused):
        transaction.arm()
    assert transaction.state is None
    with pytest.raises(GuardRefused):
        transaction.commit("anything", declared=True)
    assert transaction.state is None

    prepared = _prepared()
    with pytest.raises(GuardRefused):
        prepared.commit("startup-scripts-dialog-ok", declared=True)  # commit before arm
    assert prepared.state == "prepared"
    with pytest.raises(GuardRefused):
        prepared.resolve(envelope_satisfied=True, reproduce_satisfied=True)  # resolve before commit
    assert prepared.state == "prepared"


def test_replay_after_commit_attempted_is_never_allowed() -> None:
    """Contract section 2, commit-attempted: terminal for replay -- a
    capability is never replayed from the beginning after this point, because
    its UI state is unknown and its effects may be partially durable."""
    transaction = _commit_attempted()
    with pytest.raises(ReplayForbidden) as excinfo:
        transaction.arm()
    assert excinfo.value.guard == "replay_forbidden"
    assert transaction.state == "commit_attempted"  # the machine did not move
    assert transaction.refusals[-1].guard == "replay_forbidden"

    verified = Transaction()
    verified.prepare(
        pre_oracle_done=True, lease_held=True, context_asserted=True, recovery_declared=True
    )
    verified.arm()
    verified.commit("startup-scripts-dialog-ok", declared=True)
    verified.resolve(envelope_satisfied=True, reproduce_satisfied=True)
    with pytest.raises(ReplayForbidden):
        verified.arm()
    with pytest.raises(ReplayForbidden):
        verified.commit("startup-scripts-dialog-ok", declared=True)


def test_undeclared_mutation_is_a_profile_invalid_hard_stop() -> None:
    """Contract section 2 + section 6 rule 2: crossing an undeclared mutating
    boundary raises ProfileInvalid and forces an indeterminate terminal state."""
    transaction = _armed()
    with pytest.raises(UndeclaredMutation) as excinfo:
        transaction.commit("sneaky_apply_button", declared=False)
    assert isinstance(excinfo.value, ProfileInvalid)  # a profile-invalid finding...
    assert isinstance(excinfo.value, GuardRefused)  # ...raised as a guard refusal
    assert excinfo.value.guard == "undeclared_mutation"
    assert excinfo.value.boundary == "sneaky_apply_button"
    assert transaction.state == "indeterminate"  # the hard stop stuck
    assert transaction.is_terminal
    assert transaction.reconcile_required
    assert transaction.indeterminate_reason is not None
    assert transaction.refusals[-1].guard == "undeclared_mutation"
    # The forced transition is journaled even though the call raised:
    assert transaction.events[-1].from_state == "armed"
    assert transaction.events[-1].to_state == "indeterminate"
    assert "UNDECLARED MUTATION" in transaction.events[-1].reason
    # Terminal: oracle resolution is no longer available either.
    with pytest.raises(GuardRefused):
        transaction.resolve(envelope_satisfied=True, reproduce_satisfied=True)


def test_undeclared_mutation_after_commit_attempted_still_hard_stops() -> None:
    transaction = _commit_attempted()
    with pytest.raises(UndeclaredMutation):
        transaction.commit("second_undeclared_boundary", declared=False)
    assert transaction.state == "indeterminate"
    assert transaction.reconcile_required


def test_second_declared_commit_is_refused_not_replayed() -> None:
    """Further mutations after the first commit point are part of the same
    attempt; the machine stays in commit-attempted until oracle resolution."""
    transaction = _commit_attempted()
    with pytest.raises(GuardRefused) as excinfo:
        transaction.commit("another-declared-point", declared=True)
    assert excinfo.value.guard == "state"
    assert transaction.state == "commit_attempted"


def test_disproven_is_a_result_with_a_characterized_delta() -> None:
    """Contract section 2, disproven: envelope violated, with a characterized
    delta. Disproven is a result, not a failure."""
    transaction = _commit_attempted()
    event = transaction.resolve(
        envelope_satisfied=False,
        reproduce_satisfied=True,
        characterization="VIOLATED require[0]: version.machine did not increment",
    )
    assert event.to_state == "disproven"
    assert transaction.state == "disproven"
    assert transaction.is_terminal
    assert not transaction.reconcile_required
    assert transaction.characterization is not None
    assert "require[0]" in transaction.characterization


def test_envelope_satisfied_but_reproduction_failed_is_indeterminate() -> None:
    """Contract section 2: verified requires BOTH clauses; a state that will
    not reproduce cannot be claimed either way -> indeterminate -> reconcile."""
    transaction = _commit_attempted()
    event = transaction.resolve(envelope_satisfied=True, reproduce_satisfied=False)
    assert event.to_state == "indeterminate"
    assert transaction.state == "indeterminate"
    assert transaction.reconcile_required
    assert "reproduction" in (transaction.indeterminate_reason or "")


def test_context_mismatch_midflight_marks_indeterminate_never_a_retry() -> None:
    """Contract section 7 via section 2: any deviation in the interactive
    context invalidates the pending operation -> indeterminate, never a retry."""
    transaction = _armed()
    event = transaction.mark_indeterminate("foreground window changed mid-flight")
    assert event.to_state == "indeterminate"
    assert transaction.reconcile_required
    assert transaction.indeterminate_reason == "foreground window changed mid-flight"


def test_mark_indeterminate_refused_before_prepare_and_at_terminal() -> None:
    transaction = Transaction()
    with pytest.raises(GuardRefused):
        transaction.mark_indeterminate("too early")
    verified = _commit_attempted()
    verified.resolve(envelope_satisfied=True, reproduce_satisfied=True)
    with pytest.raises(GuardRefused):
        verified.mark_indeterminate("too late")


def test_events_are_timestamp_free_and_sequence_numbered() -> None:
    """Event records carry (sequence, from, to, reason) only -- no clock
    dependency; the journal maps them onto its own timeline."""
    transaction = _commit_attempted()
    transaction.resolve(envelope_satisfied=True, reproduce_satisfied=True)
    events = transaction.events
    assert len(events) == 4
    field_names = {field.name for field in dataclasses.fields(TransitionEvent)}
    assert field_names == {"sequence", "from_state", "to_state", "reason"}
    assert [event.sequence for event in events] == [1, 2, 3, 4]
    for event in events:
        assert isinstance(event.reason, str)


def test_refusals_are_recorded_as_guard_outcomes() -> None:
    """replay_forbidden and undeclared_mutation are first-class guard outcomes
    with reasons, recorded on the machine even though the calls raise."""
    transaction = _commit_attempted()
    with pytest.raises(ReplayForbidden):
        transaction.arm()
    fresh = Transaction()
    with pytest.raises(GuardRefused):
        fresh.arm()
    for refusal in (*transaction.refusals, *fresh.refusals):
        assert refusal.reason
    assert [refusal.guard for refusal in transaction.refusals] == ["replay_forbidden"]
    assert [refusal.guard for refusal in fresh.refusals] == ["state"]
