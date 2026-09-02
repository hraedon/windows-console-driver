"""Envelope engine tests: contract section 3 rules, by name.

Sections, in order:

- the bounded predicate evaluator: accepts exactly the documented subset,
  rejects everything else (no eval/exec, no Python attribute machinery), and
  enforces its bounds;
- the delta model: changed/added/removed with declared categories;
- :func:`wcd.envelope.parse_envelope` against capability-shaped dicts;
- assertion semantics: require/derive/forbid clauses and **the
  unclassified-change rule** -- any observed change neither covered by an
  allow category nor predicted by a require/derive clause is a violation,
  which is how a canonicalizer silently dropping a field is caught;
- convergence: stability across one poll, freeze, reproduce; **timeout and
  reproduce-mismatch are indeterminate, never a bare failure**.

All timing uses an injectable clock whose ``sleep`` advances it: no test waits.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

import pytest

from wcd.envelope import (
    MISSING,
    ConvergencePolicy,
    EnvelopeError,
    PredicateEvaluationError,
    PredicateResolutionError,
    PredicateSyntaxError,
    assert_envelope,
    compile_predicate,
    compute_delta,
    converge,
    evaluate,
    parse_envelope,
)


@dataclass
class FakeClock:
    """Injectable clock/sleep pair; sleep advances time, so tests never wait."""

    now: float = 0.0
    step: float = 5.0
    sleeps: list[float] = field(default_factory=list)

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


# --- Shared fact fixtures ------------------------------------------------------


PRE: dict[str, object] = {
    "version.machine": 4,
    "version.user": 0,
    "ad.when_changed": "2026-09-01T00:00:00Z",
    "sysvol.scripts_ini.mtime": 100.0,
    "forbid.gpc_extension_lists": [],
    "gpc.display_name": "Scripts GPO",
    "scripts_ini.machine.entries": [],
}

POST_OK: dict[str, object] = {
    "version.machine": 5,
    "version.user": 0,
    "ad.when_changed": "2026-09-01T00:01:00Z",
    "sysvol.scripts_ini.mtime": 108.0,
    "forbid.gpc_extension_lists": [],
    "gpc.display_name": "Scripts GPO",
    "scripts_ini.machine.entries": ["logon.cmd|-StartupParam"],
}

CATEGORIES: dict[str, str] = {
    "version.machine": "structural",
    "version.user": "structural",
    "ad.when_changed": "timestamps",
    "sysvol.scripts_ini.mtime": "file_mtime",
    "forbid.gpc_extension_lists": "structural",
    "gpc.display_name": "structural",
    "scripts_ini.machine.entries": "structural",
}


def _envelope_dict() -> dict[str, object]:
    """A machine-expression envelope with the shipped capability's shape."""
    return {
        "require": [
            {
                "fact": "scripts_ini.machine.entries",
                "predicate": 'facts["scripts_ini.machine.entries"] == '
                '["logon.cmd|-StartupParam"]',
            }
        ],
        "allow": [{"category": "timestamps"}, {"category": "file_mtime"}],
        "forbid": [{"scope": "forbid.gpc_extension_lists", "predicate": "scope == []"}],
        "derive": [
            {"relation": "post.version.machine > pre.version.machine"},
            {"relation": "post.version.user == pre.version.user"},
        ],
        "convergence": {"window_seconds": 90, "poll_seconds": 5, "reproduce": 2},
    }


# --- The bounded predicate evaluator -------------------------------------------


def test_evaluator_accepts_the_documented_subset() -> None:
    bindings: dict[str, object] = {
        "pre.version.machine": 4,
        "post.version.machine": 5,
        "post.version.user": 0,
        "post": {"version.user": 0},
        "facts": {"count": 2, "entries": ["logon.cmd|-StartupParam"]},
        "scope": [],
    }
    cases: list[tuple[str, bool]] = [
        ("post.version.machine > pre.version.machine", True),
        ("pre.version.machine + 1 == post.version.machine", True),
        ('post["version.user"] == 0', True),
        ('facts["entries"] == ["logon.cmd|-StartupParam"]', True),
        ('facts["count"] > 1 and post["version.user"] == 0', True),
        ('not (post.version.machine < 5) or facts["count"] == 99', True),
        ('"logon.cmd|-StartupParam" in facts["entries"]', True),
        ('"other" not in facts["entries"]', True),
        ("scope == []", True),
        ('1 < facts["count"] < 3', True),
        ('facts["count"] is not None', True),
        ('-facts["count"] < 0', True),
        ("(1, 2) == (1, 2)", True),
    ]
    for source, expected in cases:
        assert evaluate(compile_predicate(source), bindings) is expected, source


def test_boolop_returns_bool_with_python_short_circuit() -> None:
    assert evaluate(compile_predicate('facts["a"] or 5'), {"facts": {"a": 0}}) is True
    assert evaluate(compile_predicate('facts["a"] and 5'), {"facts": {"a": 1}}) is True
    assert evaluate(compile_predicate('facts["a"] and 5'), {"facts": {"a": 0}}) is False


@pytest.mark.parametrize(
    "source",
    [
        "len(scope) == 0",  # calls
        "scope.clear()",  # attribute then call
        "lambda: 1",  # lambda
        "[x for x in scope]",  # comprehension
        "f'{scope}'",  # f-string
        "scope[0]",  # non-string subscript key
        'facts[k]',  # non-literal subscript key
        "b'bytes'",  # bytes constant
        "1; 2",  # statements
        "(x := 1)",  # walrus
        "{**scope}",  # dict unpacking
        "scope == [] if True else [1]",  # conditional expression
        "import os",  # import statement
        # The shipped capability file's narrative predicates (it is unqualified
        # and its predicates are prose, not machine expressions):
        "present and parses; sections carry exactly the parameterized entries",
        "greater than pre-state machine version",
        "contains none of ['{3125E937-EB16-4b4c-9934-544FC6D24D26}']",
    ],
)
def test_evaluator_rejects_everything_outside_the_subset(source: str) -> None:
    with pytest.raises(PredicateSyntaxError):
        compile_predicate(source)


def test_predicate_bounds_are_enforced() -> None:
    with pytest.raises(PredicateSyntaxError):
        compile_predicate("1 + " * 600 + "1")  # source length bound
    with pytest.raises(PredicateSyntaxError):
        compile_predicate(" or ".join(["1"] * 130))  # AST node bound
    with pytest.raises(PredicateSyntaxError):
        compile_predicate("[" + ", ".join(str(i) for i in range(33)) + "] == []")  # list bound
    with pytest.raises(PredicateSyntaxError):
        compile_predicate("not " * 17 + "True")  # nesting bound
    with pytest.raises(PredicateSyntaxError):
        compile_predicate(123)  # type: ignore[arg-type]
    with pytest.raises(PredicateSyntaxError):
        compile_predicate("   ")


def test_unresolved_references_are_resolution_errors() -> None:
    with pytest.raises(PredicateResolutionError):
        evaluate(compile_predicate("post.version.machine > 1"), {})
    with pytest.raises(PredicateResolutionError):
        evaluate(compile_predicate('facts["absent"] == 1'), {"facts": {}})


def test_type_mistakes_are_evaluation_errors() -> None:
    with pytest.raises(PredicateEvaluationError):
        evaluate(compile_predicate('facts["n"] > 3'), {"facts": {"n": "abc"}})
    with pytest.raises(PredicateEvaluationError):
        evaluate(compile_predicate('facts["n"] // 0 == 0'), {"facts": {"n": 1}})
    with pytest.raises(PredicateEvaluationError):
        evaluate(compile_predicate('facts["n"]["k"] == 1'), {"facts": {"n": 5}})


def test_no_python_attribute_machinery_is_reachable() -> None:
    """``obj.secret`` is a dotted *key* lookup, never a getattr."""

    class Obj:
        secret = "value"

    predicate = compile_predicate("obj.secret == 'value'")
    with pytest.raises(PredicateResolutionError):
        evaluate(predicate, {"obj": Obj()})


# --- Delta model ---------------------------------------------------------------


def test_delta_changed_added_removed_with_declared_categories() -> None:
    pre: dict[str, object] = {"version.machine": 4, "gone.key": "x", "same.key": 1}
    post: dict[str, object] = {"version.machine": 5, "new.key": True, "same.key": 1}
    categories = {"version.machine": "structural", "gone.key": "structural", "same.key": "other"}
    delta = compute_delta(pre, post, categories)
    assert [entry.key for entry in delta.changed] == ["version.machine"]
    assert [entry.key for entry in delta.added] == ["new.key"]
    assert [entry.key for entry in delta.removed] == ["gone.key"]
    removed = delta.removed[0]
    assert removed.before == "x"
    assert removed.after is MISSING
    assert delta.added[0].before is MISSING
    # A key outside the category registry is "unclassified" by declaration:
    assert delta.added[0].category == "unclassified"
    assert delta.changed[0].category == "structural"
    assert len(delta) == 3
    assert bool(delta)
    assert repr(MISSING) == "<missing>"


def test_delta_ignores_unchanged_keys() -> None:
    delta = compute_delta({"a": 1}, {"a": 1}, {"a": "structural"})
    assert not delta
    assert delta.entries == ()


# --- parse_envelope ------------------------------------------------------------


def test_parse_envelope_accepts_capability_shape() -> None:
    envelope = parse_envelope(_envelope_dict())
    assert [clause.fact_key for clause in envelope.require] == ["scripts_ini.machine.entries"]
    assert [clause.category for clause in envelope.allow] == ["timestamps", "file_mtime"]
    assert [clause.scope_key for clause in envelope.forbid] == ["forbid.gpc_extension_lists"]
    assert len(envelope.derive) == 2
    assert envelope.convergence == ConvergencePolicy(
        window_seconds=90.0, poll_seconds=5.0, reproduce=2
    )


def test_parse_envelope_defaults() -> None:
    envelope = parse_envelope({})
    assert envelope.require == ()
    assert envelope.allow == ()
    assert envelope.forbid == ()
    assert envelope.derive == ()
    assert envelope.convergence == ConvergencePolicy()  # documented defaults


@pytest.mark.parametrize(
    "convergence",
    [
        {"window_seconds": 0, "poll_seconds": 5, "reproduce": 2},
        {"window_seconds": 90, "poll_seconds": -5, "reproduce": 2},
        {"window_seconds": 90, "poll_seconds": 5, "reproduce": 0},
        {"window_seconds": 90, "poll_seconds": 5, "reproduce": True},
        {"window_seconds": "90", "poll_seconds": 5, "reproduce": 2},
        {"bogus": 1},
    ],
)
def test_convergence_validation(convergence: dict[str, object]) -> None:
    with pytest.raises(EnvelopeError):
        parse_envelope({"convergence": convergence})


@pytest.mark.parametrize(
    "raw",
    [
        {"unexpected": []},
        {"require": "nope"},
        {"require": [{"fact": "a"}]},  # missing predicate
        {"require": [{"predicate": "x"}]},  # missing fact
        {"require": [{"fact": "a", "predicate": 5}]},  # non-string predicate
        {"require": [{"fact": "", "predicate": "x"}]},
        {"require": [{"fact": "a", "predicate": "x", "extra": 1}]},
        {"allow": [{"category": ""}]},
        {"allow": [{"name": "timestamps"}]},
        {"forbid": [{"scope": "s"}]},
        {"forbid": [{"predicate": "x"}]},
        {"derive": [{"relation": None}]},
        {"derive": [{"relation": "1", "extra": 2}]},
    ],
)
def test_envelope_structural_validation(raw: dict[str, object]) -> None:
    with pytest.raises(EnvelopeError):
        parse_envelope(raw)


# --- Assertion semantics (contract section 3, implemented exactly) -------------


def test_satisfied_envelope_with_every_clause_kind() -> None:
    result = assert_envelope(parse_envelope(_envelope_dict()), PRE, POST_OK, CATEGORIES)
    assert result.status == "satisfied"
    assert result.violated == ()
    assert result.unclassified == ()
    assert len(result.satisfied) == 4  # 1 require + 2 derive + 1 forbid
    assert len(result.delta) == 4  # version.machine, ad.when_changed, mtime, entries


def test_unclassified_change_catches_a_canonicalizer_dropping_a_field() -> None:
    """Contract section 3: any change not covered by require/allow/derive is a
    violation. A canonicalizer that erases ``gpc.display_name`` produces a
    removed entry whose structural category nobody allows -- the envelope is
    disproven and the characterization names the field."""
    post = {key: value for key, value in POST_OK.items() if key != "gpc.display_name"}
    result = assert_envelope(parse_envelope(_envelope_dict()), PRE, post, CATEGORIES)
    assert result.status == "disproven"
    assert result.unclassified == ("gpc.display_name",)
    assert "gpc.display_name" in result.characterization
    assert "removed" in result.characterization
    assert "structural" in result.characterization


def test_require_referencing_the_dropped_field_is_violated() -> None:
    """The other way a dropped field surfaces: a clause names it, the
    reference does not resolve, the clause does not hold."""
    raw = _envelope_dict()
    raw["require"] = [
        {"fact": "gpc.display_name", "predicate": 'facts["gpc.display_name"] != ""'}
    ]
    post = {key: value for key, value in POST_OK.items() if key != "gpc.display_name"}
    result = assert_envelope(parse_envelope(raw), PRE, post, CATEGORIES)
    assert result.status == "disproven"
    assert any("require[0]" in line and "absent" in line for line in result.violated)


def test_violated_require_and_derive_are_characterized() -> None:
    raw = _envelope_dict()
    raw["derive"] = [{"relation": "post.version.machine > pre.version.machine + 100"}]
    result = assert_envelope(parse_envelope(raw), PRE, POST_OK, CATEGORIES)
    assert result.status == "disproven"
    assert len(result.violated) == 1
    assert "derive[0]" in result.violated[0]
    assert "derive[0]" in result.characterization
    assert result.satisfied  # the rest still held -- disproven shows what did


def test_forbid_violated_when_the_blast_radius_check_fails() -> None:
    post = dict(POST_OK)
    post["forbid.gpc_extension_lists"] = ["{A3CC7818-8A30-4e0c-91C5-A4EA4B5A8DAB}"]
    result = assert_envelope(parse_envelope(_envelope_dict()), PRE, post, CATEGORIES)
    assert result.status == "disproven"
    assert any("forbid[0]" in line for line in result.violated)


def test_forbid_with_absent_scope_fact_is_violated_not_passed() -> None:
    """An unobserved blast radius is not a passing one."""
    post = {key: value for key, value in POST_OK.items() if key != "forbid.gpc_extension_lists"}
    result = assert_envelope(parse_envelope(_envelope_dict()), PRE, post, CATEGORIES)
    assert result.status == "disproven"
    assert any("forbid[0]" in line for line in result.violated)


def test_allow_covers_only_declared_categories() -> None:
    raw = _envelope_dict()
    raw["allow"] = [{"category": "timestamps"}]  # file_mtime no longer tolerated
    result = assert_envelope(parse_envelope(raw), PRE, POST_OK, CATEGORIES)
    assert result.status == "disproven"
    assert result.unclassified == ("sysvol.scripts_ini.mtime",)


def test_require_fact_key_predicts_its_dotted_prefix() -> None:
    """A change *under* a require clause's fact key is predicted by it."""
    raw = {
        "require": [{"fact": "scripts_ini.machine", "predicate": "True"}],
    }
    pre: dict[str, object] = {"scripts_ini.machine.entries": []}
    post: dict[str, object] = {"scripts_ini.machine.entries": ["logon.cmd"]}
    categories = {"scripts_ini.machine.entries": "structural"}
    result = assert_envelope(parse_envelope(raw), pre, post, categories)
    assert result.status == "satisfied"


def test_derive_predicts_the_post_side_keys_it_references() -> None:
    raw = {"derive": [{"relation": "post.version.machine > pre.version.machine"}]}
    pre: dict[str, object] = {"version.machine": 4}
    post: dict[str, object] = {"version.machine": 9}
    result = assert_envelope(parse_envelope(raw), pre, post, {"version.machine": "structural"})
    assert result.status == "satisfied"


def test_a_changed_forbid_scope_fact_is_itself_unclassified() -> None:
    """Forbid clauses constrain; they do not predict. A changed scope fact is
    a real observed change and must be accounted for by some other clause."""
    post = dict(POST_OK)
    post["forbid.gpc_extension_lists"] = ["{3125E937-EB16-4b4c-9934-544FC6D24D26}"]
    raw = _envelope_dict()
    raw["forbid"] = [{"scope": "forbid.gpc_extension_lists", "predicate": "scope == []"}]
    # The forbid predicate fails AND the change is unclassified.
    result = assert_envelope(parse_envelope(raw), PRE, post, CATEGORIES)
    assert result.status == "disproven"
    assert "forbid.gpc_extension_lists" in result.unclassified


def test_categories_are_just_names_so_unclassified_can_be_allowed() -> None:
    post = dict(POST_OK)
    post["some.observer.said"] = "volatile"
    categories = dict(CATEGORIES, **{"some.observer.said": "unclassified"})
    raw = _envelope_dict()
    raw["allow"] = [
        {"category": "timestamps"},
        {"category": "file_mtime"},
        {"category": "unclassified"},
    ]
    result = assert_envelope(parse_envelope(raw), PRE, post, categories)
    assert result.status == "satisfied"


def test_assert_envelope_never_raises_and_reports_indeterminate_only_via_convergence() -> None:
    """assert_envelope is total: satisfied or disproven, never an exception,
    even for a wildly wrong post state."""
    result = assert_envelope(parse_envelope(_envelope_dict()), {}, {}, {})
    assert result.status == "disproven"
    assert len(result.violated) == 4


# --- Convergence ---------------------------------------------------------------


def test_convergence_satisfied_with_static_state() -> None:
    clock = FakeClock()
    result = converge(
        parse_envelope(_envelope_dict()),
        PRE,
        CATEGORIES,
        lambda: dict(POST_OK),
        clock=clock,
        sleep=clock.sleep,
    )
    assert result.status == "satisfied"
    assert result.reason is None
    assert result.polls == 2  # two consecutive equal polls -> stable
    assert result.reproduce_observed == 2
    assert result.frozen is not None
    assert result.frozen == {
        "scripts_ini.machine.entries": ["logon.cmd|-StartupParam"],
        "version.machine": 5,
        "version.user": 0,
    }
    assert clock.sleeps == [5.0]  # one poll interval; tests never actually wait


def test_convergence_requires_two_consecutive_equal_polls() -> None:
    values = iter([5, 6, 6, 6, 6, 6, 6, 6])
    clock = FakeClock()

    def observe() -> dict[str, object]:
        return {**POST_OK, "version.machine": next(values)}

    result = converge(
        parse_envelope(_envelope_dict()), PRE, CATEGORIES, observe, clock=clock, sleep=clock.sleep
    )
    assert result.status == "satisfied"
    assert result.polls == 3


def test_convergence_timeout_is_indeterminate_never_a_failure() -> None:
    """Contract section 3: timeout is not failure, it is indeterminate."""
    counter = [0]
    clock = FakeClock()

    def observe() -> dict[str, object]:
        counter[0] += 1
        return {**POST_OK, "version.machine": 4 + counter[0]}

    result = converge(
        parse_envelope(_envelope_dict()), PRE, CATEGORIES, observe, clock=clock, sleep=clock.sleep
    )
    assert result.status == "indeterminate"
    assert result.frozen is None
    assert result.reason is not None and "expired" in result.reason
    assert result.assertion.status == "indeterminate"
    # Window 90s, poll 5s: polls at t=0..90 inclusive; a poll starting exactly
    # at the deadline is allowed, the next one is not.
    assert result.polls == 19
    assert result.elapsed_seconds == 90.0
    assert result.reproduce_observed == 0


def test_reproduce_mismatch_is_indeterminate() -> None:
    """Contract section 2/3: envelope satisfied but the fresh observation does
    not reproduce the frozen state -> indeterminate, never verified."""
    calls = [0]
    clock = FakeClock()

    def observe() -> dict[str, object]:
        calls[0] += 1
        version = 5 if calls[0] <= 2 else 5 + calls[0]  # stable, then churns
        return {**POST_OK, "version.machine": version}

    result = converge(
        parse_envelope(_envelope_dict()), PRE, CATEGORIES, observe, clock=clock, sleep=clock.sleep
    )
    assert result.status == "indeterminate"
    assert result.reason is not None and "reproduce observation 1" in result.reason
    assert result.reproduce_observed == 1
    assert result.frozen is not None and result.frozen["version.machine"] == 5


def test_stable_but_violated_state_is_disproven() -> None:
    raw = _envelope_dict()
    raw["derive"] = [{"relation": "post.version.machine > pre.version.machine + 100"}]
    result = converge(
        parse_envelope(raw),
        PRE,
        CATEGORIES,
        lambda: dict(POST_OK),
        clock=FakeClock(),
        sleep=lambda _seconds: None,
    )
    assert result.status == "disproven"
    assert result.reason == "frozen state failed the envelope assertion"
    assert result.assertion.status == "disproven"
    assert result.reproduce_observed == 0


def test_poll_bound_degrades_a_stuck_clock_to_indeterminate() -> None:
    """A sleep that never advances the clock must hang nothing: the poll bound
    degrades to indeterminate with a naming reason."""
    counter = [0]

    def observe() -> dict[str, object]:
        counter[0] += 1
        return {**POST_OK, "version.machine": 4 + counter[0]}

    result = converge(
        parse_envelope(_envelope_dict()),
        PRE,
        CATEGORIES,
        observe,
        clock=lambda: 0.0,
        sleep=lambda _seconds: None,
    )
    assert result.status == "indeterminate"
    assert result.polls == 10000
    assert result.reason is not None and "clock" in result.reason


def test_convergence_with_empty_envelope_stabilizes_immediately() -> None:
    result = converge(
        parse_envelope({}),
        dict(POST_OK),  # no delta, so the (empty) envelope is satisfied
        CATEGORIES,
        lambda: dict(POST_OK),
        clock=FakeClock(),
        sleep=lambda _s: None,
    )
    assert result.status == "satisfied"
    assert result.frozen == {}


def test_convergence_accepts_a_callable_object_as_observer() -> None:
    """The observation callable may be any callable returning a fact dict
    (e.g. a bound method of the fake backend)."""
    observations: list[dict[str, object]] = [dict(POST_OK), dict(POST_OK)]

    class Observer:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self) -> dict[str, object]:
            self.calls += 1
            return observations[min(self.calls, len(observations)) - 1]

    result = converge(
        parse_envelope(_envelope_dict()),
        PRE,
        CATEGORIES,
        Observer(),
        clock=FakeClock(),
        sleep=lambda _s: None,
    )
    assert result.status == "satisfied"


def test_convergence_polls_are_typed_as_callables() -> None:
    """Type-sanity pin: converge's clock/sleep params are plain callables."""
    clock: Callable[[], float] = FakeClock()
    sleeper: Callable[[float], None] = FakeClock().sleep
    result = converge(
        parse_envelope({}),
        {},  # no delta, so the (empty) envelope is satisfied
        {},
        lambda: {},
        clock=clock,
        sleep=sleeper,
    )
    assert result.status == "satisfied"
