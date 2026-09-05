"""The transition-envelope engine: constrained transition, never ``post - pre == delta``.

The oracle for a verified transaction is a *constrained transition with
convergence semantics* (docs/contract.md section 3), never an exact-delta
comparison. An :class:`Envelope` declares four clause kinds plus a convergence
policy, and this module asserts observations against it:

- **require** -- a predicate over the post-transaction facts that must hold.
- **allow** -- a *named category* of tolerated change (timestamps, replication
  metadata). Categories are declared per fact key by the observers, not guessed
  from volatility.
- **forbid** -- a named, enumerable blast-radius check backed by a pre-computed
  fact (e.g. ``forbid.gpc_extension_lists``); its predicate must hold on the
  post state.
- **derive** -- a relation over pre+post facts rather than literal expected
  values (``post.version.machine > pre.version.machine``).

The rule that does the real work: **any observed change whose declared category
is not covered by an allow clause and not predicted by a require or derive
clause is a violation** ("unclassified change"). That is what catches a
canonicalizer silently erasing something meaningful: the erased key shows up in
the delta as removed, no clause predicted it, and the assertion is disproven.

PREDICATES: A BOUNDED EXPRESSION EVALUATOR, NO eval/exec
    Predicate and relation strings are parsed with :mod:`ast` and evaluated
    against an explicit bindings mapping. Nothing is ever passed to ``eval``
    or ``exec``, no Python attribute machinery is touched
    (``post.version.machine`` is a *string key* lookup, not a ``getattr``),
    and anything outside the subset is rejected at parse time with
    :class:`PredicateSyntaxError`. The subset:

    - boolean operators ``and`` / ``or`` (short-circuit, result is a bool);
    - comparisons ``== != < <= > >= in not in is is not``, including chained
      comparisons;
    - arithmetic ``+ - * // %`` over numbers (``+`` exists because the
      contract's own derive example is ``pre.version.machine + 1``; true
      division and ``**`` are excluded to keep the evaluator tiny);
    - unary ``not`` and numeric ``-`` / ``+``;
    - literals: ``str``, ``int``, ``float``, ``bool``, ``None``, and
      list/tuple literals of those;
    - references: a dotted name chain (``post.version.machine``) or a
      subscript with a literal string key (``facts["version.machine"]``),
      resolved as a single key against the bindings mapping -- never against
      Python objects;
    - calls, lambdas, comprehensions, f-strings, attribute access on anything
      that is not a dotted reference, subscripts with non-literal or non-str
      keys, and every other AST node are syntax errors.

    Bounds (constants below): source length, AST node count, literal-list
    length, and nesting depth are all capped, so parsing and evaluation
    terminate by construction -- the subset has no loops and no recursion.

UNRESOLVED IS NOT VIOLATED (a disproof must be grounded in observed state)
    A reference that does not resolve (the fact is absent) raises
    :class:`PredicateResolutionError` from :func:`evaluate`; any other type
    error raises :class:`PredicateEvaluationError`. Inside
    :func:`assert_envelope` neither becomes a violated clause: a clause that
    could not be evaluated has no observed state to ground a verdict on, so it
    is classified **unresolved** -- a third clause outcome beside
    satisfied/violated, carried in :attr:`AssertionResult.unresolved` -- and
    the aggregate result is capped at **indeterminate**, never disproven. Only
    a predicate that *evaluated false* over the observed state is a violation.
    (A canonicalizer silently dropping a field is still caught, by the
    unclassified-change rule over the delta -- a grounded observation -- not
    by reclassifying an evaluation error as a clause failure.)

    Containment is None-safe: an attribute that is present but ``None`` (e.g.
    an AD string attribute that legitimately does not exist on the object)
    contains nothing, so ``'X' not in attr`` over a ``None`` attribute is
    trivially *satisfied* -- absent means certainly not-in -- and ``'X' in
    attr`` is False. A membership test over any other non-iterable operand
    remains a type error (hence unresolved), not a verdict.

FACTS AND CATEGORIES
    Facts are flat dicts mapping dotted keys (``"version.machine"``) to
    values. Each key carries a *declared category* supplied by the observer
    registry (``"structural"``, ``"timestamps"``, ``"replication_metadata"``,
    ``"file_mtime"``, ...). A key absent from the registry is category
    ``"unclassified"``. :func:`compute_delta` produces changed/added/removed
    entries with before/after values and declared categories;
    :data:`MISSING` marks the absent side of an added/removed entry.

CONVERGENCE
    Post-state may be asynchronous (AD/SYSVOL propagation). :func:`converge`
    polls an observation callable until the post-side state referenced by
    require+derive clauses is *stable across one poll* (two consecutive
    identical normalized observations -- value equality, not merely clause
    booleans, which can stay satisfied while a counter churns), freezes that
    state, runs the full envelope assertion on it, and then takes
    ``reproduce`` further fresh observations that must reproduce the frozen
    normalized state. Timeout and non-reproduction are **indeterminate**
    results, never failures. Clock and sleep are injectable so tests never
    wait; a poll starting exactly at the window deadline is allowed, the next
    one is not.

BINDINGS (exact rules, so envelopes are writable without reading the code)
    Every clause is evaluated against a bindings mapping built by this module:

    - ``"pre"`` and ``"post"`` -> the pre/post fact dicts themselves (so
      ``pre["version.machine"]`` works);
    - ``"facts"`` -> the post fact dict (alias for ``post``);
    - ``"pre.<key>"`` for every pre fact and ``"post.<key>"`` for every post
      fact (so ``post.version.machine`` works);
    - forbid clauses additionally bind ``"scope"`` -> the value of the scope
      fact and ``"scope_key"`` -> the scope key string.

    Prediction for the unclassified-change rule: a changed key is predicted if
    it equals -- or is a dotted key *under* -- a require clause's fact key, or
    a post-side key referenced by a require predicate or derive relation.
    Forbid clauses constrain; they do not predict, so a changed forbid-scope
    fact is itself an unclassified change unless another clause covers it.
"""

from __future__ import annotations

import ast
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Literal

AssertionStatus = Literal["satisfied", "disproven", "indeterminate"]
# Per-clause outcome: a clause is satisfied or violated over the observed
# state, or unresolved when it could not be evaluated at all (never a
# violation -- see the aggregation rule in :func:`assert_envelope`).
ClauseOutcome = Literal["satisfied", "violated", "unresolved"]

# --- Evaluator bounds ---------------------------------------------------------

MAX_PREDICATE_LENGTH: Final[int] = 1024
MAX_AST_NODES: Final[int] = 128
MAX_LIST_ITEMS: Final[int] = 32
MAX_DEPTH: Final[int] = 16
# Safety bound for the poll loop: with a correctly injected clock the window
# expires long before this; the bound exists so a sleep that never advances
# the clock degrades to indeterminate instead of hanging the run.
MAX_CONVERGE_POLLS: Final[int] = 10000

# --- Sentinel for "no value on this side of the delta" ------------------------


class Missing:
    """Type of :data:`MISSING`; deliberately not constructible elsewhere."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "<missing>"


MISSING: Final[Missing] = Missing()

# --- Errors -------------------------------------------------------------------


class EnvelopeError(Exception):
    """Base class for envelope definition and evaluation errors."""


class PredicateSyntaxError(EnvelopeError):
    """A predicate string is not inside the bounded expression subset."""


class PredicateEvaluationError(EnvelopeError):
    """A predicate failed to evaluate (type mismatch, bad operand, ...)."""


class PredicateResolutionError(PredicateEvaluationError):
    """A reference in a predicate does not resolve against the bindings."""


# --- Bounded expression evaluator ---------------------------------------------

_ALLOWED_COMPARE_OPS: Final[tuple[type[ast.cmpop], ...]] = (
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.In,
    ast.NotIn,
    ast.Is,
    ast.IsNot,
)
_ALLOWED_BIN_OPS: Final[tuple[type[ast.operator], ...]] = (
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.FloorDiv,
    ast.Mod,
)


@dataclass(frozen=True)
class Predicate:
    """A compiled predicate: the source text plus its validated AST.

    Construct only through :func:`compile_predicate`; the constructor does not
    validate. :attr:`expression` is the validated :class:`ast.Expression`.
    """

    source: str
    expression: ast.Expression

    def referenced_paths(self) -> tuple[str, ...]:
        """Every dotted reference the predicate makes, in source order.

        Subscript keys are joined into the path (``facts["a.b"]`` yields
        ``"facts.a.b"``). Used to decide which fact keys a clause *predicts*.
        """
        return _referenced_paths(self.expression.body)


def compile_predicate(source: str) -> Predicate:
    """Compile ``source`` under the bounded subset; raise on anything else."""
    if not isinstance(source, str):
        raise PredicateSyntaxError(
            f"predicate must be a string, got {type(source).__name__}"
        )
    if not source.strip():
        raise PredicateSyntaxError("predicate must not be empty")
    if len(source) > MAX_PREDICATE_LENGTH:
        raise PredicateSyntaxError(
            f"predicate exceeds the {MAX_PREDICATE_LENGTH}-character bound"
        )
    try:
        parsed = ast.parse(source, mode="eval")
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise PredicateSyntaxError(f"predicate does not parse: {exc}") from exc
    nodes = _validate(parsed.body, depth=0)
    if nodes > MAX_AST_NODES:
        raise PredicateSyntaxError(
            f"predicate exceeds the {MAX_AST_NODES}-node bound ({nodes} nodes)"
        )
    return Predicate(source=source, expression=parsed)


def _validate(node: ast.expr, depth: int) -> int:
    """Check ``node`` against the subset; return the number of AST nodes."""
    if depth > MAX_DEPTH:
        raise PredicateSyntaxError(f"predicate exceeds the nesting bound ({MAX_DEPTH})")
    if isinstance(node, ast.Constant):
        if node.value is None or isinstance(node.value, (str, int, float, bool)):
            return 1
        raise PredicateSyntaxError(
            f"constant type {type(node.value).__name__} is not in the subset"
        )
    if isinstance(node, ast.Name):
        if not isinstance(node.ctx, ast.Load):
            raise PredicateSyntaxError("names may only be read")
        return 1
    if isinstance(node, ast.Attribute):
        if not isinstance(node.value, (ast.Name, ast.Attribute)):
            raise PredicateSyntaxError(
                "attribute access is only allowed as a dotted reference chain "
                "rooted at a name"
            )
        return 1 + _validate(node.value, depth + 1)
    if isinstance(node, ast.Subscript):
        if not isinstance(node.value, (ast.Name, ast.Attribute, ast.Subscript)):
            raise PredicateSyntaxError(
                "subscripts are only allowed on a dotted reference or another string-keyed "
                "subscript (literal string key lookups, e.g. facts[\"version.machine\"])"
            )
        if not (isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str)):
            raise PredicateSyntaxError(
                "subscript keys must be literal strings; other indexing is "
                "outside the subset"
            )
        if not isinstance(node.ctx, ast.Load):
            raise PredicateSyntaxError("subscripts may only be read")
        return 2 + _validate(node.value, depth + 1)
    if isinstance(node, ast.BoolOp):
        if not isinstance(node.op, (ast.And, ast.Or)):  # pragma: no cover - exhaustive
            raise PredicateSyntaxError("unsupported boolean operator")
        return 1 + sum(_validate(v, depth + 1) for v in node.values)
    if isinstance(node, ast.UnaryOp):
        if isinstance(node.op, ast.Not):
            return 1 + _validate(node.operand, depth + 1)
        if isinstance(node.op, (ast.USub, ast.UAdd)):
            return 1 + _validate(node.operand, depth + 1)
        raise PredicateSyntaxError(
            f"unary operator {type(node.op).__name__} is not in the subset"
        )
    if isinstance(node, ast.BinOp):
        if not isinstance(node.op, _ALLOWED_BIN_OPS):
            raise PredicateSyntaxError(
                f"binary operator {type(node.op).__name__} is not in the subset"
            )
        return 1 + _validate(node.left, depth + 1) + _validate(node.right, depth + 1)
    if isinstance(node, ast.Compare):
        for op in node.ops:
            if not isinstance(op, _ALLOWED_COMPARE_OPS):
                raise PredicateSyntaxError(
                    f"comparison {type(op).__name__} is not in the subset"
                )
        return 1 + _validate(node.left, depth + 1) + sum(
            _validate(c, depth + 1) for c in node.comparators
        )
    if isinstance(node, (ast.List, ast.Tuple)):
        if len(node.elts) > MAX_LIST_ITEMS:
            raise PredicateSyntaxError(
                f"list/tuple literals are capped at {MAX_LIST_ITEMS} items"
            )
        return 1 + sum(_validate(e, depth + 1) for e in node.elts)
    raise PredicateSyntaxError(
        f"node {type(node).__name__} is not in the predicate subset"
    )


def _dotted(node: ast.expr) -> str:
    """Join a Name/Attribute chain into its dotted key (raises if not one)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    raise PredicateResolutionError("not a dotted reference")


def _referenced_paths(node: ast.expr) -> tuple[str, ...]:
    if isinstance(node, ast.Attribute):
        return (_dotted(node),)
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, ast.Subscript):
        if isinstance(node.value, (ast.Name, ast.Attribute)):
            base = _dotted(node.value)
            assert isinstance(node.slice, ast.Constant)
            key = node.slice.value
            assert isinstance(key, str)
            return (f"{base}.{key}",)
        # A chained subscript (facts["outer"]["inner"]): the reference that
        # matters for prediction is the fact key itself, i.e. the base's path.
        return _referenced_paths(node.value)
    if isinstance(node, ast.Constant):
        return ()
    if isinstance(node, ast.UnaryOp):
        return _referenced_paths(node.operand)
    if isinstance(node, ast.BinOp):
        return _referenced_paths(node.left) + _referenced_paths(node.right)
    if isinstance(node, ast.Compare):
        return _referenced_paths(node.left) + tuple(
            p for c in node.comparators for p in _referenced_paths(c)
        )
    if isinstance(node, ast.BoolOp):
        return tuple(p for v in node.values for p in _referenced_paths(v))
    if isinstance(node, (ast.List, ast.Tuple)):
        return tuple(p for e in node.elts for p in _referenced_paths(e))
    return ()


def evaluate(predicate: Predicate, bindings: Mapping[str, object]) -> object:
    """Evaluate ``predicate`` against ``bindings`` and return the raw value.

    Raises :class:`PredicateResolutionError` when a reference does not resolve
    (a fact is absent) and :class:`PredicateEvaluationError` on type errors.
    Containment is None-safe: a ``None`` right operand (an attribute that is
    present but absent-valued) contains nothing, so ``x in None`` is False and
    ``x not in None`` is True. Any other non-iterable operand is a type error.
    Callers truth-test the result; clause evaluation inside this module does.
    """
    try:
        return _eval(predicate.expression.body, bindings)
    except PredicateEvaluationError:
        raise
    except (TypeError, ZeroDivisionError, ValueError, IndexError) as exc:
        raise PredicateEvaluationError(
            f"predicate {predicate.source!r} failed to evaluate: {exc}"
        ) from exc


def _contains(left: object, right: object) -> bool:
    """None-safe membership: an absent attribute (``None``) contains nothing.

    ``left in None`` is False and ``left not in None`` is True: when the
    attribute is not there, the values it would carry are certainly not in it,
    so an absence-style (``not in``) predicate over it is *satisfied* rather
    than an evaluation error. Any other non-iterable right operand stays a
    TypeError (wrapped into :class:`PredicateEvaluationError` by
    :func:`evaluate`) -- a genuine type mistake, not an absent attribute.
    """
    if right is None:
        return False
    return left in right  # type: ignore[operator]


def _eval(node: ast.expr, bindings: Mapping[str, object]) -> object:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            return all(bool(_eval(value, bindings)) for value in node.values)
        return any(bool(_eval(value, bindings)) for value in node.values)
    if isinstance(node, ast.UnaryOp):
        if isinstance(node.op, ast.Not):
            return not _eval(node.operand, bindings)
        operand = _eval(node.operand, bindings)
        if isinstance(node.op, ast.USub):
            return -operand  # type: ignore[operator]  # validated numeric use
        return +operand  # type: ignore[operator]
    if isinstance(node, ast.BinOp):
        left = _eval(node.left, bindings)
        right = _eval(node.right, bindings)
        if isinstance(node.op, ast.Add):
            return left + right  # type: ignore[operator]
        if isinstance(node.op, ast.Sub):
            return left - right  # type: ignore[operator]
        if isinstance(node.op, ast.Mult):
            return left * right  # type: ignore[operator]
        if isinstance(node.op, ast.FloorDiv):
            return left // right  # type: ignore[operator]
        return left % right  # type: ignore[operator]
    if isinstance(node, ast.Compare):
        left = _eval(node.left, bindings)
        for op, comparator in zip(node.ops, node.comparators, strict=True):
            right = _eval(comparator, bindings)
            if isinstance(op, ast.Eq):
                ok = left == right
            elif isinstance(op, ast.NotEq):
                ok = left != right
            elif isinstance(op, ast.Lt):
                ok = left < right  # type: ignore[operator]
            elif isinstance(op, ast.LtE):
                ok = left <= right  # type: ignore[operator]
            elif isinstance(op, ast.Gt):
                ok = left > right  # type: ignore[operator]
            elif isinstance(op, ast.GtE):
                ok = left >= right  # type: ignore[operator]
            elif isinstance(op, ast.In):
                ok = _contains(left, right)
            elif isinstance(op, ast.NotIn):
                ok = not _contains(left, right)
            elif isinstance(op, ast.Is):
                ok = left is right
            else:
                ok = left is not right
            if not ok:
                return False
            left = right
        return True
    if isinstance(node, ast.List):
        return [_eval(e, bindings) for e in node.elts]
    if isinstance(node, ast.Tuple):
        return tuple(_eval(e, bindings) for e in node.elts)
    if isinstance(node, ast.Name):
        return _lookup(node.id, bindings)
    if isinstance(node, ast.Attribute):
        return _lookup(_dotted(node), bindings)
    if isinstance(node, ast.Subscript):
        base = _eval(node.value, bindings)
        assert isinstance(node.slice, ast.Constant)
        key = node.slice.value
        if not isinstance(base, Mapping):
            raise PredicateEvaluationError(
                f"subscript base {node_value_description(node.value)!r} is not a mapping"
            )
        try:
            return base[key]
        except KeyError:
            raise PredicateResolutionError(
                f"key {key!r} is absent from {node_value_description(node.value)!r}"
            ) from None
    raise PredicateEvaluationError(  # pragma: no cover - validator excludes these
        f"node {type(node).__name__} is not evaluable"
    )


def node_value_description(node: ast.expr) -> str:
    """Human-readable rendering of a reference node for error messages."""
    if isinstance(node, (ast.Name, ast.Attribute)):
        return _dotted(node)
    if isinstance(node, ast.Subscript):
        assert isinstance(node.slice, ast.Constant)
        return f"{node_value_description(node.value)}[{node.slice.value!r}]"
    return type(node).__name__


def _lookup(key: str, bindings: Mapping[str, object]) -> object:
    try:
        return bindings[key]
    except KeyError:
        raise PredicateResolutionError(f"unresolved reference {key!r}") from None


# --- Envelope model -----------------------------------------------------------


@dataclass(frozen=True)
class RequireClause:
    """A post-transaction predicate that must hold.

    ``fact_key`` names the fact the clause is about: it documents intent, and
    it *predicts* that key (and any dotted key under it) for the
    unclassified-change rule.
    """

    fact_key: str
    predicate: Predicate


@dataclass(frozen=True)
class AllowClause:
    """A named category of tolerated change."""

    category: str


@dataclass(frozen=True)
class ForbidClause:
    """A named blast-radius check whose predicate must hold on the post state.

    ``scope_key`` names the pre-computed fact carrying the check result (e.g.
    ``"forbid.gpc_extension_lists"`` -- typically a bool or a list of what the
    check found). A forbid clause without a named scope check is a defect in
    the capability spec, so the key is mandatory.
    """

    scope_key: str
    predicate: Predicate


@dataclass(frozen=True)
class DeriveClause:
    """A relation over pre+post facts rather than a literal expected value."""

    relation: Predicate


@dataclass(frozen=True)
class ConvergencePolicy:
    """Convergence window, poll interval, and number of reproduce observations.

    Defaults mirror the shipped capability (90 s window, 5 s poll, 2
    reproductions) so a partial envelope dict still parses; qualified
    capabilities declare their own.
    """

    window_seconds: float = 90.0
    poll_seconds: float = 5.0
    reproduce: int = 2


@dataclass(frozen=True)
class Envelope:
    """The constrained transition an observed transaction must fit."""

    require: tuple[RequireClause, ...] = ()
    allow: tuple[AllowClause, ...] = ()
    forbid: tuple[ForbidClause, ...] = ()
    derive: tuple[DeriveClause, ...] = ()
    convergence: ConvergencePolicy = ConvergencePolicy()


def parse_envelope(raw: Mapping[str, object]) -> Envelope:
    """Parse an envelope from a capability-shaped mapping (JSON-decoded).

    Unknown top-level keys are rejected: the envelope schema is closed, because
    an envelope that silently ignores a misspelled section asserts nothing.
    Predicates and relations are compiled with the bounded evaluator; prose
    predicates (the shipped capability file is narrative and unqualified) fail
    with :class:`PredicateSyntaxError` naming the offending text.
    """
    unknown = set(raw) - {"require", "allow", "forbid", "derive", "convergence"}
    if unknown:
        raise EnvelopeError(f"unknown envelope keys: {sorted(unknown)!r}")
    require = tuple(
        _parse_require(entry, index)
        for index, entry in enumerate(_sequence(raw.get("require")))
    )
    allow = tuple(
        _parse_allow(entry, index) for index, entry in enumerate(_sequence(raw.get("allow")))
    )
    forbid = tuple(
        _parse_forbid(entry, index) for index, entry in enumerate(_sequence(raw.get("forbid")))
    )
    derive = tuple(
        _parse_derive(entry, index) for index, entry in enumerate(_sequence(raw.get("derive")))
    )
    convergence_raw = raw.get("convergence")
    convergence = _parse_convergence(convergence_raw)
    envelope = Envelope(
        require=require, allow=allow, forbid=forbid, derive=derive, convergence=convergence
    )
    if not _normalized_keys(envelope):
        raise EnvelopeError(
            "envelope observes no post-state facts; require, forbid, or derive must "
            "reference at least one post-state fact"
        )
    return envelope


def _sequence(value: object) -> Sequence[object]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise EnvelopeError(f"expected a list of clauses, got {type(value).__name__}")
    return value


def _parse_require(entry: object, index: int) -> RequireClause:
    fact_key, predicate_text = _pair(entry, "require", index, "fact", "predicate")
    if not isinstance(fact_key, str) or not fact_key.strip() or fact_key.strip() != fact_key:
        raise EnvelopeError(f"require[{index}]: 'fact' must be a non-blank string")
    return RequireClause(
        fact_key=fact_key, predicate=compile_predicate(_text(predicate_text, "require", index))
    )


def _parse_allow(entry: object, index: int) -> AllowClause:
    if not isinstance(entry, Mapping):
        raise EnvelopeError(f"allow[{index}] must be an object with 'category'")
    category = entry.get("category")
    if not isinstance(category, str) or not category.strip():
        raise EnvelopeError(f"allow[{index}]: 'category' must be a non-blank string")
    unknown = set(entry) - {"category"}
    if unknown:
        raise EnvelopeError(f"allow[{index}]: unknown keys {sorted(unknown)!r}")
    return AllowClause(category=category)


def _parse_forbid(entry: object, index: int) -> ForbidClause:
    scope_key, predicate_text = _pair(entry, "forbid", index, "scope", "predicate")
    if not isinstance(scope_key, str) or not scope_key.strip():
        raise EnvelopeError(f"forbid[{index}]: 'scope' must be a non-blank string")
    return ForbidClause(
        scope_key=scope_key, predicate=compile_predicate(_text(predicate_text, "forbid", index))
    )


def _parse_derive(entry: object, index: int) -> DeriveClause:
    if not isinstance(entry, Mapping):
        raise EnvelopeError(f"derive[{index}] must be an object with 'relation'")
    unknown = set(entry) - {"relation"}
    if unknown:
        raise EnvelopeError(f"derive[{index}]: unknown keys {sorted(unknown)!r}")
    return DeriveClause(
        relation=compile_predicate(_text(entry.get("relation"), "derive", index))
    )


def _pair(
    entry: object, kind: str, index: int, first: str, second: str
) -> tuple[object, object]:
    if not isinstance(entry, Mapping):
        raise EnvelopeError(f"{kind}[{index}] must be an object with {first!r} and {second!r}")
    unknown = set(entry) - {first, second}
    if unknown:
        raise EnvelopeError(f"{kind}[{index}]: unknown keys {sorted(unknown)!r}")
    if first not in entry or second not in entry:
        raise EnvelopeError(f"{kind}[{index}] is missing {first!r} or {second!r}")
    return entry[first], entry[second]


def _text(value: object, kind: str, index: int) -> str:
    if not isinstance(value, str):
        raise EnvelopeError(f"{kind}[{index}] predicate must be a string")
    return value


def _parse_convergence(raw: object) -> ConvergencePolicy:
    if raw is None:
        return ConvergencePolicy()
    if not isinstance(raw, Mapping):
        raise EnvelopeError("convergence must be an object")
    unknown = set(raw) - {"window_seconds", "poll_seconds", "reproduce"}
    if unknown:
        raise EnvelopeError(f"convergence: unknown keys {sorted(unknown)!r}")
    window = raw.get("window_seconds", 90.0)
    poll = raw.get("poll_seconds", 5.0)
    reproduce = raw.get("reproduce", 2)
    if not isinstance(window, (int, float)) or isinstance(window, bool) or window <= 0:
        raise EnvelopeError("convergence.window_seconds must be a positive number")
    if not isinstance(poll, (int, float)) or isinstance(poll, bool) or poll <= 0:
        raise EnvelopeError("convergence.poll_seconds must be a positive number")
    if not isinstance(reproduce, int) or isinstance(reproduce, bool) or reproduce < 1:
        raise EnvelopeError("convergence.reproduce must be an integer >= 1")
    return ConvergencePolicy(
        window_seconds=float(window), poll_seconds=float(poll), reproduce=reproduce
    )


# --- Delta --------------------------------------------------------------------


@dataclass(frozen=True)
class DeltaEntry:
    """One observed change, with its declared category.

    ``before``/``after`` are :data:`MISSING` on the absent side of an
    added/removed entry -- deliberately a sentinel rather than ``None``, so a
    fact whose *value* is ``None`` is distinguishable from an absent fact.
    """

    key: str
    kind: Literal["changed", "added", "removed"]
    before: object
    after: object
    category: str


@dataclass(frozen=True)
class FactDelta:
    """The pre/post difference, keyed and categorized."""

    changed: tuple[DeltaEntry, ...] = ()
    added: tuple[DeltaEntry, ...] = ()
    removed: tuple[DeltaEntry, ...] = ()

    @property
    def entries(self) -> tuple[DeltaEntry, ...]:
        return self.changed + self.added + self.removed

    def __bool__(self) -> bool:
        return bool(self.entries)

    def __len__(self) -> int:
        return len(self.entries)


def compute_delta(
    pre: Mapping[str, object],
    post: Mapping[str, object],
    categories: Mapping[str, str],
) -> FactDelta:
    """Compute the pre/post delta with declared categories.

    A key absent from ``categories`` is categorized ``"unclassified"``, which
    (by the assertion rules) makes any change to it a violation unless a
    require/derive clause predicted it.
    """
    changed: list[DeltaEntry] = []
    added: list[DeltaEntry] = []
    removed: list[DeltaEntry] = []
    for key in sorted(set(pre) | set(post)):
        category = categories.get(key, "unclassified")
        in_pre = key in pre
        in_post = key in post
        if in_pre and in_post:
            if pre[key] != post[key]:
                changed.append(
                    DeltaEntry(
                        key=key,
                        kind="changed",
                        before=pre[key],
                        after=post[key],
                        category=category,
                    )
                )
        elif in_post:
            added.append(
                DeltaEntry(
                    key=key, kind="added", before=MISSING, after=post[key], category=category
                )
            )
        else:
            removed.append(
                DeltaEntry(
                    key=key, kind="removed", before=pre[key], after=MISSING, category=category
                )
            )
    return FactDelta(changed=tuple(changed), added=tuple(added), removed=tuple(removed))


# --- Assertion ----------------------------------------------------------------


@dataclass(frozen=True)
class AssertionResult:
    """The outcome of asserting a transition against an envelope.

    ``satisfied``/``violated``/``unresolved`` carry human-readable clause
    labels (violated and unresolved labels include the reason). A violated
    clause *evaluated false* over the observed state -- a grounded failure
    whose evidence is the observation itself. An unresolved clause could not
    be evaluated at all (unresolved reference, type error) and never counts as
    a violation. ``unclassified`` carries the delta keys whose changes no
    clause predicted and no allow category covered. ``characterization`` is
    the full delta narrative required for a disproven result -- which clauses
    failed and the offending delta entries; for an indeterminate result it
    names the unresolved clauses alongside any grounded failures.
    """

    status: AssertionStatus
    satisfied: tuple[str, ...]
    violated: tuple[str, ...]
    unresolved: tuple[str, ...]
    unclassified: tuple[str, ...]
    characterization: str
    delta: FactDelta


def assert_envelope(
    envelope: Envelope,
    pre: Mapping[str, object],
    post: Mapping[str, object],
    categories: Mapping[str, str],
) -> AssertionResult:
    """Assert pre/post observations against ``envelope`` (contract section 3).

    Semantics, implemented exactly:

    - every **require** predicate must hold over the post facts;
    - every **derive** relation must hold over the pre+post bindings;
    - every **forbid** predicate must hold, evaluated against the scope fact
      named by its scope key (a missing scope fact is a violated clause: an
      unobserved blast radius is not a passing one -- an observation-layer
      gap, deliberately kept distinct from the unresolved classification);
    - any delta entry whose declared category is not allowed and whose key was
      not predicted by a require/derive clause is an unclassified-change
      violation.

    Clause outcomes are three, not two. A predicate that *evaluated false*
    over the observed state is **violated** -- grounded, the observation is
    the evidence. A predicate that could not be evaluated at all (unresolved
    reference, or a type error that is not the absent-attribute case) is
    **unresolved** and is never counted as a violation: a disproof verdict
    must rest entirely on grounded observed-state violations.

    Aggregation rule: any unresolved clause caps the result at
    ``indeterminate`` -- ``disproven`` requires at least one violated clause
    or unclassified change *and* no unresolved clause. Absent-attribute
    predicates never reach that path anyway: containment over a ``None``
    attribute is None-safe (``not in`` over an absent attribute is satisfied).

    The function is total: it returns a result and never raises.
    """
    bindings = _build_bindings(pre, post)
    delta = compute_delta(pre, post, categories)

    satisfied: list[str] = []
    violated: list[str] = []
    unresolved: list[str] = []

    for index, require_clause in enumerate(envelope.require):
        label = f"require[{index}] fact={require_clause.fact_key!r}"
        outcome, reason = _holds(require_clause.predicate, bindings)
        _record(outcome, reason, label, satisfied, violated, unresolved)
    for index, derive_clause in enumerate(envelope.derive):
        label = f"derive[{index}]"
        outcome, reason = _holds(derive_clause.relation, bindings)
        _record(outcome, reason, label, satisfied, violated, unresolved)
    for index, forbid_clause in enumerate(envelope.forbid):
        label = f"forbid[{index}] scope={forbid_clause.scope_key!r}"
        scope_value = post.get(forbid_clause.scope_key, MISSING)
        if scope_value is MISSING:
            # The scope fact is the pre-computed blast-radius check; if the
            # observation layer never produced it, the blast radius is
            # unobserved, and an unobserved blast radius is not a passing one.
            # This is a grounded clause failure (the observation gap itself is
            # recorded), not an unresolved predicate.
            violated.append(
                f"{label}: scope fact {forbid_clause.scope_key!r} is absent "
                "from the post state"
            )
            continue
        scope_bindings = {
            **bindings,
            "scope": scope_value,
            "scope_key": forbid_clause.scope_key,
        }
        outcome, reason = _holds(forbid_clause.predicate, scope_bindings)
        _record(outcome, reason, label, satisfied, violated, unresolved)

    predicted = _predicted_keys(envelope)
    allowed_categories = {clause.category for clause in envelope.allow}
    unclassified: list[str] = []
    for entry in delta.entries:
        if entry.category in allowed_categories or _is_predicted(entry.key, predicted):
            continue
        unclassified.append(entry.key)

    if unresolved:
        # Never disproven on an evaluation gap: part of the envelope was not
        # checked against the observed state, so the verdict cannot claim a
        # fully grounded disproof.
        status: AssertionStatus = "indeterminate"
    elif violated or unclassified:
        status = "disproven"
    else:
        status = "satisfied"
    return AssertionResult(
        status=status,
        satisfied=tuple(satisfied),
        violated=tuple(violated),
        unresolved=tuple(unresolved),
        unclassified=tuple(unclassified),
        characterization=_characterize(
            status, satisfied, violated, unresolved, delta, unclassified
        ),
        delta=delta,
    )


def _record(
    outcome: ClauseOutcome,
    reason: str | None,
    label: str,
    satisfied: list[str],
    violated: list[str],
    unresolved: list[str],
) -> None:
    """Append a labelled clause outcome to the matching classification list."""
    text = label if reason is None else f"{label}: {reason}"
    if outcome == "satisfied":
        satisfied.append(text)
    elif outcome == "violated":
        violated.append(text)
    else:
        unresolved.append(text)


def _holds(
    predicate: Predicate, bindings: Mapping[str, object]
) -> tuple[ClauseOutcome, str | None]:
    """Evaluate ``predicate`` as a clause; three outcomes, never an exception.

    ``satisfied``: the predicate evaluated truthy over the observed state.
    ``violated``: it evaluated falsy -- a grounded verdict. ``unresolved``: it
    could not be evaluated (unresolved reference, type error); there is no
    observation to ground a verdict on, so this is never a violation.
    """
    try:
        value = evaluate(predicate, bindings)
    except PredicateEvaluationError as exc:
        return "unresolved", str(exc)
    if value:
        return "satisfied", None
    return "violated", f"predicate {predicate.source!r} is not true"


def _build_bindings(
    pre: Mapping[str, object],
    post: Mapping[str, object],
) -> dict[str, object]:
    bindings: dict[str, object] = {"pre": dict(pre), "post": dict(post), "facts": dict(post)}
    for key, value in pre.items():
        bindings[f"pre.{key}"] = value
    for key, value in post.items():
        bindings[f"post.{key}"] = value
    return bindings


def _predicted_keys(envelope: Envelope) -> tuple[str, ...]:
    """Post-side fact keys the envelope textually predicts changes to."""
    predicted: list[str] = []
    for require_clause in envelope.require:
        predicted.append(require_clause.fact_key)
        predicted.extend(_post_side_keys(require_clause.predicate))
    for derive_clause in envelope.derive:
        predicted.extend(_post_side_keys(derive_clause.relation))
    return tuple(predicted)


def _post_side_keys(predicate: Predicate) -> list[str]:
    keys: list[str] = []
    for path in predicate.referenced_paths():
        if path.startswith("post."):
            keys.append(path.removeprefix("post."))
        elif path.startswith("facts."):
            keys.append(path.removeprefix("facts."))
    return keys


def _is_predicted(key: str, predicted: tuple[str, ...]) -> bool:
    """A delta key is predicted by an exact or dotted-prefix ancestor key."""
    return any(key == p or key.startswith(f"{p}.") for p in predicted)


def _characterize(
    status: AssertionStatus,
    satisfied: list[str],
    violated: list[str],
    unresolved: list[str],
    delta: FactDelta,
    unclassified: list[str],
) -> str:
    lines: list[str] = []
    if status == "satisfied":
        lines.append(
            f"satisfied: {len(satisfied)} clause(s) held; "
            f"{len(delta)} delta entr{'y' if len(delta) == 1 else 'ies'} all covered"
        )
        for entry in delta.entries:
            lines.append(f"  covered {entry.kind}: {entry.key} (category {entry.category!r})")
        return "\n".join(lines)
    if unresolved:
        # assert_envelope returns indeterminate only via unresolved clauses.
        lines.append(
            f"indeterminate: {len(unresolved)} clause(s) could not be evaluated, "
            f"{len(violated)} grounded clause failure(s), "
            f"{len(unclassified)} unclassified change(s) -- a disproof must be "
            "grounded in observed state, so unresolved clauses cap the verdict"
        )
    else:
        lines.append(
            f"disproven: {len(violated)} clause(s) failed, "
            f"{len(unclassified)} unclassified change(s)"
        )
    for label in unresolved:
        lines.append(f"  UNRESOLVED {label}")
    for label in violated:
        lines.append(f"  VIOLATED {label}")
    for key in unclassified:
        entry = next(e for e in delta.entries if e.key == key)
        before = _show(entry.before)
        after = _show(entry.after)
        lines.append(
            f"  UNCLASSIFIED {entry.kind}: {key} (category {entry.category!r}) "
            f"before={before} after={after}"
        )
    for entry in delta.entries:
        if entry.key not in unclassified:
            lines.append(f"  covered {entry.kind}: {entry.key} (category {entry.category!r})")
    return "\n".join(lines)


def _show(value: object) -> str:
    return repr(value)


# --- Convergence --------------------------------------------------------------


@dataclass(frozen=True)
class ConvergenceResult:
    """The outcome of polling an envelope to convergence.

    ``status`` is ``indeterminate`` on window timeout, reproduce
    non-reproduction, or a frozen assertion left with unresolved clauses
    (never a bare failure), ``disproven`` when the frozen state failed the
    full envelope assertion, and ``satisfied`` otherwise. ``frozen`` is the
    normalized require+derive state that was frozen.
    """

    status: AssertionStatus
    reason: str | None
    assertion: AssertionResult
    polls: int
    elapsed_seconds: float
    reproduce_observed: int
    frozen: Mapping[str, object] | None


def converge(
    envelope: Envelope,
    pre: Mapping[str, object],
    categories: Mapping[str, str],
    observe: Callable[[], Mapping[str, object]],
    *,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> ConvergenceResult:
    """Poll ``observe`` until require+derive are stable, freeze, reproduce.

    See the module docstring for the exact semantics. ``clock`` and ``sleep``
    are injectable (tests pass a fake clock and a no-op or advancing sleep, so
    no test ever actually waits). Observer exceptions propagate: the observer
    layer is responsible for reporting its own failures as data.
    """
    window = envelope.convergence.window_seconds
    poll_seconds = envelope.convergence.poll_seconds
    reproduce_count = envelope.convergence.reproduce

    start = clock()
    deadline = start + window
    normalized_keys = _normalized_keys(envelope)
    previous: dict[str, object] | None = None
    frozen_observation: Mapping[str, object] | None = None
    frozen: dict[str, object] | None = None
    polls = 0
    while True:
        observation = observe()
        polls += 1
        normalized = {key: observation.get(key, MISSING) for key in normalized_keys}
        if previous is not None and normalized == previous:
            frozen_observation = observation
            frozen = normalized
            break
        previous = normalized
        if polls >= MAX_CONVERGE_POLLS or clock() + poll_seconds > deadline:
            elapsed = clock() - start
            cause = (
                f"poll bound ({MAX_CONVERGE_POLLS}) exceeded -- does the injected "
                "clock advance when sleep is called?"
                if polls >= MAX_CONVERGE_POLLS
                else f"convergence window ({window}s) expired"
            )
            return ConvergenceResult(
                status="indeterminate",
                reason=(
                    f"{cause} after {polls} poll(s) without require+derive stabilizing"
                ),
                assertion=AssertionResult(
                    status="indeterminate",
                    satisfied=(),
                    violated=(),
                    unresolved=(),
                    unclassified=(),
                    characterization="convergence never stabilized; no frozen state to assert",
                    delta=FactDelta(),
                ),
                polls=polls,
                elapsed_seconds=elapsed,
                reproduce_observed=0,
                frozen=None,
            )
        sleep(poll_seconds)

    assert frozen_observation is not None and frozen is not None
    assertion = assert_envelope(envelope, pre, frozen_observation, categories)
    if assertion.status == "disproven":
        return ConvergenceResult(
            status="disproven",
            reason="frozen state failed the envelope assertion",
            assertion=assertion,
            polls=polls,
            elapsed_seconds=clock() - start,
            reproduce_observed=0,
            frozen=frozen,
        )
    if assertion.status == "indeterminate":
        # Unresolved clauses: the frozen state could not be fully checked
        # against the envelope, so this is neither verified nor disproven --
        # and a reproduce pass must not upgrade it to satisfied.
        return ConvergenceResult(
            status="indeterminate",
            reason=(
                f"frozen state left {len(assertion.unresolved)} envelope clause(s) "
                "unresolved; the envelope was not fully evaluable over the "
                "frozen state"
            ),
            assertion=assertion,
            polls=polls,
            elapsed_seconds=clock() - start,
            reproduce_observed=0,
            frozen=frozen,
        )

    for index in range(reproduce_count):
        # A reproduction is a fresh observation, not another immediate read of
        # a potentially cached source.  Space each read by the declared poll
        # interval just as the convergence observations are spaced.
        sleep(poll_seconds)
        reproduction = observe()
        normalized = {key: reproduction.get(key, MISSING) for key in normalized_keys}
        if normalized != frozen:
            differing = sorted(
                key
                for key in set(normalized) | set(frozen)
                if normalized.get(key, MISSING) != frozen.get(key, MISSING)
            )
            return ConvergenceResult(
                status="indeterminate",
                reason=(
                    f"reproduce observation {index + 1} of {reproduce_count} did not "
                    f"reproduce the frozen state; differing keys: {differing}"
                ),
                assertion=assertion,
                polls=polls,
                elapsed_seconds=clock() - start,
                reproduce_observed=index + 1,
                frozen=frozen,
            )
    return ConvergenceResult(
        status="satisfied",
        reason=None,
        assertion=assertion,
        polls=polls,
        elapsed_seconds=clock() - start,
        reproduce_observed=reproduce_count,
        frozen=frozen,
    )


def _normalized_keys(envelope: Envelope) -> tuple[str, ...]:
    """Post-side keys whose values define the normalized (frozen) state.

    Stability is defined over the *values* of every post-side key the require,
    derive, and forbid clauses reference -- not merely over the clause
    booleans, which can stay satisfied while a referenced counter churns.
    """
    keys = list(_predicted_keys(envelope))
    for clause in envelope.forbid:
        keys.append(clause.scope_key)
        keys.extend(_post_side_keys(clause.predicate))
    return tuple(dict.fromkeys(keys))
