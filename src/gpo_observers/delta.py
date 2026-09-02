"""Characterized deltas over fact sets, plus the forbid-scope checks.

The delta between a pre-state and a post-state :class:`~gpo_observers.facts.FactSet`
is a *characterized* result, never a boolean: every changed, added or removed
key carries its before/after values and its declared category, so an
envelope review can see exactly what satisfied, what violated, and what was
unclassified (contract sections 2 and 3).

Coverage rule: a change is covered only by an explicit ``allow`` clause
naming its category -- ``timestamps`` and ``replication_metadata`` name the
volatile subcategories, ``volatile`` names both, and the plain categories
(``structural``, ``content``, ``file_mtime``, ``identity``) name themselves.
Anything else is a violation. ``unclassified`` can never be allowed -- the
constructor refuses the attempt; an undeclared key that changed is a
violation by design, and this is not softened.

The forbid checks each name their enumerable blast radius:

- ``gpc_extension_lists`` -- none of the forbidden GUIDs appears in either
  extension-list attribute of the GPC.
- ``sysvol_paths`` -- every SYSVOL path (relative to the Policies directory)
  is under this GPO's GUID directory.
- ``policies_container`` -- the GPC object set under CN=Policies,CN=System
  equals the pre-state set.

Missing scope facts are violations, not passes: absence of evidence cannot
prove a negative.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Literal

from .facts import Fact, JSONValue, declared_category

type ChangeKind = Literal["changed", "added", "removed"]
type DeltaStatus = Literal["satisfied", "disproven"]

SCOPE_GPC_EXTENSION_LISTS = "gpc_extension_lists"
SCOPE_SYSVOL_PATHS = "sysvol_paths"
SCOPE_POLICIES_CONTAINER = "policies_container"

_EXTENSION_LIST_FACT_KEYS: tuple[str, ...] = (
    "ad.gPCMachineExtensionNames",
    "ad.gPCUserExtensionNames",
)


class DeltaError(ValueError):
    """Raised when a delta evaluation is requested with incoherent parameters."""


@dataclass(frozen=True, slots=True)
class FactChange:
    """One key that differs between pre and post, with its declared category."""

    key: str
    kind: ChangeKind
    before: JSONValue
    after: JSONValue
    category: str
    volatile_subcategory: str | None
    covered: bool = False

    @property
    def unclassified(self) -> bool:
        return self.category == "unclassified"


@dataclass(frozen=True, slots=True)
class ForbidViolation:
    """A violated forbid clause, with the scope check that noticed it."""

    scope: str
    predicate: str
    detail: str


@dataclass(frozen=True, slots=True)
class DeltaOutcome:
    """The characterized result of comparing pre to post."""

    changes: tuple[FactChange, ...]
    forbid_violations: tuple[ForbidViolation, ...]
    allowed_categories: tuple[str, ...]

    @property
    def satisfiable(self) -> bool:
        return all(change.covered for change in self.changes) and not self.forbid_violations

    @property
    def status(self) -> DeltaStatus:
        return "satisfied" if self.satisfiable else "disproven"

    @property
    def uncovered_changes(self) -> tuple[FactChange, ...]:
        return tuple(change for change in self.changes if not change.covered)

    @property
    def unclassified_changes(self) -> tuple[FactChange, ...]:
        return tuple(change for change in self.changes if change.unclassified)


def compute_changes(
    pre: Mapping[str, Fact], post: Mapping[str, Fact]
) -> tuple[FactChange, ...]:
    """Every differing key, sorted, with before/after and declared category."""
    changes: list[FactChange] = []
    for key in sorted(set(pre) | set(post)):
        in_pre = key in pre
        in_post = key in post
        before = pre[key].value if in_pre else None
        after = post[key].value if in_post else None
        if in_pre and in_post:
            if before == after:
                continue
            kind: ChangeKind = "changed"
        elif in_post:
            kind = "added"
        else:
            kind = "removed"
        category, subcategory = declared_category(key)
        changes.append(
            FactChange(
                key=key,
                kind=kind,
                before=before,
                after=after,
                category=category,
                volatile_subcategory=subcategory,
            )
        )
    return tuple(changes)


def _is_covered(category: str, subcategory: str | None, allowed: frozenset[str]) -> bool:
    if category == "unclassified":
        return False
    if category == "volatile":
        return "volatile" in allowed or (subcategory is not None and subcategory in allowed)
    return category in allowed


def _guid_token(guid: str) -> str:
    # Delta-local GUID normalization; deliberately independent of the
    # collection module's own normalizer.
    return guid.strip().strip("{}").strip("()").upper()


def check_extension_lists(
    post: Mapping[str, Fact], forbidden_guids: Sequence[str]
) -> tuple[ForbidViolation, ...]:
    """Scope ``gpc_extension_lists``: no forbidden GUID in either list."""
    if not forbidden_guids:
        return ()
    violations: list[ForbidViolation] = []
    values: list[str] = []
    for key in _EXTENSION_LIST_FACT_KEYS:
        fact = post.get(key)
        if fact is None:
            violations.append(
                ForbidViolation(
                    scope=SCOPE_GPC_EXTENSION_LISTS,
                    predicate="extension lists contain none of the forbidden GUIDs",
                    detail=(
                        f"scope fact {key!r} absent from the snapshot; "
                        "forbidden-GUID absence cannot be verified"
                    ),
                )
            )
            continue
        if isinstance(fact.value, str):
            values.append(fact.value.upper())
    for guid in forbidden_guids:
        token = "{" + _guid_token(guid) + "}"
        if any(token in value for value in values):
            violations.append(
                ForbidViolation(
                    scope=SCOPE_GPC_EXTENSION_LISTS,
                    predicate="extension lists contain none of the forbidden GUIDs",
                    detail=f"forbidden GUID {token} appears in an extension list",
                )
            )
    return tuple(violations)


def check_sysvol_containment(
    post: Mapping[str, Fact], gpo_guid: str | None
) -> tuple[ForbidViolation, ...]:
    """Scope ``sysvol_paths``: every path is under the GPO's GUID directory.

    The scope snippet reports paths relative to the Policies directory, so a
    contained path starts with ``{<gpo guid>}/``. Paths that do not (and a
    missing scope fact) are violations.
    """
    if gpo_guid is None:
        return ()
    fact = post.get("scope.sysvol_relpaths")
    if fact is None or not isinstance(fact.value, list):
        return (
            ForbidViolation(
                scope=SCOPE_SYSVOL_PATHS,
                predicate="every SYSVOL path is under this GPO's GUID directory",
                detail=(
                    "scope fact 'scope.sysvol_relpaths' absent from the snapshot; "
                    "containment cannot be verified"
                ),
            ),
        )
    prefix = "{" + _guid_token(gpo_guid) + "}/"
    escapers = [
        relpath
        for relpath in fact.value
        if not isinstance(relpath, str) or not relpath.upper().startswith(prefix)
    ]
    if not escapers:
        return ()
    first = escapers[0] if isinstance(escapers[0], str) else repr(escapers[0])
    return (
        ForbidViolation(
            scope=SCOPE_SYSVOL_PATHS,
            predicate="every SYSVOL path is under this GPO's GUID directory",
            detail=(
                f"{len(escapers)} path(s) outside {prefix!r}; first offender: {first!r}"
            ),
        ),
    )


def check_policies_container(
    pre: Mapping[str, Fact], post: Mapping[str, Fact]
) -> tuple[ForbidViolation, ...]:
    """Scope ``policies_container``: the GPC object set equals pre-state."""
    pre_fact = pre.get("scope.policies.gpc_guids")
    post_fact = post.get("scope.policies.gpc_guids")
    missing = [side for side, fact in (("pre", pre_fact), ("post", post_fact)) if fact is None]
    if missing:
        return (
            ForbidViolation(
                scope=SCOPE_POLICIES_CONTAINER,
                predicate="GPC object set equals the pre-state set",
                detail=(
                    "scope fact 'scope.policies.gpc_guids' absent from the "
                    f"{' and '.join(missing)} snapshot; object-set stability "
                    "cannot be verified"
                ),
            ),
        )
    assert pre_fact is not None and post_fact is not None
    if not isinstance(pre_fact.value, list) or not isinstance(post_fact.value, list):
        return (
            ForbidViolation(
                scope=SCOPE_POLICIES_CONTAINER,
                predicate="GPC object set equals the pre-state set",
                detail="scope fact 'scope.policies.gpc_guids' is malformed; "
                "object-set stability cannot be verified",
            ),
        )
    pre_set = {item for item in pre_fact.value if isinstance(item, str)}
    post_set = {item for item in post_fact.value if isinstance(item, str)}
    added = sorted(post_set - pre_set)
    removed = sorted(pre_set - post_set)
    if not added and not removed:
        return ()
    return (
        ForbidViolation(
            scope=SCOPE_POLICIES_CONTAINER,
            predicate="GPC object set equals the pre-state set",
            detail=f"GPC objects added: {added}; removed: {removed}",
        ),
    )


def check_forbids(
    pre: Mapping[str, Fact],
    post: Mapping[str, Fact],
    *,
    forbidden_guids: Sequence[str] = (),
    gpo_guid: str | None = None,
) -> tuple[ForbidViolation, ...]:
    """Run every forbid-scope check against the post state."""
    return (
        *check_extension_lists(post, forbidden_guids),
        *check_sysvol_containment(post, gpo_guid),
        *check_policies_container(pre, post),
    )


def evaluate(
    pre: Mapping[str, Fact],
    post: Mapping[str, Fact],
    *,
    allowed_categories: Sequence[str] = (),
    forbidden_guids: Sequence[str] = (),
    gpo_guid: str | None = None,
) -> DeltaOutcome:
    """Compare pre to post and characterize the outcome.

    ``require`` and ``derive`` coverage is the assertion engine's concern and
    deliberately out of scope here: this evaluates the allow categories and
    the forbid scopes over the raw characterized delta.
    """
    allowed = frozenset(allowed_categories)
    if "unclassified" in allowed:
        raise DeltaError(
            "the 'unclassified' category can never be allowed; "
            "declare the fact key instead"
        )
    changes: list[FactChange] = []
    for change in compute_changes(pre, post):
        changes.append(
            replace(
                change,
                covered=_is_covered(change.category, change.volatile_subcategory, allowed),
            )
        )
    return DeltaOutcome(
        changes=tuple(changes),
        forbid_violations=check_forbids(
            pre, post, forbidden_guids=forbidden_guids, gpo_guid=gpo_guid
        ),
        allowed_categories=tuple(sorted(allowed)),
    )
