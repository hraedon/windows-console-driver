"""Driver profiles: declared commit boundaries and compatibility dependencies.

A driver profile classifies **every action** a surface driver can perform on
one surface (docs/contract.md section 6), so the transaction state machine can
tell a declared commit point from an undeclared mutation:

- ``orientation_only`` -- provably reads surface state only.
- ``reversible_pre_commit`` -- mutates only in-memory/surface state, undone by
  cancel/close before a commit point.
- ``potentially_mutating`` -- may write external state (some MMC extensions
  commit on Apply; some child dialogs commit on close).
- ``commit_point`` -- a declared external mutation point.

Classifications are **declared by the author and validated during driver
development**, never discovered at runtime (section 6 rule 1). Crossing an
undeclared mutating boundary is a hard stop and a
:class:`ProfileInvalid` finding (rule 2), and everything before the first
commit point must be replayable from scratch (rule 3). The profile also
   declares what its selectors depend on. Those declarations are retained as
   qualification metadata; the runtime does not yet capture and compare the
   qualified dependency values needed for an enforced compatibility predicate.

The shipped ``profiles/gpmc-server2025.toml`` uses the typed, closed TOML
shape this module validates::

        [profile]
        surface = "gpmc-server2025"
        description = "GPMC / GPME (gpmc.msc, group policy editor snap-ins)"
        os_family = "Windows Server 2025"
        os_build_family = "26100"
        # optional; must name an action classified commit_point:
        first_commit_point = "ok_startup_scripts_dialog"

        [actions.open_gpo_editor]
        class = "orientation_only"
        notes = "launches/attaches editor window"
        # ... one table per action; `class` is one of the four classes above

        [selectors.startup_scripts_dialog]
        title_regex = "Startup Properties"
        # free-form match criteria (title_regex, name, automation_id, class, ...)

        [[selector_dependencies]]
        selector = "startup_scripts_dialog"
        dependency = "ui_language"
        strength = "strong"

The schema is closed: unknown keys are :class:`ProfileInvalid`, because a
profile that silently ignores a misspelled section classifies nothing. The
banked estate records qualify the exercised action/selector paths; the profile
notes retain conservative classifications where exact per-dialog durability
was not isolated.
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Final, Literal, cast

ActionClass = Literal[
    "orientation_only", "reversible_pre_commit", "potentially_mutating", "commit_point"
]

ACTION_CLASSES: Final[frozenset[str]] = frozenset(
    {
        "orientation_only",
        "reversible_pre_commit",
        "potentially_mutating",
        "commit_point",
    }
)

# The compatibility-dependency vocabulary from contract section 6. Runtime
# comparison against qualified values is not implemented yet.
DEPENDENCY_NAMES: Final[frozenset[str]] = frozenset(
    {"binary_version", "dialog_fingerprint", "ui_language", "dpi", "theme", "os_build"}
)
STRENGTHS: Final[frozenset[str]] = frozenset({"strong", "strong_if_used", "provenance"})


class ProfileInvalid(Exception):
    """A driver profile is malformed, or declares something the contract forbids."""


@dataclass(frozen=True)
class SelectorDependency:
    """One declared selector dependency row of the compatibility predicate."""

    selector: str
    dependency: str
    strength: str


@dataclass(frozen=True)
class DriverProfile:
    """A loaded, validated driver profile.

    ``actions`` maps action name to its declared class; ``classification``
    returns ``None`` for an action the profile does not declare -- and an
    undeclared action must never be treated as safe: qualified execution
    refuses it, and crossing it as a mutation is a profile-invalid hard stop
    (contract section 6 rule 2). ``selectors`` are the free-form match criteria
    tables; ``selector_dependencies`` the declared compatibility rows;
    ``action_notes`` the author's per-action facts (e.g. "presumed
    scripts.ini flush" from the manual evidence regime).
    """

    surface: str
    description: str | None
    os_family: str | None
    os_build_family: str | None
    first_commit_point: str | None
    actions: Mapping[str, ActionClass]
    selectors: Mapping[str, Mapping[str, object]]
    selector_dependencies: tuple[SelectorDependency, ...]
    action_notes: Mapping[str, str]

    def classification(self, action: str) -> ActionClass | None:
        """The declared class of ``action``, or ``None`` when undeclared."""
        return self.actions.get(action)

    @property
    def commit_point_actions(self) -> tuple[str, ...]:
        """Every action declared as a commit point, in declaration order."""
        return tuple(
            name for name, action_class in self.actions.items() if action_class == "commit_point"
        )


def load_profile(path: str | Path) -> DriverProfile:
    """Load and validate the profile TOML file at ``path``."""
    with open(path, "rb") as handle:
        try:
            data = tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            raise ProfileInvalid(f"profile file {str(path)!r} is not valid TOML: {exc}") from exc
    return parse_profile(data)


def parse_profile_text(text: str) -> DriverProfile:
    """Parse a profile from TOML text (test and migration convenience)."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ProfileInvalid(f"profile text is not valid TOML: {exc}") from exc
    return parse_profile(data)


def parse_profile(data: Mapping[str, object]) -> DriverProfile:
    """Validate a ``tomllib``-decoded profile mapping and build the profile."""
    unknown_tables = set(data) - {"profile", "actions", "selectors", "selector_dependencies"}
    if unknown_tables:
        raise ProfileInvalid(f"unknown profile tables/keys: {sorted(unknown_tables)!r}")
    profile_table = _table(data, "profile", required=True)
    actions_table = _table(data, "actions", required=True)

    surface = profile_table.get("surface")
    if not isinstance(surface, str) or not surface.strip():
        raise ProfileInvalid("[profile] surface must be a non-blank string")
    description = _optional_str(profile_table, "description")
    os_family = _optional_str(profile_table, "os_family")
    os_build_family = _optional_str(profile_table, "os_build_family")
    unknown_profile_keys = set(profile_table) - {
        "surface",
        "description",
        "os_family",
        "os_build_family",
        "first_commit_point",
    }
    if unknown_profile_keys:
        raise ProfileInvalid(f"[profile] has unknown keys: {sorted(unknown_profile_keys)!r}")

    actions: dict[str, ActionClass] = {}
    action_notes: dict[str, str] = {}
    if not actions_table:
        raise ProfileInvalid("[actions] must classify at least one action")
    for name, entry in actions_table.items():
        if not isinstance(name, str) or not name.strip():
            raise ProfileInvalid("action names must be non-blank strings")
        action_table = _require_table(entry, f"[actions.{name}]")
        unknown_action_keys = set(action_table) - {"class", "notes"}
        if unknown_action_keys:
            raise ProfileInvalid(
                f"[actions.{name}] has unknown keys: {sorted(unknown_action_keys)!r}"
            )
        action_class = action_table.get("class")
        if not isinstance(action_class, str) or action_class not in ACTION_CLASSES:
            raise ProfileInvalid(
                f"[actions.{name}] class must be exactly one of {sorted(ACTION_CLASSES)}, "
                f"got {action_class!r}"
            )
        actions[name] = cast(ActionClass, action_class)
        entry_notes = action_table.get("notes")
        if entry_notes is not None:
            if not isinstance(entry_notes, str):
                raise ProfileInvalid(f"[actions.{name}] notes must be a string")
            action_notes[name] = entry_notes

    first_commit_point = profile_table.get("first_commit_point")
    if first_commit_point is not None:
        if not isinstance(first_commit_point, str) or not first_commit_point:
            raise ProfileInvalid("[profile] first_commit_point must be a string")
        declared_class = actions.get(first_commit_point)
        if declared_class is None:
            raise ProfileInvalid(
                f"[profile] first_commit_point {first_commit_point!r} names no declared action"
            )
        if declared_class != "commit_point":
            raise ProfileInvalid(
                f"[profile] first_commit_point {first_commit_point!r} is classified "
                f"{declared_class!r}, not commit_point"
            )

    selectors: dict[str, Mapping[str, object]] = {}
    selectors_table = _table(data, "selectors", required=False)
    for name, entry in selectors_table.items():
        selector_table = _require_table(entry, f"[selectors.{name}]")
        if not selector_table:
            raise ProfileInvalid(f"[selectors.{name}] must declare at least one criterion")
        for key, value in selector_table.items():
            if not isinstance(value, (str, int, float, bool)):
                raise ProfileInvalid(
                    f"[selectors.{name}].{key} must be a scalar (str/int/float/bool), "
                    f"got {type(value).__name__}"
                )
        selectors[name] = MappingProxyType(dict(selector_table))

    dependencies: list[SelectorDependency] = []
    dependencies_raw = data.get("selector_dependencies")
    if dependencies_raw is not None:
        if not isinstance(dependencies_raw, list):
            raise ProfileInvalid("selector_dependencies must be an array of tables")
        for index, entry in enumerate(dependencies_raw):
            dependencies.append(_parse_dependency_row(entry, index, selectors))

    return DriverProfile(
        surface=surface,
        description=description,
        os_family=os_family,
        os_build_family=os_build_family,
        first_commit_point=first_commit_point if isinstance(first_commit_point, str) else None,
        actions=MappingProxyType(actions),
        selectors=MappingProxyType(selectors),
        selector_dependencies=tuple(dependencies),
        action_notes=MappingProxyType(action_notes),
    )


def _parse_dependency_row(
    entry: object, index: int, selectors: Mapping[str, Mapping[str, object]]
) -> SelectorDependency:
    row = _require_table(entry, f"selector_dependencies[{index}]")
    unknown_row_keys = set(row) - {"selector", "dependency", "strength"}
    if unknown_row_keys:
        raise ProfileInvalid(
            f"selector_dependencies[{index}] has unknown keys: {sorted(unknown_row_keys)!r}"
        )
    selector = row.get("selector")
    dependency = row.get("dependency")
    strength = row.get("strength")
    for field_name, value in (
        ("selector", selector),
        ("dependency", dependency),
        ("strength", strength),
    ):
        if not isinstance(value, str) or not value:
            raise ProfileInvalid(
                f"selector_dependencies[{index}].{field_name} must be a non-blank string"
            )
    assert isinstance(selector, str) and isinstance(dependency, str) and isinstance(strength, str)
    if selector not in selectors:
        raise ProfileInvalid(
            f"selector_dependencies[{index}] names selector {selector!r}, "
            "which the profile does not declare"
        )
    if dependency not in DEPENDENCY_NAMES:
        raise ProfileInvalid(
            f"selector_dependencies[{index}] dependency {dependency!r} is not one of "
            f"{sorted(DEPENDENCY_NAMES)}"
        )
    if strength not in STRENGTHS:
        raise ProfileInvalid(
            f"selector_dependencies[{index}] strength {strength!r} is not one of "
            f"{sorted(STRENGTHS)}"
        )
    return SelectorDependency(selector=selector, dependency=dependency, strength=strength)


def _table(data: Mapping[str, object], key: str, *, required: bool) -> Mapping[str, object]:
    value = data.get(key)
    if value is None:
        if required:
            raise ProfileInvalid(f"profile is missing the required [{key}] table")
        return {}
    return _require_table(value, f"[{key}]")


def _require_table(value: object, where: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ProfileInvalid(f"{where} must be a table, got {type(value).__name__}")
    return value


def _optional_str(table: Mapping[str, object], key: str) -> str | None:
    value = table.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ProfileInvalid(f"[profile] {key} must be a string")
    return value
