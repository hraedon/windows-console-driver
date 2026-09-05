"""The Fact model: normalized, categorized observations of GPO state.

Every observer output is reduced to facts -- ``(key, value)`` pairs with
dotted keys and JSON-compatible values -- and every fact key is assigned a
declared category. The category is what makes a characterized delta possible:
an envelope may tolerate change by naming a category (a *named field set*),
never by naming "stuff that looked volatile" (contract section 3).

Categories:

- ``structural`` -- must not change unless the capability requires it.
- ``volatile`` -- timestamps and replication metadata; carries a subcategory
  (``timestamps`` or ``replication_metadata``) so allow clauses can name the
  field set precisely.
- ``file_mtime`` -- filesystem timestamps, should a future observer collect
  them.
- ``content`` -- file contents semantics: parsed INI entries, encoding facts,
  file presence.
- ``identity`` -- identifiers that evidence handling must strip before
  sharing (GPO display names, domain names).
- ``unclassified`` -- any key the declared table does not know. The delta
  engine treats changes to unclassified facts as violations, deliberately:
  a key nobody declared has no business changing silently. Do not soften
  this.

The declared table deliberately does NOT cover the per-file fingerprint keys
(``sysvol.<relpath>.sha256`` / ``sysvol.<relpath>.bytes``): the presence and
the bytes of an arbitrary file in a GPO directory have no statically knowable
category, so every appearance, disappearance or content change surfaces as an
unclassified violation. System files whose semantics already have dedicated
observers (GPT.INI, scripts.ini, psscripts.ini) are excluded from per-file
facts entirely by the snapshot builder -- their version and entry semantics
are the dedicated facts, and hashing them would drown every edit in noise.
"""

from __future__ import annotations

import fnmatch
import math
from dataclasses import dataclass
from typing import Literal

type JSONValue = str | int | float | bool | list[JSONValue] | dict[str, JSONValue] | None
type FactCategory = Literal[
    "structural", "volatile", "file_mtime", "content", "identity", "unclassified"
]
type VolatileSubcategory = Literal["timestamps", "replication_metadata"]
type FactSet = dict[str, Fact]

KNOWN_CATEGORIES: frozenset[str] = frozenset(
    {"structural", "volatile", "file_mtime", "content", "identity", "unclassified"}
)
VOLATILE_SUBCATEGORIES: frozenset[str] = frozenset({"timestamps", "replication_metadata"})


class FactError(ValueError):
    """Raised when a fact key or value violates the Fact model."""


@dataclass(frozen=True, slots=True)
class Fact:
    """One normalized observation: a dotted key, a JSON value, a category."""

    key: str
    value: JSONValue
    category: FactCategory
    volatile_subcategory: VolatileSubcategory | None = None


# Ordered rules, first match wins. ``fnmatch`` ``*`` spans dots, so one
# pattern covers both the ``scripts_ini.<side>.`` and the
# ``scripts_ini.ps.<side>.`` namespaces.
#
# DELIBERATE ABSENCE: there is no rule for "sysvol.*.sha256" or
# "sysvol.*.bytes". Per-file fingerprint keys stay unclassified so that an
# undeclared file appearing in (or vanishing from) a GPO directory is always
# a violation. See the module docstring.
FACT_CATEGORY_RULES: tuple[tuple[str, FactCategory, VolatileSubcategory | None], ...] = (
    # Identity: GPC identity and identifiers evidence handling must strip.
    ("gpo_identity.*", "identity", None),
    ("version.displayName", "identity", None),
    # Selected AD attributes: the structural/volatile split of the R2 set.
    ("ad.gPCMachineExtensionNames", "structural", None),
    ("ad.gPCUserExtensionNames", "structural", None),
    ("ad.versionNumber", "structural", None),
    ("ad.gPCFunctionalityVersion", "structural", None),
    ("ad.flags", "structural", None),
    ("ad.whenChanged", "volatile", "timestamps"),
    ("ad.uSNChanged", "volatile", "replication_metadata"),
    # Version facts (parsed from GPT.INI / AD, never inferred from a hash).
    ("version.raw", "structural", None),
    ("version.machine", "structural", None),
    ("version.user", "structural", None),
    ("version.ad_versionNumber", "structural", None),
    # scripts.ini / psscripts.ini presence, encoding and entry semantics.
    ("scripts_ini.*.present", "content", None),
    ("scripts_ini.*.encoding.*", "content", None),
    ("scripts_ini.*.config_shape", "content", None),
    ("scripts_ini.*.policy.*", "content", None),
    ("scripts_ini.*.scripts_config.*", "content", None),
    ("scripts_ini.*.entry_count", "content", None),
    ("scripts_ini.*.*.*.*", "content", None),
    # GptTmpl.inf (R4): encoding, section shapes, quoted-CSV entries, keys.
    ("gpttmpl.present", "content", None),
    ("gpttmpl.*", "content", None),
    # fdeploy.ini (R3): encoding, section shapes, entries.
    ("fdeploy.present", "content", None),
    ("fdeploy.*", "content", None),
    ("fdeploy_marker.present", "content", None),
    ("fdeploy_marker.*", "content", None),
    # Migration table (R1): the GPMC-authored .migtable XML.
    ("migtable.present", "content", None),
    ("migtable.*", "content", None),
    # Collection integrity of the two independent enumeration passes.
    ("sysvol.passes_match", "structural", None),
    # Filesystem timestamps, should a future observer collect them.
    ("sysvol.*.mtime", "file_mtime", None),
    # Scope facts feeding the forbid checks.
    ("scope.extension_lists.*", "structural", None),
    ("scope.policies.gpc_guids", "structural", None),
    ("scope.sysvol_relpaths", "structural", None),
    ("scope.sysvol_contained", "structural", None),
)


def declared_category(key: str) -> tuple[FactCategory, VolatileSubcategory | None]:
    """Return the declared ``(category, volatile subcategory)`` for *key*.

    Unknown keys are ``("unclassified", None)``; the delta engine treats
    every change to such a key as a violation.
    """
    for pattern, category, subcategory in FACT_CATEGORY_RULES:
        if fnmatch.fnmatchcase(key, pattern):
            return (category, subcategory)
    return ("unclassified", None)


def check_json_value(value: object) -> JSONValue:
    """Validate that *value* is JSON-compatible and return it typed."""
    if value is None or isinstance(value, (str, bool, int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise FactError("non-finite floats are not JSON-compatible")
        return value
    if isinstance(value, list):
        return [check_json_value(item) for item in value]
    if isinstance(value, dict):
        result: dict[str, JSONValue] = {}
        for key, item in value.items():
            result[str(key)] = check_json_value(item)
        return result
    raise FactError(f"value of type {type(value).__name__} is not JSON-compatible")


def make_fact(key: str, value: object) -> Fact:
    """Build a :class:`Fact`, filling the declared category for *key*.

    Unknown keys get the ``unclassified`` category -- that is the point of
    the table: an undeclared key that later changes is surfaced as a
    violation, not silently tolerated.
    """
    if not key:
        raise FactError("fact key must be a non-empty dotted string")
    category, subcategory = declared_category(key)
    return Fact(
        key=key,
        value=check_json_value(value),
        category=category,
        volatile_subcategory=subcategory,
    )
