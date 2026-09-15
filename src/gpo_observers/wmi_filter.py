"""WMI-filter (msWMI-Som) observer: controller-side fact tree.

The guest transports raw attribute values for every object under
``CN=SOM,CN=WMIPolicy,CN=System`` (one-level); this module turns them into
the flat fact vocabulary the envelope evaluates. Following the independence
rule, the guest never interprets: it does not know which filter is the
target, it does not compare observations, and it does not decide blast
radius. The controller knows the target name (a capability argument) and
computes the ``other_names`` residue that the forbid clause compares
pre-to-post.

Deliberately narrow fact set: every emitted key that can change across the
transaction must be referenced by the capability envelope, or the delta
characterizer treats the change as an unclassified violation. Container DN,
object DNs, the object class, and the full name list are therefore NOT
emitted as facts -- the blast radius is bounded by ``object_count`` (derived
exactly), ``other_names`` and ``unnamed_count`` (forbidden to change), and
the target's own certified fields. The class name stays unmeasured until the
first estate window records it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from gpo_observers.facts import Fact, make_fact

FactSet = dict[str, Fact]


def _obj_str(raw: object) -> str:
    """Stringify one transported attribute; absent and empty are both ''."""
    if raw is None:
        return ""
    return str(raw)


def wmi_filter_fact_tree(data: Mapping[str, Any], filter_name: str) -> FactSet:
    """Build the ``wmifilter.*`` facts from one transported observation.

    ``data`` is the ``ok: true`` payload of the collection script:
    ``container_present`` plus an ``objects`` list whose entries carry
    ``name`` (msWMI-Name), ``parm1``, ``parm2`` and ``id`` as string-or-null
    raw values. Malformed payloads raise: an observer that guesses is worse
    than an observer that refuses.
    """
    if "container_present" not in data:
        raise ValueError("wmi_filter observation missing container_present")
    container_present = data["container_present"]
    if not isinstance(container_present, bool):
        raise ValueError("wmi_filter container_present is not a boolean")
    raw_objects = data.get("objects")
    if raw_objects is None:
        raw_objects = []
    if not isinstance(raw_objects, list):
        raise ValueError("wmi_filter objects is not a list")

    names: list[str] = []
    unnamed = 0
    matches: list[Mapping[str, Any]] = []
    for raw in raw_objects:
        if not isinstance(raw, Mapping):
            raise ValueError("wmi_filter object entry is not an object")
        name = _obj_str(raw.get("name"))
        if name == "":
            unnamed += 1
            continue
        names.append(name)
        if name == filter_name:
            matches.append(raw)

    facts: FactSet = {}

    def fact(key: str, value: object) -> None:
        facts[key] = make_fact(key, value)

    fact("wmifilter.container.present", container_present)
    fact("wmifilter.container.object_count", len(raw_objects))
    fact("wmifilter.container.other_names", sorted(n for n in names if n != filter_name))
    fact("wmifilter.container.unnamed_count", unnamed)
    fact("wmifilter.target.match_count", len(matches))
    if matches:
        target = matches[0]
        fact("wmifilter.target.present", True)
        fact("wmifilter.target.name", _obj_str(target.get("name")))
        fact("wmifilter.target.parm1", _obj_str(target.get("parm1")))
        fact("wmifilter.target.parm2", _obj_str(target.get("parm2")))
        fact("wmifilter.target.id", _obj_str(target.get("id")))
    else:
        fact("wmifilter.target.present", False)
        fact("wmifilter.target.name", "")
        fact("wmifilter.target.parm1", "")
        fact("wmifilter.target.parm2", "")
        fact("wmifilter.target.id", "")
    return facts
