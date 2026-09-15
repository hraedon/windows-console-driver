"""The wmi_filter observer: transported SOM-container values to facts.

Two layers are pinned. The fact tree (gpo_observers.wmi_filter) turns one
transported observation into the ``wmifilter.*`` vocabulary -- target
certification, residue freeze, malformed-payload refusal. The executor-side
collector (wcd.exec_transaction._WmiFilterCollector) routes through a
scripted transport and refuses ``ok: false`` payloads rather than guessing.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from gpo_observers.facts import make_fact
from gpo_observers.wmi_filter import wmi_filter_fact_tree
from wcd.exec_transaction import ExecTransactionError, _WmiFilterCollector

TARGET = "zz-wmi-filter"


def _values(facts: dict[str, Any]) -> dict[str, Any]:
    return {key: fact.value for key, fact in facts.items()}


def _object(name: str | None, **extra: str | None) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "dn": f"CN=zz-{name or 'unnamed'},CN=SOM,CN=WMIPolicy,CN=System,DC=zzlab,DC=invalid",
        "class": "msWMI-Som",
    }
    entry.update(
        name=name,
        parm1=extra.get("parm1"),
        parm2=extra.get("parm2"),
        id=extra.get("id"),
    )
    return entry


class _ScriptedTransport:
    """Stand-in for SessionTransport: one canned guest payload."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload
        self.calls: list[dict[str, object]] = []

    @property
    def vm_name(self) -> str:
        return "zz-vm"

    def guest(
        self, script: str, args: list[object] | None = None, *, timeout: float = 180.0
    ) -> str:
        assert "CN=WMIPolicy" in script, "wmi collector must query the SOM container"
        self.calls.append({"script": script, "args": list(args or [])})
        return json.dumps(self._payload)


def test_absent_container_is_the_pre_state_not_an_error() -> None:
    facts = _values(
        wmi_filter_fact_tree({"container_present": False, "objects": []}, TARGET)
    )
    assert facts["wmifilter.container.present"] is False
    assert facts["wmifilter.container.object_count"] == 0
    assert facts["wmifilter.container.other_names"] == []
    assert facts["wmifilter.container.unnamed_count"] == 0
    assert facts["wmifilter.target.present"] is False
    assert facts["wmifilter.target.name"] == ""
    assert facts["wmifilter.target.match_count"] == 0


def test_target_certified_and_residue_frozen() -> None:
    data = {
        "container_present": True,
        "objects": [
            _object("zz-earlier-filter"),
            _object(
                TARGET,
                parm1="zz description",
                parm2="root\\CIMv2;SELECT * FROM Win32_OperatingSystem",
                id="{11111111-2222-3333-4444-555555555555}",
            ),
        ],
    }
    facts = _values(wmi_filter_fact_tree(data, TARGET))
    assert facts["wmifilter.container.present"] is True
    assert facts["wmifilter.container.object_count"] == 2
    assert facts["wmifilter.container.other_names"] == ["zz-earlier-filter"]
    assert facts["wmifilter.container.unnamed_count"] == 0
    assert facts["wmifilter.target.match_count"] == 1
    assert facts["wmifilter.target.present"] is True
    assert facts["wmifilter.target.name"] == TARGET
    assert facts["wmifilter.target.parm1"] == "zz description"
    assert facts["wmifilter.target.parm2"] == "root\\CIMv2;SELECT * FROM Win32_OperatingSystem"
    assert facts["wmifilter.target.id"] == "{11111111-2222-3333-4444-555555555555}"


def test_duplicate_target_names_surface_as_match_count() -> None:
    data = {
        "container_present": True,
        "objects": [_object(TARGET, id="a"), _object(TARGET, id="b")],
    }
    facts = _values(wmi_filter_fact_tree(data, TARGET))
    assert facts["wmifilter.target.match_count"] == 2
    # The first match certifies; the envelope's match_count == 1 rejects it.
    assert facts["wmifilter.target.present"] is True


def test_unnamed_objects_are_counted_not_guessed() -> None:
    data = {
        "container_present": True,
        "objects": [_object(None), _object("zz-other")],
    }
    facts = _values(wmi_filter_fact_tree(data, TARGET))
    assert facts["wmifilter.container.unnamed_count"] == 1
    assert facts["wmifilter.container.object_count"] == 2
    assert facts["wmifilter.container.other_names"] == ["zz-other"]
    assert facts["wmifilter.target.present"] is False


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"container_present": "yes", "objects": []},
        {"container_present": True, "objects": "not-a-list"},
        {"container_present": True, "objects": ["not-an-object"]},
    ],
)
def test_malformed_payloads_refuse(data: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        wmi_filter_fact_tree(data, TARGET)


def test_categories_are_declared_not_unclassified() -> None:
    facts = wmi_filter_fact_tree(
        {"container_present": True, "objects": [_object(TARGET)]}, TARGET
    )
    for fact in facts.values():
        assert fact.category != "unclassified", fact.key
    assert make_fact("wmifilter.target.id", None).category == "identity"
    assert make_fact("wmifilter.container.other_names", None).category == "structural"
    assert make_fact("wmifilter.target.parm2", None).category == "content"


def test_collector_routes_through_the_transport() -> None:
    payload = {
        "ok": True,
        "data": {
            "container_present": True,
            "objects": [_object(TARGET, parm2="ns;q")],
        },
    }
    transport = _ScriptedTransport(payload)
    facts = _WmiFilterCollector().collect(
        object(), {"filter_name": TARGET}, transport  # type: ignore[arg-type]
    )
    assert _values(facts)["wmifilter.target.parm2"] == "ns;q"
    assert transport.calls[0]["args"] == [TARGET]


def test_collector_refuses_failed_observations() -> None:
    transport = _ScriptedTransport({"ok": False, "error": "zz boom"})
    with pytest.raises(ExecTransactionError, match="zz boom"):
        _WmiFilterCollector().collect(
            object(), {"filter_name": TARGET}, transport  # type: ignore[arg-type]
        )


def test_collector_requires_a_filter_name_param() -> None:
    with pytest.raises(ExecTransactionError, match="filter_name"):
        _WmiFilterCollector().collect(
            object(), {}, _ScriptedTransport({"ok": True, "data": {}})  # type: ignore[arg-type]
        )
