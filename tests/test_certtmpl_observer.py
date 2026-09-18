"""The certtmpl observer: transported Certificate-Template lines to facts.

Two layers are pinned. The fact tree (gpo_observers.certtmpl) turns one
collected line stream into the ``certtmpl.*`` vocabulary -- target
certification, membership committed as digests (never name lists), and
the guest/controller cross-check that refuses any container claim the
recomputation cannot reproduce. The guest script
(tools/guest_scripts/certtmpl_collect.ps1) is pinned structurally -- 5.1
parse, pure ASCII, the fail-closed 512-object bound -- because no test
here touches a live host or a real AD. The executor-side collector that
routes the script over PowerShell Direct lands with the surface wiring,
not in this prep change.
"""

from __future__ import annotations

import hashlib
from typing import Any

import ps_scripts
import pytest

from gpo_observers.certtmpl import certtmpl_fact_tree

TARGET = "zz-template-candidate"
SCRIPT = ps_scripts.REPO_ROOT / "tools" / "guest_scripts" / "certtmpl_collect.ps1"

VALIDITY_DN = (
    "CN=FourYears,CN=Validity Periods,CN=Public Key Services,CN=Configuration,"
    "DC=zzlab,DC=invalid"
)
SDDL = (
    "O:SYD:(A;;CC;;;S-1-5-21-1111111111-2222222222-3333333333-1101)(A;;DC;;;BA)"
)
SDDL_ALT = "O:BAD:(A;;CC;;;BA)"

FACT_KEYS = frozenset(
    {
        "certtmpl.container.present",
        "certtmpl.container.object_count",
        "certtmpl.container.names_sha256",
        "certtmpl.container.other_names_sha256",
        "certtmpl.container.other_count",
        "certtmpl.container.unnamed_count",
        "certtmpl.target.present",
        "certtmpl.target.name",
        "certtmpl.target.validity_period",
        "certtmpl.target.validity_period_units",
        "certtmpl.target.schema_version",
        "certtmpl.target.cert_name_flag",
        "certtmpl.target.key_flag",
        "certtmpl.target.sddl_len",
        "certtmpl.target.sddl_sha256",
    }
)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _names_digest(names: list[str]) -> str:
    # The script's digest convention: LF-joined, ordinally sorted, UTF-8,
    # lowercase hex -- cross-verified against the PS emission by hand.
    return _sha256("\n".join(sorted(names)))


def _values(facts: dict[str, Any]) -> dict[str, Any]:
    return {key: fact.value for key, fact in facts.items()}


_DEFAULT_ATTRS: dict[str, str] = {
    "validity_period": VALIDITY_DN,
    "validity_period_units": "4",
    "schema_version": "2",
    "cert_name_flag": "94208",
    "key_flag": "16842752",
    "sddl_len": str(len(SDDL)),
    "sddl_sha256": _sha256(SDDL),
}


def _attr_lines(attrs: dict[str, str]) -> list[str]:
    return [
        "validity_period=" + attrs["validity_period"],
        "validity_period_units=" + attrs["validity_period_units"],
        "schema_version=" + attrs["schema_version"],
        "cert_name_flag=" + attrs["cert_name_flag"],
        "key_flag=" + attrs["key_flag"],
        "sddl_len=" + attrs["sddl_len"],
        "sddl_sha256=" + attrs["sddl_sha256"],
    ]


def _observation(
    names: list[str],
    target: str = TARGET,
    *,
    unnamed: int = 0,
    overrides: dict[str, dict[str, str]] | None = None,
) -> list[str]:
    """Mirror the guest script's emission for a synthetic container."""
    per_name = overrides or {}
    lines = ["container.present=1"] + ["name="] * unnamed
    readable = sorted(names)
    for name in readable:
        lines.append("name=" + name)
        lines.extend(_attr_lines({**_DEFAULT_ATTRS, **per_name.get(name, {})}))
    other = [name for name in readable if name.casefold() != target.casefold()]
    lines.append("container.object_count=" + str(len(readable) + unnamed))
    lines.append("container.names_sha256=" + _names_digest(readable))
    lines.append("container.other_names_sha256=" + _names_digest(other))
    lines.append("container.other_count=" + str(len(other)))
    lines.append("container.unnamed_count=" + str(unnamed))
    if target in readable:
        attrs = {**_DEFAULT_ATTRS, **per_name.get(target, {})}
        lines.append("target.present=1")
        lines.append("target.name=" + target)
        lines.extend("target." + line for line in _attr_lines(attrs))
    else:
        lines.append("target.present=0")
    return lines


def _absent_container() -> list[str]:
    return [
        "container.present=0",
        "container.object_count=0",
        "container.names_sha256=" + _names_digest([]),
        "container.other_names_sha256=" + _names_digest([]),
        "container.other_count=0",
        "container.unnamed_count=0",
        "target.present=0",
    ]


def test_absent_container_is_the_pre_state_not_an_error() -> None:
    facts = _values(certtmpl_fact_tree(_absent_container(), TARGET))
    assert facts["certtmpl.container.present"] is False
    assert facts["certtmpl.container.object_count"] == 0
    assert facts["certtmpl.container.names_sha256"] == _names_digest([])
    assert facts["certtmpl.container.other_names_sha256"] == _names_digest([])
    assert facts["certtmpl.container.other_count"] == 0
    assert facts["certtmpl.container.unnamed_count"] == 0
    assert facts["certtmpl.target.present"] is False
    assert facts["certtmpl.target.name"] == ""


def test_target_certified_and_membership_committed_as_digests() -> None:
    names = ["Computer", TARGET, "zz-other-template"]
    facts = _values(certtmpl_fact_tree(_observation(names), TARGET))
    assert facts["certtmpl.container.present"] is True
    assert facts["certtmpl.container.object_count"] == 3
    assert facts["certtmpl.container.names_sha256"] == _names_digest(names)
    assert (
        facts["certtmpl.container.other_names_sha256"]
        == _names_digest(["Computer", "zz-other-template"])
    )
    assert facts["certtmpl.container.other_count"] == 2
    assert facts["certtmpl.container.unnamed_count"] == 0
    assert facts["certtmpl.target.present"] is True
    assert facts["certtmpl.target.name"] == TARGET
    assert facts["certtmpl.target.validity_period"] == VALIDITY_DN
    assert facts["certtmpl.target.validity_period_units"] == 4
    assert facts["certtmpl.target.schema_version"] == 2
    assert facts["certtmpl.target.cert_name_flag"] == 94208
    assert facts["certtmpl.target.key_flag"] == 16842752
    assert facts["certtmpl.target.sddl_len"] == len(SDDL)
    assert facts["certtmpl.target.sddl_sha256"] == _sha256(SDDL)
    # Membership is committed as digests only: no other template name
    # survives as a fact value.
    assert not [v for v in facts.values() if isinstance(v, str) and "Computer" in v]


def test_absent_target_leaves_detail_fields_empty() -> None:
    facts = _values(certtmpl_fact_tree(_observation(["Computer", "User"]), TARGET))
    assert facts["certtmpl.container.present"] is True
    assert facts["certtmpl.container.object_count"] == 2
    assert facts["certtmpl.container.other_count"] == 2
    assert facts["certtmpl.container.names_sha256"] == _names_digest(["Computer", "User"])
    assert facts["certtmpl.target.present"] is False
    detail_keys = FACT_KEYS - {
        "certtmpl.container.present",
        "certtmpl.container.object_count",
        "certtmpl.container.names_sha256",
        "certtmpl.container.other_names_sha256",
        "certtmpl.container.other_count",
        "certtmpl.container.unnamed_count",
        "certtmpl.target.present",
    }
    for key in detail_keys:
        assert facts[key] == "", key


def test_membership_digest_moves_when_any_other_name_changes() -> None:
    before = _values(certtmpl_fact_tree(_observation(["Computer", TARGET]), TARGET))
    after = _values(
        certtmpl_fact_tree(_observation(["Computer", TARGET, "zz-added-template"]), TARGET)
    )
    assert after["certtmpl.container.object_count"] == 3
    assert after["certtmpl.container.other_count"] == 2
    assert (
        before["certtmpl.container.names_sha256"]
        != after["certtmpl.container.names_sha256"]
    )
    assert (
        before["certtmpl.container.other_names_sha256"]
        != after["certtmpl.container.other_names_sha256"]
    )
    assert (
        after["certtmpl.container.names_sha256"]
        == _names_digest(["Computer", TARGET, "zz-added-template"])
    )


def test_membership_digest_ignores_target_attribute_edits() -> None:
    # Same membership, different target certificate: the container digests
    # must not move -- they freeze membership, not content.
    plain = _values(certtmpl_fact_tree(_observation([TARGET, "Computer"]), TARGET))
    edited = _values(
        certtmpl_fact_tree(
            _observation(
                [TARGET, "Computer"],
                overrides={TARGET: {"validity_period": "CN=OneYear,CN=Validity Periods,"
                                          "CN=Public Key Services,CN=Configuration,"
                                          "DC=zzlab,DC=invalid"}},
            ),
            TARGET,
        )
    )
    for key in (
        "certtmpl.container.names_sha256",
        "certtmpl.container.other_names_sha256",
        "certtmpl.container.object_count",
        "certtmpl.container.other_count",
    ):
        assert plain[key] == edited[key], key
    assert edited["certtmpl.target.validity_period"].startswith("CN=OneYear")


def test_unnamed_objects_are_counted_not_guessed() -> None:
    facts = _values(
        certtmpl_fact_tree(_observation(["Computer", TARGET], unnamed=2), TARGET)
    )
    assert facts["certtmpl.container.object_count"] == 4
    assert facts["certtmpl.container.unnamed_count"] == 2
    assert facts["certtmpl.container.other_count"] == 1
    # Unnamed objects contribute no name to either digest.
    assert facts["certtmpl.container.names_sha256"] == _names_digest(
        ["Computer", TARGET]
    )
    assert facts["certtmpl.container.other_names_sha256"] == _names_digest(["Computer"])


@pytest.mark.parametrize("sddl", [SDDL, SDDL_ALT])
def test_sddl_facts_round_trip_len_and_sha256(sddl: str) -> None:
    # The SDDL text itself is never transported; only its length and its
    # sha256 cross the wire, and both must survive the fact tree exactly.
    lines = _observation([TARGET], overrides={TARGET: {
        "sddl_len": str(len(sddl)),
        "sddl_sha256": _sha256(sddl),
    }})
    facts = _values(certtmpl_fact_tree(lines, TARGET))
    assert facts["certtmpl.target.sddl_len"] == len(sddl)
    assert facts["certtmpl.target.sddl_sha256"] == _sha256(sddl)


def test_fact_key_vocabulary_is_the_contract() -> None:
    facts = certtmpl_fact_tree(_observation([TARGET]), TARGET)
    assert set(facts) == FACT_KEYS
    absent = certtmpl_fact_tree(_absent_container(), TARGET)
    assert set(absent) == FACT_KEYS


def _tamper(lines: list[str], old: str, new: str) -> list[str]:
    return [new if line == old else line for line in lines]


@pytest.mark.parametrize(
    ("lines", "fragment"),
    [
        # A line outside the key=value shape.
        pytest.param(["container.present=1", "just text"], "not key=value",
                     id="no-separator"),
        # A key the vocabulary does not know.
        pytest.param([*_observation([TARGET]), "rogue_key=1"], "unknown key",
                     id="unknown-key"),
        # An attribute line before the first name line.
        pytest.param(["container.present=1", "schema_version=2"], "before any name",
                     id="attribute-without-name"),
        # Repeated container claim.
        pytest.param([*_observation([TARGET]), "container.object_count=1"], "repeats",
                     id="duplicate-container-line"),
        # Missing container claim.
        pytest.param(
            [line for line in _observation([TARGET]) if line != "container.unnamed_count=0"],
            "missing",
            id="missing-container-line",
        ),
        # Flag spelled anything but 0/1.
        pytest.param(_tamper(_observation([TARGET]), "container.present=1",
                            "container.present=yes"), "must be 0 or 1",
                     id="bad-flag"),
        # Count claim that is not an integer.
        pytest.param(_tamper(_observation([TARGET]), "container.object_count=1",
                            "container.object_count=many"), "must be an integer",
                     id="count-not-integer"),
        # Count claim the records cannot reproduce.
        pytest.param(_tamper(_observation([TARGET, "Computer"]),
                            "container.object_count=2", "container.object_count=3"),
                     "recompute", id="count-mismatch"),
        # Digest claim that does not match the recomputation.
        pytest.param(_tamper(_observation([TARGET]),
                            "container.names_sha256=" + _names_digest([TARGET]),
                            "container.names_sha256=" + "0" * 64),
                     "recompute", id="digest-mismatch"),
        # Digest claim that is not a digest at all.
        pytest.param(_tamper(_observation([TARGET]),
                            "container.names_sha256=" + _names_digest([TARGET]),
                            "container.names_sha256=not-hex"),
                     "64 lowercase hex", id="digest-not-hex"),
        # Two records case-folding to the target name.
        pytest.param(_observation([TARGET, "ZZ-TEMPLATE-CANDIDATE"]), "more than one",
                     id="duplicate-target-name"),
        # Target detail lines while the target is absent.
        pytest.param([*_observation(["Computer"]), "target.name=zz-phantom"],
                     "without presence", id="detail-without-presence"),
        # Presence flag without the detail lines.
        pytest.param(
            [line for line in _observation([TARGET]) if not line.startswith("target.")]
            + ["target.present=1"],
            "detail lines missing",
            id="presence-without-details",
        ),
        # Detail line disagreeing with the target's own record.
        pytest.param(_tamper(_observation([TARGET]), "target.schema_version=2",
                            "target.schema_version=9"), "disagrees",
                     id="target-detail-disagrees"),
        # Record attribute that is not an integer.
        pytest.param(_observation([TARGET], overrides={TARGET: {"schema_version": "two"}}),
                     "must be an integer", id="record-attr-not-integer"),
        # Record SDDL digest that is not a digest.
        pytest.param(_observation([TARGET], overrides={TARGET: {"sddl_sha256": "zz"}}),
                     "64 lowercase hex", id="record-sddl-not-hex"),
        # Named record with an attribute line missing.
        pytest.param(
            [line for line in _observation([TARGET]) if line != "key_flag=16842752"],
            "incomplete key set",
            id="record-missing-attribute",
        ),
        # The guest's fail-closed error line (oversized container et al.).
        pytest.param(["error=container object count 513 exceeds bound 512"],
                     "reported an error", id="guest-error-line"),
    ],
)
def test_malformed_streams_refuse(lines: list[str], fragment: str) -> None:
    with pytest.raises(ValueError, match=fragment):
        certtmpl_fact_tree(lines, TARGET)


# --- Structural checks on the PowerShell source --------------------------------


def test_certtmpl_collect_parses_under_windows_powershell_51() -> None:
    ps_scripts.parse_check(SCRIPT)


def test_certtmpl_collect_is_pure_ascii() -> None:
    ps_scripts.assert_ascii_only(SCRIPT)


def test_certtmpl_collect_refuses_oversized_containers_fail_closed() -> None:
    # The bound is 512 and the refusal is an error line, never a silent
    # truncation: the text-level guard pins the shape the observer's
    # error-line refusal (above) completes.
    text = SCRIPT.read_text(encoding="ascii")
    assert "$objectBound = 512" in text
    assert "-gt $objectBound" in text
    assert "exceeds bound" in text
    assert "Select-Object -First" not in text
