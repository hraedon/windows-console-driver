"""The certtmpl observer: transported Certificate-Template lines to facts.

Two layers are pinned. The fact tree (gpo_observers.certtmpl) turns one
collected line stream into the ``certtmpl.*`` vocabulary -- target and
source certification, membership committed as digests (never name lists),
and the guest/controller cross-check that refuses any container claim the
recomputation cannot reproduce. The validity encoding is the MEASURED one
(2026-09-19, live Server 2025 forest): pKIExpirationPeriod /
pKIOverlapPeriod 8-byte blobs of negative 100-nanosecond ticks,
transported as 16 uppercase hex characters, decoded to whole days with a
365-day year -- the DN-form msPKI-Validity-* attributes the first draft
assumed do not exist on this surface. The guest scripts
(tools/guest_scripts/certtmpl_collect.ps1, certtmpl_launch.ps1,
certtmpl_remove.ps1) are pinned structurally -- 5.1 parse, pure ASCII, the
fail-closed 512-object bound, the measured property set -- because no test
here touches a live host or a real AD. The executor-side collector
(wcd.exec_transaction._CerttmplCollector) routes the shipped collect
script through a scripted transport, and the cleanup wiring re-queries
strict absence by the RECORDED template name (the wmi GUID-discipline
analog). The envelope seam at the bottom pins the delta-prediction
discipline: every fact key the observer moves on the happy path must be
textually predicted by the capability envelope.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import ps_scripts
import pytest

from gpo_observers.certtmpl import certtmpl_fact_tree
from gpo_observers.facts import make_fact
from wcd.envelope import parse_envelope
from wcd.exec_transaction import ExecTransactionError, _CerttmplCollector
from wcd.runsheets import GestureExecutor, RunSheet, SheetContext, load_run_sheet

TARGET = "zz-template-candidate"
SOURCE = "Workstation"
SCRIPT = ps_scripts.REPO_ROOT / "tools" / "guest_scripts" / "certtmpl_collect.ps1"
LAUNCH_SCRIPT = ps_scripts.REPO_ROOT / "tools" / "guest_scripts" / "certtmpl_launch.ps1"
REMOVE_SCRIPT = ps_scripts.REPO_ROOT / "tools" / "guest_scripts" / "certtmpl_remove.ps1"
SHEET = ps_scripts.REPO_ROOT / "runsheets" / "certtmpl.duplicate_template.json"
CAPABILITY = ps_scripts.REPO_ROOT / "capabilities" / "certtmpl.duplicate_template.json"
DOMAIN = "zzlab.invalid"

# MEASURED blobs (live Server 2025 forest, 2026-09-19): little-endian
# signed int64 of NEGATIVE 100-nanosecond ticks, 365 days to a year.
ONE_YEAR_HEX = "004039872EE1FEFF"  # 365 days
FIVE_YEAR_HEX = "00401EA4E865FAFF"  # 1825 days
TWO_YEAR_HEX = "0080720E5DC2FDFF"  # 730 days
ONE_WEEK_HEX = "00C01BD77FFAFFFF"  # 7 days
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
        "certtmpl.target.expiration_period",
        "certtmpl.target.expiration_period_days",
        "certtmpl.target.overlap_period",
        "certtmpl.target.schema_version",
        "certtmpl.target.cert_name_flag",
        "certtmpl.target.key_flag",
        "certtmpl.target.sddl_len",
        "certtmpl.target.sddl_sha256",
        "certtmpl.source.present",
        "certtmpl.source.name",
        "certtmpl.source.expiration_period",
        "certtmpl.source.expiration_period_days",
        "certtmpl.source.overlap_period",
        "certtmpl.source.schema_version",
        "certtmpl.source.cert_name_flag",
        "certtmpl.source.key_flag",
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
    "expiration_period": ONE_YEAR_HEX,
    "overlap_period": ONE_WEEK_HEX,
    "schema_version": "2",
    "cert_name_flag": "94208",
    "key_flag": "16842752",
    "sddl_len": str(len(SDDL)),
    "sddl_sha256": _sha256(SDDL),
}


def _attr_lines(attrs: dict[str, str]) -> list[str]:
    return [
        "expiration_period=" + attrs["expiration_period"],
        "overlap_period=" + attrs["overlap_period"],
        "schema_version=" + attrs["schema_version"],
        "cert_name_flag=" + attrs["cert_name_flag"],
        "key_flag=" + attrs["key_flag"],
        "sddl_len=" + attrs["sddl_len"],
        "sddl_sha256=" + attrs["sddl_sha256"],
    ]


def _observation(
    names: list[str],
    target: str = TARGET,
    source: str = SOURCE,
    *,
    unnamed: int = 0,
    overrides: dict[str, dict[str, str]] | None = None,
) -> list[str]:
    """Mirror the guest script's emission for a synthetic container.

    The target and source blocks echo their records verbatim (the guest
    only transports); overrides mutate a record AND its block together,
    the way a real attribute change would appear twice on the wire.
    """
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
    for prefix, needle in (("target", target), ("source", source)):
        block_match = [name for name in readable if name.casefold() == needle.casefold()]
        if len(block_match) == 1:
            attrs = {**_DEFAULT_ATTRS, **per_name.get(block_match[0], {})}
            lines.append(prefix + ".present=1")
            lines.append(prefix + ".name=" + block_match[0])
            lines.extend(prefix + "." + line for line in _attr_lines(attrs))
        else:
            lines.append(prefix + ".present=0")
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
        "source.present=0",
    ]


def test_absent_container_is_the_pre_state_not_an_error() -> None:
    facts = _values(certtmpl_fact_tree(_absent_container(), TARGET, SOURCE))
    assert facts["certtmpl.container.present"] is False
    assert facts["certtmpl.container.object_count"] == 0
    assert facts["certtmpl.container.names_sha256"] == _names_digest([])
    assert facts["certtmpl.container.other_names_sha256"] == _names_digest([])
    assert facts["certtmpl.container.other_count"] == 0
    assert facts["certtmpl.container.unnamed_count"] == 0
    assert facts["certtmpl.target.present"] is False
    assert facts["certtmpl.target.name"] == ""
    assert facts["certtmpl.source.present"] is False
    assert facts["certtmpl.source.name"] == ""


def test_target_and_source_certified_membership_committed_as_digests() -> None:
    names = ["Administrator", SOURCE, TARGET]
    lines = _observation(names, overrides={TARGET: {"expiration_period": FIVE_YEAR_HEX}})
    facts = _values(certtmpl_fact_tree(lines, TARGET, SOURCE))
    assert facts["certtmpl.container.present"] is True
    assert facts["certtmpl.container.object_count"] == 3
    assert facts["certtmpl.container.names_sha256"] == _names_digest(names)
    assert (
        facts["certtmpl.container.other_names_sha256"]
        == _names_digest(["Administrator", SOURCE])
    )
    assert facts["certtmpl.container.other_count"] == 2
    assert facts["certtmpl.container.unnamed_count"] == 0
    assert facts["certtmpl.target.present"] is True
    assert facts["certtmpl.target.name"] == TARGET
    assert facts["certtmpl.target.expiration_period"] == FIVE_YEAR_HEX
    assert facts["certtmpl.target.expiration_period_days"] == 1825
    assert facts["certtmpl.target.overlap_period"] == ONE_WEEK_HEX
    assert facts["certtmpl.target.schema_version"] == 2
    assert facts["certtmpl.target.cert_name_flag"] == 94208
    assert facts["certtmpl.target.key_flag"] == 16842752
    assert facts["certtmpl.target.sddl_len"] == len(SDDL)
    assert facts["certtmpl.target.sddl_sha256"] == _sha256(SDDL)
    assert facts["certtmpl.source.present"] is True
    assert facts["certtmpl.source.name"] == SOURCE
    assert facts["certtmpl.source.expiration_period"] == ONE_YEAR_HEX
    assert facts["certtmpl.source.expiration_period_days"] == 365
    assert facts["certtmpl.source.overlap_period"] == ONE_WEEK_HEX
    assert facts["certtmpl.source.schema_version"] == 2
    assert facts["certtmpl.source.cert_name_flag"] == 94208
    assert facts["certtmpl.source.key_flag"] == 16842752
    # Membership is committed as digests only: no template name survives
    # as a fact value except the target's and the source's own name facts.
    names_in_values = [
        v for v in facts.values() if isinstance(v, str) and v in {"Administrator", SOURCE}
    ]
    assert names_in_values == [SOURCE]
    # The source's descriptor is deliberately NOT part of the claim: the
    # source block transports sddl_len/sddl_sha256 (validated on the wire),
    # but no source.sddl_* fact is emitted.
    assert "certtmpl.source.sddl_len" not in facts
    assert "certtmpl.source.sddl_sha256" not in facts


@pytest.mark.parametrize(
    ("blob", "days"),
    [
        (ONE_YEAR_HEX, 365),
        (FIVE_YEAR_HEX, 1825),
        (TWO_YEAR_HEX, 730),
        (ONE_WEEK_HEX, 7),
    ],
)
def test_measured_blobs_decode_to_whole_days(blob: str, days: int) -> None:
    # The measured encoding: negative 100-nanosecond ticks, little-endian
    # signed int64, 365 days to a year. 5*365 days is the envelope's
    # validity claim for validity_units=5 / validity_period='Years'.
    facts = _values(
        certtmpl_fact_tree(
            _observation([TARGET], overrides={TARGET: {"expiration_period": blob}}),
            TARGET,
            SOURCE,
        )
    )
    assert facts["certtmpl.target.expiration_period"] == blob
    assert facts["certtmpl.target.expiration_period_days"] == days


def test_absent_target_leaves_detail_fields_empty() -> None:
    facts = _values(
        certtmpl_fact_tree(_observation(["Administrator", SOURCE]), TARGET, SOURCE)
    )
    assert facts["certtmpl.container.present"] is True
    assert facts["certtmpl.container.object_count"] == 2
    assert facts["certtmpl.container.other_count"] == 2
    assert facts["certtmpl.container.names_sha256"] == _names_digest(
        ["Administrator", SOURCE]
    )
    assert facts["certtmpl.target.present"] is False
    for key in FACT_KEYS:
        if key.startswith("certtmpl.target.") and key != "certtmpl.target.present":
            assert facts[key] == "", key
    assert facts["certtmpl.source.present"] is True
    assert facts["certtmpl.source.name"] == SOURCE


def test_absent_source_leaves_detail_fields_empty() -> None:
    # The pre-state when the arg names a source the forest does not carry:
    # present=0, no detail facts, and a refusal-free observation (the
    # envelope's source.present require is what fails, loudly, post-side).
    facts = _values(
        certtmpl_fact_tree(_observation(["Administrator", TARGET]), TARGET, SOURCE)
    )
    assert facts["certtmpl.source.present"] is False
    for key in FACT_KEYS:
        if key.startswith("certtmpl.source.") and key != "certtmpl.source.present":
            assert facts[key] == "", key
    assert facts["certtmpl.target.present"] is True


def test_membership_digest_moves_when_any_other_name_changes() -> None:
    before = _values(
        certtmpl_fact_tree(_observation(["Administrator", SOURCE, TARGET]), TARGET, SOURCE)
    )
    after = _values(
        certtmpl_fact_tree(
            _observation(["Administrator", SOURCE, TARGET, "zz-added-template"]),
            TARGET,
            SOURCE,
        )
    )
    assert after["certtmpl.container.object_count"] == 4
    assert after["certtmpl.container.other_count"] == 3
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
        == _names_digest(["Administrator", SOURCE, TARGET, "zz-added-template"])
    )


def test_membership_digest_ignores_target_attribute_edits() -> None:
    # Same membership, different target certificate: the container digests
    # must not move -- they freeze membership, not content.
    plain = _values(
        certtmpl_fact_tree(_observation([TARGET, SOURCE]), TARGET, SOURCE)
    )
    edited = _values(
        certtmpl_fact_tree(
            _observation([TARGET, SOURCE], overrides={TARGET: {
                "expiration_period": TWO_YEAR_HEX,
            }}),
            TARGET,
            SOURCE,
        )
    )
    for key in (
        "certtmpl.container.names_sha256",
        "certtmpl.container.other_names_sha256",
        "certtmpl.container.object_count",
        "certtmpl.container.other_count",
    ):
        assert plain[key] == edited[key], key
    assert edited["certtmpl.target.expiration_period"] == TWO_YEAR_HEX
    assert edited["certtmpl.target.expiration_period_days"] == 730


def test_unnamed_objects_are_counted_not_guessed() -> None:
    facts = _values(
        certtmpl_fact_tree(
            _observation(["Administrator", SOURCE, TARGET], unnamed=2), TARGET, SOURCE
        )
    )
    assert facts["certtmpl.container.object_count"] == 5
    assert facts["certtmpl.container.unnamed_count"] == 2
    assert facts["certtmpl.container.other_count"] == 2
    # Unnamed objects contribute no name to either digest.
    assert facts["certtmpl.container.names_sha256"] == _names_digest(
        ["Administrator", SOURCE, TARGET]
    )
    assert facts["certtmpl.container.other_names_sha256"] == _names_digest(
        ["Administrator", SOURCE]
    )


@pytest.mark.parametrize("sddl", [SDDL, SDDL_ALT])
def test_sddl_facts_round_trip_len_and_sha256(sddl: str) -> None:
    # The SDDL text itself is never transported; only its length and its
    # sha256 cross the wire, and both must survive the fact tree exactly.
    lines = _observation([TARGET], overrides={TARGET: {
        "sddl_len": str(len(sddl)),
        "sddl_sha256": _sha256(sddl),
    }})
    facts = _values(certtmpl_fact_tree(lines, TARGET, SOURCE))
    assert facts["certtmpl.target.sddl_len"] == len(sddl)
    assert facts["certtmpl.target.sddl_sha256"] == _sha256(sddl)


def test_fact_key_vocabulary_is_the_contract() -> None:
    facts = certtmpl_fact_tree(
        _observation([SOURCE, TARGET], overrides={TARGET: {
            "expiration_period": FIVE_YEAR_HEX,
        }}),
        TARGET,
        SOURCE,
    )
    assert set(facts) == FACT_KEYS
    absent = certtmpl_fact_tree(_absent_container(), TARGET, SOURCE)
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
        # Missing source.present claim.
        pytest.param(
            [line for line in _observation([TARGET]) if line != "source.present=0"],
            "missing source.present",
            id="missing-source-present",
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
        pytest.param(_tamper(_observation([TARGET, SOURCE]),
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
        # Two records case-folding to the source name.
        pytest.param(_observation(["Administrator", TARGET, SOURCE, "WORKSTATION"]),
                     "source name matches more than one",
                     id="duplicate-source-name"),
        # Target detail lines while the target is absent.
        pytest.param([*_observation([SOURCE]), "target.name=zz-phantom"],
                     "without presence", id="detail-without-presence"),
        # Source detail lines while the source is absent.
        pytest.param([*_observation(["Administrator", TARGET]), "source.name=Workstation"],
                     "source detail lines without presence",
                     id="source-detail-without-presence"),
        # Presence flag without the detail lines.
        pytest.param(
            [line for line in _observation([TARGET]) if not line.startswith("target.")]
            + ["target.present=1"],
            "detail lines missing",
            id="presence-without-details",
        ),
        # Source presence flag without the detail lines.
        pytest.param(
            [line for line in _observation([SOURCE]) if not line.startswith("source.")]
            + ["source.present=1"],
            "source detail lines missing",
            id="source-presence-without-details",
        ),
        # Detail line disagreeing with the target's own record.
        pytest.param(_tamper(_observation([TARGET]), "target.schema_version=2",
                            "target.schema_version=9"), "disagrees",
                     id="target-detail-disagrees"),
        # Detail line disagreeing with the source's own record.
        pytest.param(_tamper(_observation([TARGET, SOURCE]), "source.key_flag=16842752",
                            "source.key_flag=1"), "disagrees",
                     id="source-detail-disagrees"),
        # Record attribute that is not an integer.
        pytest.param(_observation([TARGET], overrides={TARGET: {"schema_version": "two"}}),
                     "must be an integer", id="record-attr-not-integer"),
        # Record SDDL digest that is not a digest.
        pytest.param(_observation([TARGET], overrides={TARGET: {"sddl_sha256": "zz"}}),
                     "64 lowercase hex", id="record-sddl-not-hex"),
        # Validity blob in lowercase hex: a different transport than the
        # certified one.
        pytest.param(
            _observation([TARGET], overrides={TARGET: {
                "expiration_period": ONE_YEAR_HEX.lower()
            }}),
            "16 uppercase hex", id="record-blob-lowercase",
        ),
        # Validity blob of the wrong length.
        pytest.param(
            _observation([TARGET], overrides={TARGET: {"overlap_period": ONE_WEEK_HEX[:15]}}),
            "16 uppercase hex", id="record-blob-wrong-length",
        ),
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
        certtmpl_fact_tree(lines, TARGET, SOURCE)


def test_empty_template_or_source_name_refuses() -> None:
    with pytest.raises(ValueError, match="non-empty template name"):
        certtmpl_fact_tree(_observation([TARGET]), "", SOURCE)
    with pytest.raises(ValueError, match="non-empty source name"):
        certtmpl_fact_tree(_observation([TARGET]), TARGET, "")


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


def test_certtmpl_collect_uses_the_measured_property_set() -> None:
    # The MEASURED AD shape (2026-09-19): validity rides in the
    # pKIExpirationPeriod / pKIOverlapPeriod blobs; the DN-form
    # msPKI-Validity-* attributes do not exist on 2025-forest templates
    # and requesting them makes Get-ADObject fail outright. The property
    # list is pinned verbatim (the header comment legitimately NAMES the
    # absent attributes in prose).
    text = SCRIPT.read_text(encoding="ascii")
    assert "-Properties cn, displayName, pKIExpirationPeriod, pKIOverlapPeriod," in text
    assert "msPKI-Template-Schema-Version" in text
    assert "msPKI-Certificate-Name-Flag" in text
    assert "msPKI-Private-Key-Flag" in text
    assert "nTSecurityDescriptor" in text


def test_certtmpl_collect_requires_all_three_parameters() -> None:
    text = SCRIPT.read_text(encoding="ascii")
    assert "param([string]$Template, [string]$DomainDns, [string]$Source)" in text
    assert "Template, DomainDns and Source parameters are required" in text


def test_certtmpl_collect_refuses_ambiguous_name_matches_fail_closed() -> None:
    # The casefold match discipline is enforced guest-side too: more than
    # one casefold match for EITHER the target or the source is an error
    # line and exit 2, never a silently chosen record.
    text = SCRIPT.read_text(encoding="ascii")
    assert "target name matches more than one template" in text
    assert "source name matches more than one template" in text


def test_categories_are_declared_not_unclassified() -> None:
    # The surface wiring declares the whole certtmpl.* vocabulary in the
    # category table (structural membership and source context, content
    # target attributes); an undeclared key would surface every change as
    # a violation.
    facts = certtmpl_fact_tree(_observation([SOURCE, TARGET]), TARGET, SOURCE)
    for fact in facts.values():
        assert fact.category != "unclassified", fact.key
    assert make_fact("certtmpl.container.other_names_sha256", None).category == "structural"
    assert make_fact("certtmpl.target.expiration_period_days", None).category == "content"
    assert make_fact("certtmpl.target.overlap_period", None).category == "content"
    assert make_fact("certtmpl.target.sddl_sha256", None).category == "content"
    assert make_fact("certtmpl.source.expiration_period_days", None).category == "structural"
    assert make_fact("certtmpl.source.key_flag", None).category == "structural"


# --- Envelope seam: delta prediction over the emitted vocabulary ----------------


# The happy path's mutating facts, hardcoded: the pre-state carries the
# source and the unrelated objects, the post-state adds the target with a
# 5-year expiration. Anything the observer newly moves pre->post lands here
# and must be predicted by the capability envelope below.
HAPPY_PATH_CHANGING_KEYS = (
    "certtmpl.container.names_sha256",
    "certtmpl.container.object_count",
    "certtmpl.target.cert_name_flag",
    "certtmpl.target.expiration_period",
    "certtmpl.target.expiration_period_days",
    "certtmpl.target.key_flag",
    "certtmpl.target.name",
    "certtmpl.target.overlap_period",
    "certtmpl.target.present",
    "certtmpl.target.schema_version",
    "certtmpl.target.sddl_len",
    "certtmpl.target.sddl_sha256",
)


def test_every_happy_path_changing_fact_key_is_predicted_by_the_envelope() -> None:
    """The unclassified-change rule, pinned statically.

    Every fact key the observer can emit that CHANGES on the happy path
    must be textually predicted by the capability envelope -- a require
    clause's fact key, or a post-side reference inside a require/derive
    predicate -- else the delta engine records an unclassified-change
    violation at qualification time. This is the registry-discipline test:
    it fails the moment someone adds an observer fact without adding the
    envelope clause that predicts it.
    """
    pre = _values(
        certtmpl_fact_tree(_observation(["Administrator", SOURCE]), TARGET, SOURCE)
    )
    post = _values(
        certtmpl_fact_tree(
            _observation(
                ["Administrator", SOURCE, TARGET],
                overrides={TARGET: {"expiration_period": FIVE_YEAR_HEX}},
            ),
            TARGET,
            SOURCE,
        )
    )
    changing = tuple(
        sorted(key for key in set(pre) | set(post) if pre.get(key) != post.get(key))
    )
    assert changing == HAPPY_PATH_CHANGING_KEYS

    envelope = parse_envelope(
        json.loads(CAPABILITY.read_text(encoding="utf-8"))["envelope"]
    )
    predicted: set[str] = set()
    for require_clause in envelope.require:
        predicted.add(require_clause.fact_key)
        for path in require_clause.predicate.referenced_paths():
            if path.startswith("post.") or path.startswith("facts."):
                predicted.add(path.removeprefix("post.").removeprefix("facts."))
    for derive_clause in envelope.derive:
        for path in derive_clause.relation.referenced_paths():
            if path.startswith("post.") or path.startswith("facts."):
                predicted.add(path.removeprefix("post.").removeprefix("facts."))
    unpredicted = [
        key
        for key in changing
        if not any(key == p or key.startswith(p + ".") for p in predicted)
    ]
    assert not unpredicted, f"envelope does not predict changing keys: {unpredicted}"


# --- Executor-side collector (surface wiring) -----------------------------------


class _ScriptedGuestTransport:
    """Stand-in for SessionTransport: one canned ``key=value`` line stream."""

    def __init__(self, lines: list[str]) -> None:
        self._lines = lines
        self.calls: list[dict[str, object]] = []

    @property
    def vm_name(self) -> str:
        return "zz-vm"

    def guest(
        self, script: str, args: list[object] | None = None, *, timeout: float = 180.0
    ) -> str:
        assert "CN=Certificate Templates" in script, (
            "certtmpl collector must query the forest templates container"
        )
        self.calls.append({"script": script, "args": list(args or [])})
        return "\n".join(self._lines) + "\n"


def test_collector_runs_the_shipped_collect_script_and_parses_lines() -> None:
    transport = _ScriptedGuestTransport(
        _observation([SOURCE, TARGET], overrides={TARGET: {
            "expiration_period": FIVE_YEAR_HEX,
        }})
    )
    facts = _values(
        _CerttmplCollector().collect(
            object(),  # type: ignore[arg-type]
            {
                "template_name": TARGET,
                "domain_dns": DOMAIN,
                "source_template": SOURCE,
            },
            transport,  # type: ignore[arg-type]
        )
    )
    assert facts["certtmpl.container.present"] is True
    assert facts["certtmpl.container.object_count"] == 2
    assert facts["certtmpl.target.present"] is True
    assert facts["certtmpl.target.name"] == TARGET
    assert facts["certtmpl.target.expiration_period_days"] == 1825
    assert facts["certtmpl.source.present"] is True
    assert facts["certtmpl.source.name"] == SOURCE
    # The shipped artifact crosses the wire verbatim with the recorded
    # params interpolated positionally (Template, DomainDns, Source) --
    # no second inline copy of the script.
    assert transport.calls[0]["script"] == SCRIPT.read_text(encoding="utf-8-sig")
    assert transport.calls[0]["args"] == [TARGET, DOMAIN, SOURCE]


def test_collector_refuses_the_guests_error_line() -> None:
    transport = _ScriptedGuestTransport(
        ["error=container object count 513 exceeds bound 512"]
    )
    with pytest.raises(ExecTransactionError, match="exceeds bound"):
        _CerttmplCollector().collect(
            object(),  # type: ignore[arg-type]
            {
                "template_name": TARGET,
                "domain_dns": DOMAIN,
                "source_template": SOURCE,
            },
            transport,  # type: ignore[arg-type]
        )


def test_collector_requires_all_three_params() -> None:
    transport = _ScriptedGuestTransport(_observation([TARGET]))
    with pytest.raises(ExecTransactionError, match="source_template"):
        _CerttmplCollector().collect(
            object(),  # type: ignore[arg-type]
            {"template_name": TARGET, "domain_dns": DOMAIN},
            transport,  # type: ignore[arg-type]
        )


# --- Cleanup wiring: recorded-name strict-absence re-query ----------------------


class _GuestOnlyTransport:
    """Stand-in for SessionTransport: answers guest scripts, records them."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def guest(
        self, script: str, args: list[object] | None = None, *, timeout: float = 180.0
    ) -> str:
        self.calls.append({"script": script, "args": list(args or [])})
        return "removed=zz\n"


def test_certtmpl_cleanup_requery_names_the_recorded_template() -> None:
    """The sheet's cleanup step routes certtmpl_remove over the transport with
    the RECORDED template name as its only argument -- the wmi GUID-discipline
    analog: the strict-absence re-query is keyed by the recorded identity,
    never a wildcard that would count unrelated templates as residue."""
    sheet = load_run_sheet(SHEET)
    step = next(s for s in sheet.steps if s.params.get("script") == "certtmpl_remove")
    transport = _GuestOnlyTransport()
    executor = GestureExecutor(
        transport,  # type: ignore[arg-type]
        guest_scripts_dir=SCRIPT.parent,
        host_scripts_dir=ps_scripts.REPO_ROOT / "tools" / "host_scripts",
    )
    ctx = SheetContext(inputs={"template_name": TARGET})
    executor.execute(
        RunSheet(name=f"{sheet.name}:cleanup", surface=sheet.surface, steps=(step,)), ctx
    )
    assert len(transport.calls) == 1
    assert transport.calls[0]["script"] == REMOVE_SCRIPT.read_text(encoding="utf-8-sig")
    assert transport.calls[0]["args"] == [TARGET]


def test_certtmpl_remove_parses_under_windows_powershell_51() -> None:
    ps_scripts.parse_check(REMOVE_SCRIPT)


def test_certtmpl_remove_is_pure_ascii() -> None:
    ps_scripts.assert_ascii_only(REMOVE_SCRIPT)


def test_certtmpl_remove_deletes_then_requeries_by_the_name() -> None:
    # Remove-ADObject under the configuration partition with no confirmation
    # prompt, then a second query keyed on the SAME name filter: the strict
    # absence evidence, reported as absent=/removed=/remove_incomplete=.
    text = REMOVE_SCRIPT.read_text(encoding="ascii")
    assert "configurationNamingContext" in text
    assert "CN=Certificate Templates,CN=Public Key Services,CN=Services," in text
    assert "Remove-ADObject" in text
    assert "-Confirm:$false" in text
    assert text.count("$_.cn -eq $Template") == 2
    assert "absent=$Template" in text
    assert "removed=$Template" in text
    assert "remove_incomplete=$Template" in text


def test_certtmpl_launch_parses_under_windows_powershell_51() -> None:
    ps_scripts.parse_check(LAUNCH_SCRIPT)


def test_certtmpl_launch_is_pure_ascii() -> None:
    ps_scripts.assert_ascii_only(LAUNCH_SCRIPT)


def test_certtmpl_launch_clones_the_helper_task_for_certtmpl_msc() -> None:
    # The scheduled-task-XML domain-SID trick is load-bearing (gpmc_launch):
    # clone the committed WCDHelper task's XML and swap only the Actions
    # subtree, so certtmpl.msc runs elevated on the console desktop with no
    # UAC mid-flight.
    text = LAUNCH_SCRIPT.read_text(encoding="ascii")
    assert "'WCDHelper'" in text
    assert "Export-ScheduledTask" in text
    assert "certtmpl.msc" in text
    assert "WCDLaunchCertTmpl" in text
