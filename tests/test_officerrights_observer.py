"""The officerrights observer: transported CA configuration lines to facts.

Four layers are pinned. The fact tree (``gpo_observers.officerrights``)
turns one collected line stream into the ``certsrv.*`` vocabulary and refuses
the disagreements that matter on this surface: a read of a machine the plan
did not name, an internally inconsistent presence claim, a split between the
two independent read channels, and -- since revision 2 -- a plan whose CA
host is not in the directory-derived CA host set (the window-11 gap: a wrong
CA named by the plan itself drove gesture and oracle alike and only the
run-sheet's targeted frame caught it). The guest scripts
(``officerrights_collect.ps1``, ``officerrights_remove.ps1``,
``certsrv_launch.ps1``) are pinned structurally -- 5.1 parse, pure ASCII --
because nothing here touches a live host, a real CA, or a real registry. The
executor-side collector (``wcd.exec_transaction._OfficerRightsCollector``)
routes the shipped collect script through a scripted transport, and the
cleanup wiring re-queries strict absence naming the RECORDED CA.

The absence cases carry most of the weight here, which is unusual for an
observer test and deliberate: this capability's pre-state is a value that
does not exist, and an observer that cannot tell "not there" from "could not
look" would certify a run that never touched anything. The directory cases
carry the revision-2 weight for the same reason: the derived host set is
what licenses the read at all, so a plan host the forest does not publish
must refuse BEFORE the mutation the capability exists to certify.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import ps_scripts
import pytest

from gpo_observers.facts import make_fact
from gpo_observers.officerrights import OfficerRightsError, officerrights_fact_tree
from wcd.exec_transaction import ExecTransactionError, _OfficerRightsCollector
from wcd.runsheets import GestureExecutor, RunSheet, SheetContext, load_run_sheet

CA_HOST = "LabCA01.zzlab.invalid"
CA_NAME = "zz Issuing CA 01"
CONSOLE = "zz-console"

SCRIPT = ps_scripts.REPO_ROOT / "tools" / "guest_scripts" / "officerrights_collect.ps1"
REMOVE_SCRIPT = ps_scripts.REPO_ROOT / "tools" / "guest_scripts" / "officerrights_remove.ps1"
LAUNCH_SCRIPT = ps_scripts.REPO_ROOT / "tools" / "guest_scripts" / "certsrv_launch.ps1"
SHEET = ps_scripts.REPO_ROOT / "runsheets" / "certsrv.restrict_certificate_manager.json"
CAPABILITY = ps_scripts.REPO_ROOT / "capabilities" / "certsrv.restrict_certificate_manager.json"

SECURITY_SHA = "a" * 64
PUBLISHED_SHA = "b" * 64
NAMES_SHA = "c" * 64
RIGHTS_SHA = "d" * 64
DECODED_SHA = "e" * 64

# The digest convention the collector and the controller share: sha256 over
# the LF-joined sorted host list. A one-CA forest digests to this.
HOSTS_SHA = hashlib.sha256(CA_HOST.encode("utf-8")).hexdigest()
OTHER_HOST = "LabCA02.zzlab.invalid"


def _hosts_sha(*hosts: str) -> str:
    return hashlib.sha256("\n".join(hosts).encode("utf-8")).hexdigest()


# certutil's rc for a value that is not there, as the estate reported it.
NOT_FOUND_RC = -2147024894


def _values(facts: dict[str, Any]) -> dict[str, Any]:
    return {key: fact.value for key, fact in facts.items()}


def _absent(**overrides: str) -> list[str]:
    """The pre-state: an unrestricted CA, where OfficerRights does not exist.

    The directory block is the revision-2 shape: a one-CA forest whose single
    published CA host is the plan's own -- the happy path, since the fixture
    stream must parse before anything can refuse.
    """
    base = {
        "ca.host": CA_HOST,
        "ca.name": CA_NAME,
        "ca.directory.count": "1",
        "ca.directory.hosts": CA_HOST,
        "ca.directory.hosts_sha256": HOSTS_SHA,
        "collector.ran_on": CONSOLE,
        "config.key_present": "True",
        "config.value_count": "49",
        "config.value_names_sha256": NAMES_SHA,
        "officerrights.present": "False",
        "officerrights.kind": "",
        "officerrights.bytes": "0",
        "officerrights.sha256": "",
        "officerrights.certutil_rc": str(NOT_FOUND_RC),
        "officerrights.decoded_present": "False",
        "officerrights.decoded_rows": "0",
        "officerrights.decoded_sha256": "",
        "security.bytes": "320",
        "security.sha256": SECURITY_SHA,
        "published.count": "9",
        "published.names_sha256": PUBLISHED_SHA,
    }
    base.update(overrides)
    return [f"{key}={value}" for key, value in base.items()]


def _present(**overrides: str) -> list[str]:
    """The post-state: the console has created the restriction."""
    return _absent(
        **{
            "config.value_count": "50",
            "config.value_names_sha256": "f" * 64,
            "officerrights.present": "True",
            "officerrights.kind": "Binary",
            "officerrights.bytes": "96",
            "officerrights.sha256": RIGHTS_SHA,
            "officerrights.certutil_rc": "0",
            "officerrights.decoded_present": "True",
            "officerrights.decoded_rows": "2",
            "officerrights.decoded_sha256": DECODED_SHA,
            **overrides,
        }
    )


# --- The pre-state: absence is an observation, not a failure -------------------


def test_absent_officerrights_is_the_pre_state_not_an_error() -> None:
    facts = _values(officerrights_fact_tree(_absent(), CA_HOST, CA_NAME))
    assert facts["certsrv.officerrights.present"] is False
    assert facts["certsrv.officerrights.bytes"] == 0
    assert facts["certsrv.officerrights.sha256"] == ""
    # certutil legitimately fails for a value that is not there; the rc is
    # carried as a fact rather than swallowed, because the capability's
    # envelope predicts it moving to 0.
    assert facts["certsrv.officerrights.certutil_rc"] == NOT_FOUND_RC
    assert facts["certsrv.officerrights.decoded_present"] is False
    # The forbid scopes are observable in the pre-state, which is what makes
    # them checkable at all.
    assert facts["certsrv.security.sha256"] == SECURITY_SHA
    assert facts["certsrv.published.names_sha256"] == PUBLISHED_SHA


def test_absence_is_decided_from_the_value_name_list_not_a_failed_read() -> None:
    """A read that errored is not evidence of absence.

    The collector reports presence from the key's value-name list. If the
    configuration KEY itself could not be opened, the observation refuses
    rather than reporting an absent value -- otherwise "could not look"
    would certify as "not there", and a run that never reached the CA would
    look exactly like a clean pre-state.
    """
    with pytest.raises(OfficerRightsError, match="CA configuration key"):
        officerrights_fact_tree(_absent(**{"config.key_present": "False"}), CA_HOST, CA_NAME)


def test_post_state_certifies_the_value_through_both_channels() -> None:
    facts = _values(officerrights_fact_tree(_present(), CA_HOST, CA_NAME))
    assert facts["certsrv.officerrights.present"] is True
    assert facts["certsrv.officerrights.kind"] == "Binary"
    assert facts["certsrv.officerrights.bytes"] == 96
    assert facts["certsrv.officerrights.sha256"] == RIGHTS_SHA
    assert facts["certsrv.officerrights.decoded_present"] is True
    assert facts["certsrv.officerrights.decoded_rows"] == 2
    assert facts["certsrv.officerrights.certutil_rc"] == 0


# --- The subject check: the oracle read the machine the plan named --------------


def test_reading_the_wrong_machine_refuses_rather_than_certifying() -> None:
    """The failure this surface invents, and the check that catches it.

    Every capability before this one actuated and observed the same guest, so
    a fact set implicitly named its own subject. Here it does not: the gesture
    drives a console on one machine and the mutation lands on another. A
    correctly-resolved read of the WRONG CA would otherwise be indistinguishable
    from evidence.
    """
    with pytest.raises(OfficerRightsError, match="plan named"):
        officerrights_fact_tree(_present(), "LabCA99.zzlab.invalid", CA_NAME)
    with pytest.raises(OfficerRightsError, match="plan named"):
        officerrights_fact_tree(_present(), CA_HOST, "zz Some Other CA")


def test_host_match_is_case_insensitive_but_ca_name_is_not() -> None:
    """DNS names are case-insensitive; a CA common name is a directory CN."""
    facts = _values(officerrights_fact_tree(_present(), CA_HOST.upper(), CA_NAME))
    assert facts["certsrv.ca.host"] == CA_HOST
    with pytest.raises(OfficerRightsError, match="plan named"):
        officerrights_fact_tree(_present(), CA_HOST, CA_NAME.upper())


def test_the_machine_read_and_the_machine_that_read_it_are_both_facts() -> None:
    facts = _values(officerrights_fact_tree(_present(), CA_HOST, CA_NAME))
    assert facts["certsrv.ca.host"] == CA_HOST
    assert facts["certsrv.ca.observed_from"] == CONSOLE
    assert facts["certsrv.ca.host"] != facts["certsrv.ca.observed_from"], (
        "the whole point of these two keys is that a reviewer can tell them apart"
    )


# --- Revision 2: the CA host is derived from the directory, not echoed ---------


def test_the_derived_host_set_and_membership_are_facts() -> None:
    """The happy path: the plan's host is one the forest publishes.

    The derived set is committed as count+digest (never the host list) and
    membership as its own fact, so the record carries the claim the
    capability's require clause pins.
    """
    facts = _values(officerrights_fact_tree(_present(), CA_HOST, CA_NAME))
    assert facts["certsrv.ca.directory.count"] == 1
    assert facts["certsrv.ca.directory.hosts_sha256"] == HOSTS_SHA
    assert facts["certsrv.ca.directory.member"] is True


def test_membership_holds_in_a_multi_ca_forest_and_across_case() -> None:
    """The derivation does not assume a one-CA forest, and DNS ignores case."""
    lines = _present(
        **{
            "ca.directory.count": "2",
            "ca.directory.hosts": f"{OTHER_HOST};{CA_HOST}",
            "ca.directory.hosts_sha256": _hosts_sha(OTHER_HOST, CA_HOST),
        }
    )
    facts = _values(officerrights_fact_tree(lines, CA_HOST, CA_NAME))
    assert facts["certsrv.ca.directory.count"] == 2
    assert facts["certsrv.ca.directory.member"] is True
    # The plan's argument may differ in case from the directory's spelling;
    # the membership comparison casefolds like the host echo check.
    upper = _present(
        **{
            "ca.directory.hosts": CA_HOST.lower(),
            "ca.directory.hosts_sha256": _hosts_sha(CA_HOST.lower()),
        }
    )
    facts = _values(officerrights_fact_tree(upper, CA_HOST, CA_NAME))
    assert facts["certsrv.ca.directory.member"] is True


def test_a_plan_host_the_forest_does_not_publish_refuses() -> None:
    """The gap revision 2 exists to close, stated as the test that closes it.

    Revision 1's subject check could not catch this: the collector is
    invoked with the plan's own ca_host, so the echo agrees all the way
    down and a correctly-resolved read of the WRONG machine certified as
    evidence. The derived set is independent of the plan -- the directory
    published two CAs and the plan named neither -- so the observation
    refuses. The pre-oracle runs before prepare, arm and the commit, which
    is what makes this a refusal BEFORE any mutation rather than a clause
    failure after one.
    """
    lines = _present(
        **{
            "ca.directory.count": "2",
            "ca.directory.hosts": f"{OTHER_HOST};LabCA03.zzlab.invalid",
            "ca.directory.hosts_sha256": _hosts_sha(OTHER_HOST, "LabCA03.zzlab.invalid"),
        }
    )
    with pytest.raises(OfficerRightsError, match="not in the directory-derived"):
        officerrights_fact_tree(lines, CA_HOST, CA_NAME)
    # The refusal names both sides, so the operator can see which was wrong.
    with pytest.raises(OfficerRightsError, match="LabCA02"):
        officerrights_fact_tree(lines, CA_HOST, CA_NAME)


def test_an_empty_derived_set_refuses_rather_than_certifying() -> None:
    """A directory with no published CA is a refusal, not a vacuous pass.

    An empty set contains no members, so membership fails -- but an observer
    that treated the empty transport as 'nothing to check' would turn a
    broken derivation (wrong container, no connectivity residue) into the
    strongest possible echo. The refusal must happen, and it must say the
    set was empty.
    """
    lines = _present(
        **{
            "ca.directory.count": "0",
            "ca.directory.hosts": "",
            "ca.directory.hosts_sha256": _hosts_sha(),
        }
    )
    with pytest.raises(OfficerRightsError, match="empty set"):
        officerrights_fact_tree(lines, CA_HOST, CA_NAME)


def test_the_derived_count_and_digest_are_recomputed_and_refused() -> None:
    """The two-pass discipline: the transported list is the record, the
    claimed count and digest are recomputed from it, and a disagreement
    refuses -- a collector that shrank or reordered the set cannot make a
    wrong host look like a member.
    """
    with pytest.raises(OfficerRightsError, match=r"ca\.directory\.count is 2 but"):
        officerrights_fact_tree(
            _present(**{"ca.directory.count": "2"}), CA_HOST, CA_NAME
        )
    with pytest.raises(OfficerRightsError, match="hosts_sha256 disagrees"):
        officerrights_fact_tree(
            _present(**{"ca.directory.hosts_sha256": RIGHTS_SHA}), CA_HOST, CA_NAME
        )


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"ca.directory.hosts": f";{CA_HOST}"}, "empty entry"),
        ({"ca.directory.hosts_sha256": ""}, "digest is empty"),
    ],
)
def test_malformed_directory_blocks_refuse(overrides: dict[str, str], fragment: str) -> None:
    with pytest.raises(OfficerRightsError, match=fragment):
        officerrights_fact_tree(_present(**overrides), CA_HOST, CA_NAME)


def test_the_capability_pins_membership_in_its_envelope() -> None:
    """The require clause is the record-facing statement of the refusal.

    The fact tree refuses a non-member before any mutation; the envelope
    clause is what makes a banked record carry the claim -- satisfied --
    without a reviewer having to read the observer source. Pinned here so a
    future edit cannot drop the clause quietly.
    """
    capability = json.loads(CAPABILITY.read_text(encoding="utf-8"))
    assert capability["revision"] == 2
    member_clauses = [
        clause
        for clause in capability["envelope"]["require"]
        if clause["fact"] == "certsrv.ca.directory.member"
    ]
    assert member_clauses == [
        {
            "fact": "certsrv.ca.directory.member",
            "predicate": "post['certsrv.ca.directory.member'] == True",
        }
    ]


# --- Disagreements the observer refuses instead of averaging -------------------


def test_registry_holds_a_value_the_ca_will_not_decode() -> None:
    """The state a service restart would explain -- surfaced, not smoothed."""
    lines = _present(
        **{
            "officerrights.decoded_present": "False",
            "officerrights.decoded_rows": "0",
            "officerrights.decoded_sha256": "",
            "officerrights.certutil_rc": str(NOT_FOUND_RC),
        }
    )
    with pytest.raises(OfficerRightsError, match="two channels disagree"):
        officerrights_fact_tree(lines, CA_HOST, CA_NAME)


def test_ca_decodes_a_value_the_registry_does_not_hold() -> None:
    lines = _absent(
        **{
            "officerrights.decoded_present": "True",
            "officerrights.decoded_rows": "2",
            "officerrights.decoded_sha256": DECODED_SHA,
            "officerrights.certutil_rc": "0",
        }
    )
    with pytest.raises(OfficerRightsError, match="registry does not hold"):
        officerrights_fact_tree(lines, CA_HOST, CA_NAME)


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"officerrights.sha256": ""}, "no digest or zero length"),
        ({"officerrights.bytes": "0"}, "no digest or zero length"),
    ],
)
def test_present_but_empty_refuses(overrides: dict[str, str], fragment: str) -> None:
    with pytest.raises(OfficerRightsError, match=fragment):
        officerrights_fact_tree(_present(**overrides), CA_HOST, CA_NAME)


def test_absent_but_carrying_a_digest_refuses() -> None:
    with pytest.raises(OfficerRightsError, match="absent but carries"):
        officerrights_fact_tree(
            _absent(**{"officerrights.sha256": RIGHTS_SHA}), CA_HOST, CA_NAME
        )


# --- Line-protocol discipline ---------------------------------------------------


@pytest.mark.parametrize(
    ("lines", "fragment"),
    [
        (["error=remote registry on host refused: access denied"], "collector refused"),
        ([*_absent(), "surprise=1"], "unknown key"),
        ([*_absent(), "ca.host=" + CA_HOST], "twice"),
        (_absent()[:-1], "incomplete"),
        (["not a pair"], "not key=value"),
        (_absent(**{"officerrights.present": "yes"}), "must be True or False"),
        (_absent(**{"config.value_count": "-1"}), "must not be negative"),
        (_absent(**{"config.value_count": "many"}), "must be an integer"),
        (_absent(**{"security.sha256": "SHORT"}), "lowercase sha256"),
        (_absent(**{"security.sha256": "A" * 64}), "lowercase sha256"),
        (_absent(**{"security.sha256": ""}), "Security descriptor digest is empty"),
        (_absent(**{"officerrights.certutil_rc": "n/a"}), "must be an integer"),
    ],
)
def test_malformed_streams_refuse(lines: list[str], fragment: str) -> None:
    with pytest.raises(OfficerRightsError, match=fragment):
        officerrights_fact_tree(lines, CA_HOST, CA_NAME)


def test_empty_ca_arguments_refuse() -> None:
    with pytest.raises(OfficerRightsError, match="CA host and name"):
        officerrights_fact_tree(_absent(), "", CA_NAME)


def test_fact_key_vocabulary_is_the_contract() -> None:
    """Every emitted key, pinned. A new one must be declared, not discovered."""
    assert set(officerrights_fact_tree(_present(), CA_HOST, CA_NAME)) == {
        "certsrv.ca.host",
        "certsrv.ca.name",
        "certsrv.ca.observed_from",
        "certsrv.ca.directory.count",
        "certsrv.ca.directory.hosts_sha256",
        "certsrv.ca.directory.member",
        "certsrv.config.value_count",
        "certsrv.config.value_names_sha256",
        "certsrv.officerrights.present",
        "certsrv.officerrights.kind",
        "certsrv.officerrights.bytes",
        "certsrv.officerrights.sha256",
        "certsrv.officerrights.decoded_present",
        "certsrv.officerrights.decoded_rows",
        "certsrv.officerrights.decoded_sha256",
        "certsrv.officerrights.certutil_rc",
        "certsrv.security.bytes",
        "certsrv.security.sha256",
        "certsrv.published.count",
        "certsrv.published.names_sha256",
    }


def test_categories_are_declared_not_unclassified() -> None:
    """An undeclared key that later changes surfaces as a violation.

    That is the right default, and exactly why every key this observer emits
    must be in the declared table: the delta engine treats a change to an
    unclassified fact as a violation, so leaving one undeclared would make
    the capability's own intended mutation read as a blast-radius breach.
    """
    for key, fact in officerrights_fact_tree(_present(), CA_HOST, CA_NAME).items():
        assert fact.category != "unclassified", f"{key} is not in the declared table"
        assert make_fact(key, fact.value).category == fact.category


def test_the_bytes_themselves_never_cross_the_wire() -> None:
    """The value is opaque and stays that way: length and digest only.

    The same discipline the template surface applies to nTSecurityDescriptor.
    A capability that certifies "this configuration exists with this digest"
    can support that claim; one that transported the bytes would be inviting
    a later revision to parse an undocumented layout and believe the result.
    """
    text = SCRIPT.read_text(encoding="utf-8-sig")
    assert "GetValue('OfficerRights')" in text
    for leak in ("BitConverter]::ToString($bytes", "-join ''"):
        assert leak not in text, f"collect script looks like it transports bytes: {leak}"


# --- Executor-side collector ----------------------------------------------------


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
        assert "CertSvc\\Configuration" in script, (
            "officerrights collector must read the CA's CertSvc configuration key"
        )
        self.calls.append({"script": script, "args": list(args or [])})
        return "\n".join(self._lines) + "\n"


def test_collector_runs_the_shipped_collect_script_and_parses_lines() -> None:
    transport = _ScriptedGuestTransport(_present())
    facts = _values(
        _OfficerRightsCollector().collect(
            object(),  # type: ignore[arg-type]
            {"ca_host": CA_HOST, "ca_name": CA_NAME},
            transport,  # type: ignore[arg-type]
        )
    )
    assert facts["certsrv.officerrights.present"] is True
    assert facts["certsrv.ca.host"] == CA_HOST
    # The shipped artifact crosses the wire verbatim with the recorded params
    # interpolated positionally -- no second inline copy of the script.
    assert transport.calls[0]["script"] == SCRIPT.read_text(encoding="utf-8-sig")
    assert transport.calls[0]["args"] == [CA_HOST, CA_NAME]


def test_collector_refuses_the_guests_error_line() -> None:
    transport = _ScriptedGuestTransport(
        ["error=remote registry on LabCA01 refused: Access is denied"]
    )
    with pytest.raises(ExecTransactionError, match="Access is denied"):
        _OfficerRightsCollector().collect(
            object(),  # type: ignore[arg-type]
            {"ca_host": CA_HOST, "ca_name": CA_NAME},
            transport,  # type: ignore[arg-type]
        )


def test_collector_requires_both_params() -> None:
    transport = _ScriptedGuestTransport(_present())
    with pytest.raises(ExecTransactionError, match="ca_host and ca_name"):
        _OfficerRightsCollector().collect(
            object(),  # type: ignore[arg-type]
            {"ca_host": CA_HOST},
            transport,  # type: ignore[arg-type]
        )


# --- Cleanup wiring: recorded-CA strict-absence re-query ------------------------


class _RecordingGuestTransport:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def guest(
        self, script: str, args: list[object] | None = None, *, timeout: float = 180.0
    ) -> str:
        self.calls.append({"script": script, "args": list(args or [])})
        return "present_before=True\nremoved=True\nabsent_registry=True\nabsent_certutil=True\n"


def test_cleanup_requery_names_the_recorded_ca() -> None:
    """Cleanup must target the CA the ARGUMENTS named, not a default.

    The GUID discipline from the WMI surface, transposed: the thing being
    removed lives on another machine, so a cleanup that resolved its target
    from anywhere but the recorded arguments could remove the right value
    from the wrong CA -- or, worse, report success having removed nothing.
    """
    sheet = load_run_sheet(SHEET)
    cleanup = [
        step
        for step in sheet.steps
        if step.action == "guest" and step.params.get("script") == "officerrights_remove"
    ]
    assert len(cleanup) == 1, "exactly one officerrights cleanup step is expected"
    assert cleanup[0].params["args"] == ["{args.ca_host}", "{args.ca_name}"]

    transport = _RecordingGuestTransport()
    executor = GestureExecutor(
        transport,  # type: ignore[arg-type]
        guest_scripts_dir=ps_scripts.REPO_ROOT / "tools" / "guest_scripts",
        host_scripts_dir=ps_scripts.REPO_ROOT / "tools" / "host_scripts",
    )
    ctx = SheetContext(inputs={"ca_host": CA_HOST, "ca_name": CA_NAME})
    executor.execute(RunSheet(name="cleanup", surface="certsrv", steps=(cleanup[0],)), ctx)
    assert transport.calls[0]["args"] == [CA_HOST, CA_NAME]


def test_cleanup_checks_absence_through_both_channels() -> None:
    """Removing the value is not the same as the CA having forgotten it.

    If the registry says gone and certutil still decodes it, the running
    service is holding a cached copy. That is a residual to record, not a
    detail to tolerate -- and checking only the channel that did the removal
    would never see it.
    """
    text = REMOVE_SCRIPT.read_text(encoding="utf-8-sig")
    assert "absent_registry" in text
    assert "absent_certutil" in text
    assert "certsvc_cached_officerrights" in text


# --- Guest-script structure -----------------------------------------------------


@pytest.mark.parametrize("script", [SCRIPT, REMOVE_SCRIPT, LAUNCH_SCRIPT])
def test_guest_scripts_parse_under_windows_powershell_51(script: object) -> None:
    ps_scripts.parse_check(script)  # type: ignore[arg-type]


@pytest.mark.parametrize("script", [SCRIPT, REMOVE_SCRIPT, LAUNCH_SCRIPT])
def test_guest_scripts_are_pure_ascii(script: object) -> None:
    ps_scripts.assert_ascii_only(script)  # type: ignore[arg-type]


def test_collect_script_derives_the_host_set_independently_of_the_plan() -> None:
    """The derivation must take no input from the plan's arguments.

    Pinned structurally: the search is over the pKIEnrollmentService CLASS
    in the Enrollment Services container -- the literal filter, not a query
    interpolated with $CaHost or $CaName, which would reduce the derived
    set to another echo of the plan. The independence is the entire point
    of revision 2, so its shape is pinned the way every other load-bearing
    guest-script property here is.
    """
    text = SCRIPT.read_text(encoding="utf-8-sig")
    assert "DirectorySearcher" in text
    assert "'(objectClass=pKIEnrollmentService)'" in text
    assert "CN=Enrollment Services,CN=Public Key Services,CN=Services" in text
    assert "dNSHostName" in text
    # The three derivation lines the controller recomputes and refuses on.
    for key in ("ca.directory.count", "ca.directory.hosts_sha256", "ca.directory.hosts"):
        assert f"'{key}'" in text
    # A search scoped to the plan's own host would rebuild the echo: the
    # filter must not mention either plan parameter.
    filter_line = next(
        line for line in text.splitlines() if line.strip().startswith("$searcher.Filter")
    )
    assert "$CaHost" not in filter_line and "$CaName" not in filter_line


def test_collect_script_fails_closed() -> None:
    text = SCRIPT.read_text(encoding="utf-8-sig")
    assert "$ErrorActionPreference = 'Stop'" in text
    assert "exit 2" in text
    assert '"error=' in text


def test_launcher_overrides_the_inherited_execution_time_limit() -> None:
    """The window-10 defect, which every launcher on this estate inherits.

    A console launched by a clone of the WCDHelper task inherits that task's
    Settings, whose ExecutionTimeLimit is PT5M -- sized for a helper that
    answers in seconds. Task Scheduler applies it to the console, so mmc.exe
    is terminated five minutes in, mid-flow, presenting as a window that
    simply vanished. This sheet is longer than certtmpl's, so it would hit
    the ceiling rather than merely risk it.
    """
    text = LAUNCH_SCRIPT.read_text(encoding="utf-8-sig")
    assert "ExecutionTimeLimit" in text
    assert "'PT1H'" in text
