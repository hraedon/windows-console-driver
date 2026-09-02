"""End-to-end snapshot capture and delta evaluation against fixtures.

Snapshot capture runs the full observer set with FileTransport serving the
filesystem-backed snippets from the committed fixture tree and a scripted
transport standing in for AD. The delta scenarios:

(a) only allowed volatile categories changed -> satisfiable;
(b) an undeclared new file appears -> unclassified violation;
(c) a forbidden extension GUID appears (plus the other forbid scopes) ->
    forbid violation.
"""

from __future__ import annotations

import base64
import shutil
from collections.abc import Mapping
from pathlib import Path

import pytest
from test_gpo_observers_collection import ScriptedTransport

from gpo_observers.collection import (
    SNIPPET_AD_ATTRIBUTES,
    SNIPPET_GPO_IDENTITY,
    SNIPPET_SCOPE_FORBID,
    SNIPPET_VERSION_VALUES,
    FileTransport,
)
from gpo_observers.delta import (
    SCOPE_GPC_EXTENSION_LISTS,
    SCOPE_POLICIES_CONTAINER,
    SCOPE_SYSVOL_PATHS,
    DeltaError,
    DeltaOutcome,
    evaluate,
)
from gpo_observers.facts import FactSet, JSONValue, make_fact
from gpo_observers.snapshots import GpoRef, capture_snapshot, is_system_relpath

GPO_GUID = "11111111-2222-3333-4444-555555555555"
BRACED_GUID = "{11111111-2222-3333-4444-555555555555}"
DOMAIN_DNS = "corp.example.com"
FORBIDDEN_GUID = "A3CC7818-8A30-4E0C-91C5-A4EA4B5A8DAB"
BASE_EXTENSION_LIST = (
    "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]"
)
FIXTURE_GPO_ROOT = (
    Path(__file__).parent / "fixtures" / "gpo-tree" / "11111111-2222-3333-4444-555555555555"
)


def _ad_data(
    when_changed: str,
    usn_changed: str,
    machine_extension_list: str | None = BASE_EXTENSION_LIST,
) -> dict[str, JSONValue]:
    return {
        "gPCMachineExtensionNames": machine_extension_list,
        "gPCUserExtensionNames": None,
        "versionNumber": 65537,
        "gPCFunctionalityVersion": 2,
        "flags": 0,
        "whenChanged": when_changed,
        "uSNChanged": usn_changed,
    }


def _scope_data(
    relpaths: list[str] | None = None,
    guids: list[str] | None = None,
    machine_extension_list: str | None = BASE_EXTENSION_LIST,
) -> dict[str, JSONValue]:
    if relpaths is None:
        relpaths = [
            BRACED_GUID + "/Machine",
            BRACED_GUID + "/Machine/Scripts",
            BRACED_GUID + "/Machine/Scripts/scripts.ini",
            BRACED_GUID + "/Machine/microsoft",
            BRACED_GUID + "/Machine/microsoft/.gpo-fingerprint-marker",
            BRACED_GUID + "/Backup.xml",
            BRACED_GUID + "/GPT.INI",
        ]
    if guids is None:
        guids = [BRACED_GUID]
    return {
        "extension_list_machine": machine_extension_list,
        "extension_list_user": None,
        "policies_gpc_guids": guids,
        "sysvol_relpaths": relpaths,
    }


def _base_responses(
    when_changed: str = "2026-09-01T10:00:00.0000000Z",
    usn_changed: str = "1000",
    machine_extension_list: str | None = BASE_EXTENSION_LIST,
    scope_relpaths: list[str] | None = None,
    scope_guids: list[str] | None = None,
) -> dict[str, dict[str, JSONValue]]:
    gpt_b64 = base64.b64encode((FIXTURE_GPO_ROOT / "GPT.INI").read_bytes()).decode("ascii")
    responses: dict[str, dict[str, JSONValue]] = {
        SNIPPET_GPO_IDENTITY: {
            "ok": True,
            "data": {"gpo_guid": BRACED_GUID, "domain_dns": DOMAIN_DNS},
        },
        SNIPPET_AD_ATTRIBUTES: {
            "ok": True,
            "data": _ad_data(when_changed, usn_changed, machine_extension_list),
        },
        SNIPPET_VERSION_VALUES: {
            "ok": True,
            "data": {
                "gpt_ini_b64": gpt_b64,
                "gpt_version_raw": "65537",
                "ad_version_number": 65537,
            },
        },
        SNIPPET_SCOPE_FORBID: {
            "ok": True,
            "data": _scope_data(scope_relpaths, scope_guids, machine_extension_list),
        },
    }
    return responses


def _capture(root: Path, responses: Mapping[str, dict[str, JSONValue]]) -> FactSet:
    transport: ScriptedTransport = ScriptedTransport(
        responses, file_transport=FileTransport(root)
    )
    gpo = GpoRef(gpo_guid=GPO_GUID, domain_dns=DOMAIN_DNS, sysvol_path=str(root))
    return capture_snapshot(transport, gpo)


def _evaluate(
    pre: FactSet,
    post: FactSet,
    *,
    allowed_categories: tuple[str, ...] = ("timestamps", "replication_metadata"),
    forbidden_guids: tuple[str, ...] = (FORBIDDEN_GUID,),
) -> DeltaOutcome:
    return evaluate(
        pre,
        post,
        allowed_categories=allowed_categories,
        forbidden_guids=forbidden_guids,
        gpo_guid=GPO_GUID,
    )


class TestCaptureSnapshot:
    @pytest.fixture()
    def facts(self) -> FactSet:
        return _capture(FIXTURE_GPO_ROOT, _base_responses())

    def test_identity_facts(self, facts: FactSet) -> None:
        assert facts["gpo_identity.guid"].value == BRACED_GUID
        assert facts["gpo_identity.domain_dns"].value == DOMAIN_DNS
        assert facts["gpo_identity.guid"].category == "identity"

    def test_ad_facts(self, facts: FactSet) -> None:
        assert facts["ad.versionNumber"].value == 65537
        assert facts["ad.versionNumber"].category == "structural"
        assert facts["ad.whenChanged"].category == "volatile"
        assert facts["ad.whenChanged"].volatile_subcategory == "timestamps"
        assert facts["ad.uSNChanged"].volatile_subcategory == "replication_metadata"
        assert facts["ad.gPCMachineExtensionNames"].value == BASE_EXTENSION_LIST

    def test_version_facts_are_parsed_not_hashed(self, facts: FactSet) -> None:
        assert facts["version.raw"].value == "65537"
        assert facts["version.machine"].value == 1
        assert facts["version.user"].value == 1
        assert facts["version.ad_versionNumber"].value == 65537
        assert facts["version.displayName"].value == "New Group Policy Object"
        assert facts["version.displayName"].category == "identity"

    def test_scripts_ini_facts(self, facts: FactSet) -> None:
        assert facts["scripts_ini.machine.present"].value is True
        assert facts["scripts_ini.machine.Startup.0.script"].value == "agent-startup.cmd"
        assert facts["scripts_ini.machine.Shutdown.0.script"].value == "agent-shutdown.cmd"
        assert facts["scripts_ini.machine.encoding.bom"].value == "utf-16le"
        assert facts["scripts_ini.ps.machine.config_shape"].value == "scripts_config"
        assert facts["scripts_ini.ps.machine.scripts_config.StartExecutePSFirst"].value == "true"
        assert facts["scripts_ini.ps.machine.policy.RunLogonScriptsSync"].value is None

    def test_system_files_are_excluded_from_per_file_facts(self, facts: FactSet) -> None:
        assert is_system_relpath("GPT.INI")
        assert is_system_relpath("Machine/Scripts/SCRIPTS.INI")
        assert not is_system_relpath("Backup.xml")
        for key in facts:
            assert ".sha256" not in key or key.startswith("sysvol.")
        assert "sysvol.GPT.INI.sha256" not in facts
        assert "sysvol.Machine/Scripts/scripts.ini.sha256" not in facts
        assert "sysvol.Machine/Scripts/psscripts.ini.sha256" not in facts

    def test_non_system_files_are_fingerprinted_unclassified(self, facts: FactSet) -> None:
        sha = facts["sysvol.Backup.xml.sha256"]
        assert sha.category == "unclassified"
        assert isinstance(sha.value, str) and len(sha.value) == 64
        marker = facts["sysvol.Machine/microsoft/.gpo-fingerprint-marker.bytes"]
        assert marker.category == "unclassified"
        assert isinstance(marker.value, int) and marker.value > 0
        assert facts["sysvol.passes_match"].value is True
        assert facts["sysvol.passes_match"].category == "structural"

    def test_scope_facts(self, facts: FactSet) -> None:
        assert facts["scope.extension_lists.machine"].value == BASE_EXTENSION_LIST
        guids = facts["scope.policies.gpc_guids"]
        assert isinstance(guids.value, list) and guids.value == [BRACED_GUID]
        relpaths = facts["scope.sysvol_relpaths"]
        assert isinstance(relpaths.value, list)
        assert all(relpath.startswith(BRACED_GUID + "/") for relpath in relpaths.value)

    def test_psscripts_policy_shape_end_to_end(self, tmp_path: Path) -> None:
        root = tmp_path / "11111111-2222-3333-4444-555555555555"
        shutil.copytree(FIXTURE_GPO_ROOT, root)
        policy_variant = (
            Path(__file__).parent
            / "fixtures"
            / "gpo-tree"
            / "_variants"
            / "psscripts_policy.ini"
        )
        shutil.copyfile(policy_variant, root / "Machine" / "Scripts" / "psscripts.ini")
        facts = _capture(root, _base_responses())
        assert facts["scripts_ini.ps.machine.config_shape"].value == "policy"
        assert facts["scripts_ini.ps.machine.policy.RunLogonScriptsSync"].value == "1"
        assert facts["scripts_ini.ps.machine.policy.PowerShellOrder"].value == "RunPowerShellLast"
        assert (
            facts["scripts_ini.ps.machine.scripts_config.StartExecutePSFirst"].value is None
        )
        # The swapped file is a system path: still no per-file hash fact.
        assert "sysvol.Machine/Scripts/psscripts.ini.sha256" not in facts


class TestDeltaScenarios:
    def test_scenario_a_only_allowed_categories_changed_is_satisfiable(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "gpo"
        shutil.copytree(FIXTURE_GPO_ROOT, root)
        pre = _capture(root, _base_responses())
        post = _capture(
            root,
            _base_responses(
                when_changed="2026-09-01T10:05:00.0000000Z",
                usn_changed="1001",
            ),
        )
        outcome = _evaluate(pre, post)
        assert outcome.satisfiable is True
        assert outcome.status == "satisfied"
        assert outcome.forbid_violations == ()
        assert len(outcome.changes) == 2
        kinds = {(change.key, change.category) for change in outcome.changes}
        assert ("ad.whenChanged", "volatile") in kinds
        assert ("ad.uSNChanged", "volatile") in kinds
        assert all(change.covered for change in outcome.changes)

    def test_scenario_b_new_file_is_an_unclassified_violation(self, tmp_path: Path) -> None:
        root = tmp_path / "gpo"
        shutil.copytree(FIXTURE_GPO_ROOT, root)
        responses = _base_responses()
        pre = _capture(root, responses)
        (root / "Machine" / "keepme-evidence.txt").write_bytes(b"synthetic\r\n")
        post = _capture(root, responses)
        outcome = _evaluate(pre, post)
        assert outcome.satisfiable is False
        assert outcome.status == "disproven"
        unclassified = outcome.unclassified_changes
        keys = {change.key for change in unclassified}
        assert "sysvol.Machine/keepme-evidence.txt.sha256" in keys
        assert "sysvol.Machine/keepme-evidence.txt.bytes" in keys
        sha_change = next(
            change
            for change in outcome.changes
            if change.key == "sysvol.Machine/keepme-evidence.txt.sha256"
        )
        assert sha_change.kind == "added"
        assert sha_change.before is None
        assert isinstance(sha_change.after, str) and len(sha_change.after) == 64
        assert sha_change.covered is False

    def test_scenario_c_forbidden_extension_guid_is_a_forbid_violation(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "gpo"
        shutil.copytree(FIXTURE_GPO_ROOT, root)
        extended = BASE_EXTENSION_LIST + "[{A3CC7818-8A30-4E0C-91C5-A4EA4B5A8DAB}{B9CC5102}]"
        pre = _capture(root, _base_responses())
        post = _capture(root, _base_responses(machine_extension_list=extended))
        outcome = _evaluate(pre, post)
        assert outcome.status == "disproven"
        scopes = {violation.scope for violation in outcome.forbid_violations}
        assert SCOPE_GPC_EXTENSION_LISTS in scopes
        violation = next(
            v for v in outcome.forbid_violations if v.scope == SCOPE_GPC_EXTENSION_LISTS
        )
        assert FORBIDDEN_GUID in violation.detail

    def test_sysvol_path_escape_is_a_forbid_violation(self, tmp_path: Path) -> None:
        root = tmp_path / "gpo"
        shutil.copytree(FIXTURE_GPO_ROOT, root)
        escaped = _scope_data(
            relpaths=[
                BRACED_GUID + "/Machine",
                "{99999999-8888-7777-6666-555555555555}/Machine/evil.ini",
            ]
        )
        pre = _capture(root, _base_responses())
        post = _capture(root, _base_responses(scope_relpaths=escaped["sysvol_relpaths"]))
        outcome = _evaluate(pre, post)
        scopes = {violation.scope for violation in outcome.forbid_violations}
        assert SCOPE_SYSVOL_PATHS in scopes

    def test_policies_container_change_is_a_forbid_violation(self, tmp_path: Path) -> None:
        root = tmp_path / "gpo"
        shutil.copytree(FIXTURE_GPO_ROOT, root)
        pre = _capture(root, _base_responses())
        post = _capture(
            root,
            _base_responses(
                scope_guids=[
                    BRACED_GUID,
                    "{99999999-8888-7777-6666-555555555555}",
                ]
            ),
        )
        outcome = _evaluate(pre, post)
        scopes = {violation.scope for violation in outcome.forbid_violations}
        assert SCOPE_POLICIES_CONTAINER in scopes

    def test_uncategorized_volatile_change_is_a_violation(self, tmp_path: Path) -> None:
        root = tmp_path / "gpo"
        shutil.copytree(FIXTURE_GPO_ROOT, root)
        pre = _capture(root, _base_responses())
        post = _capture(root, _base_responses(usn_changed="9999"))
        outcome = _evaluate(pre, post, allowed_categories=("timestamps",))
        assert outcome.satisfiable is False
        uncovered = {change.key for change in outcome.uncovered_changes}
        assert "ad.uSNChanged" in uncovered

    def test_unclassified_can_never_be_allowed(self, tmp_path: Path) -> None:
        root = tmp_path / "gpo"
        shutil.copytree(FIXTURE_GPO_ROOT, root)
        pre = _capture(root, _base_responses())
        with pytest.raises(DeltaError, match="unclassified"):
            _evaluate(pre, pre, allowed_categories=("unclassified",))

    def test_identical_snapshots_are_satisfied(self, tmp_path: Path) -> None:
        root = tmp_path / "gpo"
        shutil.copytree(FIXTURE_GPO_ROOT, root)
        facts = _capture(root, _base_responses())
        outcome = _evaluate(facts, facts)
        assert outcome.satisfiable is True
        assert outcome.changes == ()


class TestDeltaPrimitives:
    def test_changed_added_removed_with_before_after(self) -> None:
        scope = make_fact("scope.policies.gpc_guids", [BRACED_GUID])
        pre: FactSet = {
            "version.machine": make_fact("version.machine", 1),
            "ad.flags": make_fact("ad.flags", 0),
            "ad.gPCFunctionalityVersion": make_fact("ad.gPCFunctionalityVersion", 2),
            "scope.policies.gpc_guids": scope,
        }
        post: FactSet = {
            "version.machine": make_fact("version.machine", 2),
            "ad.gPCFunctionalityVersion": make_fact("ad.gPCFunctionalityVersion", 2),
            "scope.policies.gpc_guids": scope,
        }
        outcome = evaluate(pre, post, allowed_categories=("structural",))
        by_key = {change.key: change for change in outcome.changes}
        assert set(by_key) == {"version.machine", "ad.flags"}
        assert by_key["version.machine"].kind == "changed"
        assert by_key["version.machine"].before == 1
        assert by_key["version.machine"].after == 2
        assert by_key["version.machine"].category == "structural"
        assert by_key["ad.flags"].kind == "removed"
        assert by_key["ad.flags"].before == 0
        assert by_key["ad.flags"].after is None
        assert outcome.satisfiable is True

    def test_content_change_is_not_covered_by_timestamp_allowance(self) -> None:
        pre = {"scripts_ini.machine.Startup.0.script": make_fact(
            "scripts_ini.machine.Startup.0.script", "a.cmd"
        )}
        post = {"scripts_ini.machine.Startup.0.script": make_fact(
            "scripts_ini.machine.Startup.0.script", "b.cmd"
        )}
        outcome = evaluate(pre, post, allowed_categories=("timestamps", "replication_metadata"))
        assert outcome.satisfiable is False
        change = outcome.changes[0]
        assert change.category == "content"
        assert change.covered is False

    def test_generic_volatile_allowance_covers_both_subcategories(self) -> None:
        scope = make_fact("scope.policies.gpc_guids", [BRACED_GUID])
        pre = {
            "ad.whenChanged": make_fact("ad.whenChanged", "t1"),
            "ad.uSNChanged": make_fact("ad.uSNChanged", "1"),
            "scope.policies.gpc_guids": scope,
        }
        post = {
            "ad.whenChanged": make_fact("ad.whenChanged", "t2"),
            "ad.uSNChanged": make_fact("ad.uSNChanged", "2"),
            "scope.policies.gpc_guids": scope,
        }
        outcome = evaluate(pre, post, allowed_categories=("volatile",))
        assert outcome.satisfiable is True

    def test_extension_list_fact_is_checked_from_the_post_state(self) -> None:
        from gpo_observers.delta import check_extension_lists

        post = {
            "ad.gPCMachineExtensionNames": make_fact(
                "ad.gPCMachineExtensionNames",
                "[{A3CC7818-8A30-4E0C-91C5-A4EA4B5A8DAB}{X}]",
            ),
            "ad.gPCUserExtensionNames": make_fact("ad.gPCUserExtensionNames", None),
        }
        violations = check_extension_lists(post, (FORBIDDEN_GUID.lower(),))
        assert len(violations) == 1
        assert violations[0].scope == SCOPE_GPC_EXTENSION_LISTS
        # Case-insensitive: the lower-case form still matched.
        assert "A3CC7818" in violations[0].detail
        # An empty (null) extension list contains nothing: no violation.
        empty_post = {
            "ad.gPCMachineExtensionNames": make_fact("ad.gPCMachineExtensionNames", None),
            "ad.gPCUserExtensionNames": make_fact("ad.gPCUserExtensionNames", None),
        }
        assert check_extension_lists(empty_post, (FORBIDDEN_GUID,)) == ()

    def test_missing_scope_facts_fail_closed(self) -> None:
        pre: FactSet = {}
        post: FactSet = {"version.machine": make_fact("version.machine", 1)}
        outcome = evaluate(pre, post, forbidden_guids=(FORBIDDEN_GUID,), gpo_guid=GPO_GUID)
        scopes = {violation.scope for violation in outcome.forbid_violations}
        assert scopes == {SCOPE_GPC_EXTENSION_LISTS, SCOPE_SYSVOL_PATHS, SCOPE_POLICIES_CONTAINER}

    def test_no_gpo_guid_skips_containment_only(self) -> None:
        pre: FactSet = {}
        post: FactSet = {"version.machine": make_fact("version.machine", 1)}
        outcome = evaluate(pre, post)
        scopes = {violation.scope for violation in outcome.forbid_violations}
        assert SCOPE_SYSVOL_PATHS not in scopes
        assert SCOPE_POLICIES_CONTAINER in scopes


def test_fact_values_round_trip_through_json() -> None:
    import json

    root_facts = _capture(FIXTURE_GPO_ROOT, _base_responses())
    encoded = json.dumps({key: fact.value for key, fact in root_facts.items()})
    assert isinstance(encoded, str)
    decoded = json.loads(encoded)
    assert set(decoded) == set(root_facts)
    sample = root_facts["sysvol.passes_match"]
    assert decoded["sysvol.passes_match"] == sample.value
