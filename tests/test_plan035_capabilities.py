"""Static pins for the two gpo-studio Plan 035 capabilities (estate window 19).

``gpmc.author_scripts_logon_shutdown`` (WP-1) exists to MEASURE the user-side
Scripts extension pair, so the load-bearing property is what its envelope
does not say: it must never assert a user-side tool GUID, and its version
relations must stay inequalities until a run measures GPME's per-dialog bump.
``gpmc.observe_imported_firewall_rules`` (WP-2) is observe-only, so its
load-bearing property is post == pre on versions and registrations, with the
one measured side effect of the walk (GptTmpl.inf) predicted rather than
tolerated by category.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import ps_scripts
import pytest

from wcd.profiles import load_profile
from wcd.runsheets import load_run_sheet

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_CSE = "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}"
GPP_GROUPS = "3125E937-EB16-4b4c-9934-544FC6D24D26"
IMPORT_SCRIPT = REPO_ROOT / "tools" / "guest_scripts" / "gpo_import_backup.ps1"


def _capability(name: str) -> dict[str, Any]:
    return json.loads((REPO_ROOT / "capabilities" / f"{name}.json").read_text(encoding="utf-8"))


def _sheet_steps(name: str) -> list[dict[str, Any]]:
    document = json.loads((REPO_ROOT / "runsheets" / f"{name}.json").read_text(encoding="utf-8"))
    steps: list[dict[str, Any]] = document["steps"]
    return steps


# --- WP-1: logon + shutdown -------------------------------------------------------

WP1 = "gpmc.author_scripts_logon_shutdown"


def test_wp1_user_list_requires_the_scripts_cse_and_never_a_tool_guid() -> None:
    envelope = _capability(WP1)["envelope"]
    user = [c for c in envelope["require"] if c["fact"] == "ad.gPCUserExtensionNames"]
    assert len(user) == 1
    predicate = user[0]["predicate"]
    assert SCRIPTS_CSE in predicate
    # The tool half on the user side is the measurement: neither the
    # machine-side tool GUID nor the commonly recalled logon/logoff value may
    # be written into the envelope.
    assert "40B6664F" not in predicate
    assert "40B66650" not in predicate
    assert predicate.count("{") == 1


def test_wp1_version_relations_are_inequalities_plus_the_packing() -> None:
    relations = [d["relation"] for d in _capability(WP1)["envelope"]["derive"]]
    assert "post.version.machine > pre.version.machine" in relations
    assert "post.version.user > pre.version.user" in relations
    assert not any("+ 1" in relation for relation in relations)
    assert (
        "post.version.ad_versionNumber == post.version.user * 65536 + post.version.machine"
        in relations
    )


def test_wp1_forbids_gpp_clsids_on_both_extension_lists() -> None:
    scopes = {
        clause["scope"]
        for clause in _capability(WP1)["envelope"]["forbid"]
        if GPP_GROUPS in clause["predicate"]
    }
    assert scopes == {"ad.gPCMachineExtensionNames", "ad.gPCUserExtensionNames"}


def test_wp1_requires_exactly_one_entry_per_trigger_from_the_arguments() -> None:
    require = {c["fact"]: c["predicate"] for c in _capability(WP1)["envelope"]["require"]}
    assert "== 1" in require["scripts_ini.machine.Shutdown.entry_count"]
    assert "== 1" in require["scripts_ini.user.Logon.entry_count"]
    assert "args['shutdown_script']" in require["scripts_ini.machine.Shutdown.0.script"]
    assert "args['logon_script']" in require["scripts_ini.user.Logon.0.script"]


def test_wp1_backs_the_gpo_up_before_removing_it() -> None:
    cleanup = [s for s in _sheet_steps(WP1) if s.get("phase") == "cleanup"]
    scripts = [s["script"] for s in cleanup]
    assert scripts.index("gpo_backup") < scripts.index("gpo_remove")
    backup = cleanup[scripts.index("gpo_backup")]
    assert backup["args"] == ["{args.gpo_name}", "{args.backup_dir}"]


def test_wp1_crosses_to_the_user_side_through_the_measured_scope_root_route() -> None:
    steps = _sheet_steps(WP1)
    actions = [s.get("profile_action") for s in steps]
    shutdown_ok = actions.index("ok_shutdown_scripts_dialog")
    root = actions.index("navigate_scope_root")
    logon_open = actions.index("open_logon_scripts_dialog")
    assert shutdown_ok < root < logon_open
    root_step = steps[root]
    # Click into the scope tree and press Home in ONE invocation: focus does
    # not survive between helper invocations (surface-onboarding runbook).
    assert root_step["action"] == "keys"
    assert root_step["steps"][-1] == {"vks": [{"vk": 36, "modifiers": []}]}


def test_wp1_dialog_actions_are_declared_with_their_measured_classes() -> None:
    profile = load_profile(REPO_ROOT / "profiles" / "gpmc-server2025.toml")
    assert profile.classification("open_shutdown_scripts_dialog") == "orientation_only"
    assert profile.classification("open_logon_scripts_dialog") == "orientation_only"
    assert profile.classification("ok_shutdown_scripts_dialog") == "commit_point"
    assert profile.classification("ok_logon_scripts_dialog") == "commit_point"
    assert profile.classification("navigate_scope_root") == "orientation_only"


# --- WP-2: observe-only firewall view -------------------------------------------

WP2 = "gpmc.observe_imported_firewall_rules"


def test_wp2_envelope_is_post_equals_pre_on_versions_and_registrations() -> None:
    envelope = _capability(WP2)["envelope"]
    relations = {d["relation"] for d in envelope["derive"]}
    for key in (
        "version.raw",
        "version.machine",
        "version.user",
        "version.ad_versionNumber",
        "ad.versionNumber",
        "ad.gPCUserExtensionNames",
    ):
        assert f"post.{key} == pre.{key}" in relations
    machine = next(c for c in envelope["require"] if c["fact"] == "ad.gPCMachineExtensionNames")
    assert "pre.ad.gPCMachineExtensionNames == args['expected_machine_extensions']" in (
        machine["predicate"]
    )
    assert "post.ad.gPCMachineExtensionNames == pre.ad.gPCMachineExtensionNames" in (
        machine["predicate"]
    )
    # Nothing tolerated by a content/structural category: only volatile ones.
    assert {a["category"] for a in envelope["allow"]} == {
        "timestamps",
        "replication_metadata",
        "file_mtime",
    }


def test_wp2_first_crossing_is_the_measured_security_settings_write() -> None:
    capability = _capability(WP2)
    assert capability["first_commit_point"] == "navigate_security_settings"
    profile = load_profile(REPO_ROOT / "profiles" / "gpmc-server2025.toml")
    assert profile.classification("navigate_security_settings") == "potentially_mutating"
    require = {c["fact"] for c in capability["envelope"]["require"]}
    assert "gpttmpl" in require


def test_wp2_banks_full_dumps_and_cancels_before_closing() -> None:
    steps = _sheet_steps(WP2)
    saved = [s["save_as"] for s in steps if s["action"] == "dump" and "save_as" in s]
    assert {"wp2-inbound-rules", "wp2-rule-properties"} <= set(saved)
    actions = [s.get("profile_action") for s in steps]
    assert actions.index("cancel_dialog") < actions.index("close_editor_window")
    # Observe-only: no OK/Apply is ever clicked on the surface.
    for step in steps:
        if step["action"] == "click_element":
            assert step["name_regex"] not in ("^OK$", "^Apply$")


def test_wp2_cleanup_removes_the_gpo_and_the_staged_bundle() -> None:
    cleanup = [s["script"] for s in _sheet_steps(WP2) if s.get("phase") == "cleanup"]
    assert {"gpo_remove", "dir_clean", "zz_requery", "task_unregister"} <= set(cleanup)


def test_wp2_import_verifies_the_bundle_hash_before_importing() -> None:
    text = IMPORT_SCRIPT.read_text(encoding="utf-8")
    verify = text.index("Get-FileHash -LiteralPath $BundlePath")
    assert verify < text.index("Import-GPO -BackupId $backupId")
    assert text.index("bundle hash mismatch") < text.index("New-GPO -Name $Name")
    assert '"guid=$($gpo.Id)"' in text


def test_wp2_run_sheet_loads() -> None:
    sheet = load_run_sheet(REPO_ROOT / "runsheets" / f"{WP2}.json")
    assert sheet.surface == "gpmc-server2025"


# --- guest script structure (Windows PowerShell 5.1 on CI) --------------------------


def test_import_script_is_pure_ascii() -> None:
    ps_scripts.assert_ascii_only(IMPORT_SCRIPT)


@pytest.mark.skipif(
    not Path(ps_scripts.POWERSHELL).exists(), reason="Windows PowerShell 5.1 not present"
)
def test_import_script_parses_under_windows_powershell_51() -> None:
    ps_scripts.parse_check(IMPORT_SCRIPT)
