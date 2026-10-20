"""Static pins for the two gpo-studio Plan 035 capabilities, revision 2.

Revision 1 qualified in estate window 19: ``gpmc.author_scripts_logon_shutdown``
(WP-1) measured the user-side Scripts tool GUID with the envelope deliberately
silent on it; ``gpmc.observe_imported_firewall_rules`` (WP-2) observed GPME's
view of an imported firewall GPO. The window-19 review asked for revision 2:

- every measured value asserted exactly (both extension lists, the exact
  SYSVOL relpath delta, the GptTmpl.inf stub by length and SHA-256);
- cleanup that removes only the GPO whose GUID setup captured, never by name;
- staging and backup directories confined to fixed roots, by leaf name.
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
IMPORT_SCRIPT = REPO_ROOT / "tools" / "guest_scripts" / "gpo_stage_import.ps1"


def _capability(name: str) -> dict[str, Any]:
    return json.loads((REPO_ROOT / "capabilities" / f"{name}.json").read_text(encoding="utf-8"))


def _sheet_steps(name: str) -> list[dict[str, Any]]:
    document = json.loads((REPO_ROOT / "runsheets" / f"{name}.json").read_text(encoding="utf-8"))
    steps: list[dict[str, Any]] = document["steps"]
    return steps


# --- WP-1: logon + shutdown -------------------------------------------------------

WP1 = "gpmc.author_scripts_logon_shutdown"


MACHINE_PAIR = "[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]"
USER_PAIR = "[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B66650-4972-11D1-A7CA-0000F87571E3}]"


def test_wp1_rev2_asserts_both_measured_extension_lists_exactly() -> None:
    capability = _capability(WP1)
    assert capability["revision"] == 2
    require = {c["fact"]: c["predicate"] for c in capability["envelope"]["require"]}
    assert f"post.ad.gPCMachineExtensionNames == '{MACHINE_PAIR}'" in require[
        "ad.gPCMachineExtensionNames"
    ]
    assert f"post.ad.gPCUserExtensionNames == '{USER_PAIR}'" in require["ad.gPCUserExtensionNames"]
    assert "pre.ad.gPCUserExtensionNames == None" in require["ad.gPCUserExtensionNames"]


def test_wp1_rev2_pins_the_exact_sysvol_delta_and_no_psscripts() -> None:
    capability = _capability(WP1)
    require = {c["fact"]: c["predicate"] for c in capability["envelope"]["require"]}
    relpaths = require["scope.sysvol_relpaths"]
    assert "'User/Scripts/scripts.ini'" in relpaths
    assert "'Machine/Scripts/scripts.ini'" in relpaths
    assert "post.scripts_ini.ps.user.present == False" in require["scripts_ini.ps.machine.present"]
    relations = [d["relation"] for d in capability["envelope"]["derive"]]
    assert not any("sysvol_relpaths !=" in relation for relation in relations)


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


def test_wp1_backs_up_and_removes_only_the_owned_guid() -> None:
    cleanup = [s for s in _sheet_steps(WP1) if s.get("phase") == "cleanup"]
    scripts = [s["script"] for s in cleanup]
    assert "gpo_remove" not in scripts and "gpo_backup" not in scripts
    assert scripts.index("gpo_backup_owned") < scripts.index("gpo_remove_owned")
    backup = cleanup[scripts.index("gpo_backup_owned")]
    assert backup["args"] == ["{out.setup.gpo.guid}", "{args.backup_name}"]
    remove = cleanup[scripts.index("gpo_remove_owned")]
    assert remove["args"] == ["{out.setup.gpo.guid}"]


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
    assert not any("sysvol_relpaths" in d["relation"] for d in envelope["derive"])
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


def test_wp2_rev2_pins_the_stub_bytes_and_the_exact_relpath_delta() -> None:
    capability = _capability(WP2)
    assert capability["revision"] == 2
    require = {c["fact"]: c["predicate"] for c in capability["envelope"]["require"]}
    stub = require["filedigest.gpttmpl"]
    assert "pre.filedigest.gpttmpl.present == False" in stub
    assert "post.filedigest.gpttmpl.bytes == args['expected_gpttmpl_bytes']" in stub
    assert "post.filedigest.gpttmpl.sha256 == args['expected_gpttmpl_sha256']" in stub
    relpaths = require["scope.sysvol_relpaths"]
    assert relpaths.startswith("pre.scope.sysvol_relpaths == [")
    assert "post.scope.sysvol_relpaths == [" in relpaths
    assert "'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'" in relpaths
    observers = [o["name"] for o in capability["fact_plan"]["observers"]]
    assert "file_digest" in observers


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


def test_wp2_creates_before_importing_and_cleans_only_owned_targets() -> None:
    steps = _sheet_steps(WP2)
    setup = [s["script"] for s in steps if s.get("phase") == "setup"]
    assert setup.index("gpo_create") < setup.index("gpo_stage_import")
    cleanup = [s for s in steps if s.get("phase") == "cleanup"]
    scripts = [s["script"] for s in cleanup]
    assert "gpo_remove" not in scripts and "dir_clean" not in scripts
    assert cleanup[scripts.index("gpo_remove_owned")]["args"] == ["{out.setup.gpo.guid}"]
    assert cleanup[scripts.index("dir_clean_owned")]["args"] == [
        "{args.stage_name}",
        "{out.setup.gpo.guid}",
    ]


def test_wp2_import_verifies_the_bundle_hash_before_importing() -> None:
    text = IMPORT_SCRIPT.read_text(encoding="utf-8")
    verify = text.index("Get-FileHash -LiteralPath $bundle")
    assert verify < text.index("Import-GPO -BackupId $backupId")
    stage_created = text.index("New-Item -ItemType Directory -Path $stage")
    assert text.index("bundle hash mismatch") < stage_created
    assert "New-GPO" not in text


@pytest.mark.parametrize(
    "script", ["gpo_stage_import", "dir_clean_owned", "gpo_backup_owned"]
)
def test_confined_scripts_take_leaf_names_under_a_fixed_root(script: str) -> None:
    text = (REPO_ROOT / "tools" / "guest_scripts" / f"{script}.ps1").read_text(encoding="utf-8")
    assert "$root = 'C:\\gpo-studio\\wcd-" in text
    assert "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$" in text
    assert "GetDirectoryName" in text
    assert "ReparsePoint" in text


def test_owned_cleanup_requires_the_marker_and_never_removes_by_name() -> None:
    clean = (REPO_ROOT / "tools" / "guest_scripts" / "dir_clean_owned.ps1").read_text(
        encoding="utf-8"
    )
    assert clean.index("foreign_owner") < clean.index("Remove-Item -LiteralPath $stage")
    remove = (REPO_ROOT / "tools" / "guest_scripts" / "gpo_remove_owned.ps1").read_text(
        encoding="utf-8"
    )
    assert "Remove-GPO -Guid $parsed" in remove
    assert "-Name" not in remove


def test_wp2_rule_name_parameter_cannot_carry_regex_metacharacters() -> None:
    pattern = _capability(WP2)["parameters"]["properties"]["rule_display_name"]["pattern"]
    assert pattern == "^[A-Za-z0-9][A-Za-z0-9 _-]{0,127}$"


def test_wp2_run_sheet_loads() -> None:
    sheet = load_run_sheet(REPO_ROOT / "runsheets" / f"{WP2}.json")
    assert sheet.surface == "gpmc-server2025"


# --- guest script structure (Windows PowerShell 5.1 on CI) --------------------------


_NEW_SCRIPTS = [
    REPO_ROOT / "tools" / "guest_scripts" / f"{name}.ps1"
    for name in (
        "gpo_stage_import",
        "gpo_remove_owned",
        "gpo_backup_owned",
        "dir_clean_owned",
    )
]


@pytest.mark.parametrize("script", _NEW_SCRIPTS, ids=lambda p: p.stem)
def test_new_guest_scripts_are_pure_ascii(script: Path) -> None:
    ps_scripts.assert_ascii_only(script)


@pytest.mark.skipif(
    not Path(ps_scripts.POWERSHELL).exists(), reason="Windows PowerShell 5.1 not present"
)
@pytest.mark.parametrize("script", _NEW_SCRIPTS, ids=lambda p: p.stem)
def test_new_guest_scripts_parse_under_windows_powershell_51(script: Path) -> None:
    ps_scripts.parse_check(script)


def test_window_19_capture_manifest_matches_the_committed_bytes() -> None:
    """The WCD-side hash manifest (review, Sol 4) binds every banked capture,
    including the raw scripts.ini bytes gpo-studio's fixtures transcribe."""
    import hashlib

    captures = REPO_ROOT / "docs" / "estate-window-19" / "captures"
    entries = {}
    for line in (captures / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        if name.startswith("wp1-backups.zip"):
            continue  # held outside the repository; recorded for reference
        entries[name] = digest
    on_disk = {p.name for p in captures.iterdir() if p.name != "MANIFEST.sha256"}
    assert set(entries) == on_disk
    for name, digest in entries.items():
        assert hashlib.sha256((captures / name).read_bytes()).hexdigest() == digest, name
    assert entries["w19-r2-user-scripts.ini"].startswith("ba526db6")
    assert entries["w19-r2-machine-scripts.ini"].startswith("f8fa4009")
