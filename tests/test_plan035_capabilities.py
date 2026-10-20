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
import shutil
import subprocess
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


def test_wp1_rev3_asserts_both_measured_extension_lists_exactly() -> None:
    capability = _capability(WP1)
    assert capability["revision"] == 3
    require = {c["fact"]: c["predicate"] for c in capability["envelope"]["require"]}
    assert f"post.ad.gPCMachineExtensionNames == '{MACHINE_PAIR}'" in require[
        "ad.gPCMachineExtensionNames"
    ]
    assert f"post.ad.gPCUserExtensionNames == '{USER_PAIR}'" in require["ad.gPCUserExtensionNames"]
    assert "pre.ad.gPCUserExtensionNames == None" in require["ad.gPCUserExtensionNames"]


def test_wp1_rev3_predicts_no_subtree_wholesale() -> None:
    """Round-2 review (Sol B1): a require clause's fact key predicts every
    key UNDER it, so no clause may name a scripts_ini side or a file as a
    prefix -- only leaves."""
    require = _capability(WP1)["envelope"]["require"]
    facts = {clause["fact"] for clause in require}
    for broad in (
        "scripts_ini.machine",
        "scripts_ini.user",
        "scripts_ini.ps.machine",
        "scripts_ini.ps.user",
        "filedigest.machine_ini",
        "filedigest.user_ini",
    ):
        assert broad not in facts
    relpaths = next(c["predicate"] for c in require if c["fact"] == "scope.sysvol_relpaths")
    assert "'User/Scripts/scripts.ini'" in relpaths
    assert "'Machine/Scripts/scripts.ini'" in relpaths
    relations = [d["relation"] for d in _capability(WP1)["envelope"]["derive"]]
    assert not any("sysvol_relpaths !=" in relation for relation in relations)


W20_ARGS = {
    "gpo_name": "zz-studio-evidence-plan035-wp1-w20",
    "domain_dns": "ad.labdomain.dev",
    "shutdown_script": "zz-studio-shutdown.cmd",
    "shutdown_params": "/c shutdown-alpha",
    "logon_script": "zz-studio-logon.cmd",
    "logon_params": "/c logon-beta",
    "backup_name": "w20-r1",
    "expected_machine_ini_bytes": 158,
    "expected_machine_ini_sha256": (
        "f8fa40097ac3335282934200cacb2fba33deda6dbc1c8ab6876dabc14f6db489"
    ),
    "expected_user_ini_bytes": 138,
    "expected_user_ini_sha256": "ba526db64be0bbd4daf72d51083e7f91f4f36a81798fb68a3ce63d47a2182cf5",
}


def _w20_wp1_states() -> tuple[dict[str, object], dict[str, object]]:
    """Pre/post fact maps rebuilt from the banked w20-r1 delta, plus the
    unchanged facts revision 3's clauses read and the file_digest facts it
    adds (whose values window 20's cleanup journal measured)."""
    import json as _json

    from gpo_observers.scripts_ini import absent_psscripts_ini_facts

    record = _json.loads(
        (REPO_ROOT / "docs" / "estate-window-20" / "records" / "w20-r1-record.json").read_text(
            encoding="utf-8"
        )
    )
    unchanged: dict[str, object] = {
        "scope.sysvol_contained": True,
        "scope.policies.gpc_guids": ["zz"],
        "scripts_ini.machine.encoding.fallback_codec": None,
        "scripts_ini.user.encoding.fallback_codec": None,
        "scripts_ini.machine.config_shape": "none",
        "scripts_ini.user.config_shape": "none",
        **absent_psscripts_ini_facts("machine"),
        **absent_psscripts_ini_facts("user"),
    }
    pre = dict(unchanged)
    post = dict(unchanged)
    for entry in record["envelope_result"]["delta"]:
        if entry["before"] != "<missing>":
            pre[entry["key"]] = entry["before"]
        if entry["after"] != "<missing>":
            post[entry["key"]] = entry["after"]
    for side in ("machine", "user"):
        pre[f"filedigest.{side}_ini.present"] = False
        pre[f"filedigest.{side}_ini.bytes"] = None
        pre[f"filedigest.{side}_ini.sha256"] = None
        post[f"filedigest.{side}_ini.present"] = True
        post[f"filedigest.{side}_ini.bytes"] = W20_ARGS[f"expected_{side}_ini_bytes"]
        post[f"filedigest.{side}_ini.sha256"] = W20_ARGS[f"expected_{side}_ini_sha256"]
    return pre, post


def _assert_wp1(pre: dict[str, object], post: dict[str, object]):  # type: ignore[no-untyped-def]
    from gpo_observers.facts import make_fact
    from wcd.envelope import assert_envelope, parse_envelope
    from wcd.exec_transaction import _envelope_dict

    envelope = parse_envelope(_envelope_dict(_capability(WP1), W20_ARGS))
    categories = {}
    for key in set(pre) | set(post):
        fact = make_fact(key, None)
        categories[key] = fact.volatile_subcategory or fact.category
    return assert_envelope(envelope, pre, post, categories)


def test_wp1_rev3_accepts_the_banked_window_20_run() -> None:
    pre, post = _w20_wp1_states()
    result = _assert_wp1(pre, post)
    assert result.status == "satisfied", result.characterization
    assert result.unclassified == ()


def test_wp1_rev3_disproves_an_extra_populated_startup_trigger() -> None:
    """The round-2 attack: an added machine [Startup] entry with the file's
    aggregate facts moved to match. Revision 2 verified it (25 clauses, no
    unclassified delta); revision 3 must not."""
    pre, post = _w20_wp1_states()
    post.update(
        {
            "scripts_ini.machine.Startup.entry_count": 1,
            "scripts_ini.machine.Startup.0.script": "zz-extra.cmd",
            "scripts_ini.machine.Startup.0.parameters": "",
            "scripts_ini.machine.Startup.0.raw": "0CmdLine=zz-extra.cmd",
            "scripts_ini.machine.Startup.0.prop.CmdLine": "zz-extra.cmd",
            "scripts_ini.machine.Startup.0.prop.Parameters": "",
        }
    )
    result = _assert_wp1(pre, post)
    assert result.status == "disproven"
    assert "scripts_ini.machine.Startup.entry_count" in result.unclassified


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("scripts_ini.machine.encoding.total_bytes", 230),
        ("scripts_ini.machine.encoding.cr_count", 6),
        ("scripts_ini.user.encoding.lf_count", 6),
        ("filedigest.machine_ini.sha256", "0" * 64),
        ("filedigest.user_ini.bytes", 200),
    ],
)
def test_wp1_rev3_disproves_altered_ini_measurements(key: str, value: object) -> None:
    pre, post = _w20_wp1_states()
    post[key] = value
    result = _assert_wp1(pre, post)
    assert result.status == "disproven", key


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
    shutdown = require["scripts_ini.machine.Shutdown.entry_count"]
    logon = require["scripts_ini.user.Logon.entry_count"]
    assert "post['scripts_ini.machine.Shutdown.entry_count'] == 1" in shutdown
    assert "args['shutdown_script']" in shutdown and "args['shutdown_params']" in shutdown
    assert "post['scripts_ini.user.Logon.entry_count'] == 1" in logon
    assert "args['logon_script']" in logon and "args['logon_params']" in logon


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
    assert capability["revision"] == 3
    require = {c["fact"]: c["predicate"] for c in capability["envelope"]["require"]}
    assert "gpttmpl" not in require and "filedigest.gpttmpl" not in require
    assert "post['gpttmpl.sections.1.line_count'] == 2" in require["gpttmpl.present"]
    stub = require["filedigest.gpttmpl.sha256"]
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
    # dir_clean_owned takes the root as a defaulted test seam; the run-sheet
    # passes two arguments (pinned above), so the default is what runs.
    assert ("$root = 'C:\\gpo-studio\\wcd-" in text) or (
        "[string]$Root = 'C:\\gpo-studio\\wcd-stage'" in text
    )
    assert "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$" in text
    assert "GetDirectoryName" in text
    # The reparse refusal is pinned behaviourally (dir_clean_owned below) and
    # structurally here: every confined script walks the whole ancestor chain.
    assert "function Test-ReparseChain" in text


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


@pytest.mark.parametrize("window", ["estate-window-19", "estate-window-20", "estate-window-21"])
def test_capture_manifest_matches_the_committed_bytes(window: str) -> None:
    """The WCD-side hash manifest (review, Sol 4) binds every banked capture,
    including the raw scripts.ini bytes gpo-studio's fixtures transcribe."""
    import hashlib

    captures = REPO_ROOT / "docs" / window / "captures"
    entries = {}
    for line in (captures / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        entries[name] = digest
    on_disk = {p.name for p in captures.iterdir() if p.name != "MANIFEST.sha256"}
    assert set(entries) == on_disk
    for name, digest in entries.items():
        assert hashlib.sha256((captures / name).read_bytes()).hexdigest() == digest, name
    prefix = {"estate-window-19": "w19-r2", "estate-window-20": "w20-r1"}.get(window, "w21-r1")
    assert entries[f"{prefix}-user-scripts.ini"].startswith("ba526db6")
    assert entries[f"{prefix}-machine-scripts.ini"].startswith("f8fa4009")


def test_window_20_records_bind_what_window_19_left_unbound() -> None:
    """Revision 2's records carry the invocation, the setup output and the
    collected digests in themselves (review, Sol 4)."""
    import json as _json

    records = REPO_ROOT / "docs" / "estate-window-20" / "records"
    wp1 = _json.loads((records / "w20-r1-record.json").read_text(encoding="utf-8"))
    wp2 = _json.loads((records / "w20-r2-record.json").read_text(encoding="utf-8"))
    assert wp1["state"] == wp2["state"] == "verified"
    assert wp1["provenance"]["capability_revision"] == wp2["provenance"]["capability_revision"] == 2
    wp1_text = _json.dumps(wp1)
    assert "sha256=f8fa40097ac3335282934200cacb2fba33deda6dbc1c8ab6876dabc14f6db489" in wp1_text
    assert "sha256=ba526db64be0bbd4daf72d51083e7f91f4f36a81798fb68a3ce63d47a2182cf5" in wp1_text
    notes = "\n".join(wp2["provenance"]["notes"])
    assert "bundle_sha256=3f146885bb8e362e4d178582cc5710cd8067980cb9413a5411c75e2edf651e0f" in notes
    assert "invocation arguments sha256=" in notes
    captures = REPO_ROOT / "docs" / "estate-window-20" / "captures"
    wp2_text = _json.dumps(wp2)
    for name in ("wp2-inbound-rules", "wp2-rule-properties", "wp2-firewall-overview"):
        digest = hashlib_sha256((captures / f"{name}.uia.json").read_bytes())
        assert digest in wp2_text, name


def hashlib_sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


# --- dir_clean_owned, behaviourally (round-2 review, Sol B2) ---------------------
#
# Runs the shipped script under PowerShell 7 against temporary directories,
# through its $Root test seam (the run-sheets never pass it). On Linux and
# Windows alike .NET reports a symbolic link's attributes as ReparsePoint, so
# a symlinked root or ancestor is the same refusal a junction gets on the guest.

_PWSH = shutil.which("pwsh")
_CLEAN = REPO_ROOT / "tools" / "guest_scripts" / "dir_clean_owned.ps1"
_OWNER = "11111111-2222-3333-4444-555555555555"


def _clean(root: Path, stage: str, guid: str = _OWNER) -> str:
    assert _PWSH is not None
    completed = subprocess.run(
        [_PWSH, "-NoProfile", "-NonInteractive", "-File", str(_CLEAN), stage, guid, str(root)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def _owned_stage(root: Path, name: str = "w-stage", owner: str = _OWNER) -> Path:
    stage = root / name
    (stage / "expanded").mkdir(parents=True)
    (stage / "expanded" / "payload.bin").write_bytes(b"zz")
    (stage / ".wcd-owner").write_text(owner + "\n", encoding="ascii")
    return stage


needs_pwsh = pytest.mark.skipif(_PWSH is None, reason="PowerShell 7 (pwsh) not present")


@needs_pwsh
def test_dir_clean_owned_removes_an_owned_leaf(tmp_path: Path) -> None:
    root = tmp_path / "wcd-stage"
    stage = _owned_stage(root)
    assert _clean(root, "w-stage") == "removed_dir=w-stage"
    assert not stage.exists() and root.exists()


@needs_pwsh
def test_dir_clean_owned_refuses_a_foreign_owner(tmp_path: Path) -> None:
    root = tmp_path / "wcd-stage"
    stage = _owned_stage(root, owner="99999999-2222-3333-4444-555555555555")
    assert _clean(root, "w-stage") == "clean_refused=foreign_owner"
    assert stage.exists()


@needs_pwsh
def test_dir_clean_owned_refuses_a_root_swapped_for_a_link(tmp_path: Path) -> None:
    """The cleanup-time substitution: the fixed root now points elsewhere,
    where a leaf with a matching marker waits. Nothing may be deleted."""
    elsewhere = tmp_path / "elsewhere"
    victim = _owned_stage(elsewhere)
    root = tmp_path / "wcd-stage"
    root.symlink_to(elsewhere, target_is_directory=True)
    assert _clean(root, "w-stage") == "clean_refused=root_reparse_point"
    assert victim.exists() and (victim / "expanded" / "payload.bin").exists()


@needs_pwsh
def test_dir_clean_owned_refuses_a_linked_ancestor_of_the_root(tmp_path: Path) -> None:
    real = tmp_path / "real"
    victim = _owned_stage(real / "wcd-stage")
    linked = tmp_path / "gpo-studio"
    linked.symlink_to(real, target_is_directory=True)
    assert _clean(linked / "wcd-stage", "w-stage") == "clean_refused=root_reparse_point"
    assert victim.exists()


@needs_pwsh
def test_dir_clean_owned_refuses_a_linked_leaf(tmp_path: Path) -> None:
    elsewhere = _owned_stage(tmp_path / "elsewhere", name="target")
    root = tmp_path / "wcd-stage"
    root.mkdir()
    (root / "w-stage").symlink_to(elsewhere, target_is_directory=True)
    assert _clean(root, "w-stage") == "clean_refused=reparse_point"
    assert elsewhere.exists()


@needs_pwsh
@pytest.mark.parametrize("stage", ["..", "a/b", "incoming", ""])
def test_dir_clean_owned_refuses_names_that_are_not_owned_leaves(
    tmp_path: Path, stage: str
) -> None:
    root = tmp_path / "wcd-stage"
    _owned_stage(root)
    assert _clean(root, stage).startswith("clean_refused=")
    assert (root / "w-stage").exists()


def test_window_21_records_carry_a_recomputable_untruncated_invocation() -> None:
    """Round-2 review (Sol B3): the revision-3 records bind their arguments
    and setup output whole, recomputable from the record alone."""
    import hashlib
    import json as _json

    from wcd.record_schema import validate_record

    records = REPO_ROOT / "docs" / "estate-window-21" / "records"
    for name, capability in (("w21-r1", WP1), ("w21-r2", WP2)):
        record = _json.loads((records / f"{name}-record.json").read_text(encoding="utf-8"))
        text = (REPO_ROOT / "capabilities" / f"{capability}.json").read_text(encoding="utf-8")
        assert validate_record(record, capability_text=text) == 2
        assert record["state"] == "verified"
        assert record["provenance"]["capability_revision"] == 3
        invocation = record["provenance"]["invocation"]
        canonical = _json.dumps(
            invocation["arguments"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        assert hashlib.sha256(canonical.encode()).hexdigest() == invocation["arguments_sha256"]
        assert all(entry["truncated"] is False for entry in invocation["setup_manifest"])
    wp2 = _json.loads((records / "w21-r2-record.json").read_text(encoding="utf-8"))
    imported = next(
        e for e in wp2["provenance"]["invocation"]["setup_manifest"]
        if e["script"] == "gpo_stage_import"
    )
    assert "bundle_sha256=3f146885bb8e362e4d178582cc5710cd8067980cb9413a5411c75e2edf651e0f" in (
        imported["stdout"]
    )
    assert (
        "registry_pol_sha256=25ad9748d1872472abcc7b8992016989c011e9b60fda3fc5dfc53e8b179de081"
        in imported["stdout"]
    )
