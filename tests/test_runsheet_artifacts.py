"""Static checks for the shipped run-sheet artifacts.

These checks run before an estate window.  They pin the measured focus rule:
clicking a field and typing into it must happen in one composite ``keys``
helper invocation because the helper console can steal dialog focus between
invocations.
"""

from __future__ import annotations

import json
import re
from itertools import pairwise
from pathlib import Path
from typing import Any

from wcd.profiles import load_profile
from wcd.runsheets import RunSheetError, load_run_sheet, validate_channel_contract

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNSHEETS = tuple(sorted((REPO_ROOT / "runsheets").glob("*.json")))
CAPABILITIES = tuple(sorted((REPO_ROOT / "capabilities").glob("*.json")))


def _capability(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_shipped_capabilities_bind_to_matching_sheets_profiles_and_actions() -> None:
    """Catch cross-artifact drift before a disposable-estate transaction starts."""
    for capability_path in CAPABILITIES:
        capability = _capability(capability_path)
        sheet_name = capability["run_sheet"]
        surface = capability["surface"]
        sheet_path = REPO_ROOT / "runsheets" / f"{sheet_name}.json"
        profile_path = REPO_ROOT / "profiles" / f"{surface}.toml"

        assert sheet_path.is_file(), f"{capability_path.name} names missing sheet {sheet_name!r}"
        assert profile_path.is_file(), f"{capability_path.name} names missing profile {surface!r}"

        sheet = load_run_sheet(sheet_path)
        profile = load_profile(profile_path)
        assert sheet.name == sheet_name
        assert sheet.surface == surface
        assert profile.surface == surface
        validate_channel_contract(
            sheet,
            capability["channel_contract"],
            require_programmatic_requery=bool(capability["gpo_transaction"]),
        )

        first_commit = capability["first_commit_point"]
        assert first_commit in profile.actions, (
            f"{capability_path.name} first_commit_point {first_commit!r} is not a profile action"
        )
        assert profile.classification(first_commit) in ("potentially_mutating", "commit_point")
        assert any(step.profile_action == first_commit for step in sheet.steps), (
            f"{capability_path.name} first_commit_point {first_commit!r} is absent from its sheet"
        )

        mutating_steps = [
            step
            for step in sheet.steps
            if step.params.get("phase", "gesture") == "gesture"
            and step.profile_action is not None
            and profile.classification(step.profile_action)
            in ("potentially_mutating", "commit_point")
        ]
        assert mutating_steps, f"{sheet_path.name} has no declared mutating gesture"
        assert mutating_steps[0].profile_action == first_commit, (
            f"{capability_path.name} declares {first_commit!r} as its first commit point, but "
            f"{mutating_steps[0].profile_action!r} crosses first"
        )

        for index, step in enumerate(sheet.steps):
            if step.profile_action is not None:
                assert step.profile_action in profile.actions, (
                    f"{sheet_path.name} step {index} names undeclared profile action "
                    f"{step.profile_action!r}"
                )


def test_shipped_run_sheets_do_not_split_click_then_type_across_invocations() -> None:
    for path in RUNSHEETS:
        steps = load_run_sheet(path).steps
        for index, (current, following) in enumerate(pairwise(steps)):
            assert not (current.action == "click_element" and following.action == "type_text"), (
                f"{path.name} steps {index}/{index + 1} split click then type across helper "
                "invocations; use one composite keys step so focus cannot reset"
            )


def test_shipped_run_sheets_do_not_overwrite_screenshots() -> None:
    for path in RUNSHEETS:
        document = json.loads(path.read_text(encoding="utf-8"))
        names = [step["name"] for step in document["steps"] if step["action"] == "shot"]
        assert len(names) == len(set(names)), (
            f"{path.name} reuses a screenshot name; each trace image must be preserved"
        )


def test_folder_redirection_marker_claim_is_enforced_by_the_envelope() -> None:
    capability = _capability(
        REPO_ROOT / "capabilities" / "gpmc.author_folder_redirection.json"
    )
    marker = next(
        clause
        for clause in capability["envelope"]["require"]
        if clause["fact"] == "fdeploy_marker"
    )
    predicate = marker["predicate"]

    assert "fdeploy_marker.encoding.bom == 'utf16le'" in predicate
    assert "fdeploy_marker.encoding.crlf_only == True" in predicate


def test_run_sheet_and_envelope_argument_references_are_required_parameters() -> None:
    for capability_path in CAPABILITIES:
        capability = _capability(capability_path)
        required = set(capability["parameters"]["required"])
        sheet_path = REPO_ROOT / "runsheets" / f"{capability['run_sheet']}.json"
        sheet_text = sheet_path.read_text(encoding="utf-8")
        sheet_references = set(re.findall(r"\{args\.([^}]+)\}", sheet_text))
        envelope_text = json.dumps(capability["envelope"])
        envelope_references = set(re.findall(r"args\['([^']+)'\]", envelope_text))

        assert sheet_references <= required, (
            f"{capability_path.name} run-sheet references undeclared/non-required args: "
            f"{sorted(sheet_references - required)}"
        )
        assert envelope_references <= required, (
            f"{capability_path.name} envelope references undeclared/non-required args: "
            f"{sorted(envelope_references - required)}"
        )


def test_run_sheet_loader_rejects_unknown_phase(tmp_path: Path) -> None:
    path = tmp_path / "bad-phase.json"
    path.write_text(
        json.dumps(
            {
                "name": "bad-phase",
                "surface": "gpmc-server2025",
                "steps": [{"action": "guest", "phase": "cleanupp", "script": "noop"}],
            }
        ),
        encoding="utf-8",
    )
    try:
        load_run_sheet(path)
    except RunSheetError as exc:
        assert "phase must be one of" in str(exc)
    else:
        raise AssertionError("misspelled phase was accepted")


def test_gesture_script_needs_explicit_allowed_com_channel(tmp_path: Path) -> None:
    path = tmp_path / "bad-channel.json"
    path.write_text(
        json.dumps(
            {
                "name": "bad-channel",
                "surface": "gpmc-server2025",
                "steps": [{"action": "guest", "phase": "gesture", "script": "anything"}],
            }
        ),
        encoding="utf-8",
    )
    sheet = load_run_sheet(path)
    contract = {
        "setup": ["powershell"],
        "operation_under_test": ["gpmc_ui"],
        "orientation": [],
        "input_delivery": [],
        "oracle": ["gpo_observers"],
        "cleanup": ["powershell"],
    }
    try:
        validate_channel_contract(sheet, contract, require_programmatic_requery=False)
    except RunSheetError as exc:
        assert "explicit gpmc_com channel" in str(exc)
    else:
        raise AssertionError("unlabelled gesture script was accepted")
