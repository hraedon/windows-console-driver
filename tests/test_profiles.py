"""Driver profile schema and loader tests: contract section 6 rules, by name.

The happy-path fixtures are a faithful *typed-TOML* rendering of the action
table in the shipped ``profiles/gpmc-server2025.toml`` stub -- every one of the
four action classes appears, and the manual-regime commit-boundary facts ride
along as ``notes``. The stub itself is still narrative markdown (its own header
says "sketch only"); the last test pins that honest state so the conversion
documented in :mod:`wcd.profiles` cannot happen silently.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from wcd.profiles import DriverProfile, ProfileInvalid, load_profile, parse_profile_text

REPO_ROOT = Path(__file__).resolve().parent.parent

PROFILE_TOML = """\
[profile]
surface = "gpmc-server2025"
description = "GPMC / GPME (gpmc.msc, group policy editor snap-ins)"
os_family = "Windows Server 2025"
os_build_family = "26100"
first_commit_point = "ok_startup_scripts_dialog"

[actions.open_gpo_editor]
class = "orientation_only"
notes = "launches/attaches editor window"

[actions.navigate_tree]
class = "orientation_only"
notes = "scope-pane navigation"

[actions.open_startup_scripts_dialog]
class = "orientation_only"
notes = "opens property sheet"

[actions.add_script_entry]
class = "reversible_pre_commit"
notes = "child dialog; cancel undoes"

[actions.set_ps_order]
class = "reversible_pre_commit"
notes = "dropdown selection"

[actions.ok_startup_scripts_dialog]
class = "commit_point"
notes = "presumed scripts.ini flush at OK (manual evidence regime)"

[actions.cancel_dialog]
class = "reversible_pre_commit"
notes = "closes without commit"

[selectors.startup_scripts_dialog]
title_regex = "Startup Properties"

[selectors.scripts_tab]
name = "Scripts"

[selectors.add_button]
name = "Add..."

[selectors.script_name_field]
automation_id = ""

[selectors.script_parameters_field]
automation_id = ""

[selectors.ps_order_dropdown]
automation_id = ""

[[selector_dependencies]]
selector = "startup_scripts_dialog"
dependency = "ui_language"
strength = "strong"

[[selector_dependencies]]
selector = "scripts_tab"
dependency = "binary_version"
strength = "strong"

[[selector_dependencies]]
selector = "scripts_tab"
dependency = "ui_language"
strength = "strong_if_used"

[[selector_dependencies]]
selector = "ps_order_dropdown"
dependency = "binary_version"
strength = "strong"

[[selector_dependencies]]
selector = "ps_order_dropdown"
dependency = "ui_language"
strength = "strong_if_used"
"""


def _profile() -> DriverProfile:
    return parse_profile_text(PROFILE_TOML)


def test_profile_parses_with_surface_identity() -> None:
    profile = _profile()
    assert profile.surface == "gpmc-server2025"
    assert profile.description == "GPMC / GPME (gpmc.msc, group policy editor snap-ins)"
    assert profile.os_family == "Windows Server 2025"
    assert profile.os_build_family == "26100"


def test_every_action_has_exactly_one_of_the_four_classes() -> None:
    """Contract section 6: the four classes, declared by the author."""
    profile = _profile()
    assert profile.classification("open_gpo_editor") == "orientation_only"
    assert profile.classification("navigate_tree") == "orientation_only"
    assert profile.classification("open_startup_scripts_dialog") == "orientation_only"
    assert profile.classification("add_script_entry") == "reversible_pre_commit"
    assert profile.classification("set_ps_order") == "reversible_pre_commit"
    assert profile.classification("ok_startup_scripts_dialog") == "commit_point"
    assert profile.classification("cancel_dialog") == "reversible_pre_commit"
    assert set(profile.actions.values()) == {
        "orientation_only",
        "reversible_pre_commit",
        "commit_point",
    }


def test_undeclared_action_classifies_as_none_and_is_never_safe() -> None:
    profile = _profile()
    assert profile.classification("close_gpmc_entirely") is None
    assert profile.classification("") is None


def test_first_commit_point_lookup() -> None:
    """Contract section 6 rule 4: capabilities/profiles declare their first
    commit point; the loader validates it names a commit_point action."""
    profile = _profile()
    assert profile.first_commit_point == "ok_startup_scripts_dialog"
    assert profile.commit_point_actions == ("ok_startup_scripts_dialog",)
    assert profile.classification(profile.first_commit_point) == "commit_point"


def test_selectors_and_declared_dependencies() -> None:
    profile = _profile()
    assert set(profile.selectors) == {
        "startup_scripts_dialog",
        "scripts_tab",
        "add_button",
        "script_name_field",
        "script_parameters_field",
        "ps_order_dropdown",
    }
    assert profile.selectors["startup_scripts_dialog"] == {"title_regex": "Startup Properties"}
    assert len(profile.selector_dependencies) == 5
    assert ("scripts_tab", "ui_language", "strong_if_used") in [
        (row.selector, row.dependency, row.strength) for row in profile.selector_dependencies
    ]


def test_manual_regime_facts_ride_along_as_notes() -> None:
    profile = _profile()
    assert profile.action_notes["ok_startup_scripts_dialog"] == (
        "presumed scripts.ini flush at OK (manual evidence regime)"
    )


def test_load_profile_from_file(tmp_path: Path) -> None:
    path = tmp_path / "profile.toml"
    path.write_text(PROFILE_TOML, encoding="utf-8")
    profile = load_profile(path)
    assert profile.surface == "gpmc-server2025"


def test_load_profile_wraps_invalid_toml_in_profile_invalid(tmp_path: Path) -> None:
    path = tmp_path / "broken.toml"
    path.write_text("this is [ not toml", encoding="utf-8")
    with pytest.raises(ProfileInvalid):
        load_profile(path)


def _with_profile_toml(mutation: str) -> str:
    """Append a mutation to an otherwise minimal valid profile."""
    return (
        "[profile]\n"
        'surface = "test-surface"\n'
        "\n"
        "[actions.ok]\n"
        'class = "commit_point"\n'
        "\n" + mutation
    )


@pytest.mark.parametrize(
    "toml",
    [
        # unknown class -> ProfileInvalid (contract section 6: exactly four classes)
        _with_profile_toml('[actions.bogus]\nclass = "mutating"\n'),
        _with_profile_toml('[actions.bogus]\nclass = "COMMIT_POINT"\n'),
        # missing class
        _with_profile_toml("[actions.bogus]\nnotes = \"no class\"\n"),
        # non-string class
        _with_profile_toml("[actions.bogus]\nclass = 3\n"),
        # unknown top-level table (closed schema)
        "[profile]\nsurface = \"s\"\n[actions.ok]\nclass = \"commit_point\"\n[bogus]\nx = 1\n",
        # unknown [profile] key
        "[profile]\nsurface = \"s\"\nfirst = \"x\"\n[actions.ok]\nclass = \"commit_point\"\n",
        # unknown key inside an action table
        "[profile]\nsurface = \"s\"\n[actions.ok]\nclass = \"commit_point\"\nwhy = \"because\"\n",
        # empty action classification table
        "[profile]\nsurface = \"s\"\n[actions]\n",
        # missing [profile] table
        "[actions.ok]\nclass = \"commit_point\"\n",
        # missing surface
        "[profile]\n[actions.ok]\nclass = \"commit_point\"\n",
        # non-string notes
        "[profile]\nsurface = \"s\"\n[actions.ok]\nclass = \"commit_point\"\nnotes = 7\n",
        # selector dependency on an undeclared selector
        "[profile]\nsurface = \"s\"\n[actions.ok]\nclass = \"commit_point\"\n"
        "[selectors.dialog]\ntitle_regex = \"X\"\n"
        "[[selector_dependencies]]\nselector = \"other_dialog\"\n"
        "dependency = \"ui_language\"\nstrength = \"strong\"\n",
        # bad strength
        "[profile]\nsurface = \"s\"\n[actions.ok]\nclass = \"commit_point\"\n"
        "[selectors.dialog]\ntitle_regex = \"X\"\n"
        "[[selector_dependencies]]\nselector = \"dialog\"\n"
        "dependency = \"ui_language\"\nstrength = \"medium\"\n",
        # bad dependency name
        "[profile]\nsurface = \"s\"\n[actions.ok]\nclass = \"commit_point\"\n"
        "[selectors.dialog]\ntitle_regex = \"X\"\n"
        "[[selector_dependencies]]\nselector = \"dialog\"\n"
        "dependency = \"uilanguage\"\nstrength = \"strong\"\n",
        # dependency row missing a field
        "[profile]\nsurface = \"s\"\n[actions.ok]\nclass = \"commit_point\"\n"
        "[selectors.dialog]\ntitle_regex = \"X\"\n"
        "[[selector_dependencies]]\nselector = \"dialog\"\nstrength = \"strong\"\n",
        # non-scalar selector criterion
        "[profile]\nsurface = \"s\"\n[actions.ok]\nclass = \"commit_point\"\n"
        "[selectors.dialog]\nrect = [1, 2, 3, 4]\n",
    ],
)
def test_profile_validation_errors(toml: str) -> None:
    """Unknown classes, unknown keys, dangling references, missing tables: all
    ProfileInvalid."""
    with pytest.raises(ProfileInvalid):
        parse_profile_text(toml)


def test_first_commit_point_must_name_a_declared_commit_point_action() -> None:
    ok = parse_profile_text(
        '[profile]\nsurface = "s"\nfirst_commit_point = "ok"\n'
        '[actions.ok]\nclass = "commit_point"\n'
    )
    assert ok.first_commit_point == "ok"
    with pytest.raises(ProfileInvalid):
        parse_profile_text(
            '[profile]\nsurface = "s"\nfirst_commit_point = "missing"\n'
            '[actions.ok]\nclass = "commit_point"\n'
        )
    with pytest.raises(ProfileInvalid) as excinfo:
        parse_profile_text(
            '[profile]\nsurface = "s"\nfirst_commit_point = "open"\n'
            '[actions.ok]\nclass = "commit_point"\n'
            '[actions.open]\nclass = "orientation_only"\n'
        )
    assert "orientation_only" in str(excinfo.value)


def test_first_commit_point_placeholder_mutation_is_invalid() -> None:
    """Companion to the parametrized table: a first_commit_point naming an
    undeclared action (injected under [profile], where it belongs)."""
    toml = (
        '[profile]\nsurface = "s"\nfirst_commit_point = "nope"\n'
        "[actions.ok]\nclass = \"commit_point\"\n"
    )
    with pytest.raises(ProfileInvalid):
        parse_profile_text(toml)


def test_shipped_profile_loads_and_classifies_all_seven_actions() -> None:
    """The shipped profile is now the typed TOML shape (converted 2026-09-02
    from the narrative stub; see :mod:`wcd.profiles`). Its seven action
    classifications must load, validate, and match the manual-regime table --
    while its content stays UNQUALIFIED: qualification happens at the estate
    window, not by parsing."""
    stub = REPO_ROOT / "profiles" / "gpmc-server2025.toml"
    profile = load_profile(stub)
    assert profile.surface == "gpmc-server2025"
    expected = {
        "open_gpo_editor": "orientation_only",
        "navigate_tree": "orientation_only",
        "open_startup_scripts_dialog": "orientation_only",
        "add_script_entry": "reversible_pre_commit",
        "set_ps_order": "reversible_pre_commit",
        "ok_startup_scripts_dialog": "commit_point",
        "cancel_dialog": "reversible_pre_commit",
    }
    for action, cls in expected.items():
        assert profile.classification(action) == cls
    assert profile.first_commit_point == "ok_startup_scripts_dialog"
    # Every commit-point action is classified; the presumed first commit point
    # is a real commit_point action (contract section 6 rule 4).
    assert "ok_startup_scripts_dialog" in profile.commit_point_actions


def test_profiles_are_frozen_and_their_mappings_read_only() -> None:
    profile = _profile()
    with pytest.raises(AttributeError):
        profile.surface = "other"  # type: ignore[misc]
    with pytest.raises(TypeError):
        profile.actions["open_gpo_editor"] = "commit_point"  # type: ignore[index]
