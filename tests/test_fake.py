"""Fake-desktop backend tests: the whole transaction, no Windows (section 13).

The centerpiece is ``test_full_scripted_transaction_end_to_end``, which runs
contract section 2's machine and section 3's envelope over the synthetic
backend: lease -> context assert -> navigate -> add entry (reversible
pre-commit) -> click OK (declared commit) -> envelope satisfied -> verified.

The failure-scripting points get their own tests, each pinning the contract
rule it exercises: stale focus surfaces as a context mismatch and goes to
indeterminate (section 7); an undeclared mutating click is a profile-invalid
hard stop (sections 2 and 6); a surface whose facts never stabilize converges
to indeterminate, never a failure (section 3).
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import pytest

from wcd.envelope import Envelope, converge, parse_envelope
from wcd.fake import (
    FakeDesktop,
    FakeElement,
    FakeRect,
    FakeSurfaceError,
    FakeWindow,
)
from wcd.leases import ContextMismatch, LeaseRegistry, assert_context
from wcd.profiles import ProfileInvalid
from wcd.transaction import Transaction, UndeclaredMutation


@dataclass
class FakeClock:
    """Injectable clock/sleep pair; sleep advances time, so tests never wait."""

    now: float = 0.0
    sleeps: list[float] = field(default_factory=list)

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


# --- Scripted surface -----------------------------------------------------------


INITIAL_STATE: dict[str, object] = {
    "version.machine": 4,
    "version.user": 0,
    "ad.when_changed": "2026-09-01T00:00:00Z",
    "sysvol.scripts_ini.mtime": 100.0,
    "forbid.gpc_extension_lists": [],
    "gpc.display_name": "Scripts GPO",
    "scripts_ini.machine.entries": [],
}

CATEGORIES: dict[str, str] = {
    "version.machine": "structural",
    "version.user": "structural",
    "ad.when_changed": "timestamps",
    "sysvol.scripts_ini.mtime": "file_mtime",
    "forbid.gpc_extension_lists": "structural",
    "gpc.display_name": "structural",
    "scripts_ini.machine.entries": "structural",
}


def _envelope() -> Envelope:
    """Machine-expression envelope for the scripted authoring transaction."""
    return parse_envelope(
        {
            "require": [
                {
                    "fact": "scripts_ini.machine.entries",
                    "predicate": 'facts["scripts_ini.machine.entries"] == '
                    '["logon.cmd|-StartupParam"]',
                }
            ],
            "allow": [{"category": "timestamps"}, {"category": "file_mtime"}],
            "forbid": [{"scope": "forbid.gpc_extension_lists", "predicate": "scope == []"}],
            "derive": [
                {"relation": "post.version.machine > pre.version.machine"},
                {"relation": "post.version.user == pre.version.user"},
            ],
            "convergence": {"window_seconds": 90, "poll_seconds": 5, "reproduce": 2},
        }
    )


def _scripted_desktop(
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> FakeDesktop:
    """A GPMC-shaped scripted surface: main editor, property sheet, child dialog.

    Hooks are the script. ``ok_button`` is the declared commit point; it moves
    the scripted machine state (scripts.ini entries, version bump, allowed
    volatility). ``apply_button`` also mutates machine state -- but no profile
    ever declared it, which is the undeclared-commit scenario. UI scratch
    (``staged.*``, ``ui.*``) is written before the pre-state snapshot, so the
    oracle delta contains exactly what crossed the commit boundary.
    """
    desktop = FakeDesktop(
        session_id=7,
        user="lab-user",
        desktop="Default",
        process="mmc.exe",
        process_pid=4242,
        clock=clock,
        sleep=sleep,
    )
    desktop.state.update(INITIAL_STATE)

    def open_scripts_sheet(d: FakeDesktop) -> None:
        d.set_foreground("startup_properties")

    def select_scripts_tab(d: FakeDesktop) -> None:
        d.state["ui.active_tab"] = "Scripts"

    def open_add_dialog(d: FakeDesktop) -> None:
        d.add_window(_add_script_dialog())
        d.set_foreground("add_script_dialog")

    def set_ps_order(d: FakeDesktop) -> None:
        d.state["staged.ps_order"] = "powershell_first"

    def apply_clicked(d: FakeDesktop) -> None:
        # Mutates machine state WITHOUT any declared commit boundary.
        d.state["apply.clicks"] = d.state.get("apply.clicks", 0) + 1

    def cancel_sheet(d: FakeDesktop) -> None:
        d.close_window("startup_properties")
        d.set_foreground("gpmc_main")

    def sheet_ok(d: FakeDesktop) -> None:
        entries = d.state.get("staged.entries") or []
        d.state["scripts_ini.machine.entries"] = entries
        d.state["version.machine"] = 5
        d.state["ad.when_changed"] = "2026-09-01T00:01:00Z"
        d.state["sysvol.scripts_ini.mtime"] = 108.0
        d.close_window("startup_properties")
        d.set_foreground("gpmc_main")

    def chord_sink(d: FakeDesktop, _text: str) -> None:
        d.state["sheet.chords"] = d.state.get("sheet.chords", 0) + 1

    main = FakeWindow(
        name="gpmc_main",
        title="Group Policy Management Editor",
        class_name="MMCMainFrame",
        rect=FakeRect(0, 0, 1200, 800),
        elements=[
            FakeElement(
                name="tree",
                control_type="Tree",
                rect=FakeRect(0, 30, 260, 770),
                children=[
                    FakeElement(
                        name="gpo_node",
                        control_type="TreeItem",
                        title="Scripts GPO",
                        rect=FakeRect(10, 60, 250, 80),
                    )
                ],
            ),
            FakeElement(name="editor_pane", control_type="Pane", rect=FakeRect(260, 30, 1200, 770)),
            FakeElement(
                name="edit_scripts",
                control_type="Button",
                title="Edit Scripts...",
                rect=FakeRect(280, 40, 420, 60),
                on_click=open_scripts_sheet,
            ),
        ],
    )
    sheet = FakeWindow(
        name="startup_properties",
        title="Startup Properties",
        class_name="#32770",
        rect=FakeRect(100, 100, 700, 500),
        elements=[
            FakeElement(
                name="scripts_tab",
                control_type="TabItem",
                title="Scripts",
                rect=FakeRect(110, 120, 200, 140),
                on_click=select_scripts_tab,
            ),
            FakeElement(
                name="add_button",
                control_type="Button",
                title="Add...",
                rect=FakeRect(560, 120, 690, 140),
                on_click=open_add_dialog,
            ),
            FakeElement(
                name="ps_order_dropdown",
                control_type="ComboBox",
                rect=FakeRect(110, 440, 300, 460),
                on_click=set_ps_order,
            ),
            FakeElement(
                name="apply_button",
                control_type="Button",
                title="Apply",
                rect=FakeRect(360, 450, 440, 470),
                on_click=apply_clicked,
            ),
            FakeElement(
                name="cancel_button",
                control_type="Button",
                title="Cancel",
                rect=FakeRect(460, 450, 540, 470),
                on_click=cancel_sheet,
            ),
            FakeElement(
                name="ok_button",
                control_type="Button",
                title="OK",
                rect=FakeRect(560, 450, 690, 470),
                on_click=sheet_ok,
            ),
        ],
        on_key=chord_sink,
    )
    desktop.add_window(main)
    desktop.add_window(sheet)
    desktop.set_foreground("gpmc_main")
    return desktop


def _add_script_dialog() -> FakeWindow:
    def record_name(d: FakeDesktop, text: str) -> None:
        d.state["staged.name"] = text

    def record_parameters(d: FakeDesktop, text: str) -> None:
        d.state["staged.parameters"] = text

    def add_dialog_ok(d: FakeDesktop) -> None:
        name = str(d.state.get("staged.name", ""))
        parameters = str(d.state.get("staged.parameters", ""))
        d.state["staged.entries"] = [f"{name}|{parameters}"]
        d.close_window("add_script_dialog")
        d.set_foreground("startup_properties")

    def add_dialog_cancel(d: FakeDesktop) -> None:
        d.close_window("add_script_dialog")
        d.set_foreground("startup_properties")

    return FakeWindow(
        name="add_script_dialog",
        title="Add a Startup Script",
        class_name="#32770",
        rect=FakeRect(200, 200, 600, 400),
        elements=[
            FakeElement(
                name="script_name_field",
                control_type="Edit",
                rect=FakeRect(210, 230, 580, 250),
                on_key=record_name,
            ),
            FakeElement(
                name="script_parameters_field",
                control_type="Edit",
                rect=FakeRect(210, 270, 580, 290),
                on_key=record_parameters,
            ),
            FakeElement(
                name="ok_add",
                control_type="Button",
                title="OK",
                rect=FakeRect(480, 350, 580, 370),
                on_click=add_dialog_ok,
            ),
            FakeElement(
                name="cancel_add",
                control_type="Button",
                title="Cancel",
                rect=FakeRect(360, 350, 450, 370),
                on_click=add_dialog_cancel,
            ),
        ],
    )


def _find_element(window: FakeWindow, name: str) -> FakeElement:
    def search(elements: list[FakeElement]) -> FakeElement | None:
        for element in elements:
            if element.name == name:
                return element
            found = search(element.children)
            if found is not None:
                return found
        return None

    found = search(window.elements)
    assert found is not None, f"no element {name!r} on {window.name}"
    return found


def _click(desktop: FakeDesktop, window_name: str, element_name: str) -> None:
    """Click the center-ish of a scripted element, window-relative."""
    window = desktop.windows[window_name]
    element = _find_element(window, element_name)
    result = desktop.mouse(
        x=element.rect.left - window.rect.left + 2,
        y=element.rect.top - window.rect.top + 2,
        hwnd=window.hwnd,
    )
    assert result.element == element_name


# --- Action vocabulary -----------------------------------------------------------


def test_context_reports_session_user_desktop_and_foreground() -> None:
    desktop = _scripted_desktop()
    context = desktop.context()
    assert context.session_id == 7
    assert context.user == "lab-user"
    assert context.desktop == "Default"
    foreground = context.foreground
    assert foreground is not None
    assert foreground.title == "Group Policy Management Editor"
    assert foreground.class_name == "MMCMainFrame"
    assert foreground.hwnd != 0
    assert foreground.pid == 4242
    assert foreground.process == "mmc.exe"
    # The fingerprint is stable across observations and moves with the surface.
    again = desktop.context()
    assert again.foreground is not None
    assert again.foreground.uia_digest == foreground.uia_digest
    desktop.windows["gpmc_main"].title = "Something Else Entirely"
    changed = desktop.context()
    assert changed.foreground is not None
    assert changed.foreground.uia_digest != foreground.uia_digest


def test_interactive_context_maps_to_the_lease_record() -> None:
    desktop = _scripted_desktop()
    record = desktop.interactive_context()
    assert record.session_id == 7
    assert record.user == "lab-user"
    assert record.desktop == "Default"
    foreground = record.foreground
    assert foreground is not None
    assert foreground.process == "mmc.exe"
    context = desktop.context()
    assert context.foreground is not None
    assert foreground.fingerprint == context.foreground.uia_digest


def test_uia_dump_flattens_the_foreground_tree_with_depth() -> None:
    desktop = _scripted_desktop()
    dump = desktop.uia_dump()
    assert dump.element_count == 4  # tree + gpo_node + editor_pane + edit_scripts
    assert dump.truncated is False
    assert [element.depth for element in dump.elements] == [1, 2, 1, 1]
    shallow = desktop.uia_dump(depth=1)
    assert shallow.element_count == 3
    assert shallow.truncated is True  # gpo_node sits deeper than depth 1
    assert dump.elements[1].name == "Scripts GPO"
    with pytest.raises(FakeSurfaceError):
        desktop.set_foreground(None)
        desktop.uia_dump()
    with pytest.raises(ValueError):
        desktop.uia_dump(depth=0)


def test_mouse_click_resolves_elements_and_fires_hooks() -> None:
    desktop = _scripted_desktop()
    result = desktop.mouse(x=282, y=42, hwnd=desktop.windows["gpmc_main"].hwnd)
    assert result.element == "edit_scripts"
    assert result.injected_events == 1
    assert result.hwnd == desktop.windows["gpmc_main"].hwnd
    assert desktop.foreground == "startup_properties"  # the scripted hook ran
    assert desktop.journal[-1].startswith("mouse click left")
    # Deepest element wins: the gpo_node child inside the tree.
    deep = desktop.mouse(x=15, y=65, hwnd=desktop.windows["gpmc_main"].hwnd)
    assert deep.element == "gpo_node"
    # A click on bare pane hits the pane element and no hook fires.
    pane = desktop.mouse(x=300, y=300, hwnd=desktop.windows["gpmc_main"].hwnd)
    assert pane.element == "editor_pane"


def test_mouse_click_on_empty_space_is_recorded_not_fatal() -> None:
    desktop = _scripted_desktop()
    result = desktop.mouse(x=5, y=5, hwnd=desktop.windows["gpmc_main"].hwnd)
    assert result.element is None
    assert desktop.foreground == "gpmc_main"  # nothing happened


def test_mouse_dry_run_reports_without_firing() -> None:
    desktop = _scripted_desktop()
    result = desktop.mouse(x=282, y=42, hwnd=desktop.windows["gpmc_main"].hwnd, dry_run=True)
    assert result.dry_run is True
    assert result.would_inject is not None
    assert result.would_inject["element"] == "edit_scripts"
    assert result.injected_events == 0
    assert desktop.foreground == "gpmc_main"  # no hook fired


def test_mouse_double_click_fires_the_hook_twice() -> None:
    desktop = _scripted_desktop()
    desktop.set_foreground("startup_properties")
    sheet = desktop.windows["startup_properties"]
    apply_button = _find_element(sheet, "apply_button")
    result = desktop.mouse(
        x=apply_button.rect.left - sheet.rect.left + 2,
        y=apply_button.rect.top - sheet.rect.top + 2,
        hwnd=sheet.hwnd,
        mouse_action="double",
    )
    assert result.element == "apply_button"
    assert result.injected_events == 2
    assert desktop.state["apply.clicks"] == 2


def test_mouse_validation_and_unknown_targets() -> None:
    desktop = _scripted_desktop()
    with pytest.raises(ValueError):
        desktop.mouse(x=0, y=0, button="top")
    with pytest.raises(ValueError):
        desktop.mouse(x=0, y=0, mouse_action="shake")
    with pytest.raises(FakeSurfaceError):
        desktop.mouse(x=0, y=0, hwnd=999999)
    with pytest.raises(FakeSurfaceError):
        desktop.set_foreground("no-such-window")


def test_key_delivers_text_to_the_focused_field_without_returning_it() -> None:
    desktop = _scripted_desktop()
    desktop.add_window(_add_script_dialog())
    desktop.set_foreground("add_script_dialog")
    _click(desktop, "add_script_dialog", "script_name_field")
    result = desktop.key(text="logon.cmd")
    assert result.text_length == len("logon.cmd")
    assert result.text_sha256 == hashlib.sha256(b"logon.cmd").hexdigest()
    assert result.text_sha256 != "logon.cmd"  # the text itself never comes back
    assert result.injected_events == 9
    assert desktop.state["staged.name"] == "logon.cmd"  # the focused field got it


def test_key_chords_go_to_the_window_hook() -> None:
    desktop = _scripted_desktop()
    desktop.set_foreground("startup_properties")
    result = desktop.key(chords=[(0x09, ("ALT",)), (0x0D, ("CTRL",))])
    assert result.chords_sent == 2
    assert result.text_length is None
    assert result.text_sha256 is None
    assert result.injected_events == 2
    assert desktop.state["sheet.chords"] == 2


def test_key_dry_run_and_validation() -> None:
    desktop = _scripted_desktop()
    result = desktop.key(text="logon.cmd", dry_run=True)
    assert result.dry_run is True
    assert result.would_inject is not None
    assert result.would_inject["text_length"] == 9
    assert desktop.state.get("staged.name") is None  # nothing delivered
    with pytest.raises(ValueError):
        desktop.key()
    with pytest.raises(ValueError):
        desktop.key(text="a", chords=[(1, ())])


def test_wait_foreground_matches_immediately_and_times_out_on_the_fake_clock() -> None:
    desktop = _scripted_desktop()
    matched = desktop.wait_foreground(title_regex="Group Policy.*")
    assert matched.matched is True
    assert matched.waited_ms == 0
    assert matched.window == "gpmc_main"
    clock = FakeClock()
    timed = _scripted_desktop(clock=clock, sleep=clock.sleep)
    timed_out = timed.wait_foreground(title_regex="No Such Window", timeout_ms=1000, poll_ms=250)
    assert timed_out.matched is False
    assert timed_out.waited_ms == 1000
    assert clock.now == 1.0
    with pytest.raises(ValueError):
        desktop.wait_foreground(timeout_ms=0)
    with pytest.raises(ValueError):
        desktop.wait_foreground(poll_ms=-1)


def test_wait_foreground_sees_a_mid_wait_change() -> None:
    clock = FakeClock()
    sleeps = [0]
    holder: dict[str, FakeDesktop] = {}

    def scripted_sleep(seconds: float) -> None:
        sleeps[0] += 1
        if sleeps[0] == 2:  # the property sheet takes focus mid-wait
            holder["desktop"].set_foreground("startup_properties")
        clock.sleep(seconds)

    desktop = _scripted_desktop(clock=clock, sleep=scripted_sleep)
    holder["desktop"] = desktop
    result = desktop.wait_foreground(title_regex="Startup Properties", timeout_ms=5000, poll_ms=250)
    assert result.matched is True
    assert result.window == "startup_properties"
    assert result.waited_ms == 500


def test_observe_snapshots_state_and_fires_the_hook() -> None:
    desktop = _scripted_desktop()
    snapshot = desktop.observe()
    assert snapshot == dict(desktop.state)
    snapshot["injected"] = True  # a copy: mutating it cannot touch the state
    assert "injected" not in desktop.state

    seen: list[bool] = []

    def hook(d: FakeDesktop) -> None:
        seen.append(True)
        d.state["observed.at"] = "just-now"

    desktop.on_observe = hook
    observed = desktop.observe()
    assert seen == [True]
    assert observed["observed.at"] == "just-now"


def test_window_bookkeeping_validation() -> None:
    desktop = _scripted_desktop()
    with pytest.raises(ValueError):
        desktop.add_window(desktop.windows["gpmc_main"])
    with pytest.raises(FakeSurfaceError):
        desktop.close_window("not-there")


# --- Contract rules over the fake backend -----------------------------------------


def test_stale_focus_midflight_surfaces_as_context_mismatch_then_indeterminate() -> None:
    """Contract section 7 via section 2: a foreground deviation between the
    expected and freshly observed context invalidates the pending operation ->
    indeterminate, never a retry."""
    desktop = _scripted_desktop()
    registry = LeaseRegistry()
    lease = registry.acquire("desktop-7", "wcd-driver")
    transaction = Transaction(transaction_id="stale-focus")
    transaction.prepare(
        pre_oracle_done=True,
        lease_held=registry.is_active(lease),
        context_asserted=True,
        recovery_declared=True,
    )
    transaction.arm()
    expected = desktop.interactive_context()
    # Mid-flight, the property sheet takes the foreground:
    _click(desktop, "gpmc_main", "edit_scripts")
    observed = desktop.interactive_context()
    with pytest.raises(ContextMismatch) as excinfo:
        assert_context(expected, observed)
    assert set(excinfo.value.fields) == {"foreground.hwnd", "foreground.fingerprint"}
    transaction.mark_indeterminate(
        "interactive context changed mid-flight: " + ", ".join(excinfo.value.fields)
    )
    assert transaction.reconcile_required
    assert registry.is_active(lease)  # the lease itself is unaffected


def test_secure_desktop_appears_as_a_desktop_name_mismatch() -> None:
    """Contract section 7's named unsupported state: Secure Desktop/UAC shows
    up as an ordinary context mismatch -- never solved heroically."""
    desktop = _scripted_desktop()
    expected = desktop.interactive_context()
    desktop.desktop = "Secure Desktop"
    with pytest.raises(ContextMismatch) as excinfo:
        assert_context(expected, desktop.interactive_context())
    assert excinfo.value.fields == ("desktop",)


def test_undeclared_commit_scripted_by_the_surface_is_a_hard_stop() -> None:
    """Contract sections 2 and 6 rule 2: the surface happily mutates machine
    state on an undeclared boundary; the machine must refuse, raise
    ProfileInvalid, and force indeterminate."""
    desktop = _scripted_desktop()
    transaction = Transaction(transaction_id="undeclared")
    transaction.prepare(
        pre_oracle_done=True, lease_held=True, context_asserted=True, recovery_declared=True
    )
    transaction.arm()
    _click(desktop, "gpmc_main", "edit_scripts")
    _click(desktop, "startup_properties", "apply_button")
    assert desktop.state["apply.clicks"] == 1  # the mutation really happened
    with pytest.raises(UndeclaredMutation) as excinfo:
        transaction.commit("apply_button", declared=False)
    assert isinstance(excinfo.value, ProfileInvalid)
    assert excinfo.value.boundary == "apply_button"
    assert transaction.state == "indeterminate"
    assert transaction.reconcile_required


def test_no_convergence_when_observed_facts_never_stabilize() -> None:
    """Contract section 3: a surface whose require/derive facts churn forever
    times out into indeterminate -- never a bare failure."""
    desktop = _scripted_desktop()
    counter = [0]

    def churn(d: FakeDesktop) -> None:
        counter[0] += 1
        d.state["version.machine"] = 4 + (counter[0] % 3)  # oscillates: 5, 6, 7, 5, ...

    desktop.on_observe = churn
    clock = FakeClock()
    result = converge(
        _envelope(),
        dict(desktop.state),
        CATEGORIES,
        desktop.observe,
        clock=clock,
        sleep=clock.sleep,
    )
    assert result.status == "indeterminate"
    assert result.frozen is None
    assert result.polls == 19
    assert result.reason is not None and "expired" in result.reason


def test_full_scripted_transaction_end_to_end() -> None:
    """Contract sections 2 + 3 + 13: lease -> context assert -> navigate ->
    add entry (reversible pre-commit) -> click OK (the declared commit point) ->
    envelope satisfied -> reproduce -> verified.

    The pre-state snapshot is taken after the pre-commit interactions and
    immediately before the commit: everything before the first commit point is
    replayable scratch space, and the oracle compares machine state across the
    boundary.
    """
    desktop = _scripted_desktop()
    registry = LeaseRegistry()
    lease = registry.acquire("desktop-7", "wcd-driver")

    # Interactive context assertion (section 7)
    assert_context(desktop.interactive_context(), desktop.interactive_context())

    transaction = Transaction(transaction_id="author-scripts-entry")
    transaction.prepare(
        pre_oracle_done=True,
        lease_held=registry.is_active(lease),
        context_asserted=True,
        recovery_declared=True,
    )
    transaction.arm()

    # Pre-commit interactions: orientation + reversible staging.
    _click(desktop, "gpmc_main", "edit_scripts")
    assert desktop.foreground == "startup_properties"
    _click(desktop, "startup_properties", "scripts_tab")
    assert desktop.state["ui.active_tab"] == "Scripts"
    _click(desktop, "startup_properties", "add_button")
    assert desktop.foreground == "add_script_dialog"
    _click(desktop, "add_script_dialog", "script_name_field")
    desktop.key(text="logon.cmd")
    _click(desktop, "add_script_dialog", "script_parameters_field")
    desktop.key(text="-StartupParam")
    _click(desktop, "add_script_dialog", "ok_add")
    assert desktop.state["staged.entries"] == ["logon.cmd|-StartupParam"]
    _click(desktop, "startup_properties", "ps_order_dropdown")
    assert desktop.state["staged.ps_order"] == "powershell_first"

    # The pre-state oracle snapshot, then the declared commit point.
    pre_facts = dict(desktop.state)
    _click(desktop, "startup_properties", "ok_button")
    transaction.commit("startup-scripts-dialog-ok", declared=True)
    assert desktop.foreground == "gpmc_main"
    assert desktop.state["scripts_ini.machine.entries"] == ["logon.cmd|-StartupParam"]
    assert desktop.state["version.machine"] == 5

    # Post-state oracle: convergence + reproduce (section 3), injectable clock.
    clock = FakeClock()
    convergence = converge(
        _envelope(), pre_facts, CATEGORIES, desktop.observe, clock=clock, sleep=clock.sleep
    )
    assert convergence.status == "satisfied"
    assert convergence.reproduce_observed == 2
    assert convergence.assertion.status == "satisfied"
    assert convergence.assertion.unclassified == ()

    transaction.resolve(
        envelope_satisfied=(convergence.status == "satisfied"),
        reproduce_satisfied=(convergence.reproduce_observed == 2),
        characterization=convergence.assertion.characterization,
    )
    assert transaction.state == "verified"
    assert not transaction.reconcile_required
    assert [event.to_state for event in transaction.events] == [
        "prepared",
        "armed",
        "commit_attempted",
        "verified",
    ]
    assert registry.is_active(lease)


def test_cancelled_transaction_leaves_machine_state_untouched() -> None:
    """The reversible_pre_commit class means what it says: cancel/close before
    the commit point undoes the staged work."""
    desktop = _scripted_desktop()
    _click(desktop, "gpmc_main", "edit_scripts")
    _click(desktop, "startup_properties", "add_button")
    _click(desktop, "add_script_dialog", "cancel_add")
    assert desktop.foreground == "startup_properties"
    _click(desktop, "startup_properties", "cancel_button")
    assert desktop.foreground == "gpmc_main"
    assert desktop.state["scripts_ini.machine.entries"] == []
    assert desktop.state["version.machine"] == 4
    assert "staged.entries" not in desktop.state
