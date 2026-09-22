"""The ``wait_element`` primitive: waiting for CONTENT, not for a window.

``wait_foreground`` answers "does the window exist". That was sufficient for
every surface whose content is local, and it is not sufficient for a console
that administers a REMOTE service: the certsrv frame's title gains the CA host
the instant Retarget commits, while the console sits ``(Not Responding)``
enumerating the remote CA and its results pane is still empty.

Window 11's first run aborted on exactly that -- before its commit point, so
nothing was written -- and the fix is a primitive rather than a settle, because
the right delay is whatever the other machine takes today.

These tests drive the primitive through a stub transport: no host, no guest,
no helper. What they pin is the behaviour that makes it worth having over a
sleep -- that it polls, that it gives up with the last failure visible, and
that a window too busy to report its contents is a reason to keep waiting
rather than a report that the contents are absent.
"""

from __future__ import annotations

from typing import Any

import pytest

from wcd.helper_client import HelperResult
from wcd.runsheets import GestureExecutor, RunSheet, RunSheetError, SheetContext, Step

WINDOW = {
    "hwnd": 4242,
    "title": "certsrv - [Certification Authority (LabCA01.zzlab.invalid)]",
    "class": "MMCMainFrame",
    "pid": 1000,
    "visible": True,
    "minimized": False,
    "rect": {"left": 0, "top": 0, "right": 800, "bottom": 600},
}

_ROOT = {
    "name": "certsrv - [Certification Authority (LabCA01.zzlab.invalid)]",
    "control_type": "Window",
    "rect": {"left": 0, "top": 0, "right": 800, "bottom": 600},
    "depth": 0,
}
_ROW = {
    "name": "zz Issuing CA 01",
    "control_type": "ListItem",
    "rect": {"left": 300, "top": 100, "right": 600, "bottom": 120},
    "depth": 0,
}


class _StubTransport:
    """Answers ``windows`` and ``uia_dump``; the dump's contents are scripted.

    ``dumps`` is one entry per uia_dump call: a list of elements, or an
    Exception to raise (the busy-window case).
    """

    def __init__(self, dumps: list[Any]) -> None:
        self._dumps = list(dumps)
        self.dump_calls = 0

    def helper(self, request: dict[str, object], **_: object) -> HelperResult:
        if request.get("action") == "windows":
            return HelperResult(outcome="ok", exit_code=0, payload={"windows": [WINDOW]})
        if request.get("action") == "uia_dump":
            self.dump_calls += 1
            nxt = self._dumps.pop(0) if self._dumps else []
            if isinstance(nxt, Exception):
                raise nxt
            return HelperResult(
                outcome="ok", exit_code=0, payload={"hwnd": WINDOW["hwnd"], "elements": nxt}
            )
        raise AssertionError(f"unexpected helper action {request.get('action')!r}")


def _executor(transport: _StubTransport, tmp_path: Any) -> GestureExecutor:
    return GestureExecutor(
        transport,  # type: ignore[arg-type]
        guest_scripts_dir=tmp_path,
        host_scripts_dir=tmp_path,
        evidence_dir=tmp_path,
    )


def _run(executor: GestureExecutor, **params: object) -> list[dict[str, object]]:
    step = Step(action="wait_element", profile_action=None, params=params)
    ctx = SheetContext(inputs={})
    ctx.last_dump_hwnd = int(WINDOW["hwnd"])  # type: ignore[arg-type]
    return executor.execute(RunSheet(name="t", surface="certsrv", steps=(step,)), ctx)


def test_returns_as_soon_as_the_element_is_there(tmp_path: Any) -> None:
    transport = _StubTransport([[_ROOT, _ROW]])
    journal = _run(
        _executor(transport, tmp_path),
        name_regex="^zz Issuing CA 01$",
        control_type="ListItem",
        timeout_ms=30000,
        poll_ms=10,
    )
    assert journal[0]["ok"] is True
    detail = journal[0]["detail"]
    assert isinstance(detail, dict)
    assert detail["matched"] is True
    assert detail["attempts"] == 1
    assert transport.dump_calls == 1


def test_polls_past_an_empty_pane_until_the_row_arrives(tmp_path: Any) -> None:
    """The measured failure: a correctly-titled frame with nothing in it yet."""
    transport = _StubTransport([[_ROOT], [_ROOT], [_ROOT, _ROW]])
    journal = _run(
        _executor(transport, tmp_path),
        name_regex="^zz Issuing CA 01$",
        control_type="ListItem",
        timeout_ms=30000,
        poll_ms=10,
    )
    detail = journal[0]["detail"]
    assert isinstance(detail, dict)
    assert detail["attempts"] == 3
    assert transport.dump_calls == 3


def test_a_busy_window_is_a_reason_to_keep_waiting_not_to_fail(tmp_path: Any) -> None:
    """An unresponsive window cannot report its contents.

    That is not the same as reporting that its contents are absent, and the
    difference matters here: the console is at its LEAST responsive precisely
    while it is doing the remote work whose result the sheet is waiting for.
    A dump that raises must therefore extend the wait, not end it.
    """
    transport = _StubTransport(
        [
            RunSheetError("uia_dump failed: helper timed out"),
            RunSheetError("uia_dump was truncated (element or time cap)"),
            [_ROOT, _ROW],
        ]
    )
    journal = _run(
        _executor(transport, tmp_path),
        name_regex="^zz Issuing CA 01$",
        control_type="ListItem",
        timeout_ms=30000,
        poll_ms=10,
    )
    detail = journal[0]["detail"]
    assert isinstance(detail, dict)
    assert detail["attempts"] == 3


def test_timeout_names_the_selector_and_the_last_failure(tmp_path: Any) -> None:
    """A timeout that says only "timed out" sends the next reader to the wrong place.

    The useful report distinguishes "the pane never filled" from "the pane
    filled with something else", and only the last resolve failure carries
    that -- it lists what WAS visible.
    """
    transport = _StubTransport([[_ROOT]] * 50)
    with pytest.raises(RunSheetError) as excinfo:
        _run(
            _executor(transport, tmp_path),
            name_regex="^zz Issuing CA 01$",
            control_type="ListItem",
            timeout_ms=30,
            poll_ms=10,
        )
    message = str(excinfo.value)
    assert "zz Issuing CA 01" in message
    assert "attempts" in message
    # The last resolve failure is carried through, so the visible-element
    # list the resolver produced is in the record rather than discarded.
    assert "visible elements" in message


def test_name_regex_is_required(tmp_path: Any) -> None:
    transport = _StubTransport([[_ROOT, _ROW]])
    with pytest.raises(RunSheetError, match="wait_element needs name_regex"):
        _run(_executor(transport, tmp_path), timeout_ms=1000, poll_ms=10)


def test_control_type_filter_is_honoured(tmp_path: Any) -> None:
    """A same-named Pane must not satisfy a wait for a ListItem.

    MMC surfaces routinely carry both: the scope-tree peer and the
    results-pane row can share a name, and on this surface only one of them
    can be acted on.
    """
    pane_twin = dict(_ROW, control_type="Pane")
    transport = _StubTransport([[_ROOT, pane_twin]] * 50)
    with pytest.raises(RunSheetError, match="no element matching"):
        _run(
            _executor(transport, tmp_path),
            name_regex="^zz Issuing CA 01$",
            control_type="ListItem",
            timeout_ms=30,
            poll_ms=10,
        )


def test_non_positive_cadence_is_a_runsheet_error_not_a_bare_valueerror(
    tmp_path: Any,
) -> None:
    """A negative poll_ms used to reach time.sleep() and raise ValueError,
    escaping the journal wrapping (and the gesture phase's RunSheetError
    handling) -- losing the partial step journal. Refusal must be a
    RunSheetError like every other malformed step."""
    for bad in (-5, 0, "soon", None):
        transport = _StubTransport([[_ROOT, _ROW]])
        with pytest.raises(RunSheetError) as excinfo:
            _run(
                _executor(transport, tmp_path),
                name_regex="^zz Issuing CA 01$",
                poll_ms=bad,  # type: ignore[arg-type]
                timeout_ms=30000,
            )
        assert "poll_ms" in str(excinfo.value), bad
        assert transport.dump_calls == 0, bad


def test_no_target_window_refuses_rather_than_polling_the_foreground(
    tmp_path: Any,
) -> None:
    """Without a live target and without a window selector, the underlying
    dump falls back to the FOREGROUND -- which mid-sheet is the helper's own
    console. The wait would then poll the wrong window until timeout, so the
    step refuses up front exactly like keys and shot do."""
    step = Step(
        action="wait_element",
        profile_action=None,
        params={"name_regex": "^zz Issuing CA 01$", "timeout_ms": 5000},
    )
    executor = _executor(_StubTransport([[_ROOT, _ROW]]), tmp_path)
    ctx = SheetContext(inputs={})  # no last_dump_hwnd: no live target
    with pytest.raises(RunSheetError) as excinfo:
        executor.execute(RunSheet(name="t", surface="certsrv", steps=(step,)), ctx)
    assert "no target window" in str(excinfo.value)
