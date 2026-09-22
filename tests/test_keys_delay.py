"""``keys`` step-level ``delay_ms`` must actually reach the helper.

The field existed in sheets since window 3 and the helper has honoured it all
along (validated 0..2000, defaulting to 150 when absent) -- but the executor
never forwarded it, so every sheet that leaned on a measured inter-step delay
ran at the 150 ms default while its labels claimed otherwise. Window 11's
menu walks are the load-bearing case: 600 ms measured, 250 ms lands the
keystroke on the control underneath as type-ahead. These tests pin the
forwarding itself, so the gap cannot reopen silently.
"""

from __future__ import annotations

from typing import Any

from wcd.helper_client import HelperResult
from wcd.runsheets import GestureExecutor, RunSheet, RunSheetError, SheetContext, Step

WINDOW = {
    "hwnd": 4242,
    "title": "zz Properties",
    "class": "#32770",
    "pid": 1000,
    "visible": True,
    "minimized": False,
    "rect": {"left": 0, "top": 0, "right": 800, "bottom": 600},
}

_ROOT = {
    "name": "zz Properties",
    "control_type": "Window",
    "rect": {"left": 0, "top": 0, "right": 800, "bottom": 600},
    "depth": 0,
}


class _RecordingTransport:
    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []

    def helper(self, request: dict[str, object], **_: object) -> HelperResult:
        self.requests.append(request)
        if request.get("action") == "windows":
            return HelperResult(outcome="ok", exit_code=0, payload={"windows": [WINDOW]})
        if request.get("action") == "uia_dump":
            return HelperResult(
                outcome="ok", exit_code=0, payload={"hwnd": WINDOW["hwnd"], "elements": [_ROOT]}
            )
        if request.get("action") == "keys":
            return HelperResult(outcome="ok", exit_code=0, payload={"injected_events": 2})
        raise AssertionError(f"unexpected helper action {request.get('action')!r}")


def _run(executor: GestureExecutor, **params: object) -> tuple[list[dict[str, object]], Any]:
    step = Step(action="keys", profile_action=None, params=params)
    ctx = SheetContext(inputs={})
    ctx.last_dump_hwnd = int(WINDOW["hwnd"])  # type: ignore[arg-type]
    journal = executor.execute(RunSheet(name="t", surface="certsrv", steps=(step,)), ctx)
    return journal, ctx


def _executor(transport: _RecordingTransport, tmp_path: Any) -> GestureExecutor:
    return GestureExecutor(
        transport,  # type: ignore[arg-type]
        guest_scripts_dir=tmp_path,
        host_scripts_dir=tmp_path,
        evidence_dir=tmp_path,
    )


def test_declared_delay_ms_reaches_the_helper_request(tmp_path: Any) -> None:
    """The measured 600 ms window-11 cadence is what the guest must apply."""
    transport = _RecordingTransport()
    journal, _ctx = _run(
        _executor(transport, tmp_path), steps=[{"text": "p"}], delay_ms=600
    )
    assert journal[0]["ok"] is True
    keys_calls = [r for r in transport.requests if r.get("action") == "keys"]
    assert len(keys_calls) == 1
    assert keys_calls[0]["delay_ms"] == 600


def test_absent_delay_ms_is_omitted_not_defaulted(tmp_path: Any) -> None:
    """No declaration means the helper's own 150 ms default -- as before."""
    transport = _RecordingTransport()
    journal, _ctx = _run(_executor(transport, tmp_path), steps=[{"text": "p"}])
    assert journal[0]["ok"] is True
    keys_calls = [r for r in transport.requests if r.get("action") == "keys"]
    assert "delay_ms" not in keys_calls[0]


def test_out_of_range_delay_ms_refuses_before_any_helper_call(tmp_path: Any) -> None:
    """The helper would fail the whole invocation in-guest (0..2000); refuse
    here instead, where the step is identifiable and nothing was injected."""
    import pytest

    for bad in (-1, 2001, "600", True, 600.5):
        transport = _RecordingTransport()
        with pytest.raises(RunSheetError) as excinfo:
            _run(_executor(transport, tmp_path), steps=[{"text": "p"}], delay_ms=bad)
        assert "delay_ms" in str(excinfo.value), bad
        assert not [r for r in transport.requests if r.get("action") == "keys"], bad
