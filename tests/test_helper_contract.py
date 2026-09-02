"""Contract tests for the in-guest helper (guest/helper.ps1) and its client.

Coverage, per the working agreement (docs/contract.md sections 8 and 13):

- The JSON contract is locked in both directions: every request shape
  round-trips through build_request, and every action's response envelope is
  compared key-for-key against the TypedDict declared in wcd.helper_client.
- parse_response's exit-code mapping (0 ok / 2 error / 3 indeterminate) and
  its never-raises handling of malformed output.
- REAL local execution of the read-only actions -- context, uia_dump,
  screenshot -- against this machine's live desktop. These are the only
  helper behaviours verified beyond structure.
- key/mouse ONLY via -DryRun: input injection into the user's live session
  is absolutely forbidden in tests. A dry run validates the request,
  computes the would_inject summary (including the window-relative to
  screen conversion), and never loads the SendInput plumbing, so the
  observable contract is the envelope itself.
- The secret discipline: secret-shaped text warns, and only length + sha256
  ever reach stdout or stderr -- never the plaintext.

Everything else (real injection delivery, in-guest behaviour under a real
transaction, helper death and restart semantics) remains unverified until the
first estate window; see the report in the module docstring of
wcd/helper_client.py and the claim registry when that qualification happens.
"""

import base64
import hashlib
import json
import re
import subprocess
from typing import Any

import ps_scripts
import pytest

from wcd import helper_client as hc


def run_helper(
    payload: dict[str, Any] | str,
    *switches: str,
    timeout: float = 120.0,
) -> subprocess.CompletedProcess[str]:
    stdin_text = json.dumps(payload) if isinstance(payload, dict) else payload
    return ps_scripts.run_script(
        ps_scripts.HELPER_PATH, list(switches), stdin=stdin_text, timeout=timeout
    )


# --- Structural checks on the PowerShell sources ------------------------------


def test_helper_parses_under_windows_powershell_51() -> None:
    ps_scripts.parse_check(ps_scripts.HELPER_PATH)


def test_helper_is_pure_ascii() -> None:
    ps_scripts.assert_ascii_only(ps_scripts.HELPER_PATH)


def test_psscriptanalyzer_clean_when_available() -> None:
    if not ps_scripts.psscriptanalyzer_available():
        pytest.skip(
            "PSScriptAnalyzer is not installed on this machine; noted and skipped, not installed"
        )
    findings = ps_scripts.scriptanalyzer_findings(ps_scripts.HELPER_PATH)
    assert findings == []


# --- Request/response contract, controller side -------------------------------


def test_build_request_round_trips_for_every_action() -> None:
    requests: list[tuple[str, dict[str, object]]] = [
        ("context", {}),
        ("uia_dump", {"depth": 3}),
        ("screenshot", {"full": True}),
        ("key", {"text": "hello"}),
        ("key", {"vks": [{"vk": 13, "modifiers": ["ctrl"]}]}),
        ("mouse", {"x": 5, "y": 6, "button": "left", "mouse_action": "click"}),
        ("wait_foreground", {"class": "Notepad", "timeout_ms": 1000}),
    ]
    for action, params in requests:
        raw = hc.build_request(action, **params)
        decoded = json.loads(raw)
        assert decoded["action"] == action
        for key, value in params.items():
            assert decoded[key] == value


def test_build_request_refuses_unknown_action() -> None:
    with pytest.raises(ValueError, match="unknown helper action"):
        hc.build_request("reboot")


def test_parse_response_maps_exit_codes() -> None:
    ok = hc.parse_response('{"ok": true, "action": "context"}', hc.EXIT_OK)
    assert ok.outcome == "ok"
    assert ok.error is None
    assert not ok.malformed
    assert ok.payload == {"ok": True, "action": "context"}

    error = hc.parse_response('{"ok": false, "error": "boom"}', hc.EXIT_ERROR)
    assert error.outcome == "error"
    assert error.error == "boom"

    indeterminate = hc.parse_response(
        '{"ok": false, "indeterminate": true, "error": "timed out"}', hc.EXIT_INDETERMINATE
    )
    assert indeterminate.outcome == "indeterminate"
    assert indeterminate.error == "timed out"


def test_parse_response_malformed_output_never_raises() -> None:
    for stdout in ("", "   ", "not json", "[1, 2]", '"a string"', "null"):
        result = hc.parse_response(stdout, hc.EXIT_OK)
        assert result.outcome == "error"
        assert result.malformed is True
        assert result.payload == {}


def test_parse_response_flags_contradictory_exit_zero() -> None:
    result = hc.parse_response('{"ok": false, "error": "late failure"}', hc.EXIT_OK)
    assert result.outcome == "error"
    assert result.error == "late failure"
    assert not result.malformed


def test_parse_response_flags_unexpected_exit_code() -> None:
    result = hc.parse_response('{"ok": true}', 1)
    assert result.outcome == "error"
    assert result.error is not None
    assert "unexpected helper exit code 1" in result.error


def test_invoke_with_fake_transport() -> None:
    calls: list[str] = []

    def transport(request: str) -> tuple[str, int]:
        calls.append(request)
        return '{"ok": true, "action": "context"}', hc.EXIT_OK

    request = hc.build_request("context")
    result = hc.invoke(transport, request)
    assert calls == [request]
    assert result.outcome == "ok"


def test_invoke_transport_failure_is_data_not_an_exception() -> None:
    def broken_transport(request: str) -> tuple[str, int]:
        raise OSError("the guest stopped answering")

    result = hc.invoke(broken_transport, hc.build_request("context"))
    assert result.outcome == "error"
    assert result.exit_code == -1
    assert result.error is not None
    assert "the guest stopped answering" in result.error


def test_invoke_refuses_nonpositive_timeout() -> None:
    with pytest.raises(ValueError, match="timeout"):
        hc.invoke(_ok_transport, hc.build_request("context"), timeout=0)


def _ok_transport(request: str) -> tuple[str, int]:
    return '{"ok": true}', hc.EXIT_OK


def test_dry_run_coercion_accepts_a_dry_run_result() -> None:
    raw = (
        '{"ok": true, "action": "mouse", "dry_run": true, '
        '"would_inject": {"kind": "mouse"}, "secret_shaped_warning": false}'
    )
    dry = hc.dry_run(hc.parse_response(raw, hc.EXIT_OK))
    assert dry.action == "mouse"
    assert dry.would_inject == {"kind": "mouse"}
    assert dry.secret_shaped_warning is False


def test_dry_run_coercion_rejects_non_dry_run_results() -> None:
    with pytest.raises(ValueError, match="not a dry-run result"):
        hc.dry_run(hc.parse_response('{"ok": false, "error": "x"}', hc.EXIT_ERROR))
    with pytest.raises(ValueError, match="not a dry-run result"):
        hc.dry_run(hc.parse_response('{"ok": true, "action": "key"}', hc.EXIT_OK))


# --- Real local execution: the read-only actions ------------------------------


@pytest.fixture(scope="module")
def desktop_context() -> dict[str, Any]:
    """One real context read; guards the tests that need a live desktop."""
    proc = run_helper({"action": "context"})
    payload = assert_single_line_json(proc)
    if proc.returncode != 0 or payload.get("ok") is not True:
        pytest.fail(f"helper context failed on a machine that should have a desktop: {payload}")
    if not isinstance(payload.get("foreground"), dict):
        pytest.skip(
            "no interactive desktop session detected (foreground window unresolved); "
            "the real read-only checks were skipped, not faked"
        )
    return payload


def assert_single_line_json(proc: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    return ps_scripts.assert_single_line_json(proc)


def test_context_on_live_desktop() -> None:
    proc = run_helper({"action": "context"})
    payload = assert_single_line_json(proc)
    assert proc.returncode == 0
    assert set(payload) == set(hc.ContextResponse.__annotations__)
    assert isinstance(payload["session_id"], int)
    assert isinstance(payload["user"], str) and payload["user"]
    notes = [str(note) for note in payload["notes"]]

    foreground = payload["foreground"]
    if foreground is None:
        # Honest unresolved is contract-conformant, but only with a note.
        assert any("unresolved" in note for note in notes)
        pytest.skip("no foreground window on the calling desktop; envelope shape still validated")
    assert set(foreground) == set(hc.ForegroundInfo.__annotations__)
    assert foreground["hwnd"] > 0
    assert foreground["pid"] > 0

    rect = foreground["rect"]
    assert rect is not None
    assert rect["width"] == rect["right"] - rect["left"]
    assert rect["height"] == rect["bottom"] - rect["top"]

    digest = foreground["uia_digest"]
    if digest is None:
        # Over-budget walks report null with a note, never an unstable value.
        assert any("uia_digest" in note and "unresolved" in note for note in notes)
    else:
        assert re.fullmatch(r"[0-9a-f]{64}", digest)


def test_uia_dump_returns_a_depth_bounded_preorder_tree(desktop_context: dict[str, Any]) -> None:
    proc = run_helper({"action": "uia_dump", "depth": 2})
    payload = assert_single_line_json(proc)
    assert proc.returncode == 0
    assert set(payload) == set(hc.UiaDumpResponse.__annotations__)
    assert payload["depth"] == 2

    elements = payload["elements"]
    assert isinstance(elements, list) and elements
    for element in elements:
        assert set(element) == set(hc.UiaElement.__annotations__)
        assert 0 <= element["depth"] <= 2
        assert isinstance(element["patterns"], list)
        rect = element["rect"]
        if rect is not None:
            assert rect["width"] >= 0 and rect["height"] >= 0
    assert payload["element_count"] == len(elements)


def test_screenshot_captures_the_foreground_window(desktop_context: dict[str, Any]) -> None:
    proc = run_helper({"action": "screenshot"})
    payload = assert_single_line_json(proc)
    assert proc.returncode == 0
    assert set(payload) == set(hc.ScreenshotResponse.__annotations__)
    assert payload["full"] is False

    png = base64.b64decode(payload["png_base64"])
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    assert payload["png_sha256"] == hashlib.sha256(png).hexdigest()
    assert payload["bytes"] == len(png)
    assert payload["width"] > 0 and payload["height"] > 0
    rect = payload["rect"]
    assert isinstance(rect, dict)
    assert rect["width"] == payload["width"]


def test_screenshot_full_virtual_screen(desktop_context: dict[str, Any]) -> None:
    proc = run_helper({"action": "screenshot", "full": True})
    payload = assert_single_line_json(proc)
    assert proc.returncode == 0
    assert set(payload) == set(hc.ScreenshotResponse.__annotations__)
    assert payload["full"] is True
    png = base64.b64decode(payload["png_base64"])
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    assert payload["png_sha256"] == hashlib.sha256(png).hexdigest()


def test_wait_foreground_matches_the_current_fingerprint() -> None:
    context_proc = run_helper({"action": "context"})
    context = assert_single_line_json(context_proc)
    foreground = context["foreground"]
    if not isinstance(foreground, dict):
        pytest.skip("no foreground window; wait_foreground needs one to match")
    # class + pid together are the stable cheap fingerprint of the window we
    # just observed; the poll must find it again within its window.
    proc = run_helper(
        {
            "action": "wait_foreground",
            "class": foreground["class"],
            "pid": foreground["pid"],
            "timeout_ms": 5000,
            "poll_ms": 100,
        }
    )
    payload = assert_single_line_json(proc)
    assert proc.returncode == 0, payload
    assert set(payload) == set(hc.WaitForegroundResponse.__annotations__)
    assert payload["matched"] is True
    assert payload["indeterminate"] is False
    matched_context = payload["context"]
    assert isinstance(matched_context, dict)
    assert set(matched_context) == set(hc.ContextSurface.__annotations__)
    matched_foreground = matched_context["foreground"]
    assert isinstance(matched_foreground, dict)
    assert matched_foreground["pid"] == foreground["pid"]


def test_wait_foreground_timeout_is_indeterminate_exit_3() -> None:
    proc = run_helper(
        {
            "action": "wait_foreground",
            "class": "__wcd_no_such_class__",
            "timeout_ms": 700,
            "poll_ms": 100,
        }
    )
    payload = assert_single_line_json(proc)
    assert proc.returncode == 3
    assert set(payload) == set(hc.WaitForegroundResponse.__annotations__)
    assert payload["indeterminate"] is True
    assert payload["ok"] is False
    assert payload["matched"] is False
    assert "no foreground window matched" in str(payload["error"])
    # The indeterminate result is a result, not a failure: it carries the last
    # honest observation so reconciliation has something to work with.
    last = payload["last_foreground"]
    assert isinstance(last, dict)
    assert set(last) == set(hc.LastForeground.__annotations__)


@pytest.mark.parametrize(
    "payload",
    [
        {"action": "wait_foreground"},
        {"action": "wait_foreground", "title_regex": "([unclosed"},
        {"action": "wait_foreground", "class": "X", "timeout_ms": 10},
        {"action": "wait_foreground", "class": "X", "poll_ms": 1},
        {"action": "uia_dump", "depth": 0},
        {"action": "uia_dump", "depth": 13},
    ],
)
def test_read_action_validation_refuses_bad_requests(payload: dict[str, Any]) -> None:
    proc = run_helper(payload)
    result = assert_single_line_json(proc)
    assert proc.returncode == 2
    assert result["ok"] is False
    assert isinstance(result.get("error"), str) and result["error"]


# --- Inject actions: DryRun only, never a real injection ----------------------


def test_key_dry_run_returns_would_inject_without_injecting() -> None:
    text = "hello"
    proc = run_helper({"action": "key", "text": text}, "-DryRun")
    payload = assert_single_line_json(proc)
    assert proc.returncode == 0
    assert set(payload) == set(hc.KeyResponse.__annotations__)

    dry = hc.dry_run(hc.parse_response(proc.stdout, proc.returncode))
    assert dry.action == "key"
    assert dry.would_inject["kind"] == "key"
    assert dry.would_inject["text_length"] == len(text)
    assert dry.would_inject["text_sha256"] == hashlib.sha256(text.encode("utf-8")).hexdigest()

    # No injection path executed: only the real path reports injected events,
    # and a dry-run response never carries them.
    assert payload["dry_run"] is True
    assert payload["injected_events"] is None
    assert payload["chords_sent"] is None
    assert "injected_events" not in dry.would_inject
    # Evidence discipline: the text itself never lands in the response.
    assert text not in proc.stdout


def test_key_dry_run_echoes_vk_chords() -> None:
    chord = {"vk": 13, "modifiers": ["ctrl", "shift"]}
    proc = run_helper({"action": "key", "vks": [chord]}, "-DryRun")
    payload = assert_single_line_json(proc)
    assert proc.returncode == 0
    assert payload["text_length"] is None
    assert payload["text_sha256"] is None
    assert payload["secret_shaped_warning"] is False

    dry = hc.dry_run(hc.parse_response(proc.stdout, proc.returncode))
    assert dry.would_inject["kind"] == "key"
    assert dry.would_inject["vks"] == [chord]


def test_request_level_dry_run_flag_matches_the_switch() -> None:
    # The switch is the operator-facing form; the "dry_run" request field lets
    # a payload-only caller dry-run. Tests ALWAYS pass the switch as well:
    # belt and braces, because these tests must never reach a real injection.
    proc = run_helper({"action": "key", "text": "hi", "dry_run": True}, "-DryRun")
    payload = assert_single_line_json(proc)
    assert proc.returncode == 0
    assert payload["dry_run"] is True
    hc.dry_run(hc.parse_response(proc.stdout, proc.returncode))


def test_mouse_dry_run_resolves_window_relative_to_screen() -> None:
    proc = run_helper(
        {"action": "mouse", "x": 10, "y": 20, "button": "right", "mouse_action": "double"},
        "-DryRun",
    )
    payload = assert_single_line_json(proc)
    assert proc.returncode == 0
    assert set(payload) == set(hc.MouseResponse.__annotations__)
    assert payload["injected_events"] is None

    dry = hc.dry_run(hc.parse_response(proc.stdout, proc.returncode))
    would = dry.would_inject
    assert would["kind"] == "mouse"
    assert would["x"] == 10 and would["y"] == 20
    assert would["button"] == "right" and would["mouse_action"] == "double"
    # The reference window is the foreground window identified in the same
    # request (no explicit hwnd was given), and the screen conversion is
    # computed: window-relative + the reference window's origin.
    assert would["reference"] == "foreground"
    assert isinstance(would["hwnd"], int)
    screen = would["screen"]
    assert isinstance(screen, dict)
    assert isinstance(screen["x"], int) and isinstance(screen["y"], int)


@pytest.mark.parametrize(
    "payload",
    [
        {"action": "key"},
        {"action": "key", "text": ""},
        {"action": "key", "vks": []},
        {"action": "key", "vks": [{"vk": 0}]},
        {"action": "key", "vks": [{"vk": 255}]},
        {"action": "key", "vks": [{"vk": 13, "modifiers": ["hyper"]}]},
        {"action": "key", "text": 5},
        {"action": "mouse", "x": 5},
        {"action": "mouse", "y": 5},
        {"action": "mouse", "x": -1, "y": 5},
        {"action": "mouse", "x": 5, "y": 5, "button": "middle"},
        {"action": "mouse", "x": 5, "y": 5, "mouse_action": "triple"},
    ],
)
def test_inject_parameter_validation_refuses_bad_requests(payload: dict[str, Any]) -> None:
    # Validation is exactly what -DryRun exists to exercise; these requests
    # must be refused before any injection path is even loaded.
    proc = run_helper(payload, "-DryRun")
    result = assert_single_line_json(proc)
    assert proc.returncode == 2
    assert result["ok"] is False
    assert isinstance(result.get("error"), str) and result["error"]


# --- The secret discipline ----------------------------------------------------


def test_key_dry_run_marks_secret_shaped_text_and_never_echoes_it() -> None:
    secret_shaped = "Abcdef123456"  # 12 chars: upper + lower + digit
    proc = run_helper({"action": "key", "text": secret_shaped}, "-DryRun")
    payload = assert_single_line_json(proc)
    assert proc.returncode == 0
    assert payload["secret_shaped_warning"] is True
    assert payload["text_length"] == len(secret_shaped)
    assert payload["text_sha256"] == hashlib.sha256(secret_shaped.encode("utf-8")).hexdigest()
    # The helper still proceeds (warning, not refusal) -- but the plaintext
    # must not land in evidence, on either stream.
    assert secret_shaped not in proc.stdout
    assert secret_shaped not in proc.stderr


def test_key_dry_run_plain_text_is_not_marked_secret_shaped() -> None:
    proc = run_helper({"action": "key", "text": "hello"}, "-DryRun")
    payload = assert_single_line_json(proc)
    assert payload["secret_shaped_warning"] is False


def test_secret_shape_needs_upper_lower_and_digit() -> None:
    for text in ("abcdefghijkl", "ABCDEFGHIJKL", "abcdefghijkl1"):
        proc = run_helper({"action": "key", "text": text}, "-DryRun")
        payload = assert_single_line_json(proc)
        expected = bool(
            len(text) >= 12
            and re.search(r"[A-Z]", text)
            and re.search(r"[a-z]", text)
            and re.search(r"[0-9]", text)
        )
        assert payload["secret_shaped_warning"] is expected, text


# --- Protocol robustness ------------------------------------------------------


@pytest.mark.parametrize(
    "stdin_text",
    [
        "not json at all",
        "",
        "[1, 2, 3]",
        '"just a string"',
        "42",
        "{}",
        '{"nope": 1}',
        '{"action": "reboot"}',
        '{"action": "CONTEXT"}',
    ],
)
def test_helper_refuses_malformed_or_unknown_requests_with_exit_2(stdin_text: str) -> None:
    proc = run_helper(stdin_text)
    result = assert_single_line_json(proc)
    assert proc.returncode == 2
    assert result["ok"] is False
    assert isinstance(result.get("error"), str) and result["error"]
    # An error envelope still carries the notes array, even when empty.
    assert isinstance(result.get("notes"), list)
