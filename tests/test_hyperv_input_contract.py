"""Contract tests for the host-side Hyper-V input backend (guest/hyperv-input.ps1).

The script never runs against a real host in tests: every invocation here is
either -ValidateOnly (parameters checked, plan JSON printed, exit 0, no
network, no WMI) or a refusal that happens before any session is created.
The injection path itself is unverified until the first estate window
(docs/contract.md section 13).

The plan JSON shape is documentation-as-execution: the tests below assert the
EXACT key set per action, so adding or removing a plan field is a contract
change that shows up here.

    plan = {
        script, host, vm_name, action, validate_only, route, wmi_calls,
        note, credentials,                      # common to every action
        vkey_code,                              # key
        text_length, text_sha256,               # text (never the plaintext)
        x, y, button, mouse_action,             # mouse
        button_index, button_state_transitions
    }
"""

import hashlib
import os
import subprocess
from typing import Any

import ps_scripts
import pytest


def run_hyperv(
    *args: str,
    env: dict[str, str] | None = None,
    timeout: float = 60.0,
) -> subprocess.CompletedProcess[str]:
    return ps_scripts.run_script(ps_scripts.HYPERV_INPUT_PATH, list(args), env=env, timeout=timeout)


def control_credentials_env() -> dict[str, str]:
    # Dummy values are enough: the script only checks presence before
    # -ValidateOnly, and -ValidateOnly never opens a session.
    env = dict(os.environ)
    env["HYPERV_CONTROL_USERNAME"] = "dummy-control-user"
    env["HYPERV_CONTROL_PASSWORD"] = "dummy-control-password"
    return env


def env_without_control_credentials() -> dict[str, str]:
    env = dict(os.environ)
    env.pop("HYPERV_CONTROL_USERNAME", None)
    env.pop("HYPERV_CONTROL_PASSWORD", None)
    return env


def assert_denial(proc: subprocess.CompletedProcess[str], *fragments: str) -> dict[str, Any]:
    payload = ps_scripts.assert_single_line_json(proc)
    assert proc.returncode == 2
    assert payload["ok"] is False
    error = payload.get("error")
    assert isinstance(error, str) and error
    for fragment in fragments:
        assert fragment in error, f"expected {fragment!r} in error: {error}"
    return payload


# --- Structural checks on the PowerShell source -------------------------------


def test_hyperv_input_parses_under_windows_powershell_51() -> None:
    ps_scripts.parse_check(ps_scripts.HYPERV_INPUT_PATH)


def test_hyperv_input_is_pure_ascii() -> None:
    ps_scripts.assert_ascii_only(ps_scripts.HYPERV_INPUT_PATH)


def test_psscriptanalyzer_clean_when_available() -> None:
    if not ps_scripts.psscriptanalyzer_available():
        pytest.skip(
            "PSScriptAnalyzer is not installed on this machine; noted and skipped, not installed"
        )
    findings = ps_scripts.scriptanalyzer_findings(ps_scripts.HYPERV_INPUT_PATH)
    assert findings == []


# --- -ValidateOnly: the plan for every action, with no network ----------------


PLAN_COMMON_KEYS = {
    "script",
    "host",
    "vm_name",
    "action",
    "validate_only",
    "route",
    "wmi_calls",
    "note",
    "credentials",
}


def test_validate_only_key_action_prints_the_plan() -> None:
    proc = run_hyperv(
        "-HostName", "hv-host",
        "-VMName", "LabCL01",
        "-Action", "key",
        "-VKeyCode", "13",
        "-ValidateOnly",
        env=control_credentials_env(),
    )
    payload = ps_scripts.assert_single_line_json(proc)
    assert proc.returncode == 0
    assert payload["ok"] is True
    assert payload["validate_only"] is True
    plan = payload["plan"]
    assert isinstance(plan, dict)
    # Exact key set: the plan shape is part of this test file's documentation.
    assert set(plan) == PLAN_COMMON_KEYS | {"vkey_code"}
    assert plan["script"] == "hyperv-input"
    assert plan["host"] == "hv-host"
    assert plan["vm_name"] == "LabCL01"
    assert plan["action"] == "key"
    assert plan["validate_only"] is True
    assert plan["vkey_code"] == 13
    assert isinstance(plan["wmi_calls"], list) and plan["wmi_calls"]
    assert any("PressKey" in str(call) for call in plan["wmi_calls"])
    assert "Negotiate" in str(plan["route"]) and "virtualization" in str(plan["route"])
    # The blind-channel honesty note is part of the plan, not a footnote.
    assert "blind" in str(plan["note"]).lower()


def test_validate_only_text_action_reports_length_and_sha256_never_the_text() -> None:
    proc = run_hyperv(
        "-HostName", "hv-host",
        "-VMName", "LabCL01",
        "-Action", "text",
        "-Text", "hello",
        "-ValidateOnly",
        env=control_credentials_env(),
    )
    payload = ps_scripts.assert_single_line_json(proc)
    assert proc.returncode == 0
    plan = payload["plan"]
    assert isinstance(plan, dict)
    assert set(plan) == PLAN_COMMON_KEYS | {"text_length", "text_sha256"}
    assert plan["text_length"] == 5
    assert plan["text_sha256"] == hashlib.sha256(b"hello").hexdigest()
    # Same evidence discipline as the helper: the text never lands in output.
    assert "hello" not in proc.stdout
    assert "hello" not in proc.stderr


def test_validate_only_mouse_action_documents_button_transitions() -> None:
    proc = run_hyperv(
        "-HostName", "hv-host",
        "-VMName", "LabCL01",
        "-Action", "mouse",
        "-X", "100",
        "-Y", "200",
        "-Button", "right",
        "-MouseAction", "double",
        "-ValidateOnly",
        env=control_credentials_env(),
    )
    payload = ps_scripts.assert_single_line_json(proc)
    assert proc.returncode == 0
    plan = payload["plan"]
    assert isinstance(plan, dict)
    assert set(plan) == PLAN_COMMON_KEYS | {
        "x",
        "y",
        "button",
        "mouse_action",
        "button_index",
        "button_state_transitions",
    }
    assert plan["x"] == 100 and plan["y"] == 200
    assert plan["button"] == "right"
    assert plan["mouse_action"] == "double"
    assert plan["button_index"] == 1  # right button
    assert plan["button_state_transitions"] == 4  # down, up, down, up
    assert any("SetAbsolutePosition" in str(call) for call in plan["wmi_calls"])
    assert any("SetButtonState" in str(call) for call in plan["wmi_calls"])


def test_validate_only_accepts_lowercase_lab_prefix() -> None:
    proc = run_hyperv(
        "-HostName", "hv-host",
        "-VMName", "labcl01",
        "-Action", "key",
        "-VKeyCode", "13",
        "-ValidateOnly",
        env=control_credentials_env(),
    )
    payload = ps_scripts.assert_single_line_json(proc)
    assert proc.returncode == 0
    assert payload["plan"]["vm_name"] == "labcl01"


# --- Refusals: exit 2 with a clear error, before any network or WMI -----------


def test_invalid_vmname_is_refused_with_exit_2() -> None:
    proc = run_hyperv(
        "-HostName", "hv-host",
        "-VMName", "ProdWeb01",
        "-Action", "text",
        "-Text", "hi",
        "-ValidateOnly",
        env=control_credentials_env(),
    )
    payload = assert_denial(proc, "refused", "naming convention")
    assert payload["validate_only"] is True


@pytest.mark.parametrize("vm_name", ["Lab", "LABcl01", "ProdWeb01", "LabToolongnamehere15"])
def test_vmname_naming_guard_is_case_sensitive(vm_name: str) -> None:
    proc = run_hyperv(
        "-HostName", "hv-host",
        "-VMName", vm_name,
        "-Action", "key",
        "-VKeyCode", "13",
        "-ValidateOnly",
        env=control_credentials_env(),
    )
    assert_denial(proc, "refused")


def test_invalid_action_is_refused() -> None:
    proc = run_hyperv(
        "-HostName", "hv-host",
        "-VMName", "LabCL01",
        "-Action", "reboot",
        "-ValidateOnly",
        env=control_credentials_env(),
    )
    assert_denial(proc, "key, text, mouse")


@pytest.mark.parametrize(
    "args",
    [
        # key without a virtual-key code
        ("-Action", "key"),
        # text without text
        ("-Action", "text"),
        # mouse without coordinates
        ("-Action", "mouse"),
        # mouse coordinates out of the normalized 0..65535 range
        ("-Action", "mouse", "-X", "-1", "-Y", "100"),
        ("-Action", "mouse", "-X", "70000", "-Y", "100"),
        ("-Action", "mouse", "-X", "100", "-Y", "65536"),
        # unknown button / gesture
        ("-Action", "mouse", "-X", "100", "-Y", "100", "-Button", "middle"),
        ("-Action", "mouse", "-X", "100", "-Y", "100", "-MouseAction", "triple"),
    ],
)
def test_parameter_validation_refuses_bad_requests(args: tuple[str, ...]) -> None:
    proc = run_hyperv("-HostName", "hv-host", "-VMName", "LabCL01", *args, "-ValidateOnly",
                      env=control_credentials_env())
    assert_denial(proc)


def test_empty_hostname_is_refused() -> None:
    proc = run_hyperv(
        "-HostName", "",
        "-VMName", "LabCL01",
        "-Action", "key",
        "-VKeyCode", "13",
        "-ValidateOnly",
        env=control_credentials_env(),
    )
    assert_denial(proc, "HostName")


def test_missing_control_credentials_are_refused_with_a_clear_error() -> None:
    proc = run_hyperv(
        "-HostName", "hv-host",
        "-VMName", "LabCL01",
        "-Action", "key",
        "-VKeyCode", "13",
        "-ValidateOnly",
        env=env_without_control_credentials(),
    )
    assert_denial(proc, "HYPERV_CONTROL_USERNAME")


def test_missing_control_credentials_refuse_a_real_run_before_any_network_call() -> None:
    # Not a -ValidateOnly run, and safe for exactly that reason: the
    # environment check precedes New-PSSession in the script body, so this
    # invocation must refuse before any network or WMI access. A test that
    # ran the real path WITH credentials present would dial a host, which is
    # why none exists here.
    proc = run_hyperv(
        "-HostName", "hv-host",
        "-VMName", "LabCL01",
        "-Action", "key",
        "-VKeyCode", "13",
        env=env_without_control_credentials(),
    )
    assert_denial(proc, "HYPERV_CONTROL_USERNAME")
