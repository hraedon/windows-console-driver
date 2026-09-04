"""CLI contract tests: verbs, plan/record wire format, error exits, secrets.

``wcd.cli`` is the seam the WEL backend launches; these tests pin its
observable contract without Windows and without any real session:

- subcommand parsing: the required verb, unknown verbs (with the full verb
  list named), unknown flags and missing values all exit 2 with usage on
  stderr;
- ``exec-transaction``: the stdin-JSON plan -> stdout-JSON record contract
  (plan on stdin, exactly ``{state, verdict, envelope_result, events,
  provenance}`` on stdout, and nothing else), the ``--capability``/``--arg``
  controller-direct mode with JSON-typed argument binding, ``--out``
  mirroring, a non-zero exit ONLY for plumbing failures (an indeterminate
  record is a result, not an error), and clean ``plan error`` exits for
  malformed stdin plans;
- ``ensure-console``/``console-state``: the emitted payload shapes, the
  locked exit code 3, the ``--no-unlock``/``--audit`` routing, and transport
  teardown on every path;
- estate config lookup through a real TOML file, and the secret discipline:
  the estate NAMES the environment variable (``WCD_LAB_PASSWORD``) and the
  value is never echoed to stdout, stderr, or any emitted record.

Injection goes through the ``wcd.cli._default_transport`` factory seam and
monkeypatched ``execute_transaction``/``console_ops`` module attributes, so
no process, session, or credential store is ever touched.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from wcd import cli, console_ops
from wcd.console_ops import ConsoleState, LockAudit, RebootReadiness
from wcd.estate import EstateConfig

# Synthetic-estate identifiers only: zz- placeholders per the project
# convention. Nothing here names a real host, domain, user, or path, and the
# secret value below is a placeholder that must never reach any output.
SECRET = "zz-secret-password-value"


class FakeCliTransport:
    """Stands in for ``SessionTransport``: records the estate it was built from."""

    def __init__(self, estate: EstateConfig) -> None:
        self.estate = estate
        self.closed = False

    def close(self) -> None:
        self.closed = True


# A canned executor record with exactly the five wire keys of the contract.
_RECORD: dict[str, object] = {
    "state": "verified",
    "verdict": "envelope satisfied and reproduction verified",
    "envelope_result": {"status": "satisfied", "satisfied": [], "violated": []},
    "events": [
        {"sequence": 1, "from_state": "armed", "to_state": "commit_attempted", "reason": "crossed"}
    ],
    "provenance": {"capability": "zz.capability.cli", "run_sheet": "zz_cli_sheet", "notes": []},
}

_CAPABILITY: dict[str, object] = {
    "id": "zz.capability.cli",
    "surface": "zz-fake-surface",
    "run_sheet": "zz_cli_sheet",
    "gpo_transaction": True,
    "fact_plan": {"observers": []},
    "envelope": {},
}


def _estate_file(tmp_path: Path) -> Path:
    """A synthetic estate TOML: it NAMES the secret variable, never carries it."""
    path = tmp_path / "estate.toml"
    path.write_text(
        "[estate]\n"
        "host = 'zz-hyperv'\n"
        "vm_name = 'zz-vm'\n"
        "domain = 'zzlab.invalid'\n"
        "username = 'LAB\\zz-operator'\n"
        "password_env = 'WCD_LAB_PASSWORD'\n",
        encoding="utf-8",
    )
    return path


def _install_transport(monkeypatch: pytest.MonkeyPatch) -> list[FakeCliTransport]:
    """Wire the CLI's transport factory seam to fakes; return what it built."""
    built: list[FakeCliTransport] = []

    def build(estate: EstateConfig) -> FakeCliTransport:
        transport = FakeCliTransport(estate)
        built.append(transport)
        return transport

    monkeypatch.setattr(cli, "_default_transport", build)
    return built


def _install_executor(monkeypatch: pytest.MonkeyPatch, record: dict[str, object]) -> dict[str, Any]:
    """Wire ``execute_transaction`` to a canned record; return the call args."""
    calls: dict[str, Any] = {}

    def fake_execute(**kwargs: object) -> dict[str, object]:
        calls.update(kwargs)
        return record

    monkeypatch.setattr(cli, "execute_transaction", fake_execute)
    return calls


def _patch_console_ops(
    monkeypatch: pytest.MonkeyPatch,
    state: ConsoleState,
    *,
    audit: LockAudit | None = None,
    readiness: RebootReadiness | None = None,
    calls: dict[str, bool] | None = None,
) -> None:
    """Patch the console verbs' ops; record which lookup path each verb took."""

    def fake_lock_state(t: object, *, probe_helper: bool = True) -> ConsoleState:
        if calls is not None:
            calls["lock_state"] = True
        return state

    def fake_wait(t: object, estate: EstateConfig, **_kw: object) -> ConsoleState:
        if calls is not None:
            calls["wait_console_unlocked"] = True
        return state

    monkeypatch.setattr(console_ops, "lock_state", fake_lock_state)
    monkeypatch.setattr(console_ops, "wait_console_unlocked", fake_wait)
    if audit is not None:
        monkeypatch.setattr(console_ops, "read_lock_audit", lambda t: audit)
    if readiness is not None:
        monkeypatch.setattr(console_ops, "reboot_readiness", lambda t: readiness)


def _stdin(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(text))


# --- subcommand parsing and error exits ---------------------------------------------


def test_missing_verb_and_unknown_verb_exit_2_with_usage_on_stderr(
    capsys: pytest.CaptureFixture,
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main([])
    assert excinfo.value.code == 2
    assert "required" in capsys.readouterr().err

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["zz-no-such-verb"])
    assert excinfo.value.code == 2
    err = capsys.readouterr().err
    assert "invalid choice" in err
    # The usage names every verb, so the parse error is actionable.
    for verb in ("exec-transaction", "ensure-console", "console-state"):
        assert verb in err


def test_unknown_flag_and_missing_value_exit_2(capsys: pytest.CaptureFixture) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["console-state", "zz-extra"])
    assert excinfo.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["exec-transaction", "--arg"])
    assert excinfo.value.code == 2
    assert "expected one argument" in capsys.readouterr().err


def test_missing_or_malformed_estate_is_a_clean_nonzero_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.chdir(tmp_path)  # the default local/estate.toml does not exist here
    assert cli.main(["console-state"]) == 2
    err = capsys.readouterr().err
    assert "estate error" in err
    assert "estate file not found" in err
    assert capsys.readouterr().out == ""  # no payload is emitted for a config error

    bad = tmp_path / "bad.toml"
    bad.write_text("[estate\n", encoding="utf-8")  # malformed TOML
    assert cli.main(["--estate", str(bad), "console-state"]) == 2
    assert "estate error" in capsys.readouterr().err


# --- console-state -------------------------------------------------------------------


def test_console_state_emits_classification_and_closes_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    built = _install_transport(monkeypatch)
    _patch_console_ops(monkeypatch, ConsoleState("unlocked", False, True, True, ("zz-note",)))

    code = cli.main(["--estate", str(_estate_file(tmp_path)), "console-state"])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "state": "unlocked",
        "logonui_running": False,
        "console_session_active": True,
        "helper_responds": True,
        "notes": ["zz-note"],
    }
    # The estate TOML was really loaded into the transport that was closed.
    assert built and built[0].closed
    assert built[0].estate.vm_name == "zz-vm"
    assert built[0].estate.username == "LAB\\zz-operator"


# --- ensure-console ------------------------------------------------------------------


def test_ensure_console_no_unlock_reports_audit_and_reboot_and_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    built = _install_transport(monkeypatch)
    calls: dict[str, bool] = {}
    _patch_console_ops(
        monkeypatch,
        ConsoleState("unlocked", False, True, True, ()),
        audit=LockAudit(count=2, events=({"id": 4800}, {"id": 4801})),
        readiness=RebootReadiness(
            reachable=True,
            reboot_pending=False,
            reasons=(),
            last_boot="2026-09-01T10:00:00.0000000Z",
            classification="ready",
        ),
        calls=calls,
    )

    code = cli.main(
        ["--estate", str(_estate_file(tmp_path)), "ensure-console", "--no-unlock", "--audit"]
    )

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] == "unlocked"
    assert payload["lock_audit_count"] == 2
    assert [event["id"] for event in payload["lock_audit_events"]] == [4800, 4801]
    assert payload["reboot"] == {
        "classification": "ready",
        "reboot_pending": False,
        "reasons": [],
        "last_boot": "2026-09-01T10:00:00.0000000Z",
    }
    # --no-unlock classifies without the wake/unlock wait loop.
    assert calls == {"lock_state": True}
    assert built[0].closed


def test_ensure_console_locked_state_takes_the_wait_path_and_exits_3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    _install_transport(monkeypatch)
    calls: dict[str, bool] = {}
    _patch_console_ops(
        monkeypatch,
        ConsoleState("locked", True, True, True, ()),
        readiness=RebootReadiness(
            reachable=True,
            reboot_pending=True,
            reasons=("PendingFileRenameOperations",),
            last_boot="2026-09-01T10:00:00.0000000Z",
            classification="reboot_pending",
        ),
        calls=calls,
    )

    code = cli.main(["--estate", str(_estate_file(tmp_path)), "ensure-console"])

    assert code == 3  # a locked console is data, not a crash: exit 3, payload emitted
    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] == "locked"
    assert payload["reboot"]["classification"] == "reboot_pending"
    assert calls == {"wait_console_unlocked": True}


# --- exec-transaction: the plan/record wire contract ---------------------------------


def test_exec_transaction_stdin_plan_emits_exactly_the_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    built = _install_transport(monkeypatch)
    record = dict(_RECORD)
    calls = _install_executor(monkeypatch, record)
    plan = {
        "operation_id": "op-zz-1",
        "machine": "zz-vm",
        "identity": "LAB\\zz-operator",
        "capability": json.dumps(_CAPABILITY),
        "arguments": {"gpo_name": "zz-studio-evidence-01", "threshold": 2},
    }
    _stdin(monkeypatch, json.dumps(plan))

    code = cli.main(["--estate", str(_estate_file(tmp_path)), "exec-transaction"])

    assert code == 0
    # The record is the ONLY stdout payload, parsed strictly by the caller.
    assert json.loads(capsys.readouterr().out) == record
    assert calls["capability"] == _CAPABILITY
    assert calls["arguments"] == {"gpo_name": "zz-studio-evidence-01", "threshold": 2}
    provenance = calls["plan_provenance"]
    assert provenance["mode"] == "wel_exec_transaction"
    assert provenance["operation_id"] == "op-zz-1"
    assert provenance["machine"] == "zz-vm"
    assert provenance["identity"] == "LAB\\zz-operator"
    assert calls["transport"] is built[0]
    assert built[0].closed  # the transport closes on the success path too


def test_exec_transaction_capability_flag_mode_binds_args(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    _install_transport(monkeypatch)
    calls = _install_executor(monkeypatch, dict(_RECORD))
    cap_path = tmp_path / "capability.json"
    cap_path.write_text(json.dumps(_CAPABILITY), encoding="utf-8")

    code = cli.main(
        [
            "--estate",
            str(_estate_file(tmp_path)),
            "exec-transaction",
            "--capability",
            str(cap_path),
            "--arg",
            "gpo_name=zz-studio-evidence-01",  # not JSON: stays a string
            "--arg",
            f"targets={json.dumps(['zz-a', 'zz-b'])}",  # JSON: binds as JSON
            "--arg",
            "threshold=2",  # JSON number
            "--arg",
            "zz_flag",  # no '=': empty-string value
        ]
    )

    assert code == 0
    assert json.loads(capsys.readouterr().out) == dict(_RECORD)
    assert calls["capability"] == _CAPABILITY
    assert calls["arguments"] == {
        "gpo_name": "zz-studio-evidence-01",
        "targets": ["zz-a", "zz-b"],
        "threshold": 2,
        "zz_flag": "",
    }
    assert calls["plan_provenance"] == {"mode": "controller_direct"}


def test_exec_transaction_mirrors_the_record_to_the_out_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    _install_transport(monkeypatch)
    record = dict(_RECORD)
    _install_executor(monkeypatch, record)
    out_path = tmp_path / "record.json"
    _stdin(monkeypatch, json.dumps({"capability": json.dumps(_CAPABILITY)}))

    code = cli.main(
        ["--estate", str(_estate_file(tmp_path)), "exec-transaction", "--out", str(out_path)]
    )

    assert code == 0
    assert json.loads(out_path.read_text(encoding="utf-8")) == record
    assert json.loads(capsys.readouterr().out) == record  # stdout still carries it


def test_exec_transaction_indeterminate_record_still_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """A terminal record IS the result: an indeterminate state is not a
    plumbing failure, so the exit code stays 0."""
    _install_transport(monkeypatch)
    record = {**_RECORD, "state": "indeterminate", "verdict": "hard stop", "envelope_result": {}}
    _install_executor(monkeypatch, record)
    _stdin(monkeypatch, json.dumps({"capability": json.dumps(_CAPABILITY)}))

    code = cli.main(["--estate", str(_estate_file(tmp_path)), "exec-transaction"])

    assert code == 0
    assert json.loads(capsys.readouterr().out) == record


# --- exec-transaction: clean error exits for malformed plans --------------------------


def test_exec_transaction_bad_stdin_json_is_a_clean_plan_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    built = _install_transport(monkeypatch)
    calls = _install_executor(monkeypatch, dict(_RECORD))
    _stdin(monkeypatch, "{zz not json")

    code = cli.main(["--estate", str(_estate_file(tmp_path)), "exec-transaction"])

    assert code == 2
    captured = capsys.readouterr()
    assert "plan error" in captured.err
    assert captured.out == ""  # no record is emitted for an unparseable plan
    assert not calls and not built  # nothing was constructed, nothing attempted


def test_exec_transaction_plan_shape_errors_are_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    _install_transport(monkeypatch)
    calls = _install_executor(monkeypatch, dict(_RECORD))
    argv = ["--estate", str(_estate_file(tmp_path)), "exec-transaction"]

    # A plan that is not an object.
    _stdin(monkeypatch, "[1, 2]")
    assert cli.main(argv) == 2
    assert "plan error" in capsys.readouterr().err

    # A plan object with no capability text.
    _stdin(monkeypatch, json.dumps({"operation_id": "op-zz-2"}))
    assert cli.main(argv) == 2
    assert "carries no capability text" in capsys.readouterr().err

    # Capability text that is itself not JSON.
    _stdin(monkeypatch, json.dumps({"capability": "{zz"}))
    assert cli.main(argv) == 2
    assert "capability text is not valid JSON" in capsys.readouterr().err

    assert not calls  # the executor never ran for any malformed plan


# --- estate secrets: named, resolved from the environment, never echoed ----------------


def test_estate_names_the_secret_env_var_and_the_value_is_never_echoed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.setenv("WCD_LAB_PASSWORD", SECRET)
    built = _install_transport(monkeypatch)
    record = {**_RECORD, "provenance": {"capability": "zz.capability.cli", "notes": []}}
    _install_executor(monkeypatch, record)
    estate_path = _estate_file(tmp_path)
    _stdin(monkeypatch, json.dumps({"capability": json.dumps(_CAPABILITY)}))

    code = cli.main(["--estate", str(estate_path), "exec-transaction"])

    assert code == 0
    estate = built[0].estate
    # The estate NAMES the variable; the environment supplies the value.
    assert estate.password_env == "WCD_LAB_PASSWORD"
    assert estate.resolved_password() == SECRET
    # The value appears nowhere: not in the estate file, not on stdout or
    # stderr, not inside the emitted record.
    assert SECRET not in estate_path.read_text(encoding="utf-8")
    captured = capsys.readouterr()
    assert SECRET not in captured.out
    assert SECRET not in captured.err
