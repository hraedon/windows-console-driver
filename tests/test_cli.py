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
from wcd.estate_canary import CanaryCheck, CanaryReport
from wcd.exec_transaction import ExecTransactionError

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


# A canned v1 executor record with exactly the five wire keys of the contract.
_RECORD: dict[str, object] = {
    "state": "verified",
    "verdict": "envelope satisfied and reproduction verified",
    "envelope_result": {
        "status": "satisfied",
        "satisfied": [],
        "violated": [],
        "unresolved": [],
        "unclassified": [],
        "characterization": "satisfied",
        "delta": [],
    },
    "events": [
        {"sequence": 1, "from_state": "armed", "to_state": "commit_attempted", "reason": "crossed"}
    ],
    "provenance": {
        "$schema": "docs/transaction-record-schema-v1.json",
        "schema_version": 1,
        "capability": "zz.capability.cli",
        "run_sheet": "zz_cli_sheet",
        "transaction_id": "zz-transaction",
        "console": {},
        "steps": [],
        "cleanup": {},
        "notes": [],
    },
}

_CAPABILITY: dict[str, object] = {
    "$schema": "docs/capability-schema-v0.json",
    "id": "zz.capability.cli",
    "surface": "gpmc-server2025",
    "revision": 1,
    "intent": "Exercise the CLI contract with synthetic arguments.",
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "required": ["gpo_name"],
        "properties": {
            "gpo_name": {"type": "string"},
            "targets": {"type": "array", "items": {"type": "string"}},
            "threshold": {"type": "integer"},
            "zz_flag": {"type": "string"},
        },
    },
    "channel_contract": {
        "setup": ["powershell"],
        "operation_under_test": ["gpmc_ui"],
        "orientation": ["uia"],
        "input_delivery": ["helper_input"],
        "oracle": ["gpo_observers"],
        "cleanup": ["powershell"],
    },
    "first_commit_point": "zz_commit",
    "run_sheet": "zz_cli_sheet",
    "gpo_transaction": True,
    "fact_plan": {"observers": [{"name": "r2_core", "params": {}}]},
    "envelope": {
        "require": [{"fact": "zz.present", "predicate": "post.zz.present == True"}],
        "allow": [],
        "forbid": [],
        "derive": [],
        "convergence": {"window_seconds": 10, "poll_seconds": 1, "reproduce": 2},
    },
    "structured_checks": [{"id": "zz_check", "checks": "Synthetic CLI check."}],
    "bindings": {"args": "Synthetic.", "fact_vocabulary": "Synthetic."},
    "cleanup": {
        "strategy": "remove_gpo",
        "requery": "strict_absence",
        "residual_accounting": True,
    },
    "recovery": {"kind": "checkpoint_revert", "demonstration": "Synthetic."},
}
_VALID_ARGUMENTS = {"gpo_name": "zz-studio-evidence-01"}


def _estate_file(tmp_path: Path) -> Path:
    """A synthetic estate TOML: it NAMES the secret variable, never carries it."""
    path = tmp_path / "estate.toml"
    path.write_text(
        "[estate]\n"
        "host = 'zz-hyperv'\n"
        "vm_name = 'zz-vm'\n"
        "domain = 'zzlab.invalid'\n"
        "username = 'LAB\\zz-operator'\n"
        "password_env = 'WCD_LAB_PASSWORD'\n"
        "identity_role = 'domain_operator'\n",
        encoding="utf-8",
    )
    return path


def _stdin_plan(**overrides: object) -> str:
    """One well-formed WEL plan: capability text, arguments, and the target.

    Every stdin-mode test sends this shape because the plan's machine and
    identity are an agreement with the estate (record-schema v2), not optional
    annotation: the fixture estate serves 'zz-vm' as 'domain_operator'.
    """
    plan: dict[str, object] = {
        "operation_id": "op-zz-1",
        "machine": "zz-vm",
        "identity": "domain_operator",
        "capability": json.dumps(_CAPABILITY),
        "arguments": _VALID_ARGUMENTS,
    }
    plan.update(overrides)
    return json.dumps(plan)


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
    for verb in ("exec-transaction", "ensure-console", "console-state", "estate-canary"):
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
    # The default estate is anchored to the driver's own checkout (the WEL
    # seam launches from a different repository), so the "default is missing"
    # case is produced by pointing the repo root at an empty directory --
    # chdir alone no longer touches the default path.
    monkeypatch.setattr(cli, "_repo_root", lambda: tmp_path)
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
    _stdin(
        monkeypatch,
        _stdin_plan(arguments={"gpo_name": "zz-studio-evidence-01", "threshold": 2}),
    )

    code = cli.main(["--estate", str(_estate_file(tmp_path)), "exec-transaction"])

    assert code == 0
    # The record is the ONLY stdout payload, parsed strictly by the caller.
    assert json.loads(capsys.readouterr().out) == record
    assert calls["capability"] == _CAPABILITY
    assert calls["arguments"] == {"gpo_name": "zz-studio-evidence-01", "threshold": 2}
    # The exact capability text travels with the dispatch so the record can be
    # minted (and re-validated) against the content that actually ran.
    assert calls["capability_text"] == json.dumps(_CAPABILITY)
    provenance = calls["plan_provenance"]
    assert provenance["mode"] == "wel_exec_transaction"
    assert provenance["operation_id"] == "op-zz-1"
    assert provenance["machine"] == "zz-vm"
    assert provenance["identity"] == "domain_operator"
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
    # Controller-direct mode reads the file itself, so the binding digests the
    # file's exact text too -- v2 is not a WEL-plan-only guarantee.
    assert calls["capability_text"] == json.dumps(_CAPABILITY)


def test_exec_transaction_mirrors_the_record_to_the_out_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    _install_transport(monkeypatch)
    record = dict(_RECORD)
    _install_executor(monkeypatch, record)
    out_path = tmp_path / "record.json"
    _stdin(monkeypatch, _stdin_plan())

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
    _stdin(monkeypatch, _stdin_plan())

    code = cli.main(["--estate", str(_estate_file(tmp_path)), "exec-transaction"])

    assert code == 0
    assert json.loads(capsys.readouterr().out) == record


def test_exec_transaction_rejects_invalid_executor_record_before_emission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    built = _install_transport(monkeypatch)
    _install_executor(monkeypatch, {"state": "verified"})
    out_path = tmp_path / "must-not-exist.json"
    _stdin(monkeypatch, _stdin_plan())

    code = cli.main(
        ["--estate", str(_estate_file(tmp_path)), "exec-transaction", "--out", str(out_path)]
    )

    assert code == 2
    captured = capsys.readouterr()
    assert "record error: executor emitted an invalid record" in captured.err
    assert captured.out == ""
    assert not out_path.exists()
    assert built[0].closed


def test_exec_transaction_refuses_a_record_whose_capability_binding_mismatches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """Record-schema v2's content check, enforced at the emission boundary.

    The executor returned a v2 record whose digest is not the digest of the
    capability text this process executed. Whatever produced it, it is not an
    account of THIS transaction's capability content, so it may not cross the
    stdout wire -- same exit 2, no record, as any other invalid record.
    """
    _install_transport(monkeypatch)
    base_provenance = dict(_RECORD["provenance"])  # type: ignore[arg-type]
    provenance = {
        **base_provenance,
        "$schema": "docs/transaction-record-schema-v2.json",
        "schema_version": 2,
        "capability_revision": 1,
        "capability_sha256": "0" * 64,  # not the digest of _CAPABILITY's text
    }
    record = {**_RECORD, "provenance": provenance}
    _install_executor(monkeypatch, record)
    out_path = tmp_path / "must-not-exist.json"
    _stdin(monkeypatch, _stdin_plan())

    code = cli.main(
        ["--estate", str(_estate_file(tmp_path)), "exec-transaction", "--out", str(out_path)]
    )

    assert code == 2
    captured = capsys.readouterr()
    assert "record error" in captured.err
    assert "does not match the capability content" in captured.err
    assert captured.out == ""
    assert not out_path.exists()


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


def test_exec_transaction_rejects_schema_invalid_capability_before_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    built = _install_transport(monkeypatch)
    calls = _install_executor(monkeypatch, dict(_RECORD))
    malformed = json.loads(json.dumps(_CAPABILITY))
    malformed["envelope"].pop("require")
    _stdin(monkeypatch, _stdin_plan(capability=json.dumps(malformed)))

    code = cli.main(["--estate", str(_estate_file(tmp_path)), "exec-transaction"])

    assert code == 2
    captured = capsys.readouterr()
    assert "capability error" in captured.err
    assert "require" in captured.err
    assert captured.out == ""
    assert not calls and not built


@pytest.mark.parametrize("arguments", [{}, {"gpo_name": "zz", "unknown": True}])
def test_exec_transaction_rejects_invalid_arguments_before_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    arguments: dict[str, object],
) -> None:
    built = _install_transport(monkeypatch)
    calls = _install_executor(monkeypatch, dict(_RECORD))
    _stdin(monkeypatch, _stdin_plan(arguments=arguments))

    code = cli.main(["--estate", str(_estate_file(tmp_path)), "exec-transaction"])

    assert code == 2
    captured = capsys.readouterr()
    assert "capability error: arguments" in captured.err
    assert captured.out == ""
    assert not calls and not built


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        ("missing.json", None),
        ("malformed.json", "{zz not json"),
    ],
)
def test_exec_transaction_capability_file_errors_are_clean_before_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    filename: str,
    content: str | None,
) -> None:
    built = _install_transport(monkeypatch)
    calls = _install_executor(monkeypatch, dict(_RECORD))
    capability_path = tmp_path / filename
    if content is not None:
        capability_path.write_text(content, encoding="utf-8")

    code = cli.main(
        [
            "--estate",
            str(_estate_file(tmp_path)),
            "exec-transaction",
            "--capability",
            str(capability_path),
        ]
    )

    assert code == 2
    captured = capsys.readouterr()
    assert "capability error: cannot read JSON document" in captured.err
    assert captured.out == ""
    assert not calls and not built


# --- estate secrets: named, resolved from the environment, never echoed ----------------


def test_estate_names_the_secret_env_var_and_the_value_is_never_echoed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.setenv("WCD_LAB_PASSWORD", SECRET)
    built = _install_transport(monkeypatch)
    record = json.loads(json.dumps(_RECORD))
    _install_executor(monkeypatch, record)
    estate_path = _estate_file(tmp_path)
    _stdin(monkeypatch, _stdin_plan())

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


# --- estate-canary: pre-flight health checks, fail closed -------------------------------


def test_estate_canary_green_exits_0_and_emits_every_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.setenv("WCD_LAB_PASSWORD", SECRET)
    built = _install_transport(monkeypatch)
    report = CanaryReport(
        checks=(
            CanaryCheck(name="host_winrm", ok=True, detail="zz host answered"),
            CanaryCheck(name="guest_psdirect", ok=True, detail="zz guest answered"),
        )
    )
    monkeypatch.setattr(cli, "run_estate_canary", lambda t, e: report)

    code = cli.main(["--estate", str(_estate_file(tmp_path)), "estate-canary"])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert [c["name"] for c in payload["checks"]] == ["host_winrm", "guest_psdirect"]
    assert built[0].closed is True


def test_estate_canary_red_exits_3_with_the_failing_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.setenv("WCD_LAB_PASSWORD", SECRET)
    _install_transport(monkeypatch)
    report = CanaryReport(
        checks=(
            CanaryCheck(name="host_winrm", ok=True, detail="zz host answered"),
            CanaryCheck(name="checkpoint", ok=False, detail="recovery checkpoint 'zz' NOT present"),
        )
    )
    monkeypatch.setattr(cli, "run_estate_canary", lambda t, e: report)

    code = cli.main(["--estate", str(_estate_file(tmp_path)), "estate-canary"])

    assert code == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["checks"][1]["ok"] is False


def test_estate_canary_refuses_a_transport_that_will_not_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.setenv("WCD_LAB_PASSWORD", SECRET)

    def broken_build(estate: EstateConfig) -> object:
        raise OSError("zz: pwsh not found")

    monkeypatch.setattr(cli, "_default_transport", broken_build)

    code = cli.main(["--estate", str(_estate_file(tmp_path)), "estate-canary"])

    assert code == 2
    assert "canary error" in capsys.readouterr().err
    assert capsys.readouterr().out == ""


def test_a_determinate_pre_setup_refusal_exits_2_with_no_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """The surface-fingerprint gate raises; the CLI answers exit 2, no record.

    Nothing mutated, so no record is owed and no reconciliation is implied --
    WEL reads exit 2 as a determinate refusal, which is exactly the class of
    failure a mismatched qualified surface is.
    """
    monkeypatch.setenv("WCD_LAB_PASSWORD", SECRET)
    _install_transport(monkeypatch)

    def refuse(**_kwargs: object) -> dict[str, object]:
        raise ExecTransactionError(
            "prepared surface fingerprint mismatch: banked zz, observed zz-other"
        )

    monkeypatch.setattr(cli, "execute_transaction", refuse)
    _stdin(monkeypatch, _stdin_plan())

    code = cli.main(["--estate", str(_estate_file(tmp_path)), "exec-transaction"])

    assert code == 2
    captured = capsys.readouterr()
    assert "transaction error" in captured.err
    assert "fingerprint mismatch" in captured.err
    assert captured.out == ""


# --- exec-transaction: the plan/estate target agreement (record-schema v2) ------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"machine": "zz-other-vm"},  # names a machine the estate does not serve
        {"machine": None},  # carries no machine at all
        {"identity": "standard_user"},  # names an identity the estate does not serve
        {"identity": None},  # carries no identity at all
    ],
)
def test_exec_transaction_refuses_a_plan_that_disagrees_with_the_estate_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    overrides: dict[str, object],
) -> None:
    """The plan's machine/identity are an agreement, not annotation.

    Execution targets the estate's own configuration regardless of what the
    plan says, so a plan naming a different machine or identity used to run
    anyway with the disagreement buried in provenance. Record-schema v2 makes
    the disagreement itself a determinate refusal before any transport is
    built -- nothing mutated, no record is owed, exit 2 like every other
    pre-flight refusal.
    """
    built = _install_transport(monkeypatch)
    calls = _install_executor(monkeypatch, dict(_RECORD))
    _stdin(monkeypatch, _stdin_plan(**overrides))

    code = cli.main(["--estate", str(_estate_file(tmp_path)), "exec-transaction"])

    assert code == 2
    captured = capsys.readouterr()
    assert "plan error" in captured.err
    assert captured.out == ""
    assert not calls and not built  # neither executor nor transport was reached


def test_exec_transaction_names_the_disagreeing_side_of_the_agreement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """Each refusal names both sides, so the operator can see WHICH config
    disagrees -- the plan's value and the estate's -- rather than a bare
    mismatch."""
    _install_transport(monkeypatch)
    _install_executor(monkeypatch, dict(_RECORD))
    argv = ["--estate", str(_estate_file(tmp_path)), "exec-transaction"]

    _stdin(monkeypatch, _stdin_plan(machine="zz-other-vm"))
    assert cli.main(argv) == 2
    err = capsys.readouterr().err
    assert "'zz-other-vm'" in err and "'zz-vm'" in err

    _stdin(monkeypatch, _stdin_plan(identity="standard_user"))
    assert cli.main(argv) == 2
    err = capsys.readouterr().err
    assert "'standard_user'" in err and "'domain_operator'" in err


def test_exec_transaction_refuses_every_plan_when_the_estate_declares_no_identity_role(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """An undeclared identity cannot be shown to agree with anything.

    Same fail-closed shape as checkpoint_name: the operator must name the WEL
    identity role this console serves before a WEL plan can run against it.
    """
    estate_path = tmp_path / "estate.toml"
    estate_path.write_text(
        "[estate]\n"
        "host = 'zz-hyperv'\n"
        "vm_name = 'zz-vm'\n"
        "domain = 'zzlab.invalid'\n"
        "username = 'LAB\\zz-operator'\n"
        "password_env = 'WCD_LAB_PASSWORD'\n",
        encoding="utf-8",
    )
    built = _install_transport(monkeypatch)
    calls = _install_executor(monkeypatch, dict(_RECORD))
    _stdin(monkeypatch, _stdin_plan())

    code = cli.main(["--estate", str(estate_path), "exec-transaction"])

    assert code == 2
    captured = capsys.readouterr()
    assert "declares no identity_role" in captured.err
    assert captured.out == ""
    assert not calls and not built
