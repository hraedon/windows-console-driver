"""Session-transport line-protocol tests against a FAKE subprocess REPL.

The real transport behind wcd.transport is tools/session_repl.ps1 (PowerShell
Direct to a lab host); it cannot run in tests. These tests spawn a small
Python process that speaks the SAME one-JSON-line-in, one-JSON-line-out
protocol (launched via sys.executable -- no PowerShell involved), driven
through SessionTransport itself by intercepting the spawn, so the reader
thread, request-id accounting, timeout semantics, and the stderr ring are
exercised exactly as they run in production.

Coverage:

- A late response after a client timeout raises for THAT request only; the
  next request drains the stale line (accounted in the stderr ring) and
  succeeds. One timeout must never leave the channel permanently offset by
  one response.
- Many queued stale lines drain up to the bounded maximum, then fail with a
  clear desync error instead of silently consuming unbounded foreign
  responses.
- ``timeout_s`` appears on the request line exactly when provided and is
  omitted otherwise (the REPL's guest-side default stays 120 s).
- Normal request/response round trips, the spawn contract (the secret's env
  var NAME travels argv, never its value), and the stderr ring still pass.
"""

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from wcd import transport as transport_module
from wcd.estate import EstateConfig
from wcd.transport import SessionTransport, TransportError

PASSWORD_ENV = "WCD_TEST_FAKE_PASSWORD"

_FAKE_REPL_SOURCE = r'''"""Fake session REPL: speaks tools/session_repl.ps1's line protocol.

Scriptable behaviors, driven entirely by the request line:

- ping / shutdown: protocol fixtures.
- echo: replies with "stdout" = value after an optional delay_s sleep.
- stderr_note: writes note to stderr, then echoes.
- emit: writes each entry of "lines" verbatim (each a full response object),
  then -- unless final=false -- replies with the matching id.

Every received request line is appended to $WCD_FAKE_REPL_RECORD so tests
can assert on the exact wire format.
"""
import json
import os
import sys
import time


def respond(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def record(line):
    path = os.environ.get("WCD_FAKE_REPL_RECORD")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def main():
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        record(raw)
        req = json.loads(raw)
        op = req.get("op")
        rid = req.get("id")
        if op == "ping":
            respond({"ok": True, "id": rid, "kind": "ping", "stdout": "pong"})
        elif op == "shutdown":
            respond({"ok": True, "id": rid, "kind": "shutdown", "stdout": "bye"})
            return
        elif op == "echo":
            time.sleep(float(req.get("delay_s", 0)))
            respond({"ok": True, "id": rid, "kind": "echo", "stdout": str(req.get("value", ""))})
        elif op in ("host", "guest"):
            respond({"ok": True, "id": rid, "kind": op, "stdout": "ok"})
        elif op == "helper":
            respond({
                "ok": True,
                "id": rid,
                "kind": "helper",
                "response": '{"ok": true, "action": "context"}',
                "exit_code": 0,
            })
        elif op == "stderr_note":
            sys.stderr.write(str(req.get("note", "")) + "\n")
            sys.stderr.flush()
            respond({"ok": True, "id": rid, "kind": "echo", "stdout": "noted"})
        elif op == "emit":
            for extra in req.get("lines", []):
                respond(extra)
            if req.get("final", True):
                respond({"ok": True, "id": rid, "kind": "echo", "stdout": "emitted"})
        else:
            respond({"ok": False, "id": rid, "kind": "protocol", "error": "unknown op"})


main()
'''


@dataclass
class FakeRepl:
    """The fake script's path plus everything it recorded for assertions."""

    script: Path
    record: Path
    spawned: list[list[str]] = field(default_factory=list)

    def requests(self) -> list[dict[str, Any]]:
        lines = self.record.read_text(encoding="utf-8").splitlines()
        return [dict(json.loads(line)) for line in lines if line.strip()]

    @property
    def last_spawn(self) -> list[str]:
        assert self.spawned, "SessionTransport never spawned the fake REPL"
        return self.spawned[-1]


@pytest.fixture
def fake_repl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeRepl:
    """Spawn-intercepting fixture: SessionTransport runs the fake Python REPL."""
    script = tmp_path / "fake_session_repl.py"
    script.write_text(_FAKE_REPL_SOURCE, encoding="utf-8")
    record_path = tmp_path / "requests.jsonl"
    record_path.write_text("", encoding="utf-8")
    real_popen = subprocess.Popen
    spawned: list[list[str]] = []

    def patched_popen(args: Any, *pargs: Any, **pkwargs: Any) -> subprocess.Popen[bytes]:
        argv = [str(part) for part in args]
        if "-File" in argv:
            spawned.append(argv)
            return real_popen([sys.executable, str(script)], *pargs, **pkwargs)
        return real_popen(args, *pargs, **pkwargs)

    monkeypatch.setattr(transport_module.subprocess, "Popen", patched_popen)
    monkeypatch.setenv("WCD_FAKE_REPL_RECORD", str(record_path))
    return FakeRepl(script=script, record=record_path, spawned=spawned)


@pytest.fixture
def transport(fake_repl: FakeRepl, monkeypatch: pytest.MonkeyPatch) -> SessionTransport:
    monkeypatch.setenv(PASSWORD_ENV, "dummy-password-value")
    estate = EstateConfig(
        host="lab-hv-01",
        vm_name="LabT01",
        domain="lab.example",
        username="labadmin",
        password_env=PASSWORD_ENV,
    )
    session = SessionTransport(
        estate,
        repl_path=fake_repl.script,
        pwsh_executable=sys.executable,
        startup_timeout=30.0,
    )
    yield session
    session.close()


# --- Normal protocol behavior -------------------------------------------------


def test_request_round_trip(transport: SessionTransport) -> None:
    response = transport.request("echo", timeout=10, value="hello")
    assert response["ok"] is True
    assert response["stdout"] == "hello"


def test_stderr_ring_collects_repl_stderr(transport: SessionTransport) -> None:
    transport.request("stderr_note", timeout=10, note="wcd-fake-diagnostic")
    assert "wcd-fake-diagnostic" in transport.stderr_tail()


def test_spawn_uses_pwsh_flags_and_never_puts_the_password_on_argv(
    transport: SessionTransport, fake_repl: FakeRepl
) -> None:
    assert transport.vm_name == "LabT01"  # the constructor above did the spawn
    argv = fake_repl.last_spawn
    assert argv[0] == sys.executable
    assert "-NoProfile" in argv and "-NonInteractive" in argv
    file_index = argv.index("-File")
    assert argv[file_index + 1] == str(fake_repl.script)
    assert "-HostName" in argv and "lab-hv-01" in argv
    # Credential-broker discipline: the env-var NAME travels argv, the secret
    # itself never does.
    assert PASSWORD_ENV in argv
    assert "dummy-password-value" not in argv


# --- Defect 1: a timeout must degrade to "that request failed" ---------------


def test_late_response_after_timeout_does_not_desync(
    transport: SessionTransport, fake_repl: FakeRepl
) -> None:
    # Ids are deterministic: the constructor's ping is t1, so the late echo
    # below is t2 and the follow-up request is t3.
    with pytest.raises(TransportError, match="timed out"):
        transport.request("echo", timeout=0.5, delay_s=1.5, value="late")

    # The late t2 response is still inbound when the next request goes out.
    # It must be drained as stale (and accounted), never read as t3's reply.
    response = transport.request("echo", timeout=30, value="next")
    assert response["id"] == "t3"
    assert response["stdout"] == "next"

    tail = transport.stderr_tail()
    assert "drained stale response id='t2'" in tail
    assert "matched t3 after draining 1 stale response(s)" in tail
    # And the wire really carried the late reply before t3's:
    sent = [req["id"] for req in fake_repl.requests()]
    assert sent == ["t1", "t2", "t3"]


def test_timeout_without_a_late_response_leaves_the_channel_healthy(
    transport: SessionTransport,
) -> None:
    with pytest.raises(TransportError, match="timed out"):
        transport.request("emit", timeout=0.5, lines=[], final=False)
    response = transport.request("echo", timeout=10, value="after")
    assert response["stdout"] == "after"


def test_many_stale_lines_drain_up_to_the_bound_then_error_clearly(
    transport: SessionTransport,
) -> None:
    stale = [
        {"ok": True, "id": f"stale-{i}", "kind": "echo", "stdout": "old"} for i in range(12)
    ]
    # The bound is 8 drains; the 9th mismatched line must abort loudly rather
    # than keep consuming someone else's responses.
    with pytest.raises(TransportError) as excinfo:
        transport.request("emit", timeout=30, lines=stale, final=False)
    assert "drained 9 stale responses" in str(excinfo.value)
    assert "desynced" in str(excinfo.value)
    tail = transport.stderr_tail()
    assert tail.count("drained stale response id='stale-") == 9


def test_stale_lines_within_the_bound_drain_and_match(
    transport: SessionTransport,
) -> None:
    stale = [
        {"ok": True, "id": f"stale-{i}", "kind": "echo", "stdout": "old"} for i in range(3)
    ]
    response = transport.request("emit", timeout=10, lines=stale)
    assert response["stdout"] == "emitted"
    assert "drained stale response id='stale-0'" in transport.stderr_tail()


# --- Defect 2: timeout_s on the wire, exactly when provided -------------------


def test_request_lines_carry_timeout_s_exactly_when_provided(
    transport: SessionTransport, fake_repl: FakeRepl
) -> None:
    transport.request("echo", timeout=10, value="plain")
    transport.request("echo", timeout=10, timeout_s=42, value="budgeted")
    with pytest.raises(ValueError, match="timeout_s"):
        transport.request("echo", timeout=10, timeout_s=0)

    requests = fake_repl.requests()
    assert "timeout_s" not in requests[-2]
    assert requests[-1]["timeout_s"] == 42


def test_guest_and_helper_ops_thread_timeout_s_when_given(
    transport: SessionTransport, fake_repl: FakeRepl
) -> None:
    transport.guest("'probe'", timeout=10, timeout_s=55)
    transport.helper({"action": "context"}, timeout=10, timeout_s=60)
    transport.guest("'probe'", timeout=10)

    requests = fake_repl.requests()
    guest_with, helper_with, guest_without = requests[-3], requests[-2], requests[-1]
    assert guest_with["op"] == "guest" and guest_with["timeout_s"] == 55
    assert helper_with["op"] == "helper" and helper_with["timeout_s"] == 60
    assert guest_without["op"] == "guest" and "timeout_s" not in guest_without


def test_helper_client_invoke_validates_the_guest_side_budget() -> None:
    from wcd import helper_client as hc

    def ok_transport(request: str) -> tuple[str, int]:
        return '{"ok": true, "action": "context"}', hc.EXIT_OK

    result = hc.invoke(ok_transport, hc.build_request("context"), timeout=5, timeout_s=4)
    assert result.outcome == "ok"
    with pytest.raises(ValueError, match="timeout_s"):
        hc.invoke(ok_transport, hc.build_request("context"), timeout_s=0)
    with pytest.raises(ValueError, match="timeout_s"):
        hc.invoke(ok_transport, hc.build_request("context"), timeout_s=-3)
