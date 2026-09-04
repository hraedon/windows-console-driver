"""Controller-side session transport: one REPL process, many fast gestures.

:class:`SessionTransport` spawns ``tools/session_repl.ps1`` (one pwsh
process holding the host WinRM session and the guest PSDirect session) and
speaks its line protocol: one JSON request line in, one JSON response line
out. A fresh WinRM + PSDirect round trip per gesture costs 10-30 s, which
made every capability a shell-history exercise; a transaction needs dozens
of gestures, so the sessions are opened once and reused.

Ops (mirroring the REPL contract):

- ``ping`` -- liveness.
- ``host(script, args)`` -- run a PowerShell snippet on the Hyper-V host
  (Msvm_Keyboard input, checkpoint existence, framebuffer capture).
- ``guest(script, args)`` -- run a PowerShell snippet in the guest through
  PSDirect (setup, oracle snippets, audit reads).
- ``helper(request)`` -- the in-guest console helper's file-IPC dance; the
  response is parsed with :mod:`wcd.helper_client`, so the helper contract's
  exit codes and honesty rules apply unchanged.

ROBUSTNESS
    The REPL's stdout is parsed strictly one line at a time through a reader
    thread (a hung guest must surface as a timeout, not a dead pipe); stderr
    is drained into a bounded ring for diagnostics. A transport failure
    raises :class:`TransportError`; nothing here retries an injection --
    retries are the transaction layer's decision, never the pipe's. A client
    timeout degrades to "that request failed": when a late response arrives
    after its caller gave up, the NEXT request drains the stale line (bounded
    by ``_MAX_STALE_DRAIN``, every discard accounted in the stderr ring)
    until its own id matches, so one timeout can never leave the channel
    permanently offset by one response.

SECRETS
    The password travels to the REPL process through its environment (the
    estate file names the variable), never through argv, files, or logs.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import threading
import time
from collections import deque
from pathlib import Path
from queue import Empty, Queue
from typing import IO

from .estate import EstateConfig
from .helper_client import HelperResult, parse_response

_MAX_STDERR_LINES = 200
_REQUEST_ID_PREFIX = "t"
# Bounded stale-response drain: a response that arrives after its caller
# timed out stays queued, so the next request must be able to discard lines
# whose id no longer matches. This caps how many mismatched lines one request
# will consume before declaring the channel desynced instead of silently
# consuming an unbounded stream of someone else's responses.
_MAX_STALE_DRAIN = 8


class TransportError(RuntimeError):
    """The session transport failed before any remote verdict exists."""


class SessionTransport:
    """The typed client for ``tools/session_repl.ps1``."""

    def __init__(
        self,
        estate: EstateConfig,
        *,
        repl_path: str | Path,
        pwsh_executable: str = "pwsh",
        startup_timeout: float = 120.0,
    ) -> None:
        self._estate = estate
        self._counter = 0
        self._counter_lock = threading.Lock()
        env = dict(os.environ)
        env[estate.password_env] = estate.resolved_password()
        self._process = subprocess.Popen(
            [
                pwsh_executable,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(repl_path),
                "-HostName",
                estate.host,
                "-VmName",
                estate.vm_name,
                "-Domain",
                estate.domain,
                "-Username",
                estate.username,
                "-PasswordEnv",
                estate.password_env,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=False,
        )
        self._stderr_ring: deque[str] = deque(maxlen=_MAX_STDERR_LINES)
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, args=(self._process.stderr,), daemon=True
        )
        self._stderr_thread.start()
        self._lines: Queue[bytes | None] = Queue()
        self._reader = threading.Thread(
            target=self._read_lines, args=(self._process.stdout,), daemon=True
        )
        self._reader.start()
        # Session open happens lazily inside the REPL on the first request;
        # ping proves the pipe, the first host/guest op proves the sessions.
        self.request("ping", timeout=startup_timeout)

    # -- public API ------------------------------------------------------------

    @property
    def vm_name(self) -> str:
        """The configured guest VM name."""
        return self._estate.vm_name

    def request(
        self,
        op: str,
        *,
        timeout: float,
        timeout_s: float | None = None,
        **fields: object,
    ) -> dict[str, object]:
        """Send one request line and wait for its response line.

        ``timeout`` is the client-side wait for the response line; expiring it
        raises :class:`TransportError` for THIS request only -- a response
        that trickles in afterwards is drained (and accounted) by the next
        request, never held against it.

        ``timeout_s`` optionally threads the caller's budget into the request
        line so the guest side honors it too (the REPL applies it to its
        helper poll; guest default there is 120 s). When ``None`` -- the
        default -- the field is omitted from the line entirely, which is the
        historical behavior.
        """
        if timeout_s is not None and timeout_s <= 0:
            raise ValueError("timeout_s must be positive when given")
        with self._counter_lock:
            self._counter += 1
            request_id = f"{_REQUEST_ID_PREFIX}{self._counter}"
        line_fields: dict[str, object] = {"op": op, "id": request_id, **fields}
        if timeout_s is not None:
            line_fields["timeout_s"] = timeout_s
        line = json.dumps(line_fields, ensure_ascii=True)
        assert self._process.stdin is not None
        try:
            self._process.stdin.write((line + "\n").encode("utf-8"))
            self._process.stdin.flush()
        except (BrokenPipeError, ValueError) as exc:
            raise TransportError(f"transport stdin is gone: {exc}") from exc
        deadline = time.monotonic() + timeout
        drained = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransportError(
                    f"transport timed out after {timeout}s waiting for a response to {op}"
                )
            try:
                raw = self._lines.get(timeout=remaining)
            except Empty as exc:
                raise TransportError(
                    f"transport timed out after {timeout}s waiting for a response to {op}"
                ) from exc
            if raw is None:
                detail = "; ".join(list(self._stderr_ring)[-5:]) or "no stderr"
                raise TransportError(f"transport process exited while awaiting {op}: {detail}")
            try:
                response = json.loads(raw.decode("utf-8"))
            except ValueError as exc:
                raise TransportError(f"transport response is not JSON: {exc}") from exc
            if not isinstance(response, dict):
                raise TransportError(
                    f"transport response is not an object: {type(response).__name__}"
                )
            response_id = response.get("id")
            if response_id == request_id:
                if drained:
                    self._stderr_ring.append(
                        f"[transport] {op}: matched {request_id} after draining "
                        f"{drained} stale response(s)"
                    )
                return response
            # A stale or mismatched response: a late reply to an already
            # timed-out request (or a foreign id). Discard it loudly -- never
            # let one timeout offset the channel permanently.
            drained += 1
            self._stderr_ring.append(
                f"[transport] {op}: drained stale response id={response_id!r} while "
                f"awaiting {request_id} ({drained}/{_MAX_STALE_DRAIN})"
            )
            if drained > _MAX_STALE_DRAIN:
                raise TransportError(
                    f"transport drained {drained} stale responses without seeing "
                    f"{request_id!r} for {op} (last stale id {response_id!r}); "
                    "the response channel is desynced"
                )

    def host(self, script: str, args: list[object] | None = None, *, timeout: float = 120.0) -> str:
        """Run a snippet on the Hyper-V host; return stdout as text."""
        response = self.request("host", timeout=timeout, script=script, args=args or [])
        return _stdout_of(response, "host")

    def guest(
        self,
        script: str,
        args: list[object] | None = None,
        *,
        timeout: float = 180.0,
        timeout_s: float | None = None,
    ) -> str:
        """Run a snippet in the guest through PSDirect; return stdout as text.

        ``timeout_s`` optionally carries the caller's budget into the request
        line so the guest-side deadline matches (see :meth:`request`).
        """
        response = self.request(
            "guest", timeout=timeout, timeout_s=timeout_s, script=script, args=args or []
        )
        return _stdout_of(response, "guest")

    def helper(
        self,
        request: dict[str, object],
        *,
        timeout: float = 200.0,
        timeout_s: float | None = None,
    ) -> HelperResult:
        """Run one helper request in the console session; typed result.

        ``timeout_s`` optionally sizes the REPL's in-guest helper poll to the
        caller's budget instead of the 120 s default, so a wedged helper
        surfaces as the helper's own honest timeout envelope (still within
        the caller's wait) rather than a client-side transport timeout.
        """
        response = self.request(
            "helper", timeout=timeout, timeout_s=timeout_s, request=request
        )
        if not response.get("ok"):
            raise TransportError(f"helper transport failed: {response.get('error')!r}")
        raw_response = response.get("response")
        if not isinstance(raw_response, str):
            raise TransportError("helper transport returned no response text")
        raw_exit = response.get("exit_code")
        exit_code = raw_exit if isinstance(raw_exit, int) else -1
        return parse_response(raw_response, exit_code)

    def stderr_tail(self) -> str:
        """Recent transport stderr, for diagnostics on a failure."""
        return "\n".join(self._stderr_ring)

    def close(self) -> None:
        """Ask the REPL to exit and tear the process down."""
        with contextlib.suppress(TransportError):
            self.request("shutdown", timeout=10.0)
        try:
            if self._process.stdin is not None:
                self._process.stdin.close()
        except (BrokenPipeError, ValueError, OSError):
            pass
        try:
            self._process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._process.kill()

    # -- internals ---------------------------------------------------------------

    def _read_lines(self, stream: IO[bytes] | None) -> None:
        if stream is None:
            self._lines.put(None)
            return
        while True:
            line = stream.readline()
            if not line:
                self._lines.put(None)
                return
            self._lines.put(line.rstrip(b"\r\n"))

    def _drain_stderr(self, stream: IO[bytes] | None) -> None:
        if stream is None:
            return
        while True:
            try:
                line = stream.readline()
            except (ValueError, OSError):
                return
            if not line:
                return
            self._stderr_ring.append(line.decode("utf-8", errors="replace").rstrip())


def _stdout_of(response: dict[str, object], kind: str) -> str:
    if not response.get("ok"):
        detail = response.get("error")
        extra = response.get("etype")
        stack = response.get("estack")
        message = f"{kind} op failed: {detail!r}"
        if extra:
            message += f" [{extra}]"
        if stack:
            message += f" (remote stack: {stack})"
        raise TransportError(message)
    stdout = response.get("stdout")
    if not isinstance(stdout, str):
        raise TransportError(f"{kind} op returned no stdout field")
    return stdout


def default_repl_path() -> Path:
    """The REPL script shipped beside the repository layout."""
    return Path(__file__).resolve().parents[2] / "tools" / "session_repl.ps1"
