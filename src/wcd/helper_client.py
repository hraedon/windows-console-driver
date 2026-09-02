"""Controller-side client for the in-guest console helper.

``guest/helper.ps1`` is the console driver's hands inside a guest's
interactive session (docs/contract.md section 8): one JSON request object on
stdin, one single-line JSON response object on stdout, exit 0 ok / 2 error /
3 indeterminate. This module is the typed view of that protocol for the
controller side.

TRUST BOUNDARY
    The helper is also the actuator, so nothing it reports is independent
    observation of machine state. Helper output is *orientation* data when it
    decides the next gesture, and *surface* data when a claim is about what
    the UI displayed or allowed (contract section 5). It is NEVER evidence
    about machine state: state claims are certified by the GPO observers, and
    a helper screenshot is ordinary (not corroborated) surface evidence at
    best. Keep every consumer of this module honest about that.

    Two further disciplines mirror the helper's own: a ``key`` response never
    contains the typed text (only its length and sha256), and an
    ``indeterminate`` outcome (exit 3) is a result to reconcile, never a
    failure to retry.

ROBUSTNESS
    ``parse_response`` never raises into the caller. Malformed stdout, an
    empty stream, or an unexpected exit code all collapse into an error
    result so a wedged guest surfaces as data, not as an exception in the
    controller. ``build_request`` is the only function that raises, and it
    raises ValueError on a controller-side mistake (unknown action name),
    before anything reaches the guest.

TRANSPORT
    ``invoke`` takes the transport as a callable from request string to
    ``(stdout, exit_code)`` so the real transport -- PowerShell Direct exec
    in the target session -- is injectable and tests can substitute a fake.
    The protocol-level transport type carries no timeout channel; a real
    transport binds its own deadline in the closure it installs. ``invoke``
    still accepts ``timeout`` so deadlines stay visible at the call site
    where the transaction is written, and refuses a non-positive one.

Omitted optional request fields take the helper's defaults: mouse
``button='left'`` and ``mouse_action='click'``; ``uia_dump`` ``depth=4``;
``wait_foreground`` ``timeout_ms=10000`` and ``poll_ms=250``.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, TypedDict

EXIT_OK = 0
EXIT_ERROR = 2
EXIT_INDETERMINATE = 3

HELPER_ACTIONS: frozenset[str] = frozenset(
    {"context", "uia_dump", "screenshot", "key", "mouse", "wait_foreground"}
)
# The only actions that can move the user's session; every one of them accepts
# the helper's -DryRun switch (or the request field "dry_run": true).
INJECT_ACTIONS: frozenset[str] = frozenset({"key", "mouse"})
DRY_RUN_SWITCH = "-DryRun"

HelperTransport = Callable[[str], "tuple[str, int]"]
Outcome = Literal["ok", "error", "indeterminate"]

# --- Request shapes ----------------------------------------------------------


class VkChord(TypedDict, total=False):
    """One chord of the ``key`` action's ``vks`` array."""

    vk: int
    modifiers: list[str]


class ContextRequest(TypedDict):
    action: str


class UiaDumpRequest(TypedDict):
    action: str
    depth: int


class ScreenshotRequest(TypedDict):
    action: str
    full: bool


class KeyRequest(TypedDict):
    action: str
    text: str
    vks: list[VkChord]
    dry_run: bool


class MouseRequest(TypedDict):
    action: str
    x: int
    y: int
    button: str
    mouse_action: str
    hwnd: int


# Functional syntax: the "class" key is not expressible in class syntax.
WaitForegroundRequest = TypedDict(
    "WaitForegroundRequest",
    {
        "action": str,
        "title_regex": str,
        "class": str,
        "pid": int,
        "timeout_ms": int,
        "poll_ms": int,
    },
)

# --- Response shapes ---------------------------------------------------------


class RectInfo(TypedDict):
    left: int
    top: int
    right: int
    bottom: int
    width: int
    height: int


class ScreenPoint(TypedDict):
    x: int
    y: int


ForegroundInfo = TypedDict(
    "ForegroundInfo",
    {
        "hwnd": int,
        "pid": int,
        "process_name": str | None,
        "title": str | None,
        "class": str | None,
        "rect": RectInfo | None,
        "uia_digest": str | None,
    },
)

UiaElement = TypedDict(
    "UiaElement",
    {
        "depth": int,
        "name": str | None,
        "class": str | None,
        "automation_id": str | None,
        "control_type": str | None,
        "control_type_id": int | None,
        "rect": RectInfo | None,
        "patterns": list[str],
    },
)

class ContextSurface(TypedDict):
    session_id: int
    user: str
    desktop: str | None
    foreground: ForegroundInfo | None

LastForeground = TypedDict(
    "LastForeground", {"title": str | None, "class": str | None, "pid": int | None}
)

class ContextResponse(TypedDict):
    ok: bool
    action: str
    session_id: int
    user: str
    desktop: str | None
    foreground: ForegroundInfo | None
    notes: list[str]
class UiaDumpResponse(TypedDict):
    ok: bool
    action: str
    depth: int
    truncated: bool
    element_count: int
    elements: list[UiaElement]
    notes: list[str]
class ScreenshotResponse(TypedDict):
    ok: bool
    action: str
    full: bool
    rect: RectInfo | None
    width: int
    height: int
    bytes: int
    png_sha256: str
    png_base64: str
    notes: list[str]
class KeyResponse(TypedDict):
    ok: bool
    action: str
    dry_run: bool
    would_inject: dict[str, object] | None
    text_length: int | None
    text_sha256: str | None
    chords_sent: int | None
    injected_events: int | None
    secret_shaped_warning: bool
    notes: list[str]
class MouseResponse(TypedDict):
    ok: bool
    action: str
    dry_run: bool
    would_inject: dict[str, object] | None
    x: int
    y: int
    button: str
    mouse_action: str
    reference: str
    hwnd: int | None
    screen: ScreenPoint | None
    injected_events: int | None
    notes: list[str]
class WaitForegroundResponse(TypedDict):
    ok: bool
    action: str
    indeterminate: bool
    matched: bool
    waited_ms: int
    context: ContextSurface | None
    last_foreground: LastForeground | None
    error: str | None
    notes: list[str]
class ErrorResponse(TypedDict):
    ok: bool
    error: str
    notes: list[str]


def build_request(action: str, **params: object) -> str:
    """Build the single-line JSON request string for ``action``.

    Raises ValueError on an unknown action name -- a controller-side mistake
    that must fail before anything reaches the guest. Parameter validation
    itself belongs to the helper: this function is deliberately a shape
    builder, not a policy layer.
    """
    if action not in HELPER_ACTIONS:
        raise ValueError(
            f"unknown helper action {action!r}; expected one of {sorted(HELPER_ACTIONS)}"
        )
    request: dict[str, object] = {"action": action, **params}
    return json.dumps(request, ensure_ascii=True, separators=(",", ":"))


@dataclass(frozen=True)
class HelperResult:
    """Parsed helper outcome.

    ``payload`` is the decoded JSON object (empty when the output was
    malformed -- the helper's stdout is untrusted data, not a typed structure).
    ``error`` carries the helper's message for error/indeterminate outcomes
    and the reason for the outcome otherwise.
    """

    outcome: Outcome
    exit_code: int
    payload: dict[str, object]
    error: str | None = None
    malformed: bool = False


def _payload_error(payload: dict[str, object]) -> str | None:
    error = payload.get("error")
    if isinstance(error, str):
        return error
    return None


def parse_response(stdout: str, exit_code: int) -> HelperResult:
    """Map a helper invocation to a typed result; never raises.

    Exit-code contract (contract section 8): 0 -> ok, 2 -> error,
    3 -> indeterminate. Consistency rules: an exit 0 without a truthy
    ``ok`` envelope is an error, and any stdout that is not a single JSON
    object is an error result with ``malformed=True`` -- a helper that
    cannot speak its protocol is a broken helper, whatever its exit code.
    """
    text = stdout.strip().lstrip("\ufeff")
    if not text:
        return HelperResult(
            "error", exit_code, {}, f"helper produced no stdout (exit {exit_code})", True
        )
    try:
        parsed = json.loads(text)
    except ValueError as exc:
        return HelperResult(
            "error", exit_code, {}, f"malformed helper output (exit {exit_code}): {exc}", True
        )
    if not isinstance(parsed, dict):
        return HelperResult(
            "error",
            exit_code,
            {},
            "malformed helper output (exit "
            f"{exit_code}): expected a JSON object, got {type(parsed).__name__}",
            True,
        )
    payload: dict[str, object] = parsed
    error_text = _payload_error(payload)
    if exit_code == EXIT_OK:
        if payload.get("ok") is True:
            return HelperResult("ok", exit_code, payload, None, False)
        return HelperResult(
            "error",
            exit_code,
            payload,
            error_text or "helper exited 0 without a success envelope",
            False,
        )
    if exit_code == EXIT_ERROR:
        return HelperResult(
            "error",
            exit_code,
            payload,
            error_text or "helper reported an error without a message",
            False,
        )
    if exit_code == EXIT_INDETERMINATE:
        return HelperResult(
            "indeterminate",
            exit_code,
            payload,
            error_text or "helper reported an indeterminate outcome without a message",
            False,
        )
    return HelperResult(
        "error",
        exit_code,
        payload,
        f"unexpected helper exit code {exit_code}: {error_text or '(no message)'}",
        False,
    )


def invoke(transport: HelperTransport, request: str, timeout: float | None = None) -> HelperResult:
    """Send ``request`` through ``transport`` and parse the outcome.

    ``transport`` maps the request string to ``(stdout, exit_code)``. A
    transport that raises yields an error result (exit code -1), never an
    exception in the caller. ``timeout`` is refused when non-positive and
    otherwise kept visible at the call site; see the module docstring for
    why the protocol transport itself carries no deadline.
    """
    if timeout is not None and timeout <= 0:
        raise ValueError("timeout must be positive when given")
    try:
        stdout, exit_code = transport(request)
    except Exception as exc:
        return HelperResult("error", -1, {}, f"transport failed: {exc}", False)
    return parse_response(stdout, exit_code)


@dataclass(frozen=True)
class DryRunResult:
    """A successful dry-run of an inject action.

    ``would_inject`` is the helper's summary of what WOULD have been injected
    (for ``key``: text length + sha256 and/or the chord list; for ``mouse``:
    the gesture with its resolved screen coordinates). No secret-shaped text
    ever appears in it.
    """

    action: str
    would_inject: dict[str, object]
    secret_shaped_warning: bool
    payload: dict[str, object]


def dry_run(result: HelperResult) -> DryRunResult:
    """Coerce an ok ``HelperResult`` from a dry-run invocation.

    Raises ValueError when the result is not a dry-run success -- a
    programming error on the controller side, unlike helper misbehaviour,
    which parse_response reports as data.
    """
    if result.outcome != "ok":
        raise ValueError(f"not a dry-run result: outcome={result.outcome}, error={result.error!r}")
    payload = result.payload
    if payload.get("dry_run") is not True:
        raise ValueError("not a dry-run result: the payload carries no dry_run flag")
    would_inject = payload.get("would_inject")
    if not isinstance(would_inject, dict):
        raise ValueError("not a dry-run result: would_inject is missing or not an object")
    action = payload.get("action")
    if not isinstance(action, str):
        raise ValueError("not a dry-run result: the payload carries no action string")
    return DryRunResult(
        action=action,
        would_inject=would_inject,
        secret_shaped_warning=payload.get("secret_shaped_warning") is True,
        payload=payload,
    )
