"""Run-sheets: declared, profile-bound action sequences (the generalized how).

A run-sheet is the surface driver's "how" for one capability, expressed as
data: an ordered list of steps, each naming the **driver-profile action** it
instantiates, so every crossing is classified before it happens (contract
section 6). The executor interprets the same primitives for every surface;
a new surface or a new capability means writing data, not shell history.

Step schema (JSON; ``profile_action`` must be declared by the loaded
profile -- an undeclared action refuses before anything moves):

- ``guest`` / ``host``      -- run a named script from ``tools/guest_scripts``
                               (or host scripts), capture its ``key=value``
                               output lines. Setup and cleanup live here; the
                               channel contract rules: setup and cleanup are
                               programmatic, the operation-under-test never
                               touches these.
- ``wait_foreground``       -- helper ``wait_foreground`` on a fingerprint
                               subset; timeout surfaces as indeterminate data.
- ``context``               -- helper ``context``; recorded, and when
                               ``assert`` is set, mismatched session/user/
                               desktop mark the transaction indeterminate.
- ``dump``                  -- helper ``uia_dump`` of the foreground window;
                               cached for selector resolution.
- ``click_element``         -- resolve a selector against the cached dump,
                               click its center (window-relative math against
                               the dump root's rect). Options: ``control_type``,
                               ``index`` (nth match), ``double``.
- ``type_text``             -- helper ``key`` with text (types into focus).
- ``key``                   -- helper ``key`` with ``vks`` chords and/or text.
- ``commit``                -- cross the declared commit boundary; the step
                               must name a ``commit_point`` profile action.
- ``label``                 -- provenance-only annotation.

Selectors are ``name_regex`` (.NET-compatible Python regex, case-insensitive
search) against element names from the dump. Coordinates are computed from
element rect minus root rect, so nothing is pinned to screen pixels (the
bottom input rung stays unreachable from run-sheets by construction).

THE RUN-SHEET NEVER EVALUATES SUCCESS. It records facts; the envelope and
the observers decide. The one exception is mechanical: a primitive that
cannot complete (selector not found, wait timed out, helper error) aborts
the sheet with :class:`RunSheetError`, and the transaction layer owns the
indeterminate + cleanup path.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .helper_client import HelperResult
from .transport import SessionTransport, TransportError

_GESTURE_ACTIONS = frozenset(
    {
        "guest",
        "host",
        "wait_foreground",
        "context",
        "dump",
        "click_element",
        "type_text",
        "key",
        "commit",
        "label",
        "shot",
        "keys",
    }
)


class RunSheetError(RuntimeError):
    """A run-sheet step could not complete; the transaction layer reconciles.

    journal carries the entries recorded up to the failure, so a failed
    run's record still shows how far the sheet got and what the surface
    looked like -- a disproven or indeterminate result is evidence, and
    evidence without its context is not a result.
    """

    def __init__(self, message: str, journal: list[dict[str, object]] | None = None) -> None:
        super().__init__(message)
        self.journal = journal if journal is not None else []


def _default_evidence_dir() -> Path:
    """The repository's own ``runs/`` directory, anchored to this source file.

    Fallback for direct :class:`GestureExecutor` use; the transaction
    executor always passes the estate-anchored directory explicitly. The
    anchor is deliberately NOT the process working directory: evidence
    location is a deployment fact, not an accident of the invocation.
    """
    return Path(__file__).resolve().parents[2] / "runs"


@dataclass(frozen=True, slots=True)
class Step:
    """One declared run-sheet step."""

    action: str
    profile_action: str | None
    params: dict[str, object]

    @property
    def label(self) -> str:
        text = str(self.params.get("label", "")) if self.params else ""
        return f"{self.action}" + (f"[{self.profile_action}]" if self.profile_action else "") + (
            f" {text}" if text else ""
        )


@dataclass(frozen=True, slots=True)
class RunSheet:
    """A loaded, validated run-sheet."""

    name: str
    surface: str
    steps: tuple[Step, ...]


def load_run_sheet(path: str | Path) -> RunSheet:
    """Load and validate the run-sheet JSON at *path*."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RunSheetError(f"run-sheet {path} must be a JSON object")
    unknown = set(data) - {"name", "surface", "steps"}
    if unknown:
        raise RunSheetError(f"run-sheet {path} has unknown keys: {sorted(unknown)}")
    name = data.get("name")
    surface = data.get("surface")
    raw_steps = data.get("steps")
    if not isinstance(name, str) or not name:
        raise RunSheetError(f"run-sheet {path} needs a name")
    if not isinstance(surface, str) or not surface:
        raise RunSheetError(f"run-sheet {path} needs a surface")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise RunSheetError(f"run-sheet {path} needs a non-empty steps array")
    steps: list[Step] = []
    for index, raw in enumerate(raw_steps):
        if not isinstance(raw, dict):
            raise RunSheetError(f"step {index} of {path} is not an object")
        action = raw.get("action")
        if not isinstance(action, str) or action not in _GESTURE_ACTIONS:
            raise RunSheetError(
                f"step {index} of {path} has unknown action {action!r}; "
                f"expected one of {sorted(_GESTURE_ACTIONS)}"
            )
        profile_action = raw.get("profile_action")
        if profile_action is not None and not isinstance(profile_action, str):
            raise RunSheetError(f"step {index} of {path}: profile_action must be a string")
        params = {k: v for k, v in raw.items() if k not in ("action", "profile_action")}
        steps.append(Step(action=action, profile_action=profile_action, params=params))
    return RunSheet(name=name, surface=surface, steps=tuple(steps))


@dataclass
class _DumpedElement:
    """One UIA element cached from a dump, with resolution helpers."""

    name: str | None
    control_type: str | None
    rect: tuple[int, int, int, int] | None  # left, top, right, bottom (screen)
    depth: int

    @property
    def center(self) -> tuple[int, int] | None:
        if self.rect is None:
            return None
        left, top, right, bottom = self.rect
        return (left + right) // 2, (top + bottom) // 2


@dataclass
class SheetContext:
    """Mutable state one run-sheet execution carries through its steps."""

    inputs: dict[str, object]
    outputs: dict[str, str] = field(default_factory=dict)
    last_dump: list[_DumpedElement] = field(default_factory=list)
    last_dump_root_rect: tuple[int, int, int, int] | None = None
    last_dump_hwnd: int | None = None
    # The dialog chain: wait_foreground pushes each surfaced window; when a
    # dialog closes (its hwnd dies), the dump pops back to the owner window.
    hwnd_stack: list[int] = field(default_factory=list)
    last_context: dict[str, object] | None = None
    journal: list[dict[str, object]] = field(default_factory=list)

    def interpolate(self, value: object) -> object:
        """Resolve ``{args.key}`` / ``{out.key}`` references inside strings.

        Recurses into dicts and lists, so composite steps (a ``keys`` step's
        nested step array) interpolate their references too.
        """
        if isinstance(value, dict):
            return {k: self.interpolate(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.interpolate(v) for v in value]
        if not isinstance(value, str):
            return value

        def replace(match: re.Match[str]) -> str:
            scope = match.group(1)
            key = match.group(2)
            table = self.inputs if scope == "args" else self.outputs
            if key not in table:
                raise RunSheetError(f"reference {{{match.group(0)}}} does not resolve")
            return str(table[key])

        return re.sub(r"\{(args|out)\.([A-Za-z0-9_.]+)\}", replace, value)


class GestureExecutor:
    """Executes run-sheet steps against one session transport."""

    def __init__(
        self,
        transport: SessionTransport,
        *,
        guest_scripts_dir: Path,
        host_scripts_dir: Path,
        evidence_dir: Path | None = None,
        helper_timeout_s: float = 200.0,
        guest_timeout_s: float = 300.0,
    ) -> None:
        self._t = transport
        self._guest_scripts = guest_scripts_dir
        self._host_scripts = host_scripts_dir
        self._helper_timeout = helper_timeout_s
        self._guest_timeout = guest_timeout_s
        # Evidence anchor (screenshots): the transaction executor passes the
        # estate-anchored directory (or the repository's own runs/ directory).
        # The location is a deployment fact, NEVER the process working
        # directory -- evidence must not depend on where wcd was invoked from.
        self._evidence_dir = evidence_dir if evidence_dir is not None else _default_evidence_dir()
        self._last_cached_focus: int | None = None

    # -- step dispatch ---------------------------------------------------------

    def execute(
        self,
        sheet: RunSheet,
        ctx: SheetContext,
        *,
        on_commit: Callable[[str], None] | None = None,
        before_step: Callable[[Step], None] | None = None,
        classify: Callable[[str], str | None] | None = None,
    ) -> list[dict[str, object]]:
        """Run every step in order; return the journal.

        ``on_commit(boundary)`` is called for ``commit`` steps and for the
        FIRST step whose profile action classifies as ``potentially_mutating``
        or ``commit_point`` (contract section 2: crossing the first declared
        commit point -- or any potentially mutating action -- is terminal for
        replay; later crossings are part of the same attempt and are not
        re-reported). The classification applies to ANY step carrying a
        ``profile_action``, regardless of its primitive action name.
        ``classify`` resolves profile action names to their declared classes;
        a step naming an action the profile does not declare is refused, on
        every step, before and after the first crossing. A primitive failure
        raises RunSheetError with the failing step named -- the caller owns
        cleanup.
        """
        journal: list[dict[str, object]] = []
        crossed = False
        for index, step in enumerate(sheet.steps):
            if before_step is not None:
                before_step(step)
            entry: dict[str, object] = {"index": index, "step": step.label}
            try:
                # Profile classification applies to ANY step carrying a
                # profile_action, whatever its primitive action name: a
                # ``keys`` composite or a ``shot`` step instantiates a driver
                # action exactly as much as a click does (contract s6). And
                # the undeclared-action refusal runs on every such step,
                # before AND after the first crossing -- a crossing never
                # licenses later undeclared actions.
                if on_commit is not None and step.profile_action:
                    declared = (
                        classify(step.profile_action)
                        if classify
                        else "commit_point"
                    )
                    if declared is None:
                        # Qualified execution refuses undeclared actions (contract
                        # section 6): the profile classifies everything it allows.
                        raise RunSheetError(
                            f"profile action {step.profile_action!r} is not declared by the "
                            "loaded profile; refusing the step"
                        )
                    if (
                        not crossed
                        and declared in ("potentially_mutating", "commit_point")
                    ):
                        on_commit(step.profile_action)
                        crossed = True
                detail = self._execute_step(step, ctx, on_commit)
                entry["ok"] = True
                if detail:
                    entry["detail"] = detail
            except RunSheetError as exc:
                entry["ok"] = False
                entry["error"] = str(exc)[:2400]
                journal.append(entry)
                raise RunSheetError(
                    f"step {index} ({step.label}) failed: {exc}", journal
                ) from exc
            journal.append(entry)
        return journal

    def _execute_step(
        self,
        step: Step,
        ctx: SheetContext,
        on_commit: Callable[[str], None] | None,
    ) -> dict[str, object]:
        params = {k: ctx.interpolate(v) for k, v in step.params.items()}
        if step.action == "label":
            return {}
        if step.action == "guest":
            return self._run_script(self._guest_scripts, params, ctx, remote="guest")
        if step.action == "host":
            return self._run_script(self._host_scripts, params, ctx, remote="host")
        if step.action == "wait_foreground":
            return self._wait_foreground(params, ctx)
        if step.action == "context":
            return self._context(params, ctx)
        if step.action == "dump":
            return self._dump(params, ctx)
        if step.action == "click_element":
            return self._click_element(params, ctx)
        if step.action == "type_text":
            return self._type_text(params, ctx)
        if step.action == "key":
            return self._key(params, ctx)
        if step.action == "shot":
            return self._shot(params)
        if step.action == "keys":
            return self._keys(params, ctx)
        if step.action == "commit":
            boundary = params.get("boundary")
            if not isinstance(boundary, str) or not boundary:
                raise RunSheetError("commit step needs a boundary name")
            if on_commit is None:
                raise RunSheetError("commit step but no transaction callback wired")
            on_commit(boundary)
            return {"boundary": boundary}
        raise RunSheetError(f"unhandled action {step.action!r}")

    # -- primitives --------------------------------------------------------------

    def _run_script(
        self,
        directory: Path,
        params: dict[str, object],
        ctx: SheetContext,
        *,
        remote: str,
    ) -> dict[str, object]:
        script_ref = params.get("script")
        if not isinstance(script_ref, str) or not script_ref:
            raise RunSheetError("script step needs a script name")
        path = directory / f"{script_ref}.ps1"
        if not path.is_file():
            raise RunSheetError(f"script {script_ref!r} not found in {directory}")
        arg_values: list[object] = []
        raw_args = params.get("args")
        script_args: list[object] = raw_args if isinstance(raw_args, list) else []
        for value in script_args:
            arg_values.append(ctx.interpolate(value))
        text = path.read_text(encoding="utf-8-sig")
        runner = self._t.guest if remote == "guest" else self._t.host
        try:
            stdout = runner(text, arg_values, timeout=self._guest_timeout)
        except TransportError as exc:
            # Transport failures inside a sheet are reconciled, never crashed:
            # the transaction layer owns the indeterminate + cleanup path.
            raise RunSheetError(f"{remote} script {script_ref!r} transport failed: {exc}") from exc
        output_key = params.get("output_as")
        if isinstance(output_key, str) and output_key:
            for line in stdout.splitlines():
                if "=" in line and not line.startswith(" ") and not line.startswith("#"):
                    key, _, value = line.partition("=")
                    key = key.strip()
                    if key and re.fullmatch(r"[A-Za-z0-9_]+", key):
                        ctx.outputs[f"{output_key}.{key}"] = value.strip()
        return {"stdout": stdout[:512]}

    def _find_window_by_class(self, window_class: str) -> dict[str, object] | None:
        result = self._t.helper({"action": "windows"}, timeout=self._helper_timeout)
        if result.outcome != "ok":
            raise RunSheetError(f"windows enumeration failed: {result.error}")
        windows = result.payload.get("windows")
        if not isinstance(windows, list):
            windows = []
        for raw in windows:
            if not isinstance(raw, dict) or raw.get("visible") is not True:
                continue
            if raw.get("class") == window_class:
                return raw
        return None

    def _find_window(
        self, title_regex: str, window_class: str | None = None
    ) -> dict[str, object] | None:
        """Find a visible top-level window by title regex (z-order-independent).

        MEASURED 2026-09-03 (second estate window): each helper invocation's
        own console takes and holds foreground while the helper runs, so
        foreground-based reads self-shadow (a foreground uia_dump sees the
        helper console, not the surface). The top-level window enumeration is
        z-order-independent and is the honest orientation primitive; the
        foreground is forced separately, right before a gesture, through the
        mouse action's focus_hwnd (the ALT-tap EnsureForeground route).
        """
        result = self._t.helper({"action": "windows"}, timeout=self._helper_timeout)
        if result.outcome != "ok":
            raise RunSheetError(f"windows enumeration failed: {result.error}")
        regex = re.compile(title_regex, re.IGNORECASE)
        windows = result.payload.get("windows")
        if not isinstance(windows, list):
            windows = []
        for raw in windows:
            if not isinstance(raw, dict) or raw.get("visible") is not True:
                continue
            title = raw.get("title")
            if not isinstance(title, str) or not regex.search(title):
                continue
            if window_class and raw.get("class") != window_class:
                continue
            return raw
        return None

    def _wait_foreground(self, params: dict[str, object], ctx: SheetContext) -> dict[str, object]:
        """Wait for a window matching the fingerprint to EXIST, then surface it.

        Despite the historical name, this polls the window ENUMERATION, not
        the foreground: the helper console self-shadow makes foreground waits
        unresolvable from inside an invocation. Once found, the window is
        surfaced (title-bar click through focus_hwnd) so later gestures and
        dumps resolve against it.
        """
        import time as _time

        title_regex = params.get("title_regex")
        window_class = params.get("class")
        if not isinstance(title_regex, str) or not title_regex:
            raise RunSheetError("wait_foreground needs title_regex")
        timeout_ms = params.get("timeout_ms", 60000)
        deadline_s = (timeout_ms if isinstance(timeout_ms, (int, float)) else 60000) / 1000.0
        start = _time.monotonic()
        class_filter = window_class if isinstance(window_class, str) else None
        window = self._find_window(title_regex, class_filter)
        while window is None:
            if _time.monotonic() - start >= deadline_s:
                raise RunSheetError(
                    f"no window matching {title_regex!r} appeared within {deadline_s:.0f}s"
                )
            _time.sleep(3.0)
            window = self._find_window(title_regex, class_filter)
        hwnd = window.get("hwnd")
        surfaced = None
        if isinstance(hwnd, int):
            surfaced = self._surface_hwnd(hwnd)
            # A freshly surfaced window is not interactive for a beat (the
            # measured no-op: a radio click one second before the dialog was
            # ready silently missed, leaving the policy Not Configured).
            import time as _time

            _time.sleep(1.2)
            # The surfaced window is the sheet's operating target: dumps and
            # clicks resolve against it (foreground reads self-shadow).
            if ctx.last_dump_hwnd is not None and ctx.last_dump_hwnd != hwnd:
                ctx.hwnd_stack.append(ctx.last_dump_hwnd)
            ctx.last_dump_hwnd = hwnd
            self._last_cached_focus = hwnd
        return {"matched": True, "title": window.get("title"), "surfaced": surfaced}

    def _live_target(self, ctx: SheetContext) -> int | None:
        """The sheet's current window, popping dead dialog hwnds.

        A child dialog's hwnd dies when its OK/Cancel closes it; the next
        dump then targets the OWNER again (the previous entry of the dialog
        chain). Liveness is checked against the z-order-independent window
        enumeration, never against the foreground.
        """
        while ctx.last_dump_hwnd is not None:
            if self._hwnd_alive(ctx.last_dump_hwnd):
                return ctx.last_dump_hwnd
            ctx.last_dump_hwnd = ctx.hwnd_stack.pop() if ctx.hwnd_stack else None
        return None

    def _hwnd_alive(self, hwnd: int) -> bool:
        result = self._t.helper({"action": "windows"}, timeout=self._helper_timeout)
        if result.outcome != "ok":
            return True  # enum failed: assume alive and let the dump report it
        windows = result.payload.get("windows")
        if not isinstance(windows, list):
            return True
        return any(
            isinstance(raw, dict) and raw.get("hwnd") == hwnd for raw in windows
        )

    def _keys(self, params: dict[str, object], ctx: SheetContext) -> dict[str, object]:
        """Composite key sequence in ONE helper invocation (popup surfaces).

        Steps may carry click_element entries (selector + optional
        offsets): these are resolved HERE, against the target window's dump,
        and rewritten as window-relative click entries -- so a control can
        be clicked and typed into within one invocation, before the next
        invocation's console steals the dialog's focus.
        """
        raw_steps = params.get("steps")
        if not isinstance(raw_steps, list) or not raw_steps:
            raise RunSheetError("keys step needs a steps array")
        focus = self._live_target(ctx)
        if focus is None:
            raise RunSheetError("keys step has no target window")
        # One fresh dump for the whole composite; all click_element entries
        # resolve against it.
        self._dump({"depth": 12}, ctx)
        if ctx.last_dump_root_rect is None:
            raise RunSheetError("keys step: target window has no rect")
        left, top, _r, _b = ctx.last_dump_root_rect
        steps: list[object] = []
        for entry in raw_steps:
            if isinstance(entry, dict) and isinstance(entry.get("click_element"), dict):
                selector = entry["click_element"]
                if not isinstance(selector, dict):
                    raise RunSheetError("keys click_element must be an object")
                element = self._resolve(ctx, selector)
                if element.center is None:
                    raise RunSheetError(
                        f"keys click_element {selector.get('name_regex')!r} has no rect"
                    )
                cx, cy = element.center
                ox = selector.get("offset_x")
                oy = selector.get("offset_y")
                if isinstance(ox, (int, float)):
                    cx += int(ox)
                if isinstance(oy, (int, float)):
                    cy += int(oy)
                steps.append({"click": [cx - left, cy - top]})
            else:
                steps.append(entry)
        request: dict[str, object] = {"action": "keys", "steps": steps}
        request["focus_hwnd"] = focus
        result = self._t.helper(request, timeout=self._helper_timeout)
        if result.outcome != "ok":
            raise RunSheetError(f"keys failed: {result.error}")
        return {"injected_events": result.payload.get("injected_events")}

    def _shot(self, params: dict[str, object]) -> dict[str, object]:
        """Full-screen capture saved into the anchored evidence directory."""
        import base64

        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise RunSheetError("shot needs a name")
        request: dict[str, object] = {"action": "screenshot", "full": True}
        result = self._t.helper(request, timeout=self._helper_timeout)
        if result.outcome != "ok":
            raise RunSheetError(f"shot failed: {result.error}")
        png = result.payload.get("png_base64")
        if not isinstance(png, str):
            raise RunSheetError("shot returned no png payload")
        path = self._evidence_dir / f"{name}.png"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(base64.b64decode(png))
        return {"saved": str(path)}

    def _surface_hwnd(self, hwnd: int) -> bool:
        """Force a window to the foreground: title-bar click via focus_hwnd."""
        result = self._t.helper(
            {
                "action": "mouse",
                "x": 60,
                "y": 8,
                "hwnd": hwnd,
                "focus_hwnd": hwnd,
            },
            timeout=self._helper_timeout,
        )
        return result.outcome == "ok"

    def _context(self, params: dict[str, object], ctx: SheetContext) -> dict[str, object]:
        result = self._t.helper({"action": "context"}, timeout=self._helper_timeout)
        if result.outcome != "ok":
            raise RunSheetError(f"context failed: {result.error}")
        ctx.last_context = result.payload
        detail: dict[str, object] = {"foreground": result.payload.get("foreground")}
        assert_regex = params.get("assert_window_regex")
        if isinstance(assert_regex, str) and assert_regex:
            window = self._find_window(assert_regex)
            if window is None:
                raise RunSheetError(f"context assert failed: no window matches {assert_regex!r}")
            detail["asserted_window"] = window.get("title")
        return detail

    def _dump(self, params: dict[str, object], ctx: SheetContext) -> dict[str, object]:
        depth = params.get("depth", 10)
        request: dict[str, object] = {
            "action": "uia_dump",
            "depth": depth if isinstance(depth, int) else 10,
        }
        # Window targeting: the sheet's window (explicit regex, or the one the
        # sheet is already operating on). Foreground fallback self-shadows.
        hwnd = self._live_target(ctx)
        window_regex = params.get("window_regex")
        window_class = params.get("window_class")
        if isinstance(window_regex, str) and window_regex:
            window = self._find_window(window_regex)
            if window is None:
                raise RunSheetError(f"dump: no window matches {window_regex!r}")
            raw_hwnd = window.get("hwnd")
            if isinstance(raw_hwnd, int):
                hwnd = raw_hwnd
        elif isinstance(window_class, str) and window_class:
            # Class-targeted dumps reach popup surfaces with no title -- the
            # classic ComboBox dropdown list is a titleless ComboLBox window.
            window = self._find_window_by_class(window_class)
            if window is None:
                raise RunSheetError(f"dump: no window of class {window_class!r}")
            raw_hwnd = window.get("hwnd")
            if isinstance(raw_hwnd, int):
                hwnd = raw_hwnd
        if hwnd is not None:
            request["hwnd"] = hwnd
        result = self._t.helper(request, timeout=self._helper_timeout)
        if result.outcome != "ok":
            raise RunSheetError(f"uia_dump failed: {result.error}")
        dumped_hwnd = result.payload.get("hwnd")
        ctx.last_dump_hwnd = dumped_hwnd if isinstance(dumped_hwnd, int) else hwnd
        if ctx.last_dump_hwnd is not None:
            self._last_cached_focus = ctx.last_dump_hwnd
        elements: list[_DumpedElement] = []
        raw_elements = result.payload.get("elements") or []
        if not isinstance(raw_elements, list):
            raw_elements = []
        for raw in raw_elements:
            if not isinstance(raw, dict):
                continue
            rect_raw = raw.get("rect")
            rect = None
            if isinstance(rect_raw, dict):
                try:
                    rect = (
                        int(rect_raw["left"]),
                        int(rect_raw["top"]),
                        int(rect_raw["right"]),
                        int(rect_raw["bottom"]),
                    )
                except (KeyError, TypeError, ValueError):
                    rect = None
            elements.append(
                _DumpedElement(
                    name=_optional_str(raw.get("name")),
                    control_type=_optional_str(raw.get("control_type")),
                    rect=rect,
                    depth=int(raw.get("depth") or 0),
                )
            )
        ctx.last_dump = elements
        ctx.last_dump_root_rect = elements[0].rect if elements else None
        truncated = result.payload.get("truncated") is True
        if truncated:
            # A capped dump silently hides elements; selectors against it
            # would fail confusingly. Fail with the truncation visible.
            raise RunSheetError(
                "uia_dump was truncated (element or time cap); raise depth or narrow the window"
            )
        names = [e.name for e in elements if e.name]
        return {"elements": len(elements), "hwnd": ctx.last_dump_hwnd, "names": names[:60]}

    def _click_element(self, params: dict[str, object], ctx: SheetContext) -> dict[str, object]:
        if params.get("fresh", True):
            self._dump(
                {
                    "depth": params.get("dump_depth", 12),
                    "window_regex": params.get("window_regex"),
                    "window_class": params.get("window_class"),
                },
                ctx,
            )
        try:
            element = self._resolve(ctx, params)
        except RunSheetError:
            if params.get("soft"):
                # A soft step models an OPTIONAL surface element (a dialog that
                # may not appear, a tree level that may not exist on this
                # shape): matched=false is the recorded result, not a failure.
                return {"matched": False, "soft": True}
            raise
        if element.center is None or ctx.last_dump_root_rect is None:
            raise RunSheetError(
                f"selector {params.get('name_regex')!r} matched an element with no rect"
            )
        left, top, _right, _bottom = ctx.last_dump_root_rect
        cx, cy = element.center
        # Optional pixel offset from the element center: reaches controls the
        # dump cannot name (an unlabeled combo below a 'Selected key:' label).
        offset_x = params.get("offset_x")
        offset_y = params.get("offset_y")
        if isinstance(offset_x, (int, float)):
            cx += int(offset_x)
        if isinstance(offset_y, (int, float)):
            cy += int(offset_y)
        request: dict[str, object] = {
            "action": "mouse",
            "x": cx - left,
            "y": cy - top,
        }
        if params.get("double"):
            request["mouse_action"] = "double"
        if params.get("button") == "right":
            request["button"] = "right"
        # The dumped window is BOTH the coordinate reference and the forced
        # foreground target: focus_hwnd runs the ALT-tap EnsureForeground
        # route, so the click lands on the surface the sheet is operating on
        # regardless of which window (the helper console included) currently
        # holds foreground. Refusing to click without a target window
        # (contract s7) is preserved: no hwnd means no click.
        if ctx.last_dump_hwnd is not None:
            request["hwnd"] = ctx.last_dump_hwnd
            request["focus_hwnd"] = ctx.last_dump_hwnd
        result = self._helper_with_focus_retry(request)
        if result.outcome != "ok":
            raise RunSheetError(f"click failed: {result.error}")
        settle_ms = params.get("settle_ms")
        if isinstance(settle_ms, (int, float)) and settle_ms > 0:
            # Navigation and dialog opens update the surface asynchronously;
            # the next step's dump must see the SETTLED state (measured: the
            # results pane needs a beat after an MMC folder navigation).
            import time as _time

            _time.sleep(settle_ms / 1000.0)
        return {"clicked": [cx - left, cy - top]}

    def _focus_hwnd(self, ctx: SheetContext) -> int | None:
        foreground = ctx.last_context.get("foreground") if ctx.last_context else None
        if isinstance(foreground, dict) and isinstance(foreground.get("hwnd"), int):
            return int(foreground["hwnd"])
        return None

    def _type_text(self, params: dict[str, object], ctx: SheetContext) -> dict[str, object]:
        text = params.get("text")
        if not isinstance(text, str):
            raise RunSheetError("type_text needs text")
        request: dict[str, object] = {"action": "key", "text": text}
        focus = self._live_target(ctx)
        if focus is not None:
            request["focus_hwnd"] = focus
        result = self._helper_with_focus_retry(request)
        if result.outcome != "ok":
            raise RunSheetError(f"type failed: {result.error}")
        return {"typed": len(text)}

    def _helper_with_focus_retry(self, request: dict[str, object]) -> HelperResult:
        """Send one gesture, retrying through modal-transition foreground races.

        MEASURED 2026-09-03: immediately after a modal child dialog closes, the
        parent's SetForegroundWindow can lose the race with the teardown, and
        the helper refuses to inject into an unfocused target. That refusal is
        transient (the window is real and becomes focusable within a beat), so
        the retry is bounded and re-checks liveness of the target each time.
        """
        import time as _time

        result = self._t.helper(request, timeout=self._helper_timeout)
        attempts = 0
        trace = ''
        while result.outcome != "ok" and attempts < 3:
            message = result.error or ""
            if "could not bring hwnd" not in message:
                break
            attempts += 1
            _time.sleep(1.0)
            focus = request.get("focus_hwnd")
            if not isinstance(focus, int):
                break
            if not self._hwnd_alive(focus):
                trace += f'attempt {attempts}: target hwnd dead; '
                break
            # MEASURED fallback (second estate window): a title-bar surface
            # click in a fresh invocation focuses the window where the direct
            # EnsureForeground refused (modal-teardown churn). After the
            # surface click the gesture is re-sent WITHOUT the focus guard.
            surfaced = self._surface_hwnd(focus)
            trace += f'attempt {attempts}: surface={surfaced}; '
            unfocused = dict(request)
            unfocused.pop("focus_hwnd")
            result = self._t.helper(unfocused, timeout=self._helper_timeout)
        if attempts and result.outcome != "ok":
            raise RunSheetError(
                f'{result.error} (focus-retry trace: {trace.strip()})'
            )
        return result

    def _key(self, params: dict[str, object], ctx: SheetContext) -> dict[str, object]:
        request: dict[str, object] = {"action": "key"}
        text = params.get("text")
        if isinstance(text, str) and text:
            request["text"] = text
        vks = params.get("vks")
        if isinstance(vks, list) and vks:
            request["vks"] = vks
        if "text" not in request and "vks" not in request:
            raise RunSheetError("key step needs text or vks")
        focus = self._live_target(ctx)
        if focus is not None:
            request["focus_hwnd"] = focus
        result = self._helper_with_focus_retry(request)
        if result.outcome != "ok":
            raise RunSheetError(f"key failed: {result.error}")
        return {"injected_events": result.payload.get("injected_events")}

    def _focus_hwnd_cached(self) -> int | None:
        # Keys go to the sheet's window (the last dumped hwnd): the foreground
        # is self-shadowed by the helper console, so it is never the source of
        # truth for targeting. A key with no dump yet in this sheet is
        # refused: injecting without a known target is the blind fallback,
        # and run-sheets cannot reach it by construction.
        return self._last_cached_focus

    # -- selector resolution -------------------------------------------------------

    def _resolve(self, ctx: SheetContext, params: dict[str, object]) -> _DumpedElement:
        pattern = params.get("name_regex")
        if not isinstance(pattern, str) or not pattern:
            raise RunSheetError("click_element needs name_regex")
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise RunSheetError(f"bad name_regex {pattern!r}: {exc}") from exc
        control_type = params.get("control_type")
        index = params.get("index", 0)
        if not isinstance(index, int) or index < 0:
            raise RunSheetError("click_element index must be a non-negative integer")
        matches = [
            element
            for element in ctx.last_dump
            if element.name and regex.search(element.name)
            and (not isinstance(control_type, str) or (element.control_type or "") == control_type)
        ]
        # Rect-less duplicates (unrendered tree peers of results-pane items)
        # never win while a placed match exists: clicking needs a rect.
        placed = [m for m in matches if m.rect is not None]
        if placed:
            matches = placed
        if index >= len(matches):
            available = [
                f"{e.control_type}:{e.name!r}@{e.rect}" for e in ctx.last_dump if e.rect
            ]
            raise RunSheetError(
                f"selector {pattern!r} matched {len(matches)} element(s), wanted index {index}; "
                f"visible elements: {available[:40]}"
            )
        return matches[index]


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) else None
