"""Plan 035 recon driver (operator tool): run run-sheet steps with NO transaction.

Each invocation executes a JSON list of run-sheet steps against the live estate,
persisting the sheet's window chain (last target, dialog stack, outputs) in a
state file between invocations, so a recon pass can proceed one batch at a
time. Two pseudo-steps exist only here:

- ``savedump``: write the FULL raw UIA dump payload of a window to
  ``<evidence_dir>/<name>.uia.json`` (``window_regex`` / ``window_class`` /
  current target; ``depth`` 1..12) and print it as an indented tree.
- ``windows``: print the visible top-level window enumeration.

usage: recon.py <estate.toml> <evidence_dir> <state.json> <steps.json | -> [args.json]
"""

import contextlib
import json
import sys
from pathlib import Path

from wcd.cli import _default_transport, _repo_root
from wcd.estate import load_estate
from wcd.runsheets import GestureExecutor, RunSheetError, SheetContext, Step


def _savedump(ex: GestureExecutor, transport, ctx: SheetContext, raw: dict, evidence: Path) -> str:
    name = raw["name"]
    request: dict[str, object] = {"action": "uia_dump", "depth": raw.get("depth", 12)}
    target = None
    if raw.get("window_regex"):
        window = ex._find_window(raw["window_regex"])
        target = window.get("hwnd") if window else None
    elif raw.get("window_class"):
        window = ex._find_window_by_class(raw["window_class"])
        target = window.get("hwnd") if window else None
    else:
        target = ex._live_target(ctx)
    if target is not None:
        request["hwnd"] = target
    result = transport.helper(request, timeout=200)
    payload = result.payload or {}
    out = {"outcome": result.outcome, "error": result.error, "payload": payload}
    (evidence / f"{name}.uia.json").write_text(json.dumps(out, indent=1))
    elements = payload.get("elements") or []
    lines = [
        f"savedump {name}: outcome={result.outcome} hwnd={target} "
        f"elements={len(elements)} truncated={payload.get('truncated')}"
    ]
    if raw.get("print", True):
        for e in elements:
            indent = "  " * int(e.get("depth") or 0)
            lines.append(
                f"   {indent}{e.get('control_type')}|{e.get('name')!r}"
                f"|{e.get('automation_id', '')}|{e.get('class', '')}"
            )
    return "\n".join(lines)


def main() -> int:
    estate_path, evidence_arg, state_arg, steps_arg = sys.argv[1:5]
    inputs = json.loads(Path(sys.argv[5]).read_text()) if len(sys.argv) > 5 else {}
    evidence = Path(evidence_arg)
    evidence.mkdir(parents=True, exist_ok=True)
    state_file = Path(state_arg)
    state = json.loads(state_file.read_text()) if state_file.exists() else {}
    steps_text = sys.stdin.read() if steps_arg == "-" else Path(steps_arg).read_text()
    steps = json.loads(steps_text)
    repo = _repo_root()
    transport = _default_transport(load_estate(estate_path))
    ex = GestureExecutor(
        transport,
        guest_scripts_dir=repo / "tools" / "guest_scripts",
        host_scripts_dir=repo / "tools" / "host_scripts",
        evidence_dir=evidence,
    )
    ctx = SheetContext(inputs=inputs)
    ctx.outputs.update(state.get("outputs", {}))
    ctx.last_dump_hwnd = state.get("last_dump_hwnd")
    ctx.hwnd_stack = list(state.get("hwnd_stack", []))
    rc = 0
    try:
        for index, raw in enumerate(steps):
            raw = dict(raw)
            action = raw.pop("action")
            profile_action = raw.pop("profile_action", None)
            if action == "savedump":
                print(f"[{index}] " + _savedump(ex, transport, ctx, raw, evidence))
                continue
            if action == "windows":
                result = transport.helper({"action": "windows"}, timeout=200)
                for w in (result.payload or {}).get("windows") or []:
                    if w.get("visible"):
                        print(f"   hwnd={w.get('hwnd')} class={w.get('class')!r} "
                              f"title={w.get('title')!r}")
                continue
            step = Step(action=action, profile_action=profile_action, params=raw)
            detail = ex._execute_step(step, ctx, None)
            print(f"[{index}] {step.label}: {json.dumps(detail)[:1500]}")
    except RunSheetError as exc:
        print(f"STEP FAILED: {exc}")
        rc = 1
    finally:
        state = {
            "outputs": ctx.outputs,
            "last_dump_hwnd": ctx.last_dump_hwnd,
            "hwnd_stack": ctx.hwnd_stack,
        }
        state_file.write_text(json.dumps(state))
        with contextlib.suppress(Exception):
            transport.close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
