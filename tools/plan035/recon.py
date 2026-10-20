"""Plan 035 recon driver (operator tool, not committed): run a batch of
run-sheet steps against the live estate WITHOUT a transaction, persisting the
sheet's window chain between invocations, plus a `savedump` pseudo-step that
writes the full raw UIA dump payload to the evidence directory.

usage: recon.py <estate.toml> <evidence_dir> <state.json> <steps.json | -> [args.json]
"""
import json, sys
from pathlib import Path
from wcd.cli import _default_transport, _repo_root
from wcd.estate import load_estate
from wcd.runsheets import GestureExecutor, SheetContext, Step, RunSheetError

estate_path, evidence, state_path, steps_path = sys.argv[1:5]
inputs = json.loads(Path(sys.argv[5]).read_text()) if len(sys.argv) > 5 else {}
evidence = Path(evidence); evidence.mkdir(parents=True, exist_ok=True)
state_file = Path(state_path)
state = json.loads(state_file.read_text()) if state_file.exists() else {}
raw = json.loads(sys.stdin.read() if steps_path == "-" else Path(steps_path).read_text())
repo = _repo_root()
t = _default_transport(load_estate(estate_path))
ex = GestureExecutor(t, guest_scripts_dir=repo / "tools" / "guest_scripts",
                     host_scripts_dir=repo / "tools" / "host_scripts", evidence_dir=evidence)
ctx = SheetContext(inputs=inputs)
ctx.outputs.update(state.get("outputs", {}))
ctx.last_dump_hwnd = state.get("last_dump_hwnd")
ctx.hwnd_stack = list(state.get("hwnd_stack", []))
rc = 0
try:
    for i, r in enumerate(raw):
        r = dict(r)
        action = r.pop("action")
        pa = r.pop("profile_action", None)
        if action == "savedump":
            name = r["name"]
            req = {"action": "uia_dump", "depth": r.get("depth", 12)}
            target = None
            if r.get("window_regex"):
                w = ex._find_window(r["window_regex"])
                target = w.get("hwnd") if w else None
            elif r.get("window_class"):
                w = ex._find_window_by_class(r["window_class"])
                target = w.get("hwnd") if w else None
            else:
                target = ex._live_target(ctx)
            if target is not None:
                req["hwnd"] = target
            res = t.helper(req, timeout=200)
            out = {"outcome": res.outcome, "error": res.error, "payload": res.payload}
            (evidence / f"{name}.uia.json").write_text(json.dumps(out, indent=1))
            els = (res.payload or {}).get("elements") or []
            print(f"[{i}] savedump {name}: outcome={res.outcome} hwnd={target} elements={len(els)} truncated={(res.payload or {}).get('truncated')}")
            for e in els:
                if r.get("print", True):
                    print("   " + "  " * int(e.get("depth") or 0) + f"{e.get('control_type')}|{e.get('name')!r}|{e.get('automation_id', '')}|{e.get('class_name', e.get('class',''))}")
            continue
        if action == "windows":
            res = t.helper({"action": "windows"}, timeout=200)
            for w in (res.payload or {}).get("windows") or []:
                if w.get("visible"):
                    print(f"   hwnd={w.get('hwnd')} class={w.get('class')!r} title={w.get('title')!r}")
            continue
        step = Step(action=action, profile_action=pa, params=r)
        detail = ex._execute_step(step, ctx, None)
        print(f"[{i}] {step.label}: {json.dumps(detail)[:1500]}")
except RunSheetError as exc:
    print(f"STEP FAILED: {exc}"); rc = 1
finally:
    state = {"outputs": ctx.outputs, "last_dump_hwnd": ctx.last_dump_hwnd, "hwnd_stack": ctx.hwnd_stack}
    state_file.write_text(json.dumps(state))
    try: t.close()
    except Exception: pass
sys.exit(rc)
