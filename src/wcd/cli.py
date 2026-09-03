"""The ``wcd`` command line: the controller-side seam the evidence runtime launches.

Verbs:

- ``exec-transaction`` -- run one capability to a terminal state and emit the
  transaction record JSON on stdout. The plan arrives on stdin exactly as
  the WEL backend sends it (``{machine, capability, arguments, ...}``), or
  from flags for direct controller-side use:
  ``wcd exec-transaction --capability capabilities/gpmc.author_scripts_entry.json
  --arg gpo_name=zz-studio-evidence-02-scripts --arg ...``.
- ``ensure-console`` -- verify (and if permitted, establish) the unlocked
  console; prints the resulting state JSON. ``--audit`` additionally reads
  the 4800/4801 lock/unlock trail once.
- ``console-state`` -- classify the console without changing anything.

Secrets come from the environment (the estate file names the variable);
argv and stdout never carry them. The transaction record is the only
stdout payload in exec-transaction mode, so a caller can parse strictly.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import console_ops
from .estate import EstateError, load_estate
from .exec_transaction import TransactionPaths, execute_transaction
from .transport import SessionTransport, default_repl_path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wcd", description=__doc__)
    parser.add_argument(
        "--estate",
        default="local/estate.toml",
        help="path to the estate TOML (default: local/estate.toml)",
    )
    sub = parser.add_subparsers(dest="verb", required=True)

    exec_txn = sub.add_parser("exec-transaction", help="run one capability to a record")
    exec_txn.add_argument(
        "--capability", help="path to the capability JSON (stdin plan mode when omitted)"
    )
    exec_txn.add_argument(
        "--arg",
        action="append",
        default=[],
        help="capability argument as key=value (repeatable)",
    )
    exec_txn.add_argument("--out", help="also write the record to this file")

    ensure = sub.add_parser("ensure-console", help="verify/establish the unlocked console")
    ensure.add_argument("--audit", action="store_true", help="also read the 4800/4801 trail once")
    ensure.add_argument("--no-unlock", action="store_true", help="report state without wake/unlock")

    sub.add_parser("console-state", help="classify the console, changing nothing")
    return parser


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _emit_json(payload: object, out_path: str | None = None) -> None:
    text = json.dumps(payload, indent=2, default=str)
    if out_path:
        Path(out_path).write_text(text + "\n", encoding="utf-8")
    print(text)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        estate = load_estate(args.estate)
    except EstateError as exc:
        print(f"estate error: {exc}", file=sys.stderr)
        return 2

    if args.verb == "console-state":
        transport = SessionTransport(estate, repl_path=default_repl_path())
        try:
            state = console_ops.lock_state(transport)
            _emit_json(
                {
                    "state": state.state,
                    "logonui_running": state.logonui_running,
                    "console_session_active": state.console_session_active,
                    "helper_responds": state.helper_responds,
                    "notes": list(state.notes),
                }
            )
        finally:
            transport.close()
        return 0

    if args.verb == "ensure-console":
        transport = SessionTransport(estate, repl_path=default_repl_path())
        try:
            if args.no_unlock:
                state = console_ops.lock_state(transport)
            else:
                state = console_ops.wait_console_unlocked(transport, estate)
            payload: dict[str, object] = {
                "state": state.state,
                "logonui_running": state.logonui_running,
                "console_session_active": state.console_session_active,
                "helper_responds": state.helper_responds,
                "notes": list(state.notes),
            }
            if args.audit:
                audit = console_ops.read_lock_audit(transport)
                payload["lock_audit_events"] = list(audit.events)
                payload["lock_audit_count"] = audit.count
            readiness = console_ops.reboot_readiness(transport)
            payload["reboot"] = {
                "classification": readiness.classification,
                "reboot_pending": readiness.reboot_pending,
                "reasons": list(readiness.reasons),
                "last_boot": readiness.last_boot,
            }
            _emit_json(payload)
            return 0 if state.state == "unlocked" else 3
        finally:
            transport.close()

    if args.verb == "exec-transaction":
        paths = TransactionPaths(repo_root=_repo_root())
        if args.capability:
            capability = json.loads(Path(args.capability).read_text(encoding="utf-8"))
            arguments: dict[str, object] = {}
            for pair in args.arg:
                key, _, value = pair.partition("=")
                try:
                    # JSON values (arrays/objects/numbers) bind as JSON; a
                    # value that is not JSON stays a string.
                    arguments[key] = json.loads(value)
                except ValueError:
                    arguments[key] = value
            plan_provenance: dict[str, object] = {"mode": "controller_direct"}
        else:
            plan = json.loads(sys.stdin.read())
            capability_text = plan.get("capability")
            if not isinstance(capability_text, str):
                print("plan error: stdin plan carries no capability text", file=sys.stderr)
                return 2
            capability = json.loads(capability_text)
            raw_arguments = plan.get("arguments")
            arguments = dict(raw_arguments) if isinstance(raw_arguments, dict) else {}
            plan_provenance = {
                "mode": "wel_exec_transaction",
                "operation_id": plan.get("operation_id"),
                "machine": plan.get("machine"),
                "identity": plan.get("identity"),
            }

        transport = SessionTransport(estate, repl_path=default_repl_path())
        try:
            record = execute_transaction(
                capability=capability,
                arguments=arguments,
                estate=estate,
                paths=paths,
                transport=transport,
                plan_provenance=plan_provenance,
            )
        finally:
            transport.close()
        _emit_json(record, args.out)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
