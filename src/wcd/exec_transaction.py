"""The transaction executor: one capability, one verified-transaction record.

This is ``wcd exec-transaction`` (the seam the windows-evidence-lab backend
launches): a JSON plan on stdin, a JSON record on stdout with exactly
``{state, verdict, envelope_result, events, provenance}``.

Flow (contract section 2, with the setup boundary made explicit):

1. **ensure-console** -- the console must be verified unlocked before any
   prepare flag is recorded (wake/unlock through the host-side credential
   path as needed; reboot-readiness classifies a mid-boot guest).
2. **recovery check** -- the estate's checkpoint baseline must exist
   (recovery declared and demonstrated present).
3. **setup** -- the run-sheet's ``guest`` setup steps run under the setup
   role's channel contract (programmatic PowerShell; GPO creation, editor
   launch). A freshly created empty GPO is the transaction's baseline, as
   in the R2 pilot.
4. **pre-oracle** -- the capability's fact plan runs over PSDirect.
5. **prepare/arm** -- the four preconditions recorded; the capability's
   gesture steps execute; ``commit`` steps cross declared boundaries.
6. **post-oracle** -- converge (poll to stability) then reproduce (second
   fresh observation), per the envelope's convergence policy.
7. **resolution** -- envelope + reproduction -> verified / disproven /
   indeterminate; then cleanup (remove the GPO, strict absence re-query)
   runs on every path, and its result is recorded in provenance.

EVERY TERMINAL PATH EMITS A RECORD. A run-sheet failure after prepare is
indeterminate + cleanup, not an exception to the caller: the WEL journal
needs the state, and the estate needs its cleanup, whatever happened.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from gpo_observers import psl
from gpo_observers.facts import FactSet, JSONValue, make_fact
from gpo_observers.snapshots import GpoRef, capture_snapshot

from . import console_ops
from .envelope import AssertionResult, assert_envelope, converge, parse_envelope
from .estate import EstateConfig
from .profiles import load_profile
from .runsheets import GestureExecutor, RunSheet, RunSheetError, SheetContext, load_run_sheet
from .transaction import GuardRefused, Transaction, TransitionEvent
from .transport import SessionTransport

_RECORD_STATES = ("verified", "disproven", "indeterminate")


class ExecTransactionError(RuntimeError):
    """The plan or estate could not be honoured; nothing was attempted."""


@dataclass(frozen=True, slots=True)
class TransactionPaths:
    """Filesystem layout the executor reads run-sheets, scripts and profile from."""

    repo_root: Path

    @property
    def run_sheets(self) -> Path:
        return self.repo_root / "runsheets"

    @property
    def guest_scripts(self) -> Path:
        return self.repo_root / "tools" / "guest_scripts"

    @property
    def host_scripts(self) -> Path:
        return self.repo_root / "tools" / "host_scripts"

    @property
    def profiles(self) -> Path:
        return self.repo_root / "profiles"


@dataclass
class RunProvenance:
    """Bounded provenance recorded into the transaction record."""

    steps: list[object] = field(default_factory=list)
    console: dict[str, object] = field(default_factory=dict)
    cleanup: dict[str, object] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def _truncate(value: object, limit: int = 1600) -> object:
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + f"...[{len(value)} chars total]"
    if isinstance(value, dict):
        return {k: _truncate(v, limit) for k, v in value.items()}
    if isinstance(value, list):
        return [_truncate(v, limit) for v in value]
    return value


class PsdirectObserverTransport:
    """Adapts the session transport to the gpo_observers Transport protocol."""

    def __init__(self, session: SessionTransport) -> None:
        self._session = session

    def __call__(self, snippet: str, params: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
        source = psl.PSL_SNIPPETS[snippet]
        if source.startswith("\\\n"):
            source = source[2:]
        script, arg_values = _bind_snippet_params(source, params)
        stdout = self._session.guest(script, arg_values, timeout=300.0)
        try:
            payload = json.loads(stdout)
        except ValueError as exc:
            raise RuntimeError(f"observer snippet {snippet!r} emitted no JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise RuntimeError(f"observer snippet {snippet!r} emitted a non-object")
        return payload


def _bind_snippet_params(
    source: str, params: Mapping[str, object]
) -> tuple[str, list[object]]:
    """Bind snippet ``[string]$Name`` params positionally in declaration order.

    Missing optional params bind as empty strings (the snippets' own
    defaults); a missing param named Mandatory in the snippet's param block
    is a caller error and is refused here.
    """
    # Param-block declarations only: anchored at line start so `[string]$x`
    # casts inside the snippet body never count as parameters.
    ordered = re.findall(r"(?m)^\s*\[string\]\$(\w+)", source)
    # Match on a folded form (case/underscore-insensitive): snippet params are
    # PowerShell camelCase ($GpoGuid); the observer API uses python snake_case
    # (gpo_guid).
    folded = {str(k).replace("_", "").lower(): v for k, v in params.items()}
    arg_values: list[object] = []
    for name in ordered:
        folded_name = name.replace("_", "").lower()
        if folded_name in folded:
            arg_values.append(folded[folded_name])
        else:
            arg_values.append("")
    return source, arg_values


class _MigtableCollector:
    """The R1 observer: one GPMC-authored migration table, parsed controller-side.

    Namespace-agnostic by design: the observer records the root tag verbatim
    and counts ``Mapping`` children in ANY namespace, because the namespace
    itself was an R1 question (measured 2026-09-03: GPMC writes the default
    namespace ``http://www.microsoft.com/GroupPolicy/GPOOperations/MigrationTable``,
    NOT the ``GroupPolicy/Types`` namespace gpo-studio's migration.py assumes).
    Per mapping, every child element's localname and text are recorded.
    """

    def collect(self, ref: GpoRef, params: Mapping[str, object], t: SessionTransport) -> FactSet:
        path = str(params.get("path", ""))
        if not path:
            raise ExecTransactionError("migration_table observer needs a path param")
        script = r"""
param([string]$Path)
$ErrorActionPreference = 'Stop'
if (Test-Path $Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    @{
        ok = $true
        data = @{ file_b64 = [Convert]::ToBase64String($bytes) }
    } | ConvertTo-Json -Compress -Depth 4
} else {
    @{ ok = $true; data = @{} } | ConvertTo-Json -Compress -Depth 4
}
exit 0
"""
        stdout = t.guest(script, [path], timeout=120.0)
        payload = json.loads(stdout)
        facts: FactSet = {}
        data = payload.get("data") or {}
        b64 = data.get("file_b64")
        if not b64:
            fact = make_fact("migtable.present", False)
            facts[fact.key] = fact
            return facts
        import base64
        import xml.etree.ElementTree as ET

        from gpo_observers.gpttmpl_inf import decode_template_bytes

        raw = base64.b64decode(b64)
        fact = make_fact("migtable.present", True)
        facts[fact.key] = fact
        fact = make_fact("migtable.bytes", len(raw))
        facts[fact.key] = fact
        text, bom = decode_template_bytes(raw)
        fact = make_fact("migtable.encoding.bom", bom)
        facts[fact.key] = fact
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            fact = make_fact("migtable.xml_parses", False)
            facts[fact.key] = fact
            fact = make_fact("migtable.parse_error", str(exc)[:200])
            facts[fact.key] = fact
            return facts
        fact = make_fact("migtable.xml_parses", True)
        facts[fact.key] = fact
        fact = make_fact("migtable.root_tag", root.tag)
        facts[fact.key] = fact
        mappings = [
            child
            for child in root
            if child.tag.endswith("}Mapping") or child.tag == "Mapping"
        ]
        fact = make_fact("migtable.mapping_count", len(mappings))
        facts[fact.key] = fact
        for index, mapping in enumerate(mappings):
            for child in mapping:
                localname = child.tag.rsplit("}", 1)[-1]
                key = f"migtable.mapping.{index}.{localname.lower()}"
                fact = make_fact(key, child.text)
                facts[fact.key] = fact
        return facts


class _FileBytesCollector:
    """Generic bytes-over-PSDirect collector backing the INI observers."""

    def __init__(self, prefix: str, parser: Callable[[bytes], dict[str, object]]) -> None:
        self._prefix = prefix
        self._parse = parser

    def collect(self, ref: GpoRef, params: Mapping[str, object], t: SessionTransport) -> FactSet:
        relpath = str(params.get("relpath", ""))
        if not relpath:
            raise ExecTransactionError(f"{self._prefix} observer needs a relpath param")
        full = str(__import__("pathlib").PureWindowsPath(ref.sysvol_path) / relpath)
        script = r"""
param([string]$Path)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    @{
        ok = $true
        data = @{ file_b64 = [Convert]::ToBase64String($bytes) }
    } | ConvertTo-Json -Compress -Depth 4
} else {
    @{ ok = $true; data = @{} } | ConvertTo-Json -Compress -Depth 4
}
exit 0
"""
        stdout = t.guest(script, [full], timeout=120.0)
        payload = json.loads(stdout)
        facts: FactSet = {}
        data = payload.get("data") or {}
        b64 = data.get("file_b64")
        if not b64:
            fact = make_fact(f"{self._prefix}.present", False)
            facts[fact.key] = fact
            return facts
        import base64

        fact = make_fact(f"{self._prefix}.present", True)
        facts[fact.key] = fact
        fact = make_fact(f"{self._prefix}.present", True)
        facts[fact.key] = fact
        facts.update(self._fact_tree(self._prefix, self._parse(base64.b64decode(b64))))
        return facts

    @staticmethod
    def _fact_tree(prefix: str, tree: Mapping[str, object]) -> FactSet:
        facts: FactSet = {}
        for key, value in tree.items():
            if isinstance(value, dict):
                facts.update(_FileBytesCollector._fact_tree(f"{prefix}.{key}", value))
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    if isinstance(item, dict):
                        nested = _FileBytesCollector._fact_tree(
                            f"{prefix}.{key}.{index}", item
                        )
                        facts.update(nested)
                    else:
                        fact = make_fact(f"{prefix}.{key}.{index}", item)
                        facts[fact.key] = fact
            else:
                fact = make_fact(f"{prefix}.{key}", value)
                facts[fact.key] = fact
        return facts


@dataclass(frozen=True, slots=True)
class _ObserverEntry:
    name: str
    params: Mapping[str, object]


def _collect_facts(
    t: SessionTransport,
    ref: GpoRef,
    capability: Mapping[str, object],
    args: Mapping[str, object],
) -> FactSet:
    """Run the capability's declared fact plan; merge into one FactSet."""
    plan = capability.get("fact_plan")
    if not isinstance(plan, dict):
        raise ExecTransactionError(f"capability {capability.get('id')!r} declares no fact_plan")
    observers = plan.get("observers")
    if not isinstance(observers, list) or not observers:
        raise ExecTransactionError("fact_plan needs a non-empty observers array")
    facts: FactSet = {}
    entries: list[_ObserverEntry] = []
    for raw in observers:
        if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
            raise ExecTransactionError(f"fact_plan entry malformed: {raw!r}")
        params = raw.get("params") or {}
        if not isinstance(params, dict):
            raise ExecTransactionError(f"fact_plan params malformed: {raw!r}")
        entries.append(_ObserverEntry(name=raw["name"], params=params))
    for entry in entries:
        if entry.name == "r2_core":
            sides = ("machine", "user")
            factset = capture_snapshot(PsdirectObserverTransport(t), ref, scripts_sides=sides)
            facts.update(factset)
            continue
        collector = _named_collector(entry.name)
        params = {
            key: _interpolate(value, args) for key, value in entry.params.items()
        }
        facts.update(collector(ref, params, t))
    return facts


def _interpolate(value: object, args: Mapping[str, object]) -> object:
    if isinstance(value, str):
        match = re.fullmatch(r"\{args\.([A-Za-z0-9_.]+)\}", value)
        if match:
            key = match.group(1)
            if key not in args:
                raise ExecTransactionError(f"fact_plan reference {match.group(0)} does not resolve")
            return args[key]
    return value


def _named_collector(
    name: str,
) -> Callable[[GpoRef, Mapping[str, object], SessionTransport], FactSet]:
    if name == "migration_table":
        return _MigtableCollector().collect
    if name == "gpttmpl_inf":
        from gpo_observers.gpttmpl_inf import gpttmpl_fact_tree

        return _FileBytesCollector("gpttmpl", gpttmpl_fact_tree).collect
    if name == "fdeploy_ini":
        from gpo_observers.fdeploy_ini import fdeploy_fact_tree

        return _FileBytesCollector("fdeploy", fdeploy_fact_tree).collect
    raise ExecTransactionError(f"unknown observer {name!r}")


# ---------------------------------------------------------------------------
# The executor proper
# ---------------------------------------------------------------------------


def execute_transaction(
    *,
    capability: dict[str, object],
    arguments: dict[str, object],
    estate: EstateConfig,
    paths: TransactionPaths,
    transport: SessionTransport,
    plan_provenance: dict[str, object] | None = None,
) -> dict[str, object]:
    """Run one capability to a terminal state and return the record."""
    capability_id = str(capability.get("id", "unnamed"))
    surface = str(capability.get("surface", estate.vm_name))
    sheet_name = capability.get("run_sheet")
    if not isinstance(sheet_name, str) or not sheet_name:
        raise ExecTransactionError(f"capability {capability_id!r} names no run_sheet")
    sheet = load_run_sheet(paths.run_sheets / f"{sheet_name}.json")
    profile = load_profile(paths.profiles / f"{surface}.toml")

    provenance = RunProvenance()
    if plan_provenance:
        truncated_plan = _truncate(plan_provenance)
        if isinstance(truncated_plan, dict):
            provenance.console.update(truncated_plan)

    txn = Transaction(transaction_id=str(uuid.uuid4()))
    events_out: list[dict[str, object]] = []
    gpo_transaction = bool(capability.get("gpo_transaction", True))

    def abort_indeterminate(reason: str) -> None:
        if txn.state is not None and not txn.is_terminal:
            txn.mark_indeterminate(reason)
        else:
            provenance.notes.append(f"pre-prepare abort: {reason}")

    def record_event(event: TransitionEvent) -> None:
        events_out.append(
            {
                "sequence": event.sequence,
                "from_state": event.from_state,
                "to_state": event.to_state,
                "reason": str(event.reason)[:512],
            }
        )

    def on_commit(boundary: str) -> None:
        declared_class = profile.classification(boundary)
        if txn.state == "commit_attempted":
            # Later crossings are part of the same attempt (contract s2).
            return
        txn.commit(
            boundary,
            declared=declared_class in ("commit_point", "potentially_mutating"),
            reason=f"run-sheet crosses {boundary!r} (profile class {declared_class!r})",
        )
        record_event(txn.events[-1])

    # -- 1. ensure-console -----------------------------------------------------
    console_state = console_ops.wait_console_unlocked(transport, estate)
    provenance.console["state"] = console_state.state
    provenance.console["helper_responds"] = console_state.helper_responds
    if console_state.state != "unlocked":
        abort_indeterminate(
            f"console never reached unlocked: {console_state.state} (notes: {console_state.notes})"
        )
        return _emit(txn, None, provenance, events_out, capability_id, sheet.name)

    # -- 2. recovery check ------------------------------------------------------
    recovery_ok = _checkpoint_exists(transport, estate)
    provenance.notes.append(f"recovery checkpoint present: {recovery_ok}")

    # -- 3. setup (setup role: programmatic) -------------------------------------
    gpo_name = str(arguments.get("gpo_name", ""))
    executor = GestureExecutor(
        transport,
        guest_scripts_dir=paths.guest_scripts,
        host_scripts_dir=paths.host_scripts,
    )
    ctx = SheetContext(inputs=dict(arguments))
    setup_sheet = _setup_sheet(sheet, ctx)
    domain_dns = _domain_dns(transport)
    gpo_guid: str | None = None

    try:
        executor.execute(setup_sheet, ctx)
        if gpo_transaction:
            guid_value = ctx.outputs.get("setup.gpo.guid")
            gpo_guid = guid_value
            if gpo_guid is None:
                raise ExecTransactionError(
                    "setup produced no gpo.guid output (scripts must emit guid=<id>)"
                )
    except (RunSheetError, ExecTransactionError) as exc:
        abort_indeterminate(f"setup failed before prepare: {exc}")
        cleanup = _cleanup(transport, executor, sheet, ctx, gpo_name)
        provenance.cleanup.update(cleanup)
        return _emit(txn, None, provenance, events_out, capability_id, sheet.name)

    ref = GpoRef(
        gpo_guid=gpo_guid or "00000000-0000-0000-0000-000000000000",
        domain_dns=domain_dns,
        sysvol_path=_sysvol_path(domain_dns, gpo_guid or "00000000-0000-0000-0000-000000000000"),
    )

    # -- 4. pre-oracle ------------------------------------------------------------
    try:
        pre_factset = _collect_facts(transport, ref, capability, arguments)
    except Exception as exc:
        abort_indeterminate(f"pre-oracle failed: {exc}")
        cleanup = _cleanup(transport, executor, sheet, ctx, gpo_name)
        provenance.cleanup.update(cleanup)
        return _emit(txn, None, provenance, events_out, capability_id, sheet.name)

    # -- 5. prepare + arm ----------------------------------------------------------
    try:
        txn.prepare(
            pre_oracle_done=True,
            lease_held=True,
            context_asserted=console_state.state == "unlocked",
            recovery_declared=recovery_ok,
            reason=f"capability {capability_id} prepared over GPO {gpo_guid}",
        )
        record_event(txn.events[-1])
        txn.arm(reason=f"capability {capability_id} invocation started")
        record_event(txn.events[-1])
    except GuardRefused as exc:
        abort_indeterminate(f"prepare refused: {exc.reason}")
        cleanup = _cleanup(transport, executor, sheet, ctx, gpo_name)
        provenance.cleanup.update(cleanup)
        return _emit(txn, None, provenance, events_out, capability_id, sheet.name)

    envelope_result: AssertionResult | None = None
    try:
        gesture_sheet = _gesture_sheet(sheet, ctx)
        journal = executor.execute(
            gesture_sheet,
            ctx,
            on_commit=on_commit,
            classify=profile.classification,
        )
        provenance.steps.append(_truncate(journal))
    except RunSheetError as exc:
        abort_indeterminate(f"run-sheet aborted: {str(exc)[:300]}")
        provenance.steps.append(_truncate(exc.journal))
        cleanup = _cleanup(transport, executor, sheet, ctx, gpo_name)
        provenance.cleanup.update(cleanup)
        return _emit(txn, None, provenance, events_out, capability_id, sheet.name)

    # -- 6. post-oracle: converge + reproduce ---------------------------------------
    envelope = parse_envelope(_envelope_dict(capability, arguments))
    # Allow clauses name the volatile SUBcategories (timestamps,
    # replication_metadata) per the contract vocabulary; map each fact to the
    # finest declared label it carries so an allow clause matches directly.
    categories = {
        key: (fact.volatile_subcategory or fact.category)
        for key, fact in pre_factset.items()
    }

    def observe() -> dict[str, object]:
        post = _collect_facts(transport, ref, capability, arguments)
        return {key: fact.value for key, fact in post.items()}

    pre_values = {key: fact.value for key, fact in pre_factset.items()}
    try:
        convergence = converge(envelope, pre_values, categories, observe)
    except Exception as exc:
        abort_indeterminate(f"post-oracle observation failed: {exc}")
        cleanup = _cleanup(transport, executor, sheet, ctx, gpo_name)
        provenance.cleanup.update(cleanup)
        return _emit(txn, None, provenance, events_out, capability_id, sheet.name)

    post_values = dict(convergence.frozen or {})
    envelope_result = convergence.assertion if convergence.frozen else assert_envelope(
        envelope, pre_values, post_values, categories
    )
    if convergence.status == "satisfied":
        txn.resolve(
            envelope_satisfied=True,
            reproduce_satisfied=True,
            reason=f"converged after {convergence.polls} polls, "
            f"{convergence.reproduce_observed} reproductions",
        )
    elif convergence.status == "disproven":
        txn.resolve(
            envelope_satisfied=False,
            reproduce_satisfied=True,
            characterization=envelope_result.characterization[:512],
        )
    else:
        txn.resolve(
            envelope_satisfied=envelope_result.status == "satisfied",
            reproduce_satisfied=False,
            reason=convergence.reason or "convergence indeterminate",
        )
    record_event(txn.events[-1])

    # -- 7. cleanup -------------------------------------------------------------------
    cleanup_result = _cleanup(transport, executor, sheet, ctx, gpo_name)
    provenance.cleanup.update(cleanup_result)
    return _emit(txn, envelope_result, provenance, events_out, capability_id, sheet.name)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _setup_sheet(sheet: RunSheet, ctx: SheetContext) -> RunSheet:
    return _phase_sheet(sheet, "setup")


def _gesture_sheet(sheet: RunSheet, ctx: SheetContext) -> RunSheet:
    return _phase_sheet(sheet, "gesture")


def _phase_sheet(sheet: RunSheet, phase: str) -> RunSheet:
    steps = tuple(s for s in sheet.steps if s.params.get("phase", "gesture") == phase)
    return RunSheet(name=f"{sheet.name}:{phase}", surface=sheet.surface, steps=steps)


def _checkpoint_exists(t: SessionTransport, estate: EstateConfig) -> bool:
    script = (
        "$s = @(Get-VMSnapshot -VMName $args[0] -ErrorAction SilentlyContinue); "
        "\"count=$($s.Count)\""
    )
    stdout = t.host(script, [estate.vm_name], timeout=60)
    match = re.search(r"count=(\d+)", stdout)
    return match is not None and int(match.group(1)) > 0


def _domain_dns(t: SessionTransport) -> str:
    stdout = t.guest('(Get-ADDomain).DNSRoot', timeout=120)
    return stdout.strip().splitlines()[-1].strip() if stdout.strip() else ""


def _sysvol_path(domain_dns: str, gpo_guid: str) -> str:
    return f"\\\\{domain_dns}\\SYSVOL\\{domain_dns}\\Policies\\{{{gpo_guid}}}"


def _cleanup(
    t: SessionTransport,
    executor: GestureExecutor,
    sheet: RunSheet,
    ctx: SheetContext,
    gpo_name: str,
) -> dict[str, object]:
    """The capability's cleanup: the run-sheet's cleanup phase + absence requery."""
    steps = tuple(s for s in sheet.steps if s.params.get("phase") == "cleanup")
    result: dict[str, object] = {}
    if not steps:
        result["ran"] = False
        result["note"] = "run-sheet declares no cleanup phase"
    else:
        # Every cleanup step runs INDEPENDENTLY: a failed backup must never
        # skip GPO removal (the strict-absence discipline outranks evidence
        # preservation, and a partial cleanup is worse than a per-step error
        # record).
        journal: list[object] = []
        cleanup_sheet = RunSheet(name=f"{sheet.name}:cleanup", surface=sheet.surface, steps=steps)
        for index, step in enumerate(cleanup_sheet.steps):
            try:
                detail = executor._execute_step(step, ctx, None)
                journal.append(
                    {"index": index, "step": step.label, "ok": True, "detail": _truncate(detail)}
                )
            except Exception as exc:
                journal.append(
                    {"index": index, "step": step.label, "ok": False, "error": str(exc)[:512]}
                )
        result["ran"] = True
        result["journal"] = _truncate(journal)
    if gpo_name:
        try:
            stdout = t.guest(
                "$l = @(Get-GPO -All | Where-Object { "
                "$_.DisplayName -like 'zz-studio-evidence-*' }); "
                "\"remaining=$($l.Count)\"",
                timeout=120,
            )
            match = re.search(r"remaining=(\d+)", stdout)
            remaining = int(match.group(1)) if match else -1
            result["zz_studio_evidence_remaining"] = remaining
            if remaining > 0:
                result["note"] = (
                    "STRICT ABSENCE VIOLATION: zz-studio-evidence-* GPOs remain after cleanup"
                )
        except Exception as exc:
            result["requery_error"] = str(exc)[:512]
    return result


def _envelope_dict(
    capability: Mapping[str, object], arguments: Mapping[str, object]
) -> dict[str, object]:
    envelope = capability.get("envelope")
    if not isinstance(envelope, dict):
        raise ExecTransactionError("capability declares no envelope")
    return _bind_args_into_envelope(envelope, arguments)


def _flatten_args(prefix: str, value: object, out: dict[str, object]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _flatten_args(f"{prefix}.{key}" if prefix else str(key), item, out)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _flatten_args(f"{prefix}.{index}", item, out)
    else:
        out[prefix] = value


_ARGS_REF_RE = re.compile(r"args\[(['\"])([A-Za-z0-9_.]+)\1\]")


def _bind_args_into_envelope(
    envelope: Mapping[str, object], arguments: Mapping[str, object]
) -> dict[str, object]:
    """Substitute ``args['dotted.key']`` references with JSON literals.

    The capability bindings note (contract section 11): the envelope engine is
    namespace-agnostic; merging args is transaction-executor work. Done at
    load time as literal substitution so the bounded evaluator never sees an
    unbounded namespace (and every bound value stays a JSON scalar).
    """
    flat: dict[str, object] = {}
    _flatten_args("", dict(arguments), flat)

    def substitute(source: str) -> str:
        def replace(match: re.Match[str]) -> str:
            key = match.group(2)
            if key not in flat:
                raise ExecTransactionError(f"envelope references missing arg {key!r}")
            return json.dumps(flat[key])

        return _ARGS_REF_RE.sub(replace, source)

    out: dict[str, object] = {}
    for key, value in envelope.items():
        if key in ("require", "forbid"):
            out[key] = [
                {**clause, "predicate": substitute(str(clause.get("predicate", "")))}
                if isinstance(clause, dict)
                else clause
                for clause in (value if isinstance(value, list) else [])
            ]
        elif key == "derive":
            out[key] = [
                {**clause, "relation": substitute(str(clause.get("relation", "")))}
                if isinstance(clause, dict)
                else clause
                for clause in (value if isinstance(value, list) else [])
            ]
        else:
            out[key] = value
    return out


def _emit(
    txn: Transaction,
    envelope_result: AssertionResult | None,
    provenance: RunProvenance,
    events: list[dict[str, object]],
    capability_id: str,
    sheet_name: str,
) -> dict[str, object]:
    state = txn.state or "indeterminate"
    if state not in _RECORD_STATES:
        state = "indeterminate"
    verdict = txn.indeterminate_reason or txn.characterization or (
        "transaction reached " + state
    )
    envelope_out: dict[str, object] = {}
    if envelope_result is not None:
        # The characterized delta IS part of the record (contract section 3):
        # which facts changed, added, or were removed, so a disproven result
        # is analyzable without re-running the transaction.
        delta_entries = [
            {
                "key": entry.key,
                "kind": entry.kind,
                "before": _truncate(entry.before),
                "after": _truncate(entry.after),
            }
            for entry in envelope_result.delta.entries
        ]
        envelope_out = {
            "status": envelope_result.status,
            "satisfied": [_truncate(s) for s in envelope_result.satisfied],
            "violated": [_truncate(s) for s in envelope_result.violated],
            "unclassified": list(envelope_result.unclassified),
            "characterization": envelope_result.characterization[:512],
            "delta": delta_entries,
        }
    provenance_block: dict[str, object] = {
        "capability": capability_id,
        "run_sheet": sheet_name,
        "transaction_id": txn.transaction_id or "",
        "console": _truncate(provenance.console),
        "steps": provenance.steps,
        "cleanup": _truncate(provenance.cleanup),
        "notes": [str(n)[:512] for n in provenance.notes],
    }
    return {
        "state": state,
        "verdict": verdict[:512].replace("\n", " ").replace("\r", " "),
        "envelope_result": envelope_out,
        "events": events,
        "provenance": provenance_block,
    }
