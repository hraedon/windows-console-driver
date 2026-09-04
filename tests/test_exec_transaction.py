"""End-to-end executor tests: ``execute_transaction`` must honor the contract.

``docs/contract.md`` is enforced against the pure layers (``wcd.transaction``,
``wcd.envelope``, ``wcd.leases``) elsewhere; these tests pin it against the
EXECUTOR -- the seam that wires transport, helpers, run-sheets, profiles,
lease and oracle into one record. Every test runs a full transaction against
a scripted :class:`FakeTransport` (JSON stdout per op, helper results typed
through :mod:`wcd.helper_client`), no Windows required (contract section 13).

The scenarios, by defect/contract clause:

1. convergence timeout -> record state ``indeterminate``, never disproven,
   and no fabricated "removed" delta (contract s3: timeout is not failure).
2. genuinely violated envelope -> ``disproven`` WITH the characterized delta.
3. converged-but-indeterminate assertion (unresolved clause) ->
   ``indeterminate`` (a disproof must be grounded in observed state).
4. run-sheet failure after prepare -> record still emitted, cleanup ran.
5. undeclared profile action -> refused before the first crossing AND after.
6. a ``keys`` step classified ``commit_point`` -> ``on_commit`` fires.
7. context mismatch at a commit point -> ``indeterminate``; the crossing
   did not proceed (contract s7).
Plus: lease exclusivity and release on terminal paths, fail-closed context
at prepare, estate-anchored evidence paths, and per-step cleanup with the
GUID-based strict-absence re-query (contract s12).
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from pathlib import Path

import pytest

from wcd.estate import EstateConfig
from wcd.exec_transaction import TransactionPaths, execute_transaction
from wcd.helper_client import HelperResult
from wcd.leases import LeaseRegistry
from wcd.transport import TransportError

# Synthetic-estate identifiers only: zz- placeholders per the project
# convention. Nothing here names a real host, domain, user, or path.
GPO_GUID = "11111111-2222-3333-4444-555555555555"
LEASE_TARGET = "wcd.console:zz-vm"

Matcher = Callable[[str], bool]
ScriptResponder = Callable[[str, list[object]], str]
HelperResponder = Callable[[dict[str, object]], dict[str, object]]


# --- Scripted transport --------------------------------------------------------


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _migtable_present(script: str, args: list[object]) -> str:
    return json.dumps({"ok": True, "data": {"file_b64": _b64(b"<MigrationTable/>")}})


def _migtable_absent(script: str, args: list[object]) -> str:
    return json.dumps({"ok": True, "data": {}})


class FakeTransport:
    """Scripted stand-in for ``SessionTransport``: JSON stdout per op.

    ``guest``/``host`` route on script-content matchers (the fake scripts in
    the test repo carry unique ``zzfake:`` markers); ``helper`` dispatches on
    ``request["action"]``. Every op is recorded so tests can assert on what
    actually crossed -- and, critically, on what never did.
    """

    def __init__(self) -> None:
        self.guest_calls: list[dict[str, object]] = []
        self.host_calls: list[dict[str, object]] = []
        self.helper_calls: list[dict[str, object]] = []
        # The scripted interactive context; tests mutate these to script
        # context drift (an RDP session switch, a resolution change, ...).
        self.session_id = 1
        self.user = "zz-lab-user"
        self.desktop = "Default"
        self.digest = "zz-surface-digest-1"
        self.migtable_responder: ScriptResponder = _migtable_absent
        self.requery_response = "remaining=0\n"
        self.guest_routes: list[tuple[Matcher, ScriptResponder]] = [
            (lambda s: "logonui_running" in s, self._console_probe),
            (lambda s: "Get-ADDomain" in s, lambda s, a: "zzlab.invalid\n"),
            (lambda s: "zzfake: gpo_create" in s, self._gpo_create),
            (lambda s: "ReadAllBytes" in s, lambda s, a: self.migtable_responder(s, a)),
            (lambda s: "Get-GPO -All" in s, lambda s, a: self.requery_response),
            (lambda s: "zzfake: mmc_kill" in s, lambda s, a: "remaining=0\n"),
            (lambda s: "zzfake: gpo_remove" in s, lambda s, a: "removed=zz\n"),
        ]
        self.host_routes: list[tuple[Matcher, ScriptResponder]] = [
            (lambda s: "Get-VMSnapshot" in s, lambda s, a: "count=1\n"),
        ]
        self.helper_routes: dict[str, HelperResponder] = {
            "context": lambda request: self._context_payload(),
            "windows": lambda request: {
                "windows": [
                    {
                        "hwnd": 4242,
                        "pid": 99,
                        "title": "Group Policy",
                        "class": "mmc",
                        "visible": True,
                    }
                ]
            },
            "uia_dump": self._dump_payload,
            "mouse": lambda request: {"injected_events": 1},
            "key": lambda request: {"injected_events": 1},
            "keys": lambda request: {"injected_events": 3},
            "screenshot": lambda request: {"png_base64": _b64(b"zz-png")},
        }
        self.helper_errors: dict[str, str] = {}

    # -- transport protocol ----------------------------------------------------

    @property
    def vm_name(self) -> str:
        return "zz-vm"

    def guest(
        self, script: str, args: list[object] | None = None, *, timeout: float = 180.0
    ) -> str:
        self.guest_calls.append({"script": script, "args": list(args or [])})
        for matcher, responder in self.guest_routes:
            if matcher(script):
                return responder(script, list(args or []))
        raise AssertionError(f"unscripted guest call: {script[:160]!r}")

    def host(self, script: str, args: list[object] | None = None, *, timeout: float = 120.0) -> str:
        self.host_calls.append({"script": script, "args": list(args or [])})
        for matcher, responder in self.host_routes:
            if matcher(script):
                return responder(script, list(args or []))
        raise AssertionError(f"unscripted host call: {script[:160]!r}")

    def helper(
        self,
        request: dict[str, object],
        *,
        timeout: float = 200.0,
        timeout_s: float | None = None,
    ) -> HelperResult:
        self.helper_calls.append(dict(request))
        action = str(request.get("action"))
        error = self.helper_errors.get(action)
        if error is not None:
            return HelperResult("error", 2, {"ok": False, "error": error}, error, False)
        responder = self.helper_routes.get(action)
        if responder is None:
            raise AssertionError(f"unscripted helper action {action!r}")
        return HelperResult("ok", 0, responder(request), None, False)

    # -- scripted payloads -------------------------------------------------------

    def _console_probe(self, script: str, args: list[object]) -> str:
        return json.dumps(
            {
                "logonui_running": False,
                "console_session_active": True,
                "inactivity_timeout_secs": None,
                "quser": [],
            }
        )

    def _gpo_create(self, script: str, args: list[object]) -> str:
        return f"guid={GPO_GUID}\ndomain=zzlab.invalid\n"

    def _context_payload(self) -> dict[str, object]:
        return {
            "ok": True,
            "action": "context",
            "session_id": self.session_id,
            "user": self.user,
            "desktop": self.desktop,
            "foreground": {
                "hwnd": 4242,
                "pid": 99,
                "process_name": "mmc.exe",
                "title": "Group Policy",
                "class": "mmc",
                "rect": None,
                "uia_digest": self.digest,
            },
            "notes": [],
        }

    def _dump_payload(self, request: dict[str, object]) -> dict[str, object]:
        return {
            "ok": True,
            "action": "uia_dump",
            "hwnd": 4242,
            "depth": request.get("depth", 10),
            "truncated": False,
            "element_count": 2,
            "elements": [
                {
                    "depth": 0,
                    "name": None,
                    "class": "mmc",
                    "automation_id": None,
                    "control_type": "Window",
                    "rect": {"left": 0, "top": 0, "right": 800, "bottom": 600},
                    "patterns": [],
                },
                {
                    "depth": 2,
                    "name": "OK",
                    "class": "Button",
                    "automation_id": None,
                    "control_type": "Button",
                    "rect": {"left": 10, "top": 10, "right": 90, "bottom": 40},
                    "patterns": [],
                },
            ],
            "notes": [],
        }


# --- Test estate ----------------------------------------------------------------


def _estate(**overrides: str) -> EstateConfig:
    values: dict[str, str] = {
        "host": "zz-hyperv",
        "vm_name": "zz-vm",
        "domain": "zzlab.invalid",
        "username": "zz-operator",
        "password_env": "WCD_ZZ_PW",
    }
    values.update(overrides)
    return EstateConfig(**values)


_PROFILE_TOML = """\
[profile]
surface = "zz-fake-surface"
first_commit_point = "zz_commit"

[actions.zz_navigate]
class = "orientation_only"

[actions.zz_commit]
class = "commit_point"

[actions.zz_keys_commit]
class = "commit_point"
"""

_SETUP_STEPS: list[dict[str, object]] = [
    {
        "action": "guest",
        "phase": "setup",
        "script": "zz_gpo_create",
        "args": ["{args.gpo_name}", "zz test estate"],
        "output_as": "setup.gpo",
    },
]

_CLEANUP_STEPS: list[dict[str, object]] = [
    {"action": "guest", "phase": "cleanup", "script": "zz_mmc_kill"},
    {"action": "guest", "phase": "cleanup", "script": "zz_gpo_remove"},
]


def _make_repo(tmp_path: Path, sheet: dict[str, object]) -> TransactionPaths:
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "zz-fake-surface.toml").write_text(_PROFILE_TOML, encoding="utf-8")
    scripts = tmp_path / "tools" / "guest_scripts"
    scripts.mkdir(parents=True)
    for name in ("zz_gpo_create", "zz_mmc_kill", "zz_gpo_remove", "zz_requery"):
        marker = name.removeprefix("zz_")
        (scripts / f"{name}.ps1").write_text(f"# zzfake: {marker}\n", encoding="utf-8")
    (tmp_path / "runsheets").mkdir()
    name = str(sheet["name"])
    (tmp_path / "runsheets" / f"{name}.json").write_text(json.dumps(sheet), encoding="utf-8")
    return TransactionPaths(repo_root=tmp_path)


def _sheet(name: str, gesture: list[dict[str, object]]) -> dict[str, object]:
    return {
        "name": name,
        "surface": "zz-fake-surface",
        "steps": [*_SETUP_STEPS, *gesture, *_CLEANUP_STEPS],
    }


def _capability(sheet_name: str, envelope: dict[str, object]) -> dict[str, object]:
    return {
        "id": "zz.capability.test",
        "surface": "zz-fake-surface",
        "run_sheet": sheet_name,
        "gpo_transaction": True,
        "fact_plan": {
            "observers": [
                {"name": "migration_table", "params": {"path": "C:\\lab\\wcd\\zz.migtable"}}
            ]
        },
        "envelope": envelope,
    }


# A require clause the fake oracle can satisfy or violate by flipping the
# scripted migration-table file; the observation is one fact, so convergence
# stabilizes (or not) on that single value.
_SATISFIED_ENVELOPE: dict[str, object] = {
    "require": [{"fact": "migtable.present", "predicate": "post.migtable.present == False"}],
    "convergence": {"window_seconds": 10, "poll_seconds": 0.01, "reproduce": 1},
}

_FAST_CONVERGENCE: dict[str, object] = {"window_seconds": 10, "poll_seconds": 0.01, "reproduce": 1}


def _commit_crossing_gesture() -> list[dict[str, object]]:
    return [
        {"action": "dump", "profile_action": "zz_navigate", "depth": 12},
        {
            "action": "click_element",
            "profile_action": "zz_commit",
            "name_regex": "^OK$",
            "control_type": "Button",
        },
    ]


def _run(
    tmp_path: Path,
    sheet: dict[str, object],
    envelope: dict[str, object],
    transport: FakeTransport,
    *,
    arguments: dict[str, object] | None = None,
    lease_registry: LeaseRegistry | None = None,
    estate: EstateConfig | None = None,
) -> dict[str, object]:
    return execute_transaction(
        capability=_capability(str(sheet["name"]), envelope),
        arguments=arguments if arguments is not None else {"gpo_name": "zz-studio-evidence-t"},
        estate=estate if estate is not None else _estate(),
        paths=_make_repo(tmp_path, sheet),
        transport=transport,  # type: ignore[arg-type]
        lease_registry=lease_registry,
    )


def _states(record: dict[str, object]) -> list[object]:
    return [event["to_state"] for event in record["events"]]  # type: ignore[index]


def _cleanup_of(record: dict[str, object]) -> dict[str, object]:
    cleanup = record["provenance"]["cleanup"]  # type: ignore[index]
    assert isinstance(cleanup, dict)
    return cleanup


# --- 1. convergence timeout -------------------------------------------------------


def test_convergence_timeout_is_indeterminate_never_disproven(tmp_path: Path) -> None:
    """Contract s3: 'Timeout is not failure: it is indeterminate.' A run whose
    oracle never stabilizes lands in indeterminate; the executor must NOT
    re-assert against a fabricated empty post state (which characterized an
    everything-removed delta nobody observed) and must NOT resolve disproven."""
    transport = FakeTransport()
    reads = {"n": 0}

    def churn(script: str, args: list[object]) -> str:
        reads["n"] += 1
        if reads["n"] % 2 == 0:
            return _migtable_absent(script, args)
        return _migtable_present(script, args)

    transport.migtable_responder = churn
    envelope = {
        "require": [{"fact": "migtable.present", "predicate": "post.migtable.present == True"}],
        "convergence": {"window_seconds": 0.5, "poll_seconds": 0.05, "reproduce": 1},
    }
    record = _run(tmp_path, _sheet("zz_timeout", _commit_crossing_gesture()), envelope, transport)

    assert record["state"] == "indeterminate"
    assert "disproven" not in _states(record)
    envelope_result = record["envelope_result"]
    assert isinstance(envelope_result, dict)
    assert envelope_result["status"] == "indeterminate"
    # No fabricated delta: the convergence assertion over no frozen state
    # carries NO entries at all -- nothing was observed as "removed".
    assert envelope_result["delta"] == []
    assert envelope_result["violated"] == []
    assert "convergence window" in str(record["verdict"])
    # The run genuinely crossed its commit point before timing out.
    assert "commit_attempted" in _states(record)


# --- 2. genuine violation ---------------------------------------------------------


def test_genuinely_violated_envelope_is_disproven_with_delta(tmp_path: Path) -> None:
    """Contract s2/s3: a grounded envelope violation over the FROZEN
    observation resolves disproven -- a result, with the characterized delta
    recorded -- and cleanup (incl. the GUID-keyed strict-absence re-query)
    still runs."""
    transport = FakeTransport()
    reads = {"n": 0}

    def present_once(script: str, args: list[object]) -> str:
        reads["n"] += 1
        if reads["n"] == 1:  # the pre-oracle observation: file present
            return _migtable_present(script, args)
        return _migtable_absent(script, args)

    transport.migtable_responder = present_once
    envelope = {
        "require": [{"fact": "migtable.present", "predicate": "post.migtable.present == True"}],
        "convergence": _FAST_CONVERGENCE,
    }
    record = _run(tmp_path, _sheet("zz_violated", _commit_crossing_gesture()), envelope, transport)

    assert record["state"] == "disproven"
    envelope_result = record["envelope_result"]
    assert isinstance(envelope_result, dict)
    assert envelope_result["status"] == "disproven"
    assert envelope_result["violated"]  # a grounded, evaluated-false clause
    delta = envelope_result["delta"]
    assert isinstance(delta, list) and delta
    changed = [entry for entry in delta if entry["kind"] == "changed"]  # type: ignore[union-attr]
    assert any(
        entry["key"] == "migtable.present" and entry["before"] is True and entry["after"] is False
        for entry in changed
    )
    assert str(record["verdict"]).startswith("disproven")
    assert _states(record)[-1] == "disproven"

    # Cleanup ran, and the strict-absence re-query names THE GPO by GUID.
    cleanup = _cleanup_of(record)
    assert cleanup["ran"] is True
    assert cleanup["evidence_gpo_guid"] == GPO_GUID
    assert cleanup["evidence_gpo_remaining"] == 0
    requeries = [
        call
        for call in transport.guest_calls
        if "Get-GPO -All" in str(call["script"])  # type: ignore[operator]
    ]
    assert len(requeries) == 1
    script = str(requeries[0]["script"])
    assert GPO_GUID in script
    assert "$_.Id.ToString()" in script
    assert "DisplayName" not in script  # never the wildcard family count


# --- 3. unresolved clause caps at indeterminate ------------------------------------


def test_converged_but_unresolved_clause_is_indeterminate(tmp_path: Path) -> None:
    """Contract s3 via envelope tri-state semantics: a require clause that
    cannot be evaluated over the frozen state is unresolved, and unresolved
    caps the verdict at indeterminate -- never disproven."""
    transport = FakeTransport()
    envelope = {
        "require": [
            {"fact": "zz.absent_fact", "predicate": "post.zz.absent_fact == True"},
        ],
        "convergence": _FAST_CONVERGENCE,
    }
    record = _run(
        tmp_path, _sheet("zz_unresolved", _commit_crossing_gesture()), envelope, transport
    )

    assert record["state"] == "indeterminate"
    assert "disproven" not in _states(record)
    envelope_result = record["envelope_result"]
    assert isinstance(envelope_result, dict)
    assert envelope_result["status"] == "indeterminate"
    assert len(envelope_result["unresolved"]) == 1
    assert envelope_result["violated"] == []
    assert envelope_result["delta"] == []
    assert "unresolved" in str(record["verdict"])
    assert _states(record)[-1] == "indeterminate"


# --- 4. failure after prepare -------------------------------------------------------


def test_run_sheet_failure_after_prepare_emits_record_and_cleans_up(tmp_path: Path) -> None:
    """Contract s2/s7: a run-sheet failure after prepare is indeterminate +
    cleanup, not an exception to the caller -- the record is emitted, the
    cleanup phase ran, and the lease was released."""
    transport = FakeTransport()
    registry = LeaseRegistry()
    gesture = [{"action": "guest", "script": "zz_missing_script"}]
    record = _run(
        tmp_path,
        _sheet("zz_abort", gesture),
        _SATISFIED_ENVELOPE,
        transport,
        lease_registry=registry,
    )

    assert record["state"] == "indeterminate"
    assert "run-sheet aborted" in str(record["verdict"])
    assert record["envelope_result"] == {}  # never asserted
    cleanup = _cleanup_of(record)
    assert cleanup["ran"] is True
    assert isinstance(cleanup["journal"], list) and cleanup["journal"]
    assert any("zzfake: mmc_kill" in str(call["script"]) for call in transport.guest_calls)
    assert registry.holder_of(LEASE_TARGET) is None


# --- 5. undeclared profile actions ----------------------------------------------------


def test_undeclared_profile_action_refused_before_first_crossing(tmp_path: Path) -> None:
    """Contract s6 rule 2: qualified execution refuses undeclared actions --
    BEFORE the first crossing too, so nothing moves."""
    transport = FakeTransport()
    gesture = [
        {
            "action": "click_element",
            "profile_action": "zz_undeclared",
            "name_regex": "^OK$",
            "control_type": "Button",
        },
    ]
    record = _run(tmp_path, _sheet("zz_undeclared_pre", gesture), _SATISFIED_ENVELOPE, transport)

    assert record["state"] == "indeterminate"
    assert "not declared" in str(record["verdict"])
    assert "commit_attempted" not in _states(record)
    assert not [call for call in transport.helper_calls if call["action"] == "mouse"]


def test_undeclared_profile_action_still_refused_after_crossing(tmp_path: Path) -> None:
    """The refusal must not live inside the pre-crossing branch: after the
    first commit point, undeclared profile actions are still refused."""
    transport = FakeTransport()
    gesture = [
        *(_commit_crossing_gesture()),
        {
            "action": "click_element",
            "profile_action": "zz_undeclared",
            "name_regex": "^OK$",
            "control_type": "Button",
        },
    ]
    record = _run(tmp_path, _sheet("zz_undeclared_post", gesture), _SATISFIED_ENVELOPE, transport)

    assert record["state"] == "indeterminate"
    assert "not declared" in str(record["verdict"])
    # The crossing happened exactly once, then the refusal stopped the sheet.
    assert _states(record).count("commit_attempted") == 1
    mice = [call for call in transport.helper_calls if call["action"] == "mouse"]
    assert len(mice) == 1  # the declared commit click; the undeclared one never ran
    steps = record["provenance"]["steps"]  # type: ignore[index]
    journal = steps[0] if isinstance(steps, list) and steps else []
    failed = [entry for entry in journal if entry["index"] == 2]  # type: ignore[index,union-attr]
    assert failed and failed[0]["ok"] is False  # type: ignore[index]


# --- 6. keys step crossing --------------------------------------------------------------


def test_keys_step_classified_commit_point_fires_on_commit(tmp_path: Path) -> None:
    """Contract s2/s6: the crossing check applies to ANY step carrying a
    profile_action -- a ``keys`` composite classified ``commit_point`` fires
    ``on_commit``, crosses, and the transaction resolves normally. (This test
    fails on the old action-name filter, which excluded ``keys``.)"""
    transport = FakeTransport()
    registry = LeaseRegistry()
    gesture = [
        {"action": "dump", "profile_action": "zz_navigate", "depth": 12},
        {
            "action": "keys",
            "profile_action": "zz_keys_commit",
            "steps": [{"text": "zz"}],
        },
    ]
    record = _run(
        tmp_path,
        _sheet("zz_keys_crossing", gesture),
        _SATISFIED_ENVELOPE,
        transport,
        lease_registry=registry,
    )

    assert _states(record) == ["prepared", "armed", "commit_attempted", "verified"]
    assert record["state"] == "verified"
    assert [call for call in transport.helper_calls if call["action"] == "keys"]
    assert registry.holder_of(LEASE_TARGET) is None


# --- 7. context mismatch at a commit point ------------------------------------------------


def test_context_mismatch_at_commit_point_is_indeterminate_and_crossing_does_not_proceed(
    tmp_path: Path,
) -> None:
    """Contract s7: a fresh interactive-context assertion before the commit
    point that deviates from the prepared context invalidates the operation
    -> indeterminate, never a retry -- and the crossing itself never runs."""
    transport = FakeTransport()
    reads = {"n": 0}

    def drifting_context(request: dict[str, object]) -> dict[str, object]:
        reads["n"] += 1
        if reads["n"] >= 3:  # lock-state probe, prepare baseline, THEN the crossing check
            transport.session_id = 2  # scripted RDP session switch mid-flight
        return transport._context_payload()

    transport.helper_routes["context"] = drifting_context
    record = _run(
        tmp_path, _sheet("zz_drift", _commit_crossing_gesture()), _SATISFIED_ENVELOPE, transport
    )

    assert record["state"] == "indeterminate"
    assert "context mismatch" in str(record["verdict"])
    assert "session_id" in str(record["verdict"])
    # The crossing did NOT proceed: no commit was recorded, and the commit
    # point's own gesture (the mouse click) was never injected.
    assert "commit_attempted" not in _states(record)
    assert not [call for call in transport.helper_calls if call["action"] == "mouse"]


# --- lease, fail-closed context, evidence anchor, cleanup discipline ----------------------


def test_held_lease_refuses_the_transaction_before_anything_moves(tmp_path: Path) -> None:
    """Contract s7: the interactive-session lease is exclusive; a second
    transaction for the same console is refused as indeterminate and the
    incumbent holder is untouched."""
    transport = FakeTransport()
    registry = LeaseRegistry()
    registry.acquire(LEASE_TARGET, "zz-squatter")
    record = _run(
        tmp_path,
        _sheet("zz_lease_held", _commit_crossing_gesture()),
        _SATISFIED_ENVELOPE,
        transport,
        lease_registry=registry,
    )

    assert record["state"] == "indeterminate"
    assert any("lease" in str(note) for note in record["provenance"]["notes"])  # type: ignore[index]
    assert registry.holder_of(LEASE_TARGET) == "zz-squatter"
    assert _cleanup_of(record) == {}  # refused before setup: nothing to clean


def test_unreadable_context_refuses_before_arming(tmp_path: Path) -> None:
    """Contract s7 fail-closed: a helper that cannot provide a well-formed
    context means the transaction refuses to arm -- never silently passes."""
    transport = FakeTransport()

    def wedging_context(request: dict[str, object]) -> dict[str, object]:
        # The error is checked BEFORE the responder runs, so the lock-state
        # probe (call 1) still succeeds and prepare's read (call 2) fails.
        transport.helper_errors["context"] = "helper wedged"
        return transport._context_payload()

    transport.helper_routes["context"] = wedging_context
    record = _run(
        tmp_path, _sheet("zz_noctx", _commit_crossing_gesture()), _SATISFIED_ENVELOPE, transport
    )

    assert record["state"] == "indeterminate"
    assert "context" in str(record["verdict"]) or any(
        "context" in str(note) for note in record["provenance"]["notes"]  # type: ignore[index]
    )
    assert "prepared" not in _states(record)
    # Cleanup still ran: setup had already created the evidence GPO.
    assert _cleanup_of(record)["ran"] is True


def test_screenshot_evidence_is_anchored_not_cwd_relative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Evidence location is a deployment fact: shots land in the estate's
    evidence directory, never in a CWD-relative ``runs/``."""
    evidence = tmp_path / "evidence"
    cwd = tmp_path / "elsewhere"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    transport = FakeTransport()
    gesture = [
        {"action": "shot", "name": "zzcap"},
        *_commit_crossing_gesture(),
    ]
    record = _run(
        tmp_path,
        _sheet("zz_shot", gesture),
        _SATISFIED_ENVELOPE,
        transport,
        estate=_estate(evidence_dir=str(evidence)),
    )

    assert record["state"] == "verified"
    assert (evidence / "zzcap.png").read_bytes() == b"zz-png"
    assert not (cwd / "runs").exists()


def test_cleanup_runs_every_step_and_flags_absence_violation(tmp_path: Path) -> None:
    """Contract s12: cleanup steps run independently (a failed step never
    skips the rest), and the strict-absence re-query counts exactly the
    recorded GPO by GUID -- residue under that GUID is flagged, unrelated
    GPOs are not."""
    transport = FakeTransport()
    transport.requery_response = "remaining=2\n"

    def boom(script: str, args: list[object]) -> str:
        raise TransportError("scripted transport failure")

    transport.guest_routes.insert(0, (lambda s: "zzfake: mmc_kill" in s, boom))
    record = _run(
        tmp_path, _sheet("zz_cleanup", _commit_crossing_gesture()), _SATISFIED_ENVELOPE, transport
    )

    assert record["state"] == "verified"  # cleanup problems do not flip the verdict
    cleanup = _cleanup_of(record)
    journal = cleanup["journal"]
    assert isinstance(journal, list) and len(journal) == 2
    assert journal[0]["ok"] is False  # the scripted failure...  # type: ignore[index]
    assert journal[1]["ok"] is True  # ...never skipped the GPO removal  # type: ignore[index]
    assert cleanup["evidence_gpo_guid"] == GPO_GUID
    assert cleanup["evidence_gpo_remaining"] == 2
    assert "STRICT ABSENCE VIOLATION" in str(cleanup["note"])
