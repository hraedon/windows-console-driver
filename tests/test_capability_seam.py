"""Capability-spec seam: every shipped capability must speak the vocabularies.

Pins the three-way agreement between the shipped ``capabilities/*.json``
scripts specs, the :mod:`wcd.envelope` bounded expression engine, and the fact
keys :mod:`gpo_observers` actually emits. If an observer fact key changes
name, or a predicate drifts out of the bounded expression subset, this test
fails before a transaction ever runs. (The executor parses the envelope only
after the gesture phase, so an unpinned predicate error would abort an estate
run post-commit with no record -- the seam exists to make that unreachable.)
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from gpo_observers.collection import FileTransport
from gpo_observers.facts import Fact, make_fact
from gpo_observers.fdeploy_ini import fdeploy_fact_tree
from gpo_observers.gpttmpl_inf import gpttmpl_fact_tree
from gpo_observers.snapshots import GpoRef, capture_snapshot
from wcd.envelope import compile_predicate, parse_envelope

REPO_ROOT = Path(__file__).resolve().parent.parent

# The directory is the extension point: every shipped capability participates.
CAPABILITIES = tuple(sorted((REPO_ROOT / "capabilities").glob("*.json")))


def _capability(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _predicate_sources(envelope: Mapping[str, Any]) -> list[str]:
    sources = [clause["predicate"] for clause in envelope["require"]]
    sources += [clause["predicate"] for clause in envelope["forbid"]]
    sources += [clause["relation"] for clause in envelope["derive"]]
    return sources


@pytest.mark.parametrize("capability_path", CAPABILITIES, ids=lambda p: p.stem)
def test_capability_envelope_parses_with_the_bounded_evaluator(capability_path: Path) -> None:
    """Every predicate/relation string in each shipped capability compiles
    under the AST-whitelisted evaluator (contract section 3: no eval/exec)."""
    envelope = parse_envelope(_capability(capability_path)["envelope"])
    assert envelope.convergence.window_seconds > 0
    assert envelope.convergence.reproduce >= 2
    for source in _predicate_sources(_capability(capability_path)["envelope"]):
        compile_predicate(source)


def _fixture_snapshot() -> dict[str, Fact]:
    """Observer vocabulary over synthetic and banked byte fixtures."""
    fixture_root = REPO_ROOT / "tests" / "fixtures" / "gpo-tree"
    gpo = GpoRef(
        gpo_guid="11111111-2222-3333-4444-555555555555",
        domain_dns="ad.labdomain.dev",
        sysvol_path=fixture_root / "11111111-2222-3333-4444-555555555555",
    )

    def fallback(snippet: str, params: Mapping[str, Any]) -> dict[str, Any]:
        # Minimal scripted AD-backed snippets: the fixture GPO's identity and
        # version values, empty extension lists, one-GPC container.
        guid = gpo.gpo_guid
        if snippet == "gpo_identity":
            return {"ok": True, "data": {"gpo_guid": guid, "domain_dns": gpo.domain_dns}}
        if snippet == "ad_attributes":
            values: dict[str, Any] = {
                "gPCMachineExtensionNames": "",
                "gPCUserExtensionNames": "",
                "versionNumber": 65537,
                "gPCFunctionalityVersion": None,
                "flags": None,
                "whenChanged": None,
                "uSNChanged": None,
            }
            return {"ok": True, "data": values}
        if snippet == "version_values":
            gpt_bytes = (gpo.sysvol_path / "GPT.INI").read_bytes()
            return {
                "ok": True,
                "data": {
                    "gpt_ini_b64": base64.b64encode(gpt_bytes).decode("ascii"),
                    "gpt_version_raw": "65537",
                    "ad_version_number": 65537,
                },
            }
        if snippet == "scope_forbid":
            return {
                "ok": True,
                "data": {
                    "extension_list_machine": "",
                    "extension_list_user": "",
                    "policies_gpc_guids": [guid],
                    "sysvol_relpaths": [f"{{{guid}}}/GPT.INI"],
                },
            }
        raise AssertionError(f"unexpected snippet {snippet!r}")

    transport = FileTransport(gpo.sysvol_path, fallback=fallback)
    snapshot = capture_snapshot(transport, gpo)

    def add_tree(prefix: str, tree: Mapping[str, Any]) -> None:
        def walk(path: str, value: object) -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    walk(f"{path}.{key}", item)
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    walk(f"{path}.{index}", item)
            else:
                fact = make_fact(path, value)
                snapshot[fact.key] = fact

        for key, value in tree.items():
            walk(f"{prefix}.{key}", value)
        present = make_fact(f"{prefix}.present", True)
        snapshot[present.key] = present

    bytes_root = REPO_ROOT / "tests" / "fixtures" / "r3-r4"
    add_tree("fdeploy", fdeploy_fact_tree((bytes_root / "fdeploy1.ini").read_bytes()))
    add_tree(
        "fdeploy_marker",
        fdeploy_fact_tree((bytes_root / "fdeploy-marker.ini").read_bytes()),
    )
    add_tree("gpttmpl", gpttmpl_fact_tree((bytes_root / "GptTmpl.inf").read_bytes()))

    # The migration-table collector is transport-backed inside the executor;
    # the native-v1 banked record is its immutable observed fixture.
    migration_record = json.loads(
        (
            REPO_ROOT
            / "docs"
            / "estate-window-4"
            / "records"
            / "r1-v1-record.json"
        ).read_text(encoding="utf-8")
    )
    for entry in migration_record["envelope_result"]["delta"]:
        if entry["key"].startswith("migtable."):
            fact = make_fact(entry["key"], entry["after"])
            snapshot[fact.key] = fact
    return snapshot


@pytest.mark.parametrize("capability_path", CAPABILITIES, ids=lambda p: p.stem)
def test_capability_fact_keys_exist_in_a_real_snapshot(capability_path: Path) -> None:
    """Every fact key a predicate references (args.* excepted) is emitted by
    capture_snapshot against the fixture estate -- the observers and the
    capability cannot drift apart silently."""
    snapshot = _fixture_snapshot()

    referenced: set[str] = set()
    for source in _predicate_sources(_capability(capability_path)["envelope"]):
        referenced |= set(compile_predicate(source).referenced_paths())
    for path in sorted(referenced):
        namespace, _, fact_key = path.partition(".")
        if namespace in ("pre", "post"):
            assert fact_key in snapshot, f"predicate references unknown fact {fact_key!r}"
        elif namespace in ("args", "scope", "scope_key", "facts"):
            # args: capability parameters bound at runtime; scope/scope_key:
            # clause-local bindings the engine provides per contract section 3;
            # facts: post-side alias.
            continue
        else:
            raise AssertionError(f"unexpected predicate namespace {namespace!r}")


@pytest.mark.parametrize("capability_path", CAPABILITIES, ids=lambda p: p.stem)
def test_require_and_forbid_reference_declared_structural_or_content_facts(
    capability_path: Path,
) -> None:
    """No predicate may reference an unclassified fact key: the envelope's
    force comes from the observers' declared category table."""
    capability = _capability(capability_path)
    referenced: set[str] = set()
    for source in _predicate_sources(capability["envelope"]):
        referenced |= set(compile_predicate(source).referenced_paths())
    fact_keys = {
        path.partition(".")[2]
        for path in referenced
        if path.partition(".")[0] in ("pre", "post")
    }
    for key in sorted(fact_keys):
        assert make_fact(key, None).category != "unclassified", (
            f"{key!r} is outside the declared observer vocabulary"
        )
