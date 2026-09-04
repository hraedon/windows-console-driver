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
from gpo_observers.facts import Fact
from gpo_observers.snapshots import GpoRef, capture_snapshot
from wcd.envelope import compile_predicate, parse_envelope

REPO_ROOT = Path(__file__).resolve().parent.parent

# Every shipped scripts-family capability spec. New specs join this tuple:
# the parametrization is the whole extension -- no per-spec test bodies.
CAPABILITIES: tuple[Path, ...] = (
    REPO_ROOT / "capabilities" / "gpmc.author_scripts_entry.json",
    REPO_ROOT / "capabilities" / "gpmc.author_scripts_ps_order.json",
)


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
    assert envelope.convergence.window_seconds == 90
    for source in _predicate_sources(_capability(capability_path)["envelope"]):
        compile_predicate(source)


def _fixture_snapshot() -> dict[str, Fact]:
    """One capture_snapshot over the fixture estate, AD snippets scripted."""
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
    return capture_snapshot(transport, gpo)


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
    structural_prefixes = (
        "scripts_ini.",
        "version.",
        "ad.",
        "scope.",
        "gpo_identity.",
        "sysvol.passes_match",
    )
    for key in sorted(fact_keys):
        assert key.startswith(structural_prefixes), (
            f"{key!r} is outside the declared observer vocabulary"
        )
