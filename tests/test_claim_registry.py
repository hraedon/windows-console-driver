"""Guard docs/claim-registry.md against drift from the committed records.

The claim registry is the project's durable product and is hand-maintained;
the transaction records it cites live as committed JSON under
``docs/**/records/`` (the ``runs/`` copies the registry text cites are
gitignored). These tests keep the two honest about each other:

1. Every committed record JSON is referenced in the registry (by filename),
   or is listed in ``UNCLAIMED_RECORDS`` with a one-line stated reason.
2. Every record JSON filename the registry cites resolves to a committed
   record file — catching registry rows pointing at evidence that was never
   committed.

Matching is deliberately a filename substring check over the registry text:
the point is reviewability, not parsing markdown tables.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = REPO_ROOT / "docs"
REGISTRY_PATH = DOCS_DIR / "claim-registry.md"

# Committed record files with deliberately no registry row. Key: record
# filename; value: one-line stated reason. An unclaimed record must say why
# it is unclaimed — that statement is part of the registry discipline.
UNCLAIMED_RECORDS: dict[str, str] = {
    "r3-record.json": (
        "indeterminate under current envelope semantics; no claim banked; "
        "see NOTES.md correction"
    ),
}

_JSON_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.json")


def _committed_record_files() -> dict[str, Path]:
    """All committed record JSONs under docs/**/records/, keyed by filename."""
    return {path.name: path for path in sorted(DOCS_DIR.glob("**/records/*.json"))}


def test_registry_text_is_present() -> None:
    assert REGISTRY_PATH.is_file(), f"missing registry file: {REGISTRY_PATH}"


def test_every_committed_record_is_claimed_or_declared_unclaimed() -> None:
    registry_text = REGISTRY_PATH.read_text(encoding="utf-8")
    records = _committed_record_files()
    assert records, "no committed record JSONs found under docs/**/records/"

    unaccounted = [
        filename
        for filename in records
        if filename not in registry_text and filename not in UNCLAIMED_RECORDS
    ]
    assert not unaccounted, (
        f"committed records with no registry reference and no UNCLAIMED_RECORDS "
        f"entry: {sorted(unaccounted)}"
    )


def test_unclaimed_reasons_are_stated() -> None:
    for filename, reason in UNCLAIMED_RECORDS.items():
        assert reason.strip(), f"UNCLAIMED_RECORDS entry for {filename} lacks a reason"


def test_unclaimed_entries_point_at_committed_records() -> None:
    records = _committed_record_files()
    stale = sorted(set(UNCLAIMED_RECORDS) - set(records))
    assert not stale, f"UNCLAIMED_RECORDS entries with no committed file: {stale}"


def test_every_registry_cited_record_exists() -> None:
    registry_text = REGISTRY_PATH.read_text(encoding="utf-8")
    records = _committed_record_files()
    cited = set(_JSON_FILENAME.findall(registry_text))
    assert cited, "no record filenames found in the registry text"

    missing = sorted(name for name in cited if name not in records)
    assert not missing, (
        f"registry cites record JSONs with no committed copy under "
        f"docs/**/records/: {missing}"
    )
