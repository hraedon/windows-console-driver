"""The independence rule, enforced: gpo_observers imports stdlib only.

Scans every module under src/gpo_observers with ast and fails on any import
outside the standard library or the package itself. gpo_studio and wcd are
named explicitly so a violation explains itself. The comparison with
gpo_studio lives only in tests (see test_gpo_observers_crosscheck.py); the
implementation must never import the product.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parents[1] / "src" / "gpo_observers"
BANNED_ROOTS = {"gpo_studio", "wcd", "windows_console_driver", "tests"}


def _imported_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                roots.add("gpo_observers")
            elif node.module:
                roots.add(node.module.split(".")[0])
    return roots


def _package_modules() -> list[Path]:
    return sorted(PACKAGE_DIR.rglob("*.py"))


def test_package_modules_exist_and_are_scanned() -> None:
    modules = _package_modules()
    names = {path.name for path in modules}
    # Guard against a vacuous pass: the R2 set must actually be present.
    assert {
        "__init__.py",
        "facts.py",
        "scripts_ini.py",
        "version_packing.py",
        "psl.py",
        "collection.py",
        "snapshots.py",
        "delta.py",
    } <= names


def test_every_import_is_stdlib_or_self() -> None:
    for path in _package_modules():
        roots = _imported_roots(path)
        offenders = sorted(
            root
            for root in roots
            if root not in sys.stdlib_module_names and root != "gpo_observers"
        )
        assert not offenders, f"{path.name} imports non-stdlib modules: {offenders}"


def test_product_packages_are_never_imported() -> None:
    for path in _package_modules():
        roots = _imported_roots(path)
        banned = roots & BANNED_ROOTS
        assert not banned, f"{path.name} imports banned modules: {banned}"


def test_package_imports_are_actually_scanned() -> None:
    # The scan must see real imports, not an empty set everywhere.
    scanned = {path.name: _imported_roots(path) for path in _package_modules()}
    assert any("gpo_observers" in roots for roots in scanned.values())
    assert scanned["collection.py"] - {"gpo_observers"} >= {"base64", "hashlib"}
    assert "re" in scanned["scripts_ini.py"]
    assert scanned["facts.py"] - {"gpo_observers"} >= {"fnmatch", "math"}
