"""Read committed IIS configuration and compare history without an estate channel.

Missing attributes are unknown, not schema defaults. These are file observations,
not effective IIS configuration and not a new v0 console capability.
"""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

_HISTORY = re.compile(r"CFGHISTORY_[0-9]+")
_AUTH = "system.webServer/security/authentication/windowsAuthentication"
_ACCESS = "system.webServer/security/access"


class IisEvidenceError(ValueError):
    """The committed file cannot support an unambiguous observation."""


def _root(payload: bytes) -> ET.Element:
    if len(payload) > 16 * 1024 * 1024:
        raise IisEvidenceError("config exceeds the 16 MiB read limit")
    try:
        # Inspect XML declarations even in UTF-16 files before using ElementTree.
        text = payload.decode(
            "utf-16" if payload.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
        )
        if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
            raise IisEvidenceError("DTD/entity declarations are not supported")
        root = ET.fromstring(payload)
    except (UnicodeError, ET.ParseError) as exc:
        raise IisEvidenceError("invalid applicationHost.config XML") from exc
    if root.tag != "configuration":
        raise IisEvidenceError("expected a configuration root")
    return root


def _one(root: ET.Element, path: str) -> ET.Element | None:
    matches = root.findall(path)
    if len(matches) > 1:
        raise IisEvidenceError(f"ambiguous config element: {path}")
    return matches[0] if matches else None


def _boolean(value: str | None) -> bool | None:
    if value is None:
        return None
    if value.lower() not in {"true", "false"}:
        raise IisEvidenceError("invalid enabled boolean")
    return value.lower() == "true"


def _security(scope: ET.Element) -> dict[str, Any]:
    auth = _one(scope, _AUTH)
    protection = _one(scope, _AUTH + "/extendedProtection")
    access = _one(scope, _ACCESS)
    providers = _one(scope, _AUTH + "/providers")
    token = protection.get("tokenChecking") if protection is not None else None
    if token is not None and token not in {"None", "Allow", "Require"}:
        raise IisEvidenceError("tokenChecking must be None, Allow, or Require")
    flags = access.get("sslFlags") if access is not None else None
    values = [v.strip() for v in flags.split(",")] if flags is not None else None
    if values is not None and any(
        v
        not in {
            "None",
            "Ssl",
            "SslNegotiateCert",
            "SslRequireCert",
            "SslMapCert",
            "Ssl128",
        }
        for v in values
    ):
        raise IisEvidenceError("unrecognized sslFlags; preserve as an unread observation")
    return {
        "token_checking": token,
        "ssl_flags": values,
        "enabled": _boolean(auth.get("enabled") if auth is not None else None),
        # Preserve clear/remove and ordering: an add-only list can imply a
        # provider that an inherited clear/remove actually excludes.
        "provider_operations": [dict(operation=child.tag, **child.attrib) for child in providers]
        if providers is not None
        else None,
    }


def lock_state(root: ET.Element, section: str, location: str) -> dict[str, Any]:
    if section not in {_AUTH, _ACCESS}:
        raise IisEvidenceError("unsupported security section")
    groups = section.split("/")
    node = _one(root, "configSections")
    for group in groups[:-1]:
        if node is not None:
            node = _one(node, f"sectionGroup[@name='{group}']")
    definition = _one(node, f"section[@name='{groups[-1]}']") if node is not None else None
    mode = definition.get("overrideModeDefault") if definition is not None else None
    source = "configSections" if mode else None
    for scope in sorted(root.findall("location"), key=lambda e: len(e.get("path", ""))):
        path = scope.get("path", "")
        applies = (
            path == "."
            or path.lower() == location.lower()
            or location.lower().startswith(path.lower() + "/")
        )
        if (applies and scope.find(section) is not None
                and scope.get("overrideMode") in {"Allow", "Deny"}):
            mode, source = scope.get("overrideMode"), f"location:{path}"
    return {
        "section": section,
        "override_mode": mode,
        "source": source,
        "app_scope_locked": mode == "Deny" if mode is not None else None,
        "write_target": "MACHINE/WEBROOT/APPHOST + Location",
    }


def read_config(payload: bytes, locations: list[str]) -> dict[str, Any]:
    root = _root(payload)
    result: dict[str, Any] = {
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "provenance": "committed applicationHost.config",
        "locations": {},
    }
    if not locations or len({p.lower() for p in locations}) != len(locations):
        raise IisEvidenceError("locations must be nonempty and distinct")
    for location in locations:
        if not location or "'" in location:
            raise IisEvidenceError("invalid location")
        scopes = [
            s for s in root.findall("location") if s.get("path", "").lower() == location.lower()
        ]
        if len(scopes) > 1:
            raise IisEvidenceError("duplicate location")
        result["locations"][location] = {
            "apphost_global": _security(root),
            "apphost_location": _security(scopes[0]) if scopes else None,
            "lock_state": [lock_state(root, section, location) for section in (_AUTH, _ACCESS)],
        }
    return result


def config_history(
    live: Path, history: Path, locations: list[str], diff: str | None
) -> dict[str, Any]:
    paths = {"live": live}
    if not history.is_dir():
        raise IisEvidenceError("history directory is unavailable")
    for child in sorted(history.iterdir()):
        if _HISTORY.fullmatch(child.name) and child.is_dir() and not child.is_symlink():
            paths[child.name] = child / "applicationHost.config"
    observations: dict[str, Any] = {}
    for name, path in paths.items():
        try:
            # Digest the same bytes used for the typed observation.
            payload = path.read_bytes()
            observations[name] = {
                **read_config(payload, locations),
                "mtime_ns": path.stat().st_mtime_ns,
            }
        except (OSError, IisEvidenceError):
            observations[name] = {"error": "unreadable_config"}
    result: dict[str, Any] = {"schema_version": 1, "observations": observations}
    if diff is not None:
        if diff not in observations:
            raise IisEvidenceError("diff target must be live or an enumerated snapshot name")
        reference = observations[diff]
        result["diff_reference"] = diff
        result["diffs"] = {
            name: {
                "bytes_equal": value["sha256"] == reference["sha256"],
                "locations_equal": value["locations"] == reference["locations"],
                "expected_sha256": reference["sha256"],
                "actual_sha256": value["sha256"],
            }
            if "error" not in value and "error" not in reference
            else {"error": "unreadable_config"}
            for name, value in observations.items()
        }
    return result
