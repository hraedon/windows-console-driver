"""Transport-typed observers: the Python side of the R2 GPO observation set.

A :class:`Transport` is any callable that runs a named snippet (see
:mod:`gpo_observers.psl`) in the guest and returns its parsed JSON envelope.
The observers here are pure Python: they validate envelope shapes, type and
normalize the values, and produce fact dictionaries. Parsing semantics --
scripts.ini, GPT.INI -- never happens in the guest.

The transport is injectable. :class:`FileTransport` serves the
filesystem-backed snippets (``scripts_ini_raw``, ``sysvol_tree_fingerprint``)
from a local fixture directory, so parsing and fingerprint logic are testable
without a guest; anything else is delegated to a fallback transport
(tests script the AD-backed snippets) or refused.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from . import scripts_ini, version_packing
from .facts import JSONValue

SNIPPET_GPO_IDENTITY = "gpo_identity"
SNIPPET_SYSVOL_TREE_FINGERPRINT = "sysvol_tree_fingerprint"
SNIPPET_AD_ATTRIBUTES = "ad_attributes"
SNIPPET_VERSION_VALUES = "version_values"
SNIPPET_SCRIPTS_INI_RAW = "scripts_ini_raw"
SNIPPET_SCOPE_FORBID = "scope_forbid"

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


class CollectionError(RuntimeError):
    """Raised when a transport response violates its contract or fails."""


class Transport(Protocol):
    """Runs a named snippet in the guest and returns its parsed envelope."""

    def __call__(
        self, snippet: str, params: Mapping[str, JSONValue]
    ) -> dict[str, JSONValue]: ...


def normalize_guid(guid: str) -> str:
    """Validate a GUID and return it in canonical braced-free upper form."""
    stripped = guid.strip().strip("{}").strip("()")
    if _GUID_RE.match(stripped) is None:
        raise CollectionError(f"not a GUID: {guid!r}")
    return stripped.upper()


def _envelope_data(snippet: str, raw: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
    ok = raw.get("ok")
    if not isinstance(ok, bool):
        raise CollectionError(f"{snippet}: envelope field 'ok' must be a boolean")
    if not ok:
        error = raw.get("error")
        detail = error if isinstance(error, str) else repr(error)
        raise CollectionError(f"{snippet}: guest reported an error: {detail}")
    data = raw.get("data")
    if not isinstance(data, dict):
        raise CollectionError(f"{snippet}: envelope field 'data' must be an object")
    return data


def _require_str(data: Mapping[str, JSONValue], key: str, snippet: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise CollectionError(f"{snippet}: field {key!r} must be a non-empty string")
    return value


def _optional_str(data: Mapping[str, JSONValue], key: str, snippet: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise CollectionError(f"{snippet}: field {key!r} must be a string or null")
    return value


def _optional_int(data: Mapping[str, JSONValue], key: str, snippet: str) -> int | None:
    value = data.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise CollectionError(f"{snippet}: field {key!r} must be an integer or null")
    return value


def _require_bool(data: Mapping[str, JSONValue], key: str, snippet: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise CollectionError(f"{snippet}: field {key!r} must be a boolean")
    return value


def _str_list(data: Mapping[str, JSONValue], key: str, snippet: str) -> list[str]:
    value = data.get(key)
    if not isinstance(value, list):
        raise CollectionError(f"{snippet}: field {key!r} must be an array of strings")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise CollectionError(f"{snippet}: field {key!r} must contain non-empty strings")
        items.append(item)
    return items


def _decode_b64(value: str, snippet: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as error:
        raise CollectionError(f"{snippet}: invalid base64 payload") from error


# ---------------------------------------------------------------------------
# gpo_identity
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GpoIdentity:
    gpo_guid: str
    domain_dns: str


def observe_identity(transport: Transport, *, gpo_guid: str, domain_dns: str) -> GpoIdentity:
    params: dict[str, JSONValue] = {"gpo_guid": gpo_guid, "domain_dns": domain_dns}
    data = _envelope_data(
        SNIPPET_GPO_IDENTITY, transport(SNIPPET_GPO_IDENTITY, params)
    )
    reported = _require_str(data, "gpo_guid", SNIPPET_GPO_IDENTITY)
    dns = _require_str(data, "domain_dns", SNIPPET_GPO_IDENTITY)
    normalize_guid(reported)
    return GpoIdentity(gpo_guid=reported, domain_dns=dns)


# ---------------------------------------------------------------------------
# sysvol_tree_fingerprint
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FileFingerprint:
    relpath: str
    sha256: str
    bytes: int


@dataclass(frozen=True, slots=True)
class SysvolFingerprint:
    files: tuple[FileFingerprint, ...]
    passes_match: bool


def observe_sysvol_fingerprint(transport: Transport, *, sysvol_path: str) -> SysvolFingerprint:
    data = _envelope_data(
        SNIPPET_SYSVOL_TREE_FINGERPRINT,
        transport(SNIPPET_SYSVOL_TREE_FINGERPRINT, {"sysvol_path": sysvol_path}),
    )
    raw_files = data.get("files")
    if not isinstance(raw_files, list):
        raise CollectionError(f"{SNIPPET_SYSVOL_TREE_FINGERPRINT}: field 'files' must be an array")
    files: list[FileFingerprint] = []
    for item in raw_files:
        if not isinstance(item, dict):
            raise CollectionError(
                f"{SNIPPET_SYSVOL_TREE_FINGERPRINT}: 'files' entries must be objects"
            )
        relpath = item.get("relpath")
        sha256 = item.get("sha256")
        size = item.get("bytes")
        if (
            not isinstance(relpath, str)
            or not relpath
            or "\\" in relpath
            or relpath.startswith("/")
        ):
            raise CollectionError(
                f"{SNIPPET_SYSVOL_TREE_FINGERPRINT}: relpath must be non-empty and posix-normalized"
            )
        if not isinstance(sha256, str) or _SHA256_HEX_RE.match(sha256) is None:
            raise CollectionError(
                f"{SNIPPET_SYSVOL_TREE_FINGERPRINT}: sha256 must be lowercase hex of length 64"
            )
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise CollectionError(f"{SNIPPET_SYSVOL_TREE_FINGERPRINT}: bytes must be a size")
        files.append(FileFingerprint(relpath=relpath, sha256=sha256, bytes=size))
    passes_match = _require_bool(data, "passes_match", SNIPPET_SYSVOL_TREE_FINGERPRINT)
    return SysvolFingerprint(files=tuple(files), passes_match=passes_match)


# ---------------------------------------------------------------------------
# ad_attributes
# ---------------------------------------------------------------------------

AD_ATTRIBUTE_NAMES: tuple[str, ...] = (
    "gPCMachineExtensionNames",
    "gPCUserExtensionNames",
    "versionNumber",
    "gPCFunctionalityVersion",
    "flags",
    "whenChanged",
    "uSNChanged",
)
_AD_INT_ATTRIBUTES: frozenset[str] = frozenset(
    {"versionNumber", "gPCFunctionalityVersion", "flags"}
)


def observe_ad_attributes(
    transport: Transport, *, gpo_guid: str, server: str = ""
) -> dict[str, str | int | None]:
    params: dict[str, JSONValue] = {"gpo_guid": gpo_guid}
    if server:
        params["server"] = server
    data = _envelope_data(SNIPPET_AD_ATTRIBUTES, transport(SNIPPET_AD_ATTRIBUTES, params))
    values: dict[str, str | int | None] = {}
    for name in AD_ATTRIBUTE_NAMES:
        if name not in data:
            raise CollectionError(f"{SNIPPET_AD_ATTRIBUTES}: missing attribute {name!r}")
        value = data[name]
        if value is None:
            values[name] = None
        elif name in _AD_INT_ATTRIBUTES:
            if isinstance(value, bool) or not isinstance(value, int):
                raise CollectionError(f"{SNIPPET_AD_ATTRIBUTES}: attribute {name!r} must be an int")
            values[name] = value
        elif not isinstance(value, str):
            raise CollectionError(f"{SNIPPET_AD_ATTRIBUTES}: attribute {name!r} must be a string")
        else:
            values[name] = value
    return values


# ---------------------------------------------------------------------------
# version_values
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VersionValues:
    gpt_version_raw: str | None
    version: int | None
    machine: int | None
    user: int | None
    display_name: str | None
    ad_version_number: int | None


def observe_version_values(
    transport: Transport, *, gpt_ini_path: str, gpo_guid: str, server: str = ""
) -> VersionValues:
    params: dict[str, JSONValue] = {"gpt_ini_path": gpt_ini_path, "gpo_guid": gpo_guid}
    if server:
        params["server"] = server
    data = _envelope_data(SNIPPET_VERSION_VALUES, transport(SNIPPET_VERSION_VALUES, params))
    gpt_b64 = _optional_str(data, "gpt_ini_b64", SNIPPET_VERSION_VALUES)
    gpt_version_raw = _optional_str(data, "gpt_version_raw", SNIPPET_VERSION_VALUES)
    ad_version = _optional_int(data, "ad_version_number", SNIPPET_VERSION_VALUES)
    gpt = version_packing.GptIni(
        general_present=False, version_raw=None, version=None, display_name=None
    )
    if gpt_b64 is not None:
        text, _kind, _width = version_packing.decode_gpt_ini_bytes(
            _decode_b64(gpt_b64, SNIPPET_VERSION_VALUES)
        )
        try:
            gpt = version_packing.parse_gpt_ini_text(text)
        except ValueError as error:
            raise CollectionError(f"{SNIPPET_VERSION_VALUES}: {error}") from error
    if gpt_version_raw is not None and gpt.version_raw != gpt_version_raw:
        raise CollectionError(
            f"{SNIPPET_VERSION_VALUES}: guest-side Version {gpt_version_raw!r} does not "
            f"match the GPT.INI payload ({gpt.version_raw!r})"
        )
    machine: int | None = None
    user: int | None = None
    if gpt.version is not None:
        try:
            machine, user = version_packing.unpack(gpt.version)
        except ValueError as error:
            raise CollectionError(f"{SNIPPET_VERSION_VALUES}: {error}") from error
    return VersionValues(
        gpt_version_raw=gpt.version_raw,
        version=gpt.version,
        machine=machine,
        user=user,
        display_name=gpt.display_name,
        ad_version_number=ad_version,
    )


# ---------------------------------------------------------------------------
# scripts_ini_raw
# ---------------------------------------------------------------------------


def observe_scripts_ini(
    transport: Transport, *, scripts_dir: str, side: str
) -> dict[str, JSONValue]:
    """Fetch both scripts INIs as bytes and parse them into fact values.

    *side* is ``"machine"`` or ``"user"`` and only names the fact-key
    segment; the guest decides which directory to read from *scripts_dir*.
    """
    if side not in ("machine", "user"):
        raise ValueError(f"side must be 'machine' or 'user', got {side!r}")
    data = _envelope_data(
        SNIPPET_SCRIPTS_INI_RAW,
        transport(SNIPPET_SCRIPTS_INI_RAW, {"scripts_dir": scripts_dir}),
    )
    facts: dict[str, JSONValue] = {}
    scripts_b64 = _optional_str(data, "scripts_ini_b64", SNIPPET_SCRIPTS_INI_RAW)
    ps_b64 = _optional_str(data, "psscripts_ini_b64", SNIPPET_SCRIPTS_INI_RAW)
    if scripts_b64 is None:
        facts.update(scripts_ini.absent_scripts_ini_facts(side=side))
    else:
        document = scripts_ini.parse_scripts_ini(_decode_b64(scripts_b64, SNIPPET_SCRIPTS_INI_RAW))
        facts.update(scripts_ini.scripts_ini_facts(document, side=side))
    if ps_b64 is None:
        facts.update(scripts_ini.absent_psscripts_ini_facts(side=side))
    else:
        document = scripts_ini.parse_scripts_ini(_decode_b64(ps_b64, SNIPPET_SCRIPTS_INI_RAW))
        facts.update(scripts_ini.psscripts_ini_facts(document, side=side))
    return facts


# ---------------------------------------------------------------------------
# scope_forbid
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScopeFacts:
    extension_list_machine: str | None
    extension_list_user: str | None
    policies_gpc_guids: tuple[str, ...]
    sysvol_relpaths: tuple[str, ...]


def observe_scope(
    transport: Transport, *, gpo_guid: str, domain_dns: str, sysvol_gpo_path: str
) -> ScopeFacts:
    params: dict[str, JSONValue] = {
        "gpo_guid": gpo_guid,
        "domain_dns": domain_dns,
        "sysvol_gpo_path": sysvol_gpo_path,
    }
    data = _envelope_data(SNIPPET_SCOPE_FORBID, transport(SNIPPET_SCOPE_FORBID, params))
    machine = _optional_str(data, "extension_list_machine", SNIPPET_SCOPE_FORBID)
    user = _optional_str(data, "extension_list_user", SNIPPET_SCOPE_FORBID)
    # The controller re-sorts canonically; the guest's ordinal sort is a
    # convenience, not the authority.
    guids = sorted(_str_list(data, "policies_gpc_guids", SNIPPET_SCOPE_FORBID))
    relpaths = sorted(_str_list(data, "sysvol_relpaths", SNIPPET_SCOPE_FORBID))
    return ScopeFacts(
        extension_list_machine=machine,
        extension_list_user=user,
        policies_gpc_guids=tuple(guids),
        sysvol_relpaths=tuple(relpaths),
    )


# ---------------------------------------------------------------------------
# FileTransport: the no-guest test transport
# ---------------------------------------------------------------------------


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


class FileTransport:
    """Serves the filesystem-backed snippets from a local fixture tree.

    *gpo_root* stands in for the GPO's SYSVOL directory: ``scripts_ini_raw``
    is served from ``<root>\\<side>\\Scripts`` (the side is read from the
    requested directory name), and ``sysvol_tree_fingerprint`` enumerates the
    whole tree with the same two independent passes the PowerShell snippet
    uses -- a pathlib provider-style pass and an ``os.walk`` .NET-style pass
    -- and compares them in-transport. Any other snippet is delegated to
    *fallback* (tests script the AD-backed snippets) or refused.
    """

    def __init__(self, gpo_root: Path, *, fallback: Transport | None = None) -> None:
        self._gpo_root = gpo_root
        self._fallback = fallback

    def __call__(
        self, snippet: str, params: Mapping[str, JSONValue]
    ) -> dict[str, JSONValue]:
        if snippet == SNIPPET_SCRIPTS_INI_RAW:
            return self._serve_scripts_ini_raw(params)
        if snippet == SNIPPET_SYSVOL_TREE_FINGERPRINT:
            return self._serve_fingerprint()
        if self._fallback is not None:
            return self._fallback(snippet, params)
        raise CollectionError(f"FileTransport cannot serve snippet {snippet!r}")

    def _serve_scripts_ini_raw(self, params: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
        scripts_dir = params.get("scripts_dir")
        # Side detection looks at the tail of the requested directory only
        # ("<side>\Scripts"), never at the whole path: a host path such as
        # C:\Users\... must not flip the side.
        side = "machine"
        if isinstance(scripts_dir, str):
            folded_tail = scripts_dir.replace("/", "\\").casefold().rstrip("\\")
            if folded_tail.endswith("user\\scripts"):
                side = "user"
        base = self._gpo_root / side.capitalize() / "Scripts"
        return {
            "ok": True,
            "data": {
                "scripts_ini_b64": self._b64_or_none(base / "scripts.ini"),
                "psscripts_ini_b64": self._b64_or_none(base / "psscripts.ini"),
            },
        }

    @staticmethod
    def _b64_or_none(path: Path) -> str | None:
        if not path.is_file():
            return None
        return base64.b64encode(path.read_bytes()).decode("ascii")

    def _serve_fingerprint(self) -> dict[str, JSONValue]:
        root = self._gpo_root
        # Pass 1 mirrors the PowerShell provider pass (pathlib recursion).
        pass_one: dict[str, tuple[str, int]] = {}
        for path in sorted(root.rglob("*")):
            if path.is_file():
                relpath = path.relative_to(root).as_posix()
                pass_one[relpath] = (_sha256_of(path), path.stat().st_size)
        # Pass 2 mirrors the .NET enumeration pass (os.walk + explicit reads).
        pass_two: dict[str, tuple[str, int]] = {}
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            filenames.sort()
            for name in filenames:
                full = Path(dirpath) / name
                relpath = full.relative_to(root).as_posix()
                pass_two[relpath] = (_sha256_of(full), full.stat().st_size)
        files: list[JSONValue] = [
            {"relpath": relpath, "sha256": entry[0], "bytes": entry[1]}
            for relpath, entry in sorted(pass_one.items())
        ]
        return {
            "ok": True,
            "data": {
                "files": files,
                "passes_match": pass_one == pass_two,
                "pass_one_count": len(pass_one),
                "pass_two_count": len(pass_two),
            },
        }
