"""gpt.ini / AD versionNumber unpacking.

``GPT.INI`` carries ``Version=`` in its ``[General]`` section: a packed
32-bit field in which the **user** version increments the upper 16 bits and
the **machine** version the lower 16::

    machine = version & 0xFFFF
    user    = (version >> 16) & 0xFFFF

The same packing applies to the GPC's ``versionNumber`` attribute in AD.
``unpack`` is the single authority for the split in this package, and
``pack`` is its inverse (used by tests and synthetic fixtures).

The module also parses GPT.INI text: the ``[General]`` section, the
``Version=`` key, and ``displayName=`` when present. ``displayName`` is a
known identifier that evidence handling must strip before sharing, so the
fact it produces is explicitly category ``identity``.

BOM handling here is implemented independently of
:mod:`gpo_observers.scripts_ini` on purpose: the observer modules share no
parsing code with each other, only the Fact model.
"""

from __future__ import annotations

from dataclasses import dataclass

from .facts import JSONValue

VERSION_MASK = 0xFFFFFFFF
HALF_MASK = 0xFFFF

BOM_UTF16LE: bytes = b"\xff\xfe"
BOM_UTF16BE: bytes = b"\xfe\xff"
BOM_UTF8: bytes = b"\xef\xbb\xbf"


def unpack(version: int) -> tuple[int, int]:
    """Split a packed version into ``(machine, user)`` halves.

    Raises ``ValueError`` for anything outside the 32-bit unsigned range.
    """
    if version < 0 or version > VERSION_MASK:
        raise ValueError(f"version must fit in 32 unsigned bits, got {version}")
    return (version & HALF_MASK, (version >> 16) & HALF_MASK)


def pack(machine: int, user: int) -> int:
    """Pack ``(machine, user)`` halves into one 32-bit version value."""
    if not 0 <= machine <= HALF_MASK:
        raise ValueError(f"machine version must fit in 16 bits, got {machine}")
    if not 0 <= user <= HALF_MASK:
        raise ValueError(f"user version must fit in 16 bits, got {user}")
    return (user << 16) | machine


@dataclass(frozen=True, slots=True)
class GptIni:
    """The parsed [General] section of a GPT.INI file."""

    general_present: bool
    version_raw: str | None
    version: int | None
    display_name: str | None


def decode_gpt_ini_bytes(data: bytes) -> tuple[str, str, int]:
    """Decode GPT.INI bytes, returning ``(text, bom_kind, bom_width)``.

    GPMC has historically written GPT.INI as UTF-16LE; fixtures and real
    estates also show UTF-8 and plain ASCII. BOM rules: ``FF FE`` ->
    UTF-16LE, ``FE FF`` -> UTF-16BE, ``EF BB BF`` -> UTF-8, no BOM -> UTF-8
    with a ``cp1252`` fallback for undecodable bytes.
    """
    if data.startswith(BOM_UTF16LE):
        return (data.decode("utf-16"), "utf-16le", 2)
    if data.startswith(BOM_UTF16BE):
        return (data.decode("utf-16"), "utf-16be", 2)
    if data.startswith(BOM_UTF8):
        return (data.decode("utf-8-sig"), "utf-8", 3)
    try:
        return (data.decode("utf-8"), "none", 0)
    except UnicodeDecodeError:
        return (data.decode("cp1252"), "none", 0)


def parse_gpt_ini_text(text: str) -> GptIni:
    """Parse GPT.INI text: the [General] section's Version and displayName.

    Keys are matched case-insensitively (GPMC writes ``Version=`` and
    ``displayName=``). If no ``[General]`` section exists -- malformed, but
    still evidence -- the whole file is scanned for a ``Version=`` line.
    A non-numeric ``Version`` value keeps its raw text with ``version=None``.
    """
    general: dict[str, str] = {}
    general_found = False
    in_general = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";") or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_general = line[1:-1].strip().casefold() == "general"
            general_found = general_found or in_general
            continue
        if in_general:
            key, separator, value = line.partition("=")
            if separator:
                general[key.strip().casefold()] = value.strip()
    if not general_found:
        for raw_line in text.splitlines():
            line = raw_line.strip()
            key, separator, value = line.partition("=")
            if separator and key.strip().casefold() == "version":
                general.setdefault("version", value.strip())
                break
    version_raw = general.get("version")
    version: int | None = None
    if version_raw is not None and version_raw.isdigit():
        version = int(version_raw)
    return GptIni(
        general_present=general_found,
        version_raw=version_raw,
        version=version,
        display_name=general.get("displayname"),
    )


def gpt_ini_facts(gpt: GptIni) -> dict[str, JSONValue]:
    """Fact values for a parsed GPT.INI.

    ``version.displayName`` is category ``identity`` -- a known identifier
    that evidence handling must strip -- per the declared table in
    :mod:`gpo_observers.facts`.
    """
    machine: int | None = None
    user: int | None = None
    if gpt.version is not None:
        machine, user = unpack(gpt.version)
    return {
        "version.raw": gpt.version_raw,
        "version.machine": machine,
        "version.user": user,
        "version.displayName": gpt.display_name,
    }
