"""Bytes-level parser for scripts.ini / psscripts.ini -- no Windows needed.

This module answers the R2 evidence questions purely from the bytes a guest
(or a fixture) hands over:

- Encoding: does the file carry a BOM (``FF FE`` UTF-16LE, ``FE FF``
  UTF-16BE, ``EF BB BF`` UTF-8, none), and how wide is it? How many CR and LF
  characters does it contain, and how many bytes total? These are literally
  the recorded questions about what GPMC writes (does it write ``FF FE``?
  CRLF or LF?), so the counts are facts, not an implementation detail.
- Entries: sections are matched case-insensitively; entries are numeric-index
  keys mapping to script lines. Two native key styles are parsed defensively:

  * split style -- ``0CmdLine=`` / ``0Parameters=`` (plus per-entry props
    such as ``ExecutionMode``, ``NoProfile``, ``NonInteractive``), and
  * positional style -- bare ``0=``, ``1=`` keys whose value is a positional
    line, typically ``scriptname,parameters``.

  Either way the raw line is recorded too, so evidence never depends on the
  field split being right.
- Config-section shape (R2 question 3): a ``[Policy]`` section carrying
  RunLogonScriptsSync / RunLogoffScriptsSync / LegacyScriptsFirst /
  PowerShellOrder versus a ``[ScriptsConfig]`` section carrying
  StartExecutePSFirst / EndExecutePSFirst. Which shape is present is recorded
  key-by-key.

The fact keys produced here are the ``scripts_ini.*`` namespace (psscripts
facts under ``scripts_ini.ps.*``); :mod:`gpo_observers.facts` declares their
categories.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .facts import JSONValue

BOM_UTF16LE: bytes = b"\xff\xfe"
BOM_UTF16BE: bytes = b"\xfe\xff"
BOM_UTF8: bytes = b"\xef\xbb\xbf"

POLICY_SECTION_NAME = "policy"
SCRIPTS_CONFIG_SECTION_NAME = "scriptsconfig"
POLICY_MODELED_KEYS: tuple[str, ...] = (
    "RunLogonScriptsSync",
    "RunLogoffScriptsSync",
    "LegacyScriptsFirst",
    "PowerShellOrder",
)
SCRIPTS_CONFIG_MODELED_KEYS: tuple[str, ...] = (
    "StartExecutePSFirst",
    "EndExecutePSFirst",
)

_ENTRY_INDEX_RE = re.compile(r"^(\d+)$")
_ENTRY_PROP_RE = re.compile(r"^(\d+)([A-Za-z][A-Za-z0-9_]*)$")
_SECTION_RE = re.compile(r"^\[([^\]]*)\]$")


@dataclass(frozen=True, slots=True)
class BomFacts:
    """BOM presence and width, as observed in the raw bytes."""

    kind: str  # "utf-16le" | "utf-16be" | "utf-8" | "none"
    width: int  # 0, 2 or 3 bytes


def detect_bom(data: bytes) -> BomFacts:
    """Detect the BOM of *data* from its leading bytes.

    A leading ``FF FE`` is reported as UTF-16LE even though it is also the
    prefix of the UTF-32LE BOM: Windows INI tooling never writes UTF-32, and
    the evidence question is "did the author write FF FE?".
    """
    if data.startswith(BOM_UTF16LE):
        return BomFacts(kind="utf-16le", width=2)
    if data.startswith(BOM_UTF16BE):
        return BomFacts(kind="utf-16be", width=2)
    if data.startswith(BOM_UTF8):
        return BomFacts(kind="utf-8", width=3)
    return BomFacts(kind="none", width=0)


def decode_ini_bytes(data: bytes) -> tuple[str, str | None]:
    """Decode INI bytes honoring the BOM, defensively otherwise.

    Returns ``(text, fallback_codec)``. The fallback codec is ``None`` while
    the declared encoding was authoritative, and ``"cp1252"`` when Windows
    ANSI had to stand in for bytes that are not valid UTF-8 (recorded as a
    fact so the fallback is visible in evidence).
    """
    kind = detect_bom(data).kind
    if kind in ("utf-16le", "utf-16be"):
        return data.decode("utf-16"), None
    if kind == "utf-8":
        return data.decode("utf-8-sig"), None
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return data.decode("cp1252"), "cp1252"


@dataclass(frozen=True, slots=True)
class ScriptEntry:
    """One numeric-index script entry, parsed defensively.

    ``script``/``parameters`` come from whichever native style the line used;
    ``raw_line`` always records the contributing line verbatim so evidence
    does not depend on the field split. ``props`` holds the split-style
    per-entry properties (as written), empty for positional entries.
    """

    index: int
    script: str | None
    parameters: str | None
    raw_line: str
    style: str  # "positional" | "split" | "mixed"
    props: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class IniSection:
    """One INI section: original-case name, entries, non-entry keys."""

    name: str
    entries: tuple[ScriptEntry, ...]
    other_keys: tuple[tuple[str, str], ...]

    def entry(self, index: int) -> ScriptEntry | None:
        for candidate in self.entries:
            if candidate.index == index:
                return candidate
        return None

    def key(self, name: str) -> str | None:
        """Case-insensitive lookup among this section's non-entry keys."""
        folded = name.casefold()
        for key, value in self.other_keys:
            if key.casefold() == folded:
                return value
        return None


@dataclass(frozen=True, slots=True)
class ScriptsIniDocument:
    """The full parse result: encoding facts plus per-section semantics."""

    bom: BomFacts
    cr_count: int
    lf_count: int
    total_bytes: int
    text: str
    fallback_codec: str | None
    sections: tuple[IniSection, ...]
    unparsed_lines: tuple[str, ...]

    def section(self, name: str) -> IniSection | None:
        """Case-insensitive section lookup by name."""
        folded = name.casefold()
        for candidate in self.sections:
            if candidate.name.casefold() == folded:
                return candidate
        return None


def _split_positional(value: str) -> tuple[str | None, str | None]:
    """Split a positional entry value into (script, parameters).

    The native convention is positional, typically ``scriptname,parameters``.
    The first comma separates the fields; anything after it stays in the
    parameters. An empty value yields ``(None, None)``; a value without a
    comma is all script.
    """
    if value == "":
        return (None, None)
    script, separator, parameters = value.partition(",")
    if not separator:
        return (script.strip(), None)
    return (script.strip(), parameters.strip())


class _EntrySlot:
    """Accumulates every line contributing to one numeric index."""

    __slots__ = (
        "cmdline",
        "has_positional",
        "has_split",
        "parameters",
        "props",
        "raw_cmdline",
        "raw_first",
        "raw_positional",
        "value_positional",
    )

    def __init__(self) -> None:
        self.props: dict[str, str] = {}
        self.cmdline: str | None = None
        self.parameters: str | None = None
        self.raw_cmdline: str | None = None
        self.raw_first: str | None = None
        self.value_positional: str | None = None
        self.raw_positional: str | None = None
        self.has_split = False
        self.has_positional = False


class _SectionBuilder:
    """Mutable parse accumulator for one section."""

    __slots__ = ("name", "other_keys", "slots")

    def __init__(self, name: str) -> None:
        self.name = name
        self.slots: dict[int, _EntrySlot] = {}
        self.other_keys: list[tuple[str, str]] = []

    def add(self, raw_line: str, key: str, value: str) -> None:
        index_match = _ENTRY_INDEX_RE.match(key)
        if index_match is not None:
            slot = self.slots.setdefault(int(index_match.group(1)), _EntrySlot())
            slot.has_positional = True
            if slot.value_positional is None:
                slot.value_positional = value
                slot.raw_positional = raw_line
            return
        prop_match = _ENTRY_PROP_RE.match(key)
        if prop_match is not None:
            slot = self.slots.setdefault(int(prop_match.group(1)), _EntrySlot())
            slot.has_split = True
            prop = prop_match.group(2)
            folded = prop.casefold()
            if prop not in slot.props:
                slot.props[prop] = value
                if slot.raw_first is None:
                    slot.raw_first = raw_line
            if folded == "cmdline":
                if slot.cmdline is None:
                    slot.cmdline = value
                slot.raw_cmdline = raw_line
            elif folded == "parameters":
                if slot.parameters is None:
                    slot.parameters = value
            return
        self.other_keys.append((key, value))

    def build(self) -> IniSection:
        entries: list[ScriptEntry] = []
        for index in sorted(self.slots):
            slot = self.slots[index]
            if slot.has_split and slot.has_positional:
                style = "mixed"
            elif slot.has_split:
                style = "split"
            else:
                style = "positional"
            raw_line = slot.raw_cmdline or slot.raw_first or slot.raw_positional or ""
            if slot.has_split:
                # Split style wins when both appear: the fields are explicit.
                script = slot.cmdline
                parameters = slot.parameters
            else:
                assert slot.value_positional is not None
                script, parameters = _split_positional(slot.value_positional)
            entries.append(
                ScriptEntry(
                    index=index,
                    script=script,
                    parameters=parameters,
                    raw_line=raw_line,
                    style=style,
                    props=dict(slot.props),
                )
            )
        return IniSection(
            name=self.name, entries=tuple(entries), other_keys=tuple(self.other_keys)
        )


def parse_scripts_ini(data: bytes) -> ScriptsIniDocument:
    """Parse raw scripts.ini/psscripts.ini bytes into a document."""
    bom = detect_bom(data)
    text, fallback_codec = decode_ini_bytes(data)
    builders: list[_SectionBuilder] = []
    by_name: dict[str, _SectionBuilder] = {}
    current: _SectionBuilder | None = None
    unparsed: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";") or line.startswith("#"):
            continue
        header = _SECTION_RE.match(line)
        if header is not None:
            name = header.group(1)
            folded = name.casefold()
            builder = by_name.get(folded)
            if builder is None:
                builder = _SectionBuilder(name=name)
                by_name[folded] = builder
                builders.append(builder)
            current = builder
            continue
        key, separator, value = line.partition("=")
        if not separator:
            unparsed.append(line)
            continue
        if current is None:
            # Keys before any section header are recorded under an implicit
            # unnamed section rather than dropped.
            current = by_name.get("")
            if current is None:
                current = _SectionBuilder(name="")
                by_name[""] = current
                builders.append(current)
        current.add(raw_line=raw_line, key=key.strip(), value=value.strip())
    sections = tuple(builder.build() for builder in builders)
    return ScriptsIniDocument(
        bom=bom,
        cr_count=text.count("\r"),
        lf_count=text.count("\n"),
        total_bytes=len(data),
        text=text,
        fallback_codec=fallback_codec,
        sections=sections,
        unparsed_lines=tuple(unparsed),
    )


@dataclass(frozen=True, slots=True)
class ConfigSectionFacts:
    """Which modeled keys a config-shaped section carries, key-by-key."""

    present: bool
    section_name: str | None
    values: Mapping[str, str | None]
    extra_keys: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class ConfigShape:
    """The config-section shape of one scripts INI file (R2 question 3)."""

    policy: ConfigSectionFacts
    scripts_config: ConfigSectionFacts

    @property
    def shape(self) -> str:
        if self.policy.present and self.scripts_config.present:
            return "both"
        if self.policy.present:
            return "policy"
        if self.scripts_config.present:
            return "scripts_config"
        return "none"


def _config_section(
    document: ScriptsIniDocument, section_name: str, modeled_keys: Sequence[str]
) -> ConfigSectionFacts:
    section = document.section(section_name)
    if section is None:
        return ConfigSectionFacts(
            present=False,
            section_name=None,
            values={key: None for key in modeled_keys},
            extra_keys=(),
        )
    written = {key.casefold(): (key, value) for key, value in section.other_keys}
    values: dict[str, str | None] = {}
    consumed: set[str] = set()
    for modeled in modeled_keys:
        found = written.get(modeled.casefold())
        values[modeled] = found[1] if found is not None else None
        if found is not None:
            consumed.add(found[0])
    extra = tuple((key, value) for key, value in section.other_keys if key not in consumed)
    return ConfigSectionFacts(
        present=True, section_name=section.name, values=values, extra_keys=extra
    )


def analyze_config_sections(document: ScriptsIniDocument) -> ConfigShape:
    """Distinguish a [Policy] shape from a [ScriptsConfig] shape."""
    return ConfigShape(
        policy=_config_section(document, POLICY_SECTION_NAME, POLICY_MODELED_KEYS),
        scripts_config=_config_section(
            document, SCRIPTS_CONFIG_SECTION_NAME, SCRIPTS_CONFIG_MODELED_KEYS
        ),
    )


def ini_facts(document: ScriptsIniDocument, *, prefix: str, side: str) -> dict[str, JSONValue]:
    """Fact values for one parsed file under *prefix* (plus side segment)."""
    facts: dict[str, JSONValue] = {}
    base = f"{prefix}.{side}"
    facts[f"{base}.present"] = True
    facts[f"{base}.encoding.bom"] = document.bom.kind
    facts[f"{base}.encoding.bom_width"] = document.bom.width
    facts[f"{base}.encoding.cr_count"] = document.cr_count
    facts[f"{base}.encoding.lf_count"] = document.lf_count
    facts[f"{base}.encoding.total_bytes"] = document.total_bytes
    facts[f"{base}.encoding.fallback_codec"] = document.fallback_codec
    for section in document.sections:
        # Sections must not be dropped; keys before any header are kept under
        # an explicit "orphan" label rather than silently ignored.
        section_label = section.name if section.name else "orphan"
        for entry in section.entries:
            entry_base = f"{base}.{section_label}.{entry.index}"
            facts[f"{entry_base}.script"] = entry.script
            facts[f"{entry_base}.parameters"] = entry.parameters
            facts[f"{entry_base}.raw"] = entry.raw_line
            for prop, prop_value in entry.props.items():
                facts[f"{entry_base}.prop.{prop}"] = prop_value
    shape = analyze_config_sections(document)
    facts[f"{base}.config_shape"] = shape.shape
    for key, modeled_value in shape.policy.values.items():
        facts[f"{base}.policy.{key}"] = modeled_value
    for key, modeled_value in shape.scripts_config.values.items():
        facts[f"{base}.scripts_config.{key}"] = modeled_value
    return facts


def absent_ini_facts(*, prefix: str, side: str) -> dict[str, JSONValue]:
    """Fact values for a scripts INI file that is not present.

    The stable keys (presence, encoding stats, config shape and modeled keys)
    are emitted as nulls so a file appearing or vanishing shows up as a value
    change on declared keys rather than as added/removed keys.
    """
    facts: dict[str, JSONValue] = {f"{prefix}.{side}.present": False}
    for stat in ("bom", "bom_width", "cr_count", "lf_count", "total_bytes", "fallback_codec"):
        facts[f"{prefix}.{side}.encoding.{stat}"] = None
    facts[f"{prefix}.{side}.config_shape"] = "none"
    for key in POLICY_MODELED_KEYS:
        facts[f"{prefix}.{side}.policy.{key}"] = None
    for key in SCRIPTS_CONFIG_MODELED_KEYS:
        facts[f"{prefix}.{side}.scripts_config.{key}"] = None
    return facts


def scripts_ini_facts(document: ScriptsIniDocument, *, side: str) -> dict[str, JSONValue]:
    """Fact values for scripts.ini (the legacy script file)."""
    return ini_facts(document, prefix="scripts_ini", side=side)


def psscripts_ini_facts(document: ScriptsIniDocument, *, side: str) -> dict[str, JSONValue]:
    """Fact values for psscripts.ini (the PowerShell script file)."""
    return ini_facts(document, prefix="scripts_ini.ps", side=side)


def absent_scripts_ini_facts(side: str) -> dict[str, JSONValue]:
    return absent_ini_facts(prefix="scripts_ini", side=side)


def absent_psscripts_ini_facts(side: str) -> dict[str, JSONValue]:
    return absent_ini_facts(prefix="scripts_ini.ps", side=side)
