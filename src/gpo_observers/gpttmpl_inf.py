"""GptTmpl.inf semantics (the R4 observer): security-template facts.

The guest transports bytes; this module is the only place GptTmpl.inf is
parsed, controller-side, independent of both the actuation path and the
product's ``gpo_studio.security_template`` (no import, by the independence
test).

What the first capture must settle (work order R4):

- **the propagation codes**: ``[Registry Keys]`` and ``[File Security]``
  entries carry an integer option code per secured object. The repository
  contradicts itself (``0->none/1->propagate/2->replace`` in object_security
  vs ``0->propagate/1->replace/2->do-not-allow`` in a spec-informed fixture);
  the observer records the code Windows wrote per authored key so the mapping
  from the three radio options to integers is readable off the capture.
- **the entry shape**: ``key = value`` or the bare quoted-CSV line. Each
  entry records its detected shape alongside the parsed fields, so a reader
  that cannot parse the native shape is measurable (count of ``shape ==
  "quoted_csv"`` rows against the product parser's unknown_lines).
- **encoding**: BOM presence/width, CR/LF counts -- the same wire-format
  question R2 settled for scripts.ini.

The parse is deliberately shallow: sections in order, each line kept raw,
plus typed decoding ONLY for the quoted-CSV sections and ``key = value``
splitting elsewhere. No semantics are inferred beyond that; what a section
"means" is a claim registered from characterized captures, not an observer
assumption.
"""

from __future__ import annotations

from collections.abc import Mapping


def decode_template_bytes(raw: bytes) -> tuple[str, str]:
    """Decode template bytes to text; return ``(text, bom_facts)`` string.

    ``bom_facts`` is ``utf16le`` / ``utf8`` / ``none`` per the leading bytes.
    UTF-16LE BOM is the native expectation (measured for scripts.ini in the
    R2 pilot; GptTmpl.inf is expected to match -- and that expectation is
    exactly what the capture tests).
    """
    if raw.startswith(b"\xff\xfe"):
        return raw.decode("utf-16"), "utf16le"
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig"), "utf8"
    return raw.decode("utf-8", errors="replace"), "none"


def _split_quoted_csv(line: str) -> list[str] | None:
    """Parse a bare quoted-CSV template line; None when the shape does not fit.

    The native shape (WI-038): ``"MACHINE\\SOFTWARE\\Key",0,"D:PAR(...)"`` --
    double-quoted fields separated by commas, no escapes; integer option codes
    appear BARE (unquoted). Lines carrying ``=`` (INI ``key = value`` shape)
    are rejected here so callers can record the shape per entry.
    """
    text = line.strip()
    if not text or "=" in text or "," not in text:
        return None
    fields: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        if text[index] == '"':
            end = text.find('"', index + 1)
            if end < 0:
                return None
            fields.append(text[index + 1 : end])
            index = end + 1
        else:
            # A bare field runs to the next comma (no quotes, no escapes).
            comma = text.find(",", index)
            if comma < 0:
                fields.append(text[index:])
                index = length
            else:
                fields.append(text[index:comma])
                index = comma
        if index >= length:
            break
        if text[index] == ',':
            index += 1
            if index >= length:
                # Trailing comma: an empty final field.
                fields.append("")
                break
            continue
        return None
    return fields


def _parse_line(raw: str) -> dict[str, object]:
    """One template line: shape-tagged, with typed fields where the shape is known."""
    fields = _split_quoted_csv(raw)
    if fields is not None:
        return {"shape": "quoted_csv", "fields": list(fields), "raw": raw}
    if "=" in raw and not raw.strip().startswith(";"):
        key, _, value = raw.partition("=")
        return {
            "shape": "key_value",
            "key": key.strip(),
            "value": value.strip(),
            "raw": raw,
        }
    return {"shape": "raw", "raw": raw}


def _typed_object_entry(parsed: Mapping[str, object]) -> dict[str, object]:
    """Add key_path / propagation_code / sddl decodes to a quoted-CSV entry.

    Only ``[Registry Keys]`` and ``[File Security]`` entries get these typed
    fields -- field 0 is the object path, field 1 the option code (the R4
    propagation code under measurement), field 2 the SDDL string.
    """
    entry = dict(parsed)
    fields = entry.get("fields")
    if isinstance(fields, list):
        if len(fields) >= 1:
            entry["key_path"] = fields[0]
        if len(fields) >= 2:
            try:
                entry["propagation_code"] = int(str(fields[1]))
            except ValueError:
                entry["propagation_code"] = None
        if len(fields) >= 3:
            entry["sddl"] = fields[2]
    return entry


def gpttmpl_fact_tree(raw: bytes) -> dict[str, object]:
    """Parse GptTmpl.inf bytes into the fact tree the envelope consumes."""
    text, bom = decode_template_bytes(raw)
    cr_count = raw.count(b"\r")
    lf_count = raw.count(b"\n")
    sections: list[dict[str, object]] = []
    registry_keys: list[dict[str, object]] = []
    file_security: list[dict[str, object]] = []
    service_general: list[dict[str, object]] = []
    group_membership: dict[str, str] = {}
    system_access: dict[str, str] = {}
    current: dict[str, object] | None = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            current = {"name": stripped[1:-1], "lines": []}
            sections.append(current)
            continue
        if current is None:
            continue
        name = str(current["name"])
        lines = current["lines"]
        assert isinstance(lines, list)
        lines.append(stripped)
        parsed = _parse_line(stripped)
        if name == "Registry Keys":
            registry_keys.append(_typed_object_entry(parsed))
        elif name == "File Security":
            file_security.append(_typed_object_entry(parsed))
        elif name == "Service General Setting":
            service_general.append(parsed)
        elif name == "Group Membership" and parsed["shape"] == "key_value":
            group_membership[str(parsed["key"])] = str(parsed["value"])
        elif name == "System Access" and parsed["shape"] == "key_value":
            system_access[str(parsed["key"])] = str(parsed["value"])

    def key_value_shape(lines: list[str]) -> bool:
        return bool(lines) and all("=" in line and not line.startswith('"') for line in lines)

    # Lookup by authored object path: entry ORDER in GptTmpl.inf is not the
    # authoring order (measured 2026-09-03: reverse), so index-based facts
    # cannot serve require clauses that name a specific authored object. The
    # key is the object path with non-alphanumeric characters collapsed.
    by_key: dict[str, dict[str, object]] = {}
    for entry in registry_keys + file_security:
        path = entry.get("key_path")
        if not isinstance(path, str) or not path:
            continue
        slug = ""
        for ch in path:
            slug += ch if ch.isalnum() else "_"
        by_key[slug] = {
            "propagation_code": entry.get("propagation_code"),
            "sddl": entry.get("sddl"),
        }

    return {
        "encoding": {
            "bom": bom,
            "cr_count": cr_count,
            "lf_count": lf_count,
            "crlf_only": cr_count == lf_count and lf_count > 0,
        },
        "by_key": by_key,
        "sections": [
            {
                "name": section["name"],
                "line_count": len(section["lines"]),  # type: ignore[arg-type]
                "key_value_shape": key_value_shape(section["lines"]),  # type: ignore[arg-type]
            }
            for section in sections
        ],
        "registry_keys": registry_keys,
        "file_security": file_security,
        "service_general": service_general,
        "group_membership": dict(sorted(group_membership.items())),
        "system_access": dict(sorted(system_access.items())),
    }
