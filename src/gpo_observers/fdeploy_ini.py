"""fdeploy.ini semantics (the R3 observer): Folder Redirection facts.

The question R3 settles (work order): is Folder Redirection carried in
``fdeploy.ini`` under the GPO's ``User\\Documents & Settings\\`` rather than
in ``User Shell Folders`` registry settings? The observer is deliberately
generic -- sections in order, each line raw, plus a ``key = value`` split --
because the wire format's details (how folders are keyed, how the four
option flags encode, how multi-group rules represent) are the *answers* the
capture produces, not assumptions the observer bakes in.

The controller owns all parsing (the independence rule); the guest only
transports bytes.
"""

from __future__ import annotations


def decode_ini_bytes(raw: bytes) -> tuple[str, str]:
    """Decode INI bytes; return ``(text, bom_facts)`` per gpttmpl_inf.decode."""
    if raw.startswith(b"\xff\xfe"):
        return raw.decode("utf-16"), "utf16le"
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig"), "utf8"
    return raw.decode("utf-8", errors="replace"), "none"


def fdeploy_fact_tree(raw: bytes) -> dict[str, object]:
    """Parse fdeploy.ini bytes into the fact tree the envelope consumes."""
    text, bom = decode_ini_bytes(raw)
    cr_count = raw.count(b"\r")
    lf_count = raw.count(b"\n")
    sections: list[dict[str, object]] = []
    entries: list[dict[str, object]] = []
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
        lines = current["lines"]
        assert isinstance(lines, list)
        lines.append(stripped)
        section_name = str(current["name"])
        if "=" in stripped and not stripped.startswith(";"):
            key, _, value = stripped.partition("=")
            entries.append(
                {
                    "section": section_name,
                    "key": key.strip(),
                    "value": value.strip(),
                }
            )

    return {
        "encoding": {
            "bom": bom,
            "cr_count": cr_count,
            "lf_count": lf_count,
            "crlf_only": cr_count == lf_count and lf_count > 0,
        },
        "section_names": [str(section["name"]) for section in sections],
        "sections": [
            {"name": section["name"], "line_count": len(section["lines"])}  # type: ignore[arg-type]
            for section in sections
        ],
        "entries": entries,
    }
