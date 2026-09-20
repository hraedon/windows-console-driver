"""Certificate-template (pKICertificateTemplate) observer: controller facts.

The guest enumerates one-level under
``CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration``
and transports raw attribute values as deterministic ``key=value`` lines:
one record per template object (name, the two duration attributes,
schema version, name/key flags) plus the SDDL form of
``nTSecurityDescriptor`` committed only as ``sddl_len`` / ``sddl_sha256``
-- never the SDDL text itself.

The duration attributes are the measured ones. ``pKIExpirationPeriod``
(validity) and ``pKIOverlapPeriod`` (renewal) are octet strings holding an
8-byte little-endian signed FILETIME interval, stored negative because it
is relative time; there is no units attribute at all, because the
years/months/weeks/days choice the console offers is a rendering of that
single duration, not something the directory stores. The guest transports
the raw bytes as hex and this module decodes them into
``certtmpl.target.expiration_100ns`` / ``overlap_100ns``, so the
interpretation lives controller-side like every other parse here. Measured
on a Server 2025 forest 2026-09-20: the built-in Machine template carries
``00 40 39 87 2E E1 FE FF`` = 315360000000000 hundred-nanosecond units =
365 days. An earlier revision of this observer named
``msPKI-Validity-Period`` / ``msPKI-Validity-PeriodUnits``, which exist in
no Server 2025 schema -- the same filter-shaped hole that
``certTemplate`` versus ``pKICertificateTemplate`` opened for the estate's
CA work.
Following the independence rule, the guest never interprets: it does not
know which template is special beyond echoing the named target's record
under the ``target.`` prefix, and it does not compare observations. The
controller knows the target name (a capability argument).

Container membership is committed as digests (sha256 over the LF-joined,
ordinally sorted names), not name lists, so pre/post comparison detects
ANY membership change without committing real template names. The counts
and digests the guest claims are recomputed here from the transported
records -- the sysvol two-pass discipline -- and any disagreement refuses
the whole observation: an observer that guesses is worse than an observer
that refuses. Absent and empty attributes both transport as empty values
(the line protocol has no null spelling).

Deliberately narrow fact set: every emitted key that can change across the
transaction must be referenced by the capability envelope. The
``certtmpl.*`` keys stay ``unclassified`` in the category table until the
envelope work that wires this surface declares them; nothing here adds
that declaration, on purpose.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence

from gpo_observers.facts import Fact, make_fact

FactSet = dict[str, Fact]

_RECORD_ATTR_KEYS: tuple[str, ...] = (
    "expiration_period",
    "overlap_period",
    "schema_version",
    "cert_name_flag",
    "key_flag",
    "sddl_len",
    "sddl_sha256",
)
_INT_ATTR_KEYS: frozenset[str] = frozenset(
    {
        "schema_version",
        "cert_name_flag",
        "key_flag",
        "sddl_len",
    }
)
_CONTAINER_KEYS: tuple[str, ...] = (
    "container.present",
    "container.object_count",
    "container.names_sha256",
    "container.other_names_sha256",
    "container.other_count",
    "container.unnamed_count",
)
_TARGET_DETAIL_KEYS: tuple[str, ...] = tuple(
    "target." + key for key in ("name", *_RECORD_ATTR_KEYS)
)
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
# The two duration attributes transport as the uppercase hex of exactly
# eight bytes, or empty when the attribute is absent.
_DURATION_HEX_RE = re.compile(r"^[0-9A-F]{16}$")
_DURATION_ATTR_KEYS: frozenset[str] = frozenset({"expiration_period", "overlap_period"})
# Record attribute name -> the fact suffix it is published under. The
# durations are renamed because the fact is the decoded magnitude, not the
# transported bytes; everything else publishes under its own name.
_FACT_SUFFIX_BY_ATTR: dict[str, str] = {
    "expiration_period": "expiration_100ns",
    "overlap_period": "overlap_100ns",
}


def _digest(names: Sequence[str]) -> str:
    """sha256 over the LF-joined names (UTF-8, lowercase hex).

    The input is already sorted; the empty name set digests the empty
    string, so an absent container has a well-defined, comparable value.
    """
    return hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest()


def _flag(value: str, key: str) -> bool:
    """Decode a 0/1 flag line; anything else is a refusal, not a guess."""
    if value == "1":
        return True
    if value == "0":
        return False
    raise ValueError(f"certtmpl {key} must be 0 or 1, got {value!r}")


def _count(value: str, key: str) -> int:
    """Decode a non-negative integer line value."""
    try:
        parsed = int(value)
    except ValueError as error:
        raise ValueError(f"certtmpl {key} must be an integer, got {value!r}") from error
    if parsed < 0:
        raise ValueError(f"certtmpl {key} must not be negative, got {value!r}")
    return parsed


def _int_or_empty(value: str, key: str) -> int | str:
    """Decode an integer attribute line; empty stays '' (absent convention)."""
    if value == "":
        return ""
    try:
        return int(value)
    except ValueError as error:
        raise ValueError(f"certtmpl {key} must be an integer, got {value!r}") from error


def _duration_100ns(value: str, key: str) -> int | str:
    """Decode a transported duration attribute into 100ns units.

    The attribute is an 8-byte little-endian signed FILETIME interval,
    stored NEGATIVE (relative time), so the published fact is its
    magnitude. Empty stays ``''`` (the absent convention). Anything else
    refuses: a duration that cannot be read is not a duration of zero, and
    a non-negative stored value is not the representation this decode was
    measured against.
    """
    if value == "":
        return ""
    if _DURATION_HEX_RE.match(value) is None:
        raise ValueError(
            f"certtmpl {key} must be 16 uppercase hex digits (8 bytes), got {value!r}"
        )
    raw = int.from_bytes(bytes.fromhex(value), byteorder="little", signed=True)
    if raw >= 0:
        raise ValueError(
            f"certtmpl {key} must be a negative relative interval, got {raw}"
        )
    return -raw


def certtmpl_fact_tree(lines: Sequence[str], template_name: str) -> FactSet:
    """Build the ``certtmpl.*`` facts from one collected line stream.

    ``lines`` are the guest script's ``key=value`` lines (record blocks,
    ``container.*`` claims, ``target.*`` lines); ``template_name`` is the
    capability argument naming the template under observation. Malformed
    input raises :class:`ValueError`: a line outside the vocabulary, a
    container claim the recomputation cannot reproduce, or a target block
    that disagrees with its own record all refuse.
    """
    if not template_name:
        raise ValueError("certtmpl observation needs a non-empty template name")

    records: list[dict[str, str]] = []
    container: dict[str, str] = {}
    target: dict[str, str] = {}
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line:
            continue
        key, sep, value = line.partition("=")
        if not sep:
            raise ValueError(f"certtmpl line is not key=value: {line!r}")
        if key == "error":
            raise ValueError(f"certtmpl observation reported an error: {value}")
        if key == "name":
            records.append({"name": value})
        elif key in _RECORD_ATTR_KEYS:
            if not records:
                raise ValueError(f"certtmpl {key} line before any name line")
            if key in records[-1]:
                raise ValueError(f"certtmpl record repeats {key}")
            records[-1][key] = value
        elif key.startswith("target.") or key.startswith("container."):
            claimed = target if key.startswith("target.") else container
            if key in claimed:
                raise ValueError(f"certtmpl observation repeats {key}")
            claimed[key] = value
        else:
            raise ValueError(f"certtmpl line has an unknown key: {key!r}")

    for key in _CONTAINER_KEYS:
        if key not in container:
            raise ValueError(f"certtmpl observation missing {key}")
    if "target.present" not in target:
        raise ValueError("certtmpl observation missing target.present")
    for key in container:
        if key not in _CONTAINER_KEYS:
            raise ValueError(f"certtmpl container key not in the vocabulary: {key!r}")
    for key in target:
        if key != "target.present" and key not in _TARGET_DETAIL_KEYS:
            raise ValueError(f"certtmpl target key not in the vocabulary: {key!r}")

    present = _flag(container["container.present"], "container.present")
    target_present = _flag(target["target.present"], "target.present")

    # Records mirror the script's emission exactly: a named record carries
    # all seven attribute lines; an unnamed object contributes only its
    # bare name= line and the unnamed count.
    for record in records:
        expected = {"name", *_RECORD_ATTR_KEYS} if record["name"] != "" else {"name"}
        if set(record) != expected:
            raise ValueError(
                f"certtmpl record for {record['name']!r} has an incomplete key set"
            )
        if record["name"] == "":
            continue
        for attr in _INT_ATTR_KEYS:
            _int_or_empty(record[attr], f"record {attr}")
        for attr in _DURATION_ATTR_KEYS:
            _duration_100ns(record[attr], f"record {attr}")
        if _SHA256_HEX_RE.match(record["sddl_sha256"]) is None:
            raise ValueError(
                f"certtmpl record {record['name']!r} sddl_sha256 must be 64 "
                "lowercase hex digits"
            )

    # Recompute the container claims from the records; disagreement refuses.
    names = sorted(record["name"] for record in records if record["name"] != "")
    unnamed = len(records) - len(names)
    folded = template_name.casefold()
    other = [name for name in names if name.casefold() != folded]
    matches = [
        record
        for record in records
        if record["name"] != "" and record["name"].casefold() == folded
    ]
    for key in ("container.names_sha256", "container.other_names_sha256"):
        if _SHA256_HEX_RE.match(container[key]) is None:
            raise ValueError(f"certtmpl {key} must be 64 lowercase hex digits")
    checks: tuple[tuple[str, int | str, int | str], ...] = (
        (
            "container.object_count",
            _count(container["container.object_count"], "container.object_count"),
            len(records),
        ),
        (
            "container.other_count",
            _count(container["container.other_count"], "container.other_count"),
            len(other),
        ),
        (
            "container.unnamed_count",
            _count(container["container.unnamed_count"], "container.unnamed_count"),
            unnamed,
        ),
        ("container.names_sha256", container["container.names_sha256"], _digest(names)),
        (
            "container.other_names_sha256",
            container["container.other_names_sha256"],
            _digest(other),
        ),
    )
    for claim_key, claim_value, computed_value in checks:
        if claim_value != computed_value:
            raise ValueError(
                f"certtmpl {claim_key} claims {claim_value!r} but the records "
                f"recompute to {computed_value!r}"
            )

    if len(matches) > 1:
        raise ValueError("certtmpl target name matches more than one template")
    if target_present != bool(matches):
        raise ValueError("certtmpl target.present disagrees with the transported records")

    target_record = matches[0] if matches else None
    if target_record is not None:
        missing = set(_TARGET_DETAIL_KEYS) - set(target)
        if missing:
            raise ValueError(f"certtmpl target detail lines missing: {sorted(missing)}")
        for attr in ("name", *_RECORD_ATTR_KEYS):
            if target["target." + attr] != target_record[attr]:
                raise ValueError(
                    f"certtmpl target.{attr} disagrees with the target record"
                )
        if _SHA256_HEX_RE.match(target["target.sddl_sha256"]) is None:
            raise ValueError(
                "certtmpl target.sddl_sha256 must be 64 lowercase hex digits"
            )
    else:
        extra = set(target) - {"target.present"}
        if extra:
            raise ValueError(
                f"certtmpl target detail lines without presence: {sorted(extra)}"
            )

    facts: FactSet = {}

    def fact(key: str, value: object) -> None:
        facts[key] = make_fact(key, value)

    fact("certtmpl.container.present", present)
    fact("certtmpl.container.object_count", len(records))
    fact("certtmpl.container.names_sha256", _digest(names))
    fact("certtmpl.container.other_names_sha256", _digest(other))
    fact("certtmpl.container.other_count", len(other))
    fact("certtmpl.container.unnamed_count", unnamed)
    fact("certtmpl.target.present", target_present)
    if target_record is not None:
        fact("certtmpl.target.name", target_record["name"])
        for attr in _RECORD_ATTR_KEYS:
            key = f"certtmpl.target.{_FACT_SUFFIX_BY_ATTR.get(attr, attr)}"
            if attr in _DURATION_ATTR_KEYS:
                fact(key, _duration_100ns(target_record[attr], key))
            elif attr in _INT_ATTR_KEYS:
                fact(key, _int_or_empty(target_record[attr], key))
            else:
                fact(key, target_record[attr])
    else:
        for attr in ("name", *_RECORD_ATTR_KEYS):
            fact(f"certtmpl.target.{_FACT_SUFFIX_BY_ATTR.get(attr, attr)}", "")
    return facts
