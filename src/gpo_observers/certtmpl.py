"""Certificate-template (pKICertificateTemplate) observer: controller facts.

The guest enumerates one-level under
``CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration``
and transports raw attribute values as deterministic ``key=value`` lines:
one record per template object (name, validity blobs, schema version,
name/key flags) plus the SDDL form of ``nTSecurityDescriptor`` committed
only as ``sddl_len`` / ``sddl_sha256`` -- never the SDDL text itself.
Following the independence rule, the guest never interprets: it does not
know which template is special beyond echoing the named target's and the
named source's records under the ``target.`` / ``source.`` prefixes, and
it does not compare observations. The controller knows both names
(capability arguments).

MEASURED ENCODING (live read-only pass against a Server 2025 forest,
2026-09-19): template objects are class ``pKICertificateTemplate`` and
carry NO ``msPKI-Validity-Period`` / ``msPKI-Validity-PeriodUnits``
attributes -- the assumed schema the capability was first drafted
against. Validity is stored as two 8-byte blobs, ``pKIExpirationPeriod``
and ``pKIOverlapPeriod``, each a little-endian signed int64 of NEGATIVE
100-nanosecond ticks (a duration; a "year" is exactly 365 days -- the
5*365d blob is byte-identical to what multiple real templates carry).
The blobs transport as 16-character UPPERCASE hex strings ('' when the
attribute is absent) and decode to whole days with pure integer
arithmetic: ``days = (-ticks) // 864_000_000_000``. The decode stays in
integers because IEEE doubles lose integer precision above ~9e15 ticks
(about 28 years' worth) and the certification must not rest on a
precision boundary -- the arithmetic is exact for every representable
blob.

Container membership is committed as digests (sha256 over the LF-joined,
ordinally sorted names), not name lists, so pre/post comparison detects
ANY membership change without committing real template names. The counts
and digests the guest claims are recomputed here from the transported
records -- the sysvol two-pass discipline -- and any disagreement refuses
the whole observation: an observer that guesses is worse than an observer
that refuses. Absent and empty attributes both transport as empty values
(the line protocol has no null spelling).

Deliberately narrow fact set: every emitted key that can change across
the transaction must be textually predicted by the capability envelope
(a require fact key, or a post-side reference in a require/derive
clause), else the delta engine records an unclassified-change violation.
The source's descriptor is NOT part of the duplication-fidelity claim,
so ``source.sddl_len`` / ``source.sddl_sha256`` are validated on the wire
(the source block intentionally transports the same attribute set as the
target block, one protocol shape) but are never emitted as facts.
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
# The two 8-byte duration blobs transport as 16 uppercase hex characters
# ('' when the AD attribute is absent). Uppercase is pinned, not preferred:
# the guest's BitConverter emission is uppercase, and a lowercase blob is a
# different transport than the one this observer certified.
_BLOB_ATTR_KEYS: frozenset[str] = frozenset({"expiration_period", "overlap_period"})
_BLOB_HEX_RE = re.compile(r"^[0-9A-F]{16}$")
# 100-nanosecond ticks per day (measured encoding; see module docstring).
_TICKS_PER_DAY: int = 864_000_000_000
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
_SOURCE_DETAIL_KEYS: tuple[str, ...] = tuple(
    "source." + key for key in ("name", *_RECORD_ATTR_KEYS)
)
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


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


def _blob_or_empty(value: str, key: str) -> str:
    """Validate a duration-blob transport: '' or 16 uppercase hex chars."""
    if value != "" and _BLOB_HEX_RE.match(value) is None:
        raise ValueError(
            f"certtmpl {key} must be 16 uppercase hex characters or empty, got {value!r}"
        )
    return value


def _blob_days(value: str, key: str) -> int | str:
    """Decode a validated blob to whole days; '' stays '' (absent convention).

    The blob is a little-endian signed int64 of NEGATIVE 100-nanosecond
    ticks. Integer arithmetic only (see module docstring): float division
    would lose exactness above ~9e15 ticks, and the certification must not
    rest on a floating-point precision boundary.
    """
    if value == "":
        return ""
    ticks = int.from_bytes(bytes.fromhex(value), "little", signed=True)
    if ticks > 0:
        raise ValueError(f"certtmpl {key} must encode a negative tick count")
    return (-ticks) // _TICKS_PER_DAY


def certtmpl_fact_tree(
    lines: Sequence[str], template_name: str, source_name: str
) -> FactSet:
    """Build the ``certtmpl.*`` facts from one collected line stream.

    ``lines`` are the guest script's ``key=value`` lines (record blocks,
    ``container.*`` claims, ``target.*`` / ``source.*`` lines);
    ``template_name`` and ``source_name`` are the capability arguments
    naming the duplicated template and the built-in it was duplicated
    from. Malformed input raises :class:`ValueError`: a line outside the
    vocabulary, a container claim the recomputation cannot reproduce, or a
    target/source block that disagrees with its own record all refuse.
    """
    if not template_name:
        raise ValueError("certtmpl observation needs a non-empty template name")
    if not source_name:
        raise ValueError("certtmpl observation needs a non-empty source name")

    records: list[dict[str, str]] = []
    container: dict[str, str] = {}
    target: dict[str, str] = {}
    source: dict[str, str] = {}
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
        elif key.startswith(("target.", "source.", "container.")):
            if key.startswith("target."):
                claimed: dict[str, str] = target
            elif key.startswith("source."):
                claimed = source
            else:
                claimed = container
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
    if "source.present" not in source:
        raise ValueError("certtmpl observation missing source.present")
    for key in container:
        if key not in _CONTAINER_KEYS:
            raise ValueError(f"certtmpl container key not in the vocabulary: {key!r}")
    for key in target:
        if key != "target.present" and key not in _TARGET_DETAIL_KEYS:
            raise ValueError(f"certtmpl target key not in the vocabulary: {key!r}")
    for key in source:
        if key != "source.present" and key not in _SOURCE_DETAIL_KEYS:
            raise ValueError(f"certtmpl source key not in the vocabulary: {key!r}")

    present = _flag(container["container.present"], "container.present")
    target_present = _flag(target["target.present"], "target.present")
    source_present = _flag(source["source.present"], "source.present")

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
        for attr in _BLOB_ATTR_KEYS:
            _blob_or_empty(record[attr], f"record {attr} of {record['name']!r}")
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
    source_matches = [
        record
        for record in records
        if record["name"] != "" and record["name"].casefold() == source_name.casefold()
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

    target_record = _resolve_block("target", target, target_present, matches)
    source_record = _resolve_block("source", source, source_present, source_matches)

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
    fact("certtmpl.source.present", source_present)
    _emit_template_facts(facts, "target", target_record, with_descriptor=True)
    _emit_template_facts(facts, "source", source_record, with_descriptor=False)
    return facts


def _resolve_block(
    prefix: str,
    block: dict[str, str],
    present: bool,
    matches: list[dict[str, str]],
) -> dict[str, str] | None:
    """Cross-check one ``target.``/``source.`` echo block against its record.

    The block's presence flag must agree with the transported records
    (casefold-insensitive match, at most one); when present the detail set
    must be complete and line-for-line equal to the record's own values;
    when absent no detail line may appear. Both prefixes follow the same
    discipline -- the source block transports the same attribute set as
    the target block even though the observer emits fewer source facts.
    """
    detail_keys = _TARGET_DETAIL_KEYS if prefix == "target" else _SOURCE_DETAIL_KEYS
    if len(matches) > 1:
        raise ValueError(f"certtmpl {prefix} name matches more than one template")
    if present != bool(matches):
        raise ValueError(f"certtmpl {prefix}.present disagrees with the transported records")
    record = matches[0] if matches else None
    if record is not None:
        missing = set(detail_keys) - set(block)
        if missing:
            raise ValueError(f"certtmpl {prefix} detail lines missing: {sorted(missing)}")
        for attr in ("name", *_RECORD_ATTR_KEYS):
            if block[f"{prefix}.{attr}"] != record[attr]:
                raise ValueError(
                    f"certtmpl {prefix}.{attr} disagrees with the {prefix} record"
                )
        if _SHA256_HEX_RE.match(block[f"{prefix}.sddl_sha256"]) is None:
            raise ValueError(
                f"certtmpl {prefix}.sddl_sha256 must be 64 lowercase hex digits"
            )
        for attr in _BLOB_ATTR_KEYS:
            _blob_or_empty(block[f"{prefix}.{attr}"], f"{prefix}.{attr}")
    else:
        extra = set(block) - {f"{prefix}.present"}
        if extra:
            raise ValueError(f"certtmpl {prefix} detail lines without presence: {sorted(extra)}")
    return record


# The detail fact keys emitted per prefix. The target block additionally
# commits the descriptor (sddl_len / sddl_sha256); the source's descriptor
# is not part of the claim and stops at the wire (see module docstring).
_DETAIL_FACT_ATTRS: tuple[str, ...] = (
    "name",
    "expiration_period",
    "expiration_period_days",
    "overlap_period",
    "schema_version",
    "cert_name_flag",
    "key_flag",
)


def _emit_template_facts(
    facts: FactSet, prefix: str, record: dict[str, str] | None, *, with_descriptor: bool
) -> None:
    """Emit one template block's facts; an absent block emits '' details."""
    attrs = (*_DETAIL_FACT_ATTRS, "sddl_len", "sddl_sha256") if with_descriptor else (
        _DETAIL_FACT_ATTRS
    )
    if record is None:
        for attr in attrs:
            key = f"certtmpl.{prefix}.{attr}"
            facts[key] = make_fact(key, "")
        return
    facts[f"certtmpl.{prefix}.name"] = make_fact(
        f"certtmpl.{prefix}.name", record["name"]
    )
    facts[f"certtmpl.{prefix}.expiration_period"] = make_fact(
        f"certtmpl.{prefix}.expiration_period", record["expiration_period"]
    )
    facts[f"certtmpl.{prefix}.expiration_period_days"] = make_fact(
        f"certtmpl.{prefix}.expiration_period_days",
        _blob_days(record["expiration_period"], f"{prefix}.expiration_period"),
    )
    facts[f"certtmpl.{prefix}.overlap_period"] = make_fact(
        f"certtmpl.{prefix}.overlap_period", record["overlap_period"]
    )
    for attr in ("schema_version", "cert_name_flag", "key_flag"):
        facts[f"certtmpl.{prefix}.{attr}"] = make_fact(
            f"certtmpl.{prefix}.{attr}",
            _int_or_empty(record[attr], f"{prefix}.{attr}"),
        )
    if with_descriptor:
        facts[f"certtmpl.{prefix}.sddl_len"] = make_fact(
            f"certtmpl.{prefix}.sddl_len",
            _int_or_empty(record["sddl_len"], f"{prefix}.sddl_len"),
        )
        facts[f"certtmpl.{prefix}.sddl_sha256"] = make_fact(
            f"certtmpl.{prefix}.sddl_sha256", record["sddl_sha256"]
        )
