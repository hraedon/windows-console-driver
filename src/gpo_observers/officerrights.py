"""Certificate-manager restriction (``CA\\OfficerRights``) observer.

The guest half (``tools/guest_scripts/officerrights_collect.ps1``) reads the
CA's ``CertSvc\\Configuration\\<ca name>`` key -- remotely, from the console
guest -- and transports deterministic ``key=value`` lines. This module turns
them into ``certsrv.*`` facts. As everywhere in this package the guest only
transports: every decision about what a line MEANS is made here.

Three properties of this surface shape the fact set, and all three were
measured on 2026-09-21 before any gesture was driven:

**Absence is the pre-state, and it is proven positively.** On an unrestricted
CA there is no ``OfficerRights`` value: ``certutil -getreg CA\\OfficerRights``
answers ``0x80070002 ERROR_FILE_NOT_FOUND``. An observer that inferred absence
from a read that failed would be unable to tell "not there" from "could not
look" -- so presence is decided from the key's VALUE-NAME LIST, and the list
is digested into ``certsrv.config.value_names_sha256`` so that any other value
appearing or vanishing is visible too. The digest is recomputed here from the
transported count only in the sense that a disagreement between the two reads
below is refused; the name list itself is never transported, because value
names on a CA are identity-shaped.

**The value is opaque and stays that way.** Its layout is undocumented and
the console is the only sanctioned author, so the facts are presence, byte
length and sha256 -- never the bytes, exactly as the template surface handles
``nTSecurityDescriptor``. A capability that certifies "the configuration now
exists with this digest" is making a claim it can actually support; one that
claimed to know what the bytes mean would not be.

**The same value is read through two stacks.** The registry read gives the
opaque digest; ``certutil -getreg`` asks the CA's own RPC surface and, when
the value exists, decodes it into named rows. They can disagree -- a registry
value written but not yet adopted by the running service would show exactly
that -- and this module refuses the disagreement rather than averaging it:
``present`` and ``decoded_present`` must agree once the value exists. Before
it exists they need not: absence reads cleanly through both, and the rc for a
missing value is a legitimate non-zero.

The forbid scopes (``certsrv.security.*``, ``certsrv.published.*``) are here
because this capability restricts an EXISTING manager and publishes nothing.
The Certificate Managers page says as much on its face ("configured on the
Security tab") -- which is a claim worth checking rather than believing.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from gpo_observers.facts import Fact, make_fact

FactSet = dict[str, Fact]

_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")

# Every key the collector may emit. A line outside this vocabulary refuses the
# whole observation: an observer that ignores what it does not recognise is an
# observer that cannot notice the collector changing under it.
_STRING_KEYS: frozenset[str] = frozenset(
    {"ca.host", "ca.name", "collector.ran_on", "officerrights.kind"}
)
_BOOL_KEYS: frozenset[str] = frozenset(
    {"config.key_present", "officerrights.present", "officerrights.decoded_present"}
)
_COUNT_KEYS: frozenset[str] = frozenset(
    {
        "config.value_count",
        "officerrights.bytes",
        "officerrights.decoded_rows",
        "security.bytes",
        "published.count",
    }
)
_DIGEST_KEYS: frozenset[str] = frozenset(
    {
        "config.value_names_sha256",
        "officerrights.sha256",
        "officerrights.decoded_sha256",
        "security.sha256",
        "published.names_sha256",
    }
)
_INT_KEYS: frozenset[str] = frozenset({"officerrights.certutil_rc"})

_REQUIRED_KEYS: frozenset[str] = (
    _STRING_KEYS | _BOOL_KEYS | _COUNT_KEYS | _DIGEST_KEYS | _INT_KEYS
)


class OfficerRightsError(ValueError):
    """The transported observation could not be trusted; nothing is emitted."""


def _bool(value: str, key: str) -> bool:
    """Decode a PowerShell boolean line; anything else refuses.

    PowerShell renders booleans as ``True``/``False``; the collector writes
    them unquoted. A value outside that pair is a collector change, not a
    value to guess at.
    """
    if value == "True":
        return True
    if value == "False":
        return False
    raise OfficerRightsError(f"officerrights {key} must be True or False, got {value!r}")


def _count(value: str, key: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise OfficerRightsError(
            f"officerrights {key} must be an integer, got {value!r}"
        ) from error
    if parsed < 0:
        raise OfficerRightsError(f"officerrights {key} must not be negative, got {value!r}")
    return parsed


def _int(value: str, key: str) -> int:
    """A signed integer line. certutil's failure rc is negative (-2147024894)."""
    try:
        return int(value)
    except ValueError as error:
        raise OfficerRightsError(
            f"officerrights {key} must be an integer, got {value!r}"
        ) from error


def _digest(value: str, key: str) -> str:
    """A lowercase sha256, or '' for the absent convention."""
    if value == "":
        return ""
    if _SHA256_RE.match(value) is None:
        raise OfficerRightsError(
            f"officerrights {key} must be lowercase sha256 hex or empty, got {value!r}"
        )
    return value


def officerrights_fact_tree(
    lines: Sequence[str], ca_host: str, ca_name: str
) -> FactSet:
    """Build the ``certsrv.*`` facts from one collected line stream.

    ``ca_host`` and ``ca_name`` are the capability's own arguments. They are
    checked against what the collector reports it read, because a fact set
    that does not name its subject cannot be checked against the plan -- and
    on this surface the observed machine is NOT the machine the gesture ran
    on, so a mismatch is exactly the confusion the check exists to catch.
    """
    if not ca_host or not ca_name:
        raise OfficerRightsError("officerrights observation needs a CA host and name")

    raw: dict[str, str] = {}
    for line in lines:
        text = line.strip()
        if not text:
            continue
        if text.startswith("error="):
            raise OfficerRightsError(f"collector refused: {text[len('error='):]}")
        key, sep, value = text.partition("=")
        if not sep:
            raise OfficerRightsError(f"officerrights line is not key=value: {line!r}")
        key = key.strip()
        if key not in _REQUIRED_KEYS:
            raise OfficerRightsError(f"officerrights emitted an unknown key {key!r}")
        if key in raw:
            raise OfficerRightsError(f"officerrights emitted {key!r} twice")
        raw[key] = value.strip()

    missing = sorted(_REQUIRED_KEYS - set(raw))
    if missing:
        raise OfficerRightsError(
            "officerrights observation is incomplete; missing " + ", ".join(missing)
        )

    # The subject check: the collector read what the plan named.
    if raw["ca.host"].casefold() != ca_host.casefold():
        raise OfficerRightsError(
            f"officerrights read CA host {raw['ca.host']!r}, plan named {ca_host!r}"
        )
    if raw["ca.name"] != ca_name:
        raise OfficerRightsError(
            f"officerrights read CA name {raw['ca.name']!r}, plan named {ca_name!r}"
        )
    if not _bool(raw["config.key_present"], "config.key_present"):
        raise OfficerRightsError(
            f"CA configuration key for {ca_name!r} absent on {ca_host!r}"
        )

    present = _bool(raw["officerrights.present"], "officerrights.present")
    decoded_present = _bool(
        raw["officerrights.decoded_present"], "officerrights.decoded_present"
    )
    sha = _digest(raw["officerrights.sha256"], "officerrights.sha256")
    size = _count(raw["officerrights.bytes"], "officerrights.bytes")

    # Internal agreement, checked before anything is published.
    if present and (not sha or size == 0):
        raise OfficerRightsError(
            "officerrights is present but carries no digest or zero length"
        )
    if not present and (sha or size):
        raise OfficerRightsError(
            "officerrights is absent but carries a digest or a non-zero length"
        )
    # The two stacks must agree that the value exists. They need NOT agree
    # while it does not: a missing value reads cleanly through the registry
    # and legitimately fails through certutil.
    if present and not decoded_present:
        raise OfficerRightsError(
            "officerrights exists in the registry but the CA's own RPC surface "
            f"would not decode it (certutil rc {raw['officerrights.certutil_rc']}); "
            "the two channels disagree about a value that is supposed to be live"
        )
    if decoded_present and not present:
        raise OfficerRightsError(
            "the CA decoded an OfficerRights value the registry does not hold"
        )

    security_sha = _digest(raw["security.sha256"], "security.sha256")
    if not security_sha:
        raise OfficerRightsError("the CA's Security descriptor digest is empty")

    facts: FactSet = {}

    def put(key: str, value: object) -> None:
        facts[key] = make_fact(key, value)

    put("certsrv.ca.host", raw["ca.host"])
    put("certsrv.ca.name", raw["ca.name"])
    put("certsrv.ca.observed_from", raw["collector.ran_on"])
    put("certsrv.config.value_count", _count(raw["config.value_count"], "config.value_count"))
    put(
        "certsrv.config.value_names_sha256",
        _digest(raw["config.value_names_sha256"], "config.value_names_sha256"),
    )
    put("certsrv.officerrights.present", present)
    put("certsrv.officerrights.kind", raw["officerrights.kind"])
    put("certsrv.officerrights.bytes", size)
    put("certsrv.officerrights.sha256", sha)
    put("certsrv.officerrights.decoded_present", decoded_present)
    put(
        "certsrv.officerrights.decoded_rows",
        _count(raw["officerrights.decoded_rows"], "officerrights.decoded_rows"),
    )
    put(
        "certsrv.officerrights.decoded_sha256",
        _digest(raw["officerrights.decoded_sha256"], "officerrights.decoded_sha256"),
    )
    put(
        "certsrv.officerrights.certutil_rc",
        _int(raw["officerrights.certutil_rc"], "officerrights.certutil_rc"),
    )
    put("certsrv.security.bytes", _count(raw["security.bytes"], "security.bytes"))
    put("certsrv.security.sha256", security_sha)
    put("certsrv.published.count", _count(raw["published.count"], "published.count"))
    put(
        "certsrv.published.names_sha256",
        _digest(raw["published.names_sha256"], "published.names_sha256"),
    )
    return facts
