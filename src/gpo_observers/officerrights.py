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
opaque digest; ``certutil -getreg`` asks the CA's own RPC surface and, when the
value exists, decodes it into named rows. They can disagree -- a registry
value written but not yet adopted by the running service would show exactly
that -- and this module refuses the disagreement rather than averaging it:
``present`` and ``decoded_present`` must agree once the value exists. Before
it exists they need not: absence reads cleanly through both, and the rc for a
missing value is a legitimate non-zero.

**The CA host is derived from the directory, not echoed (revision 2).** The
``ca.host`` subject check below compares what the collector read against the
plan's argument -- but the collector is INVOKED with that same argument, so
both sides of the comparison are the echo. That catches a garbled or
misrouted read and nothing else; a plan that itself names the wrong CA drives
gesture and oracle alike and passes the check all the way down (the window-11
correction, 2026-09-22). Revision 2 closes the gap at the independent
source: every enterprise CA publishes a ``pKIEnrollmentService`` object under
``CN=Enrollment Services``, each carrying ``dNSHostName``, and the collector
enumerates the class -- taking no input from the plan -- and transports the
derived host set whole. The count and digest are recomputed here from the
transported list and refused on disagreement (the certtmpl two-pass
discipline), and an observation whose plan host is NOT a member of the
derived set refuses here: the pre-oracle runs before prepare, arm and the
commit, so a wrong-CA plan is refused before any mutation, fail-closed.

The forbid scopes (``certsrv.security.*``, ``certsrv.published.*``) are here
because this capability restricts an EXISTING manager and publishes nothing.
The Certificate Managers page says as much on its face ("configured on the
Security tab") -- which is a claim worth checking rather than believing.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence

from gpo_observers.facts import Fact, make_fact

FactSet = dict[str, Fact]

_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")

# Every key the collector may emit. A line outside this vocabulary refuses the
# whole observation: an observer that ignores what it does not recognise is an
# observer that cannot notice the collector changing under it.
_STRING_KEYS: frozenset[str] = frozenset(
    {"ca.host", "ca.name", "ca.directory.hosts", "collector.ran_on", "officerrights.kind"}
)
_BOOL_KEYS: frozenset[str] = frozenset(
    {"config.key_present", "officerrights.present", "officerrights.decoded_present"}
)
_COUNT_KEYS: frozenset[str] = frozenset(
    {
        "ca.directory.count",
        "config.value_count",
        "officerrights.bytes",
        "officerrights.decoded_rows",
        "security.bytes",
        "published.count",
    }
)
_DIGEST_KEYS: frozenset[str] = frozenset(
    {
        "ca.directory.hosts_sha256",
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


def _hosts_digest(hosts: Sequence[str]) -> str:
    """sha256 over the LF-joined host list (UTF-8, lowercase hex).

    The same convention the certtmpl surface uses for name lists: the
    transported list is the record, the digest is what the facts commit.
    """
    return hashlib.sha256("\n".join(hosts).encode("utf-8")).hexdigest()


def officerrights_fact_tree(
    lines: Sequence[str], ca_host: str, ca_name: str
) -> FactSet:
    """Build the ``certsrv.*`` facts from one collected line stream.

    ``ca_host`` and ``ca_name`` are the capability's own arguments. They are
    checked against what the collector reports it read, because a fact set
    that does not name its subject cannot be checked against the plan -- and
    on this surface the observed machine is NOT the machine the gesture ran
    on, so a mismatch is exactly the confusion the check exists to catch.
    Since revision 2 ``ca_host`` is additionally checked against the
    directory-derived CA host set the collector enumerates independently of
    the plan: a plan that names a host the forest does not publish as a CA
    refuses here, at the pre-oracle -- before prepare, arm, or any mutation.
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

    # The subject check, revision 1: the collector read what the plan named.
    # Both sides of this comparison are the plan's argument (the collector
    # reports ca.host as the argument it was invoked with), so it catches a
    # garbled or misrouted read -- the plan's CA name arriving wrong at the
    # guest -- and nothing else.
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

    # The subject check, revision 2: what the plan named is a CA the
    # directory knows. Unlike the echo check above, this one's right-hand
    # side is derived independently of the plan -- the forest's
    # pKIEnrollmentService objects, enumerated by class, not bound by any
    # name the plan supplied. The count and digest are recomputed from the
    # transported list and refused on disagreement before membership is
    # decided, so a collector that shrank or reordered the set cannot make a
    # wrong host look like a member.
    directory_hosts: list[str] = (
        [] if raw["ca.directory.hosts"] == "" else raw["ca.directory.hosts"].split(";")
    )
    if any(not host for host in directory_hosts):
        raise OfficerRightsError(
            "officerrights ca.directory.hosts has an empty entry: "
            f"{raw['ca.directory.hosts']!r}"
        )
    directory_count = _count(raw["ca.directory.count"], "ca.directory.count")
    if directory_count != len(directory_hosts):
        raise OfficerRightsError(
            f"officerrights ca.directory.count is {directory_count} but the "
            f"transported host list holds {len(directory_hosts)} host(s)"
        )
    directory_sha = _digest(
        raw["ca.directory.hosts_sha256"], "ca.directory.hosts_sha256"
    )
    if not directory_sha:
        raise OfficerRightsError(
            "the directory-derived CA host set digest is empty; the derivation "
            "is a membership source, not an absence-shaped value"
        )
    if directory_sha != _hosts_digest(directory_hosts):
        raise OfficerRightsError(
            "officerrights ca.directory.hosts_sha256 disagrees with the "
            "transported host list"
        )
    directory_member = ca_host.casefold() in {h.casefold() for h in directory_hosts}
    if not directory_member:
        derived = ", ".join(directory_hosts) if directory_hosts else "empty set"
        raise OfficerRightsError(
            f"plan CA host {ca_host!r} is not in the directory-derived CA host "
            f"set ({derived}); the plan names a host the forest does not "
            "publish as a CA"
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
    # The directory-derived host set: membership as a fact so the record
    # carries the claim, the set itself committed as count+digest only --
    # the same never-the-name-list convention as every container digest in
    # this package. member is True by construction (a non-member refuses
    # above, before any mutation); the require clause that pins it is the
    # envelope's record-facing statement of that refusal.
    put("certsrv.ca.directory.count", directory_count)
    put("certsrv.ca.directory.hosts_sha256", directory_sha)
    put("certsrv.ca.directory.member", directory_member)
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
