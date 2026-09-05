"""Pre/post snapshots: run the whole R2 observer set, normalize to facts.

A snapshot is a :class:`FactSet` -- ``{dotted key: Fact}`` -- built by
running every observer against one injectable transport and one GPO
reference. The fact-key scheme:

- ``gpo_identity.guid`` / ``gpo_identity.domain_dns``
- ``ad.<AttributeName>`` (the seven selected GPC attributes)
- ``version.raw`` / ``version.machine`` / ``version.user`` /
  ``version.displayName`` / ``version.ad_versionNumber``
- ``scripts_ini.<side>.*`` (scripts.ini) and ``scripts_ini.ps.<side>.*``
  (psscripts.ini): ``encoding.*``, ``<Section>.<index>.script/.parameters/
  .raw/.prop.<Prop>``, ``config_shape``, ``policy.<Key>``,
  ``scripts_config.<Key>``, ``present``
- ``sysvol.<relpath>.sha256`` / ``sysvol.<relpath>.bytes`` and
  ``sysvol.passes_match``
- ``scope.extension_lists.machine`` / ``scope.extension_lists.user`` /
  ``scope.policies.gpc_guids`` / ``scope.sysvol_relpaths``

System-path rule: GPT.INI and the scripts INIs are **excluded** from the
per-file ``sysvol.*`` hash facts. Their semantics are captured by dedicated
observers (version values, INI entries); hashing them as well would change a
fact on every edit and drown the delta in noise. Their bytes still travel
(scripts_ini_raw base64, version_values gpt_ini_b64) and they still appear
in the fingerprint's in-guest two-pass comparison, so nothing is unobserved
-- it is just factored, not hashed into per-file facts.

Categories are assigned by the declared table in
:mod:`gpo_observers.facts`; keys the table does not know (including every
per-file ``sysvol.<relpath>.sha256``) come out ``unclassified``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import PureWindowsPath

from .collection import (
    AD_ATTRIBUTE_NAMES,
    Transport,
    observe_ad_attributes,
    observe_identity,
    observe_scope,
    observe_scripts_ini,
    observe_sysvol_fingerprint,
    observe_version_values,
)
from .facts import FactSet, make_fact

_SIDES: frozenset[str] = frozenset({"machine", "user"})

# Files whose semantics dedicated observers already carry. Relpaths are
# posix-normalized and matched case-insensitively.
SYSTEM_FILE_RELPATHS: frozenset[str] = frozenset(
    {
        "gpt.ini",
        "machine/scripts/scripts.ini",
        "machine/scripts/psscripts.ini",
        "user/scripts/scripts.ini",
        "user/scripts/psscripts.ini",
        # R3/R4 additions: files whose bytes dedicated observers transport and
        # parse (gpttmpl_inf, fdeploy_ini). Hashing them here would duplicate
        # the dedicated facts and drown the delta in noise -- same rule as
        # GPT.INI above.
        "machine/microsoft/windows nt/secedit/gpttmpl.inf",
        "user/documents & settings/fdeploy.ini",
        "user/documents & settings/fdeploy1.ini",
    }
)


@dataclass(frozen=True, slots=True)
class GpoRef:
    """The GPO reference every observer is run against.

    ``sysvol_path`` is the Windows path of the GPO's SYSVOL directory, e.g.
    ``\\\\corp.example.com\\SYSVOL\\corp.example.com\\Policies\\{guid}``.
    """

    gpo_guid: str
    domain_dns: str
    sysvol_path: str

    def scripts_dir(self, side: str) -> str:
        if side not in _SIDES:
            raise ValueError(f"side must be 'machine' or 'user', got {side!r}")
        return str(PureWindowsPath(self.sysvol_path) / side.capitalize() / "Scripts")

    @property
    def gpt_ini_path(self) -> str:
        return str(PureWindowsPath(self.sysvol_path) / "GPT.INI")


def is_system_relpath(relpath: str) -> bool:
    """True for files excluded from per-file hash facts (see module doc)."""
    return relpath.casefold() in SYSTEM_FILE_RELPATHS


def capture_snapshot(
    transport: Transport,
    gpo: GpoRef,
    *,
    ad_server: str = "",
    scripts_sides: Sequence[str] = ("machine",),
) -> FactSet:
    """Run every R2 observer against *transport* and return the FactSet."""
    for side in scripts_sides:
        if side not in _SIDES:
            raise ValueError(f"side must be 'machine' or 'user', got {side!r}")
    facts: FactSet = {}

    identity = observe_identity(transport, gpo_guid=gpo.gpo_guid, domain_dns=gpo.domain_dns)
    facts["gpo_identity.guid"] = make_fact("gpo_identity.guid", identity.gpo_guid)
    facts["gpo_identity.domain_dns"] = make_fact("gpo_identity.domain_dns", identity.domain_dns)

    ad = observe_ad_attributes(transport, gpo_guid=gpo.gpo_guid, server=ad_server)
    for name in AD_ATTRIBUTE_NAMES:
        facts[f"ad.{name}"] = make_fact(f"ad.{name}", ad[name])

    versions = observe_version_values(
        transport, gpt_ini_path=gpo.gpt_ini_path, gpo_guid=gpo.gpo_guid, server=ad_server
    )
    facts["version.raw"] = make_fact("version.raw", versions.gpt_version_raw)
    facts["version.machine"] = make_fact("version.machine", versions.machine)
    facts["version.user"] = make_fact("version.user", versions.user)
    facts["version.displayName"] = make_fact("version.displayName", versions.display_name)
    facts["version.ad_versionNumber"] = make_fact(
        "version.ad_versionNumber", versions.ad_version_number
    )

    for side in scripts_sides:
        side_facts = observe_scripts_ini(
            transport, scripts_dir=gpo.scripts_dir(side), side=side
        )
        for key, value in side_facts.items():
            facts[key] = make_fact(key, value)

    fingerprint = observe_sysvol_fingerprint(transport, sysvol_path=gpo.sysvol_path)
    for file in fingerprint.files:
        if is_system_relpath(file.relpath):
            continue
        facts[f"sysvol.{file.relpath}.sha256"] = make_fact(
            f"sysvol.{file.relpath}.sha256", file.sha256
        )
        facts[f"sysvol.{file.relpath}.bytes"] = make_fact(
            f"sysvol.{file.relpath}.bytes", file.bytes
        )
    facts["sysvol.passes_match"] = make_fact("sysvol.passes_match", fingerprint.passes_match)

    scope = observe_scope(
        transport,
        gpo_guid=gpo.gpo_guid,
        domain_dns=gpo.domain_dns,
        sysvol_gpo_path=gpo.sysvol_path,
    )
    facts["scope.extension_lists.machine"] = make_fact(
        "scope.extension_lists.machine", scope.extension_list_machine
    )
    facts["scope.extension_lists.user"] = make_fact(
        "scope.extension_lists.user", scope.extension_list_user
    )
    facts["scope.policies.gpc_guids"] = make_fact(
        "scope.policies.gpc_guids", list(scope.policies_gpc_guids)
    )
    facts["scope.sysvol_relpaths"] = make_fact(
        "scope.sysvol_relpaths", list(scope.sysvol_relpaths)
    )
    # The containment boolean the declarative forbid clause consumes. The
    # relpaths are relative to THIS GPO's directory (psl.scope_forbid), so
    # containment means no path escapes it (no parent traversal, no
    # absolute). Emitted as an ordinary structural fact so bounded predicate
    # expressions can reference it.
    contained = all(
        isinstance(relpath, str)
        and not relpath.startswith("/")
        and ".." not in relpath.split("/")
        for relpath in scope.sysvol_relpaths
    )
    facts["scope.sysvol_contained"] = make_fact("scope.sysvol_contained", contained)
    return facts
