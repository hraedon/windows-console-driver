"""Estate configuration: how to reach one disposable lab console (wcd CLI side).

The WEL backend passes a transaction plan with credential *env-var names*
only; the deployment-level facts -- which Hyper-V host, which VM, which
console user, where the helper task lives -- are the console driver's own
configuration and live in an estate file (``local/estate.toml``, not
committed: it names a real host). Passwords never sit in the file either:
it names the environment variable each secret is read from at launch, the
same credential-broker discipline the rest of the project uses.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path


class EstateError(RuntimeError):
    """The estate file is missing, malformed, or names unset secrets."""


@dataclass(frozen=True, slots=True)
class EstateConfig:
    """Deployment facts for one lab console, plus secret env-var names."""

    host: str
    vm_name: str
    domain: str
    username: str
    password_env: str
    helper_task: str = "WCDHelper"
    helper_dir: str = "C:\\lab\\wcd"
    guest_scripts_dir: str = "C:\\lab\\wcd\\scripts"
    # Exact recovery point qualified for this disposable VM.  An empty value
    # deliberately makes checkpoint-backed execution fail closed.
    checkpoint_name: str = ""
    # Controller-side anchor directory for evidence artifacts (screenshots).
    # Explicit default: when unset (empty), the driver anchors evidence to its
    # OWN repository's ``runs/`` directory -- a location derived from the
    # deployment, never from the process working directory, so the evidence
    # path cannot depend on where wcd was invoked from.
    evidence_dir: str = ""

    def resolved_password(self) -> str:
        """The secret behind ``password_env``; never logged, never recorded."""
        secret = os.environ.get(self.password_env, "")
        if not secret:
            raise EstateError(
                f"environment variable {self.password_env!r} is not set; the estate "
                "file names secrets, it never carries them"
            )
        return secret


def load_estate(path: str | Path) -> EstateConfig:
    """Load and validate the estate TOML at *path*.

    Required keys: ``host``, ``vm_name``, ``domain``, ``username``,
    ``password_env``. Optional: ``helper_task``, ``helper_dir``,
    ``guest_scripts_dir``, ``checkpoint_name``, ``evidence_dir``. Unknown keys are refused (a
    misspelled secret name must fail loudly, not silently unlock nothing).
    """
    path = Path(path)
    if not path.is_file():
        raise EstateError(f"estate file not found: {path}")
    with path.open("rb") as handle:
        try:
            data = tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            raise EstateError(f"estate file {path} is not valid TOML: {exc}") from exc
    table = data.get("estate")
    if not isinstance(table, dict):
        raise EstateError(f"estate file {path} must carry an [estate] table")
    known = {
        "host",
        "vm_name",
        "domain",
        "username",
        "password_env",
        "helper_task",
        "helper_dir",
        "guest_scripts_dir",
        "checkpoint_name",
        "evidence_dir",
    }
    unknown = set(table) - known
    if unknown:
        raise EstateError(f"estate file {path} has unknown keys: {sorted(unknown)}")
    missing = {"host", "vm_name", "domain", "username", "password_env"} - set(table)
    if missing:
        raise EstateError(f"estate file {path} is missing keys: {sorted(missing)}")
    values: dict[str, str] = {}
    for key in known:
        value = table.get(key)
        if value is None:
            continue
        if not isinstance(value, str) or not value.strip():
            raise EstateError(f"estate key {key!r} must be a non-blank string")
        values[key] = value
    return EstateConfig(
        host=values["host"],
        vm_name=values["vm_name"],
        domain=values["domain"],
        username=values["username"],
        password_env=values["password_env"],
        helper_task=values.get("helper_task", "WCDHelper"),
        helper_dir=values.get("helper_dir", "C:\\lab\\wcd"),
        guest_scripts_dir=values.get("guest_scripts_dir", "C:\\lab\\wcd\\scripts"),
        checkpoint_name=values.get("checkpoint_name", ""),
        evidence_dir=values.get("evidence_dir", ""),
    )
