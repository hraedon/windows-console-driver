"""Load-time validation for capability documents.

The CLI is the WEL execution seam, so malformed capability artifacts are
rejected there before any transport, lease, console, or estate mutation can
start.  Validation uses the same Draft 2020-12 document exercised in CI.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, NoReturn

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

CAPABILITY_SCHEMA_REF = "docs/capability-schema-v0.json"


class CapabilitySchemaError(ValueError):
    """A capability or its governing schema is malformed."""


def _fail(message: str) -> NoReturn:
    raise CapabilitySchemaError(message)


def validate_capability_document(capability: object, repo_root: Path) -> None:
    """Validate one parsed capability before the execution boundary."""
    if not isinstance(capability, dict):
        _fail("document must be a JSON object")
    schema_path = repo_root / CAPABILITY_SCHEMA_REF
    try:
        schema: Any = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, SchemaError) as exc:
        _fail(f"cannot load {CAPABILITY_SCHEMA_REF}: {exc}")

    errors = sorted(
        Draft202012Validator(schema).iter_errors(capability),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if not errors:
        return
    error = errors[0]
    location = ".".join(str(part) for part in error.absolute_path) or "<root>"
    _fail(f"{location}: {error.message}")


def validate_capability_arguments(
    capability: Mapping[str, object], arguments: object
) -> None:
    """Validate invocation arguments against the capability's own schema."""
    parameter_schema = capability.get("parameters")
    if not isinstance(parameter_schema, dict):
        _fail("parameters: must be a JSON Schema object")
    errors = sorted(
        Draft202012Validator(parameter_schema).iter_errors(arguments),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if not errors:
        return
    error = errors[0]
    location = ".".join(str(part) for part in error.absolute_path) or "<root>"
    _fail(f"arguments.{location}: {error.message}")
