from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from py_security_suite.benchmark_assurance import _ROLES
from py_security_suite.benchmark_protocols import PROTOCOL_THRESHOLD_FIELDS
from py_security_suite.benchmark_semantic_evidence import (
    CANONICALIZATION,
    SIMILARITY_ALGORITHM,
)
from py_security_suite.benchmark_signing import (
    _CREDENTIAL_MODES,
    _PROVIDER_BACKENDS,
)
from py_security_suite.report_inspection import BUNDLED_SCHEMA_RESOURCES


_ROOT = Path(__file__).resolve().parents[1]
_SCHEMAS = _ROOT / "src" / "py_security_suite" / "schemas"
_VERSIONED_NAME = re.compile(r"-(\d+\.\d+)\.schema\.json$")


def _schema(name: str) -> dict[str, Any]:
    value = json.loads((_SCHEMAS / name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{name} schema root is not an object")
    return value


def _mapping(value: object, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not an object")
    return value


def _enum(schema: dict[str, Any], *path: str) -> set[str]:
    current: object = schema
    for segment in path:
        current = _mapping(current, ".".join(path)).get(segment)
    if not isinstance(current, list) or not all(
        isinstance(item, str) for item in current
    ):
        raise ValueError(f"{'.'.join(path)} is not a string enum")
    return set(current)


def _const(schema: dict[str, Any], *path: str) -> object:
    current: object = schema
    for segment in path:
        if not isinstance(current, dict):
            return None
        current = current.get(segment)
    return current


def main() -> int:
    failures: list[str] = []
    schema_files = sorted(_SCHEMAS.glob("*.schema.json"))
    identifiers: dict[str, str] = {}
    loaded: dict[str, dict[str, Any]] = {}
    for path in schema_files:
        try:
            schema = _schema(path.name)
            Draft202012Validator.check_schema(schema)
            identifier = schema.get("$id")
            if not isinstance(identifier, str) or not identifier:
                raise ValueError("$id is missing")
            if identifier in identifiers:
                raise ValueError(f"$id duplicates {identifiers[identifier]}")
            identifiers[identifier] = path.name
            if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
                raise ValueError("must declare JSON Schema draft 2020-12")
            match = _VERSIONED_NAME.search(path.name)
            declared_version = _const(schema, "properties", "schema_version", "const")
            if (
                match
                and declared_version is not None
                and declared_version != match.group(1)
            ):
                raise ValueError(
                    f"schema_version {declared_version!r} differs from filename version"
                )
            loaded[path.name] = schema
        except (KeyError, TypeError, ValueError) as exc:
            failures.append(f"{path.name}: {exc}")

    for resource, filename in BUNDLED_SCHEMA_RESOURCES.items():
        if filename not in loaded:
            failures.append(
                f"bundled resource {resource} references missing {filename}"
            )

    try:
        protocols = set(PROTOCOL_THRESHOLD_FIELDS)
        for version in ("1.0", "1.1", "1.2"):
            schema = loaded[f"benchmark-adapter-manifest-{version}.schema.json"]
            if _enum(schema, "properties", "protocol", "enum") != protocols:
                failures.append(
                    f"adapter manifest {version} protocols drift from runtime"
                )

        for version in ("1.0", "1.1"):
            schema = loaded[f"benchmark-authority-trust-policy-{version}.schema.json"]
            if (
                _enum(
                    schema,
                    "$defs",
                    "authority",
                    "properties",
                    "role",
                    "enum",
                )
                != _ROLES
            ):
                failures.append(f"authority policy {version} roles drift from runtime")

        provider = loaded["benchmark-signing-provider-profile-1.0.schema.json"]
        if _enum(provider, "properties", "backend", "enum") != _PROVIDER_BACKENDS:
            failures.append("signing-provider backends drift from runtime")
        if (
            _enum(provider, "properties", "credential_mode", "enum")
            != _CREDENTIAL_MODES
        ):
            failures.append("signing-provider credential modes drift from runtime")

        for kind in ("leakage", "duplicate", "contamination"):
            schema = loaded[f"benchmark-{kind}-analysis-1.2.schema.json"]
            if (
                _const(schema, "properties", "canonicalization", "const")
                != CANONICALIZATION
            ):
                failures.append(f"{kind} canonicalization drifts from runtime")
            if (
                _const(schema, "properties", "similarity_algorithm", "const")
                != SIMILARITY_ALGORITHM
            ):
                failures.append(f"{kind} similarity algorithm drifts from runtime")

        registry = loaded["benchmark-registry-1.0.schema.json"]
        required = _const(registry, "required")
        if not isinstance(required, list) or "receipt_authority_policy" not in required:
            failures.append(
                "benchmark registry does not require external receipt policy"
            )
    except (KeyError, TypeError, ValueError) as exc:
        failures.append(f"benchmark contract consistency check failed: {exc}")

    if failures:
        raise SystemExit("\n".join(failures))
    print(
        "benchmark schema/runtime consistency validated "
        f"for {len(loaded)} schemas and {len(BUNDLED_SCHEMA_RESOURCES)} exports"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
