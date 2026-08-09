from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from datetime import date
from typing import Any

from .config import SUPPORTED_TOOLS, SuiteConfig
from .execution import sha256_file
from .path_safety import resolve_regular_file


_MAXIMUM_CATALOG_BYTES = 16 * 1024 * 1024
_MAXIMUM_ENTRIES = 5_000
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(slots=True)
class TrustCatalogResult:
    artifact: dict[str, Any]
    errors: list[str]


def apply_trust_catalog(config: SuiteConfig) -> TrustCatalogResult:
    """Apply organization-approved executable digests without weakening explicit pins."""
    path = config.trust.catalog_path
    if path is None:
        return TrustCatalogResult(
            artifact={
                "schema_version": "1.0",
                "configured": False,
                "applied": [],
                "errors": [],
            },
            errors=[],
        )

    errors: list[str] = []
    applied: list[dict[str, str]] = []
    ignored: list[dict[str, str]] = []
    metadata: dict[str, str] = {}
    observed_digest = ""
    try:
        source = resolve_regular_file(path, "scanner trust catalog")
        size = source.stat().st_size
        if size > _MAXIMUM_CATALOG_BYTES:
            raise ValueError(
                f"scanner trust catalog exceeds {_MAXIMUM_CATALOG_BYTES} bytes"
            )
        observed_digest = sha256_file(source)
        if observed_digest != config.trust.catalog_sha256:
            raise ValueError(
                "scanner trust catalog SHA-256 mismatch: "
                f"expected {config.trust.catalog_sha256}, observed {observed_digest}"
            )
        document = json.loads(source.read_bytes())
        entries, metadata = _validate_document(document)
        seen: set[tuple[str, str]] = set()
        for index, entry in enumerate(entries):
            tool = _required_string(entry, "tool", index)
            role = _required_string(entry, "role", index)
            digest = _required_string(entry, "sha256", index).casefold()
            version = _required_string(entry, "version", index)
            source_label = _required_string(entry, "source", index)
            approved_by = _required_string(entry, "approved_by", index)
            expires = _required_string(entry, "expires", index)
            platforms = _platforms(entry, index)
            _validate_entry(tool, role, digest, expires, index)
            identity = (tool, role)
            if identity in seen:
                raise ValueError(
                    f"scanner trust catalog contains duplicate {tool}/{role} entry"
                )
            seen.add(identity)
            if "any" not in platforms and sys.platform not in platforms:
                ignored.append(
                    {"tool": tool, "role": role, "reason": "platform_not_applicable"}
                )
                continue
            if date.fromisoformat(expires) < date.today():
                errors.append(f"scanner trust entry {tool}/{role} expired on {expires}")
                continue
            if tool not in config.tools:
                ignored.append(
                    {"tool": tool, "role": role, "reason": "tool_not_configured"}
                )
                continue
            setting = (
                "executable_sha256"
                if role == "primary"
                else "auxiliary_executable_sha256"
            )
            current = str(getattr(config.tools[tool], setting) or "")
            if current:
                ignored.append(
                    {"tool": tool, "role": role, "reason": "explicit_pin_precedence"}
                )
                continue
            setattr(config.tools[tool], setting, digest)
            authority_setting = (
                "executable_organization_approved"
                if role == "primary"
                else "auxiliary_executable_organization_approved"
            )
            setattr(
                config.tools[tool],
                authority_setting,
                config.trust.catalog_organization_approved,
            )
            applied.append(
                {
                    "tool": tool,
                    "role": role,
                    "sha256": digest,
                    "version": version,
                    "source": source_label,
                    "approved_by": approved_by,
                    "expires": expires,
                }
            )
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        errors.append(str(exc))

    artifact: dict[str, Any] = {
        "schema_version": "1.0",
        "configured": True,
        "catalog": {
            "path": str(path),
            "expected_sha256": config.trust.catalog_sha256,
            "observed_sha256": observed_digest,
            **metadata,
        },
        "platform": sys.platform,
        "applied": sorted(applied, key=lambda item: (item["tool"], item["role"])),
        "ignored": sorted(ignored, key=lambda item: (item["tool"], item["role"])),
        "errors": errors,
    }
    return TrustCatalogResult(artifact=artifact, errors=errors)


def _validate_document(value: object) -> tuple[list[dict[str, Any]], dict[str, str]]:
    if not isinstance(value, dict):
        raise ValueError("scanner trust catalog must be a JSON object")
    if value.get("schema_version") != "1.0":
        raise ValueError("scanner trust catalog schema_version must be '1.0'")
    if value.get("status") != "approved":
        raise ValueError("scanner trust catalog status must be 'approved'")
    catalog_id = _document_string(value, "catalog_id")
    revision = _document_string(value, "revision")
    entries = value.get("entries")
    if not isinstance(entries, list):
        raise ValueError("scanner trust catalog entries must be an array")
    if len(entries) > _MAXIMUM_ENTRIES:
        raise ValueError(f"scanner trust catalog exceeds {_MAXIMUM_ENTRIES} entries")
    if any(not isinstance(entry, dict) for entry in entries):
        raise ValueError("each scanner trust catalog entry must be an object")
    return entries, {"catalog_id": catalog_id, "revision": revision}


def _document_string(document: dict[str, Any], name: str) -> str:
    value = document.get(name)
    if not isinstance(value, str) or not value.strip() or len(value) > 200:
        raise ValueError(f"scanner trust catalog {name} must be a non-empty string")
    return value.strip()


def _required_string(entry: dict[str, Any], name: str, index: int) -> str:
    value = entry.get(name)
    if not isinstance(value, str) or not value.strip() or len(value) > 500:
        raise ValueError(
            f"scanner trust entry {index} {name} must be a non-empty string"
        )
    return value.strip()


def _platforms(entry: dict[str, Any], index: int) -> tuple[str, ...]:
    value = entry.get("platforms", ["any"])
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 20
        or any(not isinstance(item, str) or not item.strip() for item in value)
    ):
        raise ValueError(
            f"scanner trust entry {index} platforms must be a string array"
        )
    return tuple(item.strip().casefold() for item in value)


def _validate_entry(
    tool: str, role: str, digest: str, expires: str, index: int
) -> None:
    if tool not in SUPPORTED_TOOLS:
        raise ValueError(f"scanner trust entry {index} has unsupported tool {tool!r}")
    if role not in {"primary", "auxiliary"}:
        raise ValueError(
            f"scanner trust entry {index} role must be primary or auxiliary"
        )
    if not _SHA256.fullmatch(digest):
        raise ValueError(
            f"scanner trust entry {index} sha256 must be 64 hex characters"
        )
    try:
        date.fromisoformat(expires)
    except ValueError as exc:
        raise ValueError(
            f"scanner trust entry {index} expires must use YYYY-MM-DD"
        ) from exc
