from __future__ import annotations

import hashlib
import tomllib
from collections.abc import Mapping
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .config import ConfigurationError, load_config
from .path_safety import resolve_regular_file


_SCHEMA_ID = "urn:project-py-security-suite:schema:config-advice:1.0"
_CURRENT_SCHEMA = "1"
_MAX_CONFIG_BYTES = 4 * 1024 * 1024
_PATH_KEYS = {
    "artifacts_path",
    "approval_path",
    "baseline_path",
    "bundle_root",
    "coverage_path",
    "database_path",
    "evidence_path",
    "executable",
    "kev_path",
    "provenance_path",
    "public_key_path",
    "risk_acceptance_path",
    "rules_path",
    "auxiliary_executable",
    "catalog_path",
    "epss_path",
    "vex_path",
}


def advise_configuration(
    *,
    repository_config: Path,
    organization_policy: Path | None = None,
    profile_override: str | None = None,
) -> dict[str, Any]:
    """Validate configuration and produce bounded migration/portability advice."""
    repository, repository_source, repository_error = _read_source(
        repository_config, "repository configuration"
    )
    organization: dict[str, Any] = {}
    organization_source: dict[str, Any] | None = None
    organization_error = ""
    if organization_policy is not None:
        organization, organization_source, organization_error = _read_source(
            organization_policy, "organization policy"
        )

    errors = [error for error in (repository_error, organization_error) if error]
    effective = None
    if not errors:
        try:
            config = load_config(
                organization_policy=organization_policy,
                repository_config=repository_config,
                profile_override=profile_override,
            )
        except (ConfigurationError, OSError, TypeError, ValueError) as exc:
            errors.append(str(exc))
        else:
            effective = {
                "schema_version": config.schema_version,
                "profile": config.profile,
                "selected_tools": list(config.selected_tools),
                "required_tools": list(config.required_tools),
                "network": config.isolation.network,
                "execute_target_code": config.isolation.execute_target_code,
                "bundle_namespace": "@bundle/",
            }

    declared_schema = repository.get("schema_version")
    schema_text = str(declared_schema) if declared_schema is not None else None
    migration_required = schema_text not in (None, _CURRENT_SCHEMA)
    migration_actions: list[str] = []
    if schema_text is None:
        migration_actions.append(
            'Declare schema_version = "1" explicitly before the next controlled update.'
        )
    elif migration_required:
        migration_actions.append(
            "Regenerate a current configuration with `pysec init`, then review and "
            "merge governed settings; automatic semantic migration is intentionally disabled."
        )

    repository_paths = _path_inventory(repository)
    organization_paths = _path_inventory(organization)
    all_paths = [*repository_paths, *organization_paths]
    recommendations: list[dict[str, str]] = []
    if schema_text is None:
        recommendations.append(
            _recommendation(
                "P2",
                "schema",
                'Pin schema_version = "1" so future compatibility decisions are explicit.',
                "schema_version",
            )
        )
    if any(item["kind"] == "absolute" for item in all_paths):
        recommendations.append(
            _recommendation(
                "P2",
                "portability",
                "Replace bundle-owned absolute asset paths with traversal-safe @bundle/... references.",
                "paths.bundle_root",
            )
        )
    repository_digest_settings = _declared_digest_settings(repository)
    if repository_digest_settings:
        recommendations.append(
            _recommendation(
                "P1",
                "authority",
                "Repository digest pins detect substitution but do not grant organization approval; mirror approved identities in the organization policy.",
                ", ".join(repository_digest_settings[:8]),
            )
        )
    decision = (
        "invalid" if errors else "valid_with_advice" if recommendations else "valid"
    )
    return {
        "schema_version": "1.0",
        "schema_id": _SCHEMA_ID,
        "authoritative": False,
        "decision": decision,
        "sources": {
            "repository": repository_source,
            "organization": organization_source,
        },
        "compatibility": {
            "declared_schema": schema_text,
            "current_schema": _CURRENT_SCHEMA,
            "supported_schemas": [_CURRENT_SCHEMA],
            "migration_required": migration_required,
            "automatic_migration_performed": False,
            "actions": migration_actions,
        },
        "effective": effective,
        "path_inventory": {
            "configured": len(all_paths),
            "portable_bundle": sum(item["kind"] == "bundle" for item in all_paths),
            "relative": sum(item["kind"] == "relative" for item in all_paths),
            "absolute": sum(item["kind"] == "absolute" for item in all_paths),
            "settings": all_paths,
        },
        "validation_errors": errors,
        "recommendations": recommendations,
        "scope": (
            "Read-only configuration validation and migration advice. No configuration, "
            "policy, trust approval, or scanner asset is changed."
        ),
    }


def render_config_advice(document: dict[str, Any]) -> str:
    decision = str(document["decision"]).upper().replace("_", " ")
    compatibility = document["compatibility"]
    inventory = document["path_inventory"]
    lines = [
        f"{decision}: configuration schema {compatibility['declared_schema'] or 'implicit'}",
        (
            f"Compatibility: current {compatibility['current_schema']}; "
            f"migration {'required' if compatibility['migration_required'] else 'not required'}"
        ),
        (
            f"Paths: {inventory['portable_bundle']} portable bundle; "
            f"{inventory['relative']} relative; {inventory['absolute']} absolute"
        ),
    ]
    if document["effective"] is not None:
        effective = document["effective"]
        lines.append(
            f"Effective profile: {effective['profile']} "
            f"({len(effective['selected_tools'])} selected; "
            f"{len(effective['required_tools'])} required)"
        )
    if document["validation_errors"]:
        lines.append("Validation errors:")
        lines.extend(f"- {_plain(error)}" for error in document["validation_errors"])
    if document["recommendations"]:
        lines.append("Recommendations:")
        lines.extend(
            f"- {item['priority']} [{item['category']}] {_plain(item['message'])}"
            for item in document["recommendations"]
        )
    lines.append(f"Scope: {document['scope']}")
    return "\n".join(lines)


def render_config_advice_markdown(document: dict[str, Any]) -> str:
    compatibility = document["compatibility"]
    inventory = document["path_inventory"]
    lines = [
        "# Configuration assessment",
        "",
        f"**Decision:** {str(document['decision']).upper().replace('_', ' ')}  ",
        f"**Declared schema:** `{compatibility['declared_schema'] or 'implicit 1'}`  ",
        f"**Current schema:** `{compatibility['current_schema']}`",
        "",
        "## Compatibility and portability",
        "",
        "| Measure | Result |",
        "|---|---:|",
        f"| Migration required | {'yes' if compatibility['migration_required'] else 'no'} |",
        f"| Portable `@bundle/` paths | {inventory['portable_bundle']} |",
        f"| Repository-relative paths | {inventory['relative']} |",
        f"| Absolute paths | {inventory['absolute']} |",
        "",
        "## Actions",
        "",
        "| Priority | Category | Setting | Recommendation |",
        "|---|---|---|---|",
    ]
    if document["recommendations"]:
        lines.extend(
            f"| {item['priority']} | {_md(item['category'])} | "
            f"`{_md(item['setting'])}` | {_md(item['message'])} |"
            for item in document["recommendations"]
        )
    else:
        lines.append("| - | - | - | No configuration improvements identified. |")
    if document["validation_errors"]:
        lines.extend(["", "## Validation errors", ""])
        lines.extend(f"- {_md(error)}" for error in document["validation_errors"])
    lines.extend(["", f"> {document['scope']}"])
    return "\n".join(lines) + "\n"


def _read_source(path: Path, label: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    try:
        resolved = resolve_regular_file(path, label)
        size = resolved.stat().st_size
        if size > _MAX_CONFIG_BYTES:
            raise ValueError(f"{label} exceeds {_MAX_CONFIG_BYTES} bytes")
        content = resolved.read_bytes()
        parsed = tomllib.loads(content.decode("utf-8"))
        return (
            parsed,
            {
                "name": resolved.name,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": size,
            },
            "",
        )
    except (OSError, UnicodeError, ValueError, tomllib.TOMLDecodeError) as exc:
        error = _plain(exc)
        for candidate in (str(path), str(path.expanduser().absolute())):
            error = error.replace(candidate, path.name)
        return {}, {"name": path.name, "sha256": None, "size_bytes": None}, error


def _path_inventory(mapping: Mapping[str, Any]) -> list[dict[str, str]]:
    paths: list[dict[str, str]] = []

    def visit(value: Mapping[str, Any], prefix: str = "") -> None:
        for key, item in value.items():
            setting = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(item, Mapping):
                visit(item, setting)
            elif key in _PATH_KEYS and isinstance(item, str) and item:
                paths.append({"setting": setting, "kind": _path_kind(item)})

    visit(mapping)
    return sorted(paths, key=lambda item: item["setting"])


def _path_kind(value: str) -> str:
    if value.startswith("@bundle/"):
        return "bundle"
    path_types = (Path(value), PurePosixPath(value), PureWindowsPath(value))
    return "absolute" if any(path.is_absolute() for path in path_types) else "relative"


def _declared_digest_settings(mapping: Mapping[str, Any]) -> list[str]:
    settings: list[str] = []

    def visit(value: Mapping[str, Any], prefix: str = "") -> None:
        for key, item in value.items():
            setting = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(item, Mapping):
                visit(item, setting)
            elif key.endswith("sha256") and isinstance(item, str) and item:
                settings.append(setting)

    visit(mapping)
    return sorted(settings)


def _recommendation(
    priority: str, category: str, message: str, setting: str
) -> dict[str, str]:
    return {
        "priority": priority,
        "category": category,
        "setting": setting,
        "message": message,
    }


def _plain(value: object) -> str:
    return " ".join(str(value).replace("\x00", "�").split())[:16000]


def _md(value: object) -> str:
    text = _plain(value).replace("\\", "\\\\")
    for character in ("`", "*", "_", "[", "]", "|"):
        text = text.replace(character, f"\\{character}")
    return text
