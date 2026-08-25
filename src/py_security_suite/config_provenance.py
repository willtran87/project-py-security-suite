from __future__ import annotations

import tomllib
import hashlib
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .config import load_config
from .path_safety import read_regular_file


def build_config_provenance(
    *,
    organization_policy: Path | None = None,
    repository_config: Path | None = None,
    profile_override: str | None = None,
) -> dict[str, Any]:
    """Explain configuration origins without exposing configuration values."""
    config = load_config(
        organization_policy=organization_policy,
        repository_config=repository_config,
        profile_override=profile_override,
    )
    organization, organization_source = _source(
        organization_policy, "organization policy"
    )
    repository, repository_source = _source(
        repository_config, "repository configuration"
    )
    organization_keys = _leaf_keys(organization)
    repository_keys = _leaf_keys(repository)
    all_keys = sorted(organization_keys | repository_keys | {"profile"})
    facts = []
    for key in all_keys:
        origin = (
            "cli"
            if key == "profile" and profile_override is not None
            else "repository"
            if key in repository_keys
            else "organization"
            if key in organization_keys
            else "default"
        )
        protected = key.startswith(
            ("isolation.", "intelligence.", "trust.")
        ) or key.endswith(("sha256", "required_scanners", "incomplete_is_blocking"))
        facts.append({"key": key, "origin": origin, "security_sensitive": protected})
    counts = {
        origin: sum(value["origin"] == origin for value in facts)
        for origin in ("default", "organization", "repository", "cli")
    }
    return {
        "schema_version": "1.0",
        "authoritative": bool(
            organization_policy
            and os.environ.get("PYSEC_ORGANIZATION_POLICY_SHA256", "")
        ),
        "scope": "Value-redacted origin map for the validated effective configuration; production organization authority is bound to a deployment-owned digest pin.",
        "sources": {
            "organization": organization_source,
            "repository": repository_source,
            "cli_profile_override": profile_override,
        },
        "effective": {
            "profile": config.profile,
            "selected_tools": list(config.selected_tools),
            "required_tools": list(config.required_tools),
        },
        "summary": {
            "facts": len(facts),
            "origins": counts,
            "security_sensitive_facts": sum(
                value["security_sensitive"] for value in facts
            ),
        },
        "facts": facts,
    }


def _source(path: Path | None, label: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if path is None:
        return {}, {"configured": False, "path": None, "sha256": None}
    source, payload = read_regular_file(path, label, maximum_bytes=4 * 1024 * 1024)
    value = tomllib.loads(payload.decode("utf-8"))
    return value, {
        "configured": True,
        "path": str(source),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _leaf_keys(value: Mapping[str, Any], prefix: str = "") -> set[str]:
    result: set[str] = set()
    for key, child in value.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(child, Mapping):
            result.update(_leaf_keys(child, name))
        else:
            result.add(name)
    return result
