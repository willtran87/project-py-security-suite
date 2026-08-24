from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .path_safety import read_regular_file
from .strict_json import loads as strict_loads

_FIELDS = {
    "organization",
    "host_identity_sha256",
    "control_plane_sha256",
    "implementation_sha256",
}


def verify_failure_domain(value: object, label: str) -> dict[str, str]:
    """Validate one deployment-owned authority failure-domain identity."""

    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise ValueError(f"{label} failure-domain fields do not match")
    normalized = {name: str(value[name]).strip().casefold() for name in _FIELDS}
    if not normalized["organization"] or any(
        not _digest(normalized[name])
        for name in (
            "host_identity_sha256",
            "control_plane_sha256",
            "implementation_sha256",
        )
    ):
        raise ValueError(f"{label} failure-domain identity is invalid")
    return normalized


def require_independent_failure_domains(
    first: object, second: object, *, labels: tuple[str, str]
) -> tuple[dict[str, str], dict[str, str]]:
    """Require organizational, host, control-plane, and implementation diversity."""

    left = verify_failure_domain(first, labels[0])
    right = verify_failure_domain(second, labels[1])
    if any(left[name] == right[name] for name in _FIELDS):
        raise ValueError(
            f"{labels[0]} and {labels[1]} do not span independent failure domains"
        )
    return left, right


def verify_registered_failure_domain(
    value: object, authority_key_sha256: str, label: str
) -> dict[str, str]:
    """Verify an authority domain against a deployment-pinned identity registry."""

    domain = verify_failure_domain(value, label)
    path_value = os.environ.get("PYSEC_FAILURE_DOMAIN_REGISTRY_PATH", "").strip()
    digest = os.environ.get("PYSEC_FAILURE_DOMAIN_REGISTRY_SHA256", "").strip().casefold()
    required = os.environ.get("PYSEC_REQUIRE_REGISTERED_FAILURE_DOMAINS", "").strip() == "1"
    if not path_value and not digest:
        if required:
            raise ValueError("failure-domain registry is required")
        return domain
    if not path_value or not _digest(digest) or not _digest(authority_key_sha256):
        raise ValueError("failure-domain registry configuration is incomplete")
    _, payload = read_regular_file(
        Path(path_value), "failure-domain registry", maximum_bytes=4 * 1024 * 1024
    )
    if hashlib.sha256(payload).hexdigest() != digest:
        raise ValueError("failure-domain registry does not match its pin")
    document = strict_loads(payload)
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "generation", "authorities"}
        or document.get("schema_version") != "1.0"
        or not isinstance(document.get("generation"), int)
        or document["generation"] < 1
        or not isinstance(document.get("authorities"), list)
    ):
        raise ValueError("failure-domain registry is invalid")
    matches = []
    seen: set[str] = set()
    for item in document["authorities"]:
        if (
            not isinstance(item, dict)
            or set(item)
            != {
                "authority_key_sha256",
                "failure_domain",
                "implementation_artifact_sha256",
                "status",
            }
            or not _digest(str(item.get("authority_key_sha256") or ""))
            or item["authority_key_sha256"] in seen
            or item.get("status") not in {"active", "revoked"}
        ):
            raise ValueError("failure-domain registry authority is invalid")
        seen.add(item["authority_key_sha256"])
        registered = verify_failure_domain(item["failure_domain"], "registered authority")
        if item.get("implementation_artifact_sha256") != registered["implementation_sha256"]:
            raise ValueError("registered implementation artifact is detached")
        if item["authority_key_sha256"] == authority_key_sha256:
            matches.append((item, registered))
    if len(matches) != 1 or matches[0][0]["status"] != "active" or matches[0][1] != domain:
        raise ValueError(f"{label} failure domain is not actively registered")
    return domain


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
