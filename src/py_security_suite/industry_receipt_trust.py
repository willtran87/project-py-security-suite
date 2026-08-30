from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .benchmark_assurance import BenchmarkAssuranceError, load_authority_trust_policy


_ENVIRONMENT_FIELDS = {
    "policy": "PYSEC_INDUSTRY_RECEIPT_AUTHORITY_POLICY",
    "policy_sha256": "PYSEC_INDUSTRY_RECEIPT_AUTHORITY_POLICY_SHA256",
    "signature": "PYSEC_INDUSTRY_RECEIPT_AUTHORITY_POLICY_SIGNATURE",
    "trust_root": "PYSEC_INDUSTRY_RECEIPT_AUTHORITY_TRUST_ROOT",
    "trust_root_sha256": "PYSEC_INDUSTRY_RECEIPT_AUTHORITY_TRUST_ROOT_SHA256",
}


def load_industry_receipt_trust(
    workspace: Path,
    *,
    environment: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Load deployment-owned receipt trust without consulting the target repository.

    The five settings form one atomic configuration. A partial configuration is an
    error so a misspelled digest or signature path cannot silently disable trust.
    """
    values = {
        name: (environment or os.environ).get(variable, "").strip()
        for name, variable in _ENVIRONMENT_FIELDS.items()
    }
    configured = [name for name, value in values.items() if value]
    if not configured:
        return None, []
    if len(configured) != len(values):
        missing = sorted(set(values) - set(configured))
        return None, [
            "deployment receipt authority configuration is incomplete: "
            + ", ".join(_ENVIRONMENT_FIELDS[name] for name in missing)
        ]
    try:
        policy = load_authority_trust_policy(
            Path(values["policy"]),
            values["policy_sha256"],
            signature_path=Path(values["signature"]),
            trust_root_path=Path(values["trust_root"]),
            trust_root_sha256=values["trust_root_sha256"],
            workspace=workspace,
        )
    except BenchmarkAssuranceError as exc:
        return None, [f"deployment receipt authority policy: {exc}"]
    authorities = [
        entry for entry in policy["authorities"] if entry["role"] == "execution-receipt"
    ]
    if not authorities:
        return None, [
            "deployment receipt authority policy admits no execution-receipt authority"
        ]
    return {**policy, "execution_receipt_authorities": authorities}, []


def receipt_authority_projection(
    policy: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Return the non-secret lifecycle projection embedded in scorecard inputs."""
    if policy is None:
        return [], None
    authorities = []
    for entry in policy.get("execution_receipt_authorities", []):
        authorities.append(
            {
                "key_id": entry["public_key_sha256"],
                "organization_id": entry["organization_id"],
                "key_version": entry.get("key_version", "legacy"),
                "status": entry["status"],
                "valid_from": entry.get("valid_from", policy["issued_at"]),
                "valid_until": entry.get("valid_until", policy["expires_at"]),
                "revoked_at": entry.get("revoked_at"),
            }
        )
    identity = {
        "policy_id": policy["policy_id"],
        "policy_sha256": policy["sha256"],
        "trust_root_key_id": policy["trust_root_key_id"],
        "issued_at": policy["issued_at"],
        "expires_at": policy["expires_at"],
    }
    return authorities, identity
