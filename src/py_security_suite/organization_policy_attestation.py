from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from .assurance_profile import verify_governance_quorum
from .governance_replay import consume_governance_replay
from .path_safety import read_regular_file
from .strict_json import loads as strict_loads


def validate_organization_policy_attestation(
    policy_sha256: str,
    *,
    observed_at: datetime,
    environment: Mapping[str, str],
) -> None:
    """Verify signed, expiring, generation-pinned organization policy metadata."""
    configured_path = environment.get("PYSEC_ORGANIZATION_POLICY_ATTESTATION", "")
    expected = environment.get("PYSEC_ORGANIZATION_POLICY_ATTESTATION_SHA256", "")
    if not configured_path or not expected:
        raise ValueError(
            "production organization policy requires a signed policy attestation"
        )
    path, payload = read_regular_file(
        Path(configured_path),
        "organization policy attestation",
        maximum_bytes=1024 * 1024,
    )
    if hashlib.sha256(payload).hexdigest() != expected.casefold():
        raise ValueError("organization policy attestation SHA-256 is not approved")
    value = strict_loads(payload)
    required = {
        "schema_version",
        "policy_sha256",
        "generation",
        "issued_at",
        "expires_at",
        "nonce",
        "minimum_authority_signatures",
        "authorities",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("organization policy attestation fields do not match")
    if value["schema_version"] != "1.0" or value["policy_sha256"] != policy_sha256:
        raise ValueError("organization policy attestation is detached")
    generation = value["generation"]
    threshold = value["minimum_authority_signatures"]
    if isinstance(generation, bool) or not isinstance(generation, int):
        raise ValueError("organization policy generation is invalid")
    try:
        minimum = int(environment.get("PYSEC_GOVERNANCE_MIN_GENERATION", "1"))
    except ValueError as exc:
        raise ValueError("governance minimum generation is invalid") from exc
    if generation < max(1, minimum):
        raise ValueError("organization policy generation is below deployment policy")
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, int)
        or not 2 <= threshold <= 16
    ):
        raise ValueError("organization policy authority threshold is invalid")
    nonce = value["nonce"]
    if not isinstance(nonce, str) or not 16 <= len(nonce) <= 500:
        raise ValueError("organization policy nonce is invalid")
    issued = _timestamp(value["issued_at"], "issued_at")
    expires = _timestamp(value["expires_at"], "expires_at")
    if not issued <= observed_at <= expires or expires <= issued:
        raise ValueError("organization policy attestation validity window is invalid")
    verify_governance_quorum(
        path,
        value["authorities"],
        {key: item for key, item in value.items() if key != "authorities"},
        threshold,
        observed_at,
        purpose="organization-policy",
        trust_environment=environment,
    )
    if environment.get("PYSEC_GOVERNANCE_REPLAY_SERVICE_URL") or environment.get(
        "PYSEC_GOVERNANCE_REPLAY_REQUIRE_REMOTE", ""
    ).casefold() in {"1", "true", "yes"}:
        consume_governance_replay(
            value,
            hashlib.sha256(payload).hexdigest(),
            None,
            "organization-policy",
            trust_environment=environment,
        )


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 100:
        raise ValueError(f"{label} is invalid")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)
