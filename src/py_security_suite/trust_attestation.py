from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from .assurance_profile import verify_governance_quorum
from .config import TrustConfig
from .governance import GovernanceResult, consume_governance_replay
from .path_safety import read_regular_file
from .strict_json import loads as strict_loads


def validate_trust_policy_attestation(
    config: TrustConfig,
    snapshot: dict[str, Any],
    *,
    observed_at: datetime,
    trust_environment: Mapping[str, str],
) -> GovernanceResult:
    """Authenticate the exact execution trust snapshot with an external quorum."""
    if config.policy_path is None:
        return GovernanceResult(
            errors=(
                [
                    "production execution trust policy requires external quorum signatures"
                ]
                if config.require_signed_policy
                else []
            ),
            artifact={
                "schema_version": "1.0",
                "configured": False,
                "validated": False,
                "required": config.require_signed_policy,
                "policy_sha256": snapshot["policy_sha256"],
            },
        )
    try:
        path, payload = read_regular_file(
            config.policy_path,
            "execution trust policy attestation",
            maximum_bytes=1024 * 1024,
        )
        digest = hashlib.sha256(payload).hexdigest()
        if digest != config.policy_sha256:
            raise ValueError(
                "execution trust policy attestation SHA-256 is not approved"
            )
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
            raise ValueError("execution trust policy attestation fields do not match")
        if (
            value["schema_version"] != "1.0"
            or value["policy_sha256"] != snapshot["policy_sha256"]
        ):
            raise ValueError("execution trust policy attestation is detached")
        generation = value["generation"]
        threshold = value["minimum_authority_signatures"]
        nonce = value["nonce"]
        if isinstance(generation, bool) or not isinstance(generation, int):
            raise ValueError("execution trust policy generation is invalid")
        minimum = int(trust_environment.get("PYSEC_GOVERNANCE_MIN_GENERATION", "1"))
        if generation < max(1, minimum):
            raise ValueError(
                "execution trust policy generation is below deployment policy"
            )
        if (
            isinstance(threshold, bool)
            or not isinstance(threshold, int)
            or not 2 <= threshold <= 16
        ):
            raise ValueError("execution trust policy authority threshold is invalid")
        if not isinstance(nonce, str) or not 16 <= len(nonce) <= 500:
            raise ValueError("execution trust policy nonce is invalid")
        issued = _timestamp(value["issued_at"], "issued_at")
        expires = _timestamp(value["expires_at"], "expires_at")
        if not issued <= observed_at <= expires or expires <= issued:
            raise ValueError("execution trust policy validity window is invalid")
        subject = {key: item for key, item in value.items() if key != "authorities"}
        verified = verify_governance_quorum(
            path,
            value["authorities"],
            subject,
            threshold,
            observed_at,
            purpose="execution-trust-policy",
            trust_environment=trust_environment,
        )
        replay = consume_governance_replay(
            value,
            digest,
            config.replay_ledger_path,
            "execution-trust-policy",
            trust_environment=trust_environment,
        )
        return GovernanceResult(
            artifact={
                **subject,
                "configured": True,
                "validated": True,
                "attestation_sha256": digest,
                "authority_signers": sorted(item[0] for item in verified),
                "authority_collectors": sorted(item[1] for item in verified),
                "authority_organizations": sorted({item[2] for item in verified}),
                **replay,
            }
        )
    except (OSError, TypeError, ValueError, UnicodeError) as exc:
        return GovernanceResult(
            errors=[f"execution trust policy attestation is invalid: {exc}"],
            artifact={
                "schema_version": "1.0",
                "configured": True,
                "validated": False,
                "required": config.require_signed_policy,
                "policy_sha256": snapshot["policy_sha256"],
            },
        )


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 100:
        raise ValueError(f"{label} is invalid")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)
