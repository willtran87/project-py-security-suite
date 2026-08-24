from __future__ import annotations

import hashlib
import os
from typing import Any

from .strict_json import canonical_bytes


_TRUST_ENVIRONMENT = frozenset(
    {
        "PYSEC_ASSURANCE_PROFILE_GENERATION",
        "PYSEC_ASSURANCE_PROFILE_MIN_CHECKPOINT_SEQUENCE",
        "PYSEC_ASSURANCE_PROFILE_MIN_GENERATION",
        "PYSEC_ASSURANCE_PROFILE_SHA256",
        "PYSEC_ASSURANCE_PROFILE_SIGNATURE_THRESHOLD",
        "PYSEC_AUTHORITY_KEY_LIFECYCLE",
        "PYSEC_AUTHORITY_ORGANIZATIONS",
        "PYSEC_COSIGN_EXECUTABLE_SHA256",
        "PYSEC_DB_CLUSTER_IDENTITY_SHA256",
        "PYSEC_ENVIRONMENT_SHA256",
        "PYSEC_GOVERNANCE_MIN_GENERATION",
        "PYSEC_GOVERNANCE_REPLAY_REQUIRE_REMOTE",
        "PYSEC_GOVERNANCE_REPLAY_SERVICE_CA",
        "PYSEC_GOVERNANCE_REPLAY_SERVICE_CA_SHA256",
        "PYSEC_GOVERNANCE_REPLAY_SERVICE_CLIENT_CERT",
        "PYSEC_GOVERNANCE_REPLAY_SERVICE_CLIENT_CERT_SHA256",
        "PYSEC_GOVERNANCE_REPLAY_SERVICE_CLIENT_KEY",
        "PYSEC_GOVERNANCE_REPLAY_SERVICE_CLIENT_KEY_SHA256",
        "PYSEC_GOVERNANCE_REPLAY_SERVICE_RECEIPT_KEY",
        "PYSEC_GOVERNANCE_REPLAY_SERVICE_RECEIPT_KEY_SHA256",
        "PYSEC_GOVERNANCE_REPLAY_SERVICE_STATE_FILE",
        "PYSEC_GOVERNANCE_REPLAY_SERVICE_TOKEN_ENV",
        "PYSEC_GOVERNANCE_REPLAY_SERVICE_URL",
        "PYSEC_KEYRING_MIN_GENERATION",
        "PYSEC_KEYRING_ROOT_SHA256",
        "PYSEC_KEYRING_STATE_FILE",
        "PYSEC_ORGANIZATION_POLICY_SHA256",
        "PYSEC_ORGANIZATION_POLICY_ATTESTATION",
        "PYSEC_ORGANIZATION_POLICY_ATTESTATION_SHA256",
        "PYSEC_QUALIFICATION_AUTHORITY_THRESHOLD",
        "PYSEC_QUALIFICATION_REPLAY_LEDGER",
        "PYSEC_QUALIFICATION_REPLAY_SERVICE_CA",
        "PYSEC_QUALIFICATION_REPLAY_SERVICE_CLIENT_CERT",
        "PYSEC_QUALIFICATION_REPLAY_SERVICE_CLIENT_KEY",
        "PYSEC_QUALIFICATION_REPLAY_SERVICE_TOKEN_ENV",
        "PYSEC_QUALIFICATION_REPLAY_SERVICE_URL",
        "PYSEC_REPLAY_MIN_SEQUENCE",
        "PYSEC_REPLAY_RECEIPT_KEY_SHA256",
        "PYSEC_REPLAY_STATE_FILE",
        "PYSEC_SLSA_BUILDER_KEY_SHA256",
        "PYSEC_SLSA_BUILDER_POLICY",
        "PYSEC_SOURCE_SHA256",
        "PYSEC_TRUSTED_AUTHORITY_KEY_SHA256",
        "PYSEC_TRUSTED_AUTHORITY_ROLES",
        "PYSEC_TSA_AUTHORITIES",
        "PYSEC_TSA_POLICY_OIDS",
        "PYSEC_TSA_ROOT_SHA256",
        "PYSEC_TSA_SIGNER_SHA256",
        "PYSEC_VSA_KEY_LIFECYCLE",
        "PYSEC_VSA_RESOURCE_URI",
        "PYSEC_VSA_SIGNER_VERIFIERS",
        "PYSEC_VSA_VERIFIER_KEY_SHA256",
    }
)


def capture_trust_environment() -> dict[str, str]:
    return {
        name: os.environ[name]
        for name in sorted(_TRUST_ENVIRONMENT)
        if os.environ.get(name, "")
    }


def snapshot_trust_policy(
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Seal deployment-owned trust decisions without exposing their values."""
    captured = capture_trust_environment() if environment is None else environment
    variables = {
        name: {
            "configured": True,
            "value_sha256": hashlib.sha256(value.encode()).hexdigest(),
        }
        for name, value in sorted(captured.items())
    }
    subject = {
        "schema_version": "1.0",
        "environment_contract": "deployment-trust-policy-v1",
        "variables": variables,
    }
    return {
        **subject,
        "policy_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
    }
