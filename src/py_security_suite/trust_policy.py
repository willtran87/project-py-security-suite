from __future__ import annotations

import hashlib
import base64
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .path_safety import read_regular_file
from .strict_json import canonical_bytes
from .strict_json import loads as strict_loads


_PINNED_COMMAND_SUFFIXES = {
    "COMMAND_JSON",
    "EXECUTABLE_SHA256",
    "RUNTIME_SHA256",
    "ASSETS_JSON",
    "ALLOWED_ENDPOINTS_JSON",
    "MTLS_IDENTITY_SHA256",
    "SANDBOX_COMMAND_JSON",
    "SANDBOX_EXECUTABLE_SHA256",
    "SANDBOX_IDENTITY_SHA256",
    "EXECUTION_ATTESTATION_KEY_SHA256",
    "REMOTE_ATTESTATION_KEY_SHA256",
    "AUTHORITY_KEY_SHA256",
}
_PINNED_COMMAND_PREFIXES = {
    "PYSEC_COMPILER_SEMANTIC_REPLAY",
    "PYSEC_GIT_BUNDLE_CAS",
    "PYSEC_GIT_SECONDARY_VERIFIER",
    "PYSEC_OPERATION_RECEIPT_CHECKPOINT",
    "PYSEC_RAW_EVIDENCE_KMS",
    "PYSEC_RAW_EVIDENCE_PROVIDER_AUDIT_READBACK",
    "PYSEC_RAW_EVIDENCE_RECOVERY",
    "PYSEC_TRUSTED_TIME_CHECKPOINT",
}

_EXPLICIT_POLICY_BOOTSTRAP = frozenset(
    {
        "PYSEC_EXPLICIT_TRUST_POLICY_PATH",
        "PYSEC_EXPLICIT_TRUST_POLICY_SHA256",
        "PYSEC_EXPLICIT_TRUST_POLICY_KEY_SHA256",
        "PYSEC_EXPLICIT_TRUST_POLICY_MIN_GENERATION",
        "PYSEC_REQUIRE_EXPLICIT_TRUST_POLICY",
    }
)


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
        "PYSEC_EXPLICIT_TRUST_POLICY_PATH",
        "PYSEC_EXPLICIT_TRUST_POLICY_SHA256",
        "PYSEC_EXPLICIT_TRUST_POLICY_KEY_SHA256",
        "PYSEC_EXPLICIT_TRUST_POLICY_MIN_GENERATION",
        "PYSEC_REQUIRE_EXPLICIT_TRUST_POLICY",
        "PYSEC_GOVERNANCE_MIN_GENERATION",
        "PYSEC_FAILURE_DOMAIN_REGISTRY_PATH",
        "PYSEC_FAILURE_DOMAIN_REGISTRY_SHA256",
        "PYSEC_FAILURE_DOMAIN_REGISTRY_MIN_GENERATION",
        "PYSEC_FAILURE_DOMAIN_REGISTRY_ROOT_KEYS_JSON",
        "PYSEC_FAILURE_DOMAIN_REGISTRY_SIGNATURE_THRESHOLD",
        "PYSEC_FAILURE_DOMAIN_LOG_ROOT_SHA256",
        "PYSEC_REQUIRE_FRESH_FAILURE_DOMAIN_REGISTRY",
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
        "PYSEC_NITRO_ATTESTATION_ROOT_SHA256",
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
        "PYSEC_REQUIRE_REGISTERED_FAILURE_DOMAINS",
        "PYSEC_REQUIRE_HARDWARE_ATTESTATION_ROOTS",
        "PYSEC_REQUIRE_RAW_ATTESTATION_REPLAY",
        "PYSEC_RAW_ATTESTATION_REPLAY_KEY_SHA256",
        "PYSEC_REQUIRE_KERNEL_RUNTIME_EVENTS",
        "PYSEC_RUNTIME_KERNEL_AUTHORITY_KEY_SHA256",
        "PYSEC_REQUIRE_HARDENED_RELEASE_EVIDENCE",
        "PYSEC_SEV_SNP_ATTESTATION_ROOT_SHA256",
        "PYSEC_SEV_SNP_MIN_REPORTED_TCB",
        "PYSEC_TPM2_ATTESTATION_ROOT_SHA256",
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
    | {
        f"{prefix}_{suffix}"
        for prefix in _PINNED_COMMAND_PREFIXES
        for suffix in _PINNED_COMMAND_SUFFIXES
    }
    | {
        "PYSEC_GIT_BUNDLE_CAS_AUTHORITY_KEY_SHA256",
        "PYSEC_GIT_PRIMARY_CONTROL_PLANE_SHA256",
        "PYSEC_GIT_PRIMARY_HOST_IDENTITY_SHA256",
        "PYSEC_GIT_PRIMARY_IMPLEMENTATION_SHA256",
        "PYSEC_GIT_PRIMARY_ORGANIZATION",
        "PYSEC_GIT_SECONDARY_VERIFIER_AUTHORITY_KEY_SHA256",
        "PYSEC_OPERATION_RECEIPT_CHECKPOINT_AUTHORITY_KEY_SHA256",
        "PYSEC_OPERATION_RECEIPT_CHECKPOINT_FAILURE_DOMAIN_JSON",
        "PYSEC_OPERATION_RECEIPT_CHECKPOINT_SHA256",
        "PYSEC_OPERATION_RECEIPT_MIN_SEQUENCE",
        "PYSEC_OPERATION_RECEIPT_REQUIRE_EXTERNAL_CHECKPOINT",
        "PYSEC_OPERATION_RECEIPT_CHECKPOINT_QUORUM_PREFIXES_JSON",
        "PYSEC_OPERATION_RECEIPT_CHECKPOINT_QUORUM_THRESHOLD",
        "PYSEC_OPERATION_RECEIPT_STATE_PATH",
        "PYSEC_RAW_EVIDENCE_RECOVERY_AUTHORITY_KEY_SHA256",
        "PYSEC_RAW_EVIDENCE_RECOVERY_PROVIDER_AUDIT_KEY_SHA256",
        "PYSEC_RAW_EVIDENCE_PROVIDER_AUDIT_READBACK_REQUIRED",
        "PYSEC_REQUIREMENTS_SECRET_COMMITMENT_KEY_SHA256",
        "PYSEC_REQUIREMENTS_SECRET_NONCE_STATE_PATH",
        "PYSEC_REQUIREMENTS_OCI_BUILDER_ID",
        "PYSEC_REQUIREMENTS_OCI_SIGNATURE_KEY_SHA256",
        "PYSEC_TRUSTED_TIME_CHECKPOINT_AUTHORITY_KEY_SHA256",
        "PYSEC_TRUSTED_TIME_CHECKPOINT_FAILURE_DOMAIN_JSON",
        "PYSEC_TRUSTED_TIME_CHECKPOINT_SHA256",
        "PYSEC_TRUSTED_TIME_MIN_SEQUENCE",
        "PYSEC_TRUSTED_TIME_REQUIRE_EXTERNAL_CHECKPOINT",
        "PYSEC_TRUSTED_TIME_CHECKPOINT_QUORUM_PREFIXES_JSON",
        "PYSEC_TRUSTED_TIME_CHECKPOINT_QUORUM_THRESHOLD",
        "PYSEC_TRUSTED_TIME_STATE_PATH",
    }
)


def capture_trust_environment() -> dict[str, str]:
    explicit = _explicit_trust_environment()
    if explicit is not None:
        return explicit
    dynamic_pins = {
        name
        for name in os.environ
        if name.startswith("PYSEC_")
        and any(name.endswith(f"_{suffix}") for suffix in _PINNED_COMMAND_SUFFIXES)
    }
    return {
        name: os.environ[name]
        for name in sorted(_TRUST_ENVIRONMENT | dynamic_pins)
        if os.environ.get(name, "")
    }


def _explicit_trust_environment() -> dict[str, str] | None:
    path_value = os.environ.get("PYSEC_EXPLICIT_TRUST_POLICY_PATH", "").strip()
    digest = os.environ.get("PYSEC_EXPLICIT_TRUST_POLICY_SHA256", "").strip().casefold()
    required = os.environ.get("PYSEC_REQUIRE_EXPLICIT_TRUST_POLICY", "").strip() == "1"
    if not path_value and not digest:
        if required:
            raise ValueError("an explicit signed trust policy is required")
        return None
    if not path_value or not _digest(digest):
        raise ValueError("explicit trust policy configuration is incomplete")
    _, payload = read_regular_file(
        Path(path_value), "explicit trust policy", maximum_bytes=4 * 1024 * 1024
    )
    if hashlib.sha256(payload).hexdigest() != digest:
        raise ValueError("explicit trust policy does not match its deployment pin")
    document = strict_loads(payload)
    if not isinstance(document, dict) or set(document) != {"signed", "signature"}:
        raise ValueError("explicit trust policy envelope is invalid")
    signed = document["signed"]
    signature = document["signature"]
    if (
        not isinstance(signed, dict)
        or set(signed)
        != {"schema_version", "generation", "issued_at", "expires_at", "variables"}
        or signed.get("schema_version") != "1.0"
        or not isinstance(signed.get("generation"), int)
        or signed["generation"] < 1
        or not isinstance(signed.get("variables"), dict)
        or not isinstance(signature, dict)
        or set(signature) != {"key_sha256", "public_key_pem_base64", "signature_base64"}
    ):
        raise ValueError("explicit trust policy fields are invalid")
    minimum = _integer_environment("PYSEC_EXPLICIT_TRUST_POLICY_MIN_GENERATION", 1)
    if signed["generation"] < minimum:
        raise ValueError(
            "explicit trust policy generation is below the deployment floor"
        )
    issued = _timestamp(signed["issued_at"], "explicit trust policy issued_at")
    expires = _timestamp(signed["expires_at"], "explicit trust policy expires_at")
    now = datetime.now(UTC)
    if issued > now or expires <= now or expires <= issued:
        raise ValueError("explicit trust policy is not currently valid")
    variables: dict[str, str] = {}
    for raw_name, raw_value in signed["variables"].items():
        name = str(raw_name)
        if name not in _TRUST_ENVIRONMENT and not (
            name.startswith("PYSEC_")
            and any(name.endswith(f"_{suffix}") for suffix in _PINNED_COMMAND_SUFFIXES)
        ):
            raise ValueError(
                f"explicit trust policy contains unsupported variable {name!r}"
            )
        if (
            not isinstance(raw_value, str)
            or name in variables
            or name in _EXPLICIT_POLICY_BOOTSTRAP
        ):
            raise ValueError("explicit trust policy variables are invalid")
        variables[name] = raw_value
    _verify_policy_signature(signed, signature)
    bootstrap = {
        "PYSEC_EXPLICIT_TRUST_POLICY_PATH": path_value,
        "PYSEC_EXPLICIT_TRUST_POLICY_SHA256": digest,
        "PYSEC_EXPLICIT_TRUST_POLICY_KEY_SHA256": str(signature["key_sha256"]),
        "PYSEC_EXPLICIT_TRUST_POLICY_MIN_GENERATION": str(minimum),
        "PYSEC_REQUIRE_EXPLICIT_TRUST_POLICY": "1" if required else "0",
    }
    ambient_names = {
        name
        for name in os.environ
        if os.environ.get(name, "")
        and name not in _EXPLICIT_POLICY_BOOTSTRAP
        and (
            name in _TRUST_ENVIRONMENT
            or (
                name.startswith("PYSEC_")
                and any(
                    name.endswith(f"_{suffix}") for suffix in _PINNED_COMMAND_SUFFIXES
                )
            )
        )
    }
    unsigned_ambient = ambient_names - variables.keys()
    if unsigned_ambient:
        names = ", ".join(sorted(unsigned_ambient))
        raise ValueError(
            f"ambient trust settings are absent from signed policy: {names}"
        )
    for name, expected in variables.items():
        ambient = os.environ.get(name)
        if ambient is not None and ambient != expected:
            raise ValueError(
                f"ambient trust setting {name} conflicts with signed policy"
            )
    for name, value in variables.items():
        os.environ[name] = value
    return {**variables, **bootstrap}


def _verify_policy_signature(signed: dict[str, Any], signature: dict[str, Any]) -> None:
    expected = (
        os.environ.get("PYSEC_EXPLICIT_TRUST_POLICY_KEY_SHA256", "").strip().casefold()
    )
    claimed = str(signature.get("key_sha256") or "").casefold()
    if not _digest(expected) or claimed != expected:
        raise ValueError("explicit trust policy signing key is not deployment-pinned")
    try:
        public_bytes = base64.b64decode(
            str(signature["public_key_pem_base64"]), validate=True
        )
        raw_signature = base64.b64decode(
            str(signature["signature_base64"]), validate=True
        )
        public = serialization.load_pem_public_key(public_bytes)
    except (TypeError, ValueError) as exc:
        raise ValueError("explicit trust policy signature encoding is invalid") from exc
    if hashlib.sha256(public_bytes).hexdigest() != expected or not isinstance(
        public, Ed25519PublicKey
    ):
        raise ValueError("explicit trust policy signing key is invalid")
    try:
        public.verify(raw_signature, canonical_bytes(signed))
    except Exception as exc:
        raise ValueError("explicit trust policy signature is invalid") from exc


def _timestamp(value: object, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _integer_environment(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} is invalid") from exc
    if value < 1:
        raise ValueError(f"{name} is invalid")
    return value


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


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
