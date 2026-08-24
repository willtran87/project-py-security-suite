from __future__ import annotations

import json
import hashlib
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .config import IntelligenceConfig, IsolationConfig
from .assurance_profile import verify_governance_quorum
from .strict_json import canonical_bytes
from .path_safety import read_regular_file
from .strict_json import loads as strict_loads

_MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
_DIGEST_LENGTH = 64


@dataclass(slots=True)
class GovernanceResult:
    errors: list[str] = field(default_factory=list)
    artifact: dict[str, Any] = field(default_factory=dict)


def validate_isolation_evidence(
    config: IsolationConfig,
    *,
    target_name: str,
    source_sha256: str,
    observed_at: datetime,
    trust_environment: Mapping[str, str] | None = None,
) -> GovernanceResult:
    """Validate digest-approved evidence for an externally enforced boundary."""
    if config.evidence_path is None:
        error = (
            "approved external isolation evidence is required"
            if config.require_evidence
            else ""
        )
        return GovernanceResult(
            errors=[error] if error else [],
            artifact={
                "schema_version": "1.0",
                "configured": False,
                "validated": False,
                "required": config.require_evidence,
                "organization_approved": config.evidence_organization_approved,
            },
        )
    try:
        document, digest = _digest_bound_document(
            config.evidence_path,
            config.evidence_sha256,
            "isolation evidence",
            public_key_path=config.evidence_public_key_path,
            public_key_sha256=config.evidence_public_key_sha256,
            signature_path=config.evidence_signature_path,
        )
        _validate_isolation_document(
            document,
            target_name=target_name,
            source_sha256=source_sha256,
            observed_at=observed_at,
            context=config.evidence_path,
            require_v2=config.require_governance_v2,
            trust_environment=trust_environment,
        )
        governance = _validate_governance_authorities(
            document,
            context=config.evidence_path,
            observed_at=observed_at,
            purpose="isolation-evidence",
            trust_environment=trust_environment,
        )
        if config.require_governance_v2:
            governance.update(
                consume_governance_replay(
                    document,
                    digest,
                    config.replay_ledger_path,
                    "isolation-evidence",
                    trust_environment=trust_environment,
                )
            )
        errors = (
            []
            if config.evidence_organization_approved or not config.require_evidence
            else ["isolation evidence is not bound by the organization policy"]
        )
        return GovernanceResult(
            errors=errors,
            artifact={
                **document,
                "configured": True,
                "validated": True,
                "organization_approved": config.evidence_organization_approved,
                "evidence_sha256": digest,
                **governance,
            },
        )
    except (OSError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        return GovernanceResult(
            errors=[f"external isolation evidence is invalid: {exc}"],
            artifact={
                "schema_version": "1.0",
                "configured": True,
                "validated": False,
                "required": config.require_evidence,
                "organization_approved": config.evidence_organization_approved,
            },
        )


def validate_intelligence_approval(
    config: IntelligenceConfig,
    intelligence: dict[str, Any],
    *,
    observed_at: datetime,
    trust_environment: Mapping[str, str] | None = None,
) -> GovernanceResult:
    """Validate approval of the exact offline intelligence snapshot set."""
    snapshots = intelligence.get("snapshots")
    configured = isinstance(snapshots, dict) and bool(snapshots)
    if config.approval_path is None:
        error = (
            "approved intelligence snapshot manifest is required"
            if configured and config.require_approval
            else ""
        )
        return GovernanceResult(
            errors=[error] if error else [],
            artifact={
                "schema_version": "1.0",
                "configured": False,
                "validated": False,
                "required": config.require_approval,
                "organization_approved": config.approval_organization_approved,
                "snapshot_count": len(snapshots) if isinstance(snapshots, dict) else 0,
            },
        )
    try:
        document, digest = _digest_bound_document(
            config.approval_path,
            config.approval_sha256,
            "intelligence approval",
            public_key_path=config.approval_public_key_path,
            public_key_sha256=config.approval_public_key_sha256,
            signature_path=config.approval_signature_path,
        )
        _validate_intelligence_document(
            document,
            snapshots=snapshots if isinstance(snapshots, dict) else {},
            observed_at=observed_at,
            context=config.approval_path,
            require_v2=config.require_governance_v2,
            trust_environment=trust_environment,
        )
        governance = _validate_governance_authorities(
            document,
            context=config.approval_path,
            observed_at=observed_at,
            purpose="intelligence-approval",
            trust_environment=trust_environment,
        )
        if config.require_governance_v2:
            governance.update(
                consume_governance_replay(
                    document,
                    digest,
                    config.replay_ledger_path,
                    "intelligence-approval",
                    trust_environment=trust_environment,
                )
            )
        errors = (
            []
            if config.approval_organization_approved or not config.require_approval
            else ["intelligence approval is not bound by the organization policy"]
        )
        return GovernanceResult(
            errors=errors,
            artifact={
                **document,
                "configured": True,
                "validated": True,
                "organization_approved": config.approval_organization_approved,
                "evidence_sha256": digest,
                **governance,
            },
        )
    except (OSError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        return GovernanceResult(
            errors=[f"intelligence approval is invalid: {exc}"],
            artifact={
                "schema_version": "1.0",
                "configured": True,
                "validated": False,
                "required": config.require_approval,
                "organization_approved": config.approval_organization_approved,
            },
        )


def _digest_bound_document(
    path: Path,
    expected_digest: str,
    label: str,
    *,
    public_key_path: Path | None,
    public_key_sha256: str,
    signature_path: Path | None,
) -> tuple[dict[str, Any], str]:
    _, payload = read_regular_file(path, label, maximum_bytes=_MAX_EVIDENCE_BYTES)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != expected_digest.casefold():
        raise ValueError(f"{label} does not match the approved SHA-256")
    if public_key_path is None or signature_path is None or not public_key_sha256:
        raise ValueError(f"{label} requires independent signature verification")
    _, public_key_bytes = read_regular_file(
        public_key_path, f"{label} public key", maximum_bytes=64 * 1024
    )
    if hashlib.sha256(public_key_bytes).hexdigest() != public_key_sha256.casefold():
        raise ValueError(f"{label} public key does not match the approved SHA-256")
    public_key = serialization.load_pem_public_key(public_key_bytes)
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError(f"{label} public key must use Ed25519")
    _, signature = read_regular_file(
        signature_path, f"{label} signature", maximum_bytes=1024
    )
    try:
        public_key.verify(signature, payload)
    except InvalidSignature as exc:
        raise ValueError(f"{label} signature verification failed") from exc
    document = strict_loads(payload)
    if not isinstance(document, dict):
        raise TypeError(f"{label} root must be an object")
    if document.get("trust_root_sha256") != public_key_sha256.casefold():
        raise ValueError(f"{label} trust root does not match the verified public key")
    return document, digest


def _validate_isolation_document(
    document: dict[str, Any],
    *,
    target_name: str,
    source_sha256: str,
    observed_at: datetime,
    context: Path,
    require_v2: bool,
    trust_environment: Mapping[str, str] | None,
) -> None:
    version = document.get("schema_version")
    if require_v2 and version != "2.0":
        raise ValueError("production isolation evidence requires governance v2")
    if version == "2.0":
        required = {
            "schema_version",
            "status",
            "network_policy",
            "target",
            "source_sha256",
            "issuer",
            "runner_id",
            "policy_id",
            "policy_sha256",
            "approved_by",
            "valid_from",
            "valid_until",
            "trust_root_sha256",
            "generation",
            "nonce",
            "capabilities",
            "minimum_authority_signatures",
            "authorities",
        }
        _exact_keys(document, required, "isolation evidence")
        capabilities = document["capabilities"]
        required_capabilities = {
            "network-deny-all",
            "target-read-only",
            "resource-limits",
            "process-tree-termination",
            "file-write-quota",
            "host-filesystem-read-deny",
            "credential-isolation",
            "process-isolation",
            "device-isolation",
            "ipc-isolation",
        }
        if sys.platform == "win32":
            required_capabilities.add("windows-appcontainer")
        if (
            not isinstance(capabilities, list)
            or len(capabilities) != len(set(capabilities))
            or not required_capabilities.issubset(set(capabilities))
            or not {
                "linux-user-mount-network-namespaces",
                "macos-seatbelt",
                "windows-appcontainer",
                "microvm-boundary",
            }.intersection(capabilities)
        ):
            raise ValueError(
                "isolation evidence lacks required containment capabilities"
            )
        _governance_common(document, trust_environment=trust_environment)
    else:
        _validate_isolation_v1_keys(document)

    if (
        version not in {"1.0", "2.0"}
        or document["status"] != "enforced"
        or document["network_policy"] != "deny"
        or (version == "1.0" and document["signature_verified"] is not True)
    ):
        raise ValueError("isolation evidence does not assert an enforced signed denial")
    if document["target"] not in {"*", target_name}:
        raise ValueError("isolation evidence target does not match the scan target")
    _digest(document["source_sha256"], "source_sha256")
    if document["source_sha256"] != source_sha256:
        raise ValueError("isolation evidence source digest does not match the target")
    for name in ("policy_sha256", "trust_root_sha256"):
        _digest(document[name], name)
    for name in ("issuer", "runner_id", "policy_id", "approved_by"):
        _bounded_text(document[name], name)
    if version == "1.0":
        _bounded_text(document["verifier"], "verifier")
    valid_from = _timestamp(document["valid_from"], "valid_from")
    valid_until = _timestamp(document["valid_until"], "valid_until")
    if valid_until <= valid_from or not valid_from <= observed_at <= valid_until:
        raise ValueError("isolation evidence is outside its approved validity window")


def _validate_isolation_v1_keys(document: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "status",
        "network_policy",
        "target",
        "source_sha256",
        "issuer",
        "runner_id",
        "policy_id",
        "policy_sha256",
        "approved_by",
        "valid_from",
        "valid_until",
        "signature_verified",
        "verifier",
        "trust_root_sha256",
    }
    _exact_keys(document, required, "isolation evidence")


def _validate_intelligence_document(
    document: dict[str, Any],
    *,
    snapshots: dict[str, Any],
    observed_at: datetime,
    context: Path,
    require_v2: bool,
    trust_environment: Mapping[str, str] | None,
) -> None:
    version = document.get("schema_version")
    if require_v2 and version != "2.0":
        raise ValueError("production intelligence approval requires governance v2")
    if version == "2.0":
        required = {
            "schema_version",
            "status",
            "manifest_id",
            "revision",
            "approved_by",
            "issued_at",
            "valid_until",
            "trust_root_sha256",
            "snapshots",
            "generation",
            "nonce",
            "minimum_authority_signatures",
            "authorities",
        }
        _exact_keys(document, required, "intelligence approval")
        _governance_common(document, trust_environment=trust_environment)
        issued_at = _timestamp(document["issued_at"], "issued_at")
        if issued_at > observed_at:
            raise ValueError("intelligence approval was issued in the future")
    else:
        _validate_intelligence_v1_keys(document)
    if (
        version not in {"1.0", "2.0"}
        or document["status"] != "approved"
        or (version == "1.0" and document["signature_verified"] is not True)
    ):
        raise ValueError("intelligence approval is not approved and signature-verified")
    for name in ("manifest_id", "revision", "approved_by"):
        _bounded_text(document[name], name)
    if version == "1.0":
        _bounded_text(document["verifier"], "verifier")
    _digest(document["trust_root_sha256"], "trust_root_sha256")
    if _timestamp(document["valid_until"], "valid_until") < observed_at:
        raise ValueError("intelligence approval has expired")
    _validate_approved_snapshots(document, snapshots)


def _validate_intelligence_v1_keys(document: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "status",
        "manifest_id",
        "revision",
        "approved_by",
        "valid_until",
        "signature_verified",
        "verifier",
        "trust_root_sha256",
        "snapshots",
    }
    _exact_keys(document, required, "intelligence approval")


def _validate_approved_snapshots(
    document: dict[str, Any], snapshots: dict[str, Any]
) -> None:
    approved = document["snapshots"]
    if not isinstance(approved, list) or len(approved) > 20:
        raise TypeError("intelligence approval snapshots must be a bounded array")
    approved_digests: dict[str, str] = {}
    for value in approved:
        if not isinstance(value, dict) or set(value) != {"kind", "sha256"}:
            raise TypeError("approved snapshot entries require kind and sha256")
        kind = _bounded_text(value["kind"], "snapshot kind")
        digest = _digest(value["sha256"], "snapshot sha256")
        if kind in approved_digests:
            raise ValueError("intelligence approval contains duplicate snapshot kinds")
        approved_digests[kind] = digest
    observed_digests = {
        str(kind): str(value.get("sha256") or "")
        for kind, value in snapshots.items()
        if isinstance(value, dict)
    }
    if approved_digests != observed_digests:
        raise ValueError("intelligence approval does not match the consumed snapshots")


def _governance_common(
    document: dict[str, Any],
    *,
    trust_environment: Mapping[str, str] | None,
) -> None:
    generation = document.get("generation")
    threshold = document.get("minimum_authority_signatures")
    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 1
    ):
        raise ValueError("governance generation must be a positive integer")
    environment = trust_environment or {}
    minimum_text = environment.get("PYSEC_GOVERNANCE_MIN_GENERATION", "1")
    try:
        minimum = int(minimum_text)
    except ValueError as exc:
        raise ValueError("governance minimum generation is invalid") from exc
    if generation < max(1, minimum):
        raise ValueError("governance generation is below deployment policy")
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, int)
        or not 2 <= threshold <= 16
    ):
        raise ValueError("governance authority threshold must be between 2 and 16")
    nonce = _bounded_text(document.get("nonce"), "nonce")
    if len(nonce) < 16:
        raise ValueError("governance nonce must contain at least 16 characters")


def _validate_governance_authorities(
    document: dict[str, Any],
    *,
    context: Path,
    observed_at: datetime,
    purpose: str,
    trust_environment: Mapping[str, str] | None,
) -> dict[str, Any]:
    if document.get("schema_version") != "2.0":
        return {}
    subject = {key: value for key, value in document.items() if key != "authorities"}
    verified = verify_governance_quorum(
        context,
        document.get("authorities"),
        subject,
        int(document["minimum_authority_signatures"]),
        observed_at,
        purpose=purpose,
        trust_environment=trust_environment,
    )
    return {
        "governance_contract": "v2-quorum",
        "authority_signers": sorted(item[0] for item in verified),
        "authority_collectors": sorted(item[1] for item in verified),
        "authority_organizations": sorted({item[2] for item in verified}),
    }


def consume_governance_replay(
    document: dict[str, Any],
    digest: str,
    ledger: Path | None,
    purpose: str,
    *,
    trust_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = trust_environment or {}
    service = environment.get("PYSEC_GOVERNANCE_REPLAY_SERVICE_URL", "")
    if service:
        return _consume_remote_governance_replay(document, digest, purpose, environment)
    if environment.get("PYSEC_GOVERNANCE_REPLAY_REQUIRE_REMOTE", "").casefold() in {
        "1",
        "true",
        "yes",
    }:
        raise ValueError("production governance requires remote monotonic replay")
    if ledger is None:
        raise ValueError("production governance v2 requires a replay ledger")
    resolved = ledger.expanduser().absolute()
    if resolved.is_symlink() or (resolved.exists() and not resolved.is_file()):
        raise ValueError("governance replay ledger is not a regular file")
    if not resolved.parent.is_dir() or resolved.parent.is_symlink():
        raise ValueError("governance replay ledger parent is not a regular directory")
    token = hashlib.sha256(
        canonical_bytes(
            {
                "purpose": purpose,
                "evidence_sha256": digest,
                "generation": document["generation"],
                "nonce": document["nonce"],
            }
        )
    ).hexdigest()
    try:
        connection = sqlite3.connect(resolved, timeout=10.0)
        with connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS consumed_governance ("
                "token TEXT PRIMARY KEY, purpose TEXT NOT NULL, consumed_at TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO consumed_governance(token, purpose, consumed_at) VALUES (?, ?, ?)",
                (token, purpose, datetime.now(UTC).isoformat()),
            )
    except sqlite3.IntegrityError as exc:
        raise ValueError("governance evidence replay was detected") from exc
    except sqlite3.Error as exc:
        raise ValueError("governance replay ledger could not be updated") from exc
    finally:
        if "connection" in locals():
            connection.close()
    return {
        "replay_backend": "local-sqlite",
        "replay_token_sha256": token,
        "trusted_consumed_at": None,
    }


def _consume_remote_governance_replay(
    document: dict[str, Any],
    digest: str,
    purpose: str,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    from .evidence_ingest import _consume_replay_service

    required = {
        "token_env": "PYSEC_GOVERNANCE_REPLAY_SERVICE_TOKEN_ENV",
        "ca": "PYSEC_GOVERNANCE_REPLAY_SERVICE_CA",
        "receipt_key": "PYSEC_GOVERNANCE_REPLAY_SERVICE_RECEIPT_KEY",
        "client_cert": "PYSEC_GOVERNANCE_REPLAY_SERVICE_CLIENT_CERT",
        "client_key": "PYSEC_GOVERNANCE_REPLAY_SERVICE_CLIENT_KEY",
    }
    values = {
        name: environment.get(variable, "") for name, variable in required.items()
    }
    if any(not value for value in values.values()):
        raise ValueError("remote governance replay configuration is incomplete")
    for name in ("ca", "receipt_key", "client_cert", "client_key"):
        digest_name = f"PYSEC_GOVERNANCE_REPLAY_SERVICE_{name.upper()}_SHA256"
        expected = environment.get(digest_name, "").casefold()
        _, payload = read_regular_file(
            Path(values[name]),
            f"governance replay {name.replace('_', ' ')}",
            maximum_bytes=1024 * 1024,
        )
        if not expected or hashlib.sha256(payload).hexdigest() != expected:
            raise ValueError(f"remote governance replay {name} is not digest-pinned")
    identity_document = {
        "run_id": str(document["nonce"]),
        "kind": purpose,
        "source_sha256": digest,
        "environment_sha256": hashlib.sha256(canonical_bytes(environment)).hexdigest(),
        "context": {"generation": document["generation"]},
        "provenance": {"purpose": purpose},
        "evidence_binding": {
            "authenticated": True,
            "evidence_sha256": digest,
            "attestation": {
                "key_id": str(document.get("trust_root_sha256") or purpose)
            },
        },
    }
    state_text = environment.get("PYSEC_GOVERNANCE_REPLAY_SERVICE_STATE_FILE", "")
    if not state_text:
        raise ValueError(
            "remote governance replay requires a deployment-owned checkpoint state file"
        )
    receipt = _consume_replay_service(
        identity_document,
        environment["PYSEC_GOVERNANCE_REPLAY_SERVICE_URL"],
        token_env=values["token_env"],
        ca_path=Path(values["ca"]),
        receipt_public_key=Path(values["receipt_key"]),
        client_cert=Path(values["client_cert"]),
        client_key=Path(values["client_key"]),
        receipt_state_path=Path(state_text),
    )
    trusted_time = _timestamp(receipt["consumed_at"], "remote replay consumed_at")
    valid_from = document.get("valid_from", document.get("issued_at"))
    valid_until = document.get("valid_until", document.get("expires_at"))
    if (
        valid_from is not None
        and valid_until is not None
        and not (
            _timestamp(valid_from, "valid_from")
            <= trusted_time
            <= _timestamp(valid_until, "valid_until")
        )
    ):
        raise ValueError("governance evidence is invalid at trusted replay time")
    return {
        "replay_backend": "remote-mtls-monotonic",
        "replay_receipt_sequence": receipt["sequence"],
        "replay_receipt_sha256": receipt["receipt_sha256"],
        "replay_receipt_key_id": receipt["key_id"],
        "trusted_consumed_at": receipt["consumed_at"],
    }


def _exact_keys(document: dict[str, Any], expected: set[str], label: str) -> None:
    if set(document) != expected:
        raise ValueError(f"{label} fields do not match the versioned contract")


def _bounded_text(value: object, label: str) -> str:
    text = value if isinstance(value, str) else ""
    if not text or len(text) > 500:
        raise ValueError(f"{label} must be non-empty and at most 500 characters")
    return text


def _digest(value: object, label: str) -> str:
    digest = value.casefold() if isinstance(value, str) else ""
    if len(digest) != _DIGEST_LENGTH or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise ValueError(f"{label} must be exactly 64 hexadecimal characters")
    return digest


def _timestamp(value: object, label: str) -> datetime:
    text = _bounded_text(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)
