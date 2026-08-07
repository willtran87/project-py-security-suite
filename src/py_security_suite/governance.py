from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import IntelligenceConfig, IsolationConfig
from .execution import sha256_file
from .path_safety import resolve_regular_file

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
        )
        _validate_isolation_document(
            document,
            target_name=target_name,
            source_sha256=source_sha256,
            observed_at=observed_at,
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
        )
        _validate_intelligence_document(
            document,
            snapshots=snapshots if isinstance(snapshots, dict) else {},
            observed_at=observed_at,
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
    path: Path, expected_digest: str, label: str
) -> tuple[dict[str, Any], str]:
    source = resolve_regular_file(path, label)
    if source.stat().st_size > _MAX_EVIDENCE_BYTES:
        raise ValueError(f"{label} exceeds {_MAX_EVIDENCE_BYTES} bytes")
    digest = sha256_file(source)
    if digest != expected_digest.casefold():
        raise ValueError(f"{label} does not match the approved SHA-256")
    document = json.loads(source.read_bytes())
    if not isinstance(document, dict):
        raise TypeError(f"{label} root must be an object")
    return document, digest


def _validate_isolation_document(
    document: dict[str, Any],
    *,
    target_name: str,
    source_sha256: str,
    observed_at: datetime,
) -> None:
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
    if (
        document["schema_version"] != "1.0"
        or document["status"] != "enforced"
        or document["network_policy"] != "deny"
        or document["signature_verified"] is not True
    ):
        raise ValueError("isolation evidence does not assert an enforced signed denial")
    if document["target"] not in {"*", target_name}:
        raise ValueError("isolation evidence target does not match the scan target")
    _digest(document["source_sha256"], "source_sha256")
    if document["source_sha256"] != source_sha256:
        raise ValueError("isolation evidence source digest does not match the target")
    for name in ("policy_sha256", "trust_root_sha256"):
        _digest(document[name], name)
    for name in ("issuer", "runner_id", "policy_id", "approved_by", "verifier"):
        _bounded_text(document[name], name)
    valid_from = _timestamp(document["valid_from"], "valid_from")
    valid_until = _timestamp(document["valid_until"], "valid_until")
    if valid_until <= valid_from or not valid_from <= observed_at <= valid_until:
        raise ValueError("isolation evidence is outside its approved validity window")


def _validate_intelligence_document(
    document: dict[str, Any],
    *,
    snapshots: dict[str, Any],
    observed_at: datetime,
) -> None:
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
    if (
        document["schema_version"] != "1.0"
        or document["status"] != "approved"
        or document["signature_verified"] is not True
    ):
        raise ValueError("intelligence approval is not approved and signature-verified")
    for name in ("manifest_id", "revision", "approved_by", "verifier"):
        _bounded_text(document[name], name)
    _digest(document["trust_root_sha256"], "trust_root_sha256")
    if _timestamp(document["valid_until"], "valid_until") < observed_at:
        raise ValueError("intelligence approval has expired")
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
