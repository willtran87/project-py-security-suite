from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .strict_json import canonical_bytes, loads as strict_loads


def verify_authority_quorum(
    context: Path,
    values: object,
    subject: object,
    threshold: int,
    at: datetime,
    *,
    purpose: str,
    require_organizations: bool = False,
    trust_environment: Mapping[str, str] | None = None,
) -> list[tuple[str, str, str, str]]:
    """Verify lifecycle-scoped, role-bound independent authority signatures."""

    if not isinstance(values, list) or not threshold <= len(values) <= 16:
        raise ValueError("assurance profile does not contain enough authorities")
    environment = os.environ if trust_environment is None else trust_environment
    trusted = {
        item.strip()
        for item in environment.get("PYSEC_TRUSTED_AUTHORITY_KEY_SHA256", "").split(",")
        if item.strip()
    }
    if not trusted or any(not _digest(item) for item in trusted):
        raise ValueError("organization authority trust anchors are not configured")
    try:
        roles = strict_loads(
            environment.get("PYSEC_TRUSTED_AUTHORITY_ROLES", "").encode()
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("organization authority role policy is invalid") from exc
    if not isinstance(roles, dict):
        raise ValueError("organization authority role policy is invalid")
    organizations = _organization_policy(environment) if require_organizations else {}
    result: list[tuple[str, str, str, str]] = []
    for authority in values:
        v1_required = {
            "schema_version",
            "signer_id",
            "collector_id",
            "signed_at",
            "expires_at",
            "public_key_file",
            "public_key_sha256",
            "signature_file",
            "signature_sha256",
        }
        if not isinstance(authority, dict):
            raise ValueError("assurance profile authority fields are invalid")
        version = authority.get("schema_version")
        required = v1_required | ({"algorithm"} if version == "2.0" else set())
        if version not in {"1.0", "2.0"} or set(authority) != required:
            raise ValueError("assurance profile authority fields are invalid")
        algorithm = (
            "ed25519" if version == "1.0" else str(authority.get("algorithm") or "")
        )
        if algorithm not in {"ed25519", "ecdsa-p256-sha256"}:
            raise ValueError("assurance profile authority algorithm is unsupported")
        signer = str(authority.get("signer_id") or "")
        collector = _label(authority.get("collector_id"), "collector_id")
        signed_at = _timestamp(authority.get("signed_at"), "authority signed_at")
        expires_at = _timestamp(authority.get("expires_at"), "authority expires_at")
        if not signed_at <= at <= expires_at or expires_at - signed_at > timedelta(
            days=31
        ):
            raise ValueError(
                "assurance profile authority is outside its validity window"
            )
        public_raw = _sibling(
            context,
            authority["public_key_file"],
            authority["public_key_sha256"],
            1024 * 1024,
        )
        signature = _sibling(
            context, authority["signature_file"], authority["signature_sha256"], 4096
        )
        try:
            public_key = serialization.load_pem_public_key(public_raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "assurance profile authority public key is invalid"
            ) from exc
        if algorithm == "ed25519" and not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("assurance profile authority key does not match Ed25519")
        if algorithm == "ecdsa-p256-sha256" and not (
            isinstance(public_key, ec.EllipticCurvePublicKey)
            and isinstance(public_key.curve, ec.SECP256R1)
        ):
            raise ValueError("assurance profile authority key does not match P-256")
        key_id = _public_key_id(public_key)
        if signer != key_id or key_id not in trusted:
            raise ValueError("assurance profile authority is not deployment-trusted")
        allowed_roles = roles.get(signer)
        if not isinstance(allowed_roles, list) or purpose not in allowed_roles:
            raise ValueError("assurance profile authority lacks its deployment role")
        statement = {
            "schema_version": str(version),
            "purpose": purpose,
            "subject_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
            "signer_id": signer,
            "collector_id": collector,
            "signed_at": signed_at.isoformat(),
            "expires_at": expires_at.isoformat(),
        }
        if version == "2.0":
            statement["algorithm"] = algorithm
        try:
            if isinstance(public_key, Ed25519PublicKey):
                public_key.verify(signature, canonical_bytes(statement))
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    signature, canonical_bytes(statement), ec.ECDSA(hashes.SHA256())
                )
            else:
                raise ValueError("assurance profile authority key type is unsupported")
        except Exception as exc:
            raise ValueError(
                "assurance profile authority signature verification failed"
            ) from exc
        organization = str(organizations.get(signer) or "legacy-unscoped")
        if require_organizations and not _label(organization, "authority organization"):
            raise ValueError("assurance profile authority organization is invalid")
        if require_organizations:
            _verify_key_lifecycle(
                signer, signed_at, expires_at, at, environment=environment
            )
        result.append((signer, collector, organization, algorithm))
    if (
        len({item[0] for item in result}) < threshold
        or len({item[1] for item in result}) < threshold
        or (require_organizations and len({item[2] for item in result}) < threshold)
    ):
        raise ValueError("assurance profile lacks independent signers or collectors")
    return result


def verify_governance_quorum(
    context: Path,
    values: object,
    subject: object,
    threshold: int,
    at: datetime,
    *,
    purpose: str,
    trust_environment: Mapping[str, str] | None = None,
) -> list[tuple[str, str, str, str]]:
    """Verify a domain-separated, lifecycle-scoped multi-organization quorum."""

    return verify_authority_quorum(
        context,
        values,
        subject,
        threshold,
        at,
        purpose=purpose,
        require_organizations=True,
        trust_environment=trust_environment,
    )


def _organization_policy(environment: Mapping[str, str]) -> dict[str, str]:
    try:
        value = strict_loads(
            environment.get("PYSEC_AUTHORITY_ORGANIZATIONS", "").encode()
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("organization authority mapping is invalid") from exc
    if not isinstance(value, dict) or not value:
        raise ValueError("organization authority mapping is not configured")
    result = {
        str(key): _label(item, "authority organization") for key, item in value.items()
    }
    if any(not _digest(key) for key in result):
        raise ValueError("organization authority mapping contains an invalid signer")
    return result


def _verify_key_lifecycle(
    signer: str,
    signed_at: datetime,
    expires_at: datetime,
    observed_at: datetime,
    *,
    environment: Mapping[str, str],
) -> None:
    try:
        value = strict_loads(
            environment.get("PYSEC_AUTHORITY_KEY_LIFECYCLE", "").encode()
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("organization authority key lifecycle is invalid") from exc
    record = value.get(signer) if isinstance(value, dict) else None
    if not isinstance(record, dict) or set(record) != {
        "not_before",
        "not_after",
        "revoked_at",
    }:
        raise ValueError("organization authority key lifecycle is not configured")
    not_before = _timestamp(record.get("not_before"), "key not_before")
    not_after = _timestamp(record.get("not_after"), "key not_after")
    revoked = record.get("revoked_at")
    revoked_at = (
        _timestamp(revoked, "key revoked_at") if revoked not in {None, ""} else None
    )
    if (
        not not_before <= signed_at <= expires_at <= not_after
        or not not_before <= observed_at <= not_after
        or (revoked_at is not None and signed_at >= revoked_at)
    ):
        raise ValueError("organization authority key is outside its lifecycle")


def _sibling(context: Path, name: object, expected: object, maximum: int) -> bytes:
    filename = str(name or "")
    if not filename or Path(filename).name != filename or len(filename) > 200:
        raise ValueError("assurance profile authority artifact must be a sibling file")
    path = context.resolve().parent / filename
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("assurance profile authority artifact is invalid")
    raw = path.read_bytes()
    if not _digest(str(expected)) or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("assurance profile authority artifact digest does not match")
    return raw


def _timestamp(value: object, label: str) -> datetime:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"assurance profile {label} is invalid") from exc
    if result.tzinfo is None:
        raise ValueError(f"assurance profile {label} requires a timezone")
    return result.astimezone(UTC)


def _label(value: object, label: str) -> str:
    result = str(value or "").strip()
    if (
        not result
        or len(result) > 200
        or any(ord(character) < 32 for character in result)
        or not all(character.isalnum() or character in "._:/@-" for character in result)
    ):
        raise ValueError(f"assurance profile {label} is invalid")
    return result


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _public_key_id(public_key: Any) -> str:
    if isinstance(public_key, Ed25519PublicKey):
        raw = public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        raw = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    else:
        raise ValueError("assurance profile authority key type is unsupported")
    return hashlib.sha256(raw).hexdigest()
