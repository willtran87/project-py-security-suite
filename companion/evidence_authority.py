from __future__ import annotations

import hashlib
import base64
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:
    from companion.strict_json import canonical_bytes
except ModuleNotFoundError:  # Direct script execution.
    from strict_json import canonical_bytes  # type: ignore[import-not-found,no-redef]


def verify_authority(
    context: Path,
    value: object,
    *,
    purpose: str,
    subject: object,
    at: datetime | None = None,
) -> dict[str, Any]:
    """Verify an independently signed, short-lived authority statement.

    The signature covers the purpose, canonical subject digest, validity window,
    signer identity, and collector identity.  Callers retain only digests and
    identities, never the signed source payload.
    """
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
    if not isinstance(value, dict):
        raise ValueError("authority fields do not match the v1 contract")
    version = value.get("schema_version")
    required = v1_required | ({"algorithm"} if version == "2.0" else set())
    if version not in {"1.0", "2.0"} or set(value) != required:
        raise ValueError("authority fields do not match a supported contract")
    algorithm = "ed25519" if version == "1.0" else str(value.get("algorithm") or "")
    if algorithm not in {"ed25519", "ecdsa-p256-sha256"}:
        raise ValueError("authority signature algorithm is unsupported")
    signer_id = _label(value.get("signer_id"), "authority signer")
    collector_id = _label(value.get("collector_id"), "authority collector")
    signed_at = _timestamp(value.get("signed_at"), "authority signed_at")
    expires_at = _timestamp(value.get("expires_at"), "authority expires_at")
    observed_at = (at or datetime.now(UTC)).astimezone(UTC)
    if expires_at <= signed_at or not signed_at <= observed_at <= expires_at:
        raise ValueError("authority statement is not valid at observation time")
    if expires_at - signed_at > timedelta(days=31):
        raise ValueError("authority validity window exceeds 31 days")
    public_key_bytes = _pinned_sibling(
        context,
        value.get("public_key_file"),
        value.get("public_key_sha256"),
        "authority public key",
        1024 * 1024,
    )
    signature = _pinned_sibling(
        context,
        value.get("signature_file"),
        value.get("signature_sha256"),
        "authority signature",
        4096,
    )
    statement = {
        "schema_version": str(version),
        "purpose": _label(purpose, "authority purpose"),
        "subject_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
        "signer_id": signer_id,
        "collector_id": collector_id,
        "signed_at": signed_at.isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    if version == "2.0":
        statement["algorithm"] = algorithm
    try:
        public_key = serialization.load_pem_public_key(public_key_bytes)
    except (TypeError, ValueError) as exc:
        raise ValueError("authority public key is invalid") from exc
    if algorithm == "ed25519" and not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("authority public key does not match Ed25519 policy")
    if algorithm == "ecdsa-p256-sha256" and not (
        isinstance(public_key, ec.EllipticCurvePublicKey)
        and isinstance(public_key.curve, ec.SECP256R1)
    ):
        raise ValueError("authority public key does not match P-256 policy")
    try:
        if isinstance(public_key, Ed25519PublicKey):
            public_key.verify(signature, canonical_bytes(statement))
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature, canonical_bytes(statement), ec.ECDSA(hashes.SHA256())
            )
        else:
            raise ValueError("authority public key type is unsupported")
    except Exception as exc:
        raise ValueError("authority signature verification failed") from exc
    if not isinstance(public_key, (Ed25519PublicKey, ec.EllipticCurvePublicKey)):
        raise ValueError("authority public key type is unsupported")
    key_id = _public_key_id(public_key)
    if signer_id != key_id:
        raise ValueError("authority signer_id does not match its public key")
    _verify_organizational_trust(signer_id, purpose)
    organization = _authority_organization(signer_id, required=version == "2.0")
    if version == "2.0":
        _verify_key_lifecycle(signer_id, signed_at, expires_at, observed_at)
    portable: dict[str, Any] = {
        "schema_version": "1.0",
        "statement": statement,
        "public_key_pem_base64": base64.b64encode(public_key_bytes).decode("ascii"),
        "public_key_sha256": hashlib.sha256(public_key_bytes).hexdigest(),
        "signature_base64": base64.b64encode(signature).decode("ascii"),
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
    }
    portable["receipt_sha256"] = hashlib.sha256(canonical_bytes(portable)).hexdigest()
    return {
        "schema_version": str(version),
        "signer_id": signer_id,
        "signer_ref": f"{algorithm}:{signer_id}",
        "collector_id": collector_id,
        "subject_sha256": statement["subject_sha256"],
        "signed_at": signed_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "trust_level": "organization-pinned",
        "algorithm": algorithm,
        "organization": organization,
        "portable_receipt": portable,
    }


def verify_portable_authority(
    value: object,
    *,
    purpose: str,
    subject: object,
    at: datetime,
) -> dict[str, str]:
    """Cryptographically reverify a self-contained public authority receipt."""

    required = {
        "schema_version",
        "statement",
        "public_key_pem_base64",
        "public_key_sha256",
        "signature_base64",
        "signature_sha256",
        "receipt_sha256",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != "1.0"
    ):
        raise ValueError("portable authority receipt fields do not match")
    receipt_subject = {name: value[name] for name in required - {"receipt_sha256"}}
    if (
        value["receipt_sha256"]
        != hashlib.sha256(canonical_bytes(receipt_subject)).hexdigest()
    ):
        raise ValueError("portable authority receipt commitment does not match")
    try:
        public_key_bytes = base64.b64decode(
            str(value["public_key_pem_base64"]), validate=True
        )
        signature = base64.b64decode(str(value["signature_base64"]), validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("portable authority receipt encoding is invalid") from exc
    if (
        not 1 <= len(public_key_bytes) <= 1024 * 1024
        or not 1 <= len(signature) <= 4096
        or hashlib.sha256(public_key_bytes).hexdigest() != value["public_key_sha256"]
        or hashlib.sha256(signature).hexdigest() != value["signature_sha256"]
    ):
        raise ValueError("portable authority receipt payload commitment does not match")
    statement = value["statement"]
    base_fields = {
        "schema_version",
        "purpose",
        "subject_sha256",
        "signer_id",
        "collector_id",
        "signed_at",
        "expires_at",
    }
    if not isinstance(statement, dict) or set(statement) not in {
        frozenset(base_fields),
        frozenset(base_fields | {"algorithm"}),
    }:
        raise ValueError("portable authority statement fields do not match")
    version = str(statement["schema_version"])
    algorithm = "ed25519" if version == "1.0" else str(statement.get("algorithm") or "")
    if version not in {"1.0", "2.0"} or algorithm not in {
        "ed25519",
        "ecdsa-p256-sha256",
    }:
        raise ValueError("portable authority statement algorithm is unsupported")
    if (
        statement["purpose"] != _label(purpose, "authority purpose")
        or statement["subject_sha256"]
        != hashlib.sha256(canonical_bytes(subject)).hexdigest()
    ):
        raise ValueError("portable authority statement subject does not match")
    signer_id = _label(statement["signer_id"], "authority signer")
    collector_id = _label(statement["collector_id"], "authority collector")
    signed_at = _timestamp(statement["signed_at"], "authority signed_at")
    expires_at = _timestamp(statement["expires_at"], "authority expires_at")
    if at.tzinfo is None:
        raise ValueError("portable authority verification time must include a timezone")
    observed_at = at.astimezone(UTC)
    if expires_at <= signed_at or not signed_at <= observed_at <= expires_at:
        raise ValueError("portable authority statement is not valid at trusted time")
    try:
        public_key = serialization.load_pem_public_key(public_key_bytes)
        if isinstance(public_key, Ed25519PublicKey) and algorithm == "ed25519":
            public_key.verify(signature, canonical_bytes(statement))
        elif (
            isinstance(public_key, ec.EllipticCurvePublicKey)
            and isinstance(public_key.curve, ec.SECP256R1)
            and algorithm == "ecdsa-p256-sha256"
        ):
            public_key.verify(
                signature, canonical_bytes(statement), ec.ECDSA(hashes.SHA256())
            )
        else:
            raise ValueError(
                "portable authority public key does not match its algorithm"
            )
    except Exception as exc:
        raise ValueError("portable authority signature verification failed") from exc
    if not isinstance(public_key, (Ed25519PublicKey, ec.EllipticCurvePublicKey)):
        raise ValueError("portable authority public key type is unsupported")
    if signer_id != _public_key_id(public_key):
        raise ValueError("portable authority signer does not match its public key")
    _verify_organizational_trust(signer_id, purpose)
    organization = _authority_organization(signer_id, required=version == "2.0")
    if version == "2.0":
        _verify_key_lifecycle(signer_id, signed_at, expires_at, observed_at)
    return {
        "schema_version": version,
        "signer_id": signer_id,
        "collector_id": collector_id,
        "organization": organization,
        "subject_sha256": str(statement["subject_sha256"]),
        "algorithm": algorithm,
        "receipt_sha256": str(value["receipt_sha256"]),
    }


def verify_authority_quorum(
    context: Path,
    values: object,
    *,
    purpose: str,
    subject: object,
    minimum_signatures: int,
    at: datetime | None = None,
) -> list[dict[str, Any]]:
    """Verify a separation-of-duties quorum over one canonical subject.

    A quorum is intentionally stricter than accepting several signatures: both
    signer and collector identities must be distinct so a single collection
    boundary cannot manufacture organizational consensus.
    """
    if (
        isinstance(minimum_signatures, bool)
        or not isinstance(minimum_signatures, int)
        or not 2 <= minimum_signatures <= 16
    ):
        raise ValueError("authority quorum must require 2 to 16 signatures")
    if not isinstance(values, list) or not minimum_signatures <= len(values) <= 16:
        raise ValueError("authority quorum does not contain enough signatures")
    verified = [
        verify_authority(
            context,
            value,
            purpose=purpose,
            subject=subject,
            at=at,
        )
        for value in values
    ]
    signers = {item["signer_id"] for item in verified}
    collectors = {item["collector_id"] for item in verified}
    v2 = any(item["schema_version"] == "2.0" for item in verified)
    organizations = {item["organization"] for item in verified}
    if v2 and any(item["schema_version"] != "2.0" for item in verified):
        raise ValueError(
            "authority quorum cannot mix legacy and lifecycle-bound signers"
        )
    if (
        len(signers) < minimum_signatures
        or len(collectors) < minimum_signatures
        or (v2 and len(organizations) < minimum_signatures)
    ):
        raise ValueError("authority quorum lacks independent signers or collectors")
    return verified


def _verify_organizational_trust(signer_id: str, purpose: str) -> None:
    """Anchor the self-describing statement in deployment-owned configuration.

    The allowlist is deliberately external to the evidence directory, so an
    evidence producer cannot introduce a new signing authority by replacing a
    public key and its matching signature together.
    """
    raw = os.environ.get("PYSEC_TRUSTED_AUTHORITY_KEY_SHA256", "")
    trusted = {item.strip() for item in raw.split(",") if item.strip()}
    if not trusted or not all(_digest(item) for item in trusted):
        raise ValueError("organization authority trust anchors are not configured")
    if signer_id not in trusted:
        raise ValueError("authority signer is not organization-trusted")
    roles_raw = os.environ.get("PYSEC_TRUSTED_AUTHORITY_ROLES", "")
    if not roles_raw:
        raise ValueError("organization authority role policy is not configured")
    try:
        roles = json.loads(roles_raw)
    except json.JSONDecodeError as exc:
        raise ValueError("organization authority role policy is invalid") from exc
    allowed = roles.get(signer_id) if isinstance(roles, dict) else None
    if (
        not isinstance(allowed, list)
        or not allowed
        or any(not isinstance(item, str) for item in allowed)
        or purpose not in allowed
    ):
        raise ValueError("authority signer is not trusted for this purpose")


def _authority_organization(signer_id: str, *, required: bool) -> str:
    raw = os.environ.get("PYSEC_AUTHORITY_ORGANIZATIONS", "")
    if not raw and not required:
        return "legacy-unscoped"
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("authority organization policy is invalid") from exc
    organization = value.get(signer_id) if isinstance(value, dict) else None
    if (
        not isinstance(organization, str)
        or not organization.strip()
        or len(organization) > 200
        or any(ord(character) < 32 for character in organization)
    ):
        raise ValueError("authority signer lacks a deployment-bound organization")
    return organization.strip()


def _verify_key_lifecycle(
    signer_id: str,
    signed_at: datetime,
    expires_at: datetime,
    observed_at: datetime,
) -> None:
    raw = os.environ.get("PYSEC_AUTHORITY_KEY_LIFECYCLE", "")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("authority key lifecycle policy is invalid") from exc
    record = value.get(signer_id) if isinstance(value, dict) else None
    if not isinstance(record, dict) or set(record) != {
        "not_before",
        "not_after",
        "revoked_at",
    }:
        raise ValueError("authority key lifecycle is not deployment-bound")
    not_before = _timestamp(record.get("not_before"), "authority key not_before")
    not_after = _timestamp(record.get("not_after"), "authority key not_after")
    revoked_raw = record.get("revoked_at")
    revoked_at = (
        _timestamp(revoked_raw, "authority key revoked_at")
        if revoked_raw not in {None, ""}
        else None
    )
    if (
        not not_before <= signed_at <= expires_at <= not_after
        or not not_before <= observed_at <= not_after
        or (revoked_at is not None and signed_at >= revoked_at)
    ):
        raise ValueError("authority key is expired, not yet valid, or revoked")


def _pinned_sibling(
    context: Path,
    name: object,
    expected: object,
    label: str,
    maximum: int,
) -> bytes:
    filename = str(name or "")
    digest = str(expected or "")
    if not filename or Path(filename).name != filename or len(filename) > 200:
        raise ValueError(f"{label} must be a sibling file")
    path = context.resolve().parent / filename
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError(f"{label} must be a bounded regular file")
    payload = path.read_bytes()
    if not _digest(digest) or hashlib.sha256(payload).hexdigest() != digest:
        raise ValueError(f"{label} SHA-256 does not match")
    return payload


def _timestamp(value: object, label: str) -> datetime:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    if result.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return result.astimezone(UTC)


def _label(value: Any, label: str) -> str:
    result = str(value or "").strip()
    if (
        not result
        or len(result) > 200
        or any(ord(character) < 32 for character in result)
    ):
        raise ValueError(f"{label} is invalid")
    return result


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _public_key_id(
    public_key: Ed25519PublicKey | ec.EllipticCurvePublicKey,
) -> str:
    if isinstance(public_key, Ed25519PublicKey):
        encoded = public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    else:
        encoded = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    return hashlib.sha256(encoded).hexdigest()
