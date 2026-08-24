from __future__ import annotations

import base64
import hashlib
import os
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .strict_json import canonical_bytes


def verify_operation_receipt(
    subject: object,
    receipt: object,
    *,
    purpose: str,
    observed_at: datetime,
    challenge_sha256: str,
    expected_key_sha256: str,
    expected_trusted_time_sha256: str | None = None,
) -> dict[str, Any]:
    """Verify a compact signed receipt emitted by an external operation backend."""

    if not isinstance(receipt, dict) or set(receipt) != {
        "schema_version",
        "statement",
        "signature_base64",
        "public_key_pem_base64",
    }:
        raise ValueError("operation receipt fields do not match")
    statement = receipt.get("statement")
    fields = {
        "schema_version",
        "purpose",
        "subject_sha256",
        "operation_id",
        "previous_operation_sha256",
        "challenge_sha256",
        "trusted_time_sha256",
        "issued_at",
        "expires_at",
        "signer_key_sha256",
    }
    if not isinstance(statement, dict) or set(statement) != fields:
        raise ValueError("operation receipt statement fields do not match")
    try:
        public_bytes = base64.b64decode(
            str(receipt["public_key_pem_base64"]), validate=True
        )
        signature = base64.b64decode(str(receipt["signature_base64"]), validate=True)
        public_key = serialization.load_pem_public_key(public_bytes)
    except (TypeError, ValueError) as exc:
        raise ValueError("operation receipt encoding is invalid") from exc
    key_sha256 = hashlib.sha256(public_bytes).hexdigest()
    issued = _timestamp(statement.get("issued_at"), "operation issued_at")
    expires = _timestamp(statement.get("expires_at"), "operation expires_at")
    expected_time = (
        expected_trusted_time_sha256
        if expected_trusted_time_sha256 is not None
        else os.environ.get("PYSEC_SCAN_TIME_CONTEXT_SHA256", "")
    ).strip().casefold()
    now = _trusted_observed_at(observed_at)
    if (
        receipt.get("schema_version") != "1.0"
        or statement.get("schema_version") != "1.0"
        or statement.get("purpose") != purpose
        or statement.get("subject_sha256")
        != hashlib.sha256(canonical_bytes(subject)).hexdigest()
        or statement.get("challenge_sha256") != challenge_sha256
        or not _digest(expected_time)
        or statement.get("trusted_time_sha256") != expected_time
        or statement.get("signer_key_sha256") != key_sha256
        or key_sha256 != expected_key_sha256
        or not isinstance(public_key, Ed25519PublicKey)
        or not _label(statement.get("operation_id"))
        or not _optional_digest(statement.get("previous_operation_sha256"))
        or issued > now + timedelta(hours=24)
        or expires <= issued
        or expires - issued > timedelta(hours=24)
        or now > expires
    ):
        raise ValueError("operation receipt trust binding is invalid")
    try:
        public_key.verify(signature, canonical_bytes(statement))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise ValueError("operation receipt signature is invalid") from exc
    return dict(receipt)


def _trusted_observed_at(fallback: datetime) -> datetime:
    if os.environ.get("PYSEC_SCAN_TIME_CONTEXT_PATH", "").strip():
        from .trusted_observation import scan_observed_at

        return scan_observed_at().astimezone(UTC)
    return fallback.astimezone(UTC)


def _timestamp(value: object, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _optional_digest(value: object) -> bool:
    text = str(value or "")
    return not text or (
        len(text) == 64 and all(character in "0123456789abcdef" for character in text)
    )


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _label(value: object) -> bool:
    text = str(value or "")
    return (
        bool(text)
        and len(text) <= 200
        and all(ord(character) >= 32 for character in text)
    )
