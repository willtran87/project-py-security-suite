from __future__ import annotations

import base64
import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from .path_safety import read_regular_file
from .strict_json import canonical_bytes, loads as strict_loads


def verify_deployment_receipt(
    subject: object,
    *,
    purpose: str,
    environment_prefix: str,
    observed_at: datetime | None = None,
    challenge_sha256: str | None = None,
) -> dict[str, Any]:
    """Verify a portable, time-bounded Ed25519 authority receipt for a subject.

    The receipt and public key are separately deployment-pinned.  A generation
    floor prevents an otherwise-valid older authorization from being restored.
    """

    receipt_path, receipt_digest = _pair(environment_prefix, "RECEIPT")
    key_path, key_digest = _pair(environment_prefix, "KEY")
    raw_minimum = os.environ.get(f"{environment_prefix}_MIN_GENERATION", "1").strip()
    try:
        minimum_generation = int(raw_minimum)
    except ValueError as exc:
        raise ValueError("deployment receipt generation floor is invalid") from exc
    if minimum_generation < 1:
        raise ValueError("deployment receipt generation floor is invalid")

    _, receipt_payload = read_regular_file(
        receipt_path, "deployment authority receipt", maximum_bytes=1024 * 1024
    )
    if hashlib.sha256(receipt_payload).hexdigest() != receipt_digest:
        raise ValueError("deployment authority receipt does not match its pin")
    _, key_payload = read_regular_file(
        key_path, "deployment authority public key", maximum_bytes=64 * 1024
    )
    if hashlib.sha256(key_payload).hexdigest() != key_digest:
        raise ValueError("deployment authority public key does not match its pin")
    try:
        key = serialization.load_pem_public_key(key_payload)
    except (TypeError, ValueError) as exc:
        raise ValueError("deployment authority public key is invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("deployment authority key must be Ed25519")

    value = strict_loads(receipt_payload)
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "statement",
        "signature_base64",
    }:
        raise ValueError("deployment authority receipt fields do not match")
    statement = value.get("statement")
    fields = {
        "schema_version",
        "purpose",
        "subject_sha256",
        "challenge_sha256",
        "generation",
        "issued_at",
        "expires_at",
        "signer_key_sha256",
    }
    if not isinstance(statement, dict) or set(statement) != fields:
        raise ValueError("deployment authority statement fields do not match")
    challenge = (
        challenge_sha256
        or os.environ.get("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "").strip().casefold()
    )
    generation = statement.get("generation")
    if (
        value.get("schema_version") != "1.0"
        or statement.get("schema_version") != "1.0"
        or statement.get("purpose") != purpose
        or statement.get("subject_sha256")
        != hashlib.sha256(canonical_bytes(subject)).hexdigest()
        or not _digest(challenge)
        or statement.get("challenge_sha256") != challenge
        or statement.get("signer_key_sha256") != key_digest
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < minimum_generation
    ):
        raise ValueError("deployment authority statement is not bound to this scan")
    now = (observed_at or _scan_observed_at()).astimezone(UTC)
    issued = _timestamp(statement.get("issued_at"), "issued_at")
    expires = _timestamp(statement.get("expires_at"), "expires_at")
    if (
        issued > now
        or expires <= issued
        or expires - issued > timedelta(days=7)
        or now > expires
    ):
        raise ValueError("deployment authority receipt is outside its validity window")
    try:
        signature = base64.b64decode(
            str(value.get("signature_base64") or ""), validate=True
        )
        key.verify(signature, canonical_bytes(statement))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError("deployment authority receipt signature is invalid") from exc
    return {
        "schema_version": "1.0",
        "statement": statement,
        "signature_base64": value["signature_base64"],
        "public_key_pem_base64": base64.b64encode(key_payload).decode("ascii"),
        "receipt_sha256": receipt_digest,
    }


def _pair(prefix: str, kind: str) -> tuple[Path, str]:
    raw_path = os.environ.get(f"{prefix}_{kind}_PATH", "").strip()
    digest = os.environ.get(f"{prefix}_{kind}_SHA256", "").strip().casefold()
    if not raw_path or not _digest(digest):
        raise ValueError("deployment authority receipt configuration is incomplete")
    return Path(raw_path).expanduser().resolve(), digest


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"deployment authority {label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"deployment authority {label} is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"deployment authority {label} must include a timezone")
    return parsed.astimezone(UTC)


def _scan_observed_at() -> datetime:
    from .trusted_observation import scan_observed_at

    return scan_observed_at()


def _digest(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)
