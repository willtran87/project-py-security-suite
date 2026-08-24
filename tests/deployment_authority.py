from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_security_suite.strict_json import canonical_bytes


def operation_receipt(
    subject: object,
    *,
    purpose: str,
    challenge: str = "c" * 64,
    operation_id: str = "operation-1",
    previous_operation_sha256: str = "",
    private_key: Ed25519PrivateKey | None = None,
) -> tuple[dict[str, object], str]:
    """Create a short-lived external-operation receipt for integration tests."""

    private = private_key or Ed25519PrivateKey.generate()
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_sha256 = hashlib.sha256(public_bytes).hexdigest()
    now = datetime.now(UTC)
    statement = {
        "schema_version": "1.0",
        "purpose": purpose,
        "subject_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
        "operation_id": operation_id,
        "previous_operation_sha256": previous_operation_sha256,
        "challenge_sha256": challenge,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "signer_key_sha256": key_sha256,
    }
    return (
        {
            "schema_version": "1.0",
            "statement": statement,
            "signature_base64": base64.b64encode(
                private.sign(canonical_bytes(statement))
            ).decode("ascii"),
            "public_key_pem_base64": base64.b64encode(public_bytes).decode("ascii"),
        },
        key_sha256,
    )


def authority_environment(
    root: Path,
    subject: object,
    *,
    purpose: str,
    prefix: str,
    challenge: str = "c" * 64,
) -> dict[str, str]:
    private = Ed25519PrivateKey.generate()
    public = root / f"{purpose}.authority.pem"
    public.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    key_sha256 = hashlib.sha256(public.read_bytes()).hexdigest()
    now = datetime.now(UTC)
    statement = {
        "schema_version": "1.0",
        "purpose": purpose,
        "subject_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
        "challenge_sha256": challenge,
        "generation": 1,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "signer_key_sha256": key_sha256,
    }
    receipt = root / f"{purpose}.authority-receipt.json"
    receipt.write_bytes(
        canonical_bytes(
            {
                "schema_version": "1.0",
                "statement": statement,
                "signature_base64": base64.b64encode(
                    private.sign(canonical_bytes(statement))
                ).decode("ascii"),
            }
        )
    )
    return {
        "PYSEC_SCAN_TIME_CHALLENGE_SHA256": challenge,
        f"{prefix}_RECEIPT_PATH": str(receipt),
        f"{prefix}_RECEIPT_SHA256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
        f"{prefix}_KEY_PATH": str(public),
        f"{prefix}_KEY_SHA256": key_sha256,
        f"{prefix}_MIN_GENERATION": "1",
        f"{prefix}_STATE_PATH": str(root / f"{purpose}.authority-state.sqlite3"),
    }
