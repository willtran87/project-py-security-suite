from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from .path_safety import read_regular_file
from .pinned_command import command_configured, run_pinned_json_command
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
    monotonic_state = _advance_monotonic_state(
        environment_prefix,
        purpose=purpose,
        generation=generation,
        receipt_sha256=receipt_digest,
    )
    portable = {
        "schema_version": "1.0",
        "statement": statement,
        "signature_base64": value["signature_base64"],
        "public_key_pem_base64": base64.b64encode(key_payload).decode("ascii"),
        "receipt_payload_base64": base64.b64encode(receipt_payload).decode("ascii"),
        "receipt_sha256": receipt_digest,
        "monotonic_state": monotonic_state,
    }
    verify_portable_receipt(
        subject,
        portable,
        purpose=purpose,
        observed_at=now,
        challenge_sha256=challenge,
        expected_key_sha256=key_digest,
    )
    return portable


def verify_portable_receipt(
    subject: object,
    receipt: object,
    *,
    purpose: str,
    observed_at: datetime,
    challenge_sha256: str,
    expected_key_sha256: str = "",
) -> dict[str, Any]:
    """Reverify a retained authority envelope without its original files."""

    if not isinstance(receipt, dict) or set(receipt) != {
        "schema_version",
        "statement",
        "signature_base64",
        "public_key_pem_base64",
        "receipt_payload_base64",
        "receipt_sha256",
        "monotonic_state",
    }:
        raise ValueError("portable deployment receipt fields do not match")
    statement = receipt.get("statement")
    monotonic_state = receipt.get("monotonic_state")
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
        raise ValueError("portable deployment receipt statement is invalid")
    try:
        receipt_payload = base64.b64decode(
            str(receipt.get("receipt_payload_base64") or ""), validate=True
        )
        original = strict_loads(receipt_payload)
        key_bytes = base64.b64decode(
            str(receipt.get("public_key_pem_base64") or ""), validate=True
        )
        key = serialization.load_pem_public_key(key_bytes)
    except (TypeError, ValueError) as exc:
        raise ValueError("portable deployment receipt key is invalid") from exc
    key_sha256 = hashlib.sha256(key_bytes).hexdigest()
    issued = _timestamp(statement.get("issued_at"), "issued_at")
    expires = _timestamp(statement.get("expires_at"), "expires_at")
    now = observed_at.astimezone(UTC)
    if (
        receipt.get("schema_version") != "1.0"
        or not isinstance(monotonic_state, dict)
        or set(monotonic_state)
        != {"mode", "backend_identity_sha256", "operation_id", "generation"}
        or monotonic_state.get("mode") not in {"external-command", "local-sqlite"}
        or not _digest(str(monotonic_state.get("backend_identity_sha256") or ""))
        or not str(monotonic_state.get("operation_id") or "")
        or monotonic_state.get("generation") != statement.get("generation")
        or hashlib.sha256(receipt_payload).hexdigest() != receipt.get("receipt_sha256")
        or original
        != {
            "schema_version": receipt["schema_version"],
            "statement": statement,
            "signature_base64": receipt["signature_base64"],
        }
        or statement.get("schema_version") != "1.0"
        or statement.get("purpose") != purpose
        or statement.get("subject_sha256")
        != hashlib.sha256(canonical_bytes(subject)).hexdigest()
        or statement.get("challenge_sha256") != challenge_sha256
        or statement.get("signer_key_sha256") != key_sha256
        or (expected_key_sha256 and key_sha256 != expected_key_sha256)
        or not isinstance(key, Ed25519PublicKey)
        or issued > now
        or expires <= issued
        or expires - issued > timedelta(days=7)
        or now > expires
    ):
        raise ValueError("portable deployment receipt trust binding is invalid")
    try:
        signature = base64.b64decode(
            str(receipt.get("signature_base64") or ""), validate=True
        )
        key.verify(signature, canonical_bytes(statement))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError("portable deployment receipt signature is invalid") from exc
    return dict(receipt)


def _advance_monotonic_state(
    prefix: str, *, purpose: str, generation: int, receipt_sha256: str
) -> dict[str, Any]:
    command_prefix = f"{prefix}_STATE"
    if command_configured(command_prefix):
        response = run_pinned_json_command(
            command_prefix,
            {
                "schema_version": "1.0",
                "operation": "compare-and-advance",
                "purpose": purpose,
                "generation": generation,
                "receipt_sha256": receipt_sha256,
            },
        )
        if (
            set(response)
            != {
                "schema_version",
                "accepted",
                "generation",
                "receipt_sha256",
                "backend_identity_sha256",
                "operation_id",
            }
            or response.get("schema_version") != "1.0"
            or response.get("accepted") is not True
            or response.get("generation") != generation
            or response.get("receipt_sha256") != receipt_sha256
            or not _digest(str(response.get("backend_identity_sha256") or ""))
            or not str(response.get("operation_id") or "")
        ):
            raise ValueError("external monotonic state rejected receipt advancement")
        return {
            "mode": "external-command",
            "backend_identity_sha256": response["backend_identity_sha256"],
            "operation_id": response["operation_id"],
            "generation": generation,
        }
    raw_path = os.environ.get(f"{prefix}_STATE_PATH", "").strip()
    if not raw_path:
        raise ValueError("deployment authority monotonic state is unavailable")
    path = Path(raw_path).expanduser().resolve()
    if path.is_symlink():
        raise ValueError("deployment authority state must not be a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30, isolation_level=None)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS receipt_state "
            "(purpose TEXT PRIMARY KEY, generation INTEGER NOT NULL, receipt_sha256 TEXT NOT NULL)"
        )
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT generation, receipt_sha256 FROM receipt_state WHERE purpose = ?",
            (purpose,),
        ).fetchone()
        if row is not None and (
            generation < int(row[0])
            or (generation == int(row[0]) and receipt_sha256 != str(row[1]))
        ):
            connection.execute("ROLLBACK")
            raise ValueError("deployment authority receipt rollback or fork detected")
        connection.execute(
            "INSERT INTO receipt_state(purpose, generation, receipt_sha256) VALUES (?, ?, ?) "
            "ON CONFLICT(purpose) DO UPDATE SET generation=excluded.generation, "
            "receipt_sha256=excluded.receipt_sha256",
            (purpose, generation, receipt_sha256),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return {
        "mode": "local-sqlite",
        "backend_identity_sha256": hashlib.sha256(str(path).encode()).hexdigest(),
        "operation_id": "sqlite-immediate-transaction",
        "generation": generation,
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
