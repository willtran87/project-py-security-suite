from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from .path_safety import read_regular_file
from .operation_receipt import verify_operation_receipt
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
        observed_at=now,
        challenge_sha256=challenge,
    )
    portable = {
        "schema_version": "1.0",
        "statement": statement,
        "signature_base64": value["signature_base64"],
        "public_key_pem_base64": base64.b64encode(key_payload).decode("ascii"),
        "receipt_payload_base64": base64.b64encode(receipt_payload).decode("ascii"),
        "receipt_sha256": receipt_digest,
        "monotonic_state": monotonic_state,
        "verified_at": now.isoformat(),
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
        "verified_at",
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
    verified_at = _timestamp(receipt.get("verified_at"), "verified_at")
    if (
        receipt.get("schema_version") != "1.0"
        or verified_at > now
        or verified_at < issued
        or verified_at > expires
        or not isinstance(monotonic_state, dict)
        or set(monotonic_state)
        != {
            "mode",
            "backend_identity_sha256",
            "operation_id",
            "generation",
            "previous_generation",
            "previous_receipt_sha256",
            "backend_receipt",
            "request_sha256",
            "witness_policy",
            "witnesses",
            "execution_transcript",
            "effective_policy_attestation",
        }
        or monotonic_state.get("mode") not in {"external-command", "local-sqlite"}
        or not _digest(str(monotonic_state.get("backend_identity_sha256") or ""))
        or not str(monotonic_state.get("operation_id") or "")
        or monotonic_state.get("generation") != statement.get("generation")
        or not isinstance(monotonic_state.get("previous_generation"), int)
        or monotonic_state["previous_generation"] < 0
        or monotonic_state["previous_generation"] > monotonic_state["generation"]
        or not _optional_digest(monotonic_state.get("previous_receipt_sha256"))
        or not _optional_digest(monotonic_state.get("request_sha256"))
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
    if monotonic_state["mode"] == "external-command":
        attestation = monotonic_state["effective_policy_attestation"]
        attestation_subject = (
            attestation.get("subject") if isinstance(attestation, dict) else None
        )
        if (
            not isinstance(attestation, dict)
            or set(attestation) != {"subject", "operation_receipt"}
            or not isinstance(attestation_subject, dict)
            or not _digest(str(attestation_subject.get("attestor_key_sha256") or ""))
        ):
            raise ValueError("retained command effective-policy attestation is invalid")
        from .pinned_command import verify_effective_policy_subject

        verify_effective_policy_subject(attestation_subject)
        attestation_statement = attestation["operation_receipt"].get("statement", {})
        attestation_issued = _timestamp(
            attestation_statement.get("issued_at"), "effective-policy issued_at"
        )
        verify_operation_receipt(
            attestation_subject,
            attestation["operation_receipt"],
            purpose="pinned-command-effective-policy",
            observed_at=attestation_issued,
            challenge_sha256=challenge_sha256,
            expected_key_sha256=str(attestation_subject["attestor_key_sha256"]),
        )
        backend_subject = _monotonic_backend_subject(
            purpose=purpose,
            generation=int(statement["generation"]),
            receipt_sha256=str(receipt["receipt_sha256"]),
            previous_generation=int(monotonic_state["previous_generation"]),
            previous_receipt_sha256=str(
                monotonic_state["previous_receipt_sha256"] or ""
            ),
            backend_identity_sha256=str(monotonic_state["backend_identity_sha256"]),
            operation_id=str(monotonic_state["operation_id"]),
            request_sha256=str(monotonic_state["request_sha256"]),
            execution_transcript=monotonic_state["execution_transcript"],
        )
        verified_backend = verify_operation_receipt(
            backend_subject,
            monotonic_state["backend_receipt"],
            purpose="monotonic-state-compare-and-advance",
            observed_at=now,
            challenge_sha256=challenge_sha256,
            expected_key_sha256=str(monotonic_state["backend_identity_sha256"]),
        )
        if (
            verified_backend["statement"]["operation_id"]
            != monotonic_state["operation_id"]
            or verified_backend["statement"]["previous_operation_sha256"]
            != monotonic_state["previous_receipt_sha256"]
        ):
            raise ValueError("monotonic backend receipt chain is invalid")
        _verify_monotonic_witnesses(
            backend_subject,
            monotonic_state["witness_policy"],
            monotonic_state["witnesses"],
            observed_at=now,
            challenge_sha256=challenge_sha256,
        )
    elif (
        monotonic_state["backend_receipt"] is not None
        or monotonic_state["effective_policy_attestation"] is not None
    ):
        raise ValueError("local monotonic state must not claim an external receipt")
    try:
        signature = base64.b64decode(
            str(receipt.get("signature_base64") or ""), validate=True
        )
        key.verify(signature, canonical_bytes(statement))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError("portable deployment receipt signature is invalid") from exc
    return dict(receipt)


def _advance_monotonic_state(
    prefix: str,
    *,
    purpose: str,
    generation: int,
    receipt_sha256: str,
    observed_at: datetime,
    challenge_sha256: str,
) -> dict[str, Any]:
    command_prefix = f"{prefix}_STATE"
    if command_configured(command_prefix):
        request = {
            "schema_version": "1.0",
            "operation": "compare-and-advance",
            "purpose": purpose,
            "generation": generation,
            "receipt_sha256": receipt_sha256,
            "challenge_sha256": challenge_sha256,
        }
        response = run_pinned_json_command(
            command_prefix,
            request,
        )
        effective_policy_attestation = response.pop(
            "_effective_policy_attestation", None
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
                "previous_generation",
                "previous_receipt_sha256",
                "backend_receipt",
                "request_sha256",
                "witness_policy",
                "witnesses",
                "execution_transcript",
            }
            or response.get("schema_version") != "1.0"
            or response.get("accepted") is not True
            or response.get("generation") != generation
            or response.get("receipt_sha256") != receipt_sha256
            or not _digest(str(response.get("backend_identity_sha256") or ""))
            or not str(response.get("operation_id") or "")
            or not isinstance(response.get("previous_generation"), int)
            or response["previous_generation"] < 0
            or response["previous_generation"] > generation
            or not _optional_digest(response.get("previous_receipt_sha256"))
            or response.get("request_sha256")
            != hashlib.sha256(canonical_bytes(request)).hexdigest()
            or not _execution_transcript_valid(
                response.get("execution_transcript"),
                cast(dict[str, Any], request["command_context"]),
            )
        ):
            raise ValueError("external monotonic state rejected receipt advancement")
        backend_subject = _monotonic_backend_subject(
            purpose=purpose,
            generation=generation,
            receipt_sha256=receipt_sha256,
            previous_generation=response["previous_generation"],
            previous_receipt_sha256=str(response["previous_receipt_sha256"] or ""),
            backend_identity_sha256=str(response["backend_identity_sha256"]),
            operation_id=str(response["operation_id"]),
            request_sha256=str(response["request_sha256"]),
            execution_transcript=response["execution_transcript"],
        )
        verified_backend = verify_operation_receipt(
            backend_subject,
            response["backend_receipt"],
            purpose="monotonic-state-compare-and-advance",
            observed_at=observed_at,
            challenge_sha256=challenge_sha256,
            expected_key_sha256=str(response["backend_identity_sha256"]),
        )
        if (
            verified_backend["statement"]["operation_id"] != response["operation_id"]
            or verified_backend["statement"]["previous_operation_sha256"]
            != response["previous_receipt_sha256"]
        ):
            raise ValueError("external monotonic state receipt chain is invalid")
        expected_backend_key = (
            os.environ.get(f"{command_prefix}_BACKEND_KEY_SHA256", "")
            .strip()
            .casefold()
        )
        try:
            expected_witness_policy = strict_loads(
                os.environ.get(f"{command_prefix}_WITNESS_KEYS_JSON", "").encode()
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("external monotonic witness policy is invalid") from exc
        if (
            not _digest(expected_backend_key)
            or expected_backend_key != response["backend_identity_sha256"]
            or response["witness_policy"] != expected_witness_policy
        ):
            raise ValueError("external monotonic trust policy does not match its pins")
        _verify_monotonic_witnesses(
            backend_subject,
            response["witness_policy"],
            response["witnesses"],
            observed_at=observed_at,
            challenge_sha256=challenge_sha256,
        )
        return {
            "mode": "external-command",
            "backend_identity_sha256": response["backend_identity_sha256"],
            "operation_id": response["operation_id"],
            "generation": generation,
            "previous_generation": response["previous_generation"],
            "previous_receipt_sha256": response["previous_receipt_sha256"],
            "backend_receipt": response["backend_receipt"],
            "request_sha256": response["request_sha256"],
            "witness_policy": response["witness_policy"],
            "witnesses": response["witnesses"],
            "execution_transcript": response["execution_transcript"],
            "effective_policy_attestation": effective_policy_attestation,
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
        previous_generation = int(row[0]) if row is not None else 0
        previous_receipt_sha256 = str(row[1]) if row is not None else ""
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
        "previous_generation": previous_generation,
        "previous_receipt_sha256": previous_receipt_sha256,
        "backend_receipt": None,
        "request_sha256": "",
        "witness_policy": None,
        "witnesses": [],
        "execution_transcript": None,
        "effective_policy_attestation": None,
    }


def _monotonic_backend_subject(
    *,
    purpose: str,
    generation: int,
    receipt_sha256: str,
    previous_generation: int,
    previous_receipt_sha256: str,
    backend_identity_sha256: str,
    operation_id: str,
    request_sha256: str,
    execution_transcript: object,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "operation": "compare-and-advance",
        "purpose": purpose,
        "generation": generation,
        "receipt_sha256": receipt_sha256,
        "previous_generation": previous_generation,
        "previous_receipt_sha256": previous_receipt_sha256,
        "backend_identity_sha256": backend_identity_sha256,
        "operation_id": operation_id,
        "request_sha256": request_sha256,
        "execution_transcript": execution_transcript,
    }


def _verify_monotonic_witnesses(
    subject: dict[str, Any],
    policy: object,
    witnesses: object,
    *,
    observed_at: datetime,
    challenge_sha256: str,
) -> None:
    if (
        not isinstance(policy, dict)
        or len(policy) < 2
        or not isinstance(witnesses, list)
        or len(witnesses) < 2
    ):
        raise ValueError("monotonic state witness quorum is unavailable")
    organizations: set[str] = set()
    keys: set[str] = set()
    for receipt in witnesses:
        statement = receipt.get("statement") if isinstance(receipt, dict) else None
        key_sha256 = str((statement or {}).get("signer_key_sha256") or "")
        organization = policy.get(key_sha256)
        if (
            not _digest(key_sha256)
            or not isinstance(organization, str)
            or not organization
            or key_sha256 in keys
        ):
            raise ValueError("monotonic state witness is not policy-approved")
        verify_operation_receipt(
            subject,
            receipt,
            purpose="monotonic-state-witness",
            observed_at=observed_at,
            challenge_sha256=challenge_sha256,
            expected_key_sha256=key_sha256,
        )
        keys.add(key_sha256)
        organizations.add(organization)
    if len(keys) < 2 or len(organizations) < 2:
        raise ValueError("monotonic state witness organizations are not independent")


def _execution_transcript_valid(value: object, context: dict[str, Any]) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "mode",
        "endpoint",
        "peer_identity_sha256",
        "sandbox_identity_sha256",
        "session_id",
    }:
        return False
    endpoints = context["allowed_endpoints"]
    local = not endpoints
    return bool(
        value["mode"] == ("local-sandbox" if local else "mtls")
        and value["endpoint"] == ("" if local else value["endpoint"])
        and (local or value["endpoint"] in endpoints)
        and value["peer_identity_sha256"]
        == ("" if local else context["mtls_identity_sha256"])
        and value["sandbox_identity_sha256"] == context["sandbox_identity_sha256"]
        and isinstance(value["session_id"], str)
        and 16 <= len(value["session_id"]) <= 200
    )


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


def _optional_digest(value: object) -> bool:
    text = str(value or "")
    return not text or _digest(text)
