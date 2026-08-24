from __future__ import annotations

import hashlib
import base64
import hmac
import os
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .deployment_receipt import verify_portable_receipt
from .path_safety import read_regular_file
from .pinned_command import command_configured, run_pinned_json_command
from .operation_receipt import verify_operation_receipt
from .strict_json import dumps as strict_dumps
from .strict_json import loads as strict_loads
from .strict_json import canonical_bytes
from .failure_domain import (
    require_independent_failure_domains,
    verify_failure_domain,
    verify_registered_failure_domain,
)


def protect_native_report(payload: str, *, adapter: str) -> dict[str, Any]:
    """Return a redacted replay projection and optional encrypted raw CAS receipt."""

    encoded = payload.encode("utf-8")
    raw_sha256 = hashlib.sha256(encoded).hexdigest()
    redacted = _redact(strict_loads(payload))
    redacted_utf8 = strict_dumps(redacted)
    redacted_bytes = redacted_utf8.encode("utf-8")
    storage = _encrypted_sidecar(encoded, raw_sha256)
    return {
        "native_report_sha256": raw_sha256,
        "native_report_size_bytes": len(encoded),
        "native_report_redacted_utf8": redacted_utf8,
        "native_report_redacted_sha256": hashlib.sha256(redacted_bytes).hexdigest(),
        "native_report_redacted_size_bytes": len(redacted_bytes),
        "native_report_classification": "confidential",
        "native_report_adapter": adapter,
        "native_report_replayable": storage["mode"] == "encrypted-cas",
        "native_report_storage": storage,
    }


def _redact(value: object) -> object:
    if isinstance(value, dict):
        return {
            str(key): _redact(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str) and value:
        return "<redacted>"
    return value


def _encrypted_sidecar(payload: bytes, raw_sha256: str) -> dict[str, Any]:
    raw_directory = os.environ.get("PYSEC_RAW_EVIDENCE_DIRECTORY", "").strip()
    kms_configured = command_configured("PYSEC_RAW_EVIDENCE_KMS")
    if not raw_directory and not kms_configured:
        return {
            "mode": "redacted-inline",
            "object_id": "",
            "ciphertext_sha256": "",
            "key_sha256": "",
            "custody_receipt_sha256": "",
            "custody_level": "none",
            "wrapped_data_key_base64": "",
            "custody_receipt": None,
            "custody_authority_receipt": None,
            "effective_policy_attestation": None,
            "recovery_drill": None,
        }
    if not raw_directory or not kms_configured:
        raise ValueError("encrypted raw evidence storage configuration is incomplete")
    root = Path(raw_directory).expanduser().resolve()
    if root.is_symlink() or not root.is_dir():
        raise ValueError(
            "encrypted raw evidence directory must be an existing regular directory"
        )
    key, wrapped_key, custody_receipt, custody_authority, policy_attestation = (
        _kms_data_key(root, raw_sha256)
    )
    key_sha256 = hashlib.sha256(key).hexdigest()
    custody_sha256 = hashlib.sha256(canonical_bytes(custody_receipt)).hexdigest()
    try:
        storage = _store_encrypted_sidecar(
            payload,
            raw_sha256,
            root,
            key,
            key_sha256,
            custody_sha256,
            custody_receipt,
            custody_authority,
            wrapped_key,
            policy_attestation,
        )
    finally:
        for index in range(len(key)):
            key[index] = 0
    storage["recovery_drill"] = _external_recovery_drill(root, raw_sha256, storage)
    return storage


def _store_encrypted_sidecar(
    payload: bytes,
    raw_sha256: str,
    root: Path,
    key: bytes | bytearray,
    key_sha256: str,
    custody_sha256: str,
    custody_receipt: dict[str, Any],
    custody_authority: dict[str, Any],
    wrapped_data_key_base64: str,
    effective_policy_attestation: dict[str, Any],
) -> dict[str, Any]:
    object_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(raw_sha256),
        info=b"pysec-native-evidence-object-v1",
    ).derive(key)
    nonce = os.urandom(12)
    ciphertext = nonce + AESGCM(object_key).encrypt(
        nonce, payload, raw_sha256.encode("ascii")
    )
    ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()
    opaque_id = hmac.new(key, raw_sha256.encode("ascii"), hashlib.sha256).hexdigest()
    object_id = f"hmac-sha256-{opaque_id}.aesgcm"
    destination = (root / object_id).resolve()
    if destination.parent != root:
        raise ValueError("raw evidence object escaped its content-addressed store")
    if destination.exists():
        _, existing = read_regular_file(
            destination,
            "encrypted raw evidence object",
            maximum_bytes=128 * 1024 * 1024,
            boundary=root,
        )
        if len(existing) < 28:
            raise ValueError("encrypted raw evidence object is truncated")
        try:
            recovered = AESGCM(object_key).decrypt(
                existing[:12], existing[12:], raw_sha256.encode("ascii")
            )
        except Exception as exc:
            raise ValueError(
                "encrypted raw evidence object failed authenticated verification"
            ) from exc
        if recovered != payload:
            raise ValueError(
                "encrypted raw evidence object does not match its content address"
            )
        ciphertext_sha256 = hashlib.sha256(existing).hexdigest()
    else:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            view = memoryview(ciphertext)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    _, stored = read_regular_file(
        destination,
        "encrypted raw evidence recovery drill",
        maximum_bytes=128 * 1024 * 1024,
        boundary=root,
    )
    try:
        recovered = AESGCM(object_key).decrypt(
            stored[:12], stored[12:], raw_sha256.encode("ascii")
        )
    except Exception as exc:
        raise ValueError("encrypted raw evidence recovery drill failed") from exc
    if (
        recovered != payload
        or hashlib.sha256(recovered).hexdigest() != raw_sha256
        or hashlib.sha256(stored).hexdigest() != ciphertext_sha256
    ):
        raise ValueError(
            "encrypted raw evidence recovery drill did not reproduce payload"
        )
    return {
        "mode": "encrypted-cas",
        "object_id": object_id,
        "ciphertext_sha256": ciphertext_sha256,
        "key_sha256": key_sha256,
        "custody_receipt_sha256": custody_sha256,
        "custody_level": "hardware-kms-envelope",
        "wrapped_data_key_base64": wrapped_data_key_base64,
        "custody_receipt": custody_receipt,
        "custody_authority_receipt": custody_authority,
        "effective_policy_attestation": effective_policy_attestation,
        "recovery_drill": None,
    }


def _external_recovery_drill(
    root: Path, raw_sha256: str, storage: dict[str, Any]
) -> dict[str, Any]:
    if not command_configured("PYSEC_RAW_EVIDENCE_RECOVERY"):
        raise ValueError("clean-host raw evidence recovery command is unavailable")
    challenge = (
        os.environ.get("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "").strip().casefold()
    )
    wrapped = base64.b64decode(storage["wrapped_data_key_base64"], validate=True)
    request = {
        "schema_version": "1.0",
        "operation": "recover-encrypted-evidence",
        "store_identity": hashlib.sha256(str(root).encode()).hexdigest(),
        "object_id": storage["object_id"],
        "ciphertext_sha256": storage["ciphertext_sha256"],
        "wrapped_key_sha256": hashlib.sha256(wrapped).hexdigest(),
        "wrapped_data_key_base64": storage["wrapped_data_key_base64"],
        "expected_plaintext_sha256": raw_sha256,
        "challenge_sha256": challenge,
    }
    response = run_pinned_json_command("PYSEC_RAW_EVIDENCE_RECOVERY", request)
    policy_attestation = response.pop("_effective_policy_attestation", None)
    fields = {
        "schema_version",
        "object_id",
        "ciphertext_sha256",
        "recovered_plaintext_sha256",
        "replica_identity_sha256",
        "kms_unwrap_operation_id",
        "execution_nonce",
        "recovery_operation_id",
        "recovery_authority_key_sha256",
        "recovery_operation_receipt",
        "provider_audit_authority_key_sha256",
        "provider_audit_event",
    }
    expected_key = (
        os.environ.get("PYSEC_RAW_EVIDENCE_RECOVERY_AUTHORITY_KEY_SHA256", "")
        .strip()
        .casefold()
    )
    if (
        set(response) != fields
        or response.get("schema_version") != "1.0"
        or response.get("object_id") != storage["object_id"]
        or response.get("ciphertext_sha256") != storage["ciphertext_sha256"]
        or response.get("recovered_plaintext_sha256") != raw_sha256
        or not _digest(str(response.get("replica_identity_sha256") or ""))
        or response.get("replica_identity_sha256") == request["store_identity"]
        or not str(response.get("kms_unwrap_operation_id") or "")
        or not str(response.get("recovery_operation_id") or "")
        or not str(response.get("execution_nonce") or "")
        or not _digest(expected_key)
        or response.get("recovery_authority_key_sha256") != expected_key
        or not isinstance(policy_attestation, dict)
    ):
        raise ValueError("clean-host raw evidence recovery response is invalid")
    subject = {
        "schema_version": "1.0",
        "request_sha256": hashlib.sha256(canonical_bytes(request)).hexdigest(),
        "object_id": response["object_id"],
        "ciphertext_sha256": response["ciphertext_sha256"],
        "recovered_plaintext_sha256": response["recovered_plaintext_sha256"],
        "replica_identity_sha256": response["replica_identity_sha256"],
        "kms_unwrap_operation_id": response["kms_unwrap_operation_id"],
        "execution_nonce": response["execution_nonce"],
    }
    receipt = response["recovery_operation_receipt"]
    statement = receipt.get("statement") if isinstance(receipt, dict) else None
    try:
        observed_at = datetime.fromisoformat(
            str((statement or {})["issued_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("clean-host recovery receipt time is invalid") from exc
    verified = verify_operation_receipt(
        subject,
        receipt,
        purpose="raw-evidence-clean-host-recovery",
        observed_at=observed_at,
        challenge_sha256=challenge,
        expected_key_sha256=expected_key,
    )
    if verified["statement"]["operation_id"] != response["recovery_operation_id"]:
        raise ValueError("clean-host recovery operation identity is detached")
    audit_key = (
        os.environ.get("PYSEC_RAW_EVIDENCE_RECOVERY_PROVIDER_AUDIT_KEY_SHA256", "")
        .strip()
        .casefold()
    )
    audit = response["provider_audit_event"]
    audit_fields = {
        "schema_version",
        "provider",
        "audit_event_id",
        "object_id",
        "ciphertext_sha256",
        "recovered_plaintext_sha256",
        "wrapped_key_sha256",
        "kms_unwrap_operation_id",
        "hardware_backed",
        "failure_domain",
        "operation_receipt",
    }
    if (
        not isinstance(audit, dict)
        or set(audit) != audit_fields
        or audit.get("schema_version") != "1.0"
        or not str(audit.get("provider") or "")
        or not str(audit.get("audit_event_id") or "")
        or audit.get("object_id") != response["object_id"]
        or audit.get("ciphertext_sha256") != response["ciphertext_sha256"]
        or audit.get("recovered_plaintext_sha256")
        != response["recovered_plaintext_sha256"]
        or audit.get("wrapped_key_sha256") != request["wrapped_key_sha256"]
        or audit.get("kms_unwrap_operation_id") != response["kms_unwrap_operation_id"]
        or audit.get("hardware_backed") is not True
        or response.get("provider_audit_authority_key_sha256") != audit_key
        or not _digest(audit_key)
    ):
        raise ValueError("KMS provider audit event is invalid")
    audit_domain = verify_failure_domain(audit["failure_domain"], "KMS provider audit")
    verify_registered_failure_domain(audit_domain, audit_key, "KMS provider audit")
    audit_subject = {
        name: audit[name] for name in audit_fields if name != "operation_receipt"
    }
    audit_receipt = audit["operation_receipt"]
    audit_statement = (
        audit_receipt.get("statement") if isinstance(audit_receipt, dict) else None
    )
    try:
        audit_observed_at = datetime.fromisoformat(
            str((audit_statement or {})["issued_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("KMS provider audit time is invalid") from exc
    verify_operation_receipt(
        audit_subject,
        audit_receipt,
        purpose="kms-unwrap-provider-audit",
        observed_at=audit_observed_at,
        challenge_sha256=challenge,
        expected_key_sha256=audit_key,
    )
    attestation_subject = policy_attestation.get("subject", {})
    if response["execution_nonce"] != attestation_subject.get("execution_nonce"):
        raise ValueError("recovery result is detached from its attested execution")
    remote = attestation_subject.get("policy_observations", {}).get(
        "remote_attestation", {}
    )
    remote_subject = remote.get("subject") if isinstance(remote, dict) else None
    recovery_domain = (
        {
            name: remote_subject.get(name)
            for name in (
                "organization",
                "host_identity_sha256",
                "control_plane_sha256",
                "implementation_sha256",
            )
        }
        if isinstance(remote_subject, dict)
        else None
    )
    require_independent_failure_domains(
        recovery_domain,
        audit_domain,
        labels=("recovery executor", "KMS provider audit"),
    )
    audit_readback = _provider_audit_readback(audit, audit_domain, challenge)
    return {
        "schema_version": "1.0",
        "mode": "external-clean-host-kms-restore",
        **subject,
        "recovery_request": request,
        "recovery_operation_id": response["recovery_operation_id"],
        "recovery_authority_key_sha256": expected_key,
        "recovery_operation_receipt": verified,
        "provider_audit_authority_key_sha256": audit_key,
        "provider_audit_event": audit,
        "provider_audit_readback": audit_readback,
        "effective_policy_attestation": policy_attestation,
        "verified": True,
    }


def _provider_audit_readback(
    audit: dict[str, Any], audit_domain: dict[str, str], challenge: str
) -> dict[str, Any] | None:
    prefix = "PYSEC_RAW_EVIDENCE_PROVIDER_AUDIT_READBACK"
    required = os.environ.get(f"{prefix}_REQUIRED", "").strip() == "1"
    if not command_configured(prefix):
        if required:
            raise ValueError("independent KMS provider audit readback is unavailable")
        return None
    request = {
        "schema_version": "1.0",
        "operation": "read-provider-audit-event",
        "provider": audit["provider"],
        "audit_event_id": audit["audit_event_id"],
        "expected_event_sha256": hashlib.sha256(canonical_bytes(audit)).hexdigest(),
        "challenge_sha256": challenge,
    }
    response = run_pinned_json_command(prefix, request)
    attestation = response.pop("_effective_policy_attestation", None)
    fields = {
        "schema_version",
        "provider",
        "audit_event_id",
        "audit_event",
        "authority_key_sha256",
        "execution_nonce",
        "failure_domain",
        "operation_receipt",
    }
    expected_key = os.environ.get(f"{prefix}_AUTHORITY_KEY_SHA256", "").strip().casefold()
    if (
        set(response) != fields
        or response.get("schema_version") != "1.0"
        or response.get("provider") != audit["provider"]
        or response.get("audit_event_id") != audit["audit_event_id"]
        or response.get("audit_event") != audit
        or response.get("authority_key_sha256") != expected_key
        or not _digest(expected_key)
    ):
        raise ValueError("independent KMS provider audit readback is invalid")
    domain = verify_registered_failure_domain(
        response["failure_domain"], expected_key, "KMS audit readback"
    )
    attestation_subject = attestation.get("subject") if isinstance(attestation, dict) else None
    if (
        not isinstance(attestation_subject, dict)
        or response.get("execution_nonce")
        != attestation_subject.get("execution_nonce")
    ):
        raise ValueError("KMS audit readback execution binding is invalid")
    require_independent_failure_domains(
        audit_domain,
        domain,
        labels=("KMS provider audit", "KMS audit readback"),
    )
    subject = {
        **request,
        "audit_event_sha256": hashlib.sha256(canonical_bytes(audit)).hexdigest(),
        "execution_nonce": response["execution_nonce"],
        "failure_domain": domain,
    }
    receipt = response["operation_receipt"]
    statement = receipt.get("statement") if isinstance(receipt, dict) else None
    try:
        observed = datetime.fromisoformat(
            str((statement or {})["issued_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("KMS provider audit readback time is invalid") from exc
    verify_operation_receipt(
        subject,
        receipt,
        purpose="kms-provider-audit-readback",
        observed_at=observed,
        challenge_sha256=challenge,
        expected_key_sha256=expected_key,
    )
    from .pinned_command import verify_retained_effective_policy_attestation

    if domain != verify_retained_effective_policy_attestation(attestation):
        raise ValueError("KMS provider audit readback domain is not attested")
    return {
        **response,
        "effective_policy_attestation": attestation,
        "readback_request": request,
    }


def verify_retained_provider_audit_readback(
    value: object,
    audit: dict[str, Any],
    audit_domain: dict[str, str],
    challenge: str,
) -> None:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "provider",
        "audit_event_id",
        "audit_event",
        "authority_key_sha256",
        "execution_nonce",
        "failure_domain",
        "operation_receipt",
        "effective_policy_attestation",
        "readback_request",
    }:
        raise ValueError("retained KMS audit readback fields do not match")
    prefix = "PYSEC_RAW_EVIDENCE_PROVIDER_AUDIT_READBACK"
    expected_key = os.environ.get(f"{prefix}_AUTHORITY_KEY_SHA256", "").strip().casefold()
    if (
        value.get("provider") != audit["provider"]
        or value.get("audit_event_id") != audit["audit_event_id"]
        or value.get("audit_event") != audit
        or value.get("authority_key_sha256") != expected_key
    ):
        raise ValueError("retained KMS audit readback is detached")
    domain = verify_registered_failure_domain(
        value["failure_domain"], expected_key, "KMS audit readback"
    )
    require_independent_failure_domains(
        audit_domain, domain, labels=("KMS provider audit", "KMS audit readback")
    )
    request = value["readback_request"]
    expected_request = {
        "schema_version": "1.0",
        "operation": "read-provider-audit-event",
        "provider": audit["provider"],
        "audit_event_id": audit["audit_event_id"],
        "expected_event_sha256": hashlib.sha256(canonical_bytes(audit)).hexdigest(),
        "challenge_sha256": challenge,
    }
    if (
        not isinstance(request, dict)
        or any(request.get(name) != expected for name, expected in expected_request.items())
        or not isinstance(request.get("command_context"), dict)
    ):
        raise ValueError("retained KMS audit readback request is detached")
    subject = {
        **request,
        "audit_event_sha256": hashlib.sha256(canonical_bytes(audit)).hexdigest(),
        "execution_nonce": value["execution_nonce"],
        "failure_domain": domain,
    }
    receipt = value["operation_receipt"]
    statement = receipt.get("statement") if isinstance(receipt, dict) else None
    try:
        observed = datetime.fromisoformat(
            str((statement or {})["issued_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("retained KMS audit readback time is invalid") from exc
    verify_operation_receipt(
        subject,
        receipt,
        purpose="kms-provider-audit-readback",
        observed_at=observed,
        challenge_sha256=challenge,
        expected_key_sha256=expected_key,
    )
    from .pinned_command import verify_retained_effective_policy_attestation

    attestation = value["effective_policy_attestation"]
    attestation_subject = attestation.get("subject") if isinstance(attestation, dict) else None
    if (
        not isinstance(attestation_subject, dict)
        or value["execution_nonce"] != attestation_subject.get("execution_nonce")
    ):
        raise ValueError("retained KMS audit readback execution binding is invalid")
    if domain != verify_retained_effective_policy_attestation(
        attestation
    ):
        raise ValueError("retained KMS audit readback domain is not attested")


def _kms_data_key(
    root: Path, raw_sha256: str
) -> tuple[bytearray, str, dict[str, Any], dict[str, Any], dict[str, Any]]:
    challenge = (
        os.environ.get("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "").strip().casefold()
    )
    request = {
        "schema_version": "1.0",
        "operation": "generate-data-key",
        "store_identity": hashlib.sha256(str(root).encode()).hexdigest(),
        "object_plaintext_sha256": raw_sha256,
        "challenge_sha256": challenge,
    }
    response = run_pinned_json_command(
        "PYSEC_RAW_EVIDENCE_KMS",
        request,
    )
    policy_attestation = response.pop("_effective_policy_attestation", None)
    if (
        set(response)
        != {
            "schema_version",
            "plaintext_data_key_base64",
            "wrapped_data_key_base64",
            "encryption_operation_id",
            "custody_receipt",
            "custody_authority_receipt",
        }
        or response.get("schema_version") != "1.0"
    ):
        raise ValueError("KMS data-key response fields do not match")
    plaintext = bytearray()
    try:
        import base64

        plaintext = bytearray(
            base64.b64decode(str(response["plaintext_data_key_base64"]), validate=True)
        )
        wrapped = base64.b64decode(
            str(response["wrapped_data_key_base64"]), validate=True
        )
    except (TypeError, ValueError) as exc:
        for index in range(len(plaintext)):
            plaintext[index] = 0
        raise ValueError("KMS data-key response encoding is invalid") from exc
    operation_id = str(response["encryption_operation_id"]).strip()
    if len(plaintext) != 32 or len(wrapped) < 32 or not operation_id:
        for index in range(len(plaintext)):
            plaintext[index] = 0
        raise ValueError("KMS data-key response policy failed")
    value = response["custody_receipt"]
    authority = response["custody_authority_receipt"]
    command_context = cast(dict[str, Any], request["command_context"])
    fields = {
        "schema_version",
        "provider",
        "key_id",
        "key_version",
        "store_identity",
        "retention_days",
        "plaintext_data_key_sha256",
        "key_origin",
        "wrapping_key_non_exportable",
        "hardware_backed",
        "wrapped_key_sha256",
        "encryption_operation_id",
        "request_sha256",
        "object_plaintext_sha256",
        "challenge_sha256",
        "sandbox_identity_sha256",
        "allowed_endpoints_sha256",
        "mtls_peer_identity_sha256",
        "transport_transcript",
        "transport_transcript_sha256",
        "command_context",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value.get("schema_version") != "1.0"
        or value.get("plaintext_data_key_sha256")
        != hashlib.sha256(plaintext).hexdigest()
        or value.get("store_identity") != hashlib.sha256(str(root).encode()).hexdigest()
        or value.get("key_origin") != "kms-generated-data-key"
        or value.get("wrapping_key_non_exportable") is not True
        or value.get("hardware_backed") is not True
        or value.get("wrapped_key_sha256") != hashlib.sha256(wrapped).hexdigest()
        or value.get("encryption_operation_id") != operation_id
        or value.get("request_sha256")
        != hashlib.sha256(canonical_bytes(request)).hexdigest()
        or value.get("object_plaintext_sha256") != raw_sha256
        or value.get("challenge_sha256") != challenge
        or value.get("sandbox_identity_sha256")
        != command_context["sandbox_identity_sha256"]
        or value.get("command_context") != command_context
        or value.get("allowed_endpoints_sha256")
        != hashlib.sha256(
            canonical_bytes(command_context["allowed_endpoints"])
        ).hexdigest()
        or value.get("mtls_peer_identity_sha256")
        != command_context["mtls_identity_sha256"]
        or value.get("transport_transcript_sha256")
        != hashlib.sha256(
            canonical_bytes(value.get("transport_transcript"))
        ).hexdigest()
        or not _transport_transcript(value.get("transport_transcript"), command_context)
        or not isinstance(value.get("retention_days"), int)
        or isinstance(value.get("retention_days"), bool)
        or not 1 <= value["retention_days"] <= 3650
        or not all(
            str(value.get(name) or "").strip()
            for name in ("provider", "key_id", "key_version")
        )
    ):
        for index in range(len(plaintext)):
            plaintext[index] = 0
        raise ValueError("raw evidence custody receipt policy is invalid")
    statement = authority.get("statement") if isinstance(authority, dict) else None
    expected_key = (
        os.environ.get("PYSEC_RAW_EVIDENCE_CUSTODY_AUTHORITY_KEY_SHA256", "")
        .strip()
        .casefold()
    )
    if (
        not isinstance(statement, dict)
        or not _digest(challenge)
        or not _digest(expected_key)
    ):
        for index in range(len(plaintext)):
            plaintext[index] = 0
        raise ValueError("raw evidence custody authority configuration is incomplete")
    from .trusted_observation import scan_observed_at

    try:
        verified_authority = verify_portable_receipt(
            value,
            authority,
            purpose="raw-evidence-custody",
            observed_at=scan_observed_at(),
            challenge_sha256=challenge,
            expected_key_sha256=expected_key,
        )
    except ValueError:
        for index in range(len(plaintext)):
            plaintext[index] = 0
        raise
    return (
        plaintext,
        str(response["wrapped_data_key_base64"]),
        dict(value),
        verified_authority,
        cast(dict[str, Any], policy_attestation),
    )


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _transport_transcript(value: object, context: dict[str, Any]) -> bool:
    return bool(
        isinstance(value, dict)
        and set(value)
        == {"endpoint", "peer_identity_sha256", "protocol", "cipher", "session_id"}
        and value.get("endpoint") in context["allowed_endpoints"]
        and value.get("peer_identity_sha256") == context["mtls_identity_sha256"]
        and value.get("protocol") == "TLSv1.3"
        and isinstance(value.get("cipher"), str)
        and value["cipher"]
        and isinstance(value.get("session_id"), str)
        and 16 <= len(value["session_id"]) <= 200
    )
