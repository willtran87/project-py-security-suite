from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .deployment_receipt import verify_portable_receipt
from .path_safety import read_regular_file
from .pinned_command import command_configured, run_pinned_json_command
from .strict_json import dumps as strict_dumps
from .strict_json import loads as strict_loads
from .strict_json import canonical_bytes


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
        }
    if not raw_directory or not kms_configured:
        raise ValueError("encrypted raw evidence storage configuration is incomplete")
    root = Path(raw_directory).expanduser().resolve()
    if root.is_symlink() or not root.is_dir():
        raise ValueError(
            "encrypted raw evidence directory must be an existing regular directory"
        )
    key, wrapped_key, custody_receipt, custody_authority = _kms_data_key(
        root, raw_sha256
    )
    key_sha256 = hashlib.sha256(key).hexdigest()
    custody_sha256 = hashlib.sha256(canonical_bytes(custody_receipt)).hexdigest()
    try:
        return _store_encrypted_sidecar(
            payload,
            raw_sha256,
            root,
            key,
            key_sha256,
            custody_sha256,
            custody_receipt,
            custody_authority,
            wrapped_key,
        )
    finally:
        for index in range(len(key)):
            key[index] = 0


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
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
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
    }


def _kms_data_key(
    root: Path, raw_sha256: str
) -> tuple[bytearray, str, dict[str, Any], dict[str, Any]]:
    response = run_pinned_json_command(
        "PYSEC_RAW_EVIDENCE_KMS",
        {
            "schema_version": "1.0",
            "operation": "generate-data-key",
            "store_identity": hashlib.sha256(str(root).encode()).hexdigest(),
            "object_plaintext_sha256": raw_sha256,
        },
    )
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
    challenge = (
        os.environ.get("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "").strip().casefold()
    )
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
    )


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
