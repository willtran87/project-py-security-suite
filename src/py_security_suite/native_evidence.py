from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .path_safety import read_regular_file
from .strict_json import dumps as strict_dumps
from .strict_json import loads as strict_loads


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
    key_path_raw = os.environ.get("PYSEC_RAW_EVIDENCE_KEY_PATH", "").strip()
    key_sha256 = os.environ.get("PYSEC_RAW_EVIDENCE_KEY_SHA256", "").strip().casefold()
    if not any((raw_directory, key_path_raw, key_sha256)):
        return {
            "mode": "redacted-inline",
            "object_id": "",
            "ciphertext_sha256": "",
            "key_sha256": "",
            "custody_receipt_sha256": "",
        }
    if not raw_directory or not key_path_raw or not _digest(key_sha256):
        raise ValueError("encrypted raw evidence storage configuration is incomplete")
    root = Path(raw_directory).expanduser().resolve()
    if root.is_symlink() or not root.is_dir():
        raise ValueError(
            "encrypted raw evidence directory must be an existing regular directory"
        )
    key_path = Path(key_path_raw).expanduser().resolve()
    _, key = read_regular_file(
        key_path, "raw evidence encryption key", maximum_bytes=32
    )
    if len(key) != 32 or hashlib.sha256(key).hexdigest() != key_sha256:
        raise ValueError(
            "raw evidence encryption key does not match its deployment pin"
        )
    custody_sha256 = _custody_receipt(root, key_sha256)
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
    }


def _custody_receipt(root: Path, key_sha256: str) -> str:
    raw_path = os.environ.get("PYSEC_RAW_EVIDENCE_CUSTODY_RECEIPT_PATH", "").strip()
    expected = (
        os.environ.get("PYSEC_RAW_EVIDENCE_CUSTODY_RECEIPT_SHA256", "")
        .strip()
        .casefold()
    )
    if not raw_path or not _digest(expected):
        raise ValueError("raw evidence custody receipt configuration is incomplete")
    path = Path(raw_path).expanduser().resolve()
    _, payload = read_regular_file(
        path, "raw evidence custody receipt", maximum_bytes=64 * 1024
    )
    if hashlib.sha256(payload).hexdigest() != expected:
        raise ValueError(
            "raw evidence custody receipt does not match its deployment pin"
        )
    value = strict_loads(payload)
    fields = {
        "schema_version",
        "provider",
        "key_id",
        "key_version",
        "store_identity",
        "retention_days",
        "master_key_sha256",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value.get("schema_version") != "1.0"
        or value.get("master_key_sha256") != key_sha256
        or value.get("store_identity") != hashlib.sha256(str(root).encode()).hexdigest()
        or not isinstance(value.get("retention_days"), int)
        or isinstance(value.get("retention_days"), bool)
        or not 1 <= value["retention_days"] <= 3650
        or not all(
            str(value.get(name) or "").strip()
            for name in ("provider", "key_id", "key_version")
        )
    ):
        raise ValueError("raw evidence custody receipt policy is invalid")
    return expected


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
