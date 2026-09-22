from __future__ import annotations

import base64
import hashlib
import os
import shutil
import struct
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .execution import sha256_file
from .passport import verify_report
from .path_safety import read_regular_file
from .strict_json import canonical_bytes, loads as strict_loads
from .trusted_time import verify_rfc3161


_MAGIC = b"PYSEC-REPORT-ENC-1\0"
_MAX_HEADER = 64 * 1024
_MAX_ARCHIVE = 8 * 1024**3


def encrypt_report(
    report: Path,
    output: Path,
    *,
    recipient_public_key: Path,
    recipient_public_key_sha256: str,
    key_lifecycle_receipt: Path,
    key_lifecycle_receipt_sha256: str,
    key_authority_public_key: Path,
    key_authority_public_key_sha256: str,
    key_lifecycle_signature: Path,
    provider_attestation: Path,
    provider_attestation_sha256: str,
    provider_authority_public_key: Path,
    provider_authority_public_key_sha256: str,
    provider_attestation_signature: Path,
    trusted_time_context: Path,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Encrypt a verified report using X25519, HKDF-SHA256, and AES-256-GCM."""
    verification = verify_report(report)
    root = report.expanduser().resolve()
    destination = output.expanduser().absolute()
    if destination.exists() and not overwrite:
        raise FileExistsError(f"encrypted report already exists: {destination}")
    _, public_raw = read_regular_file(
        recipient_public_key, "report recipient public key", maximum_bytes=64 * 1024
    )
    if hashlib.sha256(public_raw).hexdigest() != recipient_public_key_sha256.casefold():
        raise ValueError("report recipient public key SHA-256 is not approved")
    public_key = serialization.load_pem_public_key(public_raw)
    if not isinstance(public_key, X25519PublicKey):
        raise ValueError("report recipient public key must use X25519")
    lifecycle = _verify_key_lifecycle(
        key_lifecycle_receipt,
        key_lifecycle_receipt_sha256,
        key_authority_public_key,
        key_authority_public_key_sha256,
        key_lifecycle_signature,
        recipient_public_key_sha256.casefold(),
        provider_attestation,
        provider_attestation_sha256,
        provider_authority_public_key,
        provider_authority_public_key_sha256,
        provider_attestation_signature,
        trusted_time_context,
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{destination.name}.encrypt-", dir=destination.parent
    ) as temporary_directory:
        temporary_root = Path(temporary_directory)
        archive = temporary_root / "report.zip"
        _archive_report(root, archive)
        os.chmod(archive, 0o600)
        if archive.stat().st_size > _MAX_ARCHIVE:
            raise ValueError("report archive exceeds 8 GiB")
        ephemeral = X25519PrivateKey.generate()
        salt = os.urandom(32)
        nonce = os.urandom(12)
        key = _derive_key(ephemeral.exchange(public_key), salt)
        header = {
            "schema_version": "1.1",
            "algorithm": "X25519-HKDF-SHA256+A256GCM",
            "ephemeral_public_key": base64.b64encode(
                ephemeral.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
            ).decode(),
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "plaintext_bytes": archive.stat().st_size,
            "report_checksums_sha256": str(verification["checksums_sha256"]),
            "key_lifecycle": lifecycle,
        }
        header_bytes = canonical_bytes(header)
        temporary_output = temporary_root / "encrypted.tmp"
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(header_bytes)
        with archive.open("rb") as source, temporary_output.open("wb") as target:
            target.write(_MAGIC)
            target.write(struct.pack(">I", len(header_bytes)))
            target.write(header_bytes)
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                target.write(encryptor.update(chunk))
            target.write(encryptor.finalize())
            target.write(encryptor.tag)
            target.flush()
            os.fsync(target.fileno())
        os.chmod(temporary_output, 0o600)
        os.replace(temporary_output, destination)
    return {
        **header,
        "output": str(destination),
        "encrypted_sha256": sha256_file(destination),
    }


def _verify_key_lifecycle(
    receipt_path: Path,
    receipt_sha256: str,
    authority_path: Path,
    authority_sha256: str,
    signature_path: Path,
    recipient_sha256: str,
    provider_attestation_path: Path,
    provider_attestation_sha256: str,
    provider_authority_path: Path,
    provider_authority_sha256: str,
    provider_signature_path: Path,
    trusted_time_context: Path,
) -> dict[str, Any]:
    _, raw = read_regular_file(
        receipt_path, "key lifecycle receipt", maximum_bytes=64 * 1024
    )
    observed_receipt = hashlib.sha256(raw).hexdigest()
    if observed_receipt != receipt_sha256.casefold():
        raise ValueError("key lifecycle receipt SHA-256 is not approved")
    value = strict_loads(raw)
    required = {
        "schema_version",
        "provider",
        "key_id",
        "generation",
        "status",
        "not_before",
        "not_after",
        "recipient_public_key_sha256",
        "destruction_policy",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("key lifecycle receipt fields do not match")
    if (
        value.get("schema_version") != "1.0"
        or value.get("status") != "active"
        or value.get("destruction_policy") != "provider-verified-cryptographic-erasure"
        or value.get("recipient_public_key_sha256") != recipient_sha256
    ):
        raise ValueError("key lifecycle receipt is not active for this recipient")
    provider = str(value.get("provider") or "")
    key_id = str(value.get("key_id") or "")
    generation = value.get("generation")
    if (
        provider not in {"aws-kms", "azure-key-vault", "gcp-kms", "hsm", "external-kms"}
        or not 1 <= len(key_id) <= 500
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 1
    ):
        raise ValueError("key lifecycle identity is invalid")
    try:
        not_before = datetime.fromisoformat(
            str(value["not_before"]).replace("Z", "+00:00")
        )
        not_after = datetime.fromisoformat(
            str(value["not_after"]).replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError("key lifecycle validity is invalid") from exc
    provider_attestation = _verify_provider_attestation(
        provider_attestation_path,
        provider_attestation_sha256,
        provider_authority_path,
        provider_authority_sha256,
        provider_signature_path,
        provider=provider,
        key_id=key_id,
        generation=generation,
        recipient_sha256=recipient_sha256,
    )
    _, time_raw = read_regular_file(
        trusted_time_context,
        "key lifecycle trusted-time context",
        maximum_bytes=64 * 1024,
    )
    time_context = strict_loads(time_raw)
    if (
        not isinstance(time_context, dict)
        or set(time_context) != {"schema_version", "trusted_time"}
        or time_context.get("schema_version") != "1.0"
    ):
        raise ValueError("key lifecycle trusted-time context is invalid")
    time_challenge = hashlib.sha256(
        canonical_bytes(
            {
                "action": "encrypt-report",
                "key_lifecycle_receipt_sha256": observed_receipt,
                "provider_attestation_sha256": provider_attestation_sha256.casefold(),
                "recipient_public_key_sha256": recipient_sha256,
            }
        )
    ).hexdigest()
    trusted_time = verify_rfc3161(
        trusted_time_context,
        time_context["trusted_time"],
        time_challenge,
        require_advanced=True,
    )
    now = datetime.fromisoformat(
        trusted_time["trusted_time_observed_at"].replace("Z", "+00:00")
    ).astimezone(UTC)
    if (
        not_before.tzinfo is None
        or not_after.tzinfo is None
        or not_before.astimezone(UTC) > now
        or not_after.astimezone(UTC) <= now
        or not_after <= not_before
    ):
        raise ValueError("key lifecycle receipt is outside its validity window")
    _, authority_raw = read_regular_file(
        authority_path, "key lifecycle authority", maximum_bytes=64 * 1024
    )
    if hashlib.sha256(authority_raw).hexdigest() != authority_sha256.casefold():
        raise ValueError("key lifecycle authority SHA-256 is not approved")
    authority = serialization.load_pem_public_key(authority_raw)
    if not isinstance(authority, Ed25519PublicKey):
        raise ValueError("key lifecycle authority must use Ed25519")
    _, signature = read_regular_file(
        signature_path, "key lifecycle signature", maximum_bytes=4096
    )
    try:
        authority.verify(signature, canonical_bytes(value))
    except Exception as exc:
        raise ValueError("key lifecycle receipt signature is invalid") from exc
    return {
        "provider": provider,
        "key_id": key_id,
        "generation": generation,
        "not_before": not_before.astimezone(UTC).isoformat(),
        "not_after": not_after.astimezone(UTC).isoformat(),
        "receipt_sha256": observed_receipt,
        "authority_sha256": authority_sha256.casefold(),
        "destruction_policy": value["destruction_policy"],
        "provider_attestation": provider_attestation,
        "trusted_time_receipt_sha256": trusted_time["trusted_time_receipt_sha256"],
    }


def _verify_provider_attestation(
    attestation_path: Path,
    attestation_sha256: str,
    authority_path: Path,
    authority_sha256: str,
    signature_path: Path,
    *,
    provider: str,
    key_id: str,
    generation: int,
    recipient_sha256: str,
) -> dict[str, Any]:
    _, raw = read_regular_file(
        attestation_path, "KMS/HSM provider attestation", maximum_bytes=64 * 1024
    )
    observed = hashlib.sha256(raw).hexdigest()
    value = strict_loads(raw)
    required = {
        "schema_version",
        "provider",
        "key_id",
        "generation",
        "recipient_public_key_sha256",
        "key_non_exportable",
        "key_usage",
        "destruction_capability",
        "attested_at",
        "attestation_id",
    }
    if (
        observed != attestation_sha256.casefold()
        or not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != "1.0"
        or value.get("provider") != provider
        or value.get("key_id") != key_id
        or value.get("generation") != generation
        or value.get("recipient_public_key_sha256") != recipient_sha256
        or value.get("key_non_exportable") is not True
        or value.get("key_usage") != "decrypt-report"
        or value.get("destruction_capability")
        != "provider-verified-cryptographic-erasure"
    ):
        raise ValueError(
            "KMS/HSM provider attestation does not match the recipient key"
        )
    attested_at = datetime.fromisoformat(
        str(value["attested_at"]).replace("Z", "+00:00")
    )
    if attested_at.tzinfo is None or not str(value["attestation_id"]).strip():
        raise ValueError("KMS/HSM provider attestation identity is invalid")
    _, authority_raw = read_regular_file(
        authority_path, "KMS/HSM provider authority", maximum_bytes=64 * 1024
    )
    if hashlib.sha256(authority_raw).hexdigest() != authority_sha256.casefold():
        raise ValueError("KMS/HSM provider authority SHA-256 is not approved")
    authority = serialization.load_pem_public_key(authority_raw)
    if not isinstance(authority, Ed25519PublicKey):
        raise ValueError("KMS/HSM provider authority must use Ed25519")
    _, signature = read_regular_file(
        signature_path, "KMS/HSM provider attestation signature", maximum_bytes=4096
    )
    try:
        authority.verify(signature, canonical_bytes(value))
    except Exception as exc:
        raise ValueError("KMS/HSM provider attestation signature is invalid") from exc
    return {
        "attestation_sha256": observed,
        "authority_sha256": authority_sha256.casefold(),
        "attested_at": attested_at.astimezone(UTC).isoformat(),
        "attestation_id": str(value["attestation_id"]),
        "key_non_exportable": True,
    }


def decrypt_report(
    encrypted: Path,
    output: Path,
    *,
    recipient_private_key: Path,
    recipient_private_key_sha256: str,
) -> dict[str, Any]:
    """Decrypt, safely extract, and verify an encrypted report."""
    source_path = encrypted.expanduser().resolve()
    destination = output.expanduser().absolute()
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"decrypted report output already exists: {destination}")
    _, private_raw = read_regular_file(
        recipient_private_key, "report recipient private key", maximum_bytes=64 * 1024
    )
    if (
        hashlib.sha256(private_raw).hexdigest()
        != recipient_private_key_sha256.casefold()
    ):
        raise ValueError("report recipient private key SHA-256 is not approved")
    private_key = serialization.load_pem_private_key(private_raw, password=None)
    if not isinstance(private_key, X25519PrivateKey):
        raise ValueError("report recipient private key must use X25519")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.decrypt-", dir=destination.parent)
    )
    os.chmod(staging, 0o700)
    try:
        archive = staging.parent / f".{staging.name}.zip"
        try:
            header = _decrypt_archive(source_path, archive, private_key)
            _extract_archive(archive, staging)
        finally:
            if archive.exists():
                archive.unlink()
        verification = verify_report(staging)
        if verification["checksums_sha256"] != header["report_checksums_sha256"]:
            raise ValueError("decrypted report identity does not match its envelope")
        for path in [staging, *staging.rglob("*")]:
            os.chmod(path, 0o700 if path.is_dir() else 0o600)
        staging.rename(destination)
        return verification
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def _archive_report(root: Path, archive: Path) -> None:
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise ValueError(f"report archive cannot contain links: {path}")
            if path.is_file():
                bundle.write(path, path.relative_to(root).as_posix())


def _decrypt_archive(
    source_path: Path, archive: Path, private_key: X25519PrivateKey
) -> dict[str, Any]:
    size = source_path.stat().st_size
    with source_path.open("rb") as source:
        if source.read(len(_MAGIC)) != _MAGIC:
            raise ValueError("encrypted report format is invalid")
        raw_length = source.read(4)
        if len(raw_length) != 4:
            raise ValueError("encrypted report header is truncated")
        header_length = struct.unpack(">I", raw_length)[0]
        if not 1 <= header_length <= _MAX_HEADER:
            raise ValueError("encrypted report header size is invalid")
        header_bytes = source.read(header_length)
        header = strict_loads(header_bytes)
        if not isinstance(header, dict) or set(header) != {
            "schema_version",
            "algorithm",
            "ephemeral_public_key",
            "salt",
            "nonce",
            "plaintext_bytes",
            "report_checksums_sha256",
            "key_lifecycle",
        }:
            raise ValueError("encrypted report header fields do not match")
        if (
            header["schema_version"] != "1.1"
            or header["algorithm"] != "X25519-HKDF-SHA256+A256GCM"
        ):
            raise ValueError("encrypted report algorithm is unsupported")
        ephemeral = X25519PublicKey.from_public_bytes(
            base64.b64decode(str(header["ephemeral_public_key"]), validate=True)
        )
        salt = base64.b64decode(str(header["salt"]), validate=True)
        nonce = base64.b64decode(str(header["nonce"]), validate=True)
        ciphertext_bytes = size - len(_MAGIC) - 4 - header_length - 16
        if (
            ciphertext_bytes != header["plaintext_bytes"]
            or not 0 <= ciphertext_bytes <= _MAX_ARCHIVE
        ):
            raise ValueError("encrypted report payload length is invalid")
        source.seek(size - 16)
        tag = source.read(16)
        source.seek(len(_MAGIC) + 4 + header_length)
        decryptor = Cipher(
            algorithms.AES(_derive_key(private_key.exchange(ephemeral), salt)),
            modes.GCM(nonce, tag),
        ).decryptor()
        decryptor.authenticate_additional_data(header_bytes)
        remaining = ciphertext_bytes
        with archive.open("wb") as target:
            while remaining:
                chunk = source.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise ValueError("encrypted report payload is truncated")
                target.write(decryptor.update(chunk))
                remaining -= len(chunk)
            try:
                target.write(decryptor.finalize())
            except InvalidTag as exc:
                raise ValueError("encrypted report authentication failed") from exc
    return header


def _extract_archive(archive: Path, staging: Path) -> None:
    total = 0
    with zipfile.ZipFile(archive) as bundle:
        if len(bundle.infolist()) > 10_000:
            raise ValueError("decrypted report contains too many files")
        for item in bundle.infolist():
            relative = PurePosixPath(item.filename)
            if relative.is_absolute() or ".." in relative.parts or item.is_dir():
                raise ValueError("decrypted report archive path is invalid")
            if (item.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("decrypted report archive contains a link")
            total += item.file_size
            if total > _MAX_ARCHIVE:
                raise ValueError("decrypted report exceeds 8 GiB")
            target = staging.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(item) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)


def _derive_key(shared_secret: bytes, salt: bytes) -> bytes:
    return bytes(
        HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"py-security-suite/confidential-report/v1",
        ).derive(shared_secret)
    )
