from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import rfc3161ng  # type: ignore[import-untyped]
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

try:
    from companion.strict_json import canonical_bytes
except ModuleNotFoundError:  # Direct script execution.
    from strict_json import canonical_bytes  # type: ignore[import-not-found,no-redef]


def verify_rfc3161(
    context_path: Path,
    value: object,
    challenge_sha256: str,
    *,
    require_advanced: bool = False,
) -> dict[str, str]:
    v1_required = {
        "format",
        "authority",
        "observed_at",
        "receipt_file",
        "receipt_sha256",
        "signer_certificate_file",
        "signer_certificate_sha256",
        "nonce",
    }
    v2_extra = {
        "certificate_chain_file",
        "certificate_chain_sha256",
        "trust_roots_file",
        "trust_roots_sha256",
        "revocation_file",
        "revocation_sha256",
        "tsa_policy_oid",
        "require_ess_cert_id_v2",
    }
    if not isinstance(value, dict):
        raise TypeError("trusted_time must be an object")
    if set(value) == v1_required | v2_extra:
        try:
            from py_security_suite.trusted_time import verify_rfc3161 as verify_full
        except ModuleNotFoundError as exc:
            raise ValueError(
                "advanced RFC 3161 verification requires the locked py-security-suite runtime"
            ) from exc
        return verify_full(
            context_path,
            value,
            challenge_sha256,
            require_advanced=require_advanced,
        )
    if set(value) != v1_required:
        raise ValueError("trusted_time fields do not match the RFC 3161 contract")
    if require_advanced:
        raise ValueError("this operation requires the advanced RFC 3161 trust contract")
    if value.get("format") != "rfc3161":
        raise ValueError("trusted_time format must be rfc3161")
    authority = _text(value.get("authority"), "trusted-time authority", 200)
    receipt_path = _sibling(
        context_path, value.get("receipt_file"), "timestamp receipt"
    )
    certificate_path = _sibling(
        context_path,
        value.get("signer_certificate_file"),
        "timestamp signer certificate",
    )
    receipt = _bounded_bytes(receipt_path, "timestamp receipt", 4 * 1024 * 1024)
    certificate_bytes = _bounded_bytes(
        certificate_path, "timestamp signer certificate", 1024 * 1024
    )
    receipt_sha256 = _match_digest(
        receipt, value.get("receipt_sha256"), "timestamp receipt"
    )
    signer_sha256 = _match_digest(
        certificate_bytes,
        value.get("signer_certificate_sha256"),
        "timestamp signer certificate",
    )
    nonce = _nonce(value.get("nonce"))
    if not _digest(challenge_sha256):
        raise ValueError("challenge_sha256 is invalid")
    try:
        response = rfc3161ng.decode_timestamp_response(receipt)
        token = response["timeStampToken"]
        rfc3161ng.check_timestamp(
            token,
            certificate=certificate_bytes,
            digest=bytes.fromhex(challenge_sha256),
            hashname="sha256",
            nonce=nonce,
        )
        issued_at = rfc3161ng.get_timestamp(token, naive=False).astimezone(UTC)
    except Exception as exc:
        raise ValueError("RFC 3161 timestamp verification failed") from exc
    observed_at = _timestamp(value.get("observed_at"))
    if abs((issued_at - observed_at).total_seconds()) > 1:
        raise ValueError("RFC 3161 timestamp does not match observed_at")
    certificate = _certificate(certificate_bytes)
    try:
        eku = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("timestamp signer certificate lacks an EKU") from exc
    if ExtendedKeyUsageOID.TIME_STAMPING not in eku:
        raise ValueError(
            "timestamp signer certificate is not authorized for timestamping"
        )
    if (
        not certificate.not_valid_before_utc
        <= issued_at
        <= certificate.not_valid_after_utc
    ):
        raise ValueError("timestamp signer certificate was not valid at issuance")
    pinned = {
        item.strip()
        for item in os.environ.get("PYSEC_TSA_SIGNER_SHA256", "").split(",")
        if item.strip()
    }
    authorities = {
        item.strip()
        for item in os.environ.get("PYSEC_TSA_AUTHORITIES", "").split(",")
        if item.strip()
    }
    if signer_sha256 not in pinned or not all(_digest(item) for item in pinned):
        raise ValueError("timestamp signer is not deployment-pinned")
    if authority not in authorities:
        raise ValueError("timestamp authority is not deployment-approved")
    normalized = {
        "format": "rfc3161",
        "authority": authority,
        "observed_at": observed_at.isoformat(),
        "receipt_sha256": receipt_sha256,
        "signer_certificate_sha256": signer_sha256,
        "nonce_sha256": hashlib.sha256(str(nonce).encode()).hexdigest(),
    }
    return {
        "trusted_time_sha256": hashlib.sha256(canonical_bytes(normalized)).hexdigest(),
        "trusted_time_observed_at": observed_at.isoformat(),
        "trusted_time_receipt_sha256": receipt_sha256,
        "trusted_time_signer_sha256": signer_sha256,
    }


def _sibling(context: Path, value: object, label: str) -> Path:
    name = str(value or "")
    if not name or Path(name).name != name or len(name) > 200:
        raise ValueError(f"{label} file must be a bounded sibling filename")
    return context.resolve().parent / name


def _bounded_bytes(path: Path, label: str, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError(f"{label} must be a bounded regular file")
    return path.read_bytes()


def _match_digest(payload: bytes, expected: object, label: str) -> str:
    digest = str(expected or "")
    if not _digest(digest) or hashlib.sha256(payload).hexdigest() != digest:
        raise ValueError(f"{label} SHA-256 does not match")
    return digest


def _certificate(value: bytes) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(value)
    except ValueError:
        try:
            return x509.load_der_x509_certificate(value)
        except ValueError as exc:
            raise ValueError("timestamp signer certificate is invalid") from exc


def _nonce(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 < value <= 2**53 - 1
    ):
        raise ValueError("timestamp nonce must be a positive I-JSON integer")
    return value


def _timestamp(value: object) -> datetime:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("trusted_time observed_at is invalid") from exc
    if result.tzinfo is None:
        raise ValueError("trusted_time observed_at must include a timezone")
    return result.astimezone(UTC)


def _text(value: Any, label: str, maximum: int) -> str:
    result = str(value or "").strip()
    if not result or len(result) > maximum:
        raise ValueError(f"{label} is invalid")
    return result


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
