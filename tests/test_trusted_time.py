from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from py_security_suite.trusted_time import verify_rfc3161


def test_rfc3161_receipt_binds_challenge_nonce_time_and_signer(tmp_path: Path) -> None:
    observed = datetime.now(UTC).replace(microsecond=0)
    receipt = tmp_path / "timestamp.tsr"
    certificate = tmp_path / "timestamp.pem"
    context = tmp_path / "context.json"
    receipt.write_bytes(b"bounded-rfc3161-response")
    certificate.write_bytes(_timestamp_certificate(observed))
    context.write_text("{}", encoding="utf-8")
    challenge = "4" * 64
    value = {
        "format": "rfc3161",
        "authority": "organization-tsa",
        "observed_at": observed.isoformat(),
        "receipt_file": receipt.name,
        "receipt_sha256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
        "signer_certificate_file": certificate.name,
        "signer_certificate_sha256": hashlib.sha256(
            certificate.read_bytes()
        ).hexdigest(),
        "nonce": 42,
    }

    with (
        patch.dict(
            "os.environ",
            {
                "PYSEC_TSA_SIGNER_SHA256": value["signer_certificate_sha256"],
                "PYSEC_TSA_AUTHORITIES": "organization-tsa",
            },
        ),
        patch(
            "py_security_suite.trusted_time.rfc3161ng.decode_timestamp_response",
            return_value={"timeStampToken": "token"},
        ),
        patch("py_security_suite.trusted_time.rfc3161ng.check_timestamp") as check,
        patch(
            "py_security_suite.trusted_time.rfc3161ng.get_timestamp",
            return_value=observed,
        ),
    ):
        result = verify_rfc3161(context, value, challenge)

    assert result["trusted_time_receipt_sha256"] == value["receipt_sha256"]
    assert result["trusted_time_signer_sha256"] == value["signer_certificate_sha256"]
    assert check.call_args.kwargs["digest"] == bytes.fromhex(challenge)
    assert check.call_args.kwargs["nonce"] == 42


def _timestamp_certificate(observed: datetime) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Test Timestamp Authority")]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(observed - timedelta(hours=1))
        .not_valid_after(observed + timedelta(hours=1))
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)
