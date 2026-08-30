from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from py_security_suite.trusted_time import (
    _TRUSTED_TIME_STATE_GENESIS_SHA256,
    _advance_time_state,
    _bounded_bytes,
    _certificates,
    _deployment_values,
    _match_digest,
    _nonce,
    _select_issuer,
    _signature_hash,
    _sibling,
    _state_sequence,
    _timestamp,
    _verify_ca_constraints,
    _verify_chain,
    _verify_deployment_policy,
    _verify_legacy_policy,
    _verify_revocation,
    verify_rfc3161,
)


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


def test_trusted_time_quorum_requires_independence_agreement_and_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed = datetime(2026, 8, 30, 12, tzinfo=UTC)
    values = [{"authority": "tsa-a"}, {"authority": "tsa-b"}]

    def receipt(index: int, *, offset: int = 0) -> dict[str, str]:
        return {
            "trusted_time_sha256": str(index) * 64,
            "trusted_time_observed_at": (
                observed + timedelta(seconds=offset)
            ).isoformat(),
            "trusted_time_receipt_sha256": chr(97 + index) * 64,
            "trusted_time_signer_sha256": chr(99 + index) * 64,
        }

    with patch(
        "py_security_suite.trusted_time._verify_single_rfc3161",
        side_effect=[receipt(1), receipt(2)],
    ):
        with pytest.raises(ValueError, match="persistent monotonic state"):
            verify_rfc3161(tmp_path / "context.json", values, "f" * 64)

    monkeypatch.setenv("PYSEC_TRUSTED_TIME_STATE_PATH", str(tmp_path / "state.db"))
    monkeypatch.setenv("PYSEC_TRUSTED_TIME_MIN_SEQUENCE", "0")
    monkeypatch.setenv(
        "PYSEC_TRUSTED_TIME_CHECKPOINT_SHA256", _TRUSTED_TIME_STATE_GENESIS_SHA256
    )
    with (
        patch(
            "py_security_suite.trusted_time._verify_single_rfc3161",
            side_effect=[receipt(1), receipt(2)],
        ),
        patch(
            "py_security_suite.checkpoint_authority.publish_checkpoint",
            return_value=None,
        ),
    ):
        result = verify_rfc3161(tmp_path / "context.json", values, "f" * 64)

    assert result["trusted_time_observed_at"] == observed.isoformat()
    assert len(result["trusted_time_sha256"]) == 64

    with patch(
        "py_security_suite.trusted_time._verify_single_rfc3161",
        side_effect=[receipt(1), receipt(2, offset=6)],
    ):
        with pytest.raises(ValueError, match="timestamps disagree"):
            verify_rfc3161(tmp_path / "context.json", values, "f" * 64)


@pytest.mark.parametrize("value", [[], [{}], [{}, {}, {}, {}, {}, {}]])
def test_trusted_time_quorum_is_bounded(value: list[object]) -> None:
    with pytest.raises(ValueError, match="two to five"):
        verify_rfc3161(Path("context.json"), value, "a" * 64)


def test_trusted_time_quorum_rejects_duplicate_authorities_and_signers() -> None:
    observed = datetime(2026, 8, 30, 12, tzinfo=UTC).isoformat()
    result = {
        "trusted_time_sha256": "1" * 64,
        "trusted_time_observed_at": observed,
        "trusted_time_receipt_sha256": "2" * 64,
        "trusted_time_signer_sha256": "3" * 64,
    }
    with patch(
        "py_security_suite.trusted_time._verify_single_rfc3161",
        side_effect=[result, result],
    ):
        with pytest.raises(ValueError, match="must be independent"):
            verify_rfc3161(
                Path("context.json"),
                [{"authority": "same"}, {"authority": "same"}],
                "a" * 64,
            )


def test_trusted_time_deployment_policies_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = "a" * 64
    root = "b" * 64
    monkeypatch.setenv("PYSEC_TSA_SIGNER_SHA256", signer)
    monkeypatch.setenv("PYSEC_TSA_ROOT_SHA256", root)
    monkeypatch.setenv("PYSEC_TSA_AUTHORITIES", "tsa-a, tsa-b")
    monkeypatch.setenv("PYSEC_TSA_POLICY_OIDS", "1.2.3,1.2.4")

    _verify_legacy_policy("tsa-a", signer)
    _verify_deployment_policy("tsa-b", root, "1.2.4")
    assert _deployment_values("PYSEC_TSA_AUTHORITIES") == {"tsa-a", "tsa-b"}

    with pytest.raises(ValueError, match="signer is not deployment-pinned"):
        _verify_legacy_policy("tsa-a", "c" * 64)
    with pytest.raises(ValueError, match="trust root is not deployment-pinned"):
        _verify_deployment_policy("tsa-a", "c" * 64, "1.2.3")
    monkeypatch.setenv("PYSEC_TSA_ROOT_SHA256", "invalid")
    with pytest.raises(ValueError, match="unavailable or invalid"):
        _deployment_values("PYSEC_TSA_ROOT_SHA256", digest=True)


def test_trusted_time_primitive_validators_reject_ambiguous_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b"receipt"
    digest = hashlib.sha256(payload).hexdigest()
    assert _match_digest(payload, digest, "receipt") == digest
    assert _nonce(1) == 1
    assert _timestamp("2026-08-30T12:00:00Z").tzinfo == UTC
    assert _sibling(tmp_path / "context.json", "receipt.tsr", "receipt") == (
        tmp_path / "receipt.tsr"
    )

    for value in (True, 0, 2**53):
        with pytest.raises(ValueError, match="positive I-JSON integer"):
            _nonce(value)
    with pytest.raises(ValueError, match="include a timezone"):
        _timestamp("2026-08-30T12:00:00")
    with pytest.raises(ValueError, match="bounded sibling"):
        _sibling(tmp_path / "context.json", "../receipt.tsr", "receipt")
    with pytest.raises(ValueError, match="SHA-256 does not match"):
        _match_digest(payload, "0" * 64, "receipt")

    monkeypatch.setenv("SEQUENCE", "01")
    with pytest.raises(ValueError, match="sequence is invalid"):
        _state_sequence("SEQUENCE")
    monkeypatch.setenv("SEQUENCE", "not-an-int")
    with pytest.raises(ValueError, match="sequence is invalid"):
        _state_sequence("SEQUENCE")


def test_trusted_time_state_rejects_deletion_rollback_fork_and_missing_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "trusted-time.db"
    monkeypatch.setenv("PYSEC_TRUSTED_TIME_STATE_PATH", str(state))
    monkeypatch.setenv("PYSEC_TRUSTED_TIME_MIN_SEQUENCE", "0")
    monkeypatch.setenv(
        "PYSEC_TRUSTED_TIME_CHECKPOINT_SHA256", _TRUSTED_TIME_STATE_GENESIS_SHA256
    )
    first = {
        "trusted_time_observed_at": "2026-08-30T12:00:00+00:00",
        "trusted_time_sha256": "1" * 64,
    }
    with patch(
        "py_security_suite.checkpoint_authority.publish_checkpoint",
        return_value={"receipt": "externally-retained"},
    ):
        _advance_time_state("a" * 64, first)

    with sqlite3.connect(state) as connection:
        sequence, checkpoint = connection.execute(
            "SELECT sequence, checkpoint_sha256 FROM trusted_time_state"
        ).fetchone()
    assert sequence == 1

    monkeypatch.setenv("PYSEC_TRUSTED_TIME_MIN_SEQUENCE", "1")
    monkeypatch.setenv("PYSEC_TRUSTED_TIME_CHECKPOINT_SHA256", checkpoint)
    with patch(
        "py_security_suite.checkpoint_authority.verify_retained_checkpoint"
    ) as verify:
        _advance_time_state("a" * 64, first)
    verify.assert_called_once()

    earlier = {
        "trusted_time_observed_at": "2026-08-30T11:59:59+00:00",
        "trusted_time_sha256": "2" * 64,
    }
    with pytest.raises(ValueError, match="rollback or fork"):
        _advance_time_state("b" * 64, earlier)

    fork = dict(first, trusted_time_sha256="3" * 64)
    with pytest.raises(ValueError, match="rollback or fork"):
        _advance_time_state("a" * 64, fork)

    monkeypatch.setenv(
        "PYSEC_TRUSTED_TIME_STATE_PATH", str(tmp_path / "deleted-state.db")
    )
    with pytest.raises(ValueError, match="deletion or rollback"):
        _advance_time_state("c" * 64, first)


def test_trusted_time_state_requires_retained_external_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "trusted-time.db"
    monkeypatch.setenv("PYSEC_TRUSTED_TIME_STATE_PATH", str(state))
    monkeypatch.setenv("PYSEC_TRUSTED_TIME_MIN_SEQUENCE", "0")
    monkeypatch.setenv(
        "PYSEC_TRUSTED_TIME_CHECKPOINT_SHA256", _TRUSTED_TIME_STATE_GENESIS_SHA256
    )
    result = {
        "trusted_time_observed_at": "2026-08-30T12:00:00+00:00",
        "trusted_time_sha256": "4" * 64,
    }
    with patch(
        "py_security_suite.checkpoint_authority.publish_checkpoint", return_value=None
    ):
        _advance_time_state("d" * 64, result)

    monkeypatch.setenv("PYSEC_TRUSTED_TIME_REQUIRE_EXTERNAL_CHECKPOINT", "1")
    with pytest.raises(ValueError, match="external checkpoint is absent"):
        _advance_time_state("d" * 64, result)


def test_trusted_time_pkix_chain_and_revocation_are_cryptographically_verified() -> (
    None
):
    observed = datetime(2026, 8, 30, 12, tzinfo=UTC)
    root_key, root, leaf = _timestamp_chain(observed)

    _verify_chain([leaf], [root], observed)
    assert _select_issuer(leaf, [root]) == root
    assert _select_issuer(leaf, []) is None
    with pytest.raises(ValueError, match="missing or ambiguous"):
        _select_issuer(leaf, [root, root])
    with pytest.raises(ValueError, match="not authorized as a CA"):
        _verify_ca_constraints(leaf, 0)

    clean_crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root.subject)
        .last_update(observed - timedelta(minutes=1))
        .next_update(observed + timedelta(minutes=1))
        .sign(root_key, hashes.SHA256())
    )
    _verify_revocation(
        [leaf], [root], clean_crl.public_bytes(serialization.Encoding.PEM), observed
    )

    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(leaf.serial_number)
        .revocation_date(observed - timedelta(seconds=1))
        .build()
    )
    revoked_crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root.subject)
        .last_update(observed - timedelta(minutes=1))
        .next_update(observed + timedelta(minutes=1))
        .add_revoked_certificate(revoked)
        .sign(root_key, hashes.SHA256())
    )
    with pytest.raises(ValueError, match="revoked at issuance"):
        _verify_revocation(
            [leaf],
            [root],
            revoked_crl.public_bytes(serialization.Encoding.DER),
            observed,
        )


def test_trusted_time_certificate_and_file_helpers_fail_closed(tmp_path: Path) -> None:
    observed = datetime(2026, 8, 30, 12, tzinfo=UTC)
    _, root, leaf = _timestamp_chain(observed)
    bundle = root.public_bytes(serialization.Encoding.PEM) + leaf.public_bytes(
        serialization.Encoding.PEM
    )
    assert len(_certificates(bundle, "chain")) == 2
    with pytest.raises(ValueError, match="chain is invalid"):
        _certificates(b"not-a-certificate", "chain")
    with pytest.raises(ValueError, match="signature hash algorithm is unavailable"):
        _signature_hash(None)

    bounded = tmp_path / "bounded.bin"
    bounded.write_bytes(b"1234")
    assert _bounded_bytes(bounded, "fixture", 4) == b"1234"
    with pytest.raises(ValueError, match="bounded regular file"):
        _bounded_bytes(bounded, "fixture", 3)
    with pytest.raises(ValueError, match="bounded regular file"):
        _bounded_bytes(tmp_path / "missing.bin", "fixture", 3)


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


def _timestamp_chain(
    observed: datetime,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate, x509.Certificate]:
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root TSA CA")])
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Timestamp TSA")])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(observed - timedelta(days=1))
        .not_valid_after(observed + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(root_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(root_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(observed - timedelta(hours=1))
        .not_valid_after(observed + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
        )
        .sign(root_key, hashes.SHA256())
    )
    return root_key, root, leaf
