from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_security_suite.confidential_archive import decrypt_report, encrypt_report
from py_security_suite.config import load_config
from py_security_suite.orchestrator import scan_project
from tests.test_orchestrator import FakeBandit, FakeSecrets
from py_security_suite.strict_json import canonical_bytes


class ConfidentialArchiveTests(unittest.TestCase):
    def test_verified_report_round_trip_is_authenticated_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            (target / "app.py").write_text("print(1)\n", encoding="utf-8")
            report = root / "report"
            scan_project(
                target=target,
                output=report,
                config=load_config(profile_override="quick"),
                network_isolation_attested=True,
                adapter_types={"bandit": FakeBandit, "detect-secrets": FakeSecrets},
            )
            private = X25519PrivateKey.generate()
            private_path = root / "recipient.pem"
            public_path = root / "recipient.pub.pem"
            private_path.write_bytes(
                private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            public_path.write_bytes(
                private.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            encrypted = root / "report.pysecenc"
            authority = Ed25519PrivateKey.generate()
            authority_path = root / "key-authority.pub.pem"
            authority_path.write_bytes(
                authority.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            now = datetime.now(UTC)
            lifecycle = {
                "schema_version": "1.0",
                "provider": "hsm",
                "key_id": "test-key",
                "generation": 1,
                "status": "active",
                "not_before": (now - timedelta(minutes=1)).isoformat(),
                "not_after": (now + timedelta(days=30)).isoformat(),
                "recipient_public_key_sha256": _sha256(public_path),
                "destruction_policy": "provider-verified-cryptographic-erasure",
            }
            lifecycle_path = root / "key-lifecycle.json"
            lifecycle_path.write_text(
                json.dumps(lifecycle, sort_keys=True), encoding="utf-8"
            )
            signature_path = root / "key-lifecycle.sig"
            signature_path.write_bytes(authority.sign(canonical_bytes(lifecycle)))
            provider_authority = Ed25519PrivateKey.generate()
            provider_authority_path = root / "provider-authority.pub.pem"
            provider_authority_path.write_bytes(
                provider_authority.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            provider_attestation = {
                "schema_version": "1.0",
                "provider": "hsm",
                "key_id": "test-key",
                "generation": 1,
                "recipient_public_key_sha256": _sha256(public_path),
                "key_non_exportable": True,
                "key_usage": "decrypt-report",
                "destruction_capability": "provider-verified-cryptographic-erasure",
                "attested_at": now.isoformat(),
                "attestation_id": "provider-test-1",
            }
            provider_path = root / "provider-attestation.json"
            provider_path.write_text(
                json.dumps(provider_attestation, sort_keys=True), encoding="utf-8"
            )
            provider_signature = root / "provider-attestation.sig"
            provider_signature.write_bytes(
                provider_authority.sign(canonical_bytes(provider_attestation))
            )
            time_context = root / "encryption-time.json"
            time_context.write_text(
                json.dumps({"schema_version": "1.0", "trusted_time": {}}),
                encoding="utf-8",
            )
            with patch(
                "py_security_suite.confidential_archive.verify_rfc3161",
                return_value={
                    "trusted_time_observed_at": now.isoformat(),
                    "trusted_time_receipt_sha256": "f" * 64,
                },
            ):
                encrypt_report(
                    report,
                    encrypted,
                    recipient_public_key=public_path,
                    recipient_public_key_sha256=_sha256(public_path),
                    key_lifecycle_receipt=lifecycle_path,
                    key_lifecycle_receipt_sha256=_sha256(lifecycle_path),
                    key_authority_public_key=authority_path,
                    key_authority_public_key_sha256=_sha256(authority_path),
                    key_lifecycle_signature=signature_path,
                    provider_attestation=provider_path,
                    provider_attestation_sha256=_sha256(provider_path),
                    provider_authority_public_key=provider_authority_path,
                    provider_authority_public_key_sha256=_sha256(
                        provider_authority_path
                    ),
                    provider_attestation_signature=provider_signature,
                    trusted_time_context=time_context,
                )
            decrypted = root / "decrypted"
            receipt = decrypt_report(
                encrypted,
                decrypted,
                recipient_private_key=private_path,
                recipient_private_key_sha256=_sha256(private_path),
            )
        self.assertTrue(receipt["verified"])


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
