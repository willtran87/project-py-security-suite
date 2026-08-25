from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# The isolated Pylint lane intentionally omits locked test-only dependencies.
from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.config import IntelligenceConfig, IsolationConfig
from py_security_suite.governance import (
    validate_intelligence_approval,
    validate_isolation_evidence,
)
from py_security_suite.strict_json import canonical_bytes


class GovernanceTests(unittest.TestCase):
    def test_governance_v2_requires_quorum_capabilities_and_rejects_replay(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_path = root / "isolation.json"
            detached_key = root / "detached.pem"
            detached_signature = root / "isolation.sig"
            detached_digest, detached_private = _write_key(detached_key)
            evidence = {
                key: value
                for key, value in _isolation_document().items()
                if key not in {"signature_verified", "verifier"}
            }
            evidence.update(
                {
                    "schema_version": "2.0",
                    "trust_root_sha256": detached_digest,
                    "generation": 7,
                    "nonce": "unique-governance-nonce-17",
                    "capabilities": [
                        "network-deny-all",
                        "target-read-only",
                        "resource-limits",
                        "process-tree-termination",
                        "file-write-quota",
                        "host-filesystem-read-deny",
                        "credential-isolation",
                        "process-isolation",
                        "device-isolation",
                        "ipc-isolation",
                        "windows-appcontainer",
                    ],
                    "minimum_authority_signatures": 2,
                }
            )
            authorities, environment = _governance_authorities(
                root, evidence, "isolation-evidence"
            )
            evidence["authorities"] = authorities
            digest = _write_json(evidence_path, evidence)
            detached_signature.write_bytes(
                detached_private.sign(evidence_path.read_bytes())
            )
            config = IsolationConfig(
                require_evidence=True,
                require_governance_v2=True,
                replay_ledger_path=root / "replay.sqlite3",
                evidence_path=evidence_path,
                evidence_sha256=digest,
                evidence_public_key_path=detached_key,
                evidence_public_key_sha256=detached_digest,
                evidence_signature_path=detached_signature,
                evidence_organization_approved=True,
            )
            with patch.dict(os.environ, environment, clear=False):
                first = validate_isolation_evidence(
                    config,
                    target_name="project",
                    source_sha256="a" * 64,
                    observed_at=datetime(2026, 8, 7, 12, tzinfo=UTC),
                )
                replay = validate_isolation_evidence(
                    config,
                    target_name="project",
                    source_sha256="a" * 64,
                    observed_at=datetime(2026, 8, 7, 12, tzinfo=UTC),
                )
        self.assertEqual(first.errors, [])
        self.assertEqual(first.artifact["governance_contract"], "v2-quorum")
        self.assertIn("replay was detected", replay.errors[0])
        _validate_schema("isolation-attestation.schema.json", first.artifact)

    def test_digest_bound_isolation_evidence_is_validated_and_schema_conformant(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "isolation.json"
            key_path = Path(directory) / "governance-key.pem"
            signature_path = Path(directory) / "isolation.sig"
            key_digest, private_key = _write_key(key_path)
            evidence = _isolation_document()
            evidence["trust_root_sha256"] = key_digest
            digest = _write_json(path, evidence)
            signature_path.write_bytes(private_key.sign(path.read_bytes()))
            result = validate_isolation_evidence(
                IsolationConfig(
                    require_evidence=True,
                    evidence_path=path,
                    evidence_sha256=digest,
                    evidence_public_key_path=key_path,
                    evidence_public_key_sha256=key_digest,
                    evidence_signature_path=signature_path,
                    evidence_organization_approved=True,
                ),
                target_name="project",
                source_sha256="a" * 64,
                observed_at=datetime(2026, 8, 7, 12, tzinfo=UTC),
            )

        self.assertEqual(result.errors, [])
        self.assertTrue(result.artifact["validated"])
        _validate_schema("isolation-attestation.schema.json", result.artifact)

    def test_isolation_evidence_fails_closed_on_target_or_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "isolation.json"
            key_path = Path(directory) / "governance-key.pem"
            signature_path = Path(directory) / "isolation.sig"
            key_digest, private_key = _write_key(key_path)
            evidence = _isolation_document()
            evidence["target"] = "another-project"
            evidence["trust_root_sha256"] = key_digest
            _write_json(path, evidence)
            signature_path.write_bytes(private_key.sign(path.read_bytes()))
            result = validate_isolation_evidence(
                IsolationConfig(
                    require_evidence=True,
                    evidence_path=path,
                    evidence_sha256="b" * 64,
                    evidence_public_key_path=key_path,
                    evidence_public_key_sha256=key_digest,
                    evidence_signature_path=signature_path,
                ),
                target_name="project",
                source_sha256="a" * 64,
                observed_at=datetime(2026, 8, 7, 12, tzinfo=UTC),
            )

        self.assertFalse(result.artifact["validated"])
        self.assertIn("approved SHA-256", result.errors[0])
        _validate_schema("isolation-attestation.schema.json", result.artifact)

    def test_intelligence_approval_must_match_every_consumed_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approval.json"
            key_path = Path(directory) / "governance-key.pem"
            signature_path = Path(directory) / "approval.sig"
            key_digest, private_key = _write_key(key_path)
            approval = _intelligence_document()
            approval["trust_root_sha256"] = key_digest
            digest = _write_json(path, approval)
            signature_path.write_bytes(private_key.sign(path.read_bytes()))
            config = IntelligenceConfig(
                approval_path=path,
                approval_sha256=digest,
                approval_public_key_path=key_path,
                approval_public_key_sha256=key_digest,
                approval_signature_path=signature_path,
                require_approval=True,
                approval_organization_approved=True,
            )
            intelligence = {
                "snapshots": {
                    "kev": {"sha256": "b" * 64},
                    "epss": {"sha256": "c" * 64},
                }
            }
            result = validate_intelligence_approval(
                config,
                intelligence,
                observed_at=datetime(2026, 8, 7, 12, tzinfo=UTC),
            )
            intelligence["snapshots"]["epss"]["sha256"] = "d" * 64
            mismatch = validate_intelligence_approval(
                config,
                intelligence,
                observed_at=datetime(2026, 8, 7, 12, tzinfo=UTC),
            )

        self.assertEqual(result.errors, [])
        self.assertTrue(result.artifact["validated"])
        _validate_schema("intelligence-approval.schema.json", result.artifact)
        self.assertIn("does not match", mismatch.errors[0])
        _validate_schema("intelligence-approval.schema.json", mismatch.artifact)

    def test_self_asserted_signature_claim_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "isolation.json"
            evidence = _isolation_document()
            digest = _write_json(path, evidence)
            result = validate_isolation_evidence(
                IsolationConfig(
                    require_evidence=True,
                    evidence_path=path,
                    evidence_sha256=digest,
                    evidence_organization_approved=True,
                ),
                target_name="project",
                source_sha256="a" * 64,
                observed_at=datetime(2026, 8, 7, 12, tzinfo=UTC),
            )
        self.assertFalse(result.artifact["validated"])
        self.assertIn("independent signature verification", result.errors[0])


def _isolation_document() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "status": "enforced",
        "network_policy": "deny",
        "target": "project",
        "source_sha256": "a" * 64,
        "issuer": "enterprise-runner-controller",
        "runner_id": "runner-17",
        "policy_id": "egress-deny-v3",
        "policy_sha256": "b" * 64,
        "approved_by": "platform-security",
        "valid_from": "2026-08-07T00:00:00Z",
        "valid_until": "2026-08-08T00:00:00Z",
        "signature_verified": True,
        "verifier": "enterprise-attestation-verifier",
        "trust_root_sha256": "c" * 64,
    }


def _intelligence_document() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "status": "approved",
        "manifest_id": "intelligence-2026-08-07",
        "revision": "17",
        "approved_by": "vulnerability-management",
        "valid_until": "2026-08-08T00:00:00Z",
        "signature_verified": True,
        "verifier": "enterprise-attestation-verifier",
        "trust_root_sha256": "a" * 64,
        "snapshots": [
            {"kind": "kev", "sha256": "b" * 64},
            {"kind": "epss", "sha256": "c" * 64},
        ],
    }


def _write_json(path: Path, document: dict[str, object]) -> str:
    payload = json.dumps(document, sort_keys=True).encode()
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _write_key(path: Path) -> tuple[str, Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    payload = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest(), private_key


def _governance_authorities(
    root: Path, subject: dict[str, object], purpose: str
) -> tuple[list[dict[str, object]], dict[str, str]]:
    records: list[dict[str, object]] = []
    trusted: list[str] = []
    roles: dict[str, list[str]] = {}
    organizations: dict[str, str] = {}
    lifecycle: dict[str, dict[str, object]] = {}
    for index in range(2):
        key_path = root / f"authority-{index}.pem"
        _, private_key = _write_key(key_path)
        raw_key = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        signer = hashlib.sha256(raw_key).hexdigest()
        statement = {
            "schema_version": "1.0",
            "purpose": purpose,
            "subject_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
            "signer_id": signer,
            "collector_id": f"collector-{index}",
            "signed_at": "2026-08-07T00:00:00+00:00",
            "expires_at": "2026-08-08T00:00:00+00:00",
        }
        signature = private_key.sign(canonical_bytes(statement))
        signature_path = root / f"authority-{index}.sig"
        signature_path.write_bytes(signature)
        records.append(
            {
                "schema_version": "1.0",
                "signer_id": signer,
                "collector_id": f"collector-{index}",
                "signed_at": statement["signed_at"],
                "expires_at": statement["expires_at"],
                "public_key_file": key_path.name,
                "public_key_sha256": hashlib.sha256(key_path.read_bytes()).hexdigest(),
                "signature_file": signature_path.name,
                "signature_sha256": hashlib.sha256(signature).hexdigest(),
            }
        )
        trusted.append(signer)
        roles[signer] = [purpose]
        organizations[signer] = f"organization-{index}"
        lifecycle[signer] = {
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2027-01-01T00:00:00Z",
            "revoked_at": None,
        }
    return records, {
        "PYSEC_TRUSTED_AUTHORITY_KEY_SHA256": ",".join(trusted),
        "PYSEC_TRUSTED_AUTHORITY_ROLES": json.dumps(roles),
        "PYSEC_AUTHORITY_ORGANIZATIONS": json.dumps(organizations),
        "PYSEC_AUTHORITY_KEY_LIFECYCLE": json.dumps(lifecycle),
        "PYSEC_GOVERNANCE_MIN_GENERATION": "7",
    }


def _validate_schema(name: str, document: dict[str, object]) -> None:
    schema = json.loads(
        files("py_security_suite").joinpath("schemas", name).read_text("utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)
