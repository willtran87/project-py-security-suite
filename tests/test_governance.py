from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path

# The isolated Pylint lane intentionally omits locked test-only dependencies.
from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.config import IntelligenceConfig, IsolationConfig
from py_security_suite.governance import (
    validate_intelligence_approval,
    validate_isolation_evidence,
)


class GovernanceTests(unittest.TestCase):
    def test_digest_bound_isolation_evidence_is_validated_and_schema_conformant(
        self,
    ) -> None:
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

        self.assertEqual(result.errors, [])
        self.assertTrue(result.artifact["validated"])
        _validate_schema("isolation-attestation.schema.json", result.artifact)

    def test_isolation_evidence_fails_closed_on_target_or_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "isolation.json"
            evidence = _isolation_document()
            evidence["target"] = "another-project"
            _write_json(path, evidence)
            result = validate_isolation_evidence(
                IsolationConfig(
                    require_evidence=True,
                    evidence_path=path,
                    evidence_sha256="b" * 64,
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
            approval = _intelligence_document()
            digest = _write_json(path, approval)
            config = IntelligenceConfig(
                approval_path=path,
                approval_sha256=digest,
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


def _validate_schema(name: str, document: dict[str, object]) -> None:
    schema = json.loads(
        files("py_security_suite").joinpath("schemas", name).read_text("utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)
