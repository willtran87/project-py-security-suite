from __future__ import annotations

import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

# The isolated Pylint lane intentionally omits locked test-only dependencies.
from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.release_readiness import assess_release_readiness


class ReleaseReadinessTests(unittest.TestCase):
    @patch("py_security_suite.release_readiness.verify_report")
    def test_complete_governed_evidence_is_approved(self, verify_report_mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_release_evidence(report)
            verify_report_mock.return_value = _verification()
            result = assess_release_readiness(report)

        self.assertEqual(result["decision"], "approved")
        self.assertEqual(result["blockers"], [])
        _validate_schema(result)

    @patch("py_security_suite.release_readiness.verify_report")
    def test_policy_trust_isolation_and_approval_gaps_are_explicit(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_release_evidence(
                report,
                outcome="incomplete",
                trusted=False,
                isolated=False,
                intelligence_approved=False,
            )
            verify_report_mock.return_value = _verification()
            result = assess_release_readiness(
                report,
                minimum_effectiveness_labels=25,
                require_passport=True,
            )

        self.assertEqual(result["decision"], "not_approved")
        self.assertEqual(
            set(result["blockers"]),
            {
                "scan-policy",
                "external-isolation",
                "scanner-trust",
                "intelligence-approval",
                "detection-effectiveness",
                "signed-release-passport",
            },
        )
        _validate_schema(result)

    @patch("py_security_suite.release_readiness.verify_report")
    def test_release_profile_requires_an_authentic_passport(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_release_evidence(report, profile="release")
            verify_report_mock.return_value = _verification()
            result = assess_release_readiness(report)

        self.assertIn("signed-release-passport", result["blockers"])

    @patch("py_security_suite.release_readiness.verify_report")
    def test_digest_bound_optional_controls_must_pass_and_bind_to_report(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            report.mkdir()
            _write_release_evidence(report)
            evaluation = root / "evaluation.json"
            passport = root / "passport.json"
            evaluation_digest = _write_json(
                evaluation,
                {
                    "schema_version": "1.0",
                    "verdict": "pass",
                    "report": {"checksums_sha256": "f" * 64},
                    "corpus": {"labels": 25},
                },
            )
            passport_digest = _write_json(
                passport,
                {
                    "release_decision": "approved",
                    "authentic": True,
                    "report": {"checksums_sha256": "f" * 64},
                },
            )
            verify_report_mock.return_value = _verification()
            result = assess_release_readiness(
                report,
                effectiveness_evaluation=evaluation,
                effectiveness_sha256=evaluation_digest,
                minimum_effectiveness_labels=25,
                passport_verification=passport,
                passport_verification_sha256=passport_digest,
                require_passport=True,
            )

        self.assertEqual(result["decision"], "approved")
        self.assertIn("detection-effectiveness", _control_ids(result))
        self.assertIn("signed-release-passport", _control_ids(result))

    @patch("py_security_suite.release_readiness.verify_report")
    def test_passport_must_be_explicitly_bound_to_the_report(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            report.mkdir()
            _write_release_evidence(report)
            passport = root / "passport.json"
            passport_digest = _write_json(
                passport,
                {"release_decision": "approved", "authentic": True},
            )
            verify_report_mock.return_value = _verification()
            result = assess_release_readiness(
                report,
                passport_verification=passport,
                passport_verification_sha256=passport_digest,
                require_passport=True,
            )

        self.assertIn("signed-release-passport", result["blockers"])

    @patch("py_security_suite.release_readiness.verify_report")
    def test_applicable_scanner_without_an_identity_is_untrusted(
        self, verify_report_mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory)
            _write_release_evidence(report)
            manifest_path = report / "scan-manifest.json"
            manifest = json.loads(manifest_path.read_text("utf-8"))
            manifest["tools"][0].pop("executable_sha256")
            _write_json(manifest_path, manifest)
            verify_report_mock.return_value = _verification()
            result = assess_release_readiness(report)

        self.assertIn("scanner-trust", result["blockers"])

    def test_optional_evidence_requires_path_and_digest_together(self) -> None:
        with self.assertRaisesRegex(ValueError, "supplied together"):
            assess_release_readiness(
                Path("report"),
                effectiveness_evaluation=Path("evaluation.json"),
            )


def _verification() -> dict[str, object]:
    return {
        "verified": True,
        "scan_id": "scan-release",
        "checksums_sha256": "f" * 64,
        "file_count": 12,
        "outcome": "pass",
    }


def _write_release_evidence(
    root: Path,
    *,
    outcome: str = "pass",
    trusted: bool = True,
    isolated: bool = True,
    intelligence_approved: bool = True,
    profile: str = "production",
) -> None:
    documents: dict[str, dict[str, object]] = {
        "scan-manifest.json": {
            "outcome": outcome,
            "profile": profile,
            "network_isolation_attested": isolated,
            "tools": [
                {
                    "tool": "bandit",
                    "applicable": True,
                    "executable_sha256": "a" * 64,
                    "executable_integrity_verified": trusted,
                    "executable_unchanged": trusted,
                }
            ],
        },
        "findings.json": {"findings": []},
        "assurance-claims.json": {
            "claims": [{"control": "static-analysis", "result": "satisfied"}]
        },
        "portfolio-health.json": {"overall": {"domains_with_execution_gaps": 0}},
        "isolation-attestation.json": {
            "validated": isolated,
            "organization_approved": isolated,
        },
        "risk-intelligence.json": {"configured": True},
        "intelligence-approval.json": {
            "validated": intelligence_approved,
            "organization_approved": intelligence_approved,
        },
    }
    for name, document in documents.items():
        _write_json(root / name, document)


def _validate_schema(document: dict[str, object]) -> None:
    schema = json.loads(
        files("py_security_suite")
        .joinpath("schemas", "release-readiness.schema.json")
        .read_text("utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)


def _write_json(path: Path, document: dict[str, object]) -> str:
    import hashlib

    payload = json.dumps(document, sort_keys=True).encode()
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _control_ids(document: dict[str, object]) -> set[str]:
    controls = document["controls"]
    if not isinstance(controls, list):
        raise TypeError("controls must be a list")
    return {
        str(control["id"])
        for control in controls
        if isinstance(control, dict) and "id" in control
    }
