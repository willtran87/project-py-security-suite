from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from py_security_suite.artifact_validation import validate_governed_artifacts
from py_security_suite.industry_assurance import build_industry_assurance
from py_security_suite.report_inspection import read_bundled_schema


class IndustryAssuranceTests(unittest.TestCase):
    def test_registers_standards_benchmarks_interop_and_oscal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifacts, errors = build_industry_assurance(
                Path(directory),
                {
                    "source-inventory.json": {"source_sha256": "a" * 64},
                    "risk-intelligence.json": {
                        "vex_formats": ["cyclonedx", "openvex", "csaf"]
                    },
                    "sbom.cdx.json": {},
                },
            )
        self.assertEqual(errors, [])
        self.assertEqual(
            artifacts["standards-crosswalk.json"]["catalogs_registered"], 19
        )
        self.assertEqual(
            artifacts["benchmark-registry.json"]["benchmarks_registered"], 8
        )
        supported = {
            item["format"]
            for item in artifacts["industry-assurance.json"]["interoperability"]
            if item["status"] == "supported"
        }
        self.assertTrue(
            {"CycloneDX", "CycloneDX-VEX", "OpenVEX", "CSAF-VEX", "OSCAL"} <= supported
        )
        self.assertIn("assessment-results", artifacts["oscal-assessment-results.json"])
        self.assertEqual(len(validate_governed_artifacts(artifacts)), 7)

    def test_policy_drives_controls_and_governed_benchmark_thresholds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "security").mkdir()
            policy = {
                "schema_version": "1.0",
                "enforce": True,
                "controls": [
                    {
                        "standard": "OWASP-ASVS",
                        "control_id": "V1",
                        "objective": "Retain verification evidence.",
                        "applicable": True,
                        "evidence_artifacts": ["security-requirements-coverage.json"],
                    }
                ],
                "benchmarks": [
                    {
                        "id": "pysec-governed-holdout",
                        "enabled": True,
                        "corpus_sha256": "b" * 64,
                        "evidence_artifact": "holdout-score.json",
                        "minimum_precision": 0.8,
                        "minimum_recall": 0.8,
                        "minimum_f1": 0.8,
                        "maximum_false_positive_rate": 0.2,
                    }
                ],
                "benchmark_baseline_path": None,
            }
            (root / "security" / "industry-assurance-policy.json").write_text(
                json.dumps(policy), encoding="utf-8"
            )
            evidence = {
                "verdict": "pass",
                "replay_protected": True,
                "corpus": {
                    "sha256": "b" * 64,
                    "authority": {"organization_approved": True},
                },
                "metrics": {
                    "precision": 0.9,
                    "recall": 0.9,
                    "specificity": 0.95,
                    "f1": 0.9,
                    "mcc": 0.85,
                    "balanced_accuracy": 0.925,
                    "false_positive_rate": 0.05,
                },
            }
            artifacts, errors = build_industry_assurance(
                root,
                {
                    "source-inventory.json": {"source_sha256": "a" * 64},
                    "security-requirements-coverage.json": {"complete": True},
                    "holdout-score.json": evidence,
                },
            )
        self.assertEqual(errors, [])
        self.assertTrue(artifacts["control-assessment.json"]["complete"])
        self.assertTrue(artifacts["benchmark-scorecard.json"]["passed"])
        validate_governed_artifacts(artifacts)

    def test_example_policy_matches_bundled_schema(self) -> None:
        root = Path(__file__).resolve().parents[1]
        instance = json.loads(
            (root / "examples" / "industry-assurance-policy.example.json").read_text(
                encoding="utf-8"
            )
        )
        schema = json.loads(read_bundled_schema("industry-assurance-policy-1.0"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(instance)


if __name__ == "__main__":
    unittest.main()
