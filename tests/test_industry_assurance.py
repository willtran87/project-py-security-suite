from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from jsonschema import Draft202012Validator

from py_security_suite.artifact_validation import (
    _validate_benchmark_scorecard_accounting,
    _validate_control_assessment_accounting,
    _validate_procedure_assessment_accounting,
    _validate_standards_crosswalk_accounting,
    validate_governed_artifacts,
)
from py_security_suite.industry_assurance import (
    _authorization_validated,
    _benchmark_gaps,
    _benchmark_reproducibility_gaps,
    _procedure_assessment,
    _safe_relative,
    _standardized_prioritization,
    _validated_cvss,
    _validate_policy,
    build_industry_assurance,
)
from py_security_suite.report_inspection import read_bundled_schema
from py_security_suite.reports import (
    _render_domain_assurance_summary,
    _render_llm_adversarial_summary,
)


class IndustryAssuranceTests(unittest.TestCase):
    @staticmethod
    def _policy() -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "enforce": True,
            "controls": [],
            "benchmarks": [],
            "benchmark_baseline_path": None,
        }

    def test_registers_standards_benchmarks_interop_and_oscal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifacts, errors = build_industry_assurance(
                Path(directory),
                {
                    "source-inventory.json": {"source_sha256": "a" * 64},
                    "risk-intelligence.json": {
                        "vex_formats": ["cyclonedx", "openvex", "csaf"],
                        "vex_versions": {
                            "cyclonedx": ["1.7"],
                            "openvex": ["0.2"],
                            "csaf": ["2.0"],
                        },
                    },
                    "sbom.cdx.json": {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.7",
                        "components": [],
                    },
                },
            )
        self.assertEqual(errors, [])
        self.assertEqual(
            artifacts["standards-crosswalk.json"]["catalogs_registered"], 39
        )
        self.assertEqual(
            artifacts["benchmark-registry.json"]["benchmarks_registered"], 9
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
        self.assertTrue(
            all(
                next(iter(document.values()))["metadata"]["oscal-version"] == "1.2.2"
                for name, document in artifacts.items()
                if name.startswith("oscal-")
            )
        )
        self.assertEqual(len(validate_governed_artifacts(artifacts)), 15)

    def test_procedures_cvss_ssvc_and_full_oscal_lifecycle_are_governed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "security").mkdir()
            policy = {
                "schema_version": "1.1",
                "enforce": True,
                "controls": [],
                "procedures": [
                    {
                        "standard": "OWASP-WSTG",
                        "procedure_id": "WSTG-ATHZ-03",
                        "objective": "Test privilege boundaries.",
                        "applicable": True,
                        "execution": "executed",
                        "test_type": "dynamic",
                        "authorization_required": True,
                        "evidence_artifacts": ["authorized-test.json"],
                    }
                ],
                "benchmarks": [],
                "benchmark_baseline_path": None,
            }
            (root / "security" / "industry-assurance-policy.json").write_text(
                json.dumps(policy), encoding="utf-8"
            )
            finding = SimpleNamespace(
                finding_id="PYSEC-1",
                severity="high",
                classifications=["CWE-862"],
                evidence={
                    "cvss": {
                        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                        "score": 9.3,
                    },
                    "ssvc": {
                        "exploitation": "active",
                        "automatable": "yes",
                        "technical_impact": "total",
                        "mission_prevalence": "essential",
                        "outcome": "immediate",
                    },
                },
            )
            artifacts, errors = build_industry_assurance(
                root,
                {
                    "source-inventory.json": {"source_sha256": "a" * 64},
                    "authorized-test.json": {
                        "complete": True,
                        "authorization_validated": True,
                    },
                },
                [finding],
            )
        self.assertEqual(errors, [])
        procedure = artifacts["procedure-assessment.json"]
        self.assertTrue(procedure["complete"])
        self.assertEqual(procedure["procedures"][0]["status"], "satisfied")
        prioritization = artifacts["standardized-prioritization.json"]
        self.assertEqual(prioritization["cvss_scored"], 1)
        self.assertEqual(prioritization["ssvc_decided"], 1)
        self.assertEqual(
            artifacts["industry-assurance.json"]["oscal_models_emitted"], 7
        )
        validate_governed_artifacts(artifacts)

    def test_procedure_and_prioritization_failure_paths_remain_explicit(self) -> None:
        def procedure(
            identifier: str,
            *,
            execution: str = "executed",
            applicable: bool = True,
            authorization_required: bool = False,
            evidence: list[str] | None = None,
        ) -> dict[str, object]:
            return {
                "standard": "OWASP-WSTG",
                "procedure_id": identifier,
                "objective": "Exercise a governed procedure branch.",
                "applicable": applicable,
                "execution": execution,
                "test_type": "dynamic",
                "authorization_required": authorization_required,
                "evidence_artifacts": ["missing.json"]
                if evidence is None
                else evidence,
            }

        policy = {
            "present": True,
            "enforce": True,
            "procedures": [
                procedure("planned", execution="planned"),
                procedure("missing"),
                procedure("empty", evidence=[]),
                procedure(
                    "authorization-gap",
                    authorization_required=True,
                    evidence=["complete.json"],
                ),
                procedure(
                    "nested-authorization",
                    authorization_required=True,
                    evidence=["nested-authorization.json"],
                ),
                procedure("not-applicable", applicable=False),
            ],
        }
        artifacts = {
            "complete.json": {"complete": True},
            "nested-authorization.json": {
                "complete": True,
                "evidence": {"execution_complete": True},
                "execution": {"authorization_validated": True},
            },
        }
        assessment = _procedure_assessment(policy, artifacts, [])
        self.assertEqual(
            [item["status"] for item in assessment["procedures"]],
            [
                "planned",
                "evidence-gap",
                "evidence-gap",
                "authorization-gap",
                "satisfied",
                "not-applicable",
            ],
        )
        self.assertFalse(assessment["complete"])
        self.assertFalse(_authorization_validated(None))
        self.assertTrue(_authorization_validated({"authorized": True}))
        self.assertEqual(
            _validated_cvss({"vector": "CVSS:3.1/AV:N", "score": 11})["status"],
            "invalid-source-evidence",
        )

        prioritized = _standardized_prioritization(
            [
                SimpleNamespace(
                    finding_id="PYSEC-ACTIVE",
                    severity="high",
                    classifications=[],
                    evidence={
                        "risk_intelligence": {"known_exploited": ["CVE"]},
                        "ssvc": {
                            "automatable": "yes",
                            "mission_prevalence": "essential",
                            "outcome": "immediate",
                        },
                    },
                ),
                SimpleNamespace(
                    finding_id="PYSEC-POC",
                    severity="medium",
                    classifications=[],
                    evidence={
                        "validation": {"status": "reproduced"},
                        "ssvc": {
                            "automatable": "no",
                            "technical_impact": "partial",
                            "mission_prevalence": "support",
                            "outcome": "scheduled",
                        },
                    },
                ),
            ]
        )
        self.assertEqual(prioritized["ssvc_decided"], 2)

        gaps = _benchmark_reproducibility_gaps(
            {
                "report": {},
                "confusion_matrix": {"true_positive": True},
                "corpus": {},
                "time_authority": {"validated": False},
                "replay_protected": False,
            }
        )
        self.assertEqual(len(gaps), 5)

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
                    "revision": "approved-1",
                    "authority": {"organization_approved": True},
                },
                "report": {"checksums_sha256": "c" * 64},
                "time_authority": {"validated": True},
                "confusion_matrix": {
                    "true_positive": 90,
                    "true_negative": 95,
                    "false_positive": 5,
                    "false_negative": 10,
                },
                "metrics": {
                    "precision": 0.9,
                    "recall": 0.9,
                    "specificity": 0.95,
                    "f1": 0.9,
                    "mcc": 0.85,
                    "balanced_accuracy": 0.925,
                    "false_positive_rate": 0.05,
                    "youden_j": 0.85,
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
        schema = json.loads(read_bundled_schema("industry-assurance-policy-1.1"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(instance)

    def test_policy_validation_rejects_every_unsafe_shape(self) -> None:
        valid_control = {
            "standard": "OWASP-ASVS",
            "control_id": "V1",
            "objective": "Verify controls.",
            "applicable": True,
            "evidence_artifacts": ["evidence.json"],
        }
        valid_benchmark = {
            "id": "pysec-governed-holdout",
            "enabled": True,
            "corpus_sha256": "b" * 64,
            "evidence_artifact": "score.json",
            "minimum_precision": 0.8,
            "minimum_recall": 0.8,
            "minimum_f1": 0.8,
            "maximum_false_positive_rate": 0.2,
        }
        invalid = [
            None,
            {**self._policy(), "controls": "invalid"},
            {**self._policy(), "controls": [{"standard": "OWASP-ASVS"}]},
            {
                **self._policy(),
                "controls": [{**valid_control, "control_id": ""}],
            },
            {**self._policy(), "benchmarks": [{"id": "owasp-benchmark"}]},
            {
                **self._policy(),
                "benchmarks": [{**valid_benchmark, "corpus_sha256": "bad"}],
            },
            {
                **self._policy(),
                "benchmarks": [{**valid_benchmark, "minimum_recall": -1}],
            },
            {**self._policy(), "benchmark_baseline_path": "../escape.json"},
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                _validate_policy(value)
        self.assertFalse(_safe_relative(None))
        self.assertFalse(_safe_relative("../escape.json"))

    def test_malformed_policy_and_invalid_summary_rows_fail_visible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "security").mkdir()
            (root / "security" / "industry-assurance-policy.json").write_text(
                "{", encoding="utf-8"
            )
            artifacts, errors = build_industry_assurance(root, {})
        self.assertEqual(
            errors, ["security/industry-assurance-policy.json: JSONDecodeError"]
        )
        self.assertFalse(artifacts["industry-assurance.json"]["complete"])
        self.assertIn(
            "Cross-domain assurance coverage",
            "\n".join(_render_domain_assurance_summary({"domains": [None]})),
        )
        self.assertEqual(
            _render_llm_adversarial_summary(
                {"campaign_status_counts": [], "evidence": {}}
            ),
            [],
        )

    def test_sealed_score_evidence_baseline_and_regressions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "security").mkdir()
            policy = self._policy()
            policy["enforce"] = False
            policy["benchmarks"] = [
                {
                    "id": "pysec-governed-holdout",
                    "enabled": True,
                    "corpus_sha256": "b" * 64,
                    "evidence_artifact": "score.json",
                    "minimum_precision": 0.8,
                    "minimum_recall": 0.8,
                    "minimum_f1": 0.8,
                    "maximum_false_positive_rate": 0.2,
                }
            ]
            evidence = {
                "verdict": "pass",
                "replay_protected": True,
                "corpus": {
                    "sha256": "b" * 64,
                    "revision": "approved-1",
                    "authority": {"organization_approved": True},
                },
                "report": {"checksums_sha256": "c" * 64},
                "time_authority": {"validated": True},
                "confusion_matrix": {
                    "true_positive": 90,
                    "true_negative": 90,
                    "false_positive": 10,
                    "false_negative": 10,
                },
                "metrics": {
                    "precision": 0.9,
                    "recall": 0.9,
                    "specificity": 0.9,
                    "f1": 0.9,
                    "mcc": 0.8,
                    "balanced_accuracy": 0.9,
                    "false_positive_rate": 0.1,
                    "youden_j": 0.8,
                },
            }
            (root / "score.json").write_text(json.dumps(evidence), encoding="utf-8")
            policy_path = root / "security" / "industry-assurance-policy.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            artifacts, errors = build_industry_assurance(
                root, {"source-inventory.json": {"source_sha256": "a" * 64}}
            )
            self.assertEqual(errors, [])
            row = artifacts["benchmark-scorecard.json"]["benchmarks"][0]
            self.assertEqual(row["evidence_source"], "sealed-snapshot")
            baseline = root / "baseline.json"
            baseline.write_text(
                json.dumps(artifacts["benchmark-scorecard.json"]), encoding="utf-8"
            )
            policy["benchmark_baseline_path"] = "baseline.json"
            evidence["metrics"]["recall"] = 0.7
            (root / "score.json").write_text(json.dumps(evidence), encoding="utf-8")
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            compared, errors = build_industry_assurance(
                root, {"source-inventory.json": {"source_sha256": "a" * 64}}
            )
            self.assertEqual(errors, [])
            self.assertTrue(compared["benchmark-delta.json"]["comparable"])
            self.assertIn("recall", compared["benchmark-delta.json"]["regressions"])
            self.assertIn(
                "recall does not meet",
                compared["benchmark-scorecard.json"]["benchmarks"][0]["gaps"][0],
            )

    def test_missing_invalid_evidence_baseline_and_control_gap_fail_visible(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "security").mkdir()
            policy = self._policy()
            policy["controls"] = [
                {
                    "standard": "OWASP-ASVS",
                    "control_id": "V1",
                    "objective": "Missing evidence must remain visible.",
                    "applicable": True,
                    "evidence_artifacts": ["missing.json"],
                }
            ]
            policy["benchmarks"] = [
                {
                    "id": "owasp-benchmark",
                    "enabled": True,
                    "corpus_sha256": "c" * 64,
                    "evidence_artifact": "missing-score.json",
                    "minimum_precision": 0.8,
                    "minimum_recall": 0.8,
                    "minimum_f1": 0.8,
                    "maximum_false_positive_rate": 0.2,
                }
            ]
            policy["benchmark_baseline_path"] = "bad-baseline.json"
            (root / "bad-baseline.json").write_text("{}", encoding="utf-8")
            (root / "security" / "industry-assurance-policy.json").write_text(
                json.dumps(policy), encoding="utf-8"
            )
            artifacts, errors = build_industry_assurance(
                root, {"source-inventory.json": {"source_sha256": "a" * 64}}
            )
            self.assertTrue(errors)
            self.assertFalse(artifacts["industry-assurance.json"]["complete"])
            self.assertEqual(
                artifacts["control-assessment.json"]["controls"][0]["status"],
                "gap",
            )
            self.assertEqual(
                artifacts["benchmark-scorecard.json"]["benchmarks"][0]["gaps"],
                ["benchmark evidence is missing"],
            )
            oscal_result = artifacts["oscal-assessment-results.json"][
                "assessment-results"
            ]["results"][0]
            self.assertEqual(len(oscal_result["findings"]), 1)
        self.assertEqual(
            _benchmark_gaps({}, False, {}, {}),
            [
                "benchmark evidence lacks approved corpus authority, replay protection, or digest binding"
            ],
        )

    def test_semantic_validators_reject_tampered_accounting(self) -> None:
        with self.assertRaises(TypeError):
            _validate_standards_crosswalk_accounting(None)
        with self.assertRaises(TypeError):
            _validate_standards_crosswalk_accounting({"catalogs": None, "mappings": []})
        with self.assertRaises(ValueError):
            _validate_standards_crosswalk_accounting(
                {"catalogs_registered": 2, "catalogs": [], "mappings": []}
            )
        with self.assertRaises(TypeError):
            _validate_control_assessment_accounting(None)
        with self.assertRaises(ValueError):
            _validate_control_assessment_accounting(
                {
                    "controls": [],
                    "controls_assessed": 1,
                    "applicable_controls": 0,
                    "controls_satisfied": 0,
                    "status_counts": {
                        "satisfied": 0,
                        "gap": 0,
                        "not-applicable": 0,
                    },
                    "parse_errors": [],
                    "enforced": False,
                    "complete": True,
                }
            )
        with self.assertRaises(TypeError):
            _validate_procedure_assessment_accounting(None)
        with self.assertRaises(ValueError):
            _validate_procedure_assessment_accounting(
                {
                    "procedures": [],
                    "procedures_assessed": 1,
                    "applicable_procedures": 0,
                    "procedures_satisfied": 0,
                    "status_counts": {
                        "satisfied": 0,
                        "planned": 0,
                        "evidence-gap": 0,
                        "authorization-gap": 0,
                        "not-applicable": 0,
                    },
                    "parse_errors": [],
                    "enforced": False,
                    "complete": True,
                }
            )
        with self.assertRaises(TypeError):
            _validate_benchmark_scorecard_accounting(None)
        with self.assertRaises(ValueError):
            _validate_benchmark_scorecard_accounting(
                {
                    "benchmarks": [],
                    "benchmark_scope": [],
                    "benchmarks_enabled": 1,
                    "benchmarks_executed": 0,
                    "benchmarks_passed": 0,
                    "complete": True,
                    "passed": False,
                }
            )


if __name__ == "__main__":
    unittest.main()
