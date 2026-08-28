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
    _ASSURANCE_PROFILES,
    _BENCHMARKS,
    _STANDARDS,
    _authorization_validated,
    _benchmark_gaps,
    _benchmark_protocol,
    _benchmark_reproducibility_gaps,
    _benchmark_runner_contract,
    _protocol_metrics_valid,
    _process_capability_assessment,
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
            artifacts["standards-crosswalk.json"]["catalogs_registered"], 292
        )
        self.assertEqual(
            artifacts["benchmark-registry.json"]["benchmarks_registered"], 99
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
        self.assertEqual(len(validate_governed_artifacts(artifacts)), 23)
        profiles = artifacts["assurance-profile-registry.json"]
        self.assertEqual(profiles["profiles_available"], 80)
        self.assertEqual(profiles["profiles_selected"], 0)
        lifecycle = artifacts["standards-crosswalk.json"]["lifecycle_governance"]
        self.assertEqual(lifecycle["catalogs_assessed"], 292)
        self.assertEqual(lifecycle["catalogs_complete"], 0)
        self.assertFalse(lifecycle["complete"])
        self.assertTrue(lifecycle["signed_source_snapshot_required"])
        self.assertTrue(lifecycle["promotion_requires_human_approval"])
        self.assertTrue(
            {
                "NIST-SP-800-228",
                "NIST-SP-800-204C",
                "NIST-SP-800-233",
                "IETF-RFC-9943",
                "OWASP-AGENTIC-TOP-10",
                "ISO-IEC-TS-42119-2",
                "IETF-RFC-9116",
                "OPENSSF-S2C2F",
                "OPENTELEMETRY-SEMCONV",
                "NCSC-CAF",
                "ASD-ESSENTIAL-EIGHT",
                "ISO-24089",
                "IEC-62351",
                "SEI-ATAM",
                "CISA-SBOM-MINIMUM-ELEMENTS",
                "NIST-SP-800-172",
                "NIST-SP-800-172A",
                "NIST-SP-800-53B",
                "NISTIR-8397",
                "NIST-SP-800-227",
                "NIST-CSWP-39",
                "NIST-SP-800-137A",
                "ISO-IEC-27031",
                "ISO-IEC-27037",
                "W3C-WCAG",
                "NIST-SP-800-18",
                "NIST-SP-800-92",
                "ISO-IEC-27014",
                "ISO-IEC-27032",
                "ISO-IEC-27033-1",
                "ISO-IEC-27040",
                "NIST-SP-800-188",
                "ISO-IEC-27555",
                "ISO-IEC-27559",
                "W3C-ACT-RULES-FORMAT",
                "NIST-SP-800-232",
                "NIST-SP-800-231",
                "ISO-IEC-27400",
                "ISO-IEC-27402",
                "ISO-IEC-27403",
                "ISO-IEC-27404",
                "TIBER-EU",
                "ISO-IEC-27050-1",
                "ISO-IEC-27050-3",
            }
            <= {item["id"] for item in _STANDARDS}
        )
        self.assertTrue(
            {
                "cloud-native-api-assurance",
                "supply-chain-transparency-consumer",
                "ai-agentic-testing",
                "runtime-contract-interoperability",
                "uk-cyber-resilience",
                "australian-essential-eight",
                "automotive-software-update",
                "energy-product-security",
                "modern-sbom-assurance",
                "enhanced-cui-assurance",
                "developer-verification-minimums",
                "cryptographic-key-agility",
                "continuous-security-monitoring",
                "ict-continuity-readiness",
                "digital-forensics-readiness",
                "accessibility-quality",
            }
            <= set(_ASSURANCE_PROFILES)
        )
        self.assertTrue(
            {
                "scitt-transparency-conformance",
                "cloud-native-api-service-mesh-conformance",
                "api-contract-spec-conformance",
                "opentelemetry-semantic-conformance",
                "ai-agentic-testing-conformance",
                "multicloud-kubernetes-attack-paths",
                "cisa-sbom-minimum-elements-conformance",
                "enhanced-cui-oscal-conformance",
                "nist-developer-verification-conformance",
                "crypto-lifecycle-agility-conformance",
                "iscm-program-assessment",
                "ict-continuity-recovery-exercise",
                "digital-forensics-chain-of-custody",
                "wcag-accessibility-conformance",
                "nist-cfreds-cftt",
                "w3c-act-rules-conformance",
                "droidbench",
                "ghera-android-security",
                "secbench-js",
                "cloud-native-chaos-resilience",
                "kubernetes-sonobuoy-conformance",
                "cis-cat-scap-platform-conformance",
                "c2sp-wycheproof",
                "tiber-eu-threat-led-red-team",
            }
            <= {item["id"] for item in _BENCHMARKS}
        )

    def test_extended_interoperability_requires_complete_protocol_evidence(
        self,
    ) -> None:
        digest = "a" * 64
        profiles = (
            "security-data-interoperability",
            "security-automation-interoperability",
            "supply-chain-transparency-consumer",
            "runtime-contract-interoperability",
        )
        protocol_versions = {
            "OASIS-STIX": "2.1",
            "OASIS-TAXII": "2.1",
            "OASIS-CACAO": "2.0",
            "OASIS-OPENC2": "1.0",
            "OCSF": "policy-pinned",
            "IETF-RFC-9943": "RFC-9943",
            "IETF-RFC-9942": "RFC-9942",
            "OPENAPI-SPECIFICATION": "3.1.1-policy-pinned",
            "ASYNCAPI-SPECIFICATION": "3.0.0-policy-pinned",
            "GRAPHQL-SPECIFICATION": "september-2025",
            "JSON-SCHEMA": "2020-12",
            "OPENTELEMETRY-SEMCONV": "1.44.0-policy-pinned",
        }
        protocols = [
            {
                "id": identifier,
                "version": version,
                "schema_sha256": digest,
                "fixtures_sha256": digest,
                "report_sha256": digest,
                "positive_cases": 10,
                "negative_cases": 10,
                "round_trip_validated": True,
                "semantic_equivalence_validated": True,
                "replay_protected": True,
                "authority": {"organization_approved": True},
            }
            for identifier, version in protocol_versions.items()
        ]
        policy = {
            "schema_version": "1.2",
            "enforce": False,
            "profiles": [
                {"id": identifier, "applicable": True, "procedure_execution": "planned"}
                for identifier in profiles
            ],
            "controls": [],
            "procedures": [],
            "benchmarks": [],
            "benchmark_baseline_path": None,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "security").mkdir()
            (root / "security" / "industry-assurance-policy.json").write_text(
                json.dumps(policy), encoding="utf-8"
            )
            artifacts, errors = build_industry_assurance(
                root, {"security-automation-evidence.json": {"protocols": protocols}}
            )
        self.assertEqual(errors, [])
        conformance = artifacts["security-automation-interoperability.json"]
        self.assertTrue(conformance["complete"])
        self.assertEqual(conformance["protocols_complete"], 12)
        interoperability = {
            item["format"]: item
            for item in artifacts["industry-assurance.json"]["interoperability"]
        }
        for format_name in (
            "STIX",
            "TAXII",
            "CACAO",
            "OpenC2",
            "OCSF",
            "SCITT",
            "COSE-Receipts",
            "OpenAPI",
            "AsyncAPI",
            "GraphQL",
            "JSON-Schema",
            "OpenTelemetry-SemConv",
        ):
            self.assertEqual(interoperability[format_name]["status"], "supported")
        protocols[0]["semantic_equivalence_validated"] = False
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "security").mkdir()
            (root / "security" / "industry-assurance-policy.json").write_text(
                json.dumps(policy), encoding="utf-8"
            )
            incomplete, errors = build_industry_assurance(
                root, {"security-automation-evidence.json": {"protocols": protocols}}
            )
        self.assertEqual(errors, [])
        stix = next(
            item
            for item in incomplete["industry-assurance.json"]["interoperability"]
            if item["format"] == "STIX"
        )
        self.assertEqual(stix["status"], "not-observed")

    def test_standards_lifecycle_requires_signed_snapshots_and_human_approval(
        self,
    ) -> None:
        digest = "a" * 64
        records = [
            {
                "id": standard["id"],
                "edition_status": standard.get("lifecycle", {}).get(
                    "edition_status", "policy-pinned"
                ),
                "published": standard.get("lifecycle", {}).get(
                    "published", "policy-pinned"
                ),
                "observed_at": "2026-08-28T12:00:00Z",
                "source_sha256": digest,
                "source_reference": standard["reference"],
                "signature_sha256": digest,
                "signature_validated": True,
                "signer_identity": "publisher-signing-identity",
                "publisher_identity_validated": True,
                "change_report_sha256": digest,
                "human_approved": True,
                "approved_by": "standards-governance-board",
                "approved_at": "2026-08-28T13:00:00Z",
            }
            for standard in _STANDARDS
        ]
        with tempfile.TemporaryDirectory() as directory:
            artifacts, errors = build_industry_assurance(
                Path(directory),
                {"standards-lifecycle-evidence.json": {"records": records}},
            )
        self.assertEqual(errors, [])
        lifecycle = artifacts["standards-crosswalk.json"]["lifecycle_governance"]
        self.assertTrue(lifecycle["complete"])
        self.assertEqual(lifecycle["catalogs_complete"], len(_STANDARDS))
        validate_governed_artifacts(artifacts)
        with tempfile.TemporaryDirectory() as directory:
            duplicate, errors = build_industry_assurance(
                Path(directory),
                {
                    "standards-lifecycle-evidence.json": {
                        "records": [*records, dict(records[0])]
                    }
                },
            )
        self.assertEqual(errors, [])
        duplicate_lifecycle = duplicate["standards-crosswalk.json"][
            "lifecycle_governance"
        ]
        self.assertFalse(duplicate_lifecycle["complete"])
        self.assertEqual(
            duplicate_lifecycle["input_gaps"],
            [f"duplicate lifecycle record: {records[0]['id']}"],
        )

    def test_foundational_assurance_is_governed_and_fails_closed(self) -> None:
        calibration = {
            "samples": 250,
            "corpus_sha256": "1" * 64,
            "outcomes_sha256": "2" * 64,
            "snapshots": {"epss_sha256": "3" * 64, "kev_sha256": "4" * 64},
            "point_in_time": True,
            "future_data_excluded": True,
            "replay_protected": True,
            "authority": {"organization_approved": True},
            "metrics": {
                "brier_score": 0.08,
                "expected_calibration_error": 0.05,
                "recall_at_budget": 0.86,
                "effort": 0.3,
                "kev_time_to_prioritize_hours": 2.5,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            artifacts, errors = build_industry_assurance(
                Path(directory),
                {
                    "source-inventory.json": {
                        "complete": True,
                        "source_sha256": "a" * 64,
                    },
                    "prioritization-calibration-evidence.json": calibration,
                },
            )
            invalid_artifacts, invalid_errors = build_industry_assurance(
                Path(directory),
                {
                    "source-inventory.json": {"source_sha256": "a" * 64},
                    "prioritization-calibration-evidence.json": {
                        "samples": True,
                        "snapshots": [],
                        "metrics": {"kev_time_to_prioritize_hours": -1},
                        "authority": {},
                    },
                },
            )
        self.assertEqual(errors, [])
        self.assertEqual(invalid_errors, [])
        industry = artifacts["industry-assurance.json"]
        self.assertEqual(
            set(industry["foundational_assurance"]),
            {
                "lifecycle-traceability.json",
                "architecture-evaluation.json",
                "process-capability-assessment.json",
                "prioritization-calibration.json",
                "maturity-model-assessment.json",
                "security-automation-interoperability.json",
                "external-conformity-assessment.json",
            },
        )
        self.assertTrue(artifacts["prioritization-calibration.json"]["complete"])
        self.assertFalse(artifacts["lifecycle-traceability.json"]["complete"])
        self.assertFalse(artifacts["architecture-evaluation.json"]["complete"])
        self.assertFalse(artifacts["process-capability-assessment.json"]["complete"])
        self.assertIn(
            "bidirectional requirements evidence is incomplete",
            artifacts["lifecycle-traceability.json"]["gaps"],
        )
        invalid_calibration = invalid_artifacts["prioritization-calibration.json"]
        self.assertFalse(invalid_calibration["complete"])
        self.assertEqual(invalid_calibration["samples"], 0)
        self.assertTrue(
            {
                "corpus_sha256 is missing or invalid",
                "snapshot epss_sha256 is missing or invalid",
                "point-in-time evaluation is not proven",
                "future-data exclusion is not proven",
                "replay protection is missing",
                "organization-approved outcome authority is missing",
                "fewer than 100 temporal observations were evaluated",
                "metric brier_score is missing or invalid",
                "metric kev_time_to_prioritize_hours is missing or invalid",
            }
            <= set(invalid_calibration["gaps"])
        )
        capability = _process_capability_assessment(
            {
                name: {"complete": True}
                for name in (
                    "security-requirements-coverage.json",
                    "lifecycle-traceability.json",
                    "code-health.json",
                    "static-architecture.json",
                    "test-evidence.json",
                    "effectiveness.json",
                    "release-readiness.json",
                    "security-passport.json",
                    "risk-intelligence.json",
                    "closure-plan.json",
                    "operational-trend.json",
                    "procedure-assessment.json",
                    "capability-manifest.json",
                )
            }
        )
        self.assertEqual(capability["dimensions"][0]["capability_level"], 2)
        self.assertIn(
            "independent audit-package verification is missing",
            capability["dimensions"][0]["gaps"],
        )
        validate_governed_artifacts(artifacts)
        validate_governed_artifacts(invalid_artifacts)

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

        governed = {
            "id": "agentic-security-holdout",
            "version": "organization-pinned",
            "lane": "authorized-companion",
        }
        governed["runner_contract"] = _benchmark_runner_contract(governed)
        base_evidence = {
            "report": {"checksums_sha256": "a" * 64},
            "protocol_metrics": {
                "repetitions": 5,
                "attack_success_rate": 0.1,
                "utility_retention": 0.9,
                "variance": 0.02,
            },
            "acceptance": {
                "criteria_sha256": "9" * 64,
                "met": True,
                "authority": {"organization_approved": True},
            },
            "confusion_matrix": {
                "true_positive": 1,
                "true_negative": 1,
                "false_positive": 0,
                "false_negative": 0,
            },
            "corpus": {"revision": "approved"},
            "time_authority": {"validated": True},
            "replay_protected": True,
        }
        self.assertIn(
            "qualified benchmark execution context is missing",
            _benchmark_reproducibility_gaps(base_evidence, governed),
        )
        unsafe_context_gaps = _benchmark_reproducibility_gaps(
            {
                **base_evidence,
                "execution_context": {
                    "runner_identity": "",
                    "runner_version": "",
                    "target_sha256": "bad",
                    "environment_sha256": "bad",
                    "toolset_sha256": "bad",
                    "oracle_sha256": "bad",
                    "isolation_receipt_sha256": "bad",
                    "dataset_license_sha256": "bad",
                    "label_authority_sha256": "bad",
                    "contamination_manifest_sha256": "bad",
                    "isolation_validated": False,
                    "positive_controls": 0,
                    "negative_controls": False,
                    "split_strategy": "random",
                    "independent_reviewers": 1,
                    "repetitions": 1,
                },
            },
            governed,
        )
        self.assertIn(
            "benchmark execution target_sha256 is missing or invalid",
            unsafe_context_gaps,
        )
        self.assertIn(
            "benchmark runner identity or version is missing", unsafe_context_gaps
        )
        self.assertIn(
            "benchmark execution isolation is not validated", unsafe_context_gaps
        )
        self.assertIn(
            "benchmark execution runner_oci_image_sha256 is missing or invalid",
            unsafe_context_gaps,
        )
        self.assertIn(
            "benchmark network isolation is not validated", unsafe_context_gaps
        )
        self.assertIn(
            "benchmark target cleanup and destruction is not proven",
            unsafe_context_gaps,
        )
        self.assertIn(
            "benchmark runner provenance verification is not proven",
            unsafe_context_gaps,
        )
        self.assertIn("benchmark positive_controls are missing", unsafe_context_gaps)
        self.assertIn("benchmark negative_controls are missing", unsafe_context_gaps)
        self.assertIn(
            "benchmark split strategy is missing or invalid", unsafe_context_gaps
        )
        self.assertIn(
            "benchmark requires at least two independent reviewers",
            unsafe_context_gaps,
        )
        execution_context = {
            "runner_identity": "approved-agentic-runner",
            "runner_version": "1.0",
            "target_sha256": "b" * 64,
            "environment_sha256": "c" * 64,
            "toolset_sha256": "d" * 64,
            "oracle_sha256": "e" * 64,
            "isolation_receipt_sha256": "f" * 64,
            "runner_oci_image_sha256": "4" * 64,
            "runner_sbom_sha256": "5" * 64,
            "runner_provenance_sha256": "6" * 64,
            "resource_limits_sha256": "7" * 64,
            "network_policy_sha256": "8" * 64,
            "egress_transcript_sha256": "9" * 64,
            "cleanup_receipt_sha256": "a" * 64,
            "dataset_license_sha256": "1" * 64,
            "label_authority_sha256": "2" * 64,
            "contamination_manifest_sha256": "3" * 64,
            "isolation_validated": True,
            "network_isolation_validated": True,
            "target_destroyed": True,
            "runner_image_pinned": True,
            "runner_sbom_matches_image": True,
            "runner_provenance_verified": True,
            "provenance_subject_matches_image": True,
            "resource_limits_enforced": True,
            "network_policy_enforced": True,
            "egress_transcript_complete": True,
            "cleanup_validated": True,
            "positive_controls": 10,
            "negative_controls": 10,
            "split_strategy": "time-split",
            "independent_reviewers": 2,
            "repetitions": 5,
        }
        self.assertEqual(
            _benchmark_reproducibility_gaps(
                {**base_evidence, "execution_context": execution_context}, governed
            ),
            [],
        )
        hardened_contract = governed["runner_contract"]["required_execution_evidence"]
        self.assertTrue(
            {
                "runner-oci-image-digest",
                "runner-sbom-digest",
                "runner-provenance-digest",
                "runner-image-sbom-provenance-subject-binding",
                "resource-limit-receipt",
                "resource-limit-enforcement",
                "network-policy-digest",
                "egress-transcript-digest",
                "target-cleanup-destruction-receipt",
            }
            <= set(hardened_contract)
        )
        official = {
            "id": "nist-acvp-cryptography",
            "version": "policy-pinned",
            "lane": "authorized-companion",
        }
        official["runner_contract"] = _benchmark_runner_contract(official)
        self.assertIn(
            "qualified benchmark execution context is missing",
            _benchmark_reproducibility_gaps(base_evidence, official),
        )
        scale = {
            "id": "scanner-scale-determinism",
            "version": "organization-pinned",
            "lane": "authorized-companion",
        }
        scale["runner_contract"] = _benchmark_runner_contract(scale)
        scale_gaps = _benchmark_reproducibility_gaps(
            {**base_evidence, "execution_context": execution_context}, scale
        )
        self.assertIn("benchmark wall_time_ms measurement is missing", scale_gaps)
        self.assertIn("benchmark peak_memory_bytes measurement is missing", scale_gaps)
        self.assertIn(
            "benchmark requires at least three deterministic runs", scale_gaps
        )
        scale_context = {
            **execution_context,
            "wall_time_ms": 1,
            "peak_memory_bytes": 1,
            "deterministic_runs": 3,
        }
        self.assertEqual(
            _benchmark_reproducibility_gaps(
                {**base_evidence, "execution_context": scale_context}, scale
            ),
            [],
        )
        qualified = {
            "id": "disa-stig-scap-conformance",
            "version": "policy-pinned-quarterly-release",
            "lane": "authorized-companion",
        }
        qualified["runner_contract"] = _benchmark_runner_contract(qualified)
        self.assertEqual(
            qualified["runner_contract"]["required_execution_evidence"][-4:],
            [
                "method-validation-digest",
                "evaluator-competency-digest",
                "impartiality-review-digest",
                "measurement-traceability-digest",
            ],
        )
        qualification_gaps = _benchmark_reproducibility_gaps(
            {**base_evidence, "execution_context": execution_context}, qualified
        )
        self.assertEqual(
            [gap for gap in qualification_gaps if "laboratory qualification" in gap],
            [
                "laboratory qualification method_validation_sha256 is missing or invalid",
                "laboratory qualification evaluator_competency_sha256 is missing or invalid",
                "laboratory qualification impartiality_review_sha256 is missing or invalid",
                "laboratory qualification measurement_traceability_sha256 is missing or invalid",
            ],
        )
        qualified_context = {
            **execution_context,
            "method_validation_sha256": "4" * 64,
            "evaluator_competency_sha256": "5" * 64,
            "impartiality_review_sha256": "6" * 64,
            "measurement_traceability_sha256": "7" * 64,
        }
        conformance_evidence = {
            **base_evidence,
            "protocol_metrics": {
                "passed_cases": 10,
                "failed_cases": 0,
                "negative_cases": 5,
                "conformance_rate": 1.0,
            },
        }
        self.assertEqual(
            _benchmark_reproducibility_gaps(
                {**conformance_evidence, "execution_context": qualified_context},
                qualified,
            ),
            [],
        )
        self.assertEqual(
            _benchmark_runner_contract(
                {
                    "id": "agentdojo",
                    "version": "policy-pinned",
                    "lane": "authorized-companion",
                }
            )["minimum_repetitions"],
            5,
        )
        self.assertEqual(
            _benchmark_runner_contract(
                {
                    "id": "oss-fuzz-clusterfuzzlite",
                    "version": "policy-pinned",
                    "lane": "authorized-companion",
                }
            )["minimum_repetitions"],
            3,
        )

        temporal = {
            "id": "epss-kev-temporal-backtest",
            "version": "policy-pinned",
            "lane": "authorized-companion",
        }
        temporal["runner_contract"] = _benchmark_runner_contract(temporal)
        self.assertIn(
            "point-in-time-snapshot-digests",
            temporal["runner_contract"]["required_execution_evidence"],
        )
        temporal_context = {
            **execution_context,
            "epss_snapshot_sha256": "4" * 64,
            "kev_snapshot_sha256": "5" * 64,
            "outcome_authority_sha256": "6" * 64,
            "point_in_time": True,
            "future_data_excluded": True,
            "brier_score": 0.1,
            "expected_calibration_error": 0.05,
            "recall_at_budget": 0.85,
            "effort": 0.25,
        }
        self.assertEqual(
            _benchmark_reproducibility_gaps(
                {
                    **base_evidence,
                    "protocol_metrics": {
                        "brier_score": 0.1,
                        "expected_calibration_error": 0.05,
                        "recall_at_budget": 0.85,
                        "effort": 0.25,
                        "observations": 100,
                    },
                    "execution_context": temporal_context,
                },
                temporal,
            ),
            [],
        )

        contract_expectations = {
            "sv-comp": "competition-task-definition-digest",
            "test-comp": "validated-witness-or-test-suite-digest",
            "sigstore-client-conformance": "trust-root-digest",
            "slsa-verifier-conformance": "negative-verification-cases",
            "architecture-evaluation-scenarios": "inter-rater-agreement",
            "process-capability-assessor-agreement": "blinded-assessor-labels",
            "cwe-mapping-conformance": "cwe-release-digest",
        }
        for identifier, expected in contract_expectations.items():
            with self.subTest(identifier=identifier):
                contract = _benchmark_runner_contract(
                    {
                        "id": identifier,
                        "version": "policy-pinned",
                        "lane": "authorized-companion",
                    }
                )
                self.assertIn(expected, contract["required_execution_evidence"])

        gap_expectations = {
            "epss-kev-temporal-backtest": "temporal benchmark point-in-time execution is not proven",
            "sv-comp": "competition benchmark task_definition_sha256 is missing or invalid",
            "sigstore-client-conformance": "signing conformance negative cases are missing",
            "architecture-evaluation-scenarios": "independent assessor agreement is missing or below 0.8",
            "cwe-mapping-conformance": "CWE mapping cwe_release_sha256 is missing or invalid",
        }
        for identifier, expected_gap in gap_expectations.items():
            with self.subTest(identifier=identifier, expected_gap=expected_gap):
                benchmark = {
                    "id": identifier,
                    "version": "policy-pinned",
                    "lane": "authorized-companion",
                }
                benchmark["runner_contract"] = _benchmark_runner_contract(benchmark)
                observed_gaps = _benchmark_reproducibility_gaps(
                    {**base_evidence, "execution_context": execution_context},
                    benchmark,
                )
                self.assertIn(expected_gap, observed_gaps)

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
        schema = json.loads(read_bundled_schema("industry-assurance-policy-1.2"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(instance)
        self.assertEqual(
            {profile["id"] for profile in instance["profiles"]},
            set(_ASSURANCE_PROFILES),
        )
        self.assertEqual(
            {benchmark["id"] for benchmark in instance["benchmarks"]},
            {benchmark["id"] for benchmark in _BENCHMARKS},
        )

    def test_policy_profiles_expand_into_fail_closed_controls_and_procedures(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "security").mkdir()
            policy = {
                "schema_version": "1.2",
                "enforce": True,
                "profiles": [
                    {
                        "id": "enterprise-security",
                        "applicable": True,
                        "procedure_execution": "planned",
                    },
                    {
                        "id": "privacy",
                        "applicable": False,
                        "procedure_execution": "planned",
                    },
                ],
                "controls": [],
                "procedures": [],
                "benchmarks": [],
                "benchmark_baseline_path": None,
            }
            (root / "security" / "industry-assurance-policy.json").write_text(
                json.dumps(policy), encoding="utf-8"
            )
            artifacts, errors = build_industry_assurance(root, {})
        self.assertEqual(errors, [])
        registry = artifacts["assurance-profile-registry.json"]
        self.assertEqual(registry["profiles_selected"], 2)
        assessment = artifacts["control-assessment.json"]
        self.assertEqual(assessment["controls_assessed"], 5)
        self.assertEqual(assessment["status_counts"]["gap"], 3)
        self.assertEqual(assessment["status_counts"]["not-applicable"], 2)
        procedures = artifacts["procedure-assessment.json"]
        self.assertEqual(procedures["status_counts"]["planned"], 1)
        self.assertEqual(procedures["status_counts"]["not-applicable"], 1)
        self.assertFalse(artifacts["industry-assurance.json"]["complete"])
        validate_governed_artifacts(artifacts)

    def test_new_industry_profiles_expand_with_explicit_applicability(self) -> None:
        profile_ids = [
            "identity-protocol-security",
            "cloud-container-zero-trust",
            "cryptography-pqc",
            "operational-resilience",
            "eu-digital-regulation",
            "iot-consumer",
            "ot-industrial",
            "automotive",
            "medical-device",
            "federal-cloud-defense",
            "systems-risk-measurement",
            "security-data-interoperability",
            "product-certification",
            "detection-threat-intelligence",
            "secure-coding",
            "software-testing-vv",
            "safety-security",
            "specialized-target-validation",
            "ai-robustness-impact",
            "privacy-by-design",
            "zero-trust-implementation",
            "independent-evaluator-assurance",
            "ot-system-operations",
            "healthcare-security",
            "airborne-software-assurance",
            "federal-configuration-hardening",
            "software-quality-evaluation",
            "incident-management",
            "privacy-impact-assessment",
            "supply-chain-identity",
            "threat-model-quality",
            "software-lifecycle-traceability",
            "architecture-evaluation-process",
            "software-process-capability",
            "comprehensive-weakness-mapping",
            "exploit-prioritization-validation",
            "ai-lifecycle-data-evaluation",
            "supplier-relationship-assurance",
            "software-signing-conformance",
            "remote-attestation-assurance",
            "ot-patch-management",
            "continuing-airworthiness-security",
            "maritime-cyber-resilience",
            "financial-messaging-security",
            "devsecops-maturity",
            "test-maturity",
            "ai-conformity-quality",
            "security-automation-interoperability",
            "cloud-independent-assurance",
            "federal-vulnerability-disclosure",
            "consumer-product-regulation",
            "detection-product-evaluation",
            "external-maturity-comparison",
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "security").mkdir()
            policy = {
                "schema_version": "1.2",
                "enforce": True,
                "profiles": [
                    {
                        "id": identifier,
                        "applicable": False,
                        "procedure_execution": "planned",
                    }
                    for identifier in profile_ids
                ],
                "controls": [],
                "procedures": [],
                "benchmarks": [],
                "benchmark_baseline_path": None,
            }
            (root / "security" / "industry-assurance-policy.json").write_text(
                json.dumps(policy), encoding="utf-8"
            )
            artifacts, errors = build_industry_assurance(root, {})
        self.assertEqual(errors, [])
        registry = artifacts["assurance-profile-registry.json"]
        self.assertEqual(registry["profiles_selected"], len(profile_ids))
        selected = {item["id"] for item in registry["profiles"] if item["selected"]}
        self.assertEqual(selected, set(profile_ids))
        controls = artifacts["control-assessment.json"]
        self.assertTrue(controls["controls"])
        self.assertEqual(
            controls["status_counts"]["not-applicable"],
            controls["controls_assessed"],
        )
        validate_governed_artifacts(artifacts)

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
            {
                "schema_version": "1.2",
                "enforce": True,
                "profiles": [
                    {
                        "id": "unknown",
                        "applicable": True,
                        "procedure_execution": "planned",
                    }
                ],
                "controls": [],
                "procedures": [],
                "benchmarks": [],
                "benchmark_baseline_path": None,
            },
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

    def test_benchmark_protocols_use_method_appropriate_metrics(self) -> None:
        examples = {
            "temporal-calibration": {
                "brier_score": 0.1,
                "expected_calibration_error": 0.1,
                "recall_at_budget": 0.8,
                "effort": 0.2,
                "observations": 100,
            },
            "verification-competition": {
                "correct": 8,
                "incorrect": 0,
                "unknown": 2,
                "score": 8.0,
            },
            "test-generation": {
                "coverage": 0.8,
                "faults_detected": 3,
                "valid_tests": 10,
                "score": 7.0,
            },
            "fuzzing-statistical": {
                "trials": 20,
                "median_edges": 1000,
                "effect_size": 0.4,
                "p_value": 0.03,
            },
            "stochastic-adversarial": {
                "repetitions": 5,
                "attack_success_rate": 0.1,
                "utility_retention": 0.9,
                "variance": 0.02,
            },
            "assessor-agreement": {
                "reviewers": 2,
                "cases": 10,
                "inter_rater_agreement": 0.85,
            },
            "conformance": {
                "passed_cases": 9,
                "failed_cases": 0,
                "negative_cases": 3,
                "conformance_rate": 1.0,
            },
            "detection-evaluation": {
                "techniques": 10,
                "detections": 8,
                "analytic_coverage": 0.8,
                "false_positive_rate": 0.05,
                "latency_ms": 250,
            },
        }
        identifiers = {
            "epss-kev-temporal-backtest": "temporal-calibration",
            "sv-comp": "verification-competition",
            "test-comp": "test-generation",
            "google-fuzzbench": "fuzzing-statistical",
            "agentdojo": "stochastic-adversarial",
            "ai-agentic-testing-conformance": "stochastic-adversarial",
            "owasp-dsomm-maturity": "assessor-agreement",
            "regional-cyber-maturity-assessment": "assessor-agreement",
            "cacao-openc2-ocsf-interoperability": "conformance",
            "scitt-transparency-conformance": "conformance",
            "cloud-native-api-service-mesh-conformance": "conformance",
            "api-contract-spec-conformance": "conformance",
            "opentelemetry-semantic-conformance": "conformance",
            "automotive-software-update-conformance": "conformance",
            "energy-product-security-conformance": "conformance",
            "mitre-attack-evaluations": "detection-evaluation",
            "owasp-benchmark": "classification",
        }
        for identifier, protocol in identifiers.items():
            with self.subTest(identifier=identifier):
                self.assertEqual(_benchmark_protocol(identifier), protocol)
                contract = _benchmark_runner_contract(
                    {"id": identifier, "version": "pinned"}
                )
                self.assertEqual(contract["protocol"], protocol)
                if protocol != "classification":
                    self.assertTrue(
                        _protocol_metrics_valid(protocol, examples[protocol])
                    )
                    self.assertFalse(_protocol_metrics_valid(protocol, {}))
                    self.assertNotIn(
                        "confusion-matrix", contract["required_execution_evidence"]
                    )
                    self.assertIn(
                        "acceptance-criteria-digest",
                        contract["required_execution_evidence"],
                    )

    def test_extended_assurance_requires_governed_external_evidence(self) -> None:
        digest = "a" * 64

        def assessment(identifier: str) -> dict[str, object]:
            return {
                "id": identifier,
                "version": "pinned",
                "scope_sha256": digest,
                "evidence_sha256": digest,
                "method_sha256": digest,
                "report_sha256": digest,
                "assessor": {
                    "identity": "qualified assessor",
                    "independent": True,
                    "competency_sha256": digest,
                },
                "authority": {"organization_approved": True},
                "replay_protected": True,
            }

        profiles = [
            "devsecops-maturity",
            "security-automation-interoperability",
            "cloud-independent-assurance",
        ]
        policy = {
            "schema_version": "1.2",
            "enforce": False,
            "profiles": [
                {"id": identifier, "applicable": True, "procedure_execution": "planned"}
                for identifier in profiles
            ],
            "controls": [],
            "procedures": [],
            "benchmarks": [],
            "benchmark_baseline_path": None,
        }
        maturity = []
        for identifier in ("OWASP-DSOVS", "OWASP-DSOMM"):
            maturity.append(
                {
                    **assessment(identifier),
                    "independent_reviewers": 2,
                    "domains": ["governance", "verification"],
                }
            )
        protocols = []
        for identifier in ("OASIS-CACAO", "OASIS-OPENC2", "OCSF"):
            protocols.append(
                {
                    "id": identifier,
                    "version": "pinned",
                    "schema_sha256": digest,
                    "fixtures_sha256": digest,
                    "report_sha256": digest,
                    "positive_cases": 5,
                    "negative_cases": 5,
                    "round_trip_validated": True,
                    "semantic_equivalence_validated": True,
                    "replay_protected": True,
                    "authority": {"organization_approved": True},
                }
            )
        conformity = {
            **assessment("CSA-STAR"),
            "valid_at_assessment": "2026-08-27",
            "applicability_basis": "Cloud services in the assessment scope.",
            "assessor_credential": {
                "issuer": "Accreditation authority",
                "scheme": "ISO-IEC-17020",
                "credential_id_sha256": digest,
                "registry_snapshot_sha256": digest,
                "registry_signature_sha256": digest,
                "status": "active",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "checked_at": "2026-08-27T00:00:00Z",
                "revocation_checked": True,
                "signature_validated": True,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "security").mkdir()
            (root / "security" / "industry-assurance-policy.json").write_text(
                json.dumps(policy), encoding="utf-8"
            )
            artifacts, errors = build_industry_assurance(
                root,
                {
                    "maturity-model-evidence.json": {"models": maturity},
                    "security-automation-evidence.json": {"protocols": protocols},
                    "external-conformity-evidence.json": {"assessments": [conformity]},
                },
            )
        self.assertEqual(errors, [])
        for name in (
            "maturity-model-assessment.json",
            "security-automation-interoperability.json",
            "external-conformity-assessment.json",
        ):
            self.assertTrue(artifacts[name]["complete"], name)
        validate_governed_artifacts(artifacts)

    def test_semantic_validators_reject_tampered_accounting(self) -> None:
        with self.assertRaises(TypeError):
            _validate_standards_crosswalk_accounting(None)
        with self.assertRaises(TypeError):
            _validate_standards_crosswalk_accounting({"catalogs": None, "mappings": []})
        with self.assertRaises(ValueError):
            _validate_standards_crosswalk_accounting(
                {
                    "catalogs_registered": 2,
                    "catalogs": [],
                    "mappings": [],
                    "watchlist": [],
                    "lifecycle_governance": {
                        "records": [],
                        "catalogs_assessed": 0,
                        "catalogs_complete": 0,
                        "input_records": 0,
                        "input_gaps": [],
                        "complete": True,
                    },
                }
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
