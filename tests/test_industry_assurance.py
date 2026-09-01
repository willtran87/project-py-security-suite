from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import pytest
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
    _STANDARDS_WATCHLIST,
    _authorization_validated,
    _benchmark_gaps,
    _benchmark_protocol,
    _benchmark_reproducibility_gaps,
    _benchmark_runner_contract,
    _lifecycle_traceability,
    _protocol_metrics_valid,
    _process_capability_assessment,
    _procedure_assessment,
    _safe_relative,
    _standardized_prioritization,
    _validated_cvss,
    _validate_policy,
    _validate_builtin_catalog,
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
            artifacts["standards-crosswalk.json"]["catalogs_registered"], 663
        )
        self.assertEqual(
            artifacts["benchmark-registry.json"]["benchmarks_registered"], 282
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
        self.assertEqual(len(validate_governed_artifacts(artifacts)), 25)
        profiles = artifacts["assurance-profile-registry.json"]
        self.assertEqual(profiles["profiles_available"], 233)
        self.assertEqual(profiles["profiles_selected"], 0)
        lifecycle = artifacts["standards-crosswalk.json"]["lifecycle_governance"]
        self.assertEqual(lifecycle["catalogs_assessed"], 663)
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
                "ISO-19011",
                "ISO-IEC-27007",
                "ISO-IEC-TS-27008",
                "ISO-IEC-27006-1",
                "ISO-IEC-17021-1",
                "ISO-IEC-17029",
                "ISO-IEC-19896-1",
                "ISO-IEC-19896-2",
                "ISO-IEC-19896-3",
                "ISO-IEC-27034-2",
                "ISO-IEC-27034-3",
                "ISO-IEC-27034-5",
                "ISO-IEC-TS-27034-5-1",
                "ISO-IEC-27034-6",
                "ISO-IEC-27034-7",
                "NIST-SP-800-204A",
                "NIST-SP-800-192",
                "NIST-SP-800-193",
                "TCG-TPM-2.0",
                "NIST-SP-800-226",
                "ISO-IEC-25012",
                "ISO-IEC-25020",
                "ISO-IEC-25024",
                "ISO-IEC-25030",
                "ISO-27799",
                "ISO-IEC-27019",
                "ISO-IEC-27050-2",
                "ISO-IEC-27050-4",
                "ISO-IEC-IEEE-29119-1",
                "ISO-IEC-IEEE-29119-2",
                "ISO-IEC-IEEE-29119-3",
                "ISO-IEC-IEEE-29119-4",
                "ISO-IEC-IEEE-29119-5",
                "ISO-IEC-25019",
                "ISO-IEC-TS-25052-1",
                "ISO-IEC-TS-25052-2",
                "ISO-31000",
                "IEC-31010",
                "CISA-SECURE-BY-DESIGN",
                "CISA-PRODUCT-SECURITY-BAD-PRACTICES",
                "TCG-DICE-ATTESTATION-ARCHITECTURE",
                "ISO-IEC-27011",
                "NIST-SP-800-181-R1",
                "NIST-NICE-FRAMEWORK-COMPONENTS",
                "AMTSO-TESTING-PROTOCOL",
                "CREST-PENETRATION-TESTING-GUIDE",
                "PTES",
                "DORA-SOFTWARE-DELIVERY-PERFORMANCE",
                "IETF-RFC-8446",
                "IETF-RFC-8996",
                "REPRODUCIBLE-BUILDS-TEST-PROTOCOL",
                "ISO-IEC-IEEE-15026-2",
                "ISO-IEC-IEEE-15026-4",
                "OMG-SACM",
                "IEEE-1012",
                "NIST-CMVP",
                "ISO-IEC-19790",
                "ISO-IEC-24759",
                "ISO-IEC-17825",
                "ISO-IEC-20085-1",
                "ISO-IEC-20085-2",
                "ISO-IEC-19795-1",
                "ISO-IEC-30107-3",
                "ISO-IEC-30107-4",
                "ISO-IEC-20000-1",
                "ISO-IEC-27013",
                "ISO-IEC-17043",
                "ISO-IEC-IEEE-24748-1",
                "ISO-IEC-IEEE-15289",
                "ISO-IEC-IEEE-16085",
                "ISO-IEC-IEEE-90003",
                "ISO-IEC-25002",
                "ISO-IEC-25021",
                "ISO-IEC-25022",
                "ISO-IEC-25051",
                "NIST-SP-800-30",
                "NIST-SP-800-39",
                "ISO-IEC-29151",
                "ISO-IEC-27557",
                "ISO-IEC-TR-27550",
                "ISO-IEC-38505-1",
                "ISO-IEC-22989",
                "ISO-IEC-23053",
                "ISO-IEC-38507",
                "ISO-22340",
                "OWASP-CODE-REVIEW-GUIDE",
                "OWASP-CORNUCOPIA",
                "CIS-SAFECODE-SECURE-BY-DESIGN",
                "NIST-IR-8286",
                "NIST-IR-8286A",
                "NIST-IR-8286B",
                "NIST-IR-8286C",
                "NIST-IR-8286D",
                "CIS-RAM",
                "ISO-IEC-25001",
                "ISO-IEC-TR-42106",
                "ISO-IEC-8183",
                "ISO-IEC-12792",
                "ISO-IEC-TS-6254",
                "ISO-IEC-TS-8200",
                "ISO-IEC-TS-12791",
                "ISO-IEC-TR-5469",
                "COBIT-2019",
                "TOGAF-STANDARD",
                "ARCHIMATE",
                "OPEN-FAIR",
                "OWASP-AISVS",
                "ISO-IEC-TS-25058",
                "EU-EUCC",
                "CISA-SECURE-SOFTWARE-ATTESTATION",
                "IEEE-7000",
                "IEEE-7001",
                "IEEE-7002",
                "IEEE-7003",
                "IEEE-7009",
                "ISO-IEC-TR-27563",
                "ISO-IEC-TR-24030",
                "ISO-IEC-38500",
                "ISO-9001",
                "NIST-SP-1301",
                "ISO-IEC-27000",
                "ISO-IEC-27561",
                "ISO-IEC-TS-27564",
                "ISO-IEC-27565",
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
                "audit-assessment-integrity",
                "security-evaluator-competence",
                "application-security-governance",
                "firmware-hardware-trust",
                "differential-privacy-engineering",
                "data-quality-engineering",
                "quality-in-use-cloud",
                "enterprise-risk-techniques",
                "secure-by-design-product",
                "tls-protocol-assurance",
                "reproducible-build-assurance",
                "malware-protection-validation",
                "confidential-computing-attestation",
                "telecommunications-security",
                "cyber-workforce-assurance",
                "penetration-testing-governance",
                "software-delivery-outcomes",
                "structured-assurance-case",
                "integrity-level-vv",
                "cmvp-cryptographic-module",
                "international-cryptographic-module",
                "biometric-identity-assurance",
                "integrated-service-security-management",
                "interlaboratory-proficiency",
                "enterprise-cyber-risk-integration",
                "enterprise-architecture-governance",
                "ai-benchmark-governance",
                "ai-application-security-verification",
                "responsible-ai-system-assurance",
                "eucc-product-certification",
                "federal-software-attestation",
                "it-quality-governance",
                "nist-csf-profile-management",
                "privacy-engineering-pets",
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
                "nist-dioptra-ai-evaluation",
                "firmware-resilience-measured-boot",
                "access-control-policy-model-conformance",
                "differential-privacy-implementation-evaluation",
                "security-evaluator-calibration",
                "square-quality-measurement",
                "iso-29119-test-process-conformance",
                "square-quality-in-use-cloud",
                "risk-technique-calibration",
                "tls-protocol-conformance",
                "reproducible-build-variation",
                "cisa-secure-by-design-negative-assurance",
                "amtso-malware-protection-evaluation",
                "dice-attestation-conformance",
                "telecom-security-controls-conformance",
                "nice-workforce-coverage",
                "penetration-test-engagement-quality",
                "dora-delivery-outcomes",
                "structured-assurance-case-conformance",
                "integrity-vv-conformance",
                "cmvp-fips-140-3-validation",
                "iso-19790-24759-module-conformance",
                "biometric-performance-pad",
                "service-management-security-integration",
                "interlaboratory-proficiency-testing",
                "harmbench",
                "agentharm",
                "garak-llm-probe-conformance",
                "owasp-cornucopia-threat-model",
                "nist-8286-enterprise-risk-register",
                "cis-ram-attack-path-analysis",
                "square-quality-governance",
                "iso-42106-differentiated-ai-benchmarking",
                "enterprise-architecture-governance",
                "pyrit-ai-red-team",
                "owasp-aisvs-conformance",
                "iso-25058-ai-quality-evaluation",
                "eucc-scheme-assurance",
                "cisa-secure-software-attestation",
                "ieee-7000-ai-ethics-conformance",
                "ai-use-case-security-privacy",
                "it-quality-governance-assessor-agreement",
                "nist-csf-profile-gap-reassessment",
                "mlcommons-ailuminate-safety",
                "mlcommons-ailuminate-jailbreak",
                "privacy-engineering-pet-conformance",
            }
            <= {item["id"] for item in _BENCHMARKS}
        )
        standards = {item["id"]: item for item in _STANDARDS}
        self.assertEqual(
            standards["ISO-IEC-27403"]["reference"],
            "https://www.iso.org/standard/78702.html",
        )
        self.assertEqual(
            standards["ISO-IEC-27404"]["kind"],
            "consumer-iot-cybersecurity-labelling-framework",
        )
        self.assertTrue(
            {
                "ISO-IEC-27007-NEXT-EDITION",
                "ISO-IEC-TS-27008-NEXT-EDITION",
                "ISO-IEC-17021-1-NEXT-EDITION",
                "ISO-IEC-27034-NEXT-SERIES",
                "ISO-IEC-27050-REVIEW",
                "ISO-31000-NEXT-EDITION",
                "TCG-DICE-ATTESTATION-ARCHITECTURE-1.3",
                "OWASP-ISVS-1.0",
                "ISO-IEC-IEEE-29119-14",
                "ISO-IEC-IEEE-15026-4-NEXT-EDITION",
                "IEEE-P1012",
                "NIST-SSDF-1.2",
                "NIST-SP-800-154",
                "ISO-IEC-25000-22",
                "ISO-IEC-42105",
                "ISO-IEC-24970",
                "ISO-IEC-42007",
                "NIST-IR-8596",
                "ISO-IEC-TR-24030-NEXT-EDITION",
                "MLCOMMONS-AILUMINATE-AGENTIC",
                "MLCOMMONS-AILUMINATE-MULTIMODAL",
            }
            <= {item["id"] for item in _STANDARDS_WATCHLIST}
        )
        self.assertNotIn("ISO-IEC-IEEE-29119", {item["id"] for item in _STANDARDS})
        standards = {item["id"]: item for item in _STANDARDS}
        self.assertEqual(standards["ISO-IEC-IEEE-29119-2"]["version"], "2021")
        self.assertEqual(standards["ISO-IEC-IEEE-29119-5"]["version"], "2024")
        self.assertEqual(standards["ISO-IEC-29100"]["version"], "2024")
        self.assertEqual(
            standards["ISO-IEC-29100"]["reference"],
            "https://www.iso.org/standard/85938.html",
        )
        self.assertIn("voluntary", standards["CISA-SECURE-BY-DESIGN"]["kind"])
        self.assertIn(
            "research-backed",
            standards["DORA-SOFTWARE-DELIVERY-PERFORMANCE"]["kind"],
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
                "assurance-case-assessment.json",
                "threat-model-assessment.json",
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

    def test_threat_model_assessment_requires_bound_graph_and_negative_tests(
        self,
    ) -> None:
        source_sha256 = "a" * 64
        threat_model = {
            "schema_version": "1.0",
            "model_id": "checkout-threat-model",
            "source_sha256": source_sha256,
            "architecture_sha256": "b" * 64,
            "methodology": "OWASP four-question framework with STRIDE",
            "reviewed_at": "2026-08-20T12:00:00Z",
            "assets": [
                {
                    "id": "credentials",
                    "title": "Customer credentials",
                    "owner": "identity-team",
                    "classification": "restricted",
                    "criticality": 5,
                }
            ],
            "components": [
                {
                    "id": "browser",
                    "name": "Customer browser",
                    "kind": "external-client",
                    "zone": "internet",
                    "owner": "customer",
                },
                {
                    "id": "identity-api",
                    "name": "Identity API",
                    "kind": "service",
                    "zone": "production",
                    "owner": "identity-team",
                },
            ],
            "trust_boundaries": [
                {
                    "id": "internet-edge",
                    "from_zone": "internet",
                    "to_zone": "production",
                    "control_ids": ["TLS-CLIENT-AUTH", "RATE-LIMIT"],
                }
            ],
            "data_flows": [
                {
                    "id": "login",
                    "source_component": "browser",
                    "destination_component": "identity-api",
                    "data_classes": ["credentials"],
                    "boundary_ids": ["internet-edge"],
                    "encrypted": True,
                    "authenticated": True,
                }
            ],
            "assumptions": [
                {
                    "id": "tls-termination",
                    "statement": "The approved edge terminates TLS.",
                    "owner": "platform-team",
                    "status": "validated",
                    "expires_at": "2099-01-01T00:00:00Z",
                }
            ],
            "mitigations": [
                {
                    "id": "credential-controls",
                    "title": "Rate limit and authenticate login traffic.",
                    "owner": "identity-team",
                    "status": "verified",
                    "control_ids": ["TLS-CLIENT-AUTH", "RATE-LIMIT"],
                    "evidence": [
                        {
                            "artifact": "control-assessment.json",
                            "sha256": "c" * 64,
                            "subject_sha256": source_sha256,
                        }
                    ],
                }
            ],
            "tests": [
                {
                    "id": "credential-abuse-test",
                    "threat_ids": ["credential-stuffing"],
                    "kind": "rate-limit-negative-case",
                    "negative_case": True,
                    "result": "passed",
                    "evidence_sha256": "d" * 64,
                    "subject_sha256": source_sha256,
                }
            ],
            "threats": [
                {
                    "id": "credential-stuffing",
                    "title": "Automated credential stuffing",
                    "category": "spoofing",
                    "asset_ids": ["credentials"],
                    "component_ids": ["identity-api"],
                    "flow_ids": ["login"],
                    "boundary_ids": ["internet-edge"],
                    "preconditions": ["Attacker possesses reused credentials."],
                    "attack_steps": ["Replay credentials against the login endpoint."],
                    "likelihood": 4,
                    "impact": 5,
                    "risk_score": 20,
                    "status": "mitigated",
                    "mitigation_ids": ["credential-controls"],
                    "test_ids": ["credential-abuse-test"],
                    "residual_risk": 5,
                    "owner": "identity-team",
                    "acceptance": None,
                }
            ],
            "change_triggers": [
                {
                    "id": "architecture-snapshot",
                    "artifact": "static-architecture.json",
                    "sha256": "e" * 64,
                    "assessed": True,
                }
            ],
            "review": {
                "reviewed_at": "2026-08-20T12:00:00Z",
                "independent_reviewers": ["security-reviewer", "architecture-reviewer"],
                "approved": True,
                "approval_sha256": "f" * 64,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            complete, errors = build_industry_assurance(
                Path(directory),
                {
                    "source-inventory.json": {
                        "complete": True,
                        "source_sha256": source_sha256,
                    },
                    "threat-model-evidence.json": threat_model,
                },
            )
            invalid_model = json.loads(json.dumps(threat_model))
            invalid_model["data_flows"][0]["boundary_ids"] = []
            invalid_model["tests"][0]["result"] = "failed"
            invalid_model["change_triggers"][0]["assessed"] = False
            invalid, invalid_errors = build_industry_assurance(
                Path(directory),
                {
                    "source-inventory.json": {
                        "complete": True,
                        "source_sha256": source_sha256,
                    },
                    "threat-model-evidence.json": invalid_model,
                },
            )
        self.assertEqual(errors, [])
        self.assertEqual(invalid_errors, [])
        assessment = complete["threat-model-assessment.json"]
        self.assertTrue(assessment["complete"])
        self.assertEqual(assessment["coverage"]["assets_with_threats"], 1)
        self.assertEqual(assessment["coverage"]["threats_with_verification"], 1)
        self.assertEqual(assessment["review"]["independent_reviewers"], 2)
        invalid_assessment = invalid["threat-model-assessment.json"]
        self.assertFalse(invalid_assessment["complete"])
        self.assertTrue(
            {
                "cross-zone flow has no matching directional trust boundary: login",
                "mitigated threat lacks verified controls or passing negative tests: credential-stuffing",
                "architecture change has not been threat-modeled: architecture-snapshot",
            }
            <= set(invalid_assessment["gaps"])
        )
        validate_governed_artifacts(complete)
        validate_governed_artifacts(invalid)

    def test_lifecycle_traceability_requires_end_to_end_graph_and_change_impact(
        self,
    ) -> None:
        source_sha256 = "a" * 64
        stages = [
            "requirements",
            "architecture",
            "implementation",
            "verification",
            "release",
            "operation",
            "retirement",
        ]
        nodes = [
            {
                "id": f"node-{stage}",
                "stage": stage,
                "artifact": f"{stage}.json",
                "sha256": f"{index + 1:x}" * 64,
                "subject_sha256": source_sha256,
                "applicable": True,
            }
            for index, stage in enumerate(stages)
        ]
        link_types = [
            "derives",
            "implements",
            "verifies",
            "releases",
            "operates",
            "retires",
        ]
        links = [
            {
                "source": nodes[index]["id"],
                "target": nodes[index + 1]["id"],
                "type": link_types[index],
                "evidence_sha256": f"{index + 8:x}" * 64,
            }
            for index in range(6)
        ]
        evidence = {
            "schema_version": "1.0",
            "source_sha256": source_sha256,
            "nodes": nodes,
            "links": links,
            "change_sets": [
                {
                    "id": "change-42",
                    "changed_node_ids": ["node-implementation"],
                    "impact_node_ids": [
                        "node-verification",
                        "node-release",
                        "node-operation",
                        "node-retirement",
                    ],
                    "verified": True,
                    "evidence_sha256": "e" * 64,
                }
            ],
            "review": {
                "reviewed_at": "2026-08-20T12:00:00Z",
                "independent_reviewers": ["quality-reviewer", "security-reviewer"],
                "approved": True,
                "approval_sha256": "f" * 64,
            },
        }
        artifacts = {
            "security-requirements-coverage.json": {
                "complete": True,
                "applicable_requirements": 1,
                "evidenced_requirements": 1,
            },
            "static-architecture.json": {"complete": True},
            "architecture-history.json": {"complete": True},
            "source-inventory.json": {"complete": True},
            "test-evidence.json": {"complete": True},
            "effectiveness.json": {"complete": True},
            "release-readiness.json": {"complete": True},
            "operational-trend.json": {"complete": True},
            "closure-plan.json": {"complete": True},
            "lifecycle-traceability-evidence.json": evidence,
        }
        assessment = _lifecycle_traceability(artifacts, source_sha256)
        self.assertTrue(assessment["complete"])
        self.assertEqual(
            assessment["graph_traceability"]["requirements_with_end_to_end_trace"],
            1,
        )
        self.assertEqual(assessment["graph_traceability"]["verified_change_sets"], 1)
        validate_governed_artifacts({"lifecycle-traceability.json": assessment})

        invalid_evidence = json.loads(json.dumps(evidence))
        invalid_evidence["links"].pop()
        invalid_evidence["change_sets"][0]["verified"] = False
        invalid_artifacts = {
            **artifacts,
            "lifecycle-traceability-evidence.json": invalid_evidence,
        }
        invalid = _lifecycle_traceability(invalid_artifacts, source_sha256)
        self.assertFalse(invalid["complete"])
        self.assertIn(
            "applicable lifecycle node has no downstream trace: node-operation",
            invalid["gaps"],
        )
        self.assertIn(
            "change impact is not independently verified: change-42",
            invalid["gaps"],
        )
        validate_governed_artifacts({"lifecycle-traceability.json": invalid})

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
            "corpus": {"sha256": "1" * 64, "revision": "approved"},
            "extension_evidence": {
                "schema_version": "1.0",
                "integration": "disa-stig-scap-conformance",
                "source_sha256": "1" * 64,
                "subject_sha256": "b" * 64,
                "execution": {
                    "isolated": True,
                    "network_policy": "deny",
                    "repetitions": 3,
                    "budget_seconds": 300,
                },
                "claims": {
                    "release_policy": "policy-pinned-quarterly-release",
                    "assessment_modes": ["xccdf-oval", "manual"],
                    "assets_evaluated": 3,
                    "rules_evaluated": 10,
                    "release_deltas_evaluated": 2,
                    "release_signature_digest_and_delta_verified": True,
                    "asset_cpe_profile_tailoring_and_applicability_verified": True,
                    "automated_manual_and_engine_disagreement_adjudicated": True,
                    "exception_poam_owner_and_expiry_verified": True,
                    "laboratory_remediation_rollback_and_rescan_verified": True,
                    "longitudinal_drift_and_durability_measured": True,
                    "production_remediation_performed": False,
                    "authorization_claimed": False,
                },
                "negative_cases": [
                    {"id": "applicability-misbinding", "detected": True},
                    {"id": "manual-check-disagreement", "detected": True},
                ],
                "provenance": {
                    "producer": "digest-pinned-stig-normalizer",
                    "producer_sha256": "2" * 64,
                    "signature_verified": True,
                    "independent_replay_verified": True,
                },
                "complete": True,
            },
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
            ["suite-owned industry extension evidence is missing or invalid"],
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
        self.assertLessEqual(
            {profile["id"] for profile in instance["profiles"]},
            set(_ASSURANCE_PROFILES),
        )
        self.assertLessEqual(
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
        self.assertEqual(assessment["controls_assessed"], 9)
        self.assertEqual(assessment["status_counts"]["gap"], 3)
        self.assertEqual(assessment["status_counts"]["not-applicable"], 6)
        procedures = artifacts["procedure-assessment.json"]
        self.assertEqual(procedures["status_counts"]["planned"], 1)
        self.assertEqual(procedures["status_counts"]["not-applicable"], 2)
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

    def test_structured_assurance_case_rejects_semantic_gaps(self) -> None:
        digest = "a" * 64
        assurance_case = {
            "schema_version": "1.0",
            "case_id": "release-assurance",
            "scope_sha256": digest,
            "model": {
                "format": "OMG-SACM",
                "version": "2.3",
                "schema_sha256": "b" * 64,
                "model_sha256": "c" * 64,
                "schema_validated": True,
                "semantic_validated": True,
                "round_trip_validated": True,
            },
            "claims": [
                {
                    "id": "claim-release",
                    "type": "claim",
                    "statement": "The evaluated release satisfies its scoped security objectives.",
                    "status": "supported",
                    "confidence": 0.95,
                    "applicable": True,
                    "top_level": True,
                },
                {
                    "id": "defeater-dynamic-loading",
                    "type": "defeater",
                    "statement": "Runtime dynamic loading can invalidate static evidence.",
                    "status": "resolved",
                    "confidence": 0.9,
                    "applicable": True,
                    "top_level": False,
                },
            ],
            "evidence": [
                {
                    "id": "evidence-release",
                    "artifact": "release-readiness.json",
                    "sha256": "d" * 64,
                    "subject_sha256": digest,
                    "collected_at": "2026-08-28T12:00:00Z",
                    "valid_until": "2030-08-28T12:00:00Z",
                    "verified": True,
                }
            ],
            "relationships": [
                {
                    "source": "evidence-release",
                    "target": "claim-release",
                    "type": "supports",
                    "rationale": "The source-bound release evidence directly supports the release claim.",
                }
            ],
            "review": {
                "reviewed_at": "2026-08-28T13:00:00Z",
                "independent_reviewers": 2,
                "minimum_confidence": 0.8,
                "approved": True,
                "approval_sha256": "e" * 64,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            artifacts, errors = build_industry_assurance(
                Path(directory), {"structured-assurance-case.json": assurance_case}
            )
        self.assertEqual(errors, [])
        assessment = artifacts["assurance-case-assessment.json"]
        self.assertTrue(assessment["complete"])
        self.assertEqual(assessment["top_level_claims"], 1)
        validate_governed_artifacts(artifacts)

        assurance_case["relationships"].append(
            {
                "source": "claim-release",
                "target": "defeater-dynamic-loading",
                "type": "supports",
                "rationale": "First edge in an invalid support cycle.",
            }
        )
        assurance_case["relationships"].append(
            {
                "source": "defeater-dynamic-loading",
                "target": "claim-release",
                "type": "supports",
                "rationale": "Second edge in an invalid support cycle.",
            }
        )
        assurance_case["evidence"][0]["subject_sha256"] = "f" * 64
        with tempfile.TemporaryDirectory() as directory:
            invalid, errors = build_industry_assurance(
                Path(directory), {"structured-assurance-case.json": assurance_case}
            )
        self.assertEqual(errors, [])
        invalid_assessment = invalid["assurance-case-assessment.json"]
        self.assertFalse(invalid_assessment["complete"])
        self.assertTrue(
            any(
                "outside assurance-case scope" in gap
                for gap in invalid_assessment["gaps"]
            )
        )
        self.assertIn(
            "claim support graph contains a cycle", invalid_assessment["gaps"]
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
            "biometric-performance": {
                "genuine_attempts": 1000,
                "impostor_attempts": 1000,
                "attack_attempts": 500,
                "demographic_groups": 4,
                "threshold_locked": True,
                "false_match_rate": 0.001,
                "false_non_match_rate": 0.02,
                "iapar": 0.03,
                "fmr_wilson_upper_95": 0.006,
                "fnmr_wilson_upper_95": 0.03,
                "iapar_wilson_upper_95": 0.05,
                "worst_group_fmr_wilson_upper_95": 0.01,
                "worst_group_fnmr_wilson_upper_95": 0.05,
            },
            "proficiency-testing": {
                "participants": 4,
                "cases": 20,
                "rounds": 2,
                "blinded": True,
                "agreement": 0.9,
                "chance_corrected_agreement": 0.85,
                "reference_accuracy": 0.95,
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
            "nist-dioptra-ai-evaluation": "stochastic-adversarial",
            "harmbench": "stochastic-adversarial",
            "agentharm": "stochastic-adversarial",
            "garak-llm-probe-conformance": "stochastic-adversarial",
            "pyrit-ai-red-team": "stochastic-adversarial",
            "mlcommons-ailuminate-safety": "stochastic-adversarial",
            "mlcommons-ailuminate-jailbreak": "stochastic-adversarial",
            "owasp-dsomm-maturity": "assessor-agreement",
            "regional-cyber-maturity-assessment": "assessor-agreement",
            "security-evaluator-calibration": "assessor-agreement",
            "risk-technique-calibration": "assessor-agreement",
            "cis-ram-attack-path-analysis": "assessor-agreement",
            "enterprise-architecture-governance": "assessor-agreement",
            "it-quality-governance-assessor-agreement": "assessor-agreement",
            "biometric-performance-pad": "biometric-performance",
            "interlaboratory-proficiency-testing": "proficiency-testing",
            "cacao-openc2-ocsf-interoperability": "conformance",
            "scitt-transparency-conformance": "conformance",
            "cloud-native-api-service-mesh-conformance": "conformance",
            "api-contract-spec-conformance": "conformance",
            "opentelemetry-semantic-conformance": "conformance",
            "automotive-software-update-conformance": "conformance",
            "energy-product-security-conformance": "conformance",
            "firmware-resilience-measured-boot": "conformance",
            "access-control-policy-model-conformance": "conformance",
            "differential-privacy-implementation-evaluation": "conformance",
            "square-quality-measurement": "conformance",
            "iso-29119-test-process-conformance": "conformance",
            "square-quality-in-use-cloud": "conformance",
            "tls-protocol-conformance": "conformance",
            "reproducible-build-variation": "conformance",
            "cisa-secure-by-design-negative-assurance": "conformance",
            "amtso-malware-protection-evaluation": "detection-evaluation",
            "dice-attestation-conformance": "conformance",
            "telecom-security-controls-conformance": "conformance",
            "nice-workforce-coverage": "conformance",
            "penetration-test-engagement-quality": "conformance",
            "dora-delivery-outcomes": "conformance",
            "structured-assurance-case-conformance": "conformance",
            "integrity-vv-conformance": "conformance",
            "cmvp-fips-140-3-validation": "conformance",
            "iso-19790-24759-module-conformance": "conformance",
            "service-management-security-integration": "conformance",
            "owasp-cornucopia-threat-model": "conformance",
            "nist-8286-enterprise-risk-register": "conformance",
            "square-quality-governance": "conformance",
            "iso-42106-differentiated-ai-benchmarking": "conformance",
            "owasp-aisvs-conformance": "conformance",
            "iso-25058-ai-quality-evaluation": "conformance",
            "eucc-scheme-assurance": "conformance",
            "cisa-secure-software-attestation": "conformance",
            "ieee-7000-ai-ethics-conformance": "conformance",
            "ai-use-case-security-privacy": "conformance",
            "nist-csf-profile-gap-reassessment": "conformance",
            "privacy-engineering-pet-conformance": "conformance",
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

    def test_enterprise_risk_architecture_quality_and_ai_contracts_are_specific(
        self,
    ) -> None:
        expected = {
            "nist-8286-enterprise-risk-register": {
                "nist-8286-series-and-schema-digests",
                "risk-rollup-lineage-correlation-and-unit-analysis",
            },
            "cis-ram-attack-path-analysis": {
                "blinded-assessor-labels-and-agreement",
                "sensitivity-adjudication-and-risk-acceptance-ledger",
            },
            "square-quality-governance": {
                "licensed-25001-requirement-set-digest",
                "management-fault-injection-results",
            },
            "iso-42106-differentiated-ai-benchmarking": {
                "complexity-context-stakeholder-and-strata-design",
                "metamorphic-rank-stability-and-evaluator-robustness-results",
            },
            "enterprise-architecture-governance": {
                "licensed-framework-edition-and-requirement-map-digests",
                "architecture-model-exchange-and-semantic-validation",
            },
            "pyrit-ai-red-team": {
                "pyrit-release-lock-and-environment-digest",
                "step-token-time-spend-kill-switch-reset-and-cleanup-receipts",
            },
        }
        for identifier, evidence in expected.items():
            with self.subTest(identifier=identifier):
                contract = _benchmark_runner_contract(
                    {"id": identifier, "version": "policy-pinned"}
                )
                self.assertTrue(
                    evidence <= set(contract["required_execution_evidence"])
                )
        self.assertEqual(
            _benchmark_runner_contract(
                {"id": "pyrit-ai-red-team", "version": "policy-pinned"}
            )["minimum_repetitions"],
            5,
        )

    def test_ai_certification_attestation_governance_and_privacy_contracts_are_specific(
        self,
    ) -> None:
        profile_standards = {
            "ai-application-security-verification": {"OWASP-AISVS"},
            "responsible-ai-system-assurance": {
                "ISO-IEC-TS-25058",
                "IEEE-7000",
                "IEEE-7003",
                "IEEE-7009",
            },
            "eucc-product-certification": {"EU-EUCC", "ISO-IEC-15408"},
            "federal-software-attestation": {
                "CISA-SECURE-SOFTWARE-ATTESTATION",
                "NIST-SSDF",
            },
            "it-quality-governance": {"ISO-IEC-38500", "ISO-9001"},
            "nist-csf-profile-management": {"NIST-CSF", "NIST-SP-1301"},
            "privacy-engineering-pets": {
                "ISO-IEC-27561",
                "ISO-IEC-TS-27564",
                "ISO-IEC-27565",
            },
        }
        for profile, standards in profile_standards.items():
            with self.subTest(profile=profile):
                definition = _ASSURANCE_PROFILES[profile]
                self.assertTrue(standards <= set(definition["standards"]))
                self.assertTrue(definition["controls"])
                self.assertTrue(definition["procedures"])

        expected = {
            "owasp-aisvs-conformance": {
                "aisvs-release-requirement-and-level-digests",
                "mutation-independent-review-and-adjudication-results",
            },
            "iso-25058-ai-quality-evaluation": {
                "licensed-25058-criteria-and-quality-model-digests",
                "reperformance-metamorphic-and-adverse-case-results",
            },
            "eucc-scheme-assurance": {
                "eucc-regulation-amendment-and-sota-digests",
                "assurance-continuity-vulnerability-and-change-results",
            },
            "cisa-secure-software-attestation": {
                "signatory-authority-signature-time-and-revocation-record",
                "forgery-replay-staleness-and-change-trigger-results",
            },
            "ieee-7000-ai-ethics-conformance": {
                "stakeholder-value-harm-and-requirement-trace",
                "fail-safe-intervention-recovery-and-appeal-results",
            },
            "ai-use-case-security-privacy": {
                "domain-context-stakeholder-data-and-boundary-model",
                "normal-adverse-out-of-domain-and-misuse-results",
            },
            "it-quality-governance-assessor-agreement": {
                "blinded-assessor-labels-agreement-and-competence",
                "nonconformity-corrective-action-and-improvement-trace",
            },
            "nist-csf-profile-gap-reassessment": {
                "organizational-scope-current-and-target-profile-digests",
                "identifier-mutation-regression-and-reassessment-results",
            },
            "mlcommons-ailuminate-safety": {
                "sut-locale-persona-hazard-and-prompt-split-manifest",
                "public-private-contamination-and-grading-results",
            },
            "mlcommons-ailuminate-jailbreak": {
                "sut-attack-scenario-locale-and-protected-split-manifest",
                "naive-versus-jailbreak-safety-and-grading-results",
            },
            "privacy-engineering-pet-conformance": {
                "zkp-statement-relation-setup-parameter-and-implementation-digests",
                "malformed-replay-linkability-composition-and-differential-results",
            },
        }
        for identifier, evidence in expected.items():
            with self.subTest(identifier=identifier):
                contract = _benchmark_runner_contract(
                    {"id": identifier, "version": "policy-pinned"}
                )
                self.assertTrue(
                    evidence <= set(contract["required_execution_evidence"])
                )
        for identifier in (
            "mlcommons-ailuminate-safety",
            "mlcommons-ailuminate-jailbreak",
        ):
            self.assertEqual(
                _benchmark_runner_contract(
                    {"id": identifier, "version": "policy-pinned"}
                )["minimum_repetitions"],
                5,
            )

    def test_protocol_cloud_response_memory_and_operational_gaps_are_executable(
        self,
    ) -> None:
        standards = {item["id"]: item for item in _STANDARDS}
        self.assertTrue(
            {
                "MCP-SPECIFICATION",
                "OWASP-MCP-SECURITY-CHEAT-SHEET",
                "AWS-FOUNDATIONAL-SECURITY-BEST-PRACTICES",
                "MICROSOFT-CLOUD-SECURITY-BENCHMARK",
                "GCP-ENTERPRISE-FOUNDATIONS-BLUEPRINT",
                "FIRST-CSIRT-SERVICES-FRAMEWORK",
                "FIRST-PSIRT-SERVICES-FRAMEWORK",
                "FIRST-PSIRT-MATURITY",
                "CISA-MEMORY-SAFE-ROADMAPS",
                "IEEE-2863",
                "IEEE-7010",
                "ISO-22316",
                "ISO-TS-22317",
                "OPENSSF-BEST-PRACTICES-BADGE",
                "ISO-IEC-27003",
                "ISO-IEC-TS-27022",
            }
            <= set(standards)
        )
        self.assertNotIn("ISO-IEC-27009", standards)
        self.assertEqual(standards["MCP-SPECIFICATION"]["version"], "2025-11-25")
        self.assertEqual(standards["IEEE-2863"]["lifecycle"]["edition_status"], "final")

        profile_standards = {
            "mcp-protocol-security": {"MCP-SPECIFICATION"},
            "cloud-provider-native-security": {
                "AWS-FOUNDATIONAL-SECURITY-BEST-PRACTICES",
                "MICROSOFT-CLOUD-SECURITY-BENCHMARK",
                "GCP-ENTERPRISE-FOUNDATIONS-BLUEPRINT",
            },
            "incident-response-service-maturity": {
                "FIRST-CSIRT-SERVICES-FRAMEWORK",
                "FIRST-PSIRT-SERVICES-FRAMEWORK",
            },
            "memory-safety-engineering": {"CISA-MEMORY-SAFE-ROADMAPS"},
            "organizational-ai-governance-impact": {"IEEE-2863", "IEEE-7010"},
            "organizational-resilience-bia": {"ISO-22316", "ISO-TS-22317"},
            "open-source-project-assurance": {"OPENSSF-BEST-PRACTICES-BADGE"},
            "isms-implementation-process": {"ISO-IEC-27003", "ISO-IEC-TS-27022"},
        }
        for identifier, required in profile_standards.items():
            with self.subTest(profile=identifier):
                profile = _ASSURANCE_PROFILES[identifier]
                self.assertTrue(required <= set(profile["standards"]))
                self.assertTrue(profile["controls"])
                self.assertTrue(profile["procedures"])

        contract_evidence = {
            "mcp-client-server-security-conformance": {
                "principal-session-delegation-oauth-resource-scope-token-redirect-and-revocation-results",
                "malformed-drift-confused-deputy-ssrf-injection-session-context-propagation-teardown-and-cleanup-results",
            },
            "aws-fsbp-securityhub-conformance": {
                "aws-account-ou-region-resource-and-coverage-inventory",
                "cloudtrail-cleanup-rescan-and-claim-boundary-record",
            },
            "microsoft-mcsb-defender-conformance": {
                "defender-assessment-exemption-and-remediation-trace",
                "activity-log-cleanup-rescan-and-preview-separation-record",
            },
            "gcp-enterprise-foundations-conformance": {
                "organization-policy-architecture-scc-deviation-and-remediation-trace",
                "audit-log-cleanup-rescan-and-claim-boundary-record",
            },
            "first-csirt-psirt-maturity-assessment": {
                "mandate-constituency-service-role-and-competence-map",
                "blinded-assessor-agreement-conflict-and-adjudication-record",
            },
            "memory-safety-engineering-conformance": {
                "static-sanitizer-fuzz-crash-and-regression-results",
                "migration-roadmap-parity-performance-and-reassessment-record",
            },
            "organizational-resilience-bia-exercise": {
                "impact-tolerance-rto-rpo-capacity-and-assumption-record",
                "disruption-degradation-failover-restoration-and-reconciliation-results",
            },
            "openssf-best-practices-badge-conformance": {
                "criterion-applicability-answer-source-and-freshness-map",
                "recomputed-level-independent-sample-and-claim-boundary-record",
            },
        }
        for identifier, required in contract_evidence.items():
            with self.subTest(benchmark=identifier):
                contract = _benchmark_runner_contract(
                    {"id": identifier, "version": "policy-pinned"}
                )
                self.assertTrue(
                    required <= set(contract["required_execution_evidence"])
                )

        watchlist = {item["id"] for item in _STANDARDS_WATCHLIST}
        self.assertTrue(
            {
                "MCP-SPECIFICATION-2026-RELEASE",
                "MICROSOFT-CLOUD-SECURITY-BENCHMARK-V2",
                "ISO-IEC-27003-NEXT-EDITION",
                "ISO-22316-NEXT-EDITION",
            }
            <= watchlist
        )

    def test_agent_iot_information_web_and_sector_gaps_are_executable(self) -> None:
        standards = {item["id"]: item for item in _STANDARDS}
        expected_standards = {
            "A2A-PROTOCOL",
            "GLOBALPLATFORM-SESIP",
            "EN-17927",
            "FIRST-TLP",
            "FIRST-IEP",
            "VERIS",
            "W3C-CSP-LEVEL-2",
            "W3C-SUBRESOURCE-INTEGRITY",
            "EU-DORA-RTS-ICT-RISK",
            "EU-DORA-RTS-INCIDENT-CLASSIFICATION",
            "EU-DORA-ITS-REGISTER-OF-INFORMATION",
            "EU-DORA-RTS-INCIDENT-REPORTING",
            "EU-DORA-ITS-INCIDENT-REPORTING",
            "EU-DORA-RTS-TLPT",
            "FFIEC-IT-HANDBOOK-DAM",
            "FFIEC-IT-HANDBOOK-AIO",
            "FFIEC-IT-HANDBOOK-INFORMATION-SECURITY",
            "BSI-C5",
            "FCC-CYBER-TRUST-MARK",
        }
        self.assertTrue(expected_standards <= set(standards))
        self.assertEqual(standards["A2A-PROTOCOL"]["version"], "1.0.0")
        self.assertEqual(
            standards["W3C-CSP-LEVEL-2"]["lifecycle"]["edition_status"],
            "final",
        )

        expected_profiles = {
            "a2a-protocol-security": {"A2A-PROTOCOL"},
            "sesip-iot-platform-evaluation": {
                "GLOBALPLATFORM-SESIP",
                "EN-17927",
            },
            "threat-intelligence-handling": {"FIRST-TLP", "FIRST-IEP", "VERIS"},
            "web-platform-defense": {
                "W3C-CSP-LEVEL-2",
                "W3C-SUBRESOURCE-INTEGRITY",
            },
            "dora-level2-financial-resilience": {"EU-DORA-RTS-TLPT"},
            "ffiec-banking-technology": {"FFIEC-IT-HANDBOOK-DAM"},
            "bsi-c5-cloud-assurance": {"BSI-C5"},
            "us-cyber-trust-mark": {"FCC-CYBER-TRUST-MARK"},
        }
        for identifier, required in expected_profiles.items():
            with self.subTest(profile=identifier):
                profile = _ASSURANCE_PROFILES[identifier]
                self.assertTrue(required <= set(profile["standards"]))
                self.assertTrue(profile["controls"])
                self.assertTrue(profile["procedures"])

        expected_contracts = {
            "a2a-protocol-security-conformance": {
                "principal-skill-task-message-artifact-and-subscription-authorization-trace",
                "downgrade-cross-tenant-credential-ssrf-replay-race-and-cleanup-results",
            },
            "sesip-iot-platform-evaluation-conformance": {
                "composition-certificate-vulnerability-change-and-expiry-results",
                "scheme-laboratory-evaluator-authority-and-negative-claim-record",
            },
            "first-tlp-iep-information-handling-conformance": {
                "stix-taxii-json-roundtrip-and-semantic-equivalence-report",
                "downgrade-removal-unauthorized-sharing-and-audit-negative-cases",
            },
            "veris-incident-schema-conformance": {
                "roundtrip-aggregate-deidentification-and-analytic-equivalence-results",
            },
            "w3c-web-platform-defense-conformance": {
                "redirect-cors-cdn-substitution-multi-policy-and-fallback-results",
            },
            "dora-level2-technical-standards-conformance": {
                "incident-classification-timeline-template-and-secure-channel-results",
            },
            "ffiec-it-handbook-assessment": {
                "retired-cat-exclusion-and-handbook-claim-boundary-review"
            },
            "bsi-c5-cloud-assurance-assessment": {
                "attestation-versus-certification-claim-boundary-review"
            },
            "fcc-cyber-trust-mark-conformance": {
                "forgery-copied-label-redirect-expiry-withdrawal-and-overclaim-results"
            },
        }
        for identifier, required in expected_contracts.items():
            with self.subTest(benchmark=identifier):
                contract = _benchmark_runner_contract(
                    {"id": identifier, "version": "policy-pinned"}
                )
                self.assertTrue(
                    required <= set(contract["required_execution_evidence"])
                )

        watchlist = {item["id"] for item in _STANDARDS_WATCHLIST}
        self.assertTrue(
            {
                "W3C-CSP-LEVEL-3",
                "W3C-SUBRESOURCE-INTEGRITY-2",
                "W3C-TRUSTED-TYPES",
                "BSI-TR-03183-PARTS-1-AND-3",
            }
            <= watchlist
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


def test_credentials_cloud_ast_privacy_and_sector_assurance_are_version_pinned() -> (
    None
):
    standards = {item["id"]: item for item in _STANDARDS}
    assert standards["OIDF-FAPI"]["version"] == "2.0-final-2025"
    assert standards["OIDF-FAPI"]["lifecycle"]["edition_status"] == "final"
    assert {
        "W3C-VC-DATA-MODEL",
        "OIDF-OPENID4VP",
        "OIDF-OPENID4VCI",
        "OIDF-OPENID4VC-HAIP",
        "CISA-SCUBA-M365",
        "CISA-SCUBA-GWS",
        "CIS-KUBERNETES-BENCHMARK",
        "LINDDUN-PRO",
        "GSMA-NESAS",
        "3GPP-SCAS",
        "VDA-ISA",
        "ENX-TISAX",
        "C2PA-CONTENT-CREDENTIALS",
        "PCI-MPOC",
        "PCI-P2PE",
    } <= standards.keys()

    assert {
        "digital-credential-security",
        "federal-saas-hardening",
        "kubernetes-hardening-conformance",
        "privacy-threat-modeling",
        "ast-modality-effectiveness",
        "telecom-equipment-assurance",
        "tisax-automotive-information-assurance",
        "content-provenance-authenticity",
        "payment-acceptance-security",
    } <= _ASSURANCE_PROFILES.keys()

    benchmark_ids = {item["id"] for item in _BENCHMARKS}
    assert {
        "openid-digital-credential-conformance",
        "cisa-scuba-saas-posture-conformance",
        "cis-kubernetes-hardening-conformance",
        "linddun-privacy-threat-model-conformance",
        "owasp-benchmark-ast-modality-comparison",
        "rasp-prevention-effectiveness",
        "gsma-nesas-scas-assurance",
        "tisax-vda-isa-assessment",
        "c2pa-content-credentials-conformance",
        "pci-payment-acceptance-conformance",
    } <= benchmark_ids

    watch_ids = {item["id"] for item in _STANDARDS_WATCHLIST}
    assert {
        "W3C-VC-DATA-MODEL-2.1",
        "OIDF-OPENID4VP-1.1",
        "VDA-ISA-2027",
        "FIDO-CTAP-2.3",
        "ENISA-EUCS",
        "ENISA-EUMSS",
        "ENISA-EUDIW-CERTIFICATION",
        "ENISA-EU5G",
    } <= watch_ids


def test_currency_profiles_are_pinned_and_catalog_references_fail_closed() -> None:
    standards = {item["id"]: item for item in _STANDARDS}
    assert standards["HITRUST-CSF"]["version"] == "11.8.0"
    assert standards["PCI-SECURE-SOFTWARE"]["version"] == "2.0-2026"
    assert standards["EU-EUDI-ARF"]["version"] == "3.0.0"
    assert standards["FIDO-CTAP"]["version"] == "2.2-proposed-standard-2025-07-14"
    assert {
        "fedramp-20x-continuous-assurance",
        "fido2-authenticator-assurance",
        "eudi-wallet-assurance",
        "hitrust-assessment-assurance",
        "pci-software-security-framework",
        "nis2-implementation-assurance",
        "supplier-due-diligence",
        "software-assurance-maturity",
    } <= _ASSURANCE_PROFILES.keys()

    broken = {
        "broken": {
            "standards": ["UNKNOWN"],
            "controls": [("UNKNOWN", "C", "objective", ["evidence.json"])],
            "procedures": [
                ("UNKNOWN", "P", "objective", "test", False, ["evidence.json"])
            ],
        }
    }
    with pytest.raises(ValueError, match="unknown standards"):
        _validate_builtin_catalog(profiles=broken)


def test_repository_embedded_logic_and_supply_chain_extensions_are_pinned() -> None:
    standards = {item["id"]: item for item in _STANDARDS}
    assert standards["OpenSSF-OSPS"]["version"] == "2026.08.28"
    assert standards["MITRE-EMB3D"]["version"] == "2.0.2"
    assert (
        standards["OWASP-BUSINESS-LOGIC-ABUSE-TOP-10"]["version"]
        == "2025-second-release"
    )
    assert (
        standards["CNCF-SOFTWARE-SUPPLY-CHAIN-BEST-PRACTICES"]["version"]
        == "v2-2025-policy-pinned"
    )
    assert {
        "repository-level-vulnerability-context",
        "embedded-device-threat-assurance",
        "business-logic-abuse-assurance",
        "cncf-supply-chain-practices-assurance",
        "public-vulnerable-application-testing",
        "statistical-fuzzing-evaluation",
        "sbom-build-truth-validation",
        "architecture-fitness-validation",
    } <= _ASSURANCE_PROFILES.keys()
    assert {
        "reposvul-repository-context-validation",
        "vuleval-repository-dependency-evaluation",
        "mitre-emb3d-property-threat-conformance",
        "owasp-business-logic-abuse-top10-conformance",
        "cncf-supply-chain-best-practices-v2-conformance",
        "owasp-api-security-testing-framework",
    } <= {item["id"] for item in _BENCHMARKS}

    watchlist = {item["id"]: item for item in _STANDARDS_WATCHLIST}
    assert watchlist["ISO-IEC-27091"]["status"] == "under-development"
    assert watchlist["OWASP-CLIENT-SIDE-TOP-10"]["status"] == "candidate"
    assert watchlist["VULNGYM"]["status"] == "research-preview"
    assert watchlist["SECVULEVAL"]["status"] == "research-preview"
    assert watchlist["SPDX-3.1"]["status"] == "release-candidate"
    assert watchlist["OWASP-BENCHMARK-PYTHON"]["status"] == "research-preview"


def test_identity_model_automotive_and_calibration_extensions_are_pinned() -> None:
    standards = {item["id"]: item for item in _STANDARDS}
    assert standards["IETF-SCIM-CURSOR-RFC9865"]["version"] == "RFC9865-2025-10"
    assert standards["IETF-SCIM-SET-RFC9967"]["version"] == "RFC9967-2026-03"
    assert standards["OPENID-SSF-1.0"]["version"] == "1.0-final-2025-09-02"
    assert standards["OPENSSF-MODEL-SIGNING"]["version"] == "1.0"
    assert standards["CYCLONEDX-MLBOM"]["version"] == "1.7"
    assert standards["UPTANE-STANDARD"]["version"] == "2.1.0"

    assert {
        "identity-lifecycle-continuous-access",
        "workload-identity-federation",
        "ai-ml-artifact-supply-chain",
        "automotive-secure-update-protocol",
        "open-source-criticality-prioritization",
    } <= _ASSURANCE_PROFILES.keys()
    assert {
        "scim-lifecycle-security-conformance",
        "openid-shared-signals-conformance",
        "spiffe-workload-identity-conformance",
        "openssf-model-signing-conformance",
        "cyclonedx-mlbom-conformance",
        "uptane-ota-security-conformance",
        "darpa-aixcc-autonomous-vulnerability-remediation",
        "openssf-criticality-score-calibration",
    } <= {item["id"] for item in _BENCHMARKS}

    watchlist = {item["id"]: item for item in _STANDARDS_WATCHLIST}
    assert watchlist["OPENID-SSF-CONFORMANCE"]["status"] == "alpha"
    assert watchlist["DARPA-AIXCC-PUBLIC-CORPUS"]["status"] == "research-transition"
    assert watchlist["SPIFFE-REMOTE-WORKLOAD-API"]["status"] == "experimental"


if __name__ == "__main__":
    unittest.main()
