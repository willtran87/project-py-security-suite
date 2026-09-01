from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from py_security_suite.assurance_catalog import (
    AssuranceCatalogError,
    build_standards_source_manifest,
    export_assurance_catalog,
)
from py_security_suite.industry_assurance import _validate_policy
from py_security_suite.report_inspection import read_bundled_schema


def test_catalog_export_is_complete_deterministic_and_schema_valid() -> None:
    first = export_assurance_catalog()
    second = export_assurance_catalog()

    assert first == second
    assert first["counts"]["standards"] == 663
    assert first["counts"]["profiles"] == 233
    assert first["counts"]["benchmarks"] == 282
    assert first["counts"]["adapter_specs"] == 212
    assert first["counts"]["execution_contracts"] == 212
    assert len(first["catalog_sha256"]) == 64
    components = first["components"]
    assert {
        "OIDF-AUTHZEN-AUTHORIZATION-API",
        "OIDF-OPENID-FEDERATION",
        "OIDF-OPENID-FEDERATION-CONNECT",
        "NIST-SP-800-223",
        "NIST-SP-800-234",
        "ISO-IEC-24760-1",
        "ISO-IEC-24760-2",
        "ISO-IEC-24760-3",
        "ISO-IEC-TR-5259-6",
        "AWWA-J100",
        "NENA-STA-040",
        "EU-GMP-ANNEX-11",
        "NIST-IR-8576",
        "ISO-22320",
        "NIST-IR-8374-R1",
        "NIST-SP-800-88-R2",
        "IEC-TS-62443-6-1",
        "ISO-22361",
        "NIST-SP-1347",
        "OWASP-OPENCRE",
        "OPENSSF-GEMARA",
        "UK-CBEST",
        "OCP-SAFE",
        "OCP-SOLID",
        "DOE-C2M2",
        "FINOS-CCC",
        "NCSC-CRT-APC",
        "NCSC-CRTF-SCHEME",
        "UK-SOFTWARE-SECURITY-CODE-OF-PRACTICE",
        "NIST-PRAM",
        "NIST-IR-8062",
        "ITIL-4",
        "CIS-AWS-FOUNDATIONS",
        "CIS-AZURE-FOUNDATIONS",
        "CIS-GCP-FOUNDATIONS",
        "CIS-DOCKER",
        "OWASP-GENAI-RED-TEAMING-GUIDE",
        "IMDA-AI-VERIFY",
        "IMDA-PROJECT-MOONSHOT",
        "NCSC-CHECK",
        "AIUC-1",
        "CSA-IOT-SECURITY-CONTROLS-FRAMEWORK",
    } <= {item["id"] for item in components["standards"]}
    assert {
        "NIST-SP-800-239",
        "OASIS-OPENEOX-1.0",
        "OASIS-CSAF-2.1",
        "NIST-IR-8546",
        "EU-GMP-ANNEX-11-REVISION",
        "NIST-SP-800-82-R4",
        "NIST-SP-1353",
        "NCSC-CYAS-MVP",
        "COSAI-MCP-SECURITY-GUIDANCE",
    } <= {item["id"] for item in components["standards_watchlist"]}
    schema = json.loads(read_bundled_schema("assurance-catalog-export-1.0"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(first)


def test_standards_manifest_builder_verifies_baselines_and_impact(
    tmp_path: Path,
) -> None:
    baseline = tmp_path / "owasp-asvs.html"
    baseline.write_text("publisher snapshot", encoding="utf-8")
    inventory = {
        "schema_version": "1.0",
        "baselines": [
            {
                "id": "OWASP-ASVS",
                "publisher": "OWASP Foundation",
                "baseline_path": baseline.name,
                "baseline_sha256": hashlib.sha256(baseline.read_bytes()).hexdigest(),
                "media_type": "text/html",
                "maximum_bytes": 4096,
            }
        ],
    }
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(inventory), encoding="utf-8")

    manifest = build_standards_source_manifest(path, selected_ids={"OWASP-ASVS"})

    assert manifest["allowed_hosts"] == ["owasp.org"]
    assert (
        manifest["sources"][0]["baseline_sha256"]
        == inventory["baselines"][0]["baseline_sha256"]
    )
    assert manifest["sources"][0]["impact"]["profiles"]
    schema = json.loads(read_bundled_schema("standards-source-manifest-1.0"))
    Draft202012Validator(schema).validate(manifest)

    inventory["baselines"][0]["baseline_sha256"] = "0" * 64
    path.write_text(json.dumps(inventory), encoding="utf-8")
    with pytest.raises(AssuranceCatalogError, match="digest does not match"):
        build_standards_source_manifest(path, selected_ids={"OWASP-ASVS"})


def test_new_policy_and_preparation_examples_match_their_contracts() -> None:
    examples = Path("examples")
    policy = json.loads(
        (examples / "industry-assurance-policy-1.3.example.json").read_text(
            encoding="utf-8"
        )
    )
    request = json.loads(
        (examples / "benchmark-preparation-request.example.json").read_text(
            encoding="utf-8"
        )
    )

    _validate_policy(policy)
    Draft202012Validator(
        json.loads(read_bundled_schema("industry-assurance-policy-1.3"))
    ).validate(policy)
    assert {
        "autonomous-vulnerability-research",
        "open-source-security-metadata-graph",
        "forge-independent-source-integrity",
        "malicious-package-behavior",
        "cloud-native-delivery-risk-taxonomies",
        "build-observed-sbom-assurance",
        "real-world-vulnerability-generalization",
        "mobile-risk-taxonomy-assurance",
        "smart-contract-security-assurance",
        "cloud-native-lifecycle-control-assurance",
        "repository-level-vulnerability-context",
        "embedded-device-threat-assurance",
        "business-logic-abuse-assurance",
        "cncf-supply-chain-practices-assurance",
        "public-vulnerable-application-testing",
        "statistical-fuzzing-evaluation",
        "sbom-build-truth-validation",
        "architecture-fitness-validation",
        "identity-lifecycle-continuous-access",
        "workload-identity-federation",
        "ai-ml-artifact-supply-chain",
        "automotive-secure-update-protocol",
        "open-source-criticality-prioritization",
        "authorization-decision-interoperability",
        "openid-federation-security",
        "hpc-ai-infrastructure-security",
        "identity-management-framework",
        "cis-cloud-container-hardening",
        "owasp-genai-red-team-assurance",
        "imda-ai-verify-moonshot-assurance",
        "ncsc-check-penetration-testing",
        "aiuc1-agent-assurance",
        "csa-iot-controls-alignment",
    } <= {item["id"] for item in policy["profiles"]}
    assert {
        "oss-crs-crsbench",
        "openssf-security-insights-conformance",
        "guac-interoperability",
        "gittuf-source-policy-conformance",
        "openssf-package-analysis-malicious-packages",
        "owasp-kubernetes-top10-conformance",
        "owasp-cicd-top10-conformance",
        "sbomit-build-observed-sbom",
        "primevul-real-world-vulnerability-detection",
        "diversevul-unseen-project-generalization",
        "cvefixes-chronological-fix-pair-validation",
        "owasp-mobile-top10-conformance",
        "owasp-smart-contract-top10-conformance",
        "cncf-cloud-native-security-controls-conformance",
        "reposvul-repository-context-validation",
        "vuleval-repository-dependency-evaluation",
        "mitre-emb3d-property-threat-conformance",
        "owasp-business-logic-abuse-top10-conformance",
        "cncf-supply-chain-best-practices-v2-conformance",
        "owasp-api-security-testing-framework",
        "scim-lifecycle-security-conformance",
        "openid-shared-signals-conformance",
        "spiffe-workload-identity-conformance",
        "openssf-model-signing-conformance",
        "cyclonedx-mlbom-conformance",
        "uptane-ota-security-conformance",
        "darpa-aixcc-autonomous-vulnerability-remediation",
        "openssf-criticality-score-calibration",
        "authzen-authorization-api-conformance",
        "openid-federation-conformance",
        "nist-hpc-ai-infrastructure-assurance",
        "iso-24760-identity-management-assurance",
        "iso-5259-6-data-quality-visualization",
        "cis-aws-foundations-conformance",
        "cis-azure-foundations-conformance",
        "cis-gcp-foundations-conformance",
        "cis-docker-conformance",
        "owasp-genai-red-team-assurance",
        "imda-ai-verify-moonshot-assurance",
        "ncsc-check-engagement-assurance",
        "aiuc1-agent-assurance",
        "csa-iot-controls-conformance",
    } <= {item["id"] for item in policy["benchmarks"]}
    Draft202012Validator(
        json.loads(read_bundled_schema("benchmark-preparation-request-1.0"))
    ).validate(request)
