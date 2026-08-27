from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from jsonschema import Draft202012Validator

from py_security_suite import domain_assurance as domain_assurance_module
from py_security_suite.artifact_validation import validate_governed_artifacts
from py_security_suite.domain_assurance import analyze_domain_assurance
from py_security_suite.report_inspection import read_bundled_schema


def _domain(artifact: dict[str, object], name: str) -> dict[str, object]:
    domains = artifact["domains"]
    assert isinstance(domains, list)
    return next(item for item in domains if item["name"] == name)


def _requirement(
    *,
    requirement_id: str = "checkout-value",
    evidence: list[str] | None = None,
    tests: list[str] | None = None,
) -> dict[str, object]:
    return {
        "id": requirement_id,
        "kind": "value-conservation",
        "objective": "The charged total equals the authorized cart total.",
        "subjects": ["checkout"],
        "evidence_artifacts": evidence or [],
        "test_ids": tests or [],
        "enforcement_points": ["src/checkout.py:charge"],
    }


def _policy(domain: dict[str, object], *, enforce: bool = False) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "enforce_inferred_domains": enforce,
        "domains": [domain],
    }


def test_infers_specialized_domains_without_claiming_vulnerabilities(
    tmp_path: Path,
) -> None:
    (tmp_path / "analysis.ipynb").write_text("{}", encoding="utf-8")
    (tmp_path / "contract.sol").write_text("contract Vault {}", encoding="utf-8")
    (tmp_path / "platformio.ini").write_text("[env:test]\n", encoding="utf-8")
    (tmp_path / "electron-builder.yml").write_text("appId: test\n", encoding="utf-8")
    detections = tmp_path / "detections"
    detections.mkdir()
    (detections / "rule.sigma").write_text("title: test\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "\n".join(
            (
                "import authlib",
                "import chalice",
                "import cryptography",
                "import graphql",
                "import pandas",
                "import pymodbus",
                "import requests",
                "import slowapi",
                "import smtplib",
                "import spiffe",
                "import django.contrib.admin",
                "import etcd3",
                "import hvac",
                "import lxml",
                "import mlflow",
                "import opentelemetry",
                "patient_email = 'test@example.invalid'",
                "tenant_id = 'tenant'",
                "webhook_signature = 'verified'",
                "incident_response = 'exercised'",
                "security_confirmation = 'phishing_resistant'",
                "dev_container = 'governed'",
                "content_moderation = 'redress'",
                "enclave_attestation = 'fresh'",
                "sanctions_screening = 'maker_checker'",
                "facility_access = 'tamper_monitored'",
            )
        )
        + "\n",
        encoding="utf-8",
    )

    findings, artifact = analyze_domain_assurance(tmp_path, {})

    assert findings == []
    for name in (
        "privacy-lifecycle",
        "detection-engineering",
        "cryptographic-agility",
        "notebook-security",
        "desktop-client-security",
        "firmware-iot-security",
        "web3-security",
        "graphql-security",
        "identity-assurance",
        "tenant-isolation",
        "abuse-resistance",
        "workload-identity",
        "integration-security",
        "incident-response-recovery",
        "data-integrity-lineage",
        "serverless-edge-security",
        "external-asset-communication",
        "ot-ics-safety",
        "privileged-control-plane",
        "distributed-temporal-correctness",
        "secure-human-interaction",
        "ml-model-data-supply-chain",
        "credential-secret-lifecycle",
        "observability-integrity",
        "developer-environment-security",
        "parser-content-security",
        "trust-safety",
        "confidential-computing-side-channels",
        "regulated-transaction-integrity",
        "physical-environmental-security",
    ):
        assert _domain(artifact, name)["status"] == "unmodeled"
    assert artifact["coverage_complete"] is False
    assert "applicability, not vulnerability" in artifact["claim_boundary"]
    validate_governed_artifacts({"domain-assurance.json": artifact})


def test_declared_requirement_requires_named_artifact_and_passing_test(
    tmp_path: Path,
) -> None:
    policy_dir = tmp_path / "security"
    policy_dir.mkdir()
    source = tmp_path / "src"
    source.mkdir()
    source.joinpath("checkout.py").write_text("def charge(): pass\n", encoding="utf-8")
    policy_dir.joinpath("domain-assurance-policy.json").write_text(
        json.dumps(
            _policy(
                {
                    "name": "business-logic",
                    "applicable": True,
                    "owner": "payments-platform",
                    "requirements": [
                        _requirement(
                            evidence=["application-contract-analysis.json"],
                            tests=["tests/test_checkout.py::test_value_conservation"],
                        )
                    ],
                }
            )
        ),
        encoding="utf-8",
    )
    artifacts = {
        "application-contract-analysis.json": {
            "observed_test_cases": [
                {
                    "id": "tests/test_checkout.py::test_value_conservation",
                    "result": "passed",
                    "source_bound": True,
                }
            ],
        }
    }

    findings, artifact = analyze_domain_assurance(tmp_path, artifacts)

    business = _domain(artifact, "business-logic")
    assert findings == []
    assert business["status"] == "covered"
    assert business["requirements_satisfied"] == 1
    assert artifact["coverage_score"] == 100
    validate_governed_artifacts({"domain-assurance.json": artifact})


def test_policy_gap_and_false_non_applicability_are_fail_visible(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text("import fastapi\n", encoding="utf-8")
    policy_dir = tmp_path / "security"
    policy_dir.mkdir()
    policy_dir.joinpath("domain-assurance-policy.json").write_text(
        json.dumps(
            _policy(
                {
                    "name": "business-logic",
                    "applicable": False,
                    "owner": "platform-security",
                    "requirements": [],
                }
            )
        ),
        encoding="utf-8",
    )

    findings, artifact = analyze_domain_assurance(tmp_path, {})

    business = _domain(artifact, "business-logic")
    assert business["status"] == "partial"
    assert "conflicts" in business["gaps"][0]
    assert len(findings) == 1
    assert findings[0].severity.value == "high"
    validate_governed_artifacts({"domain-assurance.json": artifact})


def test_unbound_tests_incomplete_artifacts_and_missing_points_do_not_count(
    tmp_path: Path,
) -> None:
    policy_dir = tmp_path / "security"
    policy_dir.mkdir()
    policy_dir.joinpath("domain-assurance-policy.json").write_text(
        json.dumps(
            _policy(
                {
                    "name": "business-logic",
                    "applicable": True,
                    "owner": "payments-platform",
                    "requirements": [
                        _requirement(
                            evidence=["event-security-summary.json"],
                            tests=["tests/test_checkout.py::test_value_conservation"],
                        )
                    ],
                }
            )
        ),
        encoding="utf-8",
    )
    artifacts = {
        "event-security-summary.json": {"complete": False},
        "junit-summary.json": {
            "test_cases": [
                {
                    "id": "tests/test_checkout.py::test_value_conservation",
                    "result": "passed",
                }
            ]
        },
    }

    findings, artifact = analyze_domain_assurance(tmp_path, artifacts)

    requirement = _domain(artifact, "business-logic")["requirements"][0]
    assert requirement["status"] == "gap"
    assert requirement["incomplete_evidence_artifacts"] == [
        "event-security-summary.json"
    ]
    assert requirement["missing_test_ids"] == [
        "tests/test_checkout.py::test_value_conservation"
    ]
    assert requirement["missing_enforcement_points"] == ["src/checkout.py:charge"]
    assert len(findings) == 1
    validate_governed_artifacts({"domain-assurance.json": artifact})


def test_invalid_policy_is_incomplete_and_blocks_semantic_overstatement(
    tmp_path: Path,
) -> None:
    policy_dir = tmp_path / "security"
    policy_dir.mkdir()
    policy_dir.joinpath("domain-assurance-policy.json").write_text(
        '{"schema_version":"1.0","domains":[]}', encoding="utf-8"
    )

    findings, artifact = analyze_domain_assurance(tmp_path, {})

    assert artifact["complete"] is False
    assert artifact["policy_present"] is True
    assert findings[0].classifications == ["DOMAIN-ASSURANCE-POLICY-INVALID"]
    validate_governed_artifacts({"domain-assurance.json": artifact})
    artifact["coverage_score"] = 0
    with pytest.raises(ValueError, match="accounting"):
        validate_governed_artifacts({"domain-assurance.json": artifact})


def test_domain_policy_schema_is_bundled() -> None:
    schema = json.loads(read_bundled_schema("domain-assurance-policy-1.0"))
    artifact_schema = json.loads(read_bundled_schema("domain-assurance-1.0"))
    example = json.loads(
        Path(__file__)
        .parents[1]
        .joinpath("examples/domain-assurance-policy.example.json")
        .read_text(encoding="utf-8")
    )

    assert schema["$id"].endswith("domain-assurance-policy:1.0")
    Draft202012Validator(schema).validate(example)
    assert len(example["domains"]) == 33
    assert len({item["name"] for item in example["domains"]}) == 33
    expected_domains = set(domain_assurance_module._DOMAINS)
    expected_kinds = domain_assurance_module._REQUIREMENT_KINDS
    assert set(schema["$defs"]["domainName"]["enum"]) == expected_domains
    assert set(artifact_schema["$defs"]["domainName"]["enum"]) == expected_domains
    assert {item["name"] for item in example["domains"]} == expected_domains
    assert set(schema["$defs"]["requirementKind"]["enum"]) == expected_kinds
    assert set(artifact_schema["$defs"]["requirementKind"]["enum"]) == expected_kinds


def test_supporting_examples_do_not_activate_runtime_domains(tmp_path: Path) -> None:
    examples = tmp_path / "examples"
    examples.mkdir()
    examples.joinpath("all-domains.json").write_text(
        json.dumps({"webhook": "spiffe", "tenant_id": "fraud", "dnssec": "modbus"}),
        encoding="utf-8",
    )

    findings, artifact = analyze_domain_assurance(tmp_path, {})

    assert findings == []
    assert artifact["applicable_domains"] == 0


def test_generic_ai_and_secret_scan_evidence_do_not_imply_lifecycle_domains(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text(
        "from openai import OpenAI\nclient = OpenAI()\n", encoding="utf-8"
    )
    artifacts = {
        "ai-security-summary.json": {"complete": True},
        "secret-verification-summary.json": {"complete": True},
    }

    _, artifact = analyze_domain_assurance(tmp_path, artifacts)

    assert _domain(artifact, "ml-model-data-supply-chain")["applicable"] is False
    assert _domain(artifact, "credential-secret-lifecycle")["applicable"] is False


def test_bounded_configuration_signals_activate_new_domains(tmp_path: Path) -> None:
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    deploy.joinpath("security.yaml").write_text(
        "\n".join(
            (
                "identity_provider: oidc",
                "tenant_context: required",
                "fraud_control: rate_limit",
                "workload_identity: spiffe",
                "webhook_signature: required",
                "incident_response: exercised",
                "data_lineage: reconciled",
                "runtime: aws_lambda",
                "email_authentication: dmarc",
                "industrial_protocol: modbus",
                "admin_console: break_glass",
                "consensus: quorum_and_clock_skew",
                "security_confirmation: phishing_resistant",
                "model_registry: provenance_required",
                "credential_rotation: emergency",
                "telemetry_authentication: required",
                "dev_container: extensions_governed",
                "archive_bomb: expansion_bounded",
                "content_moderation: redress",
                "enclave_attestation: fresh",
                "sanctions_screening: maker_checker",
                "facility_access: tamper_monitored",
            )
        )
        + "\n",
        encoding="utf-8",
    )

    _, artifact = analyze_domain_assurance(tmp_path, {})

    for name in (
        "identity-assurance",
        "tenant-isolation",
        "abuse-resistance",
        "workload-identity",
        "integration-security",
        "incident-response-recovery",
        "data-integrity-lineage",
        "serverless-edge-security",
        "external-asset-communication",
        "ot-ics-safety",
        "privileged-control-plane",
        "distributed-temporal-correctness",
        "secure-human-interaction",
        "ml-model-data-supply-chain",
        "credential-secret-lifecycle",
        "observability-integrity",
        "developer-environment-security",
        "parser-content-security",
        "trust-safety",
        "confidential-computing-side-channels",
        "regulated-transaction-integrity",
        "physical-environmental-security",
    ):
        assert _domain(artifact, name)["status"] == "unmodeled"


def test_source_byte_budget_is_fail_visible(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import authlib\n", encoding="utf-8")

    with patch("py_security_suite.domain_assurance._MAX_TOTAL_SOURCE_BYTES", 1):
        _, artifact = analyze_domain_assurance(tmp_path, {})

    assert artifact["complete"] is False
    assert artifact["truncated"] is True
    assert artifact["parse_errors"] == ["domain assurance source byte budget exhausted"]
