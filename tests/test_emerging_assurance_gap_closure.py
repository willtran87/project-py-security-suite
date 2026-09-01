from __future__ import annotations

import json
from copy import deepcopy

import pytest

from py_security_suite.benchmark_adapters import benchmark_adapter_spec
from py_security_suite.industry_assurance import (
    _ASSURANCE_PROFILES,
    _BENCHMARKS,
    _LABORATORY_QUALIFIED_BENCHMARKS,
    _STANDARDS,
    _STANDARDS_WATCHLIST,
    _benchmark_protocol,
)
from py_security_suite.industry_emerging_assurance_catalog import (
    EMERGING_ASSURANCE_EVIDENCE_CONTRACTS,
)
from py_security_suite.industry_extension_evidence import (
    IndustryExtensionEvidenceError,
    industry_extension_runner_requirements,
    validate_industry_extension_evidence,
)


SOURCE = "a" * 64
SUBJECT = "b" * 64


def _claims(identifier: str) -> dict[str, object]:
    contract = EMERGING_ASSURANCE_EVIDENCE_CONTRACTS[identifier]
    claims: dict[str, object] = dict(contract["scalars"])
    claims.update({name: sorted(values) for name, values in contract["sets"].items()})
    claims.update(dict.fromkeys(contract["counts"], 3))
    claims.update(dict.fromkeys(contract["required_true"], True))
    claims.update(dict.fromkeys(contract["required_false"], False))
    return claims


def _evidence(identifier: str) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "integration": identifier,
        "source_sha256": SOURCE,
        "subject_sha256": SUBJECT,
        "execution": {
            "isolated": True,
            "network_policy": "deny",
            "repetitions": 3,
            "budget_seconds": 1800,
        },
        "claims": _claims(identifier),
        "negative_cases": [
            {"id": "source-edition-tamper", "detected": True},
            {"id": "subject-authority-misbinding", "detected": True},
            {"id": "unsupported-assurance-claim", "detected": True},
        ],
        "provenance": {
            "producer": "digest-pinned-emerging-assurance-normalizer",
            "producer_sha256": "c" * 64,
            "signature_verified": True,
            "independent_replay_verified": True,
        },
        "complete": True,
    }


def test_emerging_assurance_catalog_is_complete_and_protocol_bound() -> None:
    assert {
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
        "ETSI-EN-304-223",
        "FIVE-EYES-AGENTIC-AI-GUIDANCE",
        "NSA-MCP-SECURITY-GUIDANCE",
        "CSA-MAESTRO",
        "OWASP-FIASSE",
    } <= {str(item["id"]) for item in _STANDARDS}
    assert {
        "cis-cloud-container-hardening",
        "owasp-genai-red-team-assurance",
        "imda-ai-verify-moonshot-assurance",
        "ncsc-check-penetration-testing",
        "aiuc1-agent-assurance",
        "csa-iot-controls-alignment",
        "etsi-ai-cybersecurity-baseline",
        "agentic-adoption-and-containment",
        "mcp-high-assurance-automation",
        "fiasse-securability-engineering",
    } <= set(_ASSURANCE_PROFILES)
    assert set(EMERGING_ASSURANCE_EVIDENCE_CONTRACTS) <= {
        str(item["id"]) for item in _BENCHMARKS
    }
    for identifier in EMERGING_ASSURANCE_EVIDENCE_CONTRACTS:
        assert _benchmark_protocol(identifier) == "conformance"

    versions = {str(item["id"]): str(item["version"]) for item in _STANDARDS}
    assert versions["OWASP-LLM-TOP-10"] == "2026"
    assert versions["OWASP-TCASVS"] == "5.0.1"


def test_immature_sources_are_quarantined_not_active() -> None:
    active = {str(item["id"]) for item in _STANDARDS}
    watched = {str(item["id"]): item for item in _STANDARDS_WATCHLIST}
    assert "NCSC-CYAS-MVP" not in active
    assert "COSAI-MCP-SECURITY-GUIDANCE" not in active
    assert "EU-CRA-M606-HARMONISED-STANDARDS" not in active
    assert "ETSI-CRA-17-VERTICAL-DRAFT-STANDARDS" not in active
    assert "OWASP-AIVSS" not in active
    assert watched["NCSC-CYAS-MVP"]["status"] == "scheme-in-development-mvp"
    assert (
        watched["COSAI-MCP-SECURITY-GUIDANCE"]["status"]
        == "guidance-crosswalk-candidate"
    )
    assert watched["EU-CRA-M606-HARMONISED-STANDARDS"]["status"] == "under-development"
    assert watched["ETSI-CRA-17-VERTICAL-DRAFT-STANDARDS"]["status"] == "public-enquiry"
    assert watched["OWASP-AIVSS"]["stage"] == "v0.8-experimental-scoring"


def test_emerging_adapters_are_pinned_isolated_and_claim_bounded() -> None:
    boundaries = {
        "cis-aws-foundations-conformance": "no CIS certification claim",
        "cis-azure-foundations-conformance": "no CIS certification claim",
        "cis-gcp-foundations-conformance": "no CIS certification claim",
        "cis-docker-conformance": "no CIS certification claim",
        "owasp-genai-red-team-assurance": "no OWASP certification",
        "imda-ai-verify-moonshot-assurance": "no IMDA",
        "ncsc-check-engagement-assurance": "no inferred CHECK provider status",
        "aiuc1-agent-assurance": "no suite-issued AIUC-1 certificate",
        "csa-iot-controls-conformance": "no CSA or product certification",
        "etsi-ai-cybersecurity-lifecycle-conformance": "no ETSI certification",
        "agentic-evaluator-containment-assurance": "outer enforcement boundary",
        "fiasse-securability-assurance": "no claim that SSEM beta scores prove security",
    }
    for identifier, boundary in boundaries.items():
        adapter = benchmark_adapter_spec(identifier)
        assert adapter["protocol"] == "conformance"
        assert len(adapter["required_inputs"]) == 5
        assert adapter["acquisition"]["signed_provenance_required"] is True
        assert adapter["acquisition"]["replay_ledger_required"] is True
        assert boundary in adapter["isolation"]
        requirements = industry_extension_runner_requirements(identifier)
        assert "publisher-edition-license-and-source-digest-lock" in requirements
        assert (
            "independent-replay-remediation-cleanup-restoration-and-retest-ledger"
            in requirements
        )

    assert {
        "owasp-genai-red-team-assurance",
        "imda-ai-verify-moonshot-assurance",
        "ncsc-check-engagement-assurance",
        "aiuc1-agent-assurance",
        "csa-iot-controls-conformance",
    } <= _LABORATORY_QUALIFIED_BENCHMARKS


@pytest.mark.parametrize("identifier", sorted(EMERGING_ASSURANCE_EVIDENCE_CONTRACTS))
def test_emerging_evidence_is_exact_subject_bound_and_fail_closed(
    identifier: str,
) -> None:
    document = _evidence(identifier)
    assert (
        validate_industry_extension_evidence(
            json.dumps(document),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )
        == document
    )

    contract = EMERGING_ASSURANCE_EVIDENCE_CONTRACTS[identifier]
    invalid = deepcopy(document)
    invalid["claims"][contract["required_false"][0]] = True  # type: ignore[index]
    with pytest.raises(IndustryExtensionEvidenceError, match="boundaries must hold"):
        validate_industry_extension_evidence(
            json.dumps(invalid),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )

    invalid = deepcopy(document)
    invalid["claims"][contract["required_true"][0]] = False  # type: ignore[index]
    with pytest.raises(IndustryExtensionEvidenceError, match="checks must pass"):
        validate_industry_extension_evidence(
            json.dumps(invalid),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )

    set_name = next(iter(contract["sets"]))
    invalid = deepcopy(document)
    invalid["claims"][set_name] = ["substituted-surface"]  # type: ignore[index]
    with pytest.raises(IndustryExtensionEvidenceError, match="exact governed set"):
        validate_industry_extension_evidence(
            json.dumps(invalid),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )
