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
    _benchmark_protocol,
)
from py_security_suite.industry_extension_evidence import (
    IndustryExtensionEvidenceError,
    industry_extension_runner_requirements,
    validate_industry_extension_evidence,
)
from py_security_suite.industry_maturity_product_catalog import (
    MATURITY_PRODUCT_EVIDENCE_CONTRACTS,
)


SOURCE = "d" * 64
SUBJECT = "e" * 64


def _claims(identifier: str) -> dict[str, object]:
    contract = MATURITY_PRODUCT_EVIDENCE_CONTRACTS[identifier]
    claims: dict[str, object] = dict(contract["scalars"])
    claims.update({name: sorted(values) for name, values in contract["sets"].items()})
    claims.update({name: 3 for name in contract["counts"]})
    claims.update({name: True for name in contract["required_true"]})
    claims.update({name: False for name in contract["required_false"]})
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
            {"id": "source-version-tamper", "detected": True},
            {"id": "subject-scope-misbinding", "detected": True},
            {"id": "unsupported-assurance-claim", "detected": True},
        ],
        "provenance": {
            "producer": "digest-pinned-maturity-product-normalizer",
            "producer_sha256": "f" * 64,
            "signature_verified": True,
            "independent_replay_verified": True,
        },
        "complete": True,
    }


def test_maturity_product_catalog_is_complete_and_protocol_bound() -> None:
    assert {
        "DOE-C2M2",
        "FINOS-CCC",
        "NCSC-CRT-APC",
        "NCSC-CRTF-SCHEME",
        "UK-SOFTWARE-SECURITY-CODE-OF-PRACTICE",
        "NIST-PRAM",
        "NIST-IR-8062",
        "ITIL-4",
    } <= {str(item["id"]) for item in _STANDARDS}
    assert {
        "c2m2-capability-maturity",
        "finos-common-cloud-controls",
        "ncsc-product-cyber-resilience-testing",
        "nist-pram-privacy-risk-assessment",
        "itil4-service-management-alignment",
    } <= set(_ASSURANCE_PROFILES)
    assert set(MATURITY_PRODUCT_EVIDENCE_CONTRACTS) <= {
        str(item["id"]) for item in _BENCHMARKS
    }
    for identifier in MATURITY_PRODUCT_EVIDENCE_CONTRACTS:
        assert _benchmark_protocol(identifier) == "conformance"
    assert "ncsc-product-cyber-resilience-testing" in _LABORATORY_QUALIFIED_BENCHMARKS


def test_maturity_product_adapters_are_pinned_and_claim_bounded() -> None:
    boundaries = {
        "doe-c2m2-capability-assessment": "no DOE endorsement",
        "finos-ccc-cloud-control-conformance": "no FINOS",
        "ncsc-product-cyber-resilience-testing": "no NCSC approval",
        "nist-pram-privacy-risk-assessment": "no legal-compliance",
        "itil4-service-management-outcome-assurance": "no PeopleCert",
    }
    for identifier, boundary in boundaries.items():
        adapter = benchmark_adapter_spec(identifier)
        assert adapter["protocol"] == "conformance"
        assert len(adapter["required_inputs"]) == 5
        assert adapter["acquisition"]["signed_provenance_required"] is True
        assert adapter["acquisition"]["replay_ledger_required"] is True
        assert boundary in adapter["isolation"]
        requirements = industry_extension_runner_requirements(identifier)
        assert "publisher-version-license-and-source-digest-lock" in requirements
        assert (
            "independent-assessment-adjudication-remediation-and-retest-ledger"
            in requirements
        )
        assert (
            "no-endorsement-accreditation-certification-or-legal-compliance-claim-policy"
            in requirements
        )


@pytest.mark.parametrize("identifier", sorted(MATURITY_PRODUCT_EVIDENCE_CONTRACTS))
def test_maturity_product_evidence_is_strict_and_subject_bound(identifier: str) -> None:
    document = _evidence(identifier)
    assert (
        validate_industry_extension_evidence(
            json.dumps(document),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )
        == document
    )

    contract = MATURITY_PRODUCT_EVIDENCE_CONTRACTS[identifier]
    false_claim = contract["required_false"][0]
    invalid = deepcopy(document)
    invalid["claims"][false_claim] = True  # type: ignore[index]
    with pytest.raises(IndustryExtensionEvidenceError, match="boundaries must hold"):
        validate_industry_extension_evidence(
            json.dumps(invalid),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )

    true_claim = contract["required_true"][0]
    invalid = deepcopy(document)
    invalid["claims"][true_claim] = False  # type: ignore[index]
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


def test_maturity_product_profiles_retain_conditional_boundaries() -> None:
    itil = _ASSURANCE_PROFILES["itil4-service-management-alignment"]
    assert "ITIL-4" in itil["standards"]
    assert any("licensed" in str(control[2]).lower() for control in itil["controls"])
    crt = _ASSURANCE_PROFILES["ncsc-product-cyber-resilience-testing"]
    assert {"NCSC-CRT-APC", "NCSC-CRTF-SCHEME"} <= set(crt["standards"])
    assert any(
        "separating suite readiness" in str(control[2]).lower()
        for control in crt["controls"]
    )
