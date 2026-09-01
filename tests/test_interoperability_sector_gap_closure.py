from __future__ import annotations

import json
from copy import deepcopy

import pytest

from py_security_suite.benchmark_adapters import benchmark_adapter_spec
from py_security_suite.industry_assurance import (
    _ASSURANCE_PROFILES,
    _BENCHMARKS,
    _INTEROPERABILITY,
    _LABORATORY_QUALIFIED_BENCHMARKS,
    _STANDARDS,
    _benchmark_protocol,
)
from py_security_suite.industry_benchmark_catalog import _STANDARDS_WATCHLIST
from py_security_suite.industry_extension_evidence import (
    IndustryExtensionEvidenceError,
    industry_extension_runner_requirements,
    validate_industry_extension_evidence,
)
from py_security_suite.industry_interoperability_sector_catalog import (
    INTEROPERABILITY_SECTOR_EVIDENCE_CONTRACTS,
)


SOURCE = "a" * 64
SUBJECT = "b" * 64


def _claims(identifier: str) -> dict[str, object]:
    contract = INTEROPERABILITY_SECTOR_EVIDENCE_CONTRACTS[identifier]
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
            {"id": "source-tamper", "detected": True},
            {"id": "subject-misbinding", "detected": True},
            {"id": "domain-false-assurance", "detected": True},
        ],
        "provenance": {
            "producer": "digest-pinned-interoperability-sector-normalizer",
            "producer_sha256": "c" * 64,
            "signature_verified": True,
            "independent_replay_verified": True,
        },
        "complete": True,
    }


def test_gap_closure_catalog_is_complete_and_protocol_bound() -> None:
    standard_ids = {str(item["id"]) for item in _STANDARDS}
    assert {
        "OWASP-OPENCRE",
        "OPENSSF-GEMARA",
        "UK-CBEST",
        "OCP-SAFE",
        "OCP-SOLID",
    } <= standard_ids
    assert {
        "control-knowledge-interoperability",
        "uk-financial-cbest-assurance",
        "ocp-safe-hardware-firmware-assurance",
    } <= set(_ASSURANCE_PROFILES)
    benchmark_ids = {str(item["id"]) for item in _BENCHMARKS}
    assert set(INTEROPERABILITY_SECTOR_EVIDENCE_CONTRACTS) <= benchmark_ids
    assert (
        _benchmark_protocol("opencre-gemara-control-interoperability") == "conformance"
    )
    assert _benchmark_protocol("cbest-threat-led-assurance") == "detection-evaluation"
    assert _benchmark_protocol("ocp-safe-hardware-firmware-assurance") == "conformance"
    assert {
        "cbest-threat-led-assurance",
        "ocp-safe-hardware-firmware-assurance",
    } <= _LABORATORY_QUALIFIED_BENCHMARKS


def test_gap_closure_adapters_preserve_authority_and_claim_boundaries() -> None:
    boundaries = {
        "opencre-gemara-control-interoperability": "no equivalence claim",
        "cbest-threat-led-assurance": "no CBEST completion",
        "ocp-safe-hardware-firmware-assurance": "no OCP recognition",
    }
    for identifier, boundary in boundaries.items():
        adapter = benchmark_adapter_spec(identifier)
        assert len(adapter["required_inputs"]) == 5
        assert adapter["acquisition"]["signed_provenance_required"] is True
        assert boundary in adapter["isolation"]
        requirements = industry_extension_runner_requirements(identifier)
        assert "independent-adjudication-remediation-and-replay-ledger" in requirements
        assert (
            "no-equivalence-certification-supervisory-or-product-claim-policy"
            in requirements
        )


@pytest.mark.parametrize(
    "identifier", sorted(INTEROPERABILITY_SECTOR_EVIDENCE_CONTRACTS)
)
def test_gap_closure_semantic_evidence_accepts_only_strict_bound_claims(
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

    false_claim = INTEROPERABILITY_SECTOR_EVIDENCE_CONTRACTS[identifier][
        "required_false"
    ][0]
    invalid = deepcopy(document)
    invalid["claims"][false_claim] = True  # type: ignore[index]
    with pytest.raises(IndustryExtensionEvidenceError, match="boundaries must hold"):
        validate_industry_extension_evidence(
            json.dumps(invalid),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )

    true_claim = INTEROPERABILITY_SECTOR_EVIDENCE_CONTRACTS[identifier][
        "required_true"
    ][0]
    invalid = deepcopy(document)
    invalid["claims"][true_claim] = False  # type: ignore[index]
    with pytest.raises(IndustryExtensionEvidenceError, match="checks must pass"):
        validate_industry_extension_evidence(
            json.dumps(invalid),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )


def test_csaf_watch_and_control_interoperability_versions_are_current() -> None:
    watch = {str(item["id"]): item for item in _STANDARDS_WATCHLIST}
    csaf = watch["OASIS-CSAF-2.1"]
    assert csaf["stage"] == "csd02-2026-02-25"
    assert "/csd02/" in csaf["reference"]
    assert csaf["status"] == "committee-specification-draft"

    formats = {name: version for name, version, _ in _INTEROPERABILITY}
    assert formats["OpenCRE"] == "2026-08-31-policy-pinned"
    assert formats["Gemara"] == "2026-08-31-schema-policy-pinned"
