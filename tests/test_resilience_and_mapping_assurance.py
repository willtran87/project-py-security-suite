from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import pytest

from py_security_suite.benchmark_adapters import benchmark_adapter_spec
from py_security_suite.industry_assurance import (
    _ASSURANCE_PROFILES,
    _BENCHMARKS,
    _STANDARDS,
    _STANDARDS_WATCHLIST,
    _benchmark_protocol,
)
from py_security_suite.industry_extension_evidence import (
    IndustryExtensionEvidenceError,
    industry_extension_runner_requirements,
    validate_industry_extension_evidence,
)
from py_security_suite.industry_resilience_catalog import (
    RESILIENCE_BENCHMARK_IDS,
    RESILIENCE_EVIDENCE_CONTRACTS,
)


SOURCE = "a" * 64
SUBJECT = "b" * 64

EXPECTED_STANDARDS = {
    "NIST-IR-8374-R1",
    "NIST-SP-1800-11",
    "NIST-SP-1800-25",
    "NIST-SP-1800-26",
    "NIST-SP-800-88-R2",
    "IEEE-2883",
    "IEEE-2883-1",
    "NIST-SP-1339",
    "NIST-SP-1800-45",
    "IEC-TS-62443-6-1",
    "ISO-22361",
    "ISO-22398",
    "NIST-SP-800-221",
    "NIST-SP-800-221A",
    "NIST-SP-1347",
    "NIST-IR-8406",
    "NIST-IR-8473",
}
EXPECTED_PROFILES = {
    "ransomware-resilience",
    "media-sanitization",
    "ot-backup-and-remote-access",
    "iec-62443-provider-evaluation",
    "crisis-leadership-and-exercises",
    "enterprise-ict-risk-portfolio",
    "standards-crosswalk-governance",
    "lng-and-ev-infrastructure",
}
EXPECTED_BENCHMARKS = {
    "ransomware-resilience-exercise",
    "media-sanitization-verification",
    "ot-backup-remote-access-recovery",
    "iec-62443-service-provider-evaluation",
    "crisis-exercise-assurance",
    "enterprise-ict-risk-aggregation",
    "standards-crosswalk-semantic-conformance",
    "lng-ev-charging-sector-resilience",
}


def _claims(identifier: str) -> dict[str, Any]:
    contract = RESILIENCE_EVIDENCE_CONTRACTS[identifier]
    return {
        **contract["scalars"],
        **{name: sorted(values) for name, values in contract["sets"].items()},
        **{name: 3 for name in contract["counts"]},
        **{name: True for name in contract["required_true"]},
        **{name: False for name in contract["required_false"]},
    }


def _evidence(identifier: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "integration": identifier,
        "source_sha256": SOURCE,
        "subject_sha256": SUBJECT,
        "execution": {
            "isolated": True,
            "network_policy": "deny",
            "repetitions": 3,
            "budget_seconds": 1200,
        },
        "claims": _claims(identifier),
        "negative_cases": [
            {"id": "source-tamper", "detected": True},
            {"id": "subject-misbinding", "detected": True},
            {"id": "false-assurance", "detected": True},
        ],
        "provenance": {
            "producer": "digest-pinned-resilience-normalizer",
            "producer_sha256": "c" * 64,
            "signature_verified": True,
            "independent_replay_verified": True,
        },
        "complete": True,
    }


def test_resilience_catalog_is_registered_end_to_end() -> None:
    assert EXPECTED_STANDARDS <= {str(item["id"]) for item in _STANDARDS}
    assert EXPECTED_PROFILES <= set(_ASSURANCE_PROFILES)
    assert EXPECTED_BENCHMARKS == RESILIENCE_BENCHMARK_IDS
    assert EXPECTED_BENCHMARKS <= {str(item["id"]) for item in _BENCHMARKS}
    watchlist = {str(item["id"]): item for item in _STANDARDS_WATCHLIST}
    assert {
        "NIST-SP-800-82-R4",
        "NIST-IR-8183-R2",
        "NIST-SP-1353",
        "NIST-IR-8613",
    } <= set(watchlist)
    assert all(
        watchlist[identifier]["status"] == "under-development"
        for identifier in {
            "NIST-SP-800-82-R4",
            "NIST-IR-8183-R2",
            "NIST-SP-1353",
            "NIST-IR-8613",
        }
    )


@pytest.mark.parametrize("identifier", sorted(EXPECTED_BENCHMARKS))
def test_resilience_evidence_is_strict_bound_and_operational(identifier: str) -> None:
    document = _evidence(identifier)
    assert (
        validate_industry_extension_evidence(
            json.dumps(document),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )
        == document
    )
    requirements = industry_extension_runner_requirements(identifier)
    assert {
        "suite-owned-extension-evidence",
        "normative-edition-applicability-and-license-lock",
        "positive-negative-clean-control-and-failure-injection-report",
        "independent-replay-adjudication-recovery-and-retest-ledger",
        "production-isolation-and-no-certification-claim-policy",
    } <= set(requirements)
    adapter = benchmark_adapter_spec(identifier)
    assert adapter["protocol"] == _benchmark_protocol(identifier)
    assert len(adapter["required_inputs"]) >= 5
    assert "no " in str(adapter["isolation"]).lower()


@pytest.mark.parametrize("identifier", sorted(EXPECTED_BENCHMARKS))
def test_resilience_false_assurance_boundaries_fail_closed(identifier: str) -> None:
    document = _evidence(identifier)
    boundary = RESILIENCE_EVIDENCE_CONTRACTS[identifier]["required_false"][0]
    document["claims"][boundary] = True
    with pytest.raises(IndustryExtensionEvidenceError, match="boundaries must hold"):
        validate_industry_extension_evidence(
            json.dumps(document),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )


@pytest.mark.parametrize("identifier", sorted(EXPECTED_BENCHMARKS))
def test_resilience_missing_or_invented_claims_fail_closed(identifier: str) -> None:
    missing = _evidence(identifier)
    removed = next(iter(RESILIENCE_EVIDENCE_CONTRACTS[identifier]["required_true"]))
    del missing["claims"][removed]
    with pytest.raises(IndustryExtensionEvidenceError, match="fields must be exactly"):
        validate_industry_extension_evidence(
            json.dumps(missing),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )

    invented = deepcopy(_evidence(identifier))
    invented["claims"]["certified_by_publisher"] = True
    with pytest.raises(IndustryExtensionEvidenceError, match="fields must be exactly"):
        validate_industry_extension_evidence(
            json.dumps(invented),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )


def test_crosswalk_semantics_reject_direction_and_relationship_drift() -> None:
    document = _evidence("standards-crosswalk-semantic-conformance")
    document["claims"]["relationship_types"] = [
        "equivalent",
        "subset",
        "superset",
        "intersects",
    ]
    with pytest.raises(IndustryExtensionEvidenceError, match="exact governed set"):
        validate_industry_extension_evidence(
            json.dumps(document),
            expected_source_sha256=SOURCE,
            expected_subject_sha256=SUBJECT,
        )
