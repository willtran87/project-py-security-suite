from __future__ import annotations

import pytest

from companion.semantic_assurance import REQUIRED_CONTROLS, analyze
from companion.strict_json import dumps as strict_dumps
from py_security_suite.control_proof import verify_control_proof
import hashlib


def _case(control: str, *, observed: str = "pass") -> dict[str, object]:
    return {
        "id": f"case-{control}",
        "target_id": "service-primary",
        "role": "security-test",
        "control": control,
        "expected": "pass",
        "observed": observed,
        "severity": "high",
        "classification": "CWE-693",
    }


@pytest.mark.parametrize(
    "kind",
    ["surface-inventory", "event-security", "database-security", "ai-security"],
)
def test_semantic_lanes_require_complete_control_coverage(kind: str) -> None:
    cases = [_case(control) for control in sorted(REQUIRED_CONTROLS[kind])]
    document = {
        "schema_version": "1.0",
        "kind": kind,
        "cases": cases,
        "canary_id": cases[0]["id"],
    }

    result = analyze(document, kind)

    assert result["findings"] == []
    assert result["execution"]["coverage_percent"] == 100.0
    assert set(result["execution"]["features"]) == REQUIRED_CONTROLS[kind]
    proof = verify_control_proof(
        result["execution"]["control_proof"], REQUIRED_CONTROLS[kind]
    )
    assert proof["proof_sha256"]


def test_semantic_control_proof_rejects_feature_label_tampering() -> None:
    kind = "event-security"
    cases = [_case(control) for control in sorted(REQUIRED_CONTROLS[kind])]
    result = analyze(
        {
            "schema_version": "1.0",
            "kind": kind,
            "cases": cases,
            "canary_id": cases[0]["id"],
        },
        kind,
    )
    proof = result["execution"]["control_proof"]
    proof["controls"]["message-signing"]["cases"] = 2
    with pytest.raises(ValueError, match="commitment"):
        verify_control_proof(proof, REQUIRED_CONTROLS[kind])


def test_semantic_lane_derives_findings_from_oracle_mismatch() -> None:
    kind = "database-security"
    cases = [
        _case(control, observed="allow" if control == "row-level-security" else "pass")
        for control in sorted(REQUIRED_CONTROLS[kind])
    ]
    result = analyze(
        {
            "schema_version": "1.0",
            "kind": kind,
            "cases": cases,
            "canary_id": cases[0]["id"],
        },
        kind,
    )

    assert [finding["rule_id"] for finding in result["findings"]] == [
        "database-security:row-level-security"
    ]


def test_ruleset_regression_compares_derived_scores_to_signed_baseline() -> None:
    kind = "ruleset-regression"
    cases = [_case(control) for control in sorted(REQUIRED_CONTROLS[kind])]
    true_positive = next(case for case in cases if case["control"] == "true-positive")
    true_positive["observed"] = "clean"
    corpus_sha256 = hashlib.sha256(strict_dumps(cases).encode()).hexdigest()
    result = analyze(
        {
            "schema_version": "1.0",
            "kind": kind,
            "cases": cases,
            "canary_id": cases[0]["id"],
            "baseline": {
                "true_positive_rate": 100.0,
                "true_negative_rate": 100.0,
                "mutation_rate": 100.0,
                "corpus_sha256": corpus_sha256,
                "ruleset_sha256": "a" * 64,
                "sample_sizes": {
                    "true_positive_rate": 1,
                    "true_negative_rate": 1,
                    "mutation_rate": 1,
                },
                "confidence_level": 0.95,
            },
        },
        kind,
    )

    rules = {finding["rule_id"] for finding in result["findings"]}
    assert "ruleset-regression:true-positive" in rules
    assert "ruleset-regression:true_positive_rate" in rules


def test_semantic_lane_rejects_missing_controls_and_failed_canary() -> None:
    with pytest.raises(ValueError, match="missing controls"):
        analyze(
            {
                "schema_version": "1.0",
                "kind": "surface-inventory",
                "cases": [_case("declared-observed")],
                "canary_id": "case-declared-observed",
            },
            "surface-inventory",
        )
