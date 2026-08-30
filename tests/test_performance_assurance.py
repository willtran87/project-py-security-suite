from __future__ import annotations

import json
from unittest.mock import patch

from jsonschema import Draft202012Validator
import pytest

from py_security_suite.performance_assurance import (
    performance_budget_failures,
    run_extended_performance_probe,
    run_reference_performance_probe,
)
from py_security_suite import performance_assurance
from py_security_suite.report_inspection import read_bundled_schema


def test_reference_performance_probe_meets_enforced_budgets() -> None:
    result = run_reference_performance_probe()
    assert result["passed"] is True
    assert result["failures"] == []
    Draft202012Validator(
        json.loads(read_bundled_schema("performance-assurance-1.0"))
    ).validate(result)


def test_performance_budget_failures_name_each_regression() -> None:
    failures = performance_budget_failures(
        {
            "large_seconds": 6.0,
            "growth_ratio": 30.0,
            "large_cases_per_second": 100.0,
            "peak_mib": 256.0,
        },
        {
            "maximum_large_seconds": 5.0,
            "maximum_growth_ratio": 25.0,
            "minimum_large_cases_per_second": 2_000.0,
            "maximum_peak_mib": 128.0,
        },
    )
    assert len(failures) == 4


def test_extended_workload_receipts_fail_closed_on_each_budget_dimension() -> None:
    with patch.object(
        performance_assurance,
        "_measure_distribution",
        side_effect=[([0.01] * 5, 0), ([1.0] * 5, 3 * 1024 * 1024)],
    ):
        scaled = performance_assurance._scaled_workload(
            "scaled",
            small_cases=1,
            large_cases=1,
            small=lambda: None,
            large=lambda: None,
            maximum_seconds=0.5,
            minimum_throughput=2.0,
            maximum_peak_mib=2.0,
            maximum_growth_ratio=50.0,
        )
    assert scaled["passed"] is False
    assert len(scaled["failures"]) == 4

    with patch.object(
        performance_assurance,
        "_measure_distribution",
        return_value=([1.0] * 5, 3 * 1024 * 1024),
    ):
        fixed = performance_assurance._fixed_workload(
            "fixed",
            operation=lambda: None,
            maximum_seconds=0.5,
            maximum_peak_mib=2.0,
        )
    assert fixed["passed"] is False
    assert fixed["sample_count"] == 5
    assert len(fixed["failures"]) == 2


@pytest.mark.timeout(180)
def test_extended_performance_probe_covers_scale_and_schema_workloads() -> None:
    result = run_extended_performance_probe()
    assert result["passed"] is True
    assert result["failures"] == []
    assert {item["name"] for item in result["workloads"]} == {
        "strict-json-classification-scoring",
        "canonical-evidence-serialization",
        "bundled-schema-validation",
        "production-source-inventory",
        "production-source-ast-parse",
        "repository-analysis-pipeline",
    }
    assert all(item["passed"] for item in result["workloads"])
    Draft202012Validator(
        json.loads(read_bundled_schema("performance-assurance-1.1"))
    ).validate(result)
