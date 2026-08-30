from __future__ import annotations

import json

from jsonschema import Draft202012Validator

from py_security_suite.performance_assurance import (
    performance_budget_failures,
    run_reference_performance_probe,
)
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
