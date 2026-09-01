from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.generate_ci_assurance_metrics import (
    AssuranceMetricsError,
    build_metrics,
    render_markdown,
)


def test_metrics_are_derived_from_revision_bound_ci_evidence(tmp_path: Path) -> None:
    coverage = tmp_path / "coverage.json"
    coverage.write_text(
        json.dumps(
            {
                "totals": {
                    "num_statements": 100,
                    "covered_lines": 90,
                    "missing_lines": 10,
                    "num_branches": 50,
                    "covered_branches": 40,
                    "missing_branches": 10,
                    "percent_covered": 86.666666,
                }
            }
        ),
        encoding="utf-8",
    )
    junit = tmp_path / "junit.xml"
    junit.write_text(
        '<testsuites><testsuite tests="12" failures="1" errors="0" skipped="2" />'
        "</testsuites>",
        encoding="utf-8",
    )

    metrics = build_metrics(coverage, junit, source_revision="a" * 40)

    assert metrics["coverage"]["combined_percent"] == 86.67
    assert metrics["tests"] == {
        "collected": 12,
        "passed": 9,
        "failed": 1,
        "errors": 0,
        "skipped": 2,
    }
    markdown = render_markdown(metrics)
    assert "86.67%" in markdown
    assert f"`{'a' * 40}`" in markdown


@pytest.mark.parametrize(
    ("coverage", "junit", "message"),
    [
        ("[]", '<testsuite tests="1" />', "must be an object"),
        ('{"totals":{}}', '<testsuite tests="1" />', "omits required totals"),
        (
            '{"totals":{"num_statements":1,"covered_lines":1,"missing_lines":0,'
            '"num_branches":0,"covered_branches":0,"missing_branches":0,'
            '"percent_covered":100}}',
            '<!DOCTYPE x><testsuite tests="1" />',
            "must not contain",
        ),
    ],
)
def test_metrics_reject_malformed_or_active_content(
    tmp_path: Path, coverage: str, junit: str, message: str
) -> None:
    coverage_path = tmp_path / "coverage.json"
    junit_path = tmp_path / "junit.xml"
    coverage_path.write_text(coverage, encoding="utf-8")
    junit_path.write_text(junit, encoding="utf-8")

    with pytest.raises(AssuranceMetricsError, match=message):
        build_metrics(coverage_path, junit_path, source_revision="b" * 40)
