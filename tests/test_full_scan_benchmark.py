from __future__ import annotations

from unittest.mock import patch

from py_security_suite.bounded_subprocess import BoundedSubprocessError
from scripts.benchmark_full_scan import collect_case, summarize


def test_benchmark_records_worker_failure_instead_of_losing_results() -> None:
    with patch(
        "scripts.benchmark_full_scan.run_bounded_subprocess",
        side_effect=BoundedSubprocessError("bounded subprocess timed out"),
    ):
        result = collect_case("many-files", 3, 1)
    assert result["passed"] is False
    assert result["failures"] == ["bounded subprocess timed out"]


def test_benchmark_rejects_skipped_scanners_even_when_report_exists() -> None:
    result = summarize(
        [
            {
                "case": "many-findings",
                "scale": 1,
                "total_seconds": 1,
                "peak_rss_bytes": 1024,
                "artifact_bytes": 1024,
                "cancellation_seconds": None,
                "finding_count": 0,
                "tool_statuses": {"bandit": "skipped"},
                "report_verified": True,
            }
        ]
    )
    assert result["passed"] is False
    assert len(result["failures"]) == 2
