from __future__ import annotations

from scripts.validate_documentation_metrics import documentation_metric_failures


def test_documented_repository_metrics_match_enforced_sources() -> None:
    assert documentation_metric_failures() == []
