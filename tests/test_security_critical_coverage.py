from __future__ import annotations

import json

import pytest

from scripts import validate_security_critical_coverage as coverage_gate


def _complete_report(percent: float = 100.0) -> dict[str, object]:
    return {
        "files": {
            name: {"summary": {"percent_covered": percent}}
            for name in coverage_gate._FLOORS
        }
    }


def test_high_assurance_floors_cannot_silently_regress() -> None:
    expected = {
        "src/py_security_suite/atomic_file.py": 93.0,
        "src/py_security_suite/benchmark_pipeline.py": 95.0,
        "src/py_security_suite/benchmark_semantic_evidence.py": 85.0,
        "src/py_security_suite/governance_quorum.py": 92.0,
        "src/py_security_suite/industry_benchmark_scoring.py": 96.0,
        "src/py_security_suite/industry_receipt_trust.py": 93.0,
        "src/py_security_suite/native_parser_worker.py": 98.0,
    }

    for name, floor in expected.items():
        assert coverage_gate._FLOORS[name] >= floor


def test_complete_report_passes_and_low_coverage_is_reported() -> None:
    report = _complete_report()
    first_name = next(iter(coverage_gate._FLOORS))
    report_files = report["files"]
    assert isinstance(report_files, dict)
    report_files[first_name] = {"summary": {"percent_covered": 0.0}}

    failures = coverage_gate.coverage_failures(report)

    assert failures == [
        f"{first_name}: 0.00% < {coverage_gate._FLOORS[first_name]:.2f}%"
    ]


@pytest.mark.parametrize("percent", [True, "100", -1, 101, float("inf")])
def test_invalid_coverage_percentages_fail_closed(percent: object) -> None:
    report = _complete_report()
    first_name = next(iter(coverage_gate._FLOORS))
    report_files = report["files"]
    assert isinstance(report_files, dict)
    report_files[first_name] = {"summary": {"percent_covered": percent}}

    with pytest.raises(coverage_gate.CoverageReportError, match="finite number"):
        coverage_gate.coverage_failures(report)


def test_normalized_path_collision_is_rejected() -> None:
    report = _complete_report()
    first_name = next(iter(coverage_gate._FLOORS))
    report_files = report["files"]
    assert isinstance(report_files, dict)
    report_files[first_name.replace("/", "\\")] = report_files[first_name]

    with pytest.raises(coverage_gate.CoverageReportError, match="duplicate normalized"):
        coverage_gate.coverage_failures(report)


def test_loader_rejects_non_finite_json(tmp_path) -> None:
    report_path = tmp_path / "coverage.json"
    report_path.write_text(
        json.dumps(_complete_report()).replace("100.0", "NaN", 1),
        encoding="utf-8",
    )

    with pytest.raises(coverage_gate.CoverageReportError, match="non-finite"):
        coverage_gate.load_coverage_report(report_path)


def test_loader_rejects_duplicate_json_keys(tmp_path) -> None:
    report_path = tmp_path / "coverage.json"
    report_path.write_text('{"files": {}, "files": {}}', encoding="utf-8")

    with pytest.raises(coverage_gate.CoverageReportError, match="duplicate JSON"):
        coverage_gate.load_coverage_report(report_path)


def test_missing_files_object_is_rejected() -> None:
    with pytest.raises(coverage_gate.CoverageReportError, match="files must"):
        coverage_gate.coverage_failures({})
