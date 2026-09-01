from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any


_FLOORS = {
    "src/py_security_suite/atomic_file.py": 93.0,
    "src/py_security_suite/strict_json.py": 85.0,
    "src/py_security_suite/path_safety.py": 77.0,
    "src/py_security_suite/benchmark_input_validation.py": 75.0,
    "src/py_security_suite/benchmark_pipeline.py": 95.0,
    "src/py_security_suite/benchmark_receipt.py": 95.0,
    "src/py_security_suite/benchmark_signing.py": 75.0,
    "src/py_security_suite/bounded_subprocess.py": 78.0,
    "src/py_security_suite/bytecode_analysis.py": 85.0,
    "src/py_security_suite/diagnostic_safety.py": 90.0,
    "src/py_security_suite/benchmark_adapter_conformance.py": 74.0,
    "src/py_security_suite/benchmark_semantic_evidence.py": 85.0,
    "src/py_security_suite/benchmark_telemetry.py": 73.0,
    "src/py_security_suite/benchmark_scoring.py": 88.0,
    "src/py_security_suite/benchmark_statistical_evidence.py": 65.0,
    "src/py_security_suite/benchmark_evidence.py": 70.0,
    "src/py_security_suite/benchmark_execution.py": 66.0,
    "src/py_security_suite/benchmark_assurance.py": 74.0,
    "src/py_security_suite/industry_receipt_trust.py": 93.0,
    "src/py_security_suite/industry_benchmark_scoring.py": 96.0,
    "src/py_security_suite/industry_extension_evidence.py": 90.0,
    "src/py_security_suite/native_parser_worker.py": 98.0,
    "src/py_security_suite/organization_policy_attestation.py": 80.0,
    "src/py_security_suite/trust_attestation.py": 85.0,
    "src/py_security_suite/trusted_time.py": 70.0,
    "src/py_security_suite/standards_monitor.py": 52.0,
    "src/py_security_suite/artifact_validation.py": 70.0,
    "src/py_security_suite/requirements_coverage.py": 69.0,
    "src/py_security_suite/adapters/assurance_evidence.py": 64.0,
    "src/py_security_suite/git_replay.py": 65.0,
    "src/py_security_suite/isolation_probe.py": 59.0,
    "src/py_security_suite/checkpoint_authority.py": 50.0,
    "src/py_security_suite/execution.py": 72.0,
    "src/py_security_suite/execution_policy.py": 95.0,
    "src/py_security_suite/governance_replay.py": 78.0,
    "src/py_security_suite/governance_quorum.py": 92.0,
    "src/py_security_suite/native_evidence.py": 57.0,
    "src/py_security_suite/boundary_graph.py": 65.0,
    "src/py_security_suite/inventory.py": 59.0,
    "src/py_security_suite/evidence_ingest.py": 59.0,
    "src/py_security_suite/attestation_formats.py": 60.0,
    "src/py_security_suite/trust_policy.py": 65.0,
    "src/py_security_suite/failure_domain.py": 65.0,
    "src/py_security_suite/operation_receipt.py": 77.0,
    "src/py_security_suite/benchmark_runtime.py": 65.0,
    "src/py_security_suite/performance_assurance.py": 80.0,
    "src/py_security_suite/release_readiness.py": 90.0,
    "src/py_security_suite/repository_file_policy.py": 93.0,
    "src/py_security_suite/trusted_observation.py": 71.0,
}


class CoverageReportError(ValueError):
    """Raised when coverage evidence is malformed or ambiguous."""


def _reject_non_finite_json(value: str) -> None:
    raise CoverageReportError(f"non-finite JSON number {value!r}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CoverageReportError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def load_coverage_report(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise CoverageReportError(f"cannot read {path}: {error}") from error
    try:
        report = json.loads(
            raw,
            parse_constant=_reject_non_finite_json,
            object_pairs_hook=_unique_object,
        )
    except json.JSONDecodeError as error:
        raise CoverageReportError(
            f"invalid JSON at line {error.lineno}, column {error.colno}"
        ) from error
    if not isinstance(report, dict):
        raise CoverageReportError("top-level value must be an object")
    return report


def coverage_failures(report: dict[str, Any]) -> list[str]:
    raw_files = report.get("files")
    if not isinstance(raw_files, dict):
        raise CoverageReportError("files must be an object")

    files: dict[str, dict[str, Any]] = {}
    for raw_name, value in raw_files.items():
        if not isinstance(raw_name, str) or not raw_name:
            raise CoverageReportError("every file name must be a non-empty string")
        name = raw_name.replace("\\", "/")
        if name in files:
            raise CoverageReportError(f"duplicate normalized file name {name!r}")
        if not isinstance(value, dict):
            raise CoverageReportError(f"file entry {raw_name!r} must be an object")
        files[name] = value

    failures: list[str] = []
    for name, floor in sorted(_FLOORS.items()):
        entry = files.get(name)
        if entry is None:
            failures.append(f"{name}: missing from coverage report")
            continue
        summary = entry.get("summary")
        if not isinstance(summary, dict):
            raise CoverageReportError(f"{name}: summary must be an object")
        actual_value = summary.get("percent_covered")
        if (
            isinstance(actual_value, bool)
            or not isinstance(actual_value, (int, float))
            or not math.isfinite(actual_value)
            or not 0.0 <= actual_value <= 100.0
        ):
            raise CoverageReportError(
                f"{name}: percent_covered must be a finite number from 0 to 100"
            )
        actual = float(actual_value)
        if actual + 1e-9 < floor:
            failures.append(f"{name}: {actual:.2f}% < {floor:.2f}%")
    return failures


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_security_critical_coverage.py COVERAGE_JSON")
    try:
        report = load_coverage_report(Path(sys.argv[1]))
        failures = coverage_failures(report)
    except CoverageReportError as error:
        print(
            f"security-critical coverage ratchet failed: invalid report: {error}",
            file=sys.stderr,
        )
        return 1
    if failures:
        print("security-critical coverage ratchet failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"security-critical coverage ratchet passed for {len(_FLOORS)} modules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
