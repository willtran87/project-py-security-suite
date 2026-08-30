from __future__ import annotations

import json
import sys
from pathlib import Path


_FLOORS = {
    "src/py_security_suite/atomic_file.py": 85.0,
    "src/py_security_suite/strict_json.py": 85.0,
    "src/py_security_suite/path_safety.py": 75.0,
    "src/py_security_suite/benchmark_input_validation.py": 75.0,
    "src/py_security_suite/benchmark_pipeline.py": 90.0,
    "src/py_security_suite/benchmark_receipt.py": 95.0,
    "src/py_security_suite/benchmark_signing.py": 75.0,
    "src/py_security_suite/bounded_subprocess.py": 70.0,
    "src/py_security_suite/diagnostic_safety.py": 90.0,
    "src/py_security_suite/benchmark_adapter_conformance.py": 70.0,
    "src/py_security_suite/benchmark_semantic_evidence.py": 70.0,
    "src/py_security_suite/benchmark_telemetry.py": 70.0,
    "src/py_security_suite/benchmark_scoring.py": 85.0,
    "src/py_security_suite/benchmark_statistical_evidence.py": 60.0,
    "src/py_security_suite/benchmark_evidence.py": 70.0,
    "src/py_security_suite/benchmark_execution.py": 65.0,
    "src/py_security_suite/benchmark_assurance.py": 70.0,
    "src/py_security_suite/industry_receipt_trust.py": 85.0,
    "src/py_security_suite/industry_benchmark_scoring.py": 90.0,
    "src/py_security_suite/native_parser_worker.py": 85.0,
    "src/py_security_suite/organization_policy_attestation.py": 80.0,
    "src/py_security_suite/trust_attestation.py": 85.0,
    "src/py_security_suite/trusted_time.py": 65.0,
    "src/py_security_suite/standards_monitor.py": 50.0,
    "src/py_security_suite/artifact_validation.py": 70.0,
    "src/py_security_suite/requirements_coverage.py": 65.0,
    "src/py_security_suite/adapters/assurance_evidence.py": 60.0,
    "src/py_security_suite/git_replay.py": 65.0,
    "src/py_security_suite/isolation_probe.py": 50.0,
    "src/py_security_suite/checkpoint_authority.py": 50.0,
    "src/py_security_suite/execution.py": 55.0,
    "src/py_security_suite/execution_policy.py": 95.0,
    "src/py_security_suite/governance_replay.py": 70.0,
    "src/py_security_suite/governance_quorum.py": 85.0,
    "src/py_security_suite/native_evidence.py": 55.0,
    "src/py_security_suite/boundary_graph.py": 55.0,
    "src/py_security_suite/inventory.py": 55.0,
    "src/py_security_suite/evidence_ingest.py": 55.0,
    "src/py_security_suite/attestation_formats.py": 60.0,
    "src/py_security_suite/trust_policy.py": 65.0,
    "src/py_security_suite/failure_domain.py": 65.0,
    "src/py_security_suite/benchmark_runtime.py": 65.0,
    "src/py_security_suite/performance_assurance.py": 80.0,
    "src/py_security_suite/release_readiness.py": 90.0,
    "src/py_security_suite/repository_file_policy.py": 90.0,
}


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_security_critical_coverage.py COVERAGE_JSON")
    report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    files = {name.replace("\\", "/"): value for name, value in report["files"].items()}
    failures: list[str] = []
    for name, floor in sorted(_FLOORS.items()):
        entry = files.get(name)
        if not isinstance(entry, dict):
            failures.append(f"{name}: missing from coverage report")
            continue
        actual = float(entry["summary"]["percent_covered"])
        if actual + 1e-9 < floor:
            failures.append(f"{name}: {actual:.2f}% < {floor:.2f}%")
    if failures:
        print("security-critical coverage ratchet failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"security-critical coverage ratchet passed for {len(_FLOORS)} modules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
