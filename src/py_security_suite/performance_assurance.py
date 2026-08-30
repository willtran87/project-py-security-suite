from __future__ import annotations

import ast
import gc
import json
import platform
import statistics
import subprocess  # nosec B404 - fixed self-analysis interpreter command
import sys
import time
import tracemalloc
from importlib.resources import files
from pathlib import Path
from typing import Any, Callable

from jsonschema.validators import validator_for  # type: ignore[import-untyped]
import psutil

from .benchmark_scoring import _score_normalized_result
from .code_health import analyze_code_health
from .repository_file_policy import maintained_repository_files
from .static_architecture import analyze_static_architecture
from .strict_json import canonical_bytes, loads as strict_loads


_SMALL_CASES = 1_000
_LARGE_CASES = 10_000
_MAX_LARGE_SECONDS = 5.0
_MAX_GROWTH_RATIO = 25.0
_MIN_LARGE_THROUGHPUT = 2_000.0
_MAX_PEAK_MIB = 128.0
_EXTENDED_REPETITIONS = 5


def run_reference_performance_probe() -> dict[str, Any]:
    """Measure bounded parser-and-scoring work at two deterministic scales."""
    small_payload = _classification_payload(_SMALL_CASES)
    large_payload = _classification_payload(_LARGE_CASES)
    small_seconds, _ = _measure(lambda: _parse_and_score(small_payload))
    large_seconds, peak_bytes = _measure(lambda: _parse_and_score(large_payload))
    measurements = {
        "small_cases": _SMALL_CASES,
        "large_cases": _LARGE_CASES,
        "small_seconds": round(small_seconds, 6),
        "large_seconds": round(large_seconds, 6),
        "growth_ratio": round(large_seconds / max(small_seconds, 0.001), 6),
        "large_cases_per_second": round(_LARGE_CASES / max(large_seconds, 0.001), 3),
        "peak_mib": round(peak_bytes / (1024 * 1024), 3),
    }
    budgets = {
        "maximum_large_seconds": _MAX_LARGE_SECONDS,
        "maximum_growth_ratio": _MAX_GROWTH_RATIO,
        "minimum_large_cases_per_second": _MIN_LARGE_THROUGHPUT,
        "maximum_peak_mib": _MAX_PEAK_MIB,
    }
    failures = performance_budget_failures(measurements, budgets)
    return {
        "schema_version": "1.0",
        "workload": "strict-json-plus-classification-scoring",
        "measurements": measurements,
        "budgets": budgets,
        "passed": not failures,
        "failures": failures,
    }


def run_extended_performance_probe() -> dict[str, Any]:
    """Measure representative scoring, canonicalization, and schema workloads."""

    classification_small = _classification_payload(_SMALL_CASES)
    classification_large = _classification_payload(_LARGE_CASES)
    canonical_small = _canonical_payload(_SMALL_CASES)
    canonical_large = _canonical_payload(_LARGE_CASES)
    workloads = [
        _scaled_workload(
            "strict-json-classification-scoring",
            small_cases=_SMALL_CASES,
            large_cases=_LARGE_CASES,
            small=lambda: _parse_and_score(classification_small),
            large=lambda: _parse_and_score(classification_large),
            maximum_seconds=5.0,
            minimum_throughput=2_000.0,
            maximum_peak_mib=128.0,
            maximum_growth_ratio=25.0,
        ),
        _scaled_workload(
            "canonical-evidence-serialization",
            small_cases=_SMALL_CASES,
            large_cases=_LARGE_CASES,
            small=lambda: _canonicalize(canonical_small),
            large=lambda: _canonicalize(canonical_large),
            maximum_seconds=5.0,
            minimum_throughput=2_000.0,
            maximum_peak_mib=128.0,
            maximum_growth_ratio=25.0,
        ),
        _fixed_workload(
            "bundled-schema-validation",
            operation=_validate_schema_catalog,
            maximum_seconds=15.0,
            maximum_peak_mib=256.0,
        ),
        _fixed_workload(
            "production-source-inventory",
            operation=_inventory_production_source,
            maximum_seconds=5.0,
            maximum_peak_mib=128.0,
        ),
        _fixed_workload(
            "production-source-ast-parse",
            operation=_parse_production_source,
            maximum_seconds=15.0,
            maximum_peak_mib=256.0,
        ),
        _repository_pipeline_workload(),
    ]
    failures = [
        f"{workload['name']}: {failure}"
        for workload in workloads
        for failure in workload["failures"]
    ]
    return {
        "schema_version": "1.1",
        "environment": {
            "python_implementation": platform.python_implementation(),
            "python_version": ".".join(str(item) for item in sys.version_info[:3]),
            "platform_system": platform.system(),
            "machine": platform.machine() or "unknown",
        },
        "repetitions": _EXTENDED_REPETITIONS,
        "workloads": workloads,
        "passed": not failures,
        "failures": failures,
    }


def performance_budget_failures(
    measurements: dict[str, int | float], budgets: dict[str, float]
) -> list[str]:
    """Return stable, machine-readable budget failures for measured work."""
    checks = (
        (
            float(measurements["large_seconds"]) <= budgets["maximum_large_seconds"],
            "large workload exceeded the wall-clock budget",
        ),
        (
            float(measurements["growth_ratio"]) <= budgets["maximum_growth_ratio"],
            "workload scaling exceeded the growth-ratio budget",
        ),
        (
            float(measurements["large_cases_per_second"])
            >= budgets["minimum_large_cases_per_second"],
            "large workload fell below the throughput budget",
        ),
        (
            float(measurements["peak_mib"]) <= budgets["maximum_peak_mib"],
            "large workload exceeded the memory budget",
        ),
    )
    return [message for passed, message in checks if not passed]


def _measure(operation: Callable[[], None]) -> tuple[float, int]:
    durations: list[float] = []
    peak = 0
    for _ in range(3):
        gc.collect()
        tracemalloc.start()
        started = time.perf_counter()
        operation()
        durations.append(time.perf_counter() - started)
        _, observed_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peak = max(peak, observed_peak)
    return statistics.median(durations), peak


def _measure_distribution(
    operation: Callable[[], None], *, repetitions: int = _EXTENDED_REPETITIONS
) -> tuple[list[float], int]:
    durations: list[float] = []
    peak = 0
    for _ in range(repetitions):
        gc.collect()
        tracemalloc.start()
        started = time.perf_counter()
        operation()
        durations.append(time.perf_counter() - started)
        _, observed_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peak = max(peak, observed_peak)
    return durations, peak


def _percentile_95(values: list[float]) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(len(ordered) * 0.95 + 0.999) - 1))
    return ordered[index]


def _scaled_workload(
    name: str,
    *,
    small_cases: int,
    large_cases: int,
    small: Callable[[], None],
    large: Callable[[], None],
    maximum_seconds: float,
    minimum_throughput: float,
    maximum_peak_mib: float,
    maximum_growth_ratio: float,
) -> dict[str, Any]:
    small_samples, _ = _measure_distribution(small)
    large_samples, peak = _measure_distribution(large)
    small_median = statistics.median(small_samples)
    large_median = statistics.median(large_samples)
    p95 = _percentile_95(large_samples)
    throughput = large_cases / max(large_median, 0.001)
    growth = large_median / max(small_median, 0.001)
    peak_mib = peak / (1024 * 1024)
    failures: list[str] = []
    if p95 > maximum_seconds:
        failures.append("p95 latency exceeded the budget")
    if throughput < minimum_throughput:
        failures.append("median throughput fell below the budget")
    if peak_mib > maximum_peak_mib:
        failures.append("peak memory exceeded the budget")
    if growth > maximum_growth_ratio:
        failures.append("median scaling ratio exceeded the budget")
    return {
        "name": name,
        "kind": "scaled",
        "small_cases": small_cases,
        "large_cases": large_cases,
        "median_small_seconds": round(small_median, 6),
        "median_large_seconds": round(large_median, 6),
        "p95_large_seconds": round(p95, 6),
        "large_cases_per_second": round(throughput, 3),
        "growth_ratio": round(growth, 6),
        "peak_mib": round(peak_mib, 3),
        "budgets": {
            "maximum_p95_seconds": maximum_seconds,
            "minimum_median_cases_per_second": minimum_throughput,
            "maximum_peak_mib": maximum_peak_mib,
            "maximum_growth_ratio": maximum_growth_ratio,
        },
        "passed": not failures,
        "failures": failures,
    }


def _fixed_workload(
    name: str,
    *,
    operation: Callable[[], None],
    maximum_seconds: float,
    maximum_peak_mib: float,
    repetitions: int = _EXTENDED_REPETITIONS,
) -> dict[str, Any]:
    samples, peak = _measure_distribution(operation, repetitions=repetitions)
    median = statistics.median(samples)
    p95 = _percentile_95(samples)
    peak_mib = peak / (1024 * 1024)
    failures: list[str] = []
    if p95 > maximum_seconds:
        failures.append("p95 latency exceeded the budget")
    if peak_mib > maximum_peak_mib:
        failures.append("peak memory exceeded the budget")
    return {
        "name": name,
        "kind": "fixed",
        "sample_count": repetitions,
        "median_seconds": round(median, 6),
        "p95_seconds": round(p95, 6),
        "peak_mib": round(peak_mib, 3),
        "budgets": {
            "maximum_p95_seconds": maximum_seconds,
            "maximum_peak_mib": maximum_peak_mib,
        },
        "passed": not failures,
        "failures": failures,
    }


def _repository_pipeline_workload() -> dict[str, Any]:
    root = Path(__file__).resolve().parents[2]
    command = [
        sys.executable,
        "-c",
        (
            "from py_security_suite.performance_assurance import "
            "analyze_repository_pipeline_probe; analyze_repository_pipeline_probe(); "
            "print('ok')"
        ),
    ]
    started = time.perf_counter()
    process = subprocess.Popen(  # noqa: S603 - fixed interpreter and program
        command,
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    peak_bytes = 0
    timed_out = False
    while process.poll() is None:
        if time.perf_counter() - started > 90.0:
            timed_out = True
            _kill_probe_tree(process)
            break
        peak_bytes = max(peak_bytes, _process_tree_resident_bytes(process.pid))
        time.sleep(0.02)
    stdout, stderr = process.communicate()
    elapsed = time.perf_counter() - started
    peak_mib = peak_bytes / (1024 * 1024)
    failures: list[str] = []
    if timed_out or elapsed > 90.0:
        failures.append("repository pipeline exceeded the latency budget")
    if peak_mib > 1024.0:
        failures.append("repository pipeline exceeded the memory budget")
    if process.returncode != 0 or stdout.strip() != b"ok":
        diagnostic = stderr.decode("utf-8", errors="replace")[-512:]
        failures.append(f"repository pipeline failed: {diagnostic}")
    return {
        "name": "repository-analysis-pipeline",
        "kind": "fixed",
        "sample_count": 1,
        "median_seconds": round(elapsed, 6),
        "p95_seconds": round(elapsed, 6),
        "peak_mib": round(peak_mib, 3),
        "budgets": {
            "maximum_p95_seconds": 90.0,
            "maximum_peak_mib": 1024.0,
        },
        "passed": not failures,
        "failures": failures,
    }


def _process_tree_resident_bytes(pid: int) -> int:
    try:
        root = psutil.Process(pid)
        processes = [root, *root.children(recursive=True)]
        return sum(process.memory_info().rss for process in processes)
    except (psutil.Error, OSError):
        return 0


def _kill_probe_tree(process: subprocess.Popen[bytes]) -> None:
    try:
        root = psutil.Process(process.pid)
        children = root.children(recursive=True)
        for child in reversed(children):
            child.kill()
        root.kill()
        psutil.wait_procs([*children, root], timeout=5)
    except (psutil.Error, OSError):
        process.kill()


def _parse_and_score(payload: bytes) -> None:
    value = strict_loads(payload)
    result = _score_normalized_result(
        value,
        benchmark_id="performance-reference",
        protocol="classification",
    )
    if result["case_count"] <= 0 or result["false_positive"] != 0:
        raise RuntimeError("reference performance workload produced invalid metrics")


def _classification_payload(count: int) -> bytes:
    cases = [
        {
            "id": f"case-{index:06d}",
            "expected_positive": index % 2 == 0,
            "observed_positive": index % 2 == 0,
            "strata": {"language": "python", "family": "reference"},
        }
        for index in range(count)
    ]
    return json.dumps(
        {
            "schema_version": "1.0",
            "benchmark_id": "performance-reference",
            "protocol": "classification",
            "cases": cases,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _canonical_payload(count: int) -> list[dict[str, object]]:
    return [
        {
            "id": f"finding-{index:06d}",
            "path": f"src/package/module_{index % 100:03d}.py",
            "line": index + 1,
            "severity": ("low", "medium", "high", "critical")[index % 4],
            "evidence": {"rule": f"RULE-{index % 250:03d}", "confirmed": True},
        }
        for index in range(count)
    ]


def _canonicalize(value: list[dict[str, object]]) -> None:
    payload = canonical_bytes(value)
    if not payload.startswith(b"[") or not payload.endswith(b"]"):
        raise RuntimeError("canonical workload produced invalid JSON")


def _validate_schema_catalog() -> None:
    root = files("py_security_suite").joinpath("schemas")
    documents: list[tuple[int, dict[str, object]]] = []
    for resource in sorted(root.iterdir(), key=lambda item: item.name):
        if not resource.name.endswith(".schema.json"):
            continue
        payload = resource.read_bytes()
        document = strict_loads(payload)
        if not isinstance(document, dict):
            raise RuntimeError("bundled schema root is not an object")
        documents.append((len(payload), document))
    if len(documents) < 200:
        raise RuntimeError("bundled schema workload is unexpectedly incomplete")
    # Validator construction is sampled from the largest contracts; the
    # separate schema-consistency gate performs exhaustive meta-schema checks.
    # This workload measures realistic catalog loading without duplicating that
    # multi-minute correctness gate under tracemalloc.
    for _, document in sorted(documents, reverse=True, key=lambda item: item[0])[:2]:
        validator_for(document)(document)


def _production_python_files() -> list[Path]:
    package = Path(__file__).resolve().parent
    result = [
        path for path in maintained_repository_files(package) if path.suffix == ".py"
    ]
    if len(result) < 100:
        raise RuntimeError("production source workload is unexpectedly incomplete")
    return result


def _inventory_production_source() -> None:
    files_found = _production_python_files()
    if not all(path.is_file() for path in files_found):
        raise RuntimeError("production source inventory contains a non-file")


def _parse_production_source() -> None:
    modules = _production_python_files()
    for path in modules:
        ast.parse(path.read_bytes(), filename=str(path))


def analyze_repository_pipeline_probe() -> None:
    """Execute the real repository analyzers for an isolated performance probe."""
    root = Path(__file__).resolve().parents[2]
    health_findings, health = analyze_code_health(root)
    architecture_findings, architecture = analyze_static_architecture(root)
    if (
        health.get("schema_version") != "1.4"
        or architecture.get("schema_version") != "1.4"
        or not isinstance(health_findings, list)
        or not isinstance(architecture_findings, list)
    ):
        raise RuntimeError("repository analysis pipeline produced invalid evidence")
