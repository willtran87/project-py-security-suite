from __future__ import annotations

import gc
import json
import statistics
import time
import tracemalloc
from typing import Any, Callable

from .benchmark_scoring import _score_normalized_result
from .strict_json import loads as strict_loads


_SMALL_CASES = 1_000
_LARGE_CASES = 10_000
_MAX_LARGE_SECONDS = 5.0
_MAX_GROWTH_RATIO = 25.0
_MIN_LARGE_THROUGHPUT = 2_000.0
_MAX_PEAK_MIB = 128.0


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
