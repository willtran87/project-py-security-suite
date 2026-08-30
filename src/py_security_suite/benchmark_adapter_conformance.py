from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

from .strict_json import canonical_bytes


Normalizer = Callable[[bytes], dict[str, Any]]
SemanticOracle = Callable[[dict[str, Any]], bool]
_MAX_FIXTURE_BYTES = 32 * 1024 * 1024
_MAX_SUITE_BYTES = 128 * 1024 * 1024
_MAX_RUNS = 25


class BenchmarkAdapterConformanceError(ValueError):
    """Raised when an adapter normalizer fails its executable contract."""


def run_adapter_conformance_suite(
    *,
    normalizer: Normalizer,
    golden_fixtures: list[tuple[bytes, dict[str, Any]]],
    malformed_fixtures: list[bytes],
    inverted_fixtures: list[bytes],
    semantic_oracle: SemanticOracle,
    adapter_spec_sha256: str,
    runner_executable_sha256: str,
    normalizer_identity: str,
    semantic_oracle_identity: str,
    semantic_oracle_sha256: str,
    runs: int = 3,
) -> dict[str, Any]:
    """Execute a multi-fixture parser and semantic-oracle conformance matrix."""
    fixtures = [payload for payload, _ in golden_fixtures]
    fixtures.extend(malformed_fixtures)
    fixtures.extend(inverted_fixtures)
    if (
        len(golden_fixtures) < 3
        or len(malformed_fixtures) < 3
        or len(inverted_fixtures) < 3
        or len(fixtures) > 1000
        or sum(len(item) for item in fixtures) > _MAX_SUITE_BYTES
        or any(len(item) > _MAX_FIXTURE_BYTES for item in fixtures)
        or not 3 <= runs <= _MAX_RUNS
        or not _digest(adapter_spec_sha256)
        or not _digest(runner_executable_sha256)
        or not isinstance(normalizer_identity, str)
        or not 1 <= len(normalizer_identity) <= 512
        or not isinstance(semantic_oracle_identity, str)
        or not 1 <= len(semantic_oracle_identity) <= 512
        or not _digest(semantic_oracle_sha256)
    ):
        raise BenchmarkAdapterConformanceError(
            "adapter conformance suite configuration is invalid"
        )
    run_digests: list[str] = []
    for _ in range(runs):
        outputs: list[dict[str, Any]] = []
        for fixture, expected in golden_fixtures:
            normalized = _normalize(normalizer, fixture, "golden")
            if canonical_bytes(normalized) != canonical_bytes(expected):
                raise BenchmarkAdapterConformanceError(
                    "adapter golden fixture output does not match the approved oracle"
                )
            if semantic_oracle(normalized) is not True:
                raise BenchmarkAdapterConformanceError(
                    "adapter golden fixture fails its semantic oracle"
                )
            outputs.append(normalized)
        if not all(_is_rejected(normalizer, fixture) for fixture in malformed_fixtures):
            raise BenchmarkAdapterConformanceError(
                "adapter accepted a malformed fixture"
            )
        for fixture in inverted_fixtures:
            normalized = _normalize(normalizer, fixture, "label-inverted")
            if semantic_oracle(normalized) is not False:
                raise BenchmarkAdapterConformanceError(
                    "adapter semantic oracle did not detect label inversion"
                )
            outputs.append(normalized)
        run_digests.append(hashlib.sha256(canonical_bytes(outputs)).hexdigest())
    if len(set(run_digests)) != 1:
        raise BenchmarkAdapterConformanceError(
            "adapter output is nondeterministic across conformance runs"
        )
    return {
        "schema_version": "1.1",
        "adapter_spec_sha256": adapter_spec_sha256,
        "runner_executable_sha256": runner_executable_sha256,
        "normalizer": normalizer_identity,
        "semantic_oracle_identity": semantic_oracle_identity,
        "semantic_oracle_sha256": semantic_oracle_sha256,
        "deterministic_runs": runs,
        "fixture_counts": {
            "golden": len(golden_fixtures),
            "malformed": len(malformed_fixtures),
            "label_inverted": len(inverted_fixtures),
        },
        "fixture_set_sha256": hashlib.sha256(
            canonical_bytes(
                [
                    {
                        "kind": "golden",
                        "payload_sha256": hashlib.sha256(payload).hexdigest(),
                        "expected_sha256": hashlib.sha256(
                            canonical_bytes(expected)
                        ).hexdigest(),
                    }
                    for payload, expected in golden_fixtures
                ]
                + [
                    {
                        "kind": "malformed",
                        "payload_sha256": hashlib.sha256(payload).hexdigest(),
                    }
                    for payload in malformed_fixtures
                ]
                + [
                    {
                        "kind": "label-inverted",
                        "payload_sha256": hashlib.sha256(payload).hexdigest(),
                    }
                    for payload in inverted_fixtures
                ]
            )
        ).hexdigest(),
        "output_sha256": run_digests[0],
        "parser_negative_controls_passed": True,
        "semantic_inversion_controls_passed": True,
    }


def run_adapter_conformance(
    *,
    normalizer: Normalizer,
    golden_fixture: bytes,
    expected_normalized: dict[str, Any],
    malformed_fixture: bytes,
    inverted_fixture: bytes,
    adapter_spec_sha256: str,
    runner_executable_sha256: str,
    normalizer_identity: str,
    runs: int = 3,
) -> dict[str, Any]:
    """Execute deterministic, malformed-input, and label-inversion controls."""
    if (
        not 3 <= runs <= _MAX_RUNS
        or any(
            len(item) > _MAX_FIXTURE_BYTES
            for item in (golden_fixture, malformed_fixture, inverted_fixture)
        )
        or not _digest(adapter_spec_sha256)
        or not _digest(runner_executable_sha256)
        or not isinstance(normalizer_identity, str)
        or not 1 <= len(normalizer_identity) <= 512
    ):
        raise BenchmarkAdapterConformanceError(
            "adapter conformance configuration is invalid"
        )
    expected_payload = canonical_bytes(expected_normalized)
    run_records: list[dict[str, Any]] = []
    for run in range(1, runs + 1):
        try:
            normalized = normalizer(golden_fixture)
        except (TypeError, ValueError) as exc:
            raise BenchmarkAdapterConformanceError(
                "adapter rejected its golden fixture"
            ) from exc
        if (
            not isinstance(normalized, dict)
            or canonical_bytes(normalized) != expected_payload
        ):
            raise BenchmarkAdapterConformanceError(
                "adapter golden fixture output does not match the approved oracle"
            )
        malformed_rejected = _is_rejected(normalizer, malformed_fixture)
        inverted_rejected = _is_rejected(normalizer, inverted_fixture)
        if not malformed_rejected:
            raise BenchmarkAdapterConformanceError(
                "adapter accepted its malformed fixture"
            )
        if not inverted_rejected:
            raise BenchmarkAdapterConformanceError(
                "adapter did not detect label inversion"
            )
        run_records.append(
            {
                "run": run,
                "golden_passed": True,
                "malformed_rejected": True,
                "label_inversion_detected": True,
                "output_sha256": hashlib.sha256(expected_payload).hexdigest(),
            }
        )
    return {
        "schema_version": "1.0",
        "adapter_spec_sha256": adapter_spec_sha256,
        "runner_executable_sha256": runner_executable_sha256,
        "normalizer": normalizer_identity,
        "golden_fixture_sha256": hashlib.sha256(golden_fixture).hexdigest(),
        "malformed_fixture_sha256": hashlib.sha256(malformed_fixture).hexdigest(),
        "deterministic_runs": runs,
        "golden_passed": True,
        "malformed_rejected": True,
        "label_inversion_detected": True,
        "runs": run_records,
    }


def _is_rejected(normalizer: Normalizer, fixture: bytes) -> bool:
    try:
        normalizer(fixture)
    except (TypeError, ValueError):
        return True
    return False


def _normalize(normalizer: Normalizer, fixture: bytes, label: str) -> dict[str, Any]:
    try:
        normalized = normalizer(fixture)
    except (TypeError, ValueError) as exc:
        raise BenchmarkAdapterConformanceError(
            f"adapter rejected its {label} fixture"
        ) from exc
    if not isinstance(normalized, dict):
        raise BenchmarkAdapterConformanceError(
            f"adapter {label} fixture output is invalid"
        )
    return normalized


def _digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
