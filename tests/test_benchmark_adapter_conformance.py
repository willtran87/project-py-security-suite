from __future__ import annotations

import json

import pytest

from py_security_suite.benchmark_adapter_conformance import (
    BenchmarkAdapterConformanceError,
    run_adapter_conformance,
    run_adapter_conformance_suite,
)


def _normalizer(payload: bytes) -> dict[str, object]:
    value = json.loads(payload)
    if not isinstance(value, dict) or set(value) != {"label", "observed"}:
        raise ValueError("invalid result")
    if value["label"] != value["observed"]:
        raise ValueError("label inversion")
    return {"case": "fixture", "passed": True}


def test_adapter_conformance_executes_all_negative_controls() -> None:
    report = run_adapter_conformance(
        normalizer=_normalizer,
        golden_fixture=b'{"label":true,"observed":true}',
        expected_normalized={"case": "fixture", "passed": True},
        malformed_fixture=b"not-json",
        inverted_fixture=b'{"label":true,"observed":false}',
        adapter_spec_sha256="a" * 64,
        runner_executable_sha256="b" * 64,
        normalizer_identity="tests:_normalizer",
    )

    assert report["deterministic_runs"] == 3
    assert len(report["runs"]) == 3
    assert len({item["output_sha256"] for item in report["runs"]}) == 1


def test_adapter_conformance_rejects_a_permissive_normalizer() -> None:
    with pytest.raises(BenchmarkAdapterConformanceError, match="malformed"):
        run_adapter_conformance(
            normalizer=lambda _: {"case": "fixture", "passed": True},
            golden_fixture=b"golden",
            expected_normalized={"case": "fixture", "passed": True},
            malformed_fixture=b"malformed",
            inverted_fixture=b"inverted",
            adapter_spec_sha256="a" * 64,
            runner_executable_sha256="b" * 64,
            normalizer_identity="tests:permissive",
        )


def test_conformance_suite_separates_parser_and_semantic_controls() -> None:
    def normalizer(payload: bytes) -> dict[str, object]:
        value = json.loads(payload)
        if not isinstance(value, dict) or set(value) != {"expected", "observed"}:
            raise ValueError("invalid result")
        return value

    report = run_adapter_conformance_suite(
        normalizer=normalizer,
        golden_fixtures=[
            (
                json.dumps({"expected": index, "observed": index}).encode(),
                {"expected": index, "observed": index},
            )
            for index in range(3)
        ],
        malformed_fixtures=[b"not-json", b"[]", b'{"unexpected":true}'],
        inverted_fixtures=[
            json.dumps({"expected": index, "observed": index + 1}).encode()
            for index in range(3)
        ],
        semantic_oracle=lambda value: value["expected"] == value["observed"],
        adapter_spec_sha256="a" * 64,
        runner_executable_sha256="b" * 64,
        normalizer_identity="tests:normalizer",
        semantic_oracle_identity="tests:expected-equals-observed:v1",
        semantic_oracle_sha256="c" * 64,
    )

    assert report["fixture_counts"] == {
        "golden": 3,
        "malformed": 3,
        "label_inverted": 3,
    }
    assert report["semantic_inversion_controls_passed"] is True
    assert report["semantic_oracle_sha256"] == "c" * 64
