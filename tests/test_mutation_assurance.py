from __future__ import annotations

import json
from pathlib import Path
from xml.etree import ElementTree

import pytest

from scripts.run_mutation_assurance import (
    mutation_workload_weights,
    select_mutation_shard,
)
from scripts.validate_mutation_assurance import (
    MutationEvidenceError,
    aggregate_mutation_stats,
    assurance_failures,
    load_mutation_stats,
    mutation_score,
    write_junit_evidence,
)


def _stats(**overrides: int | bool) -> dict[str, int | bool]:
    values: dict[str, int | bool] = {
        "killed": 80,
        "survived": 20,
        "total": 100,
        "no_tests": 0,
        "skipped": 0,
        "suspicious": 0,
        "timeout": 0,
        "check_was_interrupted_by_user": False,
        "segfault": 0,
    }
    values.update(overrides)
    return values


def test_mutation_shards_are_deterministic_complete_and_disjoint() -> None:
    candidates = [f"module-{index}.py" for index in range(17)]
    shards = [
        select_mutation_shard(candidates, shard_index=index, shard_count=6)
        for index in range(6)
    ]

    assert sorted(item for shard in shards for item in shard) == sorted(candidates)
    assert sum(len(set(shard)) for shard in shards) == len(candidates)
    assert shards[0] == select_mutation_shard(
        list(reversed(candidates)), shard_index=0, shard_count=6
    )


def test_mutation_shards_balance_weighted_workloads() -> None:
    candidates = ["large-a.py", "large-b.py", "small-a.py", "small-b.py"]
    weights = {
        "large-a.py": 100,
        "large-b.py": 100,
        "small-a.py": 1,
        "small-b.py": 1,
    }
    shards = [
        select_mutation_shard(
            candidates,
            shard_index=index,
            shard_count=2,
            weights=weights,
        )
        for index in range(2)
    ]

    loads = [sum(weights[item] for item in shard) for shard in shards]
    assert sorted(item for shard in shards for item in shard) == sorted(candidates)
    assert loads == [101, 101]


def test_mutation_shard_weights_validate_and_measure_sources(tmp_path: Path) -> None:
    empty = tmp_path / "empty.py"
    populated = tmp_path / "populated.py"
    empty.write_bytes(b"")
    populated.write_bytes(b"value = 1\n")

    weights = mutation_workload_weights([str(empty), str(populated)])

    assert weights == {str(empty): 1, str(populated): 10}
    with pytest.raises(ValueError, match="positive integers"):
        select_mutation_shard(
            [str(empty)], shard_index=0, shard_count=1, weights={str(empty): 0}
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"killed": 69, "survived": 31}, "below 70.00%"),
        (
            {"killed": 79, "survived": 18, "timeout": 3},
            "timeout and crash mutants exceeded",
        ),
        (
            {"killed": 79, "survived": 18, "segfault": 3},
            "timeout and crash mutants exceeded",
        ),
        ({"check_was_interrupted_by_user": True}, "interrupted"),
    ],
)
def test_mutation_gate_fails_closed(
    overrides: dict[str, int | bool], message: str
) -> None:
    score, failures = assurance_failures(_stats(**overrides), minimum_score=70)

    assert score >= 0
    assert any(message in failure for failure in failures)


def test_mutation_evidence_rejects_duplicate_or_inconsistent_counts(
    tmp_path: Path,
) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"killed": 1, "killed": 2}', encoding="utf-8")
    with pytest.raises(MutationEvidenceError, match="duplicate"):
        load_mutation_stats(duplicate)

    inconsistent = tmp_path / "inconsistent.json"
    inconsistent.write_text(json.dumps(_stats(total=99)), encoding="utf-8")
    with pytest.raises(MutationEvidenceError, match="exceed total"):
        load_mutation_stats(inconsistent)


def test_mutation_score_accepts_type_checker_only_kills() -> None:
    stats = _stats(killed=0, survived=0, total=3)
    stats["inferred_type_checker_kills"] = 3

    assert mutation_score(stats) == 100.0


def test_mutation_gate_counts_one_bounded_timeout_as_detected() -> None:
    stats = _stats(killed=79, survived=20, timeout=1, total=100)

    score, failures = assurance_failures(stats, minimum_score=70)

    assert score == 80.0
    assert failures == []


def test_mutation_gate_counts_one_bounded_crash_as_detected() -> None:
    stats = _stats(killed=79, survived=20, segfault=1, total=100)

    score, failures = assurance_failures(stats, minimum_score=70)

    assert score == 80.0
    assert failures == []


def test_mutation_shards_are_aggregated_and_emit_junit(tmp_path: Path) -> None:
    paths: list[Path] = []
    for index, stats in enumerate((_stats(killed=69, survived=31), _stats())):
        path = tmp_path / f"shard-{index}.json"
        path.write_text(json.dumps(stats), encoding="utf-8")
        paths.append(path)

    aggregate = aggregate_mutation_stats(paths)
    score, failures = assurance_failures(aggregate, minimum_score=70)
    document = {
        "shard": "aggregate-2",
        "minimum_score": 70,
        "mutation_score": score,
        "passed": not failures,
        "failures": failures,
        "counts": aggregate,
    }
    junit = tmp_path / "mutation.xml"
    write_junit_evidence(junit, document)
    suite = ElementTree.parse(junit).getroot()  # noqa: S314 - parses local generated evidence

    assert aggregate["total"] == 200
    assert score == 74.5
    assert failures == []
    assert suite.attrib["tests"] == "1"
    assert suite.attrib["failures"] == "0"
    assert suite.find("./testcase") is not None
