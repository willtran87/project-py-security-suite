from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.run_mutation_assurance import select_mutation_shard
from scripts.validate_mutation_assurance import (
    MutationEvidenceError,
    assurance_failures,
    load_mutation_stats,
    mutation_score,
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


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"killed": 69, "survived": 31}, "below 70.00%"),
        ({"killed": 79, "survived": 20, "timeout": 1}, "timeout mutants"),
        ({"check_was_interrupted_by_user": True}, "interrupted"),
    ],
)
def test_mutation_gate_fails_closed(overrides: dict[str, int | bool], message: str) -> None:
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
