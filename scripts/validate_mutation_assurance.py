"""Validate Mutmut CI evidence against an explicit mutation-score ratchet."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


_COUNT_FIELDS = (
    "killed",
    "survived",
    "total",
    "no_tests",
    "skipped",
    "suspicious",
    "timeout",
    "segfault",
)


class MutationEvidenceError(ValueError):
    """Raised when mutation evidence is incomplete or malformed."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MutationEvidenceError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def load_mutation_stats(path: Path) -> dict[str, int | bool]:
    try:
        raw = path.read_text(encoding="utf-8")
        document = json.loads(raw, object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise MutationEvidenceError(f"cannot read mutation evidence: {error}") from error
    if not isinstance(document, dict):
        raise MutationEvidenceError("mutation evidence must be an object")
    normalized: dict[str, int | bool] = {}
    for field in _COUNT_FIELDS:
        value = document.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise MutationEvidenceError(f"{field} must be a non-negative integer")
        normalized[field] = value
    interrupted = document.get("check_was_interrupted_by_user")
    if isinstance(interrupted, bool):
        normalized["check_was_interrupted_by_user"] = interrupted
    elif isinstance(interrupted, int) and interrupted in {0, 1}:
        # Mutmut 3.7 serializes this boolean-like summary field as a count.
        normalized["check_was_interrupted_by_user"] = bool(interrupted)
    else:
        raise MutationEvidenceError(
            "check_was_interrupted_by_user must be a boolean or zero/one"
        )
    accounted = sum(int(normalized[field]) for field in _COUNT_FIELDS if field != "total")
    # Mutmut includes type-checker kills in total but omits that count from its
    # CI/CD JSON schema. A completed run can recover the count exactly as the
    # non-negative remainder; interrupted runs are rejected by policy below.
    inferred_type_checker_kills = int(normalized["total"]) - accounted
    if inferred_type_checker_kills < 0:
        raise MutationEvidenceError(
            f"mutation counts exceed total: {accounted} > {normalized['total']}"
        )
    normalized["inferred_type_checker_kills"] = inferred_type_checker_kills
    return normalized


def mutation_score(stats: dict[str, int | bool]) -> float:
    inferred_type_checker_kills = int(stats.get("inferred_type_checker_kills", 0))
    assessed = inferred_type_checker_kills + sum(
        int(stats[field])
        for field in ("killed", "survived", "no_tests", "suspicious", "timeout", "segfault")
    )
    if assessed < 1:
        raise MutationEvidenceError("mutation evidence contains no assessed mutants")
    return 100.0 * (int(stats["killed"]) + inferred_type_checker_kills) / assessed


def assurance_failures(
    stats: dict[str, int | bool], *, minimum_score: float
) -> tuple[float, list[str]]:
    if not math.isfinite(minimum_score) or not 0.0 <= minimum_score <= 100.0:
        raise MutationEvidenceError("minimum score must be from 0 through 100")
    score = mutation_score(stats)
    failures: list[str] = []
    if stats["check_was_interrupted_by_user"]:
        failures.append("mutation execution was interrupted")
    for field in ("no_tests", "suspicious", "timeout", "segfault"):
        if stats[field]:
            failures.append(f"{field} mutants must be zero; observed {stats[field]}")
    if score + 1e-9 < minimum_score:
        failures.append(f"mutation score {score:.2f}% is below {minimum_score:.2f}%")
    return score, failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stats", type=Path, required=True)
    parser.add_argument("--minimum-score", type=float, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--shard", required=True)
    arguments = parser.parse_args()
    try:
        stats = load_mutation_stats(arguments.stats)
        score, failures = assurance_failures(
            stats, minimum_score=arguments.minimum_score
        )
    except MutationEvidenceError as error:
        print(f"mutation assurance failed: invalid evidence: {error}")
        return 1
    document = {
        "schema_version": "1.0",
        "shard": arguments.shard,
        "minimum_score": arguments.minimum_score,
        "mutation_score": round(score, 4),
        "passed": not failures,
        "failures": failures,
        "counts": stats,
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if failures:
        print("mutation assurance failed:\n- " + "\n- ".join(failures))
        return 1
    print(f"mutation assurance passed with score {score:.2f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
