from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path
from typing import Any

try:
    from companion.strict_json import dumps as strict_dumps
    from companion.strict_json import loads as strict_loads
except ModuleNotFoundError:  # Direct script execution.
    from strict_json import dumps as strict_dumps  # type: ignore[import-not-found,no-redef]
    from strict_json import loads as strict_loads  # type: ignore[import-not-found,no-redef]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Normalize bounded Fuzz Introspector reachability and corpus-health evidence."
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--minimum-coverage-percent", type=float, default=70.0)
    args = parser.parse_args(argv)
    document = _read(args.input)
    _write(args.output, _analyze(document, args.minimum_coverage_percent))
    return 0


def _read(path: Path) -> dict[str, Any]:
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > 64 * 1024 * 1024
    ):
        raise ValueError(
            "Fuzz Introspector summary must be a regular file of at most 64 MiB"
        )
    value = strict_loads(path.read_bytes())
    if not isinstance(value, dict):
        raise TypeError("Fuzz Introspector summary root must be an object")
    return value


def _analyze(document: dict[str, Any], minimum: float) -> dict[str, Any]:
    if not 0.0 <= minimum <= 100.0 or set(document) != {
        "schema_version",
        "fuzzers",
        "health_canary_observed",
    }:
        raise ValueError("Fuzz Introspector summary fields are invalid")
    if document["schema_version"] != "1.0":
        raise ValueError("Fuzz Introspector summary requires schema 1.0")
    fuzzers = document["fuzzers"]
    if not isinstance(fuzzers, list) or not 1 <= len(fuzzers) <= 1_000:
        raise ValueError("Fuzz Introspector summary requires 1 to 1000 fuzzers")
    findings: list[dict[str, Any]] = []
    total_reachable = 0
    total_covered = 0
    for value in fuzzers:
        if not isinstance(value, dict) or set(value) != {
            "name",
            "statically_reachable_functions",
            "dynamically_covered_functions",
            "corpus_files",
            "blockers",
        }:
            raise ValueError("fuzzer summary fields do not match the contract")
        name = _label(value["name"], 160)
        reachable = _count(value["statically_reachable_functions"])
        covered = _count(value["dynamically_covered_functions"])
        corpus = _count(value["corpus_files"])
        blockers = value["blockers"]
        if covered > reachable or not isinstance(blockers, list) or len(blockers) > 500:
            raise ValueError("fuzzer coverage or blockers are invalid")
        if any(not isinstance(item, str) or len(item) > 160 for item in blockers):
            raise ValueError("fuzzer blocker labels are invalid")
        total_reachable += reachable
        total_covered += covered
        coverage = 100.0 * covered / reachable if reachable else 100.0
        if coverage < minimum or corpus == 0 or blockers:
            findings.append(_finding(name, reachable, covered, corpus, len(blockers)))
    aggregate = 100.0 * total_covered / total_reachable if total_reachable else 100.0
    return {
        "execution": {
            "status": "completed",
            "targets_discovered": len(fuzzers),
            "targets_exercised": len(fuzzers),
            "requests": len(fuzzers),
            "coverage_percent": aggregate,
            "coverage_metric": "fuzzer-static-reachability-vs-dynamic-coverage",
            "roles": ["fuzz-harness"],
            "features": [
                "static-reachability",
                "dynamic-coverage",
                "corpus-health",
            ],
            "skipped_checks": [],
            "canaries_expected": 1,
            "canaries_observed": int(document["health_canary_observed"] is True),
        },
        "findings": findings,
    }


def _finding(
    name: str, reachable: int, covered: int, corpus: int, blockers: int
) -> dict[str, Any]:
    return {
        "rule_id": "fuzz-harness-coverage-gap",
        "title": "A fuzz harness has a reachability or corpus-quality gap",
        "message": "Static reachability, dynamic coverage, corpus health, or blocker analysis indicates insufficient fuzz depth.",
        "path": "<fuzz-introspector>",
        "severity": "medium",
        "classification": "CWE-693",
        "citation": "https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/",
        "impact": "Security-sensitive parser or state space may remain unexplored by the fuzz campaign.",
        "remediation": "Improve the harness, seed corpus, dictionaries, and target decomposition until coverage and blocker gates pass.",
        "area": "fuzz-harness-quality",
        "domain": "testing",
        "fingerprint": name,
        "evidence": {
            "fuzzer": name,
            "statically_reachable": reachable,
            "dynamically_covered": covered,
            "corpus_files": corpus,
            "blockers": blockers,
        },
    }


def _count(value: object) -> int:
    if isinstance(value, bool):
        raise ValueError("fuzzer counts must be nonnegative integers")
    result = int(str(value))
    if result < 0 or result > 100_000_000:
        raise ValueError("fuzzer counts are outside bounds")
    return result


def _label(value: object, maximum: int) -> str:
    result = str(value or "").strip()
    if not result or len(result) > maximum:
        raise ValueError("fuzzer label is invalid")
    return result


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ValueError("Fuzz Introspector output is not replaceable")
    payload = (strict_dumps(value, indent=2) + "\n").encode()
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
