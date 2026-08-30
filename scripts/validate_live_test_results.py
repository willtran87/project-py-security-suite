from __future__ import annotations

import argparse
import itertools
import json
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as ET  # type: ignore[import-untyped]


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _case_combination(
    name: str, parameters: dict[str, list[str]]
) -> tuple[str, ...] | None:
    if "[" not in name or not name.endswith("]"):
        return None
    parameter_id = name.rsplit("[", 1)[1][:-1]
    selected: list[str] = []
    for values in parameters.values():
        matches = [value for value in values if value in parameter_id]
        if len(matches) != 1:
            return None
        selected.append(matches[0])
    return tuple(selected)


def validate_results(
    policy: dict[str, Any], *, job_name: str, junit_path: Path
) -> dict[str, Any]:
    contracts = policy.get("required_test_matrices")
    if not isinstance(contracts, dict) or not isinstance(contracts.get(job_name), dict):
        raise ValueError(f"live-assurance policy has no test matrix for {job_name}")
    contract = contracts[job_name]
    test_name = contract.get("test")
    raw_parameters = contract.get("parameters")
    if not isinstance(test_name, str) or not isinstance(raw_parameters, dict):
        raise ValueError(f"live-assurance test matrix for {job_name} is invalid")
    parameters: dict[str, list[str]] = {}
    for dimension, raw_values in raw_parameters.items():
        if not isinstance(raw_values, list) or any(
            not isinstance(value, str) or not value for value in raw_values
        ):
            raise ValueError(f"live-assurance dimension {dimension} is invalid")
        parameters[str(dimension)] = list(raw_values)
    expected = set(itertools.product(*parameters.values()))
    tree = ET.parse(junit_path)
    root = tree.getroot()
    if root is None:
        raise ValueError("live-assurance JUnit document has no root element")
    observed: set[tuple[str, ...]] = set()
    failures: list[str] = []
    for case in root.iter("testcase"):
        name = str(case.attrib.get("name") or "")
        if not name.startswith(test_name + "["):
            continue
        combination = _case_combination(name, parameters)
        if combination is None:
            failures.append(f"unrecognized parametrized case: {name}")
            continue
        if any(
            case.find(state) is not None for state in ("failure", "error", "skipped")
        ):
            failures.append(f"required live case did not pass: {name}")
            continue
        if combination in observed:
            failures.append(f"duplicate live case: {combination}")
        observed.add(combination)
    missing = sorted(expected - observed)
    unexpected = sorted(observed - expected)
    if missing:
        failures.append(f"missing required live combinations: {missing}")
    if unexpected:
        failures.append(f"unexpected live combinations: {unexpected}")
    return {
        "schema_version": "1.0",
        "job": job_name,
        "test": test_name,
        "dimensions": parameters,
        "expected_cases": len(expected),
        "passed_cases": len(observed & expected),
        "passed": not failures,
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("junit", type=Path)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--job", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = validate_results(
        _load_object(args.policy), job_name=args.job, junit_path=args.junit
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if not result["passed"]:
        raise SystemExit(
            "live test matrix validation failed:\n" + "\n".join(result["failures"])
        )
    print(
        f"live test matrix passed {result['passed_cases']}/"
        f"{result['expected_cases']} required cases"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
