from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


_ROOT = Path(__file__).resolve().parents[1]
_POLICY = _ROOT / "security" / "live-assurance-policy.json"


def _matrix_values(job: dict[str, Any], dimension: str) -> set[str]:
    matrix = (job.get("strategy") or {}).get("matrix") or {}
    direct = matrix.get(dimension)
    if isinstance(direct, list):
        return {str(item) for item in direct}
    include = matrix.get("include")
    if isinstance(include, list):
        return {
            str(item[dimension])
            for item in include
            if isinstance(item, dict) and dimension in item
        }
    return set()


def _literal_parametrizations(path: Path, function_name: str) -> dict[str, set[str]]:
    tree = ast.parse(path.read_bytes(), filename=str(path))
    function = next(
        (
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == function_name
        ),
        None,
    )
    if function is None:
        return {}
    observed: dict[str, set[str]] = {}
    for decorator in function.decorator_list:
        if (
            not isinstance(decorator, ast.Call)
            or not isinstance(decorator.func, ast.Attribute)
            or decorator.func.attr != "parametrize"
            or len(decorator.args) < 2
        ):
            continue
        try:
            dimension = ast.literal_eval(decorator.args[0])
            values = ast.literal_eval(decorator.args[1])
        except (TypeError, ValueError):
            continue
        if isinstance(dimension, str) and isinstance(values, (list, tuple)):
            observed[dimension] = {str(item) for item in values}
    return observed


def policy_failures(
    policy: dict[str, Any], workflow: dict[str, Any], *, root: Path = _ROOT
) -> list[str]:
    failures: list[str] = []
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return ["workflow jobs are missing"]
    required_jobs = policy.get("required_jobs")
    gate_name = policy.get("required_gate")
    gate = jobs.get(gate_name) if isinstance(gate_name, str) else None
    needs = gate.get("needs") if isinstance(gate, dict) else None
    if not isinstance(required_jobs, list) or not isinstance(needs, list):
        failures.append("required gate dependency contract is invalid")
    else:
        missing = sorted(set(required_jobs) - set(needs))
        if missing:
            failures.append("required gate omits live jobs: " + ", ".join(missing))
    matrices = policy.get("required_matrices")
    if not isinstance(matrices, dict):
        failures.append("required matrix contract is invalid")
        return failures
    for job_name, dimensions in matrices.items():
        job = jobs.get(job_name)
        if not isinstance(job, dict) or not isinstance(dimensions, dict):
            failures.append(f"required live job is missing: {job_name}")
            continue
        for dimension, expected in dimensions.items():
            if not isinstance(expected, list):
                failures.append(f"{job_name} {dimension} policy is invalid")
                continue
            observed_matrix = _matrix_values(job, dimension)
            missing = sorted({str(item) for item in expected} - observed_matrix)
            if missing:
                failures.append(
                    f"{job_name} omits required {dimension} values: "
                    + ", ".join(missing)
                )
    test_matrices = policy.get("required_test_matrices", {})
    if not isinstance(test_matrices, dict):
        failures.append("required test-matrix contract is invalid")
        return failures
    for job_name, contract in test_matrices.items():
        if not isinstance(contract, dict):
            failures.append(f"{job_name} test-matrix contract is invalid")
            continue
        relative = contract.get("path")
        test_name = contract.get("test")
        expected_parameters = contract.get("parameters")
        junit_output = contract.get("junit_output")
        path = root / str(relative or "")
        job = jobs.get(job_name)
        job_text = json.dumps(job, sort_keys=True)
        if (
            not isinstance(relative, str)
            or not isinstance(test_name, str)
            or not isinstance(expected_parameters, dict)
            or not isinstance(junit_output, str)
            or not path.is_file()
            or relative not in job_text
            or junit_output not in job_text
            or "validate_live_test_results" not in job_text
        ):
            failures.append(
                f"{job_name} required live-test evidence contract is invalid"
            )
            continue
        parametrizations = _literal_parametrizations(path, test_name)
        for dimension, expected in expected_parameters.items():
            if not isinstance(expected, list) or any(
                not isinstance(item, str) or not item for item in expected
            ):
                failures.append(f"{job_name} {dimension} test policy is invalid")
                continue
            actual = parametrizations.get(str(dimension), set())
            required = set(expected)
            if actual != required:
                failures.append(
                    f"{job_name} {dimension} parametrization differs: "
                    f"expected {sorted(required)}, observed {sorted(actual)}"
                )
    return failures


def main() -> int:
    policy = json.loads(_POLICY.read_text(encoding="utf-8"))
    workflow_path = _ROOT / str(policy.get("workflow") or "")
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    failures = policy_failures(policy, workflow)
    if failures:
        raise SystemExit("live assurance policy failed:\n" + "\n".join(failures))
    print(
        "live assurance policy passed for "
        f"{len(policy['required_jobs'])} mandatory jobs and "
        f"{len(policy['required_matrices'])} infrastructure matrices and "
        f"{len(policy['required_test_matrices'])} executable test matrices"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
