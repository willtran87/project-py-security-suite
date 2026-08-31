from __future__ import annotations

import ast
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]
_FILE_LINE_LIMITS = {
    "src/py_security_suite/industry_assurance.py": 5_400,
    "src/py_security_suite/industry_standards_catalog.py": 6_243,
    "src/py_security_suite/industry_benchmark_catalog.py": 2_398,
    "src/py_security_suite/industry_profile_catalog.py": 6_888,
    "src/py_security_suite/risk_paths.py": 8_035,
    "src/py_security_suite/reports.py": 7_925,
    "src/py_security_suite/data_exposure.py": 3_800,
    "src/py_security_suite/evidence_ingest.py": 2_550,
    "src/py_security_suite/artifact_validation.py": 2_500,
    "src/py_security_suite/benchmark_execution.py": 2_440,
    "src/py_security_suite/cli.py": 2_950,
    "src/py_security_suite/execution.py": 1_560,
    "src/py_security_suite/cli_benchmark_arguments.py": 220,
    "src/py_security_suite/cli_release_arguments.py": 100,
}
_FUNCTION_LINE_LIMITS = {
    ("src/py_security_suite/benchmark_execution.py", "execute_benchmark_manifest"): 475,
    ("src/py_security_suite/industry_assurance.py", "_benchmark_runner_contract"): 737,
    (
        "src/py_security_suite/industry_assurance.py",
        "_benchmark_reproducibility_gaps",
    ): 495,
    ("src/py_security_suite/orchestrator.py", "_scan_sealed_project"): 685,
    ("src/py_security_suite/risk_paths.py", "build_risk_paths"): 1_175,
    ("src/py_security_suite/cli.py", "build_parser"): 1_050,
    (
        "src/py_security_suite/cli_benchmark_arguments.py",
        "add_benchmark_commands",
    ): 210,
    (
        "src/py_security_suite/cli_release_arguments.py",
        "add_release_check_command",
    ): 90,
    ("src/py_security_suite/industry_assurance.py", "_threat_model_assessment"): 600,
    ("src/py_security_suite/reports.py", "_render_risk_path_summary"): 575,
    ("src/py_security_suite/isolation_probe.py", "probe_isolation_boundary"): 400,
    (
        "src/py_security_suite/semantic_coverage.py",
        "semantic_language_coverage_artifact",
    ): 315,
    (
        "src/py_security_suite/artifact_validation.py",
        "_validate_native_normalization",
    ): 340,
}
_FUNCTION_DECISION_LIMITS = {
    ("src/py_security_suite/risk_paths.py", "build_risk_paths"): 230,
    ("src/py_security_suite/industry_assurance.py", "_threat_model_assessment"): 140,
    ("src/py_security_suite/reports.py", "_render_risk_path_summary"): 130,
    ("src/py_security_suite/benchmark_execution.py", "execute_benchmark_manifest"): 70,
    ("src/py_security_suite/isolation_probe.py", "probe_isolation_boundary"): 75,
    (
        "src/py_security_suite/semantic_coverage.py",
        "semantic_language_coverage_artifact",
    ): 150,
}
_DECISION_NODES = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Try,
    ast.Match,
    ast.IfExp,
    ast.BoolOp,
    ast.comprehension,
)


def main() -> int:
    failures: list[str] = []
    parsed: dict[str, ast.Module] = {}
    for relative, maximum in _FILE_LINE_LIMITS.items():
        path = _ROOT / relative
        text = path.read_text(encoding="utf-8")
        lines = len(text.splitlines())
        if lines > maximum:
            failures.append(f"{relative}: {lines} lines exceeds {maximum}")
        parsed[relative] = ast.parse(text, filename=relative)
    for (relative, function_name), maximum in _FUNCTION_LINE_LIMITS.items():
        tree = parsed.get(relative)
        if tree is None:
            path = _ROOT / relative
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            parsed[relative] = tree
        functions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == function_name
        ]
        if len(functions) != 1:
            failures.append(f"{relative}: expected exactly one {function_name}")
            continue
        function = functions[0]
        end = function.end_lineno or function.lineno
        lines = end - function.lineno + 1
        if lines > maximum:
            failures.append(
                f"{relative}:{function.lineno} {function_name} has {lines} lines; "
                f"limit is {maximum}"
            )
    for (relative, function_name), maximum in _FUNCTION_DECISION_LIMITS.items():
        tree = parsed.get(relative)
        if tree is None:
            path = _ROOT / relative
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            parsed[relative] = tree
        functions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == function_name
        ]
        if len(functions) != 1:
            failures.append(f"{relative}: expected exactly one {function_name}")
            continue
        decisions = sum(
            isinstance(node, _DECISION_NODES) for node in ast.walk(functions[0])
        )
        if decisions > maximum:
            failures.append(
                f"{relative}:{functions[0].lineno} {function_name} has "
                f"{decisions} decision nodes; limit is {maximum}"
            )
    if failures:
        raise SystemExit(
            "architecture concentration ratchet failed:\n" + "\n".join(failures)
        )
    print(
        "architecture concentration ratchet passed for "
        f"{len(_FILE_LINE_LIMITS)} files, {len(_FUNCTION_LINE_LIMITS)} function "
        f"lengths, and {len(_FUNCTION_DECISION_LIMITS)} decision budgets"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
