from __future__ import annotations

import ast
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]
_MAXIMUM_UNTRACKED_FILE_LINES = 2_000
_MAXIMUM_UNTRACKED_FUNCTION_LINES = 300
_MAXIMUM_UNTRACKED_FUNCTION_DECISIONS = 65
_FILE_LINE_LIMITS = {
    "src/py_security_suite/industry_assurance.py": 5_420,
    "src/py_security_suite/industry_standards_catalog.py": 6_256,
    "src/py_security_suite/industry_benchmark_catalog.py": 2_409,
    "src/py_security_suite/industry_profile_catalog.py": 6_896,
    "src/py_security_suite/industry_interoperability_sector_catalog.py": 413,
    "src/py_security_suite/industry_maturity_product_catalog.py": 630,
    "src/py_security_suite/industry_emerging_assurance_catalog.py": 1_188,
    "src/py_security_suite/industry_extension_evidence.py": 3_606,
    "src/py_security_suite/risk_paths.py": 8_028,
    "src/py_security_suite/reports.py": 7_924,
    "src/py_security_suite/data_exposure.py": 3_774,
    "src/py_security_suite/evidence_ingest.py": 2_523,
    "src/py_security_suite/artifact_validation.py": 2_482,
    "src/py_security_suite/benchmark_execution.py": 2_432,
    "src/py_security_suite/benchmark_adapters.py": 3_130,
    "src/py_security_suite/cli.py": 2_920,
    "src/py_security_suite/closure_plan.py": 3_043,
    "src/py_security_suite/config.py": 2_528,
    "src/py_security_suite/execution.py": 1_560,
    "src/py_security_suite/reachability.py": 2_295,
    "src/py_security_suite/cli_benchmark_arguments.py": 209,
    "src/py_security_suite/cli_release_arguments.py": 70,
}
_FUNCTION_LINE_LIMITS = {
    ("src/py_security_suite/benchmark_execution.py", "execute_benchmark_manifest"): 458,
    ("src/py_security_suite/industry_assurance.py", "_benchmark_runner_contract"): 737,
    (
        "src/py_security_suite/industry_assurance.py",
        "_benchmark_reproducibility_gaps",
    ): 490,
    ("src/py_security_suite/orchestrator.py", "_scan_sealed_project"): 586,
    ("src/py_security_suite/risk_paths.py", "build_risk_paths"): 1_165,
    ("src/py_security_suite/cli.py", "build_parser"): 972,
    ("src/py_security_suite/config.py", "_default_mapping"): 627,
    (
        "src/py_security_suite/cli_benchmark_arguments.py",
        "add_benchmark_commands",
    ): 203,
    (
        "src/py_security_suite/cli_release_arguments.py",
        "add_release_check_command",
    ): 64,
    ("src/py_security_suite/industry_assurance.py", "_threat_model_assessment"): 591,
    ("src/py_security_suite/reports.py", "_render_risk_path_summary"): 566,
    ("src/py_security_suite/isolation_probe.py", "probe_isolation_boundary"): 297,
    (
        "src/py_security_suite/semantic_coverage.py",
        "semantic_language_coverage_artifact",
    ): 306,
    (
        "src/py_security_suite/artifact_validation.py",
        "_validate_native_normalization",
    ): 331,
    (
        "src/py_security_suite/requirements_coverage.py",
        "security_requirements_coverage_artifact",
    ): 352,
    ("src/py_security_suite/industry_assurance.py", "_oscal_documents"): 351,
    ("src/py_security_suite/code_health.py", "analyze_code_health"): 321,
    ("src/py_security_suite/reports.py", "render_assurance_case"): 316,
    (
        "src/py_security_suite/benchmark_evidence.py",
        "verify_benchmark_evidence_documents",
    ): 314,
    ("src/py_security_suite/risk_paths.py", "_owner_work_queues"): 312,
    (
        "src/py_security_suite/industry_assurance.py",
        "_assurance_case_assessment",
    ): 306,
    ("src/py_security_suite/data_exposure.py", "_sdk_dependency_contexts"): 305,
    ("src/py_security_suite/runtime_trace.py", "runtime_trace_artifact"): 301,
}
_FUNCTION_DECISION_LIMITS = {
    ("src/py_security_suite/risk_paths.py", "build_risk_paths"): 222,
    ("src/py_security_suite/industry_assurance.py", "_threat_model_assessment"): 135,
    ("src/py_security_suite/reports.py", "_render_risk_path_summary"): 121,
    ("src/py_security_suite/benchmark_execution.py", "execute_benchmark_manifest"): 58,
    ("src/py_security_suite/isolation_probe.py", "probe_isolation_boundary"): 45,
    (
        "src/py_security_suite/semantic_coverage.py",
        "semantic_language_coverage_artifact",
    ): 143,
    ("src/py_security_suite/orchestrator.py", "_scan_sealed_project"): 69,
    (
        "src/py_security_suite/industry_assurance.py",
        "_assurance_case_assessment",
    ): 85,
    ("src/py_security_suite/data_exposure.py", "_sdk_dependency_contexts"): 83,
    ("src/py_security_suite/reports.py", "_markdown_risk_path_context"): 77,
    ("src/py_security_suite/data_exposure.py", "apply_data_exposure_fusion"): 80,
    ("src/py_security_suite/reports.py", "_html_risk_path_context"): 74,
    ("src/py_security_suite/industry_assurance.py", "_lifecycle_trace_graph"): 75,
    ("src/py_security_suite/domain_assurance.py", "_domain_signals"): 86,
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
    tracked_files = set(_FILE_LINE_LIMITS)
    tracked_functions = set(_FUNCTION_LINE_LIMITS) | set(_FUNCTION_DECISION_LIMITS)
    for path in sorted((_ROOT / "src/py_security_suite").rglob("*.py")):
        relative = path.relative_to(_ROOT).as_posix()
        text = path.read_text(encoding="utf-8")
        module = ast.parse(text, filename=relative)
        parsed[relative] = module
        lines = len(text.splitlines())
        if lines > _MAXIMUM_UNTRACKED_FILE_LINES and relative not in tracked_files:
            failures.append(
                f"{relative}: {lines} lines exceeds the untracked-file limit of "
                f"{_MAXIMUM_UNTRACKED_FILE_LINES}; add an explicit debt ratchet"
            )
        for function in (
            node
            for node in ast.walk(module)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            key = (relative, function.name)
            function_lines = (
                (function.end_lineno or function.lineno) - function.lineno + 1
            )
            decisions = sum(
                isinstance(node, _DECISION_NODES) for node in ast.walk(function)
            )
            if (
                function_lines > _MAXIMUM_UNTRACKED_FUNCTION_LINES
                or decisions > _MAXIMUM_UNTRACKED_FUNCTION_DECISIONS
            ) and key not in tracked_functions:
                failures.append(
                    f"{relative}:{function.lineno} {function.name} has "
                    f"{function_lines} lines and {decisions} decisions; add an "
                    "explicit debt ratchet before increasing concentration"
                )
    for relative, maximum in _FILE_LINE_LIMITS.items():
        path = _ROOT / relative
        text = path.read_text(encoding="utf-8")
        lines = len(text.splitlines())
        if lines > maximum:
            failures.append(f"{relative}: {lines} lines exceeds {maximum}")
        elif lines < maximum:
            failures.append(
                f"{relative}: debt improved to {lines} lines; tighten the ratchet "
                f"from {maximum} in the same change"
            )
        parsed.setdefault(relative, ast.parse(text, filename=relative))
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
        elif lines < maximum:
            failures.append(
                f"{relative}:{function.lineno} {function_name} improved to {lines} "
                f"lines; tighten the ratchet from {maximum} in the same change"
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
        elif decisions < maximum:
            failures.append(
                f"{relative}:{functions[0].lineno} {function_name} improved to "
                f"{decisions} decision nodes; tighten the ratchet from {maximum} "
                "in the same change"
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
