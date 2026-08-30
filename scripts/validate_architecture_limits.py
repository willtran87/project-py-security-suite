from __future__ import annotations

import ast
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]
_FILE_LINE_LIMITS = {
    "src/py_security_suite/industry_assurance.py": 17_300,
    "src/py_security_suite/risk_paths.py": 8_035,
    "src/py_security_suite/reports.py": 7_925,
    "src/py_security_suite/benchmark_execution.py": 2_440,
    "src/py_security_suite/cli.py": 2_950,
    "src/py_security_suite/cli_benchmark_arguments.py": 220,
}
_FUNCTION_LINE_LIMITS = {
    ("src/py_security_suite/benchmark_execution.py", "execute_benchmark_manifest"): 475,
    ("src/py_security_suite/industry_assurance.py", "_benchmark_runner_contract"): 730,
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
}


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
    if failures:
        raise SystemExit(
            "architecture concentration ratchet failed:\n" + "\n".join(failures)
        )
    print(
        "architecture concentration ratchet passed for "
        f"{len(_FILE_LINE_LIMITS)} files and {len(_FUNCTION_LINE_LIMITS)} functions"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
