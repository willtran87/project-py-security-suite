"""Reject hand-maintained documentation metrics that drift from enforced code."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from py_security_suite.report_inspection import BUNDLED_SCHEMA_RESOURCES

_ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(_ROOT))

from scripts.validate_architecture_limits import (  # noqa: E402
    _FILE_LINE_LIMITS,
    _FUNCTION_DECISION_LIMITS,
    _FUNCTION_LINE_LIMITS,
)


def documentation_metric_failures() -> list[str]:
    design = (_ROOT / "docs/design.md").read_text(encoding="utf-8")
    index = (_ROOT / "docs/index.md").read_text(encoding="utf-8")
    architecture = re.search(
        r"pysec-architecture-metrics files=(\d+) function_lengths=(\d+) "
        r"decision_budgets=(\d+)",
        design,
    )
    failures: list[str] = []
    expected_architecture = (
        len(_FILE_LINE_LIMITS),
        len(_FUNCTION_LINE_LIMITS),
        len(_FUNCTION_DECISION_LIMITS),
    )
    if architecture is None or tuple(map(int, architecture.groups())) != expected_architecture:
        failures.append(
            "design architecture marker does not match enforced concentration budgets"
        )

    schemas = len(list((_ROOT / "src/py_security_suite/schemas").glob("*.json")))
    baseline = json.loads(
        (_ROOT / "security/api-surface-1.1.json").read_text(encoding="utf-8")
    )
    stable = baseline.get("stable_schema_resources", [])
    if not isinstance(stable, list):
        failures.append("public API stable_schema_resources must be an array")
        stable_count = -1
    else:
        stable_count = len(stable)
    schema_marker = re.search(
        r"pysec-schema-metrics files=(\d+) runtime_exports=(\d+) stable_contracts=(\d+)",
        index,
    )
    expected_schema = (schemas, len(BUNDLED_SCHEMA_RESOURCES), stable_count)
    if schema_marker is None or tuple(map(int, schema_marker.groups())) != expected_schema:
        failures.append("index schema marker does not match runtime and compatibility data")
    for stale in ("1,559 passed", "204 bundled JSON Schemas"):
        if stale in index:
            failures.append(f"index retains stale metric {stale!r}")
    return failures


def main() -> int:
    try:
        failures = documentation_metric_failures()
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"documentation metrics failed: {error}", file=sys.stderr)
        return 1
    if failures:
        print("documentation metrics failed:\n- " + "\n- ".join(failures), file=sys.stderr)
        return 1
    print("documentation metrics match enforced repository contracts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
