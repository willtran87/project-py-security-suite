from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as DefusedElementTree  # type: ignore[import-untyped]
from defusedxml.common import DefusedXmlException  # type: ignore[import-untyped]


_MAXIMUM_INPUT_BYTES = 32 * 1024 * 1024
_REVISION = re.compile(r"^[0-9a-f]{40}$")


class AssuranceMetricsError(ValueError):
    """Raised when CI evidence cannot produce an accurate metrics summary."""


def build_metrics(
    coverage_path: Path, junit_path: Path, *, source_revision: str
) -> dict[str, object]:
    if not _REVISION.fullmatch(source_revision):
        raise AssuranceMetricsError("source revision must be a full Git SHA")
    coverage = _read_json_object(coverage_path)
    totals = coverage.get("totals")
    if not isinstance(totals, dict):
        raise AssuranceMetricsError("coverage evidence has no totals object")
    required_coverage = {
        "num_statements",
        "covered_lines",
        "missing_lines",
        "num_branches",
        "covered_branches",
        "missing_branches",
        "percent_covered",
    }
    if not required_coverage <= set(totals):
        raise AssuranceMetricsError("coverage evidence omits required totals")
    integer_fields = required_coverage - {"percent_covered"}
    if any(
        not isinstance(totals[field], int) or isinstance(totals[field], bool)
        for field in integer_fields
    ):
        raise AssuranceMetricsError("coverage totals contain invalid counts")
    percentage = totals["percent_covered"]
    if not isinstance(percentage, (int, float)) or isinstance(percentage, bool):
        raise AssuranceMetricsError("coverage percentage is invalid")
    if not 0 <= float(percentage) <= 100:
        raise AssuranceMetricsError("coverage percentage is outside 0-100")

    root = _read_junit(junit_path)
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    if not suites:
        raise AssuranceMetricsError("JUnit evidence contains no test suites")

    def total(attribute: str) -> int:
        values: list[int] = []
        for suite in suites:
            raw = suite.attrib.get(attribute, "0")
            try:
                value = int(raw)
            except ValueError as exc:
                raise AssuranceMetricsError(
                    f"JUnit {attribute} count is invalid"
                ) from exc
            if value < 0:
                raise AssuranceMetricsError(f"JUnit {attribute} count is negative")
            values.append(value)
        return sum(values)

    tests = total("tests")
    failures = total("failures")
    errors = total("errors")
    skipped = total("skipped")
    if failures + errors + skipped > tests:
        raise AssuranceMetricsError("JUnit outcome counts exceed collected tests")
    return {
        "schema_version": "1.0",
        "source_revision": source_revision,
        "coverage": {
            "combined_percent": round(float(percentage), 2),
            "statements": totals["num_statements"],
            "covered_lines": totals["covered_lines"],
            "missing_lines": totals["missing_lines"],
            "branches": totals["num_branches"],
            "covered_branches": totals["covered_branches"],
            "missing_branches": totals["missing_branches"],
        },
        "tests": {
            "collected": tests,
            "passed": tests - failures - errors - skipped,
            "failed": failures,
            "errors": errors,
            "skipped": skipped,
        },
        "claim_boundary": (
            "Metrics are derived from the retained coverage.py JSON and JUnit XML "
            "for this exact revision; they are not a timeless documentation claim."
        ),
    }


def render_markdown(metrics: dict[str, object]) -> str:
    coverage = metrics["coverage"]
    tests = metrics["tests"]
    if not isinstance(coverage, dict) or not isinstance(tests, dict):
        raise AssuranceMetricsError("metrics document is malformed")
    return (
        "# CI assurance metrics\n\n"
        f"Source revision: `{metrics['source_revision']}`\n\n"
        "| Measure | Observed |\n"
        "|---|---:|\n"
        f"| Combined line and branch coverage | {coverage['combined_percent']:.2f}% |\n"
        f"| Statements | {coverage['statements']} |\n"
        f"| Branches | {coverage['branches']} |\n"
        f"| Tests collected | {tests['collected']} |\n"
        f"| Tests passed | {tests['passed']} |\n"
        f"| Tests failed or errored | {tests['failed'] + tests['errors']} |\n"
        f"| Tests skipped | {tests['skipped']} |\n\n"
        f"> {metrics['claim_boundary']}\n"
    )


def _read_json_object(path: Path) -> dict[str, Any]:
    payload = _read_bounded(path)
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssuranceMetricsError("coverage evidence is invalid JSON") from exc
    if not isinstance(value, dict):
        raise AssuranceMetricsError("coverage evidence must be an object")
    return value


def _read_junit(path: Path) -> ElementTree.Element:
    payload = _read_bounded(path)
    if b"<!DOCTYPE" in payload.upper() or b"<!ENTITY" in payload.upper():
        raise AssuranceMetricsError("JUnit evidence must not contain a DTD or entity")
    try:
        return DefusedElementTree.fromstring(payload)
    except (ElementTree.ParseError, DefusedXmlException) as exc:
        raise AssuranceMetricsError("JUnit evidence is invalid XML") from exc


def _read_bounded(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise AssuranceMetricsError(f"evidence is not a regular file: {path}")
    payload = path.read_bytes()
    if len(payload) > _MAXIMUM_INPUT_BYTES:
        raise AssuranceMetricsError(f"evidence exceeds the byte limit: {path}")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Derive revision-bound documentation metrics from CI evidence."
    )
    parser.add_argument("--coverage", type=Path, required=True)
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    arguments = parser.parse_args()
    metrics = build_metrics(
        arguments.coverage,
        arguments.junit,
        source_revision=arguments.source_revision,
    )
    arguments.json_output.write_text(
        json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    arguments.markdown_output.write_text(render_markdown(metrics), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
