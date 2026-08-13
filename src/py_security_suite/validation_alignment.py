from __future__ import annotations

from collections import defaultdict
from typing import Any


TEST_EVIDENCE_ARTIFACTS = (
    "junit-summary.json",
    "hypothesis-summary.json",
    "schemathesis-summary.json",
)


def build_test_execution_index(
    artifacts: dict[str, Any],
) -> tuple[dict[str, list[dict[str, str]]], dict[str, Any]]:
    """Index bounded, output-free test cases by normalized repository path."""
    by_path: dict[str, list[dict[str, str]]] = defaultdict(list)
    sources: list[str] = []
    inventory_sources: list[str] = []
    inventory_complete: list[bool] = []
    for name in TEST_EVIDENCE_ARTIFACTS:
        document = artifacts.get(name)
        if not isinstance(document, dict):
            continue
        sources.append(name)
        cases = document.get("test_cases")
        if not isinstance(cases, list):
            continue
        inventory_sources.append(name)
        inventory_complete.append(document.get("test_case_inventory_complete") is True)
        for item in cases[:100_000]:
            if not isinstance(item, dict):
                continue
            path = normalize_test_path(str(item.get("file") or ""))
            result = str(item.get("result") or "")
            if not path or path in {".", "<outside-target>"} or result not in {
                "passed",
                "failure",
                "error",
                "skipped",
            }:
                continue
            attribution = str(item.get("file_attribution") or "producer")
            if attribution not in {"producer", "classname-module"}:
                continue
            by_path[path].append(
                {
                    "source": name,
                    "result": result,
                    "file_attribution": attribution,
                }
            )
    return dict(by_path), {
        "available": bool(sources),
        "case_inventory_available": bool(inventory_sources),
        "case_inventory_complete": (
            all(inventory_complete) if inventory_sources else None
        ),
        "sources": sorted(sources),
        "inventory_sources": sorted(inventory_sources),
    }


def focused_test_execution(
    recommended: list[str],
    *,
    test_executions: dict[str, list[dict[str, str]]],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Describe exact execution evidence for graph-selected test files."""
    records: list[dict[str, Any]] = []
    unobserved: list[str] = []
    for raw_path in recommended[:50]:
        path = normalize_test_path(raw_path)
        cases = test_executions.get(path, [])
        counts = {
            result: sum(item["result"] == result for item in cases)
            for result in ("passed", "failure", "error", "skipped")
        }
        status = (
            "failed"
            if counts["failure"] or counts["error"]
            else "partial"
            if counts["passed"] and counts["skipped"]
            else "passed"
            if counts["passed"]
            else "skipped"
            if counts["skipped"]
            else "not-observed"
        )
        if status == "not-observed":
            unobserved.append(path)
        records.append(
            {
                "path": path,
                "status": status,
                "tests": len(cases),
                "passed": counts["passed"],
                "failures": counts["failure"],
                "errors": counts["error"],
                "skipped": counts["skipped"],
                "sources": sorted({item["source"] for item in cases}),
                "path_attributions": sorted(
                    {item["file_attribution"] for item in cases}
                ),
            }
        )
    statuses = {str(item["status"]) for item in records}
    validation_status = (
        "not-selected"
        if not recommended
        else "not-available"
        if evidence.get("case_inventory_available") is not True
        else "failed"
        if "failed" in statuses
        else "not-observed"
        if statuses == {"not-observed"}
        else "passed"
        if statuses == {"passed"}
        else "incomplete"
    )
    return {
        "test_execution_evidence_available": evidence.get("available") is True,
        "test_case_inventory_available": evidence.get("case_inventory_available")
        is True,
        "test_case_inventory_complete": evidence.get("case_inventory_complete"),
        "test_execution_sources": list(evidence.get("sources") or [])[:10],
        "focused_test_execution": records,
        "focused_test_validation_status": validation_status,
        "unobserved_recommended_test_files": unobserved,
    }


def test_coverage_alignment(
    execution: dict[str, Any],
    *,
    coverage_evidence_available: bool,
    coverage_gap: bool,
    coverage_subject: str,
) -> dict[str, Any]:
    """Cross-check selected-test execution with coverage of the affected code."""
    status = str(execution.get("focused_test_validation_status") or "not-available")
    reasons: list[str] = []
    if status == "not-selected":
        alignment = "not-selected"
        reasons.append("No graph-selected focused test file was available.")
    elif status == "not-available":
        alignment = "test-evidence-not-available"
        reasons.append(
            "Case-level test execution evidence was unavailable for the selected files."
        )
    elif status == "failed":
        alignment = "tests-failing"
        reasons.append("A graph-selected focused test reported a failure or error.")
    elif status == "not-observed":
        alignment = "tests-not-observed"
        reasons.append("No retained case matched a graph-selected focused test file.")
    elif status == "incomplete":
        alignment = "tests-incomplete"
        reasons.append(
            "Selected test execution was partial, skipped, or missing for at least one file."
        )
    elif not coverage_evidence_available:
        alignment = "coverage-not-available"
        reasons.append(f"Coverage evidence was unavailable for {coverage_subject}.")
    elif coverage_gap:
        alignment = "coverage-gap"
        reasons.append(
            "Focused tests passed, but retained coverage did not exercise "
            + coverage_subject
            + "."
        )
    else:
        alignment = "aligned-current-evidence"
    return {
        "test_coverage_alignment": alignment,
        "validation_gap_reasons": reasons,
    }


def normalize_test_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    return normalized[2:] if normalized.startswith("./") else normalized


