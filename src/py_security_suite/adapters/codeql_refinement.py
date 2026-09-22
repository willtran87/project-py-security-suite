"""Apply explicit native flow comparisons from the sealed supplemental pack.

This is used only by a live scan of the same database, after extraction and asset
integrity checks succeed. Imported SARIF and local AST review hints cannot invoke
it. An absent proof never removes an alert. Original native results are retained
in diagnostics for every exclusion.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, cast

from .sarif import load_sarif_document

_PROOFS = {
    "pysec/constant-path-proof": "py/path-injection",
    "pysec/constant-xpath-proof": "py/xpath-injection",
}
_MARKERS = {
    "pysec/constant-path-proof": "pysec-constant-choice-v1:",
    "pysec/constant-xpath-proof": "pysec-xpath-context-v2:",
}
_MAX_PROOFS = 256
_MAX_AUDIT_BYTES = 2 * 1024**2


def _run(document: dict[str, Any]) -> dict[str, Any]:
    runs = document.get("runs")
    if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict):
        raise ValueError("native refinement requires one CodeQL run")
    run = runs[0]
    tool = run.get("tool")
    driver = tool.get("driver") if isinstance(tool, dict) else None
    if not isinstance(driver, dict) or driver.get("name") != "CodeQL":
        raise ValueError("native refinement requires CodeQL results")
    if not isinstance(run.get("results"), list):
        raise ValueError("native refinement results are missing")
    return run


def _complete(run: dict[str, Any]) -> bool:
    invocations = run.get("invocations")
    if not isinstance(invocations, list) or not invocations:
        return False
    for invocation in invocations:
        if (
            not isinstance(invocation, dict)
            or invocation.get("executionSuccessful") is not True
        ):
            return False
        for field in ("toolExecutionNotifications", "toolConfigurationNotifications"):
            notices = invocation.get(field, [])
            if not isinstance(notices, list) or any(
                not isinstance(notice, dict)
                or notice.get("level") not in {"none", "note"}
                for notice in notices
            ):
                return False
    return True


def _location(result: dict[str, Any]) -> tuple[str, int, int, int, int] | None:
    """Require exact native source coordinates, including columns, without guessing."""
    locations = result.get("locations")
    if not isinstance(locations, list) or len(locations) != 1:
        return None
    if not isinstance(locations[0], dict):
        return None
    physical = locations[0].get("physicalLocation", {})
    if not isinstance(physical, dict):
        return None
    artifact, region = physical.get("artifactLocation"), physical.get("region")
    if not isinstance(artifact, dict) or not isinstance(region, dict):
        return None
    uri = artifact.get("uri")
    if (
        not isinstance(uri, str)
        or not uri
        or uri.startswith(("/", "\\"))
        or any(value in uri for value in ("\\", ":", "%", "?", "#"))
        or any(part in {"", ".", ".."} for part in uri.split("/"))
        or artifact.get("uriBaseId") != "%SRCROOT%"
    ):
        return None
    start, column = region.get("startLine"), region.get("startColumn")
    end, end_column = region.get("endLine", start), region.get("endColumn")
    if any(
        type(value) is not int or value < 1
        for value in (start, column, end, end_column)
    ):
        return None
    if (end, end_column) <= (start, column):
        return None
    return (
        uri,
        cast(int, start),
        cast(int, column),
        cast(int, end),
        cast(int, end_column),
    )


def refine_native_results(
    primary_payload: str,
    supplemental_payload: str,
    *,
    eligible: bool,
    normalize: Callable[[str], list[dict[str, Any]]] | None = None,
) -> tuple[str, str, dict[str, Any]]:
    primary = load_sarif_document(primary_payload)
    extra = load_sarif_document(supplemental_payload)
    # Optional refinement must not tighten the existing parser contract when a
    # pack produces no comparison records (including a valid empty report).
    runs = extra.get("runs", [])
    if isinstance(runs, list) and not any(
        isinstance(result, dict) and result.get("ruleId") in _PROOFS
        for run in runs
        if isinstance(run, dict)
        for result in run.get("results", [])
        if isinstance(run.get("results", []), list)
    ):
        return (
            primary_payload,
            supplemental_payload,
            {
                "schema_version": "1.0",
                "method": "native-flow-comparison-v2",
                "eligible": False,
                "proof_count": 0,
                "excluded_count": 0,
                "exclusions": [],
            },
        )
    primary_run, extra_run = _run(primary), _run(extra)
    proofs: dict[tuple[str, tuple[str, int, int, int, int]], dict[str, Any]] = {}
    retained_extra = []
    valid = eligible and _complete(primary_run) and _complete(extra_run)
    count = 0
    for result in extra_run["results"]:
        if not isinstance(result, dict):
            raise ValueError("invalid native refinement result")
        rule = result.get("ruleId")
        target_rule = _PROOFS.get(rule) if isinstance(rule, str) else None
        if target_rule is None:
            retained_extra.append(result)
            continue
        count += 1
        location = _location(result)
        message = result.get("message")
        if (
            location is None
            or not isinstance(message, dict)
            or message.get("text") != _MARKERS[cast(str, rule)] + target_rule
            or result.get("kind", "fail") != "fail"
            or result.get("suppressions")
            or count > _MAX_PROOFS
        ):
            valid = False
            continue
        key = (target_rule, location)
        if key in proofs:
            valid = False
        proofs[key] = result
    valid = valid and count <= _MAX_PROOFS
    extra_run["results"] = retained_extra
    retained, audit = [], []
    for result in primary_run["results"]:
        if not isinstance(result, dict):
            raise ValueError("invalid primary native result")
        location = _location(result)
        rule = result.get("ruleId")
        proof = (
            proofs.get((rule, location)) if isinstance(rule, str) and location else None
        )
        if valid and proof and result.get("codeFlows"):
            audit.append({"original_result": result, "native_proof": proof})
        else:
            retained.append(result)
    if audit and normalize is not None:
        # Resolve native artifact/trace caches with the original run context and
        # use the product's normal redaction before publishing audit evidence.
        original_results = primary_run["results"]
        primary_run["results"] = [entry["original_result"] for entry in audit]
        normalized = normalize(json.dumps(primary))
        primary_run["results"] = original_results
        if len(normalized) != len(audit):
            raise ValueError(
                "native refinement audit could not be normalized completely"
            )
        audit = [
            {"original_finding": finding, "native_proof": entry["native_proof"]}
            for finding, entry in zip(normalized, audit, strict=True)
        ]
    if len(json.dumps(audit).encode("utf-8")) > _MAX_AUDIT_BYTES:
        valid, audit = False, []
    if valid:
        primary_run["results"] = retained
    return (
        json.dumps(primary),
        json.dumps(extra),
        {
            "schema_version": "1.0",
            "method": "native-flow-comparison-v2",
            "eligible": valid,
            "proof_count": count,
            "excluded_count": len(audit),
            "exclusions": audit,
        },
    )
