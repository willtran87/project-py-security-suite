"""Validation campaigns, shared-test hotspots and campaign assurance review."""

from __future__ import annotations

import json
from collections import defaultdict, deque
from typing import Any

from .risk_path_values import _object, _strings, _nonnegative_integer
from .models import Finding, FindingStatus
from .ownership import owners_for_path
from .validation_alignment import (
    TEST_EVIDENCE_ARTIFACTS,
    build_test_execution_index,
    focused_test_execution,
    test_coverage_alignment,
)
from .risk_path_common import (
    _MAX_CAMPAIGN_MISSING_LINES,
    _MAX_CAMPAIGN_TESTS,
    _MAX_GRAPH_FILES,
    _MAX_ROUTES,
    _digest,
    _is_test_path,
    _optional_number,
    _optional_string,
    _path,
    _priority_rank,
)


__all__ = [
    "_attach_shared_test_evidence_quality",
    "_campaign_control_context_index",
    "_empty_campaign_control_context",
    "_refresh_validation_test_hotspot_review",
    "_validation_campaigns",
    "_validation_test_hotspots",
]


_MAX_TEST_GRAPH_NEIGHBORS = 500


def _validation_campaigns(
    hotspots: list[dict[str, Any]],
    routes: list[dict[str, Any]],
    adjacency: dict[str, dict[str, str]],
    artifacts: dict[str, Any],
) -> list[dict[str, Any]]:
    incoming = _reverse_adjacency(adjacency)
    coverage = _campaign_coverage_index(artifacts.get("coverage-summary.json"))
    control_context = _campaign_control_context_index(
        artifacts.get("structural-synthesis.json"),
        artifacts.get("reachability.json"),
    )
    source_sha256, source_files = _campaign_source_index(
        artifacts.get("source-inventory.json")
    )
    test_executions, test_evidence = build_test_execution_index(artifacts)
    routes_by_id = {str(route["route_id"]): route for route in routes}
    campaigns: list[dict[str, Any]] = []
    for hotspot in hotspots:
        path = str(hotspot["path"])
        direct, transitive = _graph_selected_tests(path, incoming)
        route_mapped = sorted(
            {
                _path(value)
                for value in hotspot.get("mapped_test_files", [])
                if _is_test_path(_path(value))
            }
        )[:_MAX_CAMPAIGN_TESTS]
        selected = list(dict.fromkeys([*direct, *transitive, *route_mapped]))[
            :_MAX_CAMPAIGN_TESTS
        ]
        selection_confidence = (
            "high"
            if direct
            else "medium"
            if transitive
            else "context-only"
            if route_mapped
            else "not-available"
        )
        execution = focused_test_execution(
            selected,
            test_executions=test_executions,
            evidence=test_evidence,
        )
        coverage_record = coverage.get(path)
        missing_lines = (
            list(coverage_record["missing_lines"])
            if coverage_record is not None
            else []
        )
        percent = coverage_record.get("percent") if coverage_record else None
        coverage_available = isinstance(percent, (int, float))
        coverage_gap = bool(missing_lines) or (
            isinstance(percent, (int, float)) and float(percent) < 100.0
        )
        coverage_status = (
            "not-available"
            if not coverage_available
            else "gap"
            if coverage_gap
            else "covered"
        )
        alignment = test_coverage_alignment(
            execution,
            coverage_evidence_available=coverage_available,
            coverage_gap=coverage_gap,
            coverage_subject=(
                f"all executable lines in shared control-point file {path}"
            ),
        )
        campaign_id = (
            "campaign-"
            + _digest(
                {
                    "hotspot_id": hotspot["hotspot_id"],
                    "path": path,
                    "selected_tests": selected,
                }
            )[:16]
        )
        evidence_artifacts = sorted(
            {
                *({"graphify.json"} if direct or transitive else set()),
                *({"structural-synthesis.json"} if route_mapped else set()),
                *({"coverage-summary.json"} if coverage_available else set()),
                *test_evidence.get("sources", []),
            }
        )
        snapshot = _campaign_source_snapshot(
            path,
            selected,
            source_sha256=source_sha256,
            source_files=source_files,
            artifacts=artifacts,
            evidence_artifacts=evidence_artifacts,
        )
        context = control_context.get(
            path,
            _empty_campaign_control_context(),
        )
        route_assurance = _campaign_route_assurance(hotspot, routes_by_id)
        review = _campaign_review_assessment(
            hotspot,
            execution_status=str(execution["focused_test_validation_status"]),
            test_execution_sources=_strings(
                execution.get("test_execution_sources"), 10
            ),
            coverage_status=coverage_status,
            context=context,
            revision_binding=str(snapshot["evidence_revision_binding"]),
            route_assurance=route_assurance,
        )
        campaigns.append(
            {
                "campaign_id": campaign_id,
                "hotspot_id": hotspot["hotspot_id"],
                "path": path,
                "priority": hotspot["priority"],
                "owners": list(hotspot["owners"]),
                "route_ids": list(hotspot["route_ids"]),
                "target_ids": list(hotspot["target_ids"]),
                "finding_ids": list(hotspot["finding_ids"]),
                "direct_test_files": direct,
                "transitive_test_files": transitive,
                "route_mapped_test_files": route_mapped,
                "selected_test_files": selected,
                "test_selection_confidence": selection_confidence,
                **execution,
                "coverage_status": coverage_status,
                "coverage_evidence_scope": (
                    "aggregate-retained-file" if coverage_available else "not-available"
                ),
                "coverage_attribution": "not-established",
                "coverage_percent": percent,
                "missing_line_count": (
                    int(coverage_record["missing_line_count"])
                    if coverage_record is not None
                    else 0
                ),
                "missing_lines": missing_lines[:_MAX_CAMPAIGN_MISSING_LINES],
                **alignment,
                "control_point_context": context,
                "route_evidence_assurance": route_assurance,
                "source_snapshot": snapshot,
                **review,
                "recommended_action": _campaign_action(
                    str(alignment["test_coverage_alignment"]),
                    selected,
                    path,
                    revision_binding=str(snapshot["evidence_revision_binding"]),
                    context=context,
                    route_assurance=route_assurance,
                ),
                "evidence_artifacts": sorted(
                    {
                        *evidence_artifacts,
                        *context["evidence_artifacts"],
                        *route_assurance["evidence_artifacts"],
                        *(
                            {"source-inventory.json"}
                            if snapshot["source_inventory_available"]
                            else set()
                        ),
                    }
                ),
                "interpretation": (
                    "Static test selection plus retained execution and coverage "
                    "evidence supports a shared regression plan. Coverage is "
                    "aggregate file evidence and is not attributed solely to the "
                    "selected tests; neither lane proves security, exploitability, "
                    "complete runtime behavior, or the assurance of the scanner "
                    "evidence that selected the routes."
                ),
            }
        )
    return campaigns


def _validation_test_hotspots(
    campaigns: list[dict[str, Any]],
    findings: list[Finding],
    ownership_rules: list[tuple[str, list[str]]],
) -> list[dict[str, Any]]:
    findings_by_path = _test_file_findings_index(findings)
    grouped = _campaigns_by_selected_test(campaigns)
    result = [
        record
        for test_path, selected_campaigns in grouped.items()
        if (
            record := _validation_test_hotspot_record(
                test_path,
                selected_campaigns,
                findings_by_path=findings_by_path,
                ownership_rules=ownership_rules,
            )
        )
        is not None
    ]
    result.sort(
        key=lambda item: (
            -int(item["highest_review_score"]),
            -len(item["campaign_ids"]),
            str(item["test_path"]),
        )
    )
    return result


def _campaigns_by_selected_test(
    campaigns: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for campaign in campaigns:
        for path in campaign.get("selected_test_files", [])[:_MAX_CAMPAIGN_TESTS]:
            if isinstance(path, str) and path:
                grouped[path].append(campaign)
    return grouped


def _validation_test_hotspot_record(
    test_path: str,
    campaigns: list[dict[str, Any]],
    *,
    findings_by_path: dict[str, list[dict[str, Any]]],
    ownership_rules: list[tuple[str, list[str]]],
) -> dict[str, Any] | None:
    campaign_ids = sorted({str(campaign["campaign_id"]) for campaign in campaigns})
    if len(campaign_ids) < 2:
        return None
    execution = _shared_test_execution_context(test_path, campaigns)
    ownership = _shared_test_ownership_context(
        test_path,
        campaigns,
        findings_by_path=findings_by_path,
        ownership_rules=ownership_rules,
    )
    single_dependency_ids = sorted(
        str(campaign["campaign_id"])
        for campaign in campaigns
        if len(campaign.get("selected_test_files", [])) == 1
    )
    highest_score = max(int(campaign["review_score"]) for campaign in campaigns)
    test_findings = ownership["test_findings"]
    quality = _shared_test_quality(
        statuses=execution["statuses"],
        source_binding=execution["source_binding"],
        source_binding_consistent=execution["binding_consistent"],
        test_findings=test_findings,
        owner_alignment=ownership["owner_alignment"],
        single_dependencies=len(single_dependency_ids),
    )
    return {
        "test_hotspot_id": "test-hotspot-"
        + _digest({"path": test_path, "campaign_ids": campaign_ids})[:16],
        "test_path": test_path,
        "campaign_ids": campaign_ids,
        "control_point_paths": _campaign_values(campaigns, "path"),
        "route_ids": _campaign_values(campaigns, "route_ids"),
        "target_ids": _campaign_values(campaigns, "target_ids"),
        "finding_ids": _campaign_values(campaigns, "finding_ids"),
        "owners": ownership["campaign_owners"],
        "test_file_owners": ownership["test_owners"],
        "ownership_evidence_available": bool(ownership_rules),
        "test_owner_alignment": ownership["owner_alignment"],
        "test_file_findings": test_findings,
        "test_file_finding_ids": [
            str(finding["finding_id"]) for finding in test_findings
        ],
        "test_file_finding_tools": sorted(
            {str(tool) for finding in test_findings for tool in finding["tools"]}
        ),
        "test_file_highest_severity": _highest_severity(
            [str(finding["severity"]) for finding in test_findings]
        ),
        **quality,
        "highest_priority": min(
            (str(campaign["priority"]) for campaign in campaigns),
            key=_priority_rank,
        ),
        "highest_review_score": highest_score,
        "highest_review_tier": _review_tier(highest_score),
        "direct_campaigns": _campaigns_selecting_test(
            test_path, campaigns, "direct_test_files"
        ),
        "transitive_campaigns": _campaigns_selecting_test(
            test_path, campaigns, "transitive_test_files"
        ),
        "route_mapped_campaigns": _campaigns_selecting_test(
            test_path, campaigns, "route_mapped_test_files"
        ),
        "single_test_dependency_campaign_ids": single_dependency_ids,
        "execution_statuses": execution["statuses"],
        "observed_case_count": execution["observed_case_count"],
        "execution_sources": execution["sources"],
        "source_binding": execution["source_binding"],
        "source_binding_consistent": execution["binding_consistent"],
        "recommended_action": _validation_test_hotspot_action(
            test_path,
            statuses=execution["statuses"],
            campaigns=len(campaign_ids),
            controls=len(_campaign_values(campaigns, "path")),
            single_dependencies=len(single_dependency_ids),
            source_binding_consistent=execution["binding_consistent"],
            test_findings=test_findings,
            test_owners=ownership["test_owners"],
            owner_alignment=ownership["owner_alignment"],
        ),
        "evidence_artifacts": _shared_test_evidence_artifacts(
            campaigns,
            source_binding=execution["source_binding"],
            has_findings=bool(test_findings),
            has_ownership=bool(ownership_rules),
        ),
        "interpretation": (
            "This record identifies one test file selected for multiple shared-control "
            "campaigns. Repeated selection supports coordinated validation planning but "
            "does not establish independent assertions, finding correctness, test "
            "quality, or sufficient behavioral coverage."
        ),
    }


def _shared_test_execution_context(
    test_path: str, campaigns: list[dict[str, Any]]
) -> dict[str, Any]:
    records = [
        record
        for campaign in campaigns
        for record in campaign.get("focused_test_execution", [])
        if isinstance(record, dict) and record.get("path") == test_path
    ]
    bindings = [
        binding
        for campaign in campaigns
        for binding in campaign["source_snapshot"].get("selected_test_bindings", [])
        if isinstance(binding, dict) and binding.get("path") == test_path
    ]
    unique_bindings = {
        json.dumps(binding, sort_keys=True, separators=(",", ":")): binding
        for binding in bindings
    }
    return {
        "statuses": sorted(
            {
                str(record["status"])
                for record in records
                if isinstance(record.get("status"), str)
            }
        ),
        "observed_case_count": max(
            (int(record.get("tests") or 0) for record in records), default=0
        ),
        "sources": sorted(
            {
                str(source)
                for record in records
                for source in record.get("sources", [])
                if isinstance(source, str) and source
            }
        ),
        "source_binding": next(iter(unique_bindings.values()))
        if len(unique_bindings) == 1
        else None,
        "binding_consistent": len(bindings) == len(campaigns)
        and len(unique_bindings) == 1,
    }


def _shared_test_ownership_context(
    test_path: str,
    campaigns: list[dict[str, Any]],
    *,
    findings_by_path: dict[str, list[dict[str, Any]]],
    ownership_rules: list[tuple[str, list[str]]],
) -> dict[str, Any]:
    campaign_owners = _campaign_values(campaigns, "owners")
    test_owners = owners_for_path(test_path, ownership_rules) if ownership_rules else []
    return {
        "campaign_owners": campaign_owners,
        "test_owners": test_owners,
        "test_findings": findings_by_path.get(test_path, [])[:25],
        "owner_alignment": _test_owner_alignment(
            campaign_owners,
            test_owners,
            ownership_evidence_available=bool(ownership_rules),
        ),
    }


def _campaign_values(campaigns: list[dict[str, Any]], key: str) -> list[str]:
    values: set[str] = set()
    for campaign in campaigns:
        value = campaign[key]
        values.update(str(item) for item in value if isinstance(value, list))
        if not isinstance(value, list):
            values.add(str(value))
    return sorted(values)


def _campaigns_selecting_test(
    test_path: str, campaigns: list[dict[str, Any]], key: str
) -> int:
    return sum(test_path in campaign[key] for campaign in campaigns)


def _shared_test_evidence_artifacts(
    campaigns: list[dict[str, Any]],
    *,
    source_binding: Any,
    has_findings: bool,
    has_ownership: bool,
) -> list[str]:
    artifacts = {
        "graphify.json",
        *({"source-inventory.json"} if source_binding is not None else set()),
        *({"findings.json"} if has_findings else set()),
        *({"finding-delta.json"} if has_ownership else set()),
        *(
            str(artifact)
            for campaign in campaigns
            for artifact in campaign["evidence_artifacts"]
        ),
    }
    return sorted(artifacts)


def _attach_shared_test_evidence_quality(
    campaigns: list[dict[str, Any]], hotspots: list[dict[str, Any]]
) -> None:
    hotspots_by_campaign: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for hotspot in hotspots:
        for campaign_id in hotspot["campaign_ids"]:
            hotspots_by_campaign[str(campaign_id)].append(hotspot)
    assessment_rank = {"not-established": 0, "weak": 1, "qualified": 2, "strong": 3}
    for campaign in campaigns:
        selected = hotspots_by_campaign.get(str(campaign["campaign_id"]), [])
        assessments = [
            str(hotspot["validation_quality_assessment"]) for hotspot in selected
        ]
        assessment = (
            min(assessments, key=lambda item: assessment_rank.get(item, -1))
            if assessments
            else "not-applicable"
        )
        finding_ids = sorted(
            {
                str(finding_id)
                for hotspot in selected
                for finding_id in hotspot["test_file_finding_ids"]
            }
        )
        cross_owner_files = sorted(
            str(hotspot["test_path"])
            for hotspot in selected
            if hotspot["test_owner_alignment"] == "coordination-needed"
        )
        unowned_files = sorted(
            str(hotspot["test_path"])
            for hotspot in selected
            if hotspot["test_owner_alignment"] == "unowned"
        )
        evidence: dict[str, Any] = {
            "assessment": assessment,
            "shared_test_files": [str(hotspot["test_path"]) for hotspot in selected],
            "hotspot_ids": [str(hotspot["test_hotspot_id"]) for hotspot in selected],
            "quality_counts": {
                state: sum(
                    hotspot["validation_quality_assessment"] == state
                    for hotspot in selected
                )
                for state in ("strong", "qualified", "weak", "not-established")
            },
            "test_file_finding_ids": finding_ids,
            "test_files_with_findings": sorted(
                str(hotspot["test_path"])
                for hotspot in selected
                if hotspot["test_file_finding_ids"]
            ),
            "cross_owner_test_files": cross_owner_files,
            "unowned_test_files": unowned_files,
            "ownership_not_established_test_files": sorted(
                str(hotspot["test_path"])
                for hotspot in selected
                if hotspot["test_owner_alignment"] == "not-established"
            ),
            "recommended_action": _shared_test_quality_action(
                assessment,
                finding_ids=len(finding_ids),
                cross_owner_files=len(cross_owner_files),
                unowned_files=len(unowned_files),
            ),
            "evidence_artifacts": sorted(
                {
                    artifact
                    for hotspot in selected
                    for artifact in hotspot["evidence_artifacts"]
                }
            ),
        }
        campaign["shared_test_evidence_quality"] = evidence
        if assessment in {"not-established", "weak", "qualified"}:
            points = 10 if assessment in {"not-established", "weak"} else 5
            campaign["review_factors"].append(
                {
                    "id": "shared-test-evidence-" + assessment,
                    "points": points,
                    "evidence": (
                        f"Shared-test validation evidence is {assessment}; "
                        f"{len(finding_ids)} active test-file finding(s), "
                        f"{len(cross_owner_files)} cross-owner test file(s), and "
                        f"{len(unowned_files)} unowned test file(s)."
                    ),
                    "evidence_artifacts": evidence["evidence_artifacts"],
                }
            )
            campaign["review_score"] = min(
                100,
                sum(int(factor["points"]) for factor in campaign["review_factors"]),
            )
            campaign["review_tier"] = _review_tier(campaign["review_score"])
            campaign["recommended_action"] += " " + evidence["recommended_action"]
        campaign["evidence_artifacts"] = sorted(
            {*campaign["evidence_artifacts"], *evidence["evidence_artifacts"]}
        )


def _shared_test_quality_action(
    assessment: str,
    *,
    finding_ids: int,
    cross_owner_files: int,
    unowned_files: int,
) -> str:
    if assessment == "not-applicable":
        return "No cross-campaign shared-test quality action is required."
    parts = [
        "Review shared-test fixtures and assertions before accepting campaign closure."
    ]
    if assessment in {"not-established", "weak"}:
        parts.insert(
            0,
            "Restore consistent source-bound passing execution for every shared test.",
        )
    if finding_ids:
        parts.append(
            f"Resolve or govern {finding_ids} active test-file finding(s) and confirm they do not weaken validation."
        )
    if cross_owner_files:
        parts.append(
            f"Coordinate campaign owners with the owners of {cross_owner_files} shared test file(s)."
        )
    if unowned_files:
        parts.append(
            f"Assign CODEOWNERS responsibility for {unowned_files} shared test file(s)."
        )
    return " ".join(parts)


def _refresh_validation_test_hotspot_review(
    hotspots: list[dict[str, Any]], campaigns: list[dict[str, Any]]
) -> None:
    campaigns_by_id = {str(campaign["campaign_id"]): campaign for campaign in campaigns}
    for hotspot in hotspots:
        scores = [
            int(campaigns_by_id[campaign_id]["review_score"])
            for campaign_id in hotspot["campaign_ids"]
            if campaign_id in campaigns_by_id
        ]
        hotspot["highest_review_score"] = max(scores, default=0)
        hotspot["highest_review_tier"] = _review_tier(
            int(hotspot["highest_review_score"])
        )


def _validation_test_hotspot_action(
    test_path: str,
    *,
    statuses: list[str],
    campaigns: int,
    controls: int,
    single_dependencies: int,
    source_binding_consistent: bool,
    test_findings: list[dict[str, Any]],
    test_owners: list[str],
    owner_alignment: str,
) -> str:
    if not source_binding_consistent:
        return (
            f"Regenerate and source-bind {test_path}; complete consistent source "
            "identity is not established across its selected campaigns."
        )
    if "failed" in statuses:
        return f"Resolve failures in {test_path} before using it across {campaigns} shared-control campaigns."
    if "not-observed" in statuses or not statuses:
        return f"Execute {test_path} and retain case-level evidence before relying on it across {controls} controls."
    action = (
        f"Coordinate assertions and fixtures in {test_path} across {campaigns} "
        f"campaigns and {controls} shared controls."
    )
    if single_dependencies:
        action += (
            f" Add an independent focused test for {single_dependencies} campaign(s) "
            "that currently depend on this test alone."
        )
    if test_findings:
        action += (
            f" Review {len(test_findings)} active finding(s) in the test file, "
            "and confirm they do not weaken fixtures, assertions, or failure handling."
        )
    if owner_alignment == "coordination-needed":
        action += (
            " Coordinate campaign and test-file owners before changing this shared "
            "validation dependency."
        )
    elif owner_alignment == "unowned":
        action += " Assign CODEOWNERS responsibility for the shared test file."
    elif owner_alignment == "not-established":
        action += " Establish test-file ownership evidence."
    if test_owners:
        action += " Test-file owner(s): " + ", ".join(test_owners[:5]) + "."
    return action


def _test_file_findings_index(
    findings: list[Finding],
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for finding in findings:
        if finding.status in {FindingStatus.RESOLVED, FindingStatus.SUPPRESSED}:
            continue
        for location in finding.locations:
            path = _path(location.path)
            if not _is_test_path(path):
                continue
            result[path][finding.finding_id] = {
                "finding_id": finding.finding_id,
                "title": finding.title,
                "severity": finding.severity.value,
                "domain": finding.domain,
                "area": finding.area,
                "line": location.start_line,
                "tools": sorted({source.tool for source in finding.sources}),
                "classifications": sorted(set(finding.classifications))[:25],
            }
    return {
        path: sorted(
            records.values(),
            key=lambda item: (
                _severity_rank(str(item["severity"])),
                int(item["line"] or 0),
                str(item["finding_id"]),
            ),
        )
        for path, records in result.items()
    }


def _test_owner_alignment(
    campaign_owners: list[str],
    test_owners: list[str],
    *,
    ownership_evidence_available: bool,
) -> str:
    if not ownership_evidence_available:
        return "not-established"
    if not test_owners:
        return "unowned"
    if set(campaign_owners) & set(test_owners):
        return "aligned"
    return "coordination-needed"


def _shared_test_quality(
    *,
    statuses: list[str],
    source_binding: dict[str, Any] | None,
    source_binding_consistent: bool,
    test_findings: list[dict[str, Any]],
    owner_alignment: str,
    single_dependencies: int,
) -> dict[str, Any]:
    reasons: list[str] = []
    if source_binding is None or not source_binding_consistent:
        reasons.append("consistent source binding is not established")
    if not statuses:
        reasons.append("case-level execution is not observed")
    elif set(statuses) & {"failed", "partial", "not-observed"}:
        reasons.append("retained execution is failing, partial, or unobserved")
    if test_findings:
        highest = _highest_severity(
            [str(finding["severity"]) for finding in test_findings]
        )
        reasons.append(
            f"test file has {len(test_findings)} active finding(s), highest {highest}"
        )
    if owner_alignment != "aligned":
        reasons.append(f"test ownership is {owner_alignment}")
    if single_dependencies:
        reasons.append(
            f"{single_dependencies} campaign(s) depend solely on this shared test"
        )
    assessment = (
        "not-established"
        if source_binding is None or not source_binding_consistent or not statuses
        else "weak"
        if set(statuses) & {"failed", "partial", "not-observed"}
        else "qualified"
        if test_findings or owner_alignment != "aligned" or single_dependencies
        else "strong"
    )
    return {
        "validation_quality_assessment": assessment,
        "validation_quality_reasons": reasons,
    }


def _highest_severity(values: list[str]) -> str | None:
    return min(values, key=_severity_rank) if values else None


def _severity_rank(value: str) -> int:
    return {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "informational": 4,
        "unknown": 5,
    }.get(value, 6)


def _reverse_adjacency(
    adjacency: dict[str, dict[str, str]],
) -> dict[str, set[str]]:
    incoming: dict[str, set[str]] = defaultdict(set)
    for source, targets in adjacency.items():
        for target in targets:
            incoming[target].add(source)
    return incoming


def _graph_selected_tests(
    path: str, incoming: dict[str, set[str]]
) -> tuple[list[str], list[str]]:
    direct = sorted(
        candidate for candidate in incoming.get(path, set()) if _is_test_path(candidate)
    )[:_MAX_CAMPAIGN_TESTS]
    visited = {path}
    queue = deque([(path, 0)])
    transitive: set[str] = set()
    examined = 0
    while queue and examined < _MAX_TEST_GRAPH_NEIGHBORS:
        current, depth = queue.popleft()
        if depth >= 2:
            continue
        for candidate in sorted(incoming.get(current, set())):
            if candidate in visited:
                continue
            visited.add(candidate)
            examined += 1
            if _is_test_path(candidate):
                if candidate not in direct:
                    transitive.add(candidate)
            else:
                queue.append((candidate, depth + 1))
            if examined >= _MAX_TEST_GRAPH_NEIGHBORS:
                break
    return direct, sorted(transitive)[:_MAX_CAMPAIGN_TESTS]


def _campaign_coverage_index(value: Any) -> dict[str, dict[str, Any]]:
    files = value.get("files") if isinstance(value, dict) else None
    if not isinstance(files, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for item in files[:_MAX_GRAPH_FILES]:
        if not isinstance(item, dict):
            continue
        path = _path(item.get("path"))
        if not path:
            continue
        summary = item.get("summary")
        percent = (
            _optional_number(summary.get("percent_covered"))
            if isinstance(summary, dict)
            else None
        )
        raw_missing = item.get("missing_lines")
        missing = (
            sorted(
                {
                    line
                    for line in raw_missing
                    if isinstance(line, int) and not isinstance(line, bool) and line > 0
                }
            )
            if isinstance(raw_missing, list)
            else []
        )
        result[path] = {
            "percent": percent,
            "missing_line_count": len(missing),
            "missing_lines": missing,
        }
    return result


def _campaign_control_context_index(
    structural_value: Any, reachability_value: Any
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    assessments = (
        structural_value.get("finding_assessments")
        if isinstance(structural_value, dict)
        else None
    )
    if isinstance(assessments, list):
        for item in assessments[:_MAX_GRAPH_FILES]:
            if not isinstance(item, dict) or not (path := _path(item.get("path"))):
                continue
            degree = item.get("degree")
            complexity = item.get("maximum_complexity")
            record = result.setdefault(path, _empty_campaign_control_context())
            record.update(
                {
                    "graph_degree": _nonnegative_integer(degree),
                    "maximum_complexity": _nonnegative_integer(complexity),
                    "maximum_complexity_rank": _optional_string(
                        item.get("maximum_complexity_rank")
                    ),
                    "reachability_states": _strings(
                        item.get("reachability_states"), 10
                    ),
                    "evidence_artifacts": ["structural-synthesis.json"],
                }
            )
    changes = (
        structural_value.get("change_impact_assessments")
        if isinstance(structural_value, dict)
        else None
    )
    if isinstance(changes, list):
        for item in changes[:_MAX_GRAPH_FILES]:
            if not isinstance(item, dict) or not (path := _path(item.get("path"))):
                continue
            risk_score = _nonnegative_integer(item.get("risk_score"))
            record = result.setdefault(path, _empty_campaign_control_context())
            current_score = record.get("change_risk_score")
            if risk_score is None or (
                isinstance(current_score, int) and current_score > risk_score
            ):
                continue
            uncovered = sorted(
                {
                    line
                    for line in item.get("uncovered_changed_lines", [])
                    if isinstance(line, int) and not isinstance(line, bool) and line > 0
                }
            )[:_MAX_CAMPAIGN_MISSING_LINES]
            record.update(
                {
                    "change_risk_score": risk_score,
                    "change_priority": _optional_string(item.get("priority")),
                    "change_classification": _optional_string(
                        item.get("classification")
                    ),
                    "changed_lines": _nonnegative_integer(item.get("changed_lines")),
                    "uncovered_changed_lines": uncovered,
                    "changed_line_coverage_percent": _optional_number(
                        item.get("changed_line_coverage_percent")
                    ),
                    "evidence_artifacts": sorted(
                        {*record["evidence_artifacts"], "structural-synthesis.json"}
                    ),
                }
            )
    nodes = (
        reachability_value.get("nodes")
        if isinstance(reachability_value, dict)
        else None
    )
    runtime_by_path: dict[str, set[str]] = defaultdict(set)
    states_by_path: dict[str, set[str]] = defaultdict(set)
    if isinstance(nodes, list):
        for node in nodes[:_MAX_GRAPH_FILES]:
            if not isinstance(node, dict) or not (path := _path(node.get("path"))):
                continue
            observation = node.get("runtime_observation")
            state = node.get("state")
            if isinstance(observation, str) and observation:
                runtime_by_path[path].add(observation[:1000])
            if isinstance(state, str) and state:
                states_by_path[path].add(state[:1000])
    for path in sorted(set(runtime_by_path) | set(states_by_path)):
        record = result.setdefault(
            path,
            _empty_campaign_control_context(),
        )
        record["reachability_states"] = sorted(
            set(record["reachability_states"]) | states_by_path[path]
        )[:10]
        record["runtime_observations"] = sorted(runtime_by_path[path])[:10]
        record["evidence_artifacts"] = sorted(
            {*record["evidence_artifacts"], "reachability.json"}
        )
    return result


def _empty_campaign_control_context() -> dict[str, Any]:
    return {
        "graph_degree": None,
        "maximum_complexity": None,
        "maximum_complexity_rank": None,
        "change_risk_score": None,
        "change_priority": None,
        "change_classification": None,
        "changed_lines": None,
        "uncovered_changed_lines": [],
        "changed_line_coverage_percent": None,
        "reachability_states": [],
        "runtime_observations": [],
        "evidence_artifacts": [],
    }


def _campaign_source_index(
    value: Any,
) -> tuple[str | None, dict[str, dict[str, Any]]]:
    if not isinstance(value, dict) or value.get("schema_version") != "1.0":
        return None, {}
    aggregate = value.get("source_sha256")
    files = value.get("files")
    if not _is_digest(aggregate) or not isinstance(files, list):
        return None, {}
    result: dict[str, dict[str, Any]] = {}
    for item in files[:_MAX_GRAPH_FILES]:
        if not isinstance(item, dict) or not (path := _path(item.get("path"))):
            continue
        digest = item.get("sha256")
        size = item.get("size_bytes")
        if (
            not _is_digest(digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            continue
        result[path] = {"path": path, "sha256": digest, "size_bytes": size}
    return str(aggregate), result


def _campaign_source_snapshot(
    path: str,
    selected: list[str],
    *,
    source_sha256: str | None,
    source_files: dict[str, dict[str, Any]],
    artifacts: dict[str, Any],
    evidence_artifacts: list[str],
) -> dict[str, Any]:
    selected_bindings = [
        source_files[test] for test in selected if test in source_files
    ]
    missing = [test for test in selected if test not in source_files]
    evidence_names = [
        name
        for name in evidence_artifacts
        if name == "coverage-summary.json" or name in TEST_EVIDENCE_ARTIFACTS
    ]
    evidence_bindings = [
        _campaign_evidence_source_binding(
            name,
            artifacts.get(name),
            source_sha256=source_sha256,
        )
        for name in evidence_names
    ]
    revision_binding = (
        "not-applicable"
        if not evidence_bindings
        else "mismatch"
        if any(item["status"] == "mismatch" for item in evidence_bindings)
        else "unverified"
        if any(item["status"] == "unverified" for item in evidence_bindings)
        else "aligned"
        if evidence_bindings
        and all(item["status"] == "aligned" for item in evidence_bindings)
        else "not-established"
    )
    reason = {
        "not-applicable": "No retained case or coverage evidence requires a source-revision binding.",
        "mismatch": "At least one retained case or coverage artifact declares a different source snapshot.",
        "unverified": "At least one retained case or coverage artifact declares the sealed source digest without a valid producer-verified payload-binding receipt.",
        "aligned": "Every retained case and coverage artifact declares the sealed source-inventory digest.",
        "not-established": "Retained case or coverage evidence does not completely declare the sealed source-inventory digest.",
    }[revision_binding]
    return {
        "source_inventory_available": source_sha256 is not None,
        "source_sha256": source_sha256,
        "control_point_binding": source_files.get(path),
        "selected_test_bindings": selected_bindings,
        "selected_test_files_bound": len(selected_bindings),
        "selected_test_files_missing": missing,
        "evidence_revision_binding": revision_binding,
        "evidence_revision_binding_reason": reason,
        "evidence_source_bindings": evidence_bindings,
    }


def _campaign_evidence_source_binding(
    name: str,
    value: Any,
    *,
    source_sha256: str | None,
) -> dict[str, Any]:
    document = _object(value)
    declared = document.get("source_sha256")
    binding = _object(document.get("evidence_binding"))
    evidence_sha256 = binding.get("evidence_sha256")
    binding_file = binding.get("binding_file")
    binding_verified = (
        binding.get("verified") is True
        and binding.get("schema_version") == "1.0"
        and _is_digest(evidence_sha256)
        and isinstance(binding_file, str)
        and bool(binding_file.strip())
    )
    status = (
        "no-source-inventory"
        if source_sha256 is None
        else "not-declared"
        if not _is_digest(declared)
        else "mismatch"
        if declared != source_sha256
        else "aligned"
        if binding_verified
        else "unverified"
    )
    return {
        "artifact": name,
        "declared_source_sha256": str(declared) if _is_digest(declared) else None,
        "binding_verified": binding_verified,
        "evidence_sha256": (
            str(evidence_sha256) if _is_digest(evidence_sha256) else None
        ),
        "binding_file": (
            str(binding_file)[:1000]
            if isinstance(binding_file, str) and binding_file.strip()
            else None
        ),
        "status": status,
    }


def _campaign_route_assurance(
    hotspot: dict[str, Any], routes_by_id: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """Aggregate exact route evidence posture without letting tests mask trust gaps."""
    expected_ids = _strings(hotspot.get("route_ids"), _MAX_ROUTES)
    routes = [
        routes_by_id[route_id] for route_id in expected_ids if route_id in routes_by_id
    ]
    missing = sorted(set(expected_ids) - routes_by_id.keys())
    statuses = {
        status: sum(
            str(_object(route.get("evidence_assurance")).get("review_status")) == status
            for route in routes
        )
        for status in (
            "assured",
            "perspective-gap",
            "trust-gap",
            "execution-gap",
            "not-assessed",
            "derived-analysis",
        )
    }

    def tools(key: str) -> list[str]:
        return sorted(
            {
                tool
                for route in routes
                for tool in _strings(
                    _object(route.get("evidence_assurance")).get(key), 25
                )
            }
        )

    blocking = bool(
        missing
        or statuses["trust-gap"]
        or statuses["execution-gap"]
        or statuses["not-assessed"]
    )
    assessment = (
        "route-reference-gap"
        if missing
        else "execution-gap"
        if statuses["execution-gap"]
        else "trust-gap"
        if statuses["trust-gap"]
        else "not-assessed"
        if statuses["not-assessed"]
        else "perspective-gap"
        if statuses["perspective-gap"]
        else "derived-analysis"
        if statuses["derived-analysis"] and not statuses["assured"]
        else "assured"
    )
    trust_gap_tools = tools("trust_gap_tools")
    execution_gap_tools = tools("execution_gap_tools")
    unassessed_tools = tools("unassessed_tools")
    if missing:
        action = (
            "Regenerate the risk-path graph so every campaign route reference resolves "
            "before using the campaign as closure evidence."
        )
    elif execution_gap_tools or statuses["execution-gap"]:
        action = (
            "Complete the exact contributing scanner runs and regenerate normalized "
            "route evidence before accepting campaign test results."
        )
    elif trust_gap_tools or statuses["trust-gap"]:
        named = ", ".join(trust_gap_tools) or "the exact contributing scanners"
        action = (
            "Verify executable integrity and obtain organization approval for "
            f"{named} before accepting campaign test results."
        )
    elif unassessed_tools or statuses["not-assessed"]:
        action = (
            "Establish execution and trust posture for every exact contributing "
            "scanner before accepting campaign test results."
        )
    elif statuses["perspective-gap"]:
        action = (
            "Retain the trusted route evidence and add an independent applicable "
            "scanner perspective or approve a single-perspective disposition."
        )
    else:
        action = (
            "Retain the exact contributing-tool execution and trust evidence with "
            "the campaign."
        )
    evidence_artifacts = sorted(
        {
            "risk-paths.json",
            *(
                {"effectiveness.json", "scanner-trust.json"}
                if any(
                    _object(route.get("evidence_assurance")).get("tool_records")
                    for route in routes
                )
                else set()
            ),
        }
    )
    return {
        "assessment": assessment,
        "tool_assurance_prerequisite_met": not blocking,
        "routes_expected": len(expected_ids),
        "routes_assessed": len(routes),
        "route_ids_missing": missing,
        "route_statuses": statuses,
        "contributing_tools": tools("contributing_tools"),
        "approved_tools": tools("approved_tools"),
        "trust_gap_tools": trust_gap_tools,
        "execution_gap_tools": execution_gap_tools,
        "unassessed_tools": unassessed_tools,
        "evidence_lanes": tools("evidence_lanes"),
        "recommended_action": action,
        "evidence_artifacts": evidence_artifacts,
    }


def _campaign_review_assessment(
    hotspot: dict[str, Any],
    *,
    execution_status: str,
    test_execution_sources: list[str],
    coverage_status: str,
    context: dict[str, Any],
    revision_binding: str,
    route_assurance: dict[str, Any],
) -> dict[str, Any]:
    factors: list[dict[str, Any]] = []

    def add(identifier: str, points: int, evidence: str, artifacts: list[str]) -> None:
        if points > 0:
            factors.append(
                {
                    "id": identifier,
                    "points": points,
                    "evidence": evidence,
                    "evidence_artifacts": artifacts,
                }
            )

    priority = str(hotspot.get("priority") or "P4")
    priority_points = {"P0": 40, "P1": 32, "P2": 24, "P3": 12, "P4": 4}.get(priority, 4)
    add(
        "highest-route-priority",
        priority_points,
        f"Highest converging route priority is {priority}.",
        ["findings.json", "risk-paths.json"],
    )
    route_count = len(hotspot.get("route_ids") or [])
    add(
        "route-convergence",
        min(20, max(0, route_count - 1) * 4),
        f"{route_count} distinct routes cross this control point.",
        ["graphify.json", "risk-paths.json"],
    )
    target_count = len(hotspot.get("target_ids") or [])
    add(
        "target-concentration",
        min(10, max(0, target_count - 1) * 2),
        f"{target_count} distinct review targets share this control point.",
        ["findings.json", "risk-paths.json"],
    )
    security_targets = int(hotspot.get("security_target_count") or 0)
    add(
        "security-targets",
        min(20, security_targets * 5),
        f"{security_targets} security or supply-chain target(s) converge here.",
        ["findings.json"],
    )
    tool_count = len(hotspot.get("tools") or [])
    add(
        "tool-diversity",
        min(6, max(0, tool_count - 1) * 2),
        f"{tool_count} distinct tools contribute target evidence.",
        ["findings.json"],
    )
    if coverage_status == "gap":
        add(
            "coverage-gap",
            10,
            "The shared control-point file has uncovered executable lines.",
            ["coverage-summary.json"],
        )
    elif coverage_status == "not-available":
        add(
            "coverage-unavailable",
            6,
            "File coverage is unavailable for the shared control point.",
            [],
        )
    execution_points = {
        "failed": 20,
        "not-selected": 12,
        "not-observed": 10,
        "incomplete": 8,
        "not-available": 8,
    }.get(execution_status, 0)
    add(
        "focused-test-state",
        execution_points,
        f"Focused test execution state is {execution_status}.",
        test_execution_sources,
    )
    change_risk = context.get("change_risk_score")
    change_points = (
        15
        if isinstance(change_risk, int) and change_risk >= 75
        else 10
        if isinstance(change_risk, int) and change_risk >= 50
        else 5
        if isinstance(change_risk, int) and change_risk > 0
        else 0
    )
    add(
        "changed-control-risk",
        change_points,
        "Changed shared control point has structural risk score "
        f"{change_risk} ({context.get('change_priority') or 'unclassified'}).",
        ["diff-coverage.json", "structural-synthesis.json"],
    )
    uncovered_changed = context.get("uncovered_changed_lines")
    uncovered_changed = uncovered_changed if isinstance(uncovered_changed, list) else []
    add(
        "uncovered-changed-lines",
        12 if uncovered_changed else 0,
        f"{len(uncovered_changed)} changed executable line(s) are uncovered: "
        + ", ".join(str(line) for line in uncovered_changed[:10])
        + ("." if len(uncovered_changed) <= 10 else ", …"),
        ["diff-coverage.json", "structural-synthesis.json"],
    )
    observations = set(_strings(context.get("runtime_observations"), 10))
    runtime_points = (
        0
        if "observed" in observations
        else 6
        if "not-observed" in observations
        else 4
        if observations & {"not-measured", "unknown"} or not observations
        else 0
    )
    add(
        "runtime-observation-gap",
        runtime_points,
        "Shared control point runtime state is "
        + (", ".join(sorted(observations)) if observations else "not available")
        + ".",
        (
            ["reachability.json"]
            if "reachability.json" in context.get("evidence_artifacts", [])
            else []
        ),
    )
    complexity = context.get("maximum_complexity")
    complexity_points = (
        15
        if isinstance(complexity, int) and complexity >= 30
        else 10
        if isinstance(complexity, int) and complexity >= 20
        else 0
    )
    add(
        "control-point-complexity",
        complexity_points,
        f"Maximum retained cyclomatic complexity is {complexity}.",
        ["structural-synthesis.json"],
    )
    degree = context.get("graph_degree")
    degree_points = (
        10
        if isinstance(degree, int) and degree >= 100
        else 5
        if isinstance(degree, int) and degree >= 25
        else 0
    )
    add(
        "graph-centrality",
        degree_points,
        f"Graph degree is {degree}.",
        ["graphify.json", "structural-synthesis.json"],
    )
    if not hotspot.get("owners"):
        add(
            "unassigned-owner",
            5,
            "No owner is assigned to the shared control point.",
            ["finding-delta.json"],
        )
    factors.extend(
        _campaign_assurance_review_factors(route_assurance, revision_binding)
    )
    score = min(100, sum(int(factor["points"]) for factor in factors))
    tier = _review_tier(score)
    return {
        "review_score_model": "shared-control-review-v5",
        "review_score": score,
        "review_tier": tier,
        "review_factors": factors,
    }


def _campaign_assurance_review_factors(
    route_assurance: dict[str, Any], revision_binding: str
) -> list[dict[str, Any]]:
    statuses = _object(route_assurance.get("route_statuses"))
    values = {
        "execution": int(statuses.get("execution-gap") or 0),
        "trust": int(statuses.get("trust-gap") or 0),
        "unassessed": int(statuses.get("not-assessed") or 0),
        "perspective": int(statuses.get("perspective-gap") or 0),
        "missing": len(_strings(route_assurance.get("route_ids_missing"), 250)),
    }
    factors: list[dict[str, Any]] = []

    def add(identifier: str, points: int, evidence: str, artifacts: list[str]) -> None:
        factors.append(
            {
                "id": identifier,
                "points": points,
                "evidence": evidence,
                "evidence_artifacts": artifacts,
            }
        )

    if values["execution"]:
        add(
            "route-tool-execution-gap",
            20,
            f"{values['execution']} converging route(s) depend on scanner evidence that did not complete successfully.",
            ["effectiveness.json", "risk-paths.json"],
        )
    if values["trust"]:
        add(
            "route-tool-trust-gap",
            15,
            f"{values['trust']} converging route(s) depend on scanner evidence without complete integrity and organization approval.",
            ["scanner-trust.json", "risk-paths.json"],
        )
    if values["unassessed"] or values["missing"]:
        add(
            "route-tool-assurance-unassessed",
            10,
            f"{values['unassessed']} route(s) lack a tool-assurance assessment and {values['missing']} retained route reference(s) could not be resolved.",
            ["effectiveness.json", "scanner-trust.json", "risk-paths.json"],
        )
    if values["perspective"]:
        add(
            "route-perspective-gap",
            5,
            f"{values['perspective']} converging route(s) rely on a single scanner perspective.",
            ["effectiveness.json", "risk-paths.json"],
        )
    revision = {
        "mismatch": (
            "evidence-revision-mismatch",
            20,
            "Retained test or coverage evidence declares a different source snapshot.",
        ),
        "unverified": (
            "evidence-binding-unverified",
            15,
            "Retained test or coverage evidence declares the sealed source digest without a valid producer-verified payload-binding receipt.",
        ),
        "not-established": (
            "evidence-revision-unbound",
            5,
            "Retained test or coverage evidence is not fully bound to the sealed source snapshot.",
        ),
    }.get(revision_binding)
    if revision is not None:
        add(*revision, ["source-inventory.json"])
    return factors


def _review_tier(score: int) -> str:
    return (
        "critical"
        if score >= 80
        else "high"
        if score >= 60
        else "medium"
        if score >= 35
        else "low"
    )


def _campaign_action(
    alignment: str,
    selected: list[str],
    path: str,
    *,
    revision_binding: str,
    context: dict[str, Any],
    route_assurance: dict[str, Any],
) -> str:
    tests = ", ".join(selected[:5])
    if alignment == "aligned-current-evidence":
        action = (
            f"Retain the passing focused-test and complete file-coverage evidence "
            f"for {path}; rerun the campaign after shared-control changes."
        )
    elif alignment == "coverage-gap":
        action = (
            f"Extend the passing selected tests until uncovered executable lines in "
            f"{path} are covered, then regenerate case and coverage evidence."
        )
    elif alignment == "tests-failing":
        action = "Resolve failing or errored selected tests before accepting this shared change."
    elif alignment == "tests-not-observed":
        action = "Run the selected tests and retain case-level evidence" + (
            f": {tests}." if tests else "."
        )
    elif alignment == "tests-incomplete":
        action = "Complete or explain skipped and unobserved selected tests, then retain a complete case inventory."
    elif alignment == "test-evidence-not-available":
        action = "Produce bounded case-level test evidence for the selected files" + (
            f": {tests}." if tests else "."
        )
    elif alignment == "coverage-not-available":
        action = f"Produce line coverage for {path} from the selected-test campaign."
    else:
        action = f"Add a focused test that reaches shared control point {path}, then retain execution and coverage evidence."
    uncovered_changed = context.get("uncovered_changed_lines")
    if isinstance(uncovered_changed, list) and uncovered_changed:
        lines = ", ".join(str(line) for line in uncovered_changed[:10])
        action += f" Prioritize uncovered changed line(s) {lines} in {path}."
    observations = set(_strings(context.get("runtime_observations"), 10))
    if "observed" not in observations and observations & {
        "not-observed",
        "not-measured",
        "unknown",
    }:
        action += " Retain runtime coverage that exercises this control point."
    if revision_binding in {"mismatch", "unverified"}:
        action = (
            "Discard mismatched or unverified test/coverage evidence and regenerate "
            "it with a verified payload binding against the sealed source snapshot. "
            + action
        )
    if revision_binding == "not-established":
        action += (
            " Bind the regenerated evidence to the sealed source-inventory digest."
        )
    if route_assurance.get("tool_assurance_prerequisite_met") is not True:
        return (
            str(
                route_assurance.get("recommended_action")
                or "Establish route evidence assurance."
            )
            + " "
            + action
        )
    if int(_object(route_assurance.get("route_statuses")).get("perspective-gap") or 0):
        action += (
            " Add an independent applicable scanner perspective or retain an approved "
            "single-perspective disposition."
        )
    return action


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
