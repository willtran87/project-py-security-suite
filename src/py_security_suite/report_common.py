"""Formatting, ordering and reference helpers shared by the report renderers."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .report_markdown import _markdown_text, _markdown_code
from .models import (
    Citation,
    Finding,
    Location,
    Outcome,
    ScanManifest,
    Severity,
    Source,
    ToolRun,
)
from .prioritization import finding_order_key, finding_priority
from .report_references import TOOL_REFERENCES as _TOOL_REFERENCES


__all__ = [
    "_advanced_taint_alignment_counts",
    "_applicable_scanner_gaps",
    "_applicable_tools",
    "_area_summary",
    "_artifact_identity",
    "_campaign_route_assurance_text",
    "_campaign_shared_test_quality_text",
    "_change_lifecycle_text",
    "_classification_uri",
    "_completed_tools",
    "_coverage_action",
    "_dependency_usage_summary",
    "_entry_point_exposure_text",
    "_entry_runtime_status_text",
    "_entrypoint_integrity_counts",
    "_entrypoint_integrity_states",
    "_evidence_assurance_text",
    "_executable_integrity_label",
    "_exposure_cross_reference_signals",
    "_finding_owners",
    "_finding_priority",
    "_finding_sort_key",
    "_graph_corroboration_text",
    "_line_is_highlighted",
    "_location_text",
    "_markdown_citation",
    "_markdown_classification",
    "_markdown_table",
    "_markdown_tool_reference",
    "_missing_source_evidence_text",
    "_next_action",
    "_next_action_for_manifest",
    "_not_applicable_scanners",
    "_owner_values",
    "_package_lifecycle_text",
    "_policy_decision_value",
    "_policy_disposition",
    "_primary_snippet_location",
    "_reference_uri",
    "_remediation_context_summary",
    "_report_release_status",
    "_risk_advisory_citations_text",
    "_risk_campaign_control_text",
    "_risk_campaign_factor_text",
    "_risk_path_validation_signals",
    "_route_applicability_text",
    "_route_ownership_text",
    "_safe_http_reference",
    "_sdk_dependency_context_summary",
    "_secret_membership_text",
    "_source_version",
    "_threat_intelligence_summary",
    "_unrouted_structural_context_text",
]


_MAX_REFERENCE_URI = 2048


_UNSAFE_MARKDOWN_URI_CHARACTERS = frozenset("()<>\\")


def _secret_membership_text(label: str, available: Any, member: Any) -> str:
    if available is not True:
        return f"{label} not available"
    if member is True:
        return f"{label} member"
    if member is False:
        return f"{label} absent"
    return f"{label} unknown"


def _package_lifecycle_text(value: Any) -> str:
    lifecycle = value if isinstance(value, dict) else {}
    assessment = str(lifecycle.get("assessment") or "not-available")
    source = lifecycle.get("source_versions")
    artifact = lifecycle.get("artifact_versions")
    source_text = (
        ", ".join(str(item) for item in source[:5])
        if isinstance(source, list) and source
        else "not observed"
    )
    artifact_text = (
        ", ".join(str(item) for item in artifact[:5])
        if isinstance(artifact, list) and artifact
        else "not observed"
    )
    exact_match = lifecycle.get("artifact_fixed_version_exact_match")
    exact_text = (
        "yes"
        if exact_match is True
        else "no"
        if exact_match is False
        else "not established"
    )
    return (
        f"lifecycle {assessment}; source {source_text}; artifact {artifact_text}; "
        f"exact fixed version in artifact {exact_text}"
    )


def _entry_point_exposure_text(value: Any) -> str:
    route = value if isinstance(value, dict) else {}
    exposures = route.get("entry_point_exposures")
    retained = exposures if isinstance(exposures, list) else []
    count = int(route.get("entry_point_exposure_count") or len(retained))
    omitted = int(route.get("entry_point_exposures_omitted") or 0)
    kinds = route.get("entry_point_kinds")
    kind_values = kinds if isinstance(kinds, list) else []
    alternates = [
        str(entry.get("declared_as") or entry.get("id") or "unknown")
        + (
            f" ({entry['path']})"
            if entry.get("path") and entry.get("path") != entry.get("declared_as")
            else ""
        )
        for item in retained
        if isinstance(item, dict)
        and item.get("primary") is not True
        and isinstance((entry := item.get("entry_point")), dict)
    ][:3]
    text = f"{count} declared entry-point route(s)"
    if kind_values:
        text += " across " + ", ".join(str(item) for item in kind_values[:5])
    if alternates:
        text += "; alternate(s): " + ", ".join(alternates)
    if omitted:
        text += f"; {omitted} omitted by bound"
    runtime_counts = _entry_runtime_counts_from_exposures(retained)
    text += "; " + _entry_runtime_status_text(runtime_counts)
    return text


def _entry_runtime_counts_from_exposures(values: list[Any]) -> dict[str, int]:
    return {
        status: sum(
            isinstance(item, dict)
            and isinstance(item.get("runtime_context"), dict)
            and item["runtime_context"].get("assessment") == status
            for item in values
        )
        for status in ("observed", "not-observed", "not-available")
    }


def _entry_runtime_status_text(value: Any) -> str:
    counts = value if isinstance(value, dict) else {}
    return (
        "runtime observed/unobserved/unavailable "
        f"{int(counts.get('observed') or 0)}/"
        f"{int(counts.get('not-observed') or 0)}/"
        f"{int(counts.get('not-available') or 0)}"
    )


def _evidence_assurance_text(value: Any) -> str:
    assurance = value if isinstance(value, dict) else {}
    status = str(assurance.get("review_status") or "not-assessed")
    perspective = str(assurance.get("perspective_assessment") or "not-established")
    contributing = assurance.get("contributing_tools")
    tools = contributing if isinstance(contributing, list) else []
    completed = assurance.get("completed_tools")
    completed_tools = completed if isinstance(completed, list) else []
    approved = assurance.get("approved_tools")
    approved_tools = approved if isinstance(approved, list) else []
    gaps = []
    for label, key in (
        ("trust", "trust_gap_tools"),
        ("execution", "execution_gap_tools"),
        ("unassessed", "unassessed_tools"),
    ):
        raw = assurance.get(key)
        values = raw if isinstance(raw, list) else []
        if values:
            gaps.append(label + " " + ", ".join(str(item) for item in values[:5]))
    return (
        f"{status}; perspective {perspective}; tools {', '.join(str(item) for item in tools[:5]) or 'suite-derived'}; "
        f"completed/approved {len(completed_tools)}/{len(approved_tools)}"
        + ("; gaps " + "; ".join(gaps) if gaps else "")
    )


def _change_lifecycle_text(value: Any) -> str:
    context = value if isinstance(value, dict) else {}
    if not context:
        return "not applicable to derived target"
    classification = str(context.get("classification") or "baseline-not-established")
    signal = str(context.get("review_signal") or "baseline-not-established")
    runtime = _entry_runtime_status_text(context.get("entry_point_runtime_statuses"))
    reasons = context.get("baseline_reasons")
    reason_values = reasons if isinstance(reasons, list) else []
    return f"{classification}; review {signal}; {runtime}" + (
        "; baseline reason " + "; ".join(str(item) for item in reason_values[:2])
        if reason_values
        else ""
    )


def _route_ownership_text(value: Any) -> str:
    context = value if isinstance(value, dict) else {}
    if not context or context.get("evidence_available") is not True:
        return "not established"
    status = str(context.get("coordination_status") or "not-established")
    owners = context.get("coordination_owners")
    owner_values = owners if isinstance(owners, list) else []
    unowned = context.get("unowned_files")
    unowned_values = unowned if isinstance(unowned, list) else []
    return (
        f"{status}; owners {', '.join(str(item) for item in owner_values[:5]) or 'none'}; "
        f"handoffs {int(context.get('boundary_count') or 0)}; "
        f"unowned files {len(unowned_values)}; target owner "
        f"{context.get('target_owner_alignment') or 'not-established'!s}"
    )


def _risk_path_validation_signals(
    validation: dict[str, Any], runtime: dict[str, Any]
) -> str:
    signals: list[str] = []
    status = validation.get("assessment_status")
    if isinstance(status, str):
        signals.append("assessment " + status)
    assessment_reasons = validation.get("assessment_reasons")
    if isinstance(assessment_reasons, list) and assessment_reasons:
        signals.append(
            "missing "
            + ", ".join(
                str(item).removeprefix("retained ").removesuffix(" is unavailable")
                for item in assessment_reasons[:3]
            )
        )
    states = runtime.get("reachability_states")
    if isinstance(states, list) and states:
        signals.append("reachability " + "/".join(str(item) for item in states[:3]))
    observations = runtime.get("observations")
    if isinstance(observations, list) and observations:
        signals.append("runtime " + "/".join(str(item) for item in observations[:3]))
    if validation.get("changed_line") is True:
        signals.append("changed line")
    if validation.get("line_covered") is False:
        signals.append("uncovered line")
    elif validation.get("line_covered") is True:
        signals.append("covered line")
    alignment = validation.get("coverage_alignment")
    if isinstance(alignment, str):
        signals.append("validation " + alignment)
    mapped = validation.get("mapped_test_files")
    if isinstance(mapped, list) and mapped:
        signals.append("tests " + ", ".join(str(item) for item in mapped[:2]))
    return "; ".join(signals) or "runtime and validation evidence unavailable"


def _campaign_route_assurance_text(campaign: dict[str, Any]) -> str:
    assurance = campaign.get("route_evidence_assurance")
    assurance = assurance if isinstance(assurance, dict) else {}
    statuses = assurance.get("route_statuses")
    statuses = statuses if isinstance(statuses, dict) else {}
    assessment = str(assurance.get("assessment") or "not-assessed")
    expected = int(assurance.get("routes_expected") or 0)
    assessed = int(assurance.get("routes_assessed") or 0)
    gaps = "/".join(
        str(int(statuses.get(status) or 0))
        for status in ("trust-gap", "execution-gap", "not-assessed")
    )
    return (
        f"{assessment}; routes {assessed}/{expected}; trust/execution/unassessed {gaps}"
    )


def _route_applicability_text(value: dict[str, Any]) -> str:
    assessment = str(value.get("assessment") or "not-established")
    classification = str(value.get("classification") or "not-established")
    return f"{assessment} ({classification})"


def _unrouted_structural_context_text(value: Any) -> str:
    intersections = value if isinstance(value, list) else []
    retained = [item for item in intersections if isinstance(item, dict)]
    if not retained:
        return ""
    first = retained[0]
    entries = first.get("candidate_entry_paths")
    entry_values = entries if isinstance(entries, list) else []
    tests = first.get("direct_test_files")
    test_values = tests if isinstance(tests, list) else []
    owners = first.get("coordination_owners")
    owner_values = owners if isinstance(owners, list) else []
    return (
        " Structural cross-reference: "
        + str(len(retained))
        + " exact retained island membership(s); first island "
        + str(first.get("island_id") or "unknown")
        + ", state "
        + str(first.get("island_state") or "unknown")
        + ", boundary "
        + str(first.get("boundary_classification") or "not-established")
        + ", signal "
        + str(first.get("risk_signal") or "unknown")
        + ", decision "
        + str(first.get("decision") or "review")
        + (
            ", candidate entries " + ", ".join(map(str, entry_values[:3]))
            if entry_values
            else ""
        )
        + (
            ", focused tests " + ", ".join(map(str, test_values[:3]))
            if test_values
            else ""
        )
        + (
            ", coordinating owners " + ", ".join(map(str, owner_values[:5]))
            if owner_values
            else ""
        )
        + ". This membership does not prove dead code or production inaccessibility."
    )


def _campaign_shared_test_quality_text(campaign: dict[str, Any]) -> str:
    quality = campaign.get("shared_test_evidence_quality")
    quality = quality if isinstance(quality, dict) else {}
    return (
        str(quality.get("assessment") or "not-applicable")
        + "; findings "
        + str(len(quality.get("test_file_finding_ids") or []))
        + "; cross-owner/unowned "
        + str(len(quality.get("cross_owner_test_files") or []))
        + "/"
        + str(len(quality.get("unowned_test_files") or []))
    )


def _risk_advisory_citations_text(value: Any) -> str:
    if not isinstance(value, list):
        return ""
    citations: list[str] = []
    for item in value[:5]:
        if not isinstance(item, dict):
            continue
        identifier = str(item.get("identifier") or "reference")
        uri_value = item.get("uri")
        uri = _safe_http_reference(uri_value) if isinstance(uri_value, str) else None
        citations.append(
            f"[{_markdown_text(identifier)}]({uri})"
            if uri
            else f"`{_markdown_code(identifier)}`"
        )
    return ", ".join(citations)


def _sdk_dependency_context_summary(value: Any) -> str:
    if not isinstance(value, dict) or not value.get("context_available"):
        return ""
    packages = value.get("packages")
    package_text = (
        ", ".join(str(item) for item in packages[:3])
        if isinstance(packages, list) and packages
        else "unknown"
    )
    signals = [f"SDK packages {package_text}"]
    if value.get("risk_present"):
        signals.append(f"package risk {value.get('risk_tier', 'medium')}")
        clusters = value.get("advisory_clusters")
        tools = value.get("package_finding_tools")
        if isinstance(clusters, list) and clusters:
            distinct = int(value.get("distinct_advisory_count") or len(clusters))
            observations = int(value.get("advisory_observation_count") or 0)
            attribution = (
                " via " + ", ".join(str(item) for item in tools[:3])
                if isinstance(tools, list) and tools
                else ""
            )
            primary = [
                str(item.get("primary_identifier"))
                for item in clusters[:3]
                if isinstance(item, dict) and item.get("primary_identifier")
            ]
            signals.append(
                f"{distinct} distinct advisories / {observations} observations"
                + attribution
            )
            if primary:
                signals.append("advisories " + ", ".join(primary))
            usage_summaries = sorted(
                {
                    summary
                    for item in clusters
                    if isinstance(item, dict)
                    and (
                        summary := _dependency_usage_summary(
                            item.get("dependency_usage")
                        )
                    )
                }
            )
            if usage_summaries:
                signals.append("use " + " / ".join(usage_summaries[:3]))
            remediation_summaries = sorted(
                {
                    summary
                    for item in clusters
                    if isinstance(item, dict)
                    and (
                        summary := _remediation_context_summary(
                            item.get("remediation_context")
                        )
                    )
                }
            )
            if remediation_summaries:
                signals.append("action " + " / ".join(remediation_summaries[:3]))
        else:
            finding_ids = value.get("package_finding_ids")
            if isinstance(finding_ids, list) and finding_ids:
                attribution = (
                    " via " + ", ".join(str(item) for item in tools[:3])
                    if isinstance(tools, list) and tools
                    else ""
                )
                signals.append(
                    "findings "
                    + ", ".join(str(item) for item in finding_ids[:3])
                    + attribution
                )
    else:
        signals.append("no joined package-risk finding")
    lineage = value.get("lineage")
    exceptional = (
        [
            f"{item.get('package')}:{item.get('status')}"
            for item in lineage
            if isinstance(item, dict)
            and item.get("status") in {"version-drift", "artifact-only"}
        ]
        if isinstance(lineage, list)
        else []
    )
    if exceptional:
        signals.append("lineage " + ", ".join(exceptional[:3]))
    return "; ".join(signals)


def _dependency_usage_summary(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    assessment = str(value.get("assessment") or "unknown")
    relationship = str(value.get("source_relationship") or "unknown")
    paths = value.get("import_paths")
    statuses = value.get("deptry_statuses")
    if (
        assessment == "unknown"
        and relationship == "unknown"
        and not paths
        and not statuses
        and value.get("signals_conflict") is not True
    ):
        return ""
    signals = [assessment]
    if relationship != "unknown":
        signals.append(relationship + " dependency")
    dependency_paths = value.get("dependency_paths")
    if isinstance(dependency_paths, list) and dependency_paths:
        first = dependency_paths[0] if isinstance(dependency_paths[0], dict) else {}
        path = first.get("path") if isinstance(first, dict) else []
        if isinstance(path, list) and path:
            signals.append(
                "introduced by "
                + " -> ".join(str(item) for item in path[:5])
                + f" ({value.get('dependency_path_confidence', 'unknown')})"
            )
    elif relationship == "transitive":
        signals.append(
            "no introducing path"
            if value.get("dependency_path_evidence_available") is True
            else "dependency-path evidence unavailable"
        )
    if value.get("dependency_environment_warning") is True:
        signals.append("installed dependency environment has health gaps")
    elif value.get("environment_health_evidence_available") is not True:
        signals.append("installed-environment health unavailable")
    if isinstance(paths, list) and paths:
        signals.append("imports " + ", ".join(str(item) for item in paths[:2]))
    if (
        value.get("import_observed") is True
        and value.get("reachability_complete") is False
    ):
        signals.append("reachability incomplete")
    if isinstance(statuses, list) and statuses:
        signals.append("deptry " + ", ".join(str(item) for item in statuses[:2]))
    if value.get("signals_conflict") is True:
        signals.append("evidence conflict")
    tests = value.get("recommended_test_files")
    if isinstance(tests, list) and tests:
        signals.append(
            "focused tests "
            + ", ".join(str(item) for item in tests[:2])
            + f" ({value.get('test_selection_confidence', 'unknown')})"
        )
        execution_status = str(
            value.get("focused_test_validation_status") or "not-available"
        )
        signals.append("scanned-state focused-test evidence " + execution_status)
        signals.append(
            "test/coverage alignment "
            + str(value.get("test_coverage_alignment") or "not-available")
        )
        unobserved = value.get("unobserved_recommended_test_files")
        if isinstance(unobserved, list) and unobserved:
            signals.append(
                "not observed " + ", ".join(str(item) for item in unobserved[:2])
            )
    elif value.get("import_observed") is True:
        signals.append(
            "no focused test mapping"
            if value.get("test_mapping_evidence_available") is True
            else "test mapping unavailable"
        )
    owners = value.get("import_path_owners")
    if isinstance(owners, list) and owners:
        signals.append("owners " + ", ".join(str(item) for item in owners[:2]))
    elif value.get("import_observed") is True:
        signals.append(
            "no matched import-path owner"
            if value.get("ownership_evidence_available") is True
            else "ownership evidence unavailable"
        )
    uncovered = value.get("uncovered_import_paths")
    if isinstance(uncovered, list) and uncovered:
        signals.append(
            "below 80% coverage " + ", ".join(str(item) for item in uncovered[:2])
        )
    elif (
        value.get("import_observed") is True
        and value.get("coverage_evidence_available") is not True
    ):
        signals.append("coverage evidence unavailable")
    return ", ".join(signals)


def _remediation_context_summary(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    priority = str(value.get("priority") or "P4")
    kind = str(value.get("action_kind") or "review")
    candidates = value.get("fixed_version_candidates")
    parts = [priority, kind]
    if isinstance(candidates, list) and candidates:
        parts.append(
            "fix candidates " + ", ".join(str(item) for item in candidates[:4])
        )
    elif value.get("fix_available") is False:
        parts.append("no scanner-reported fix")
    owners = value.get("owners")
    if isinstance(owners, list) and owners:
        parts.append("owner " + ", ".join(str(item) for item in owners[:2]))
    tests = value.get("recommended_test_files")
    if isinstance(tests, list) and tests:
        parts.append("tests " + ", ".join(str(item) for item in tests[:2]))
        parts.append(
            "scanned-state focused-test evidence "
            + str(value.get("focused_test_validation_status") or "not-available")
        )
        parts.append(
            "test/coverage alignment "
            + str(value.get("test_coverage_alignment") or "not-available")
        )
    roots = value.get("introducing_packages")
    if isinstance(roots, list) and roots:
        parts.append("introduced by " + ", ".join(str(item) for item in roots[:3]))
    return ", ".join(parts)


def _advanced_taint_alignment_counts(value: dict[str, Any]) -> tuple[int, int]:
    taint_paths = value.get("taint_paths")
    retained = taint_paths if isinstance(taint_paths, list) else []
    aligned = sum(
        isinstance(item, dict) and item.get("route_alignment") == "aligned"
        for item in retained
    )
    return aligned, len(retained)


def _area_summary(
    findings: list[Finding],
) -> list[tuple[str, dict[str, int]]]:
    areas: dict[str, dict[str, int]] = {}
    severity_names = [item.value for item in Severity]
    for finding in findings:
        area = finding.area.strip() or "unclassified"
        counts = areas.setdefault(
            area,
            dict.fromkeys([*severity_names, "total"], 0),
        )
        counts[finding.severity.value] += 1
        counts["total"] += 1
    return sorted(
        areas.items(),
        key=lambda item: (
            -item[1]["critical"],
            -item[1]["high"],
            -item[1]["medium"],
            -item[1]["low"],
            item[0],
        ),
    )


def _location_text(finding: Finding) -> str:
    if not finding.locations:
        return "<unknown>"
    location = finding.locations[0]
    value = location.path
    if location.start_line:
        value += f":{location.start_line}"
        if location.end_line and location.end_line != location.start_line:
            value += f"-{location.end_line}"
    if location.package:
        package = location.package
        if location.version:
            package += f" {location.version}"
        if location.ecosystem:
            package = f"{location.ecosystem}:{package}"
        value += f" ({package})"
    return value


def _markdown_classification(value: str) -> str:
    uri = _classification_uri(value)
    label = _markdown_text(value)
    return f"[{label}]({uri})" if uri else f"`{_markdown_code(value)}`"


def _markdown_citation(citation: Citation) -> str:
    label = citation.identifier
    if citation.title and citation.title != citation.identifier:
        label += f" - {citation.title}"
    uri = _reference_uri(citation)
    escaped = _markdown_text(label)
    return f"[{escaped}]({uri})" if uri else f"`{_markdown_code(label)}`"


def _markdown_tool_reference(tool: str) -> str:
    uri = _TOOL_REFERENCES.get(tool)
    return f"[Official documentation]({uri})" if uri else "-"


def _exposure_cross_reference_signals(context: dict[str, Any]) -> str:
    if not context.get("fusion_available"):
        return "fusion unavailable"
    signals = [
        "fusion " + str(context.get("fusion_review_tier") or "standard"),
        "corroboration " + str(context.get("corroboration") or "single-tool"),
    ]
    if context.get("changed_line") is True:
        signals.append("changed line")
    if context.get("line_covered") is False:
        signals.append("uncovered line")
    elif context.get("line_covered") is True:
        signals.append("covered line")
    states = context.get("reachability_states")
    if isinstance(states, list) and states:
        signals.append("reachability " + "/".join(str(value) for value in states[:3]))
    observations = context.get("runtime_observations")
    if isinstance(observations, list) and observations:
        signals.append("runtime " + "/".join(str(value) for value in observations[:3]))
    upstream = context.get("graph_upstream_files")
    if isinstance(upstream, int):
        signals.append(f"{upstream} upstream files")
    owners = context.get("owners")
    if isinstance(owners, list) and owners:
        signals.append("owners " + ", ".join(str(value) for value in owners[:3]))
    mapped = context.get("mapped_test_files")
    if isinstance(mapped, list) and mapped:
        signals.append("mapped tests " + ", ".join(str(value) for value in mapped[:3]))
    alignment = context.get("test_coverage_alignment")
    if isinstance(alignment, str):
        signals.append("validation " + alignment)
    priority = context.get("change_risk_priority")
    score = context.get("change_risk_score")
    if isinstance(priority, str):
        signals.append(
            f"change risk {priority}" + (f"/{score}" if isinstance(score, int) else "")
        )
    risks = context.get("structural_risk_kinds")
    if isinstance(risks, list) and risks:
        signals.append("structural " + ", ".join(str(value) for value in risks[:3]))
    return "; ".join(signals)


def _risk_campaign_control_text(campaign: dict[str, Any]) -> str:
    raw = campaign.get("control_point_context")
    control = raw if isinstance(raw, dict) else {}
    parts: list[str] = []
    if isinstance(control.get("graph_degree"), int):
        parts.append(f"degree {int(control['graph_degree'])}")
    if isinstance(control.get("maximum_complexity"), int):
        parts.append(
            "complexity "
            + str(int(control["maximum_complexity"]))
            + (
                f" ({control['maximum_complexity_rank']})"
                if control.get("maximum_complexity_rank")
                else ""
            )
        )
    if isinstance(control.get("change_risk_score"), int):
        parts.append(
            "change risk "
            + str(int(control["change_risk_score"]))
            + (
                f" ({control['change_priority']})"
                if control.get("change_priority")
                else ""
            )
        )
    uncovered = control.get("uncovered_changed_lines")
    if isinstance(uncovered, list) and uncovered:
        lines = ", ".join(str(line) for line in uncovered[:5])
        if len(uncovered) > 5:
            lines += f" (+{len(uncovered) - 5})"
        parts.append(f"uncovered changed lines {lines}")
    observations = control.get("runtime_observations")
    if isinstance(observations, list) and observations:
        parts.append("runtime " + ", ".join(str(value) for value in observations[:3]))
    return "; ".join(parts)


def _risk_campaign_factor_text(campaign: dict[str, Any]) -> str:
    raw = campaign.get("review_factors")
    factors = raw if isinstance(raw, list) else []
    values = [
        f"{factor.get('id')} +{int(factor.get('points') or 0)}"
        for factor in factors[:8]
        if isinstance(factor, dict) and factor.get("id") and factor.get("points")
    ]
    if len(factors) > 8:
        values.append(f"+{len(factors) - 8} more")
    return "; ".join(values)


def _graph_corroboration_text(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    parts: list[str] = []
    coverage = value.get("coverage_percent")
    if isinstance(coverage, (int, float)) and not isinstance(coverage, bool):
        parts.append(f"coverage {float(coverage):.1f}%")
    states = value.get("reachability_states", [])
    if isinstance(states, list) and states:
        parts.append("reachability " + "/".join(str(item) for item in states[:3]))
    rank = value.get("maximum_complexity_rank")
    complexity = value.get("maximum_complexity")
    if rank and isinstance(complexity, int):
        parts.append(f"max complexity {complexity} ({rank})")
    scanners = value.get("neighboring_scanners", [])
    if isinstance(scanners, list) and scanners:
        parts.append("nearby scanners " + ", ".join(str(item) for item in scanners[:5]))
    return "; ".join(parts)


def _primary_snippet_location(finding: Finding) -> Location | None:
    return next(
        (location for location in finding.locations if location.snippet is not None),
        None,
    )


def _artifact_identity(finding: Finding) -> tuple[str, str, int | None] | None:
    path = finding.evidence.get("artifact_path")
    digest = finding.evidence.get("artifact_sha256")
    size = finding.evidence.get("artifact_size_bytes")
    if not isinstance(path, str) or not path or path == "<outside-target>":
        return None
    candidate = Path(path)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        return None
    normalized_size = (
        size
        if isinstance(size, int) and not isinstance(size, bool) and size >= 0
        else None
    )
    return path, digest, normalized_size


def _missing_source_evidence_text(finding: Finding) -> str:
    location = next((item for item in finding.locations if item.path), None)
    if location is not None and location.start_line is not None:
        return (
            "No safe local source excerpt was available; inspect the cited file and "
            "line in the protected checkout."
        )
    if location is not None:
        return (
            "No source excerpt applies; inspect the cited repository object and "
            "normalized scanner evidence."
        )
    return (
        "No local source location was supplied; review the normalized scanner evidence."
    )


def _line_is_highlighted(location: Location, number: int) -> bool:
    start = location.start_line or number
    end = location.end_line or start
    return start <= number <= end


def _source_version(source: Source, tool_versions: dict[str, str]) -> str:
    version = source.version
    if version == "unknown":
        version = tool_versions.get(source.tool, "unknown")
    if version == "unknown":
        return "unknown"
    lowered = version.casefold()
    tool = source.tool.casefold()
    for prefix in (f"{tool} version: ", f"{tool} "):
        if lowered.startswith(prefix):
            return version[len(prefix) :]
    return version


def _reference_uri(citation: Citation) -> str | None:
    if citation.uri:
        uri = _safe_http_reference(citation.uri)
        if uri:
            return uri
    return _classification_uri(citation.identifier)


def _safe_http_reference(value: str) -> str | None:
    if len(value) > _MAX_REFERENCE_URI or _has_unsafe_reference_character(value):
        return None
    return value if _is_well_formed_http_reference(value) else None


def _has_unsafe_reference_character(value: str) -> bool:
    return any(
        not character.isprintable()
        or character.isspace()
        or character in _UNSAFE_MARKDOWN_URI_CHARACTERS
        for character in value
    )


def _is_well_formed_http_reference(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme.lower() in {"http", "https"}
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
    )


def _classification_uri(value: str) -> str | None:
    normalized = value.upper().split(":", 1)[0].strip()
    if normalized.startswith("CWE-") and normalized[4:].isdigit():
        return f"https://cwe.mitre.org/data/definitions/{normalized[4:]}.html"
    return None


def _completed_tools(tools: list[ToolRun]) -> int:
    return sum(1 for tool in tools if tool.status.value == "completed")


def _applicable_tools(tools: list[ToolRun]) -> int:
    return sum(1 for tool in tools if tool.applicable)


def _applicable_scanner_gaps(tools: list[ToolRun]) -> list[ToolRun]:
    return [
        tool for tool in tools if tool.applicable and tool.status.value != "completed"
    ]


def _not_applicable_scanners(tools: list[ToolRun]) -> list[ToolRun]:
    return [tool for tool in tools if not tool.applicable]


def _entrypoint_integrity_counts(tools: list[ToolRun]) -> tuple[int, int, int]:
    states = _entrypoint_integrity_states(tools)
    return (
        len(states),
        sum(
            approved is True and unchanged is True
            for _, _, _, approved, unchanged in states
        ),
        sum(unchanged is True for _, _, _, _, unchanged in states),
    )


def _entrypoint_integrity_states(
    tools: list[ToolRun],
) -> list[tuple[str, str, str, bool | None, bool | None]]:
    states: list[tuple[str, str, str, bool | None, bool | None]] = []
    for tool in tools:
        if tool.executable_sha256 is not None:
            states.append(
                (
                    tool.tool,
                    "primary",
                    tool.executable_sha256,
                    (
                        tool.executable_integrity_verified is True
                        and tool.executable_organization_approved
                    ),
                    tool.executable_unchanged,
                )
            )
        if tool.auxiliary_executable_sha256 is not None:
            states.append(
                (
                    tool.tool,
                    "helper",
                    tool.auxiliary_executable_sha256,
                    (
                        tool.auxiliary_executable_integrity_verified is True
                        and tool.auxiliary_executable_organization_approved
                    ),
                    tool.auxiliary_executable_unchanged,
                )
            )
    return states


def _executable_integrity_label(run: ToolRun) -> str:
    primary = _integrity_label(
        run.executable_sha256,
        (
            run.executable_integrity_verified is True
            and run.executable_organization_approved
        ),
        run.executable_unchanged,
    )
    if run.auxiliary_executable_sha256 is None:
        return primary
    auxiliary = _integrity_label(
        run.auxiliary_executable_sha256,
        (
            run.auxiliary_executable_integrity_verified is True
            and run.auxiliary_executable_organization_approved
        ),
        run.auxiliary_executable_unchanged,
    )
    return f"{primary}; helper: {auxiliary}"


def _integrity_label(
    digest: str | None,
    approved: bool | None,
    unchanged: bool | None,
) -> str:
    if digest is None:
        return "not checked"
    short_digest = digest[:12]
    if unchanged is False:
        return f"changed ({short_digest}...)"
    if approved and unchanged:
        return f"approved and unchanged ({short_digest}...)"
    if unchanged:
        return f"observed, not approved ({short_digest}...)"
    return f"observed, post-check unavailable ({short_digest}...)"


def _finding_sort_key(finding: Finding) -> tuple[int, int, int, int, str]:
    return finding_order_key(
        finding_id=finding.finding_id,
        severity=finding.severity,
        classifications=finding.classifications,
        evidence=finding.evidence,
        blocking=finding.blocking,
        status=finding.status,
    )


def _next_action(outcome: Outcome) -> str:
    return {
        Outcome.PASS: "No policy-blocking action is required.",
        Outcome.WARN: "Review the non-blocking findings and record disposition.",
        Outcome.FAIL: (
            "Remediate or govern blocking findings, then rerun before release or merge."
        ),
        Outcome.INCOMPLETE: (
            "Restore required scanner coverage or isolation evidence, then rerun; "
            "do not interpret this result as clean."
        ),
    }[outcome]


def _next_action_for_manifest(manifest: ScanManifest) -> str:
    if manifest.outcome is Outcome.INCOMPLETE and manifest.policy_reasons:
        return f"Resolve the first blocking evidence gap: {manifest.policy_reasons[0]}"
    return _next_action(manifest.outcome)


def _report_release_status(outcome: Outcome) -> str:
    return "PENDING EXTERNAL CONTROLS" if outcome is Outcome.PASS else "NOT APPROVED"


def _policy_disposition(outcome: Outcome) -> str:
    decision = _policy_decision_value(outcome)
    suffix = " (incomplete evidence)" if outcome is Outcome.INCOMPLETE else ""
    return f"`{decision}`{suffix}"


def _policy_decision_value(outcome: Outcome) -> str:
    return {
        Outcome.PASS: "ALLOW",
        Outcome.WARN: "REVIEW",
        Outcome.FAIL: "BLOCK",
        Outcome.INCOMPLETE: "BLOCK",
    }[outcome]


def _finding_priority(finding: Finding) -> str:
    return finding_priority(
        severity=finding.severity,
        classifications=finding.classifications,
        evidence=finding.evidence,
    )


def _owner_values(finding: Finding) -> list[str]:
    owners = finding.evidence.get("owners", [])
    return [str(value) for value in owners[:20]] if isinstance(owners, list) else []


def _finding_owners(finding: Finding) -> str:
    owners = _owner_values(finding)
    return ", ".join(f"`{_markdown_code(value)}`" for value in owners) or "Unassigned"


def _threat_intelligence_summary(finding: Finding) -> str:
    intelligence = finding.evidence.get("risk_intelligence", {})
    if not isinstance(intelligence, dict):
        return "No matched offline intelligence"
    values: list[str] = []
    known = intelligence.get("known_exploited", [])
    if isinstance(known, list) and known:
        values.append("CISA KEV: known exploitation")
    epss = intelligence.get("epss", [])
    if isinstance(epss, list) and epss:
        epss_records: list[dict[str, Any]] = [
            value for value in epss if isinstance(value, dict)
        ]
        highest = max(
            epss_records,
            key=lambda value: float(value.get("probability", 0.0)),
            default=None,
        )
        if highest is not None:
            values.append(
                f"EPSS {float(highest.get('probability', 0.0)):.1%} "
                f"(percentile {float(highest.get('percentile', 0.0)):.1%})"
            )
    vex = intelligence.get("vex", [])
    if isinstance(vex, list) and vex:
        states = sorted(
            {
                str(value.get("state") or "unknown")
                for value in vex
                if isinstance(value, dict)
            }
        )
        values.append("VEX: " + ", ".join(states))
    return "; ".join(values) or "No matched offline intelligence"


def _coverage_action(run: ToolRun, manifest: ScanManifest) -> str:
    if not run.applicable:
        if (
            manifest.profile in {"production", "release"}
            and run.tool == "pysa"
            and manifest.inventory.python_files
        ):
            return (
                "Add a reviewed Pyre/Pysa configuration and models, stage Pysa "
                "on a supported native runner, and rerun."
            )
        if (
            manifest.profile in {"production", "release"}
            and manifest.inventory.declared_dependencies
            and run.tool in {"cyclonedx-py", "guarddog"}
        ):
            return (
                "Provide a supported reproducible dependency lock and run this "
                "control on a compatible native platform."
            )
        return (
            "No current action; rerun if the project gains content or a platform "
            "configuration that makes this scanner applicable."
        )
    actions = {
        "unavailable": (
            "Stage the approved executable and required offline data or rules, "
            "verify its checksum and version, then rerun."
        ),
        "failed": (
            "Inspect the sanitized evidence record, correct the scanner invocation "
            "or local assets, then rerun."
        ),
        "timed_out": (
            "Review the target scope and runner capacity, tune the scanner timeout "
            "under policy, then rerun."
        ),
        "parse_error": (
            "Verify the scanner version/output schema and update the adapter or pin "
            "a compatible version before rerunning."
        ),
        "skipped": "Confirm the skip reason is approved, then rerun if it changes.",
    }
    return actions.get(
        run.status.value,
        "Review the scanner diagnostic and restore completed coverage.",
    )


def _markdown_table(value: str) -> str:
    # ``_markdown_text`` already escapes ``|``; escaping again would emit
    # ``\\|``, which GFM reads as a literal backslash followed by a cell break.
    return _markdown_text(value)
