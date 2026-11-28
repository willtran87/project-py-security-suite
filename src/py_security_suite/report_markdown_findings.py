from __future__ import annotations

import re
from typing import Any

from .report_markdown import _markdown_text, _markdown_code
from .models import Finding, Source
from .source_context import source_language
from .report_common import (
    _artifact_identity,
    _campaign_route_assurance_text,
    _campaign_shared_test_quality_text,
    _change_lifecycle_text,
    _dependency_usage_summary,
    _entry_point_exposure_text,
    _entry_runtime_status_text,
    _evidence_assurance_text,
    _exposure_cross_reference_signals,
    _finding_owners,
    _finding_priority,
    _finding_sort_key,
    _graph_corroboration_text,
    _line_is_highlighted,
    _location_text,
    _markdown_citation,
    _markdown_classification,
    _missing_source_evidence_text,
    _package_lifecycle_text,
    _primary_snippet_location,
    _remediation_context_summary,
    _risk_advisory_citations_text,
    _risk_campaign_control_text,
    _risk_path_validation_signals,
    _route_applicability_text,
    _route_ownership_text,
    _sdk_dependency_context_summary,
    _secret_membership_text,
    _source_version,
    _threat_intelligence_summary,
    _unrouted_structural_context_text,
)


__all__ = [
    "_markdown_data_exposure_context",
    "_markdown_fusion_context",
    "_markdown_risk_path_context",
    "_markdown_secret_provenance_context",
    "_markdown_structural_context",
    "_render_markdown_findings",
]


def _render_markdown_findings(
    findings: list[Finding],
    tool_versions: dict[str, str],
) -> list[str]:
    lines = ["", "## Findings requiring review", ""]
    if not findings:
        return [*lines, "- No normalized findings.", ""]
    ordered = sorted(findings, key=_finding_sort_key)
    for index, finding in enumerate(ordered[:20], start=1):
        sources = (
            "; ".join(
                _markdown_source(source, tool_versions) for source in finding.sources
            )
            or "No scanner attribution recorded"
        )
        classifications = (
            "; ".join(
                _markdown_classification(item) for item in finding.classifications
            )
            or "Unclassified"
        )
        references = (
            "; ".join(_markdown_citation(item) for item in finding.citations)
            or "No external reference"
        )
        lines.extend(
            [
                f"### {index}. {finding.severity.value.upper()} - "
                f"{_markdown_text(finding.title)}",
                "",
                f"- **Finding ID:** `{_markdown_code(finding.finding_id)}`",
                f"- **Priority:** `{_finding_priority(finding)}`",
                f"- **Lifecycle:** `{finding.status.value}`",
                f"- **Validation tier:** `{finding.validation_status.value}` — "
                + _markdown_text(
                    "; ".join(finding.validation_reasons)
                    or "No higher-tier positive evidence was retained."
                ),
                f"- **Owners:** {_finding_owners(finding)}",
                f"- **Threat intelligence:** {_threat_intelligence_summary(finding)}",
                f"- **Location:** `{_markdown_code(_location_text(finding))}`",
                f"- **Found by:** {sources}",
                f"- **Domain / area / confidence:** "
                f"`{_markdown_code(finding.domain)}` / "
                f"`{_markdown_code(finding.area)}` / "
                f"`{_markdown_code(finding.confidence.value)}`",
                f"- **Classification:** {classifications}",
                f"- **References:** {references}",
                *_markdown_graph_context(finding),
                *_markdown_secret_provenance_context(finding),
                *_markdown_risk_path_context(finding),
                *_markdown_structural_context(finding),
                *_markdown_data_exposure_context(finding),
                *_markdown_fusion_context(finding),
                "",
                f"**What was detected:** {_markdown_text(finding.description)}",
                "",
                *_markdown_source_excerpt(finding),
                f"**Why it matters:** {_markdown_text(finding.impact)}",
                "",
                f"**Recommended action:** {_markdown_text(finding.remediation)}",
                "",
            ]
        )
    if len(ordered) > 20:
        lines.extend(
            [
                f"{len(ordered) - 20} additional finding(s) are available in "
                "`index.html`, `findings.json`, and `results.sarif`.",
                "",
            ]
        )
    return lines


def _markdown_source(source: Source, tool_versions: dict[str, str]) -> str:
    version = _source_version(source, tool_versions)
    tool_label = source.tool if version == "unknown" else f"{source.tool} {version}"
    return f"`{_markdown_code(tool_label)}` rule `{_markdown_code(source.rule_id)}`"


def _markdown_secret_provenance_context(finding: Finding) -> list[str]:
    context = finding.evidence.get("secret_provenance")
    if not isinstance(context, dict):
        return []
    membership = "; ".join(
        (
            _secret_membership_text(
                "source",
                context.get("source_inventory_available"),
                context.get("source_inventory_member"),
            ),
            _secret_membership_text(
                "graph",
                context.get("graph_available"),
                context.get("graph_path_member"),
            ),
            _secret_membership_text(
                "artifact",
                context.get("artifact_manifest_available"),
                context.get("artifact_manifest_member"),
            ),
        )
    )
    lines = [
        "- **Secret candidate provenance:** `"
        + _markdown_code(str(context.get("secret_context_id") or "unknown"))
        + "`; content `"
        + _markdown_code(str(context.get("content_lane") or "unknown"))
        + "`; disposition `"
        + _markdown_code(str(context.get("review_disposition") or "unknown"))
        + "`; verification `"
        + _markdown_code(str(context.get("verification_status") or "not-established"))
        + "`; history `"
        + _markdown_code(str(context.get("history_status") or "not-established"))
        + "`; "
        + _markdown_text(membership)
        + "; scanner `"
        + _markdown_code(str(context.get("scanner_perspective") or "single-scanner"))
        + "`; assurance `"
        + _markdown_code(
            str(context.get("evidence_assurance_status") or "not-assessed")
        )
        + "`; redacted `"
        + _markdown_code("yes" if context.get("redacted") is True else "no")
        + "`. **Lane-specific action:** "
        + _markdown_text(
            str(context.get("recommended_action") or "Review the redacted candidate.")
        )
        + " This context does not establish that the candidate is a real, active, "
        "exploitable, or unique credential, and test/generated placement is not an "
        "automatic false-positive disposition."
    ]
    intersections = context.get("secret_exposure_intersections")
    values = intersections if isinstance(intersections, list) else []
    for item in values[:3]:
        if not isinstance(item, dict):
            continue
        sink_path = str(item.get("sink_path") or "unknown")
        if item.get("sink_line"):
            sink_path += f":{item['sink_line']}"
        handoff = item.get("validation_handoff")
        handoff = handoff if isinstance(handoff, dict) else {}
        candidate_tests = handoff.get("candidate_test_files")
        candidate_tests = candidate_tests if isinstance(candidate_tests, list) else []
        lines.append(
            "- **Secret-to-sensitive-sink intersection:** `"
            + _markdown_code(str(item.get("intersection_id") or "unknown"))
            + "`; relationship `"
            + _markdown_code(str(item.get("association_kind") or "unknown"))
            + "`; sink `"
            + _markdown_code(sink_path)
            + "`; family `"
            + _markdown_code(str(item.get("sink_family") or "unknown"))
            + "`; boundary `"
            + _markdown_code(str(item.get("trust_boundary") or "unknown"))
            + "`; protection `"
            + _markdown_code(str(item.get("protection_status") or "unknown"))
            + "`; distance `"
            + _markdown_code(str(item.get("distance_to_sink") or 0))
            + "` file hop(s); temporal `"
            + _markdown_code(str(item.get("temporal_alignment") or "not-established"))
            + "`; validation handoff `"
            + _markdown_code(
                str(handoff.get("supporting_evidence_readiness") or "not-established")
            )
            + "`; candidate tests `"
            + _markdown_code(
                ", ".join(str(value) for value in candidate_tests[:3]) or "none"
            )
            + "`; combined assurance prerequisite `"
            + _markdown_code(
                "met"
                if item.get("combined_assurance_prerequisite_met") is True
                else "not met"
            )
            + "`; canary `"
            + _markdown_code(
                str(item.get("canary_validation_status") or "not-established")
            )
            + "`. **Cross-reference action:** "
            + _markdown_text(
                str(item.get("recommended_action") or "Trace and protect the route.")
            )
            + " Static file-route co-location does not prove value flow, runtime "
            "execution, credential validity, or disclosure."
        )
        compounds = item.get("secret_exposure_advisory_intersections")
        compound_values = compounds if isinstance(compounds, list) else []
        for compound in compound_values[:2]:
            if not isinstance(compound, dict):
                continue
            lines.append(
                "- **Secret / sensitive-boundary / advisory intersection:** `"
                + _markdown_code(str(compound.get("intersection_id") or "unknown"))
                + "`; package `"
                + _markdown_code(str(compound.get("package") or "unknown"))
                + "`; advisory `"
                + _markdown_code(str(compound.get("primary_identifier") or "unknown"))
                + "`; known exploited `"
                + _markdown_code(
                    "yes" if compound.get("known_exploited") is True else "no"
                )
                + "`; fix available `"
                + _markdown_code(
                    "yes" if compound.get("fix_available") is True else "no"
                )
                + "`; canary `"
                + _markdown_code(
                    str(compound.get("canary_validation_status") or "not-established")
                )
                + "`. This exact-route join does not prove value flow, disclosure, vulnerable-function execution, or exploitability."
            )
    omitted = int(context.get("secret_exposure_intersections_omitted") or 0)
    if omitted:
        lines.append(
            f"- **Additional secret-to-sink intersections omitted from finding context:** {omitted}; inspect `risk-paths.json`."
        )
    return lines


def _markdown_graph_context(finding: Finding) -> list[str]:
    context = finding.evidence.get("graph_context")
    if not isinstance(context, dict):
        return []
    upstream = int(context.get("two_hop_upstream_count", 0))
    downstream = int(context.get("two_hop_downstream_count", 0))
    degree = int(context.get("degree", 0))
    interpretation = _markdown_text(str(context.get("interpretation", "")))
    related = context.get("related_finding_ids", [])
    related_text = ", ".join(f"`{_markdown_code(str(value))}`" for value in related[:5])
    suffix = f" Related: {related_text}." if related_text else ""
    corroboration = _graph_corroboration_text(context.get("corroborating_evidence", {}))
    if corroboration:
        suffix += f" Corroboration: {corroboration}."
    return [
        "- **Graph impact:** "
        f"degree `{degree}`; two-hop upstream `{upstream}`; "
        f"two-hop downstream `{downstream}` — {interpretation}.{suffix}"
    ]


def _markdown_risk_path_context(finding: Finding) -> list[str]:
    context = finding.evidence.get("risk_path")
    if not isinstance(context, dict):
        return []
    if context.get("status") != "routed":
        applicability = context.get("route_applicability")
        applicability = applicability if isinstance(applicability, dict) else {}
        applicability_text = _route_applicability_text(applicability)
        interpretation = (
            "This is a Python route-model evidence gap, not proof that the code is unreachable."
            if applicability.get("assessment") == "route-applicable"
            else "The finding remains actionable in its native evidence lane; a production Python route is not expected."
        )
        structural_text = _unrouted_structural_context_text(
            context.get("unrouted_structural_intersections")
        )
        return [
            "- **Static risk route:** "
            + _markdown_text(applicability_text)
            + "; "
            + _markdown_text(str(context.get("reason") or "review model coverage"))
            + ". **Evidence assurance:** "
            + _markdown_text(
                _evidence_assurance_text(context.get("evidence_assurance"))
            )
            + ". **Change/lifecycle attribution:** "
            + _markdown_text(
                _change_lifecycle_text(context.get("change_lifecycle_attribution"))
            )
            + ". **Action:** "
            + _markdown_text(
                str(context.get("recommended_action") or "Review.").rstrip(".")
            )
            + ". "
            + interpretation
            + structural_text
        ]
    entry = context.get("entry_point")
    entry = entry if isinstance(entry, dict) else {}
    files = context.get("files")
    file_values = files if isinstance(files, list) else []
    route = " → ".join(str(item) for item in file_values[:6])
    if len(file_values) > 6:
        route += f" → … (+{len(file_values) - 6})"
    validation = context.get("validation")
    runtime = context.get("runtime_context")
    validation = validation if isinstance(validation, dict) else {}
    runtime = runtime if isinstance(runtime, dict) else {}
    hotspot_ids = context.get("convergence_hotspot_ids")
    hotspot_text = (
        " **Shared control points:** "
        + ", ".join(f"`{_markdown_code(str(value))}`" for value in hotspot_ids[:5])
        + "."
        if isinstance(hotspot_ids, list) and hotspot_ids
        else ""
    )
    test_hotspot_ids = context.get("validation_test_hotspot_ids")
    test_hotspot_text = (
        " **Shared validation tests:** "
        + ", ".join(f"`{_markdown_code(str(value))}`" for value in test_hotspot_ids[:5])
        + "."
        if isinstance(test_hotspot_ids, list) and test_hotspot_ids
        else ""
    )
    campaigns = context.get("validation_campaigns")
    campaign_values = campaigns if isinstance(campaigns, list) else []
    campaign_text = ""
    if campaign_values:
        campaign = campaign_values[0]
        if isinstance(campaign, dict):
            campaign_ids = ", ".join(
                f"`{_markdown_code(str(value.get('campaign_id') or 'unknown'))}`"
                for value in campaign_values[:5]
                if isinstance(value, dict)
            )
            selected = campaign.get("selected_test_files")
            selected_values = selected if isinstance(selected, list) else []
            snapshot = campaign.get("source_snapshot")
            snapshot = snapshot if isinstance(snapshot, dict) else {}
            control_text = _risk_campaign_control_text(campaign)
            campaign_text = (
                " **Shared validation campaign(s):** "
                + campaign_ids
                + "; first campaign selected tests "
                + (
                    ", ".join(
                        f"`{_markdown_code(str(value))}`"
                        for value in selected_values[:3]
                    )
                    if selected_values
                    else "none mapped"
                )
                + "; execution `"
                + _markdown_code(
                    str(
                        campaign.get("focused_test_validation_status")
                        or "not-available"
                    )
                )
                + "`; aggregate coverage `"
                + _markdown_code(
                    str(campaign.get("coverage_status") or "not-available")
                )
                + "`; alignment `"
                + _markdown_code(
                    str(campaign.get("test_coverage_alignment") or "not-selected")
                )
                + "`; review `"
                + _markdown_code(str(campaign.get("review_tier") or "low"))
                + "`/`"
                + _markdown_code(str(int(campaign.get("review_score") or 0)))
                + "`; revision `"
                + _markdown_code(
                    str(snapshot.get("evidence_revision_binding") or "not-established")
                )
                + "`"
                + "; route evidence "
                + _markdown_text(_campaign_route_assurance_text(campaign))
                + "; shared tests "
                + _markdown_text(_campaign_shared_test_quality_text(campaign))
                + ("; " + _markdown_text(control_text) if control_text else "")
                + "."
            )
    advisory_routes = context.get("dependency_advisory_routes")
    advisory_values = advisory_routes if isinstance(advisory_routes, list) else []
    advisory_text = ""
    if advisory_values and isinstance(advisory_values[0], dict):
        first = advisory_values[0]
        identifiers = sorted(
            {
                str(item.get("primary_identifier") or item.get("advisory_cluster_id"))
                for item in advisory_values
                if isinstance(item, dict)
            }
        )
        import_paths = sorted(
            {
                str(item.get("import_path"))
                for item in advisory_values
                if isinstance(item, dict) and item.get("import_path")
            }
        )
        citations = _risk_advisory_citations_text(first.get("advisory_citations"))
        advisory_text = (
            " **Dependency exposure routes:** "
            + str(len(advisory_values))
            + " route(s) for "
            + ", ".join(
                f"`{_markdown_code(identifier)}`" for identifier in identifiers[:5]
            )
            + " through importer(s) "
            + ", ".join(f"`{_markdown_code(path)}`" for path in import_paths[:5])
            + ("; known exploited" if first.get("known_exploited") is True else "")
            + ("; fixed version retained" if first.get("fix_available") is True else "")
            + "; "
            + _markdown_text(_package_lifecycle_text(first.get("package_lifecycle")))
            + "; "
            + _markdown_text(_entry_point_exposure_text(first))
            + ("; citations " + citations if citations else "")
            + "."
        )
    raw_intersections = context.get("exposure_advisory_intersections")
    intersections = raw_intersections if isinstance(raw_intersections, list) else []
    intersection_text = ""
    if intersections:
        first_intersection = (
            intersections[0] if isinstance(intersections[0], dict) else {}
        )
        intersection_text = (
            " **Sensitive-boundary dependency intersection(s):** "
            + str(len(intersections))
            + "; exact path `"
            + _markdown_code(str(first_intersection.get("path") or "unknown"))
            + "`; SDK package `"
            + _markdown_code(str(first_intersection.get("package") or "unknown"))
            + "`; advisory `"
            + _markdown_code(
                str(first_intersection.get("primary_identifier") or "unknown")
            )
            + "`; protection `"
            + _markdown_code(
                str(first_intersection.get("protection_status") or "unknown")
            )
            + "`; "
            + _markdown_text(
                _package_lifecycle_text(first_intersection.get("package_lifecycle"))
            )
            + "; entry exposure `"
            + _markdown_code(
                str(int(first_intersection.get("entry_point_exposure_count") or 0))
            )
            + "` declared route(s); "
            + _markdown_text(
                _entry_runtime_status_text(
                    first_intersection.get("entry_point_runtime_statuses")
                )
            )
            + ". This is compound review context, not leakage or vulnerable-function proof."
        )
    compound_values = [
        compound
        for intersection in intersections
        if isinstance(intersection, dict)
        for compound in (
            intersection.get("secret_exposure_advisory_intersections") or []
        )
        if isinstance(compound, dict)
    ]
    compound_text = ""
    if compound_values:
        first_compound = compound_values[0]
        compound_text = (
            " **Secret / sensitive-boundary / advisory intersection(s):** "
            + str(len(compound_values))
            + "; secret `"
            + _markdown_code(str(first_compound.get("secret_path") or "unknown"))
            + "`; package `"
            + _markdown_code(str(first_compound.get("package") or "unknown"))
            + "`; advisory `"
            + _markdown_code(str(first_compound.get("primary_identifier") or "unknown"))
            + "`; canary `"
            + _markdown_code(
                str(first_compound.get("canary_validation_status") or "not-established")
            )
            + "`. The exact sensitive-route join does not prove value flow, disclosure, or vulnerable-function execution."
        )
    sensitive_route = context.get("sensitive_data_route")
    sensitive_route = sensitive_route if isinstance(sensitive_route, dict) else {}
    sensitive_route_text = ""
    if sensitive_route:
        sensitive_route_citations = _risk_advisory_citations_text(
            sensitive_route.get("citations")
        )
        sensitive_route_text = (
            " **End-to-end sensitive-data route:** `"
            + _markdown_code(
                str(sensitive_route.get("sensitive_route_id") or "unknown")
            )
            + "`; evidence `"
            + _markdown_code(str(sensitive_route.get("evidence_basis") or "unknown"))
            + "`; sink `"
            + _markdown_code(str(sensitive_route.get("sink_family") or "unknown"))
            + "`; boundary `"
            + _markdown_code(str(sensitive_route.get("trust_boundary") or "unknown"))
            + "`; protection `"
            + _markdown_code(str(sensitive_route.get("protection_status") or "unknown"))
            + "`; scanner assurance `"
            + _markdown_code(
                str(sensitive_route.get("evidence_assurance_status") or "not-assessed")
            )
            + "`; validation `"
            + _markdown_code(
                str(sensitive_route.get("validation_status") or "not-assessed")
            )
            + "`"
            + (
                "; guidance " + sensitive_route_citations
                if sensitive_route_citations
                else "; guidance citation unavailable"
            )
            + ". Citations support classification and remediation guidance; this "
            "static route is not proof of disclosure."
        )
    return [
        "- **Static risk route:** `"
        + _markdown_code(str(context.get("route_id") or "unknown"))
        + "` from `"
        + _markdown_code(str(entry.get("declared_as") or entry.get("id") or "unknown"))
        + "` in `"
        + _markdown_code(str(int(context.get("hop_count") or 0)))
        + "` file hop(s): "
        + _markdown_text(route or str(entry.get("path") or "same file"))
        + ". **Entry exposure:** "
        + _markdown_text(_entry_point_exposure_text(context))
        + ". **Validation:** "
        + _markdown_text(_risk_path_validation_signals(validation, runtime))
        + ". **Evidence assurance:** "
        + _markdown_text(_evidence_assurance_text(context.get("evidence_assurance")))
        + ". **Change/lifecycle attribution:** "
        + _markdown_text(
            _change_lifecycle_text(context.get("change_lifecycle_attribution"))
        )
        + ". **Route ownership:** "
        + _markdown_text(_route_ownership_text(context.get("ownership_context")))
        + "."
        + hotspot_text
        + test_hotspot_text
        + campaign_text
        + advisory_text
        + intersection_text
        + compound_text
        + sensitive_route_text
    ]


def _markdown_fusion_context(finding: Finding) -> list[str]:
    fusion = finding.evidence.get("fusion")
    if not isinstance(fusion, dict):
        return []
    reasons = fusion.get("review_reasons", [])
    reason_text = "; ".join(_markdown_text(str(value)) for value in reasons[:5])
    related = fusion.get("related_finding_ids", [])
    related_text = ", ".join(f"`{_markdown_code(str(value))}`" for value in related[:5])
    details = []
    if reason_text:
        details.append(reason_text)
    if related_text:
        details.append(f"related findings {related_text}")
    advisory = fusion.get("advisory_context")
    if isinstance(advisory, dict) and advisory.get("cluster_id"):
        primary = str(advisory.get("primary_identifier") or advisory["cluster_id"])
        usage = _dependency_usage_summary(advisory.get("dependency_usage"))
        remediation = advisory.get("remediation_context")
        remediation_summary = _remediation_context_summary(remediation)
        details.append(
            "advisory `"
            + _markdown_code(primary)
            + "`"
            + ("; dependency use " + _markdown_text(usage) if usage else "")
            + (
                "; remediation " + _markdown_text(remediation_summary)
                if remediation_summary
                else ""
            )
        )
        if isinstance(remediation, dict) and remediation.get("recommended_action"):
            details.append(
                "action " + _markdown_text(str(remediation["recommended_action"]))
            )
    suffix = " — " + "; ".join(details) if details else ""
    return [
        "- **Evidence fusion:** "
        f"review tier `{_markdown_code(str(fusion.get('review_tier', 'standard')))}`; "
        f"corroboration `{_markdown_code(str(fusion.get('corroboration', 'single-tool')))}`"
        f"{suffix}"
    ]


def _markdown_data_exposure_context(finding: Finding) -> list[str]:
    context = finding.evidence.get("data_exposure")
    if not isinstance(context, dict):
        return []
    sdk = str(context.get("sdk") or "none identified")
    exact_sink = str(context.get("sink") or context.get("sink_family") or "unknown")
    sanitizer = context.get("sanitizer_visible")
    sanitizer_text = (
        "visible; verify effectiveness"
        if sanitizer is True
        else "not visible"
        if sanitizer is False
        else "unknown"
    )
    data_classes = (
        ", ".join(str(value) for value in context.get("data_classes", []))
        or "unclassified"
    )
    risk_factors = (
        ", ".join(str(value) for value in context.get("risk_factors", [])[:5])
        or "none recorded"
    )
    cross = context.get("cross_references")
    cross = cross if isinstance(cross, dict) else {}
    cross_signals = _exposure_cross_reference_signals(cross)
    result = [
        "- **Sensitive-data path:** concern `"
        + _markdown_code(str(context.get("concern", "review")))
        + "`; sink `"
        + _markdown_code(exact_sink)
        + "` (family `"
        + _markdown_code(str(context.get("sink_family", "unknown")))
        + "`)"
        + "; SDK `"
        + _markdown_code(sdk)
        + "`; structural relevance `"
        + _markdown_code(str(context.get("structural_relevance", "unknown")))
        + "`; priority `"
        + _markdown_code(str(context.get("review_priority", "medium")))
        + "`; cross-tool triage `"
        + _markdown_code(str(context.get("triage_tier", "standard")))
        + "`; data classes `"
        + _markdown_code(data_classes)
        + "`; trust boundary `"
        + _markdown_code(str(context.get("trust_boundary", "unknown")))
        + "`; risk factors `"
        + _markdown_code(risk_factors)
        + "`; sanitizer `"
        + _markdown_code(sanitizer_text)
        + "`; joined evidence `"
        + _markdown_code(cross_signals)
        + "` - "
        + _markdown_text(str(context.get("recommended_action", "Review the path.")))
    ]
    result.extend(
        _markdown_sdk_dependency_context(context.get("sdk_dependency_context"))
    )
    steps = context.get("verification_steps")
    if isinstance(steps, list) and steps:
        result.append(
            "- **Exposure verification:** "
            + " ".join(
                f"{index}. {_markdown_text(str(step))}"
                for index, step in enumerate(steps, start=1)
            )
        )
    return result


def _markdown_sdk_dependency_context(value: Any) -> list[str]:
    summary = _sdk_dependency_context_summary(value)
    if not summary:
        return []
    citations = value.get("citations") if isinstance(value, dict) else None
    links: list[str] = []
    if isinstance(citations, list):
        for item in citations[:5]:
            if not isinstance(item, dict):
                continue
            identifier = _markdown_text(str(item.get("identifier") or "reference"))
            uri = item.get("uri")
            links.append(
                f"[{identifier}]({uri})"
                if isinstance(uri, str) and uri.startswith(("https://", "http://"))
                else f"`{_markdown_code(identifier)}`"
            )
    suffix = "; citations " + ", ".join(links) if links else ""
    result = [
        "- **SDK dependency cross-reference:** "
        + _markdown_text(summary)
        + suffix
        + ". This context raises review priority but does not prove SDK-mediated disclosure."
    ]
    clusters = value.get("advisory_clusters") if isinstance(value, dict) else None
    if isinstance(clusters, list):
        actions = [
            (
                str(
                    item.get("primary_identifier")
                    or item.get("cluster_id")
                    or "advisory"
                ),
                str(remediation.get("priority") or "P4"),
                str(remediation.get("recommended_action") or ""),
            )
            for item in clusters[:5]
            if isinstance(item, dict)
            and isinstance((remediation := item.get("remediation_context")), dict)
            and remediation.get("recommended_action")
        ]
        if actions:
            result.append(
                "- **SDK advisory action:** "
                + " ".join(
                    f"`{_markdown_code(priority)}` `{_markdown_code(identifier)}`: {_markdown_text(action)}"
                    for identifier, priority, action in actions[:3]
                )
            )
    return result


def _markdown_structural_context(finding: Finding) -> list[str]:
    structural = finding.evidence.get("structural_synthesis")
    if not isinstance(structural, dict):
        return []
    parts: list[str] = []
    disposition = structural.get("disposition")
    confidence = structural.get("confidence")
    if disposition:
        label = f"dead-code `{_markdown_code(str(disposition))}`"
        if confidence:
            label += f" ({_markdown_code(str(confidence))} confidence)"
        parts.append(label)
    island = structural.get("island")
    if isinstance(island, dict):
        parts.append(
            "island `"
            + _markdown_code(str(island.get("classification", "review")))
            + "` ("
            + str(int(island.get("lines_of_code", 0)))
            + " LOC, `"
            + _markdown_code(str(island.get("priority", "low")))
            + "` priority)"
        )
    cycle = structural.get("import_cycle")
    if isinstance(cycle, dict):
        parts.append(
            "import cycle `"
            + str(int(cycle.get("file_count", 0)))
            + "` files (`"
            + _markdown_code(str(cycle.get("priority", "low")))
            + "` priority)"
        )
    change = structural.get("change_impact")
    if isinstance(change, dict):
        test_count = (
            len(change.get("direct_test_files", []))
            + len(change.get("transitive_test_files", []))
            + len(change.get("associated_test_files", []))
        )
        parts.append(
            "change impact `"
            + _markdown_code(str(change.get("classification", "review")))
            + "` (risk `"
            + str(int(change.get("risk_score", 0)))
            + "`, mapped tests `"
            + str(test_count)
            + "`, validation `"
            + _markdown_code(
                str(change.get("test_coverage_alignment", "not-available"))
            )
            + "`)"
        )
    boundary = structural.get("island_boundary")
    if isinstance(boundary, dict):
        parts.append(
            "island boundary `"
            + _markdown_code(str(boundary.get("boundary_classification", "review")))
            + "`"
        )
    if not parts:
        return []
    action = structural.get("recommended_action")
    if not action and isinstance(island, dict):
        action = island.get("recommended_action")
    if not action and isinstance(cycle, dict):
        action = cycle.get("recommended_action")
    if not action and isinstance(change, dict):
        action = change.get("recommended_action")
    if not action and isinstance(boundary, dict):
        action = boundary.get("recommended_action")
    suffix = f" - {_markdown_text(str(action))}" if action else ""
    return ["- **Structural synthesis:** " + "; ".join(parts) + suffix]


def _markdown_source_excerpt(finding: Finding) -> list[str]:
    location = _primary_snippet_location(finding)
    if location is None or location.snippet is None:
        artifact = _artifact_identity(finding)
        if artifact is not None:
            path, digest, size = artifact
            size_line = f"size: {size} bytes\n" if size is not None else ""
            return [
                f"**Artifact identity evidence - `{_markdown_code(path)}`:**",
                "",
                "```text",
                f"sha256:{digest}\n{size_line}".rstrip(),
                "```",
                "",
            ]
        return [
            f"**Source evidence:** {_missing_source_evidence_text(finding)}",
            "",
        ]
    start = location.snippet_start_line or location.start_line or 1
    lines = location.snippet.splitlines() or [""]
    numbered = []
    for offset, value in enumerate(lines):
        number = start + offset
        marker = ">" if _line_is_highlighted(location, number) else " "
        numbered.append(f"{marker} {number:>5} | {value}")
    body = "\n".join(numbered)
    fence = "`" * max(3, _longest_backtick_run(body) + 1)
    language = source_language(location.path)
    result = [
        f"**Source evidence - `{_markdown_code(_location_text(finding))}`:**",
        "",
        f"{fence}{language}",
        body,
        fence,
        "",
    ]
    if location.snippet_redacted:
        result.extend(
            [
                "_The secret-bearing line is deliberately redacted from every "
                + "report format. Inspect it only in the protected checkout._",
                "",
            ]
        )
    return result


def _longest_backtick_run(value: str) -> int:
    return max((len(match.group(0)) for match in re.finditer(r"`+", value)), default=0)
