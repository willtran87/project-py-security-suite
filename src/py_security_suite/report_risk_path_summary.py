"""Markdown risk-path, route and campaign sections of the security summary."""

from __future__ import annotations

from typing import Any

from .report_markdown import _markdown_text, _markdown_code
from .risk_path_report_intro import render_risk_path_intro
from .report_common import (
    _campaign_route_assurance_text,
    _campaign_shared_test_quality_text,
    _change_lifecycle_text,
    _entry_point_exposure_text,
    _entry_runtime_status_text,
    _evidence_assurance_text,
    _package_lifecycle_text,
    _risk_advisory_citations_text,
    _risk_campaign_control_text,
    _risk_campaign_factor_text,
    _risk_path_validation_signals,
    _route_ownership_text,
    _secret_membership_text,
)


__all__ = [
    "_render_risk_path_summary",
]


def _render_risk_path_summary(value: dict[str, Any] | None) -> list[str]:
    if not isinstance(value, dict) or not isinstance(value.get("summary"), dict):
        return []
    summary = value["summary"]
    routes = value.get("routes")
    routes = routes if isinstance(routes, list) else []
    dependency_routes = [
        route
        for route in routes
        if isinstance(route, dict)
        and isinstance(route.get("target"), dict)
        and route["target"].get("kind") == "dependency-advisory-import"
    ]
    unrouted = value.get("unrouted_targets")
    unrouted = unrouted if isinstance(unrouted, list) else []
    unrouted_structural = value.get("unrouted_structural_intersections")
    unrouted_structural = (
        unrouted_structural if isinstance(unrouted_structural, list) else []
    )
    hotspots = value.get("convergence_hotspots")
    hotspots = hotspots if isinstance(hotspots, list) else []
    campaigns = value.get("validation_campaigns")
    campaigns = campaigns if isinstance(campaigns, list) else []
    test_hotspots = value.get("validation_test_hotspots")
    test_hotspots = test_hotspots if isinstance(test_hotspots, list) else []
    intersections = value.get("exposure_advisory_intersections")
    intersections = intersections if isinstance(intersections, list) else []
    sensitive_routes = value.get("sensitive_data_routes")
    sensitive_routes = sensitive_routes if isinstance(sensitive_routes, list) else []
    secret_assessments = value.get("secret_provenance_assessments")
    secret_assessments = (
        secret_assessments if isinstance(secret_assessments, list) else []
    )
    secret_exposure_intersections = value.get("secret_exposure_intersections")
    secret_exposure_intersections = (
        secret_exposure_intersections
        if isinstance(secret_exposure_intersections, list)
        else []
    )
    secret_exposure_advisory_intersections = value.get(
        "secret_exposure_advisory_intersections"
    )
    secret_exposure_advisory_intersections = (
        secret_exposure_advisory_intersections
        if isinstance(secret_exposure_advisory_intersections, list)
        else []
    )
    owner_queues = value.get("owner_work_queues")
    owner_queues = owner_queues if isinstance(owner_queues, list) else []
    lines = render_risk_path_intro(summary)
    lines.extend(_render_risk_routes_table(routes))
    lines.extend(_render_dependency_route_table(dependency_routes))
    lines.extend(_render_sensitive_data_routes(sensitive_routes))
    lines.extend(_render_secret_provenance_assessments(secret_assessments))
    lines.extend(_render_secret_exposure_intersections(secret_exposure_intersections))
    lines.extend(
        _render_secret_exposure_advisory_intersections(
            secret_exposure_advisory_intersections
        )
    )
    lines.extend(_render_exposure_advisory_intersections(intersections))
    lines.extend(_render_risk_test_hotspots_table(test_hotspots))
    lines.extend(_render_risk_campaigns_table(campaigns))
    lines.extend(_render_risk_hotspots_table(hotspots))
    lines.extend(_render_risk_owner_queues(owner_queues))
    lines.extend(_render_unrouted_structural_intersections(unrouted_structural))
    lines.extend(_render_risk_unrouted_table(unrouted))
    return lines


def _render_unrouted_structural_intersections(values: list[Any]) -> list[str]:
    if not values:
        return []
    lines = [
        "",
        "### Unrouted target / structural-island decisions",
        "",
        (
            "These exact retained island-membership joins combine route gaps with "
            "reachability, Graphify boundaries, dead-code corroboration, runtime "
            "counter-evidence, coverage, tests, and ownership. They guide a missing-"
            "entry-point versus dormant-capability decision; they do not prove dead "
            "code, safety, exploitability, or production inaccessibility."
        ),
        "",
        "| Priority / target | Island / evidence | Decision | Validation / owner / action |",
        "|---|---|---|---|",
    ]
    for item in values[:10]:
        if not isinstance(item, dict):
            continue
        validation = item.get("target_validation")
        validation = validation if isinstance(validation, dict) else {}
        owners = item.get("coordination_owners")
        owner_values = owners if isinstance(owners, list) else []
        candidate_entries = item.get("candidate_entry_paths")
        entry_values = candidate_entries if isinstance(candidate_entries, list) else []
        tests = item.get("direct_test_files")
        test_values = tests if isinstance(tests, list) else []
        lines.append(
            "| `"
            + _markdown_code(str(item.get("priority") or "P4"))
            + "` `"
            + _markdown_code(str(item.get("path") or "unknown"))
            + "`"
            + (
                ":" + str(int(item["line"]))
                if isinstance(item.get("line"), int)
                else ""
            )
            + "<br>`"
            + _markdown_code(str(item.get("target_kind") or "unknown"))
            + "` | `"
            + _markdown_code(str(item.get("island_id") or "unknown"))
            + "`<br>state `"
            + _markdown_code(str(item.get("island_state") or "unknown"))
            + "`; boundary `"
            + _markdown_code(
                str(item.get("boundary_classification") or "not-established")
            )
            + "`; membership `"
            + _markdown_code(str(item.get("evidence_basis") or "unknown"))
            + "` | `"
            + _markdown_code(str(item.get("risk_signal") or "unknown"))
            + "`<br>`"
            + _markdown_code(str(item.get("decision") or "review"))
            + "`"
            + (
                "<br>candidate entry "
                + ", ".join(
                    "`" + _markdown_code(str(path)) + "`" for path in entry_values[:3]
                )
                if entry_values
                else ""
            )
            + " | validation `"
            + _markdown_code(str(validation.get("assessment_status") or "not-assessed"))
            + "`; tests "
            + (
                ", ".join(
                    "`" + _markdown_code(str(path)) + "`" for path in test_values[:3]
                )
                if test_values
                else "not mapped"
            )
            + "<br>owner "
            + _markdown_text(
                ", ".join(str(owner) for owner in owner_values) or "unassigned"
            )
            + "<br>"
            + _markdown_text(str(item.get("recommended_action") or "Review."))
            + " |"
        )
    if len(values) > 10:
        lines.extend(
            [
                "",
                f"{len(values) - 10} additional retained structural intersection(s) are available in `risk-paths.json`.",
            ]
        )
    return lines


def _render_sensitive_data_routes(values: list[Any]) -> list[str]:
    if not values:
        return []
    lines = [
        "",
        "### End-to-end sensitive-data routes",
        "",
        (
            "These records join scanner-confirmed exposure findings or review-worthy "
            "sink inventory to declared entry points, trust boundaries, observed "
            "protections, scanner assurance, validation, and ownership. They are "
            "bounded static review paths, not proof of attacker control, runtime "
            "data flow, disclosure, or regulatory impact. Retained citations support "
            "classification and remediation guidance; they do not validate the route."
        ),
        "",
        "| Priority / evidence | Entry route / boundary | Data / protection | Assurance / validation | Owner / action |",
        "|---|---|---|---|---|",
    ]
    for value in values[:10]:
        if not isinstance(value, dict):
            continue
        entry_ids = value.get("entry_point_ids")
        entries = entry_ids if isinstance(entry_ids, list) else []
        data_classes = value.get("data_classes")
        classes = data_classes if isinstance(data_classes, list) else []
        owners = value.get("owners")
        owner_values = owners if isinstance(owners, list) else []
        runtime = value.get("entry_point_runtime_statuses")
        runtime_text = _entry_runtime_status_text(runtime)
        citations = _risk_advisory_citations_text(value.get("citations"))
        path = str(value.get("path") or "unknown")
        if value.get("line"):
            path += f":{value['line']}"
        lines.append(
            "| `"
            + _markdown_code(str(value.get("priority") or "P4"))
            + "` `"
            + _markdown_code(str(value.get("evidence_basis") or "unknown"))
            + "`<br>`"
            + _markdown_code(str(value.get("sensitive_route_id") or "unknown"))
            + "`<br>`"
            + _markdown_code(path)
            + "` | "
            + _markdown_text(
                ", ".join(str(item) for item in entries[:3]) or "No retained entry"
            )
            + "<br>"
            + _markdown_text(runtime_text)
            + "<br>sink `"
            + _markdown_code(str(value.get("sink_family") or "unknown"))
            + "`; boundary `"
            + _markdown_code(str(value.get("trust_boundary") or "unknown"))
            + "` | "
            + _markdown_text(
                ", ".join(str(item) for item in classes[:5]) or "Unclassified"
            )
            + "<br>protection `"
            + _markdown_code(str(value.get("protection_status") or "unknown"))
            + "`"
            + (
                "<br>SDK `" + _markdown_code(str(value["sdk"])) + "`"
                if value.get("sdk")
                else ""
            )
            + ("<br>guidance " + citations if citations else "<br>guidance unavailable")
            + " | scanner `"
            + _markdown_code(
                str(value.get("evidence_assurance_status") or "not-assessed")
            )
            + "`<br>validation `"
            + _markdown_code(str(value.get("validation_status") or "not-assessed"))
            + "` | **"
            + _markdown_text(
                ", ".join(str(item) for item in owner_values[:3]) or "Unassigned"
            )
            + "**<br>handoffs `"
            + _markdown_code(str(int(value.get("ownership_boundaries") or 0)))
            + "`<br>"
            + _markdown_text(
                str(
                    value.get("recommended_action")
                    or "Review the sensitive-data route."
                )
            )
            + " |"
        )
    return lines


def _render_secret_provenance_assessments(values: list[Any]) -> list[str]:
    if not values:
        return []
    lines = [
        "",
        "### Secret candidate provenance",
        "",
        (
            "These records join redacted secret-scanner candidates with content lane, "
            "source/graph/artifact membership, history mode, scanner verification and "
            "assurance, lifecycle, and ownership. Generated evidence or test context "
            "is not an automatic false-positive disposition, and scanner verification "
            "does not establish current usability or scope."
        ),
        "",
        "| Priority / candidate | Content / inventory | Verification / history | Scanner / owner | Action |",
        "|---|---|---|---|---|",
    ]
    for value in values[:10]:
        if not isinstance(value, dict):
            continue
        path = str(value.get("path") or "unknown")
        if value.get("line"):
            path += f":{value['line']}"
        tools = value.get("scanner_tools")
        tool_values = tools if isinstance(tools, list) else []
        owners = value.get("owners")
        owner_values = owners if isinstance(owners, list) else []
        citations = _risk_advisory_citations_text(value.get("citations"))
        inventory = "; ".join(
            (
                _secret_membership_text(
                    "source",
                    value.get("source_inventory_available"),
                    value.get("source_inventory_member"),
                ),
                _secret_membership_text(
                    "graph",
                    value.get("graph_available"),
                    value.get("graph_path_member"),
                ),
                _secret_membership_text(
                    "artifact",
                    value.get("artifact_manifest_available"),
                    value.get("artifact_manifest_member"),
                ),
            )
        )
        lines.append(
            "| `"
            + _markdown_code(str(value.get("priority") or "P4"))
            + "` `"
            + _markdown_code(str(value.get("secret_context_id") or "unknown"))
            + "`<br>`"
            + _markdown_code(path)
            + "`<br>finding `"
            + _markdown_code(str(value.get("finding_id") or "unknown"))
            + "` | `"
            + _markdown_code(str(value.get("content_lane") or "unknown"))
            + "`<br>disposition `"
            + _markdown_code(str(value.get("review_disposition") or "unknown"))
            + "`<br>"
            + _markdown_text(inventory)
            + "<br>redacted `"
            + _markdown_code("yes" if value.get("redacted") is True else "no")
            + "` | verification `"
            + _markdown_code(str(value.get("verification_status") or "not-established"))
            + "`<br>history `"
            + _markdown_code(str(value.get("history_status") or "not-established"))
            + "`<br>lifecycle `"
            + _markdown_code(str(value.get("lifecycle_status") or "unclassified"))
            + "` | "
            + _markdown_text(
                ", ".join(str(item) for item in tool_values[:5]) or "Unattributed"
            )
            + "<br>perspective `"
            + _markdown_code(str(value.get("scanner_perspective") or "single-scanner"))
            + "`; assurance `"
            + _markdown_code(
                str(value.get("evidence_assurance_status") or "not-assessed")
            )
            + "`<br>owner **"
            + _markdown_text(
                ", ".join(str(item) for item in owner_values[:3]) or "Unassigned"
            )
            + "**"
            + ("<br>" + citations if citations else "")
            + " | "
            + _markdown_text(
                str(value.get("recommended_action") or "Review the redacted candidate.")
            )
            + " |"
        )
    return lines


def _render_secret_exposure_intersections(values: list[Any]) -> list[str]:
    if not values:
        return []
    lines = [
        "",
        "### Secret-to-sensitive-sink route intersections",
        "",
        (
            "These records identify a redacted production-source secret candidate in "
            "the exact sink file or on the bounded Graphify file route to a sensitive "
            "sink. This is a focused review signal, not symbol-level taint proof, "
            "credential validation, runtime execution evidence, or proof of disclosure."
        ),
        "",
        "| Priority / relationship | Secret candidate | Sensitive sink | Evidence / assurance | Owners / action |",
        "|---|---|---|---|---|",
    ]
    for value in values[:10]:
        if not isinstance(value, dict):
            continue
        secret_path = str(value.get("secret_path") or "unknown")
        if value.get("secret_line"):
            secret_path += f":{value['secret_line']}"
        sink_path = str(value.get("sink_path") or "unknown")
        if value.get("sink_line"):
            sink_path += f":{value['sink_line']}"
        owners = value.get("owners")
        owner_values = owners if isinstance(owners, list) else []
        citations = _risk_advisory_citations_text(value.get("citations"))
        handoff = value.get("validation_handoff")
        handoff = handoff if isinstance(handoff, dict) else {}
        candidate_tests = handoff.get("candidate_test_files")
        candidate_tests = candidate_tests if isinstance(candidate_tests, list) else []
        focused_statuses = handoff.get("focused_test_statuses")
        focused_statuses = (
            focused_statuses if isinstance(focused_statuses, list) else []
        )
        alignments = handoff.get("test_coverage_alignments")
        alignments = alignments if isinstance(alignments, list) else []
        revisions = handoff.get("source_revision_bindings")
        revisions = revisions if isinstance(revisions, list) else []
        lines.append(
            "| `"
            + _markdown_code(str(value.get("priority") or "P4"))
            + "` `"
            + _markdown_code(str(value.get("association_kind") or "unknown"))
            + "`<br>distance `"
            + _markdown_code(str(value.get("distance_to_sink") or 0))
            + "` file hop(s)<br>temporal `"
            + _markdown_code(str(value.get("temporal_alignment") or "not-established"))
            + "` | `"
            + _markdown_code(secret_path)
            + "`<br>verification `"
            + _markdown_code(
                str(value.get("secret_verification_status") or "not-established")
            )
            + "` | `"
            + _markdown_code(sink_path)
            + "`<br>family `"
            + _markdown_code(str(value.get("sink_family") or "unknown"))
            + "`; boundary `"
            + _markdown_code(str(value.get("trust_boundary") or "unknown"))
            + "`<br>protection `"
            + _markdown_code(str(value.get("protection_status") or "unknown"))
            + "` | basis `"
            + _markdown_code(str(value.get("sensitive_evidence_basis") or "unknown"))
            + "`<br>secret `"
            + _markdown_code(
                str(value.get("secret_assurance_status") or "not-assessed")
            )
            + "`; sink `"
            + _markdown_code(
                str(value.get("sensitive_assurance_status") or "not-assessed")
            )
            + "`; validation `"
            + _markdown_code(str(value.get("validation_status") or "not-assessed"))
            + "`<br>handoff `"
            + _markdown_code(
                str(handoff.get("supporting_evidence_readiness") or "not-established")
            )
            + "`; combined prerequisite `"
            + _markdown_code(
                "met"
                if value.get("combined_assurance_prerequisite_met") is True
                else "not met"
            )
            + "`<br>candidate tests `"
            + _markdown_code(
                ", ".join(str(item) for item in candidate_tests[:3]) or "none"
            )
            + "`; focused `"
            + _markdown_code(
                ", ".join(str(item) for item in focused_statuses) or "not available"
            )
            + "`<br>coverage alignment `"
            + _markdown_code(
                ", ".join(str(item) for item in alignments) or "not available"
            )
            + "`; revision `"
            + _markdown_code(
                ", ".join(str(item) for item in revisions) or "not established"
            )
            + "`; canary `"
            + _markdown_code(
                str(value.get("canary_validation_status") or "not-established")
            )
            + "`"
            + ("<br>" + citations if citations else "")
            + " | **"
            + _markdown_text(
                ", ".join(str(item) for item in owner_values[:3]) or "Unassigned"
            )
            + "**<br>"
            + _markdown_text(
                str(value.get("recommended_action") or "Trace and protect the route.")
            )
            + " |"
        )
    if len(values) > 10:
        lines.extend(
            [
                "",
                f"{len(values) - 10} additional retained intersection(s) are available in `risk-paths.json`.",
            ]
        )
    return lines


def _render_secret_exposure_advisory_intersections(
    values: list[Any],
) -> list[str]:
    if not values:
        return []
    lines = [
        "",
        "### Secret, sensitive-boundary, and advisory intersections",
        "",
        (
            "Each record joins a secret-to-sink intersection and an SDK-advisory "
            "intersection only when both cite the identical retained sensitive "
            "route. It is compound review scope—not proof of credential flow, "
            "disclosure, vulnerable-function execution, or exploitability."
        ),
        "",
        "| Priority / secret | Sensitive boundary | Advisory / lifecycle | Runtime / validation / assurance | Owners / action |",
        "|---|---|---|---|---|",
    ]
    for value in values[:10]:
        if not isinstance(value, dict):
            continue
        secret_path = str(value.get("secret_path") or "unknown")
        if value.get("secret_line"):
            secret_path += f":{value['secret_line']}"
        sink_path = str(value.get("sink_path") or "unknown")
        if value.get("sink_line"):
            sink_path += f":{value['sink_line']}"
        handoff = value.get("validation_handoff")
        handoff = handoff if isinstance(handoff, dict) else {}
        tests = value.get("recommended_test_files")
        tests = tests if isinstance(tests, list) else []
        statuses = value.get("validation_statuses")
        statuses = statuses if isinstance(statuses, dict) else {}
        owners = value.get("owners")
        owners = owners if isinstance(owners, list) else []
        citations = _risk_advisory_citations_text(value.get("citations"))
        threat = (
            ", ".join(
                label
                for applies, label in (
                    (value.get("known_exploited") is True, "CISA KEV"),
                    (value.get("epss_high") is True, "high EPSS"),
                    (value.get("fix_available") is True, "fix available"),
                )
                if applies
            )
            or "no retained KEV/high-EPSS/fix signal"
        )
        lines.append(
            "| `"
            + _markdown_code(str(value.get("priority") or "P4"))
            + "` `"
            + _markdown_code(secret_path)
            + "`<br>verification `"
            + _markdown_code(
                str(value.get("secret_verification_status") or "not-established")
            )
            + "`; temporal `"
            + _markdown_code(str(value.get("temporal_alignment") or "not-established"))
            + "`; distance `"
            + _markdown_code(str(value.get("secret_distance_to_sink") or 0))
            + "` hop(s) | `"
            + _markdown_code(sink_path)
            + "`<br>family `"
            + _markdown_code(str(value.get("sink_family") or "unknown"))
            + "`; boundary `"
            + _markdown_code(str(value.get("trust_boundary") or "unknown"))
            + "`; protection `"
            + _markdown_code(str(value.get("protection_status") or "unknown"))
            + "` | `"
            + _markdown_code(str(value.get("package") or "unknown"))
            + "` / `"
            + _markdown_code(str(value.get("primary_identifier") or "unknown"))
            + "`<br>"
            + _markdown_text(threat)
            + "<br>lifecycle "
            + _markdown_text(_package_lifecycle_text(value.get("package_lifecycle")))
            + ("<br>" + citations if citations else "")
            + " | runtime "
            + _markdown_text(
                _entry_runtime_status_text(value.get("entry_point_runtime_statuses"))
            )
            + "<br>validation secret/sink/dependency `"
            + _markdown_code(
                "/".join(
                    str(statuses.get(key) or "not-assessed")
                    for key in ("secret_sink", "sink", "dependency")
                )
            )
            + "`<br>handoff `"
            + _markdown_code(
                str(handoff.get("supporting_evidence_readiness") or "not-established")
            )
            + "`; combined prerequisite `"
            + _markdown_code(
                "met"
                if value.get("combined_assurance_prerequisite_met") is True
                else "not met"
            )
            + "`; canary `"
            + _markdown_code(
                str(value.get("canary_validation_status") or "not-established")
            )
            + "`<br>tests `"
            + _markdown_code(", ".join(str(item) for item in tests[:3]) or "none")
            + "` | **"
            + _markdown_text(
                ", ".join(str(item) for item in owners[:3]) or "Unassigned"
            )
            + "**<br>"
            + _markdown_text(
                str(value.get("recommended_action") or "Review the compound scope.")
            )
            + " |"
        )
    if len(values) > 10:
        lines.extend(
            [
                "",
                f"{len(values) - 10} additional retained compound intersection(s) are available in `risk-paths.json`.",
            ]
        )
    return lines


def _render_dependency_route_table(routes: list[Any]) -> list[str]:
    if not routes:
        return []
    lines = [
        "",
        "### Routed dependency-advisory imports",
        "",
        "These routes join deduplicated advisory clusters to exact source importers and declared entry points. They prioritize vulnerable-function review but do not prove vulnerable-function invocation, attacker control, or exploitability.",
        "",
        "| Priority / advisory | Import exposure | Threat / fix | Validation | Citation / action |",
        "|---|---|---|---|---|",
    ]
    lines.extend(
        _render_dependency_route_row(route)
        for route in routes[:10]
        if isinstance(route, dict)
    )
    return lines


def _render_exposure_advisory_intersections(values: list[Any]) -> list[str]:
    if not values:
        return []
    lines = [
        "",
        "### Sensitive-boundary dependency intersections",
        "",
        "These records require the same exact source path, SDK package, and advisory cluster on a sensitive sink route and a dependency-importer route. They identify compound review scope; they do not prove sensitive data reached the SDK, leaked, or exercised a vulnerable function.",
        "",
        "| Priority / boundary | SDK advisory | Protection / threat | Validation | Owner / action |",
        "|---|---|---|---|---|",
    ]
    for value in values[:10]:
        if not isinstance(value, dict):
            continue
        statuses = value.get("validation_statuses")
        statuses = statuses if isinstance(statuses, dict) else {}
        assurance_statuses = value.get("evidence_assurance_statuses")
        assurance_statuses = (
            assurance_statuses if isinstance(assurance_statuses, dict) else {}
        )
        owners = value.get("owners")
        owner_text = (
            ", ".join(str(item) for item in owners[:3])
            if isinstance(owners, list) and owners
            else "Unassigned"
        )
        citations = _risk_advisory_citations_text(value.get("advisory_citations"))
        threat = []
        if value.get("known_exploited") is True:
            threat.append("CISA KEV")
        if value.get("epss_high") is True:
            threat.append("high EPSS")
        if value.get("fix_available") is True:
            threat.append("fix available")
        lifecycle_text = _package_lifecycle_text(value.get("package_lifecycle"))
        entry_runtime = _entry_runtime_status_text(
            value.get("entry_point_runtime_statuses")
        )
        lines.append(
            "| `"
            + _markdown_code(str(value.get("priority") or "P4"))
            + "` `"
            + _markdown_code(str(value.get("path") or "unknown"))
            + (":" + str(value["line"]) if value.get("line") else "")
            + "`<br>boundary `"
            + _markdown_code(str(value.get("trust_boundary") or "unknown"))
            + "`; sink `"
            + _markdown_code(str(value.get("sink_family") or "unknown"))
            + "` | `"
            + _markdown_code(str(value.get("package") or "unknown"))
            + "` / `"
            + _markdown_code(str(value.get("primary_identifier") or "unknown-advisory"))
            + "`<br>SDK `"
            + _markdown_code(str(value.get("sdk") or "unknown"))
            + "`"
            + ("<br>" + citations if citations else "")
            + " | protection `"
            + _markdown_code(str(value.get("protection_status") or "unknown"))
            + "`<br>"
            + _markdown_text(", ".join(threat) or "no elevated threat signal retained")
            + "<br>"
            + _markdown_text(lifecycle_text)
            + "<br>entry exposure `"
            + _markdown_code(str(int(value.get("entry_point_exposure_count") or 0)))
            + "` declared route(s); "
            + _markdown_text(entry_runtime)
            + " | sink / dependency `"
            + _markdown_code(str(statuses.get("sink") or "not-assessed"))
            + "/"
            + _markdown_code(str(statuses.get("dependency") or "not-assessed"))
            + "`<br>evidence `"
            + _markdown_code(str(assurance_statuses.get("sink") or "not-assessed"))
            + "/"
            + _markdown_code(
                str(assurance_statuses.get("dependency") or "not-assessed")
            )
            + "` | **"
            + _markdown_text(owner_text)
            + "**<br>"
            + _markdown_text(
                str(value.get("recommended_action") or "Review the intersection.")
            )
            + " |"
        )
    return lines


def _render_risk_owner_queues(queues: list[Any]) -> list[str]:
    if not queues:
        return []
    lines = [
        "",
        "### Route owner queues",
        "",
        "| Owner | Priority | Routes / targets | Controls / campaigns / shared tests / boundary intersections / multi-entry | Validation / campaign review | Next action |",
        "|---|---|---:|---:|---|---|",
    ]
    for queue in queues[:10]:
        if not isinstance(queue, dict):
            continue
        validation = queue.get("validation_statuses")
        validation = validation if isinstance(validation, dict) else {}
        assurance = queue.get("evidence_assurance_statuses")
        assurance = assurance if isinstance(assurance, dict) else {}
        lines.append(
            "| **"
            + _markdown_text(str(queue.get("owner") or "Unassigned"))
            + "**<br>`"
            + _markdown_code(str(queue.get("queue_id") or "unknown"))
            + "` | `"
            + _markdown_code(str(queue.get("priority") or "P4"))
            + "` | "
            + str(int(queue.get("routes") or 0))
            + " / "
            + str(int(queue.get("targets") or 0))
            + " | "
            + str(len(queue.get("convergence_hotspot_ids") or []))
            + " / "
            + str(len(queue.get("validation_campaign_ids") or []))
            + " / "
            + str(int(queue.get("shared_validation_test_files") or 0))
            + " / "
            + str(int(queue.get("exposure_advisory_intersections") or 0))
            + "; multi-entry routes `"
            + _markdown_code(str(int(queue.get("multi_entry_routes") or 0)))
            + "`<br>interface runtime "
            + _markdown_text(
                _entry_runtime_status_text(queue.get("entry_point_runtime_statuses"))
            )
            + " | "
            + _markdown_text(_validation_count_summary(validation))
            + "<br>evidence assured/perspective/trust/execution/unassessed/derived `"
            + _markdown_code(
                "/".join(
                    str(int(assurance.get(status) or 0))
                    for status in (
                        "assured",
                        "perspective-gap",
                        "trust-gap",
                        "execution-gap",
                        "not-assessed",
                        "derived-analysis",
                    )
                )
            )
            + "`"
            + "<br>lifecycle changed new/regressed/gapped `"
            + _markdown_code(
                str(int(queue.get("baseline_new_or_regressed_changed_routes") or 0))
                + "/"
                + str(
                    int(
                        queue.get(
                            "baseline_new_or_regressed_changed_routes_with_validation_gaps"
                        )
                        or 0
                    )
                )
            )
            + "`; changed existing/unassessed `"
            + _markdown_code(
                str(int(queue.get("existing_finding_routes_at_changed_lines") or 0))
                + "/"
                + str(
                    int(queue.get("routes_without_comparable_finding_lifecycle") or 0)
                )
            )
            + "`"
            + "<br>ownership handoffs/unowned/gaps `"
            + _markdown_code(
                str(int(queue.get("ownership_boundaries") or 0))
                + "/"
                + str(len(queue.get("unowned_route_files") or []))
                + "/"
                + str(int(queue.get("routes_without_ownership_evidence") or 0))
            )
            + "`; collaborators `"
            + _markdown_code(
                ", ".join(
                    str(item) for item in queue.get("collaborating_owners", [])[:5]
                )
                or "none"
            )
            + "`"
            + "<br>highest campaign score `"
            + _markdown_code(str(int(queue.get("highest_campaign_review_score") or 0)))
            + "`; mismatch/unverified/unbound `"
            + _markdown_code(
                str(int(queue.get("campaigns_revision_mismatched") or 0))
                + "/"
                + str(int(queue.get("campaigns_revision_unverified") or 0))
                + "/"
                + str(int(queue.get("campaigns_revision_unbound") or 0))
            )
            + "`; route-assurance blocked/trust/execution `"
            + _markdown_code(
                str(int(queue.get("campaigns_blocked_by_route_assurance") or 0))
                + "/"
                + str(int(queue.get("campaigns_with_route_trust_gaps") or 0))
                + "/"
                + str(int(queue.get("campaigns_with_route_execution_gaps") or 0))
            )
            + "`; shared-test qualified/weak/findings `"
            + _markdown_code(
                str(
                    int(queue.get("campaigns_with_qualified_shared_test_evidence") or 0)
                )
                + "/"
                + str(int(queue.get("campaigns_with_weak_shared_test_evidence") or 0))
                + "/"
                + str(len(queue.get("shared_test_file_finding_ids") or []))
            )
            + "`; changed/runtime gaps `"
            + _markdown_code(
                str(int(queue.get("campaigns_with_uncovered_changed_lines") or 0))
                + "/"
                + str(int(queue.get("campaigns_with_runtime_observation_gaps") or 0))
            )
            + "` | "
            + _markdown_text(
                str(queue.get("recommended_action") or "Review the queue.")
            )
            + " |"
        )
    return lines


def _render_dependency_route_row(route: dict[str, Any]) -> str:
    target = route.get("target")
    correlations = route.get("correlations")
    validation = route.get("validation")
    runtime = route.get("runtime_context")
    target = target if isinstance(target, dict) else {}
    correlations = correlations if isinstance(correlations, dict) else {}
    validation = validation if isinstance(validation, dict) else {}
    runtime = runtime if isinstance(runtime, dict) else {}
    versions = correlations.get("versions")
    version_text = (
        ", ".join(str(item) for item in versions[:5])
        if isinstance(versions, list) and versions
        else "unknown"
    )
    fixed = correlations.get("fixed_version_candidates")
    fixed_text = (
        ", ".join(str(item) for item in fixed[:5])
        if isinstance(fixed, list) and fixed
        else "not retained"
    )
    citations = _risk_advisory_citations_text(correlations.get("advisory_citations"))
    lifecycle_text = _package_lifecycle_text(correlations.get("package_lifecycle"))
    threat_signals = []
    if correlations.get("known_exploited") is True:
        threat_signals.append("CISA KEV")
    if correlations.get("epss_high") is True:
        probability = correlations.get("epss_probability")
        threat_signals.append(
            "high EPSS"
            + (
                f" {float(probability):.1%}"
                if isinstance(probability, (int, float))
                else ""
            )
        )
    threat_text = ", ".join(threat_signals) or "no elevated signal retained"
    change_signals = []
    if isinstance(correlations.get("change_risk_score"), int):
        change_signals.append(
            "change risk "
            + str(int(correlations["change_risk_score"]))
            + (
                f" ({correlations['change_priority']})"
                if correlations.get("change_priority")
                else ""
            )
        )
    uncovered_changed = correlations.get("uncovered_changed_lines")
    if isinstance(uncovered_changed, list) and uncovered_changed:
        change_signals.append(
            "uncovered changed lines "
            + ", ".join(str(line) for line in uncovered_changed[:10])
        )
    import_lines = correlations.get("import_lines")
    import_line_text = (
        ", ".join(str(line) for line in import_lines[:10])
        if isinstance(import_lines, list) and import_lines
        else "not retained"
    )
    return (
        "| `"
        + _markdown_code(str(route.get("priority") or "P4"))
        + "` `"
        + _markdown_code(str(correlations.get("primary_identifier") or "advisory"))
        + "`<br>"
        + _markdown_text(str(correlations.get("package") or "unknown"))
        + " `"
        + _markdown_code(version_text)
        + "` | `"
        + _markdown_code(str(target.get("path") or "unknown"))
        + "`<br>relationship `"
        + _markdown_code(str(correlations.get("source_relationship") or "unknown"))
        + "`; usage `"
        + _markdown_code(
            str(correlations.get("dependency_usage_assessment") or "unknown")
        )
        + "`; import lines `"
        + _markdown_code(import_line_text)
        + "`; hops `"
        + _markdown_code(str(int(route.get("hop_count") or 0)))
        + "`<br>"
        + _markdown_text(_entry_point_exposure_text(route))
        + " | "
        + _markdown_text(threat_text)
        + "<br>fix `"
        + _markdown_code(
            "available" if correlations.get("fix_available") else "unknown"
        )
        + "`: "
        + _markdown_text(fixed_text)
        + "<br>"
        + _markdown_text(lifecycle_text)
        + " | "
        + _markdown_text(_risk_path_validation_signals(validation, runtime))
        + "<br>evidence "
        + _markdown_text(_evidence_assurance_text(route.get("evidence_assurance")))
        + ("<br>" + _markdown_text("; ".join(change_signals)) if change_signals else "")
        + " | "
        + (citations + "<br>" if citations else "")
        + _markdown_text(
            str(route.get("recommended_action") or "Review dependency use.")
        )
        + " |"
    )


def _validation_count_summary(value: dict[str, Any]) -> str:
    labels = (
        ("gap", "gap"),
        ("not-assessed", "not assessed"),
        ("partial", "partial"),
        ("aligned", "aligned"),
    )
    parts = [
        f"{int(value.get(key) or 0)} {label}"
        for key, label in labels
        if int(value.get(key) or 0)
    ]
    return ", ".join(parts) or "no retained assessment"


def _route_applicability_membership_text(value: dict[str, Any]) -> str:
    def state(key: str) -> str:
        member = value.get(key)
        return "yes" if member is True else "no" if member is False else "n/a"

    return "/".join(
        state(key)
        for key in (
            "graph_path_member",
            "source_inventory_member",
            "artifact_manifest_member",
        )
    )


def _render_risk_routes_table(routes: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    if routes:
        lines.extend(
            [
                "| Priority / target | Entry point and bounded route | Runtime / validation | Owner and action |",
                "|---|---|---|---|",
            ]
        )
        for route in routes[:10]:
            if not isinstance(route, dict):
                continue
            target = route.get("target")
            entry = route.get("entry_point")
            validation = route.get("validation")
            runtime = route.get("runtime_context")
            assurance = route.get("evidence_assurance")
            lifecycle = route.get("change_lifecycle_attribution")
            ownership = route.get("ownership_context")
            target = target if isinstance(target, dict) else {}
            entry = entry if isinstance(entry, dict) else {}
            validation = validation if isinstance(validation, dict) else {}
            runtime = runtime if isinstance(runtime, dict) else {}
            files = route.get("files")
            file_values = files if isinstance(files, list) else []
            route_text = " → ".join((str(item) for item in file_values[:5]))
            if len(file_values) > 5:
                route_text += f" → … (+{len(file_values) - 5})"
            signals = _risk_path_validation_signals(validation, runtime)
            owners = route.get("owners")
            owner_text = (
                ", ".join((str(item) for item in owners[:3]))
                if isinstance(owners, list) and owners
                else "Unassigned"
            )
            lines.append(
                "| `"
                + _markdown_code(str(route.get("priority") or "P4"))
                + "` "
                + _markdown_text(
                    str(target.get("label") or target.get("id") or "target")
                )
                + "<br>`"
                + _markdown_code(
                    str(target.get("path") or "unknown")
                    + (f":{target['line']}" if target.get("line") else "")
                )
                + "` | `"
                + _markdown_code(
                    str(entry.get("declared_as") or entry.get("id") or "unknown")
                )
                + "`<br>"
                + _markdown_text(route_text or "same-file entry point")
                + "<br>"
                + _markdown_text(_entry_point_exposure_text(route))
                + " | "
                + _markdown_text(signals)
                + "<br>evidence "
                + _markdown_text(_evidence_assurance_text(assurance))
                + "<br>lifecycle "
                + _markdown_text(_change_lifecycle_text(lifecycle))
                + "<br>ownership "
                + _markdown_text(_route_ownership_text(ownership))
                + " | **"
                + _markdown_text(owner_text)
                + "**<br>"
                + _markdown_text(
                    str(route.get("recommended_action") or "Review the route.")
                )
                + " |"
            )
    return lines


def _render_risk_test_hotspots_table(test_hotspots: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    if test_hotspots:
        lines.extend(
            [
                "",
                "### Shared validation-test hotspots",
                "",
                "These test files are selected by multiple shared-control campaigns. Concentration coordinates regression work but does not prove independent assertions or sufficient coverage.",
                "",
                "| Review / test | Campaigns / controls / routes | Selection / dependency | Execution / source | Owners / action |",
                "|---|---:|---|---|---|",
            ]
        )
        for hotspot in test_hotspots[:10]:
            if not isinstance(hotspot, dict):
                continue
            owners = hotspot.get("owners")
            owner_text = (
                ", ".join((str(owner) for owner in owners[:3]))
                if isinstance(owners, list) and owners
                else "Unassigned"
            )
            test_owners = hotspot.get("test_file_owners")
            test_owner_text = (
                ", ".join((str(owner) for owner in test_owners[:3]))
                if isinstance(test_owners, list) and test_owners
                else "Unassigned"
            )
            statuses = hotspot.get("execution_statuses")
            status_text = (
                ", ".join((str(status) for status in statuses[:5]))
                if isinstance(statuses, list) and statuses
                else "not observed"
            )
            binding = hotspot.get("source_binding")
            source_text = (
                "bound"
                if isinstance(binding, dict)
                and hotspot.get("source_binding_consistent") is True
                else "not established"
                if hotspot.get("source_binding_consistent") is False
                else "not bound"
            )
            lines.append(
                "| `"
                + _markdown_code(str(hotspot.get("highest_review_tier") or "low"))
                + "` score `"
                + _markdown_code(str(int(hotspot.get("highest_review_score") or 0)))
                + "`<br>`"
                + _markdown_code(str(hotspot.get("test_path") or "unknown"))
                + "`<br>`"
                + _markdown_code(str(hotspot.get("test_hotspot_id") or "unknown"))
                + "` | "
                + str(len(hotspot.get("campaign_ids") or []))
                + " / "
                + str(len(hotspot.get("control_point_paths") or []))
                + " / "
                + str(len(hotspot.get("route_ids") or []))
                + " | direct/transitive/context `"
                + _markdown_code(
                    str(int(hotspot.get("direct_campaigns") or 0))
                    + "/"
                    + str(int(hotspot.get("transitive_campaigns") or 0))
                    + "/"
                    + str(int(hotspot.get("route_mapped_campaigns") or 0))
                )
                + "`<br>sole dependency `"
                + _markdown_code(
                    str(len(hotspot.get("single_test_dependency_campaign_ids") or []))
                )
                + "` | status `"
                + _markdown_code(status_text)
                + "`; cases `"
                + _markdown_code(str(int(hotspot.get("observed_case_count") or 0)))
                + "`<br>source `"
                + _markdown_code(source_text)
                + "`<br>quality `"
                + _markdown_code(
                    str(
                        hotspot.get("validation_quality_assessment")
                        or "not-established"
                    )
                )
                + "`; test findings `"
                + _markdown_code(str(len(hotspot.get("test_file_finding_ids") or [])))
                + "` | **"
                + _markdown_text(owner_text)
                + "** campaign<br>**"
                + _markdown_text(test_owner_text)
                + "** test (`"
                + _markdown_code(
                    str(hotspot.get("test_owner_alignment") or "not-established")
                )
                + "`)<br>"
                + _markdown_text(
                    str(
                        hotspot.get("recommended_action") or "Review shared test scope."
                    )
                )
                + " |"
            )
    return lines


def _render_risk_campaigns_table(campaigns: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    if campaigns:
        lines.extend(
            [
                "",
                "### Shared validation campaigns",
                "",
                "Each campaign converts one shared control point into a bounded regression plan. Test selection is static context; even passing tests with complete retained coverage do not prove security or exploitability.",
                "",
                "| Review / campaign | Selected tests | Execution / coverage | Evidence coherence | Owners / action |",
                "|---|---|---|---|---|",
            ]
        )
        for campaign in campaigns[:10]:
            if not isinstance(campaign, dict):
                continue
            selected = campaign.get("selected_test_files")
            selected = selected if isinstance(selected, list) else []
            tests = ", ".join(
                (f"`{_markdown_code(str(path))}`" for path in selected[:5])
            )
            if len(selected) > 5:
                tests += f" (+{len(selected) - 5})"
            owners = campaign.get("owners")
            owner_text = (
                ", ".join((str(owner) for owner in owners[:3]))
                if isinstance(owners, list) and owners
                else "Unassigned"
            )
            coverage = campaign.get("coverage_percent")
            coverage_text = (
                f"{float(coverage):.1f}%"
                if isinstance(coverage, (int, float))
                else "not available"
            )
            snapshot = campaign.get("source_snapshot")
            snapshot = snapshot if isinstance(snapshot, dict) else {}
            revision = str(
                snapshot.get("evidence_revision_binding") or "not-established"
            )
            route_assurance_text = _campaign_route_assurance_text(campaign)
            context_text = _risk_campaign_control_text(campaign)
            factor_text = _risk_campaign_factor_text(campaign)
            lines.append(
                "| `"
                + _markdown_code(str(campaign.get("review_tier") or "low"))
                + "` score `"
                + _markdown_code(str(int(campaign.get("review_score") or 0)))
                + "`"
                + ("<br>factors " + _markdown_text(factor_text) if factor_text else "")
                + "<br>route priority `"
                + _markdown_code(str(campaign.get("priority") or "P4"))
                + "`<br>`"
                + _markdown_code(str(campaign.get("campaign_id") or "unknown"))
                + "`<br>`"
                + _markdown_code(str(campaign.get("path") or "unknown"))
                + "` | "
                + (tests or "No bounded test candidate")
                + "<br>selection `"
                + _markdown_code(
                    str(campaign.get("test_selection_confidence") or "not-available")
                )
                + "` | execution `"
                + _markdown_code(
                    str(
                        campaign.get("focused_test_validation_status")
                        or "not-available"
                    )
                )
                + "`<br>aggregate coverage `"
                + _markdown_code(
                    str(campaign.get("coverage_status") or "not-available")
                )
                + "` ("
                + coverage_text
                + ")<br>alignment `"
                + _markdown_code(
                    str(campaign.get("test_coverage_alignment") or "not-selected")
                )
                + "`"
                + ("<br>" + _markdown_text(context_text) if context_text else "")
                + " | revision `"
                + _markdown_code(revision)
                + "`<br>control bound `"
                + _markdown_code(
                    "yes" if snapshot.get("control_point_binding") else "no"
                )
                + "`; tests bound `"
                + _markdown_code(
                    str(int(snapshot.get("selected_test_files_bound") or 0))
                )
                + "`<br>route evidence "
                + _markdown_text(route_assurance_text)
                + "<br>shared tests "
                + _markdown_text(_campaign_shared_test_quality_text(campaign))
                + " | **"
                + _markdown_text(owner_text)
                + "**<br>"
                + _markdown_text(
                    str(campaign.get("recommended_action") or "Run the campaign.")
                )
                + " |"
            )
    return lines


def _render_risk_hotspots_table(hotspots: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    if hotspots:
        lines.extend(
            [
                "",
                "### Shared route control points",
                "",
                "These files occur on multiple distinct target routes. Review shared remediation and integration-test scope before creating duplicate work.",
                "",
                "| Priority / control point | Role | Routes / targets | Owners | Validation | Consolidated action |",
                "|---|---|---:|---|---|---|",
            ]
        )
        for hotspot in hotspots[:10]:
            if not isinstance(hotspot, dict):
                continue
            validation = hotspot.get("validation_statuses")
            validation = validation if isinstance(validation, dict) else {}
            owners = hotspot.get("owners")
            owner_text = (
                ", ".join((str(item) for item in owners[:3]))
                if isinstance(owners, list) and owners
                else "Unassigned"
            )
            lines.append(
                "| `"
                + _markdown_code(str(hotspot.get("priority") or "P4"))
                + "` `"
                + _markdown_code(str(hotspot.get("path") or "unknown"))
                + "`<br>`"
                + _markdown_code(str(hotspot.get("hotspot_id") or "unknown"))
                + "` | `"
                + _markdown_code(str(hotspot.get("kind") or "unknown"))
                + "` | "
                + str(len(hotspot.get("route_ids") or []))
                + " / "
                + str(len(hotspot.get("target_ids") or []))
                + " | "
                + _markdown_text(owner_text)
                + " | "
                + _markdown_text(_validation_count_summary(validation))
                + " | "
                + _markdown_text(
                    str(hotspot.get("recommended_action") or "Review shared scope.")
                )
                + " |"
            )
    return lines


def _render_risk_unrouted_table(unrouted: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    if unrouted:
        lines.extend(
            [
                "",
                "### Unrouted target dispositions",
                "",
                "Only Python runtime-source targets are reachability gaps. Artifact controls, generated evidence, tests, and non-Python repository controls retain their findings but receive their native evidence-lane action instead of misleading entry-point advice.",
                "",
                "| Applicability | Target | Evidence | Action |",
                "|---|---|---|---|",
            ]
        )
        for item in unrouted[:10]:
            if not isinstance(item, dict):
                continue
            target = item.get("target")
            target = target if isinstance(target, dict) else {}
            applicability = item.get("route_applicability")
            applicability = applicability if isinstance(applicability, dict) else {}
            lines.append(
                "| `"
                + _markdown_code(
                    str(applicability.get("assessment") or "not-established")
                )
                + "`<br>`"
                + _markdown_code(
                    str(applicability.get("classification") or "not-established")
                )
                + "` | `"
                + _markdown_code(str(item.get("priority") or "P4"))
                + "` `"
                + _markdown_code(str(target.get("path") or "unknown"))
                + "`<br>"
                + _markdown_text(str(item.get("reason") or "route unavailable"))
                + " | graph/source/artifact `"
                + _markdown_code(_route_applicability_membership_text(applicability))
                + "`<br>scanner "
                + _markdown_text(
                    _evidence_assurance_text(item.get("evidence_assurance"))
                )
                + " | "
                + _markdown_text(
                    str(
                        item.get("recommended_action")
                        or applicability.get("recommended_action")
                        or "Review the target in its native evidence lane."
                    )
                )
                + " |"
            )
    return lines
