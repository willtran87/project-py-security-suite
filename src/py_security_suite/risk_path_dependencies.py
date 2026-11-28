"""Dependency advisory routing, package lifecycle and exposure intersections."""

from __future__ import annotations

from typing import Any

from .risk_path_values import _object, _strings
from .risk_path_common import (
    _MAX_ADVISORY_IMPORT_PATHS,
    _MAX_CAMPAIGN_MISSING_LINES,
    _digest,
    _optional_number,
    _optional_string,
    _path,
    _positive_integers,
    _priority_rank,
)
from .risk_path_validation import _entry_runtime_counts


__all__ = [
    "_compact_dependency_advisory_route",
    "_compact_exposure_advisory_intersection",
    "_composition_evidence",
    "_dependency_advisory_action",
    "_dependency_advisory_classifications",
    "_dependency_advisory_validation",
    "_exposure_advisory_intersections",
    "_package_lifecycle_assessment",
    "_surface_dependency_advisories",
]


def _surface_dependency_advisories(
    dependency: dict[str, Any], path: str
) -> list[dict[str, Any]]:
    """Retain only advisory records whose exact importer ledger matches the sink."""
    if dependency.get("risk_present") is not True:
        return []
    raw_clusters = dependency.get("advisory_clusters")
    clusters = raw_clusters if isinstance(raw_clusters, list) else []
    result: list[dict[str, Any]] = []
    for cluster in clusters[:50]:
        if not isinstance(cluster, dict):
            continue
        usage = _object(cluster.get("dependency_usage"))
        raw_assessments = usage.get("import_path_assessments")
        assessments = raw_assessments if isinstance(raw_assessments, list) else []
        assessment = next(
            (
                item
                for item in assessments[:_MAX_ADVISORY_IMPORT_PATHS]
                if isinstance(item, dict) and _path(item.get("path")) == path
            ),
            None,
        )
        cluster_id = _optional_string(cluster.get("cluster_id"))
        package = _optional_string(cluster.get("package"))
        primary = _optional_string(cluster.get("primary_identifier"))
        if assessment is None or not cluster_id or not package or not primary:
            continue
        threat = _object(cluster.get("threat_context"))
        remediation = _object(cluster.get("remediation_context"))
        priority = str(remediation.get("priority") or "P4")
        if priority not in {"P0", "P1", "P2", "P3", "P4"}:
            priority = "P4"
        result.append(
            {
                "cluster_id": cluster_id,
                "primary_identifier": primary,
                "package": package,
                "finding_ids": _strings(cluster.get("finding_ids"), 100),
                "tools": _strings(cluster.get("tools"), 25),
                "known_exploited": threat.get("known_exploited") is True,
                "epss_high": threat.get("epss_high") is True,
                "fix_available": remediation.get("fix_available") is True,
                "priority": priority,
                "import_assessment": _optional_string(assessment.get("assessment")),
                "import_lines": _positive_integers(assessment.get("import_lines"), 100),
            }
        )
    return sorted(
        result,
        key=lambda item: (
            _priority_rank(str(item["priority"])),
            str(item["package"]),
            str(item["cluster_id"]),
        ),
    )[:50]


def _composition_evidence(value: dict[str, Any]) -> dict[str, Any]:
    raw_lanes = value.get("evidence_lanes")
    lanes = raw_lanes if isinstance(raw_lanes, list) else []
    by_name = {
        str(item.get("lane")): item
        for item in lanes
        if isinstance(item, dict) and item.get("lane")
    }
    source = _object(by_name.get("source_composition"))
    artifact = _object(by_name.get("artifact_composition"))
    source_artifacts = _strings(source.get("available_artifacts"), 25)
    artifact_artifacts = _strings(artifact.get("available_artifacts"), 25)
    return {
        "source_inventory_available": "sbom.cdx.json" in source_artifacts,
        "artifact_inventory_available": "artifact-sbom.cdx.json" in artifact_artifacts,
        "source_execution_gaps": _strings(source.get("execution_gaps"), 25),
        "artifact_execution_gaps": _strings(artifact.get("execution_gaps"), 25),
        "evidence_artifacts": sorted({*source_artifacts, *artifact_artifacts}),
    }


def _package_lifecycle_assessment(
    lineage: dict[str, Any] | None,
    composition: dict[str, Any],
    fixed_versions: list[str],
) -> dict[str, Any]:
    source_available = composition.get("source_inventory_available") is True
    artifact_available = composition.get("artifact_inventory_available") is True
    comparison_available = source_available and artifact_available
    status = str(lineage.get("status")) if lineage else "not-available"
    source_versions = _strings(lineage.get("source_versions"), 50) if lineage else []
    artifact_versions = (
        _strings(lineage.get("artifact_versions"), 50) if lineage else []
    )
    if comparison_available:
        assessment = status if lineage else "package-not-observed"
    elif source_available:
        assessment = "artifact-inventory-unavailable"
    elif artifact_available:
        assessment = "source-inventory-unavailable"
    else:
        assessment = "composition-inventories-unavailable"
    fixed_match = (
        bool(set(artifact_versions) & set(fixed_versions))
        if artifact_versions and fixed_versions
        else None
    )
    version_match = (
        status == "matched"
        if comparison_available and status in {"matched", "version-drift"}
        else None
    )
    return {
        "assessment": assessment,
        "lineage_status": status,
        "comparison_available": comparison_available,
        "source_inventory_available": source_available,
        "artifact_inventory_available": artifact_available,
        "source_versions": source_versions,
        "artifact_versions": artifact_versions,
        "source_artifact_versions_match": version_match,
        "artifact_fixed_version_exact_match": fixed_match,
        "finding_ids": _strings(lineage.get("finding_ids"), 100) if lineage else [],
        "source_execution_gaps": _strings(composition.get("source_execution_gaps"), 25),
        "artifact_execution_gaps": _strings(
            composition.get("artifact_execution_gaps"), 25
        ),
        "evidence_artifacts": _strings(composition.get("evidence_artifacts"), 10),
    }


def _dependency_advisory_validation(
    path: str,
    usage: dict[str, Any],
    coverage_by_path: dict[str, float | None],
    path_assessment: dict[str, Any],
) -> dict[str, Any]:
    exact = bool(path_assessment)
    alignment = _optional_string(
        path_assessment.get("test_coverage_alignment")
        if exact
        else usage.get("test_coverage_alignment")
    )
    uncovered = set(_strings(usage.get("uncovered_import_paths"), 50))
    gap_reasons = _strings(
        (
            path_assessment.get("validation_gap_reasons")
            if exact
            else usage.get("validation_gap_reasons")
        ),
        10,
    )
    if not exact and alignment == "coverage-gap" and path not in uncovered:
        alignment = None
        gap_reasons = [
            reason for reason in gap_reasons if "cover" not in reason.casefold()
        ]
    return {
        "changed_line": None,
        "line_covered": None,
        "coverage_percent": _optional_number(path_assessment.get("coverage_percent"))
        if exact
        else coverage_by_path.get(path),
        "mapped_test_files": _strings(
            (
                path_assessment.get("recommended_test_files")
                if exact
                else usage.get("recommended_test_files")
            ),
            25,
        ),
        "focused_test_status": _optional_string(
            path_assessment.get("focused_test_validation_status")
            if exact
            else usage.get("focused_test_validation_status")
        ),
        "coverage_alignment": alignment,
        "gap_reasons": gap_reasons,
        "action": (
            "Use this exact importer assessment; do not infer validation from other import paths."
            if exact
            else None
        ),
    }


def _dependency_advisory_classifications(
    identifiers: list[str], threat: dict[str, Any]
) -> list[str]:
    values = {"DEPENDENCY-ADVISORY", *identifiers}
    if threat.get("known_exploited") is True:
        values.add("CISA-KEV")
    if threat.get("epss_high") is True:
        values.add("EPSS-HIGH")
    vex = _optional_string(threat.get("vex_disposition"))
    if vex:
        values.add("VEX-" + vex.upper().replace("_", "-")[:100])
    return sorted(values)[:50]


def _dependency_advisory_action(
    package: str,
    primary: str,
    path: str,
    remediation: dict[str, Any],
    usage: dict[str, Any],
    lifecycle: dict[str, Any],
) -> str:
    action = str(remediation.get("recommended_action") or "").strip()
    if not action:
        action = (
            f"Review {primary} for {package}, establish vulnerable-function use, "
            "then upgrade, remove, mitigate, or record a governed VEX disposition."
        )
    tests = _strings(usage.get("recommended_test_files"), 5)
    if tests:
        action += " Re-run focused importer tests: " + ", ".join(tests) + "."
    else:
        action += f" Add a focused test that exercises dependency use from {path}."
    lifecycle_assessment = str(lifecycle.get("assessment") or "not-available")
    if lifecycle_assessment == "version-drift":
        action += (
            " Reconcile source and built-artifact versions, then verify remediation "
            "against the exact packaged component."
        )
    elif lifecycle_assessment == "artifact-only":
        action += (
            " Identify and govern the artifact-only introduction path before release."
        )
    elif lifecycle_assessment == "source-only":
        action += (
            " Verify the package is intentionally excluded from the complete built "
            "artifact inventory before treating source-only status as risk reduction."
        )
    elif lifecycle_assessment in {
        "source-inventory-unavailable",
        "artifact-inventory-unavailable",
        "composition-inventories-unavailable",
        "package-not-observed",
    }:
        action += (
            " Produce complete source and built-artifact composition evidence for "
            "this package before lifecycle disposition."
        )
    return action[:2000]


def _exposure_advisory_intersections(
    routes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Join exact-path SDK sink routes to the same advisory importer route."""
    dependency_routes = {
        (
            str(route["target"]["path"]),
            str(route["correlations"].get("advisory_cluster_id") or ""),
            str(route["correlations"].get("package") or ""),
        ): route
        for route in routes
        if route["target"].get("kind") == "dependency-advisory-import"
    }
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for sink_route in routes:
        if sink_route["target"].get("kind") != "sink-surface":
            continue
        path = str(sink_route["target"]["path"])
        raw_advisories = sink_route["correlations"].get("exact_path_sdk_advisories")
        advisories = raw_advisories if isinstance(raw_advisories, list) else []
        for advisory in advisories[:50]:
            if not isinstance(advisory, dict):
                continue
            cluster_id = str(advisory.get("cluster_id") or "")
            package = str(advisory.get("package") or "")
            dependency_route = dependency_routes.get((path, cluster_id, package))
            if dependency_route is None:
                continue
            pair = (
                str(sink_route["route_id"]),
                str(dependency_route["route_id"]),
            )
            if pair in seen:
                continue
            seen.add(pair)
            priorities = sorted(
                [str(sink_route["priority"]), str(dependency_route["priority"])],
                key=_priority_rank,
            )
            intersection_id = (
                "exposure-advisory-"
                + _digest(
                    {
                        "sink_route_id": pair[0],
                        "dependency_route_id": pair[1],
                        "cluster_id": cluster_id,
                    }
                )[:16]
            )
            owners = sorted(
                {
                    *_strings(sink_route.get("owners"), 20),
                    *_strings(dependency_route.get("owners"), 20),
                }
            )[:20]
            finding_ids = sorted(
                {
                    *_strings(
                        sink_route["correlations"].get("related_finding_ids"), 50
                    ),
                    *_strings(advisory.get("finding_ids"), 100),
                    *_strings(
                        dependency_route["correlations"].get("related_finding_ids"),
                        100,
                    ),
                }
            )[:100]
            entry_exposures = {
                str(exposure["exposure_id"]): exposure
                for route in (sink_route, dependency_route)
                for exposure in route["entry_point_exposures"]
            }
            result.append(
                {
                    "intersection_id": intersection_id,
                    "priority": priorities[0] if priorities else "P4",
                    "path": path,
                    "line": sink_route["target"].get("line"),
                    "route_ids": [pair[0], pair[1]],
                    "sink_route_id": pair[0],
                    "sink_target_id": str(sink_route["target"]["id"]),
                    "dependency_route_id": pair[1],
                    "dependency_target_id": str(dependency_route["target"]["id"]),
                    "advisory_cluster_id": cluster_id,
                    "primary_identifier": str(
                        dependency_route["correlations"].get("primary_identifier")
                        or cluster_id
                    ),
                    "package": package,
                    "sdk": _optional_string(sink_route["correlations"].get("sdk")),
                    "sink_family": str(
                        sink_route["correlations"].get("sink_family") or "unknown"
                    ),
                    "trust_boundary": str(
                        sink_route["correlations"].get("trust_boundary") or "unknown"
                    ),
                    "data_classes": _strings(
                        sink_route["correlations"].get("data_classes"), 25
                    ),
                    "protection_status": str(
                        sink_route["correlations"].get("protection_status") or "unknown"
                    ),
                    "finding_ids": finding_ids,
                    "tools": sorted(
                        {
                            *_strings(sink_route["target"].get("tools"), 25),
                            *_strings(dependency_route["target"].get("tools"), 25),
                        }
                    )[:25],
                    "owners": owners,
                    "known_exploited": dependency_route["correlations"].get(
                        "known_exploited"
                    )
                    is True,
                    "epss_high": dependency_route["correlations"].get("epss_high")
                    is True,
                    "fix_available": dependency_route["correlations"].get(
                        "fix_available"
                    )
                    is True,
                    "package_lifecycle": _object(
                        dependency_route["correlations"].get("package_lifecycle")
                    ),
                    "entry_point_exposure_ids": sorted(entry_exposures),
                    "entry_point_ids": sorted(
                        {
                            str(exposure["entry_point"]["id"])
                            for exposure in entry_exposures.values()
                        }
                    ),
                    "entry_point_exposure_count": len(
                        {
                            str(exposure["entry_point"]["id"])
                            for exposure in entry_exposures.values()
                        }
                    ),
                    "entry_point_exposures_omitted": max(
                        int(sink_route["entry_point_exposures_omitted"]),
                        int(dependency_route["entry_point_exposures_omitted"]),
                    ),
                    "entry_point_runtime_statuses": _entry_runtime_counts(
                        entry_exposures.values()
                    ),
                    "validation_statuses": {
                        "sink": str(
                            sink_route["validation"].get("assessment_status")
                            or "not-assessed"
                        ),
                        "dependency": str(
                            dependency_route["validation"].get("assessment_status")
                            or "not-assessed"
                        ),
                    },
                    "evidence_assurance_statuses": {
                        "sink": str(
                            sink_route["evidence_assurance"].get("review_status")
                            or "not-assessed"
                        ),
                        "dependency": str(
                            dependency_route["evidence_assurance"].get("review_status")
                            or "not-assessed"
                        ),
                    },
                    "advisory_citations": list(
                        dependency_route["correlations"].get("advisory_citations") or []
                    )[:25],
                    "evidence_artifacts": sorted(
                        {
                            "data-exposure.json",
                            "evidence-fusion.json",
                            "risk-paths.json",
                            *_strings(sink_route.get("evidence_artifacts"), 25),
                            *_strings(dependency_route.get("evidence_artifacts"), 25),
                        }
                    ),
                    "recommended_action": (
                        "Review the exact SDK sink/import path for sensitive-field "
                        "minimization and redaction, establish whether the advisory's "
                        "vulnerable function can process this boundary data, then apply "
                        "the retained dependency remediation and rerun both sink and "
                        "importer validation."
                    ),
                }
            )
    return sorted(
        result,
        key=lambda item: (
            _priority_rank(str(item["priority"])),
            str(item["path"]),
            int(item["line"] or 0),
            str(item["intersection_id"]),
        ),
    )


def _compact_dependency_advisory_route(
    route: dict[str, Any],
) -> dict[str, Any]:
    correlations = route["correlations"]
    target = route["target"]
    return {
        "route_id": route["route_id"],
        "target_id": target["id"],
        "priority": route["priority"],
        "advisory_cluster_id": correlations.get("advisory_cluster_id"),
        "primary_identifier": correlations.get("primary_identifier"),
        "package": correlations.get("package"),
        "versions": list(correlations.get("versions") or [])[:25],
        "import_path": target["path"],
        "import_modules": list(correlations.get("import_modules") or [])[:50],
        "import_lines": list(correlations.get("import_lines") or [])[:100],
        "dependency_usage_assessment": correlations.get("dependency_usage_assessment"),
        "import_path_assessment": correlations.get("import_path_assessment"),
        "entry_point": route["entry_point"],
        "entry_point_exposure_count": route["entry_point_exposure_count"],
        "entry_point_exposures": list(route["entry_point_exposures"]),
        "entry_point_exposures_omitted": route["entry_point_exposures_omitted"],
        "entry_point_kinds": list(route["entry_point_kinds"]),
        "entry_point_runtime_statuses": _entry_runtime_counts(
            route["entry_point_exposures"]
        ),
        "hop_count": route["hop_count"],
        "files": list(route["files"]),
        "runtime_context": route["runtime_context"],
        "validation": route["validation"],
        "evidence_assurance": route["evidence_assurance"],
        "route_applicability": route["route_applicability"],
        "ownership_context": route["ownership_context"],
        "validation_campaign_ids": list(route["validation_campaign_ids"]),
        "exposure_advisory_intersection_ids": list(
            route.get("exposure_advisory_intersection_ids") or []
        )[:100],
        "known_exploited": correlations.get("known_exploited") is True,
        "epss_probability": correlations.get("epss_probability"),
        "fix_available": correlations.get("fix_available") is True,
        "fixed_version_candidates": list(
            correlations.get("fixed_version_candidates") or []
        )[:25],
        "package_lifecycle": _object(correlations.get("package_lifecycle")),
        "change_risk_score": correlations.get("change_risk_score"),
        "change_priority": correlations.get("change_priority"),
        "uncovered_changed_lines": list(
            correlations.get("uncovered_changed_lines") or []
        )[:_MAX_CAMPAIGN_MISSING_LINES],
        "advisory_citations": list(correlations.get("advisory_citations") or [])[:25],
        "recommended_action": route["recommended_action"],
    }


def _compact_exposure_advisory_intersection(
    value: dict[str, Any],
) -> dict[str, Any]:
    return {
        key: value[key]
        for key in (
            "intersection_id",
            "priority",
            "path",
            "line",
            "sink_route_id",
            "dependency_route_id",
            "advisory_cluster_id",
            "primary_identifier",
            "package",
            "sdk",
            "sink_family",
            "trust_boundary",
            "data_classes",
            "protection_status",
            "known_exploited",
            "epss_high",
            "fix_available",
            "package_lifecycle",
            "entry_point_exposure_ids",
            "entry_point_ids",
            "entry_point_exposure_count",
            "entry_point_exposures_omitted",
            "entry_point_runtime_statuses",
            "evidence_assurance_statuses",
            "validation_statuses",
            "advisory_citations",
            "secret_exposure_advisory_intersection_ids",
            "secret_exposure_advisory_intersections",
            "secret_exposure_advisory_intersections_omitted",
            "recommended_action",
        )
    }
