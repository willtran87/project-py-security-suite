from __future__ import annotations

from collections import defaultdict
from typing import Any

from .risk_path_values import _object, _strings
from .models import Finding, FindingStatus
from .prioritization import finding_priority
from .risk_path_common import (
    _MAX_SENSITIVE_ROUTE_CITATIONS,
    _citation_records,
    _digest,
    _optional_string,
    _path,
    _positive_integer,
    _priority_rank,
)
from .risk_path_dependencies import _surface_dependency_advisories
from .risk_path_evidence import _finding_correlations, _finding_evidence_artifacts
from .risk_path_lifecycle import _bounded_baseline_match
from .risk_path_validation import (
    _runtime_context,
    _surface_validation,
    _validation_context,
)


__all__ = [
    "_convergence_hotspots",
    "_finding_targets",
    "_sink_surface_targets",
]


_SENSITIVE_ROUTE_STANDARD_IDS = {
    "analytics": ("CWE-201", "OTEL-SENSITIVE-DATA"),
    "client-response": ("CWE-209",),
    "error-monitoring": ("CWE-201", "OTEL-SENSITIVE-DATA"),
    "exception": ("CWE-209",),
    "logging": ("CWE-532", "OWASP-LOGGING"),
    "metrics": ("CWE-201", "OTEL-SENSITIVE-DATA"),
    "network-egress": ("CWE-201",),
    "observability": ("CWE-201", "OTEL-SENSITIVE-DATA"),
    "telemetry": ("CWE-201", "OTEL-SENSITIVE-DATA"),
    "url": ("CWE-598",),
    "url-query": ("CWE-598",),
}


def _finding_targets(findings: list[Finding]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for finding in findings:
        if finding.status is FindingStatus.SUPPRESSED or not finding.locations:
            continue
        location = finding.locations[0]
        path = _path(location.path)
        if not path or path in {".", "<outside-target>"}:
            continue
        fusion = _object(finding.evidence.get("fusion"))
        source = _object(fusion.get("source_context"))
        structural = _object(finding.evidence.get("structural_synthesis"))
        exposure = _object(finding.evidence.get("data_exposure"))
        validation = _validation_context(source, structural, exposure)
        result.append(
            {
                "kind": "finding",
                "id": finding.finding_id,
                "finding_id": finding.finding_id,
                "path": path,
                "line": location.start_line,
                "label": finding.title[:1000],
                "domain": finding.domain,
                "area": finding.area,
                "severity": finding.severity.value,
                "lifecycle_status": finding.status.value,
                "baseline_match": _bounded_baseline_match(
                    finding.evidence.get("baseline")
                ),
                "priority": finding_priority(
                    severity=finding.severity.value,
                    classifications=finding.classifications,
                    evidence=finding.evidence,
                ),
                "tools": sorted({source.tool for source in finding.sources})[:25],
                "classifications": sorted(set(finding.classifications))[:50],
                "owners": _strings(finding.evidence.get("owners"), 20),
                "runtime_context": _runtime_context(source, structural),
                "validation": validation,
                "correlations": _finding_correlations(
                    finding, fusion, structural, exposure
                ),
                "recommended_action": _recommended_action(
                    finding.remediation, validation, exposure
                ),
                "evidence_artifacts": _finding_evidence_artifacts(
                    finding, fusion, structural, exposure
                ),
            }
        )
    return result


def _sink_surface_targets(value: Any) -> list[dict[str, Any]]:
    surfaces = value.get("sink_surfaces") if isinstance(value, dict) else None
    if not isinstance(surfaces, list):
        return []
    standards = _citation_records(
        value.get("standards") if isinstance(value, dict) else None,
        limit=25,
        default_kind="standard",
    )
    result: list[dict[str, Any]] = []
    for surface in surfaces:
        if not isinstance(surface, dict) or surface.get("scope") != "production":
            continue
        structural = _object(surface.get("structural_context"))
        if not _review_worthy_surface(surface, structural):
            continue
        path = _path(surface.get("path"))
        if not path:
            continue
        line = _positive_integer(surface.get("line"))
        label = str(surface.get("label") or surface.get("sink_family") or "sink")
        sink_family = str(surface.get("sink_family") or "unknown")[:100]
        identifier = (
            "surface-" + _digest({"path": path, "line": line, "label": label})[:16]
        )
        priority = {
            "high": "P1",
            "medium": "P2",
            "low": "P3",
        }.get(str(surface.get("review_priority") or "medium"), "P2")
        validation = _surface_validation(structural)
        dependency = _object(surface.get("sdk_dependency_context"))
        exact_advisories = _surface_dependency_advisories(dependency, path)
        result.append(
            {
                "kind": "sink-surface",
                "id": identifier,
                "finding_id": None,
                "path": path,
                "line": line,
                "label": label[:1000],
                "domain": "security",
                "area": "data-exposure",
                "severity": None,
                "priority": priority,
                "tools": ["pysec-data-exposure"],
                "classifications": _surface_classifications(surface),
                "owners": _strings(structural.get("owners"), 20),
                "runtime_context": {
                    "reachability_states": _strings(
                        structural.get("reachability_states"), 10
                    ),
                    "observations": _strings(
                        structural.get("runtime_observations"), 10
                    ),
                },
                "validation": validation,
                "correlations": {
                    "related_finding_ids": _strings(
                        structural.get("related_finding_ids"), 50
                    ),
                    "related_tools": _strings(structural.get("related_tools"), 25),
                    "structural_risk_ids": _strings(
                        structural.get("structural_risk_ids"), 25
                    ),
                    "sink_family": sink_family,
                    "data_classes": _strings(surface.get("data_classes"), 25),
                    "protection_status": str(
                        surface.get("protection_status") or "unknown"
                    )[:100],
                    "trust_boundary": str(surface.get("trust_boundary") or "unknown")[
                        :100
                    ],
                    "sdk": _optional_string(surface.get("sdk")),
                    "sdk_package_risk": dependency.get("risk_present") is True,
                    "sdk_risk_tier": _optional_string(dependency.get("risk_tier")),
                    "exact_path_sdk_advisories": exact_advisories,
                    "citations": _sensitive_route_standard_citations(
                        standards, sink_family
                    ),
                },
                "recommended_action": _surface_action(surface, structural),
                "evidence_artifacts": sorted(
                    {
                        "data-exposure.json",
                        *(
                            ["structural-synthesis.json"]
                            if structural.get("context_available")
                            else []
                        ),
                    }
                ),
            }
        )
    return result


def _sensitive_route_standard_citations(
    standards: list[dict[str, str | None]], sink_family: str
) -> list[dict[str, str | None]]:
    identifiers = set(_SENSITIVE_ROUTE_STANDARD_IDS.get(sink_family.casefold(), ()))
    return [
        citation
        for citation in standards
        if str(citation.get("identifier") or "") in identifiers
    ][:_MAX_SENSITIVE_ROUTE_CITATIONS]


def _convergence_hotspots(routes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_path: dict[str, list[tuple[dict[str, Any], str]]] = defaultdict(list)
    for route in routes:
        files = route["files"]
        for index, path in enumerate(files):
            if index == 0:
                continue
            role = "target" if index == len(files) - 1 else "transit"
            by_path[path].append((route, role))
    result: list[dict[str, Any]] = []
    for path, observations in by_path.items():
        route_ids = sorted({route["route_id"] for route, _role in observations})
        target_ids = sorted(
            {str(route["target"]["id"]) for route, _role in observations}
        )
        if len(route_ids) < 2 or len(target_ids) < 2:
            continue
        roles = {role for _route, role in observations}
        kind = (
            "target-concentration"
            if roles == {"target"}
            else "shared-transit"
            if roles == {"transit"}
            else "mixed"
        )
        validation_counts = {
            status: sum(
                route["validation"]["assessment_status"] == status
                for route, _role in observations
            )
            for status in ("aligned", "gap", "partial", "not-assessed")
        }
        priorities = sorted(
            {str(route["priority"]) for route, _role in observations},
            key=_priority_rank,
        )
        hotspot_id = (
            "hotspot-" + _digest({"path": path, "routes": route_ids, "kind": kind})[:16]
        )
        result.append(
            {
                "hotspot_id": hotspot_id,
                "path": path,
                "kind": kind,
                "priority": priorities[0] if priorities else "P4",
                "route_ids": route_ids,
                "target_ids": target_ids,
                "finding_ids": sorted(
                    {
                        str(finding_id)
                        for route, _role in observations
                        for finding_id in [
                            route["target"].get("finding_id"),
                            *(
                                _strings(
                                    route["correlations"].get("related_finding_ids"),
                                    100,
                                )
                                if route["target"].get("kind")
                                == "dependency-advisory-import"
                                else []
                            ),
                        ]
                        if finding_id
                    }
                ),
                "entry_point_ids": sorted(
                    {str(route["entry_point"]["id"]) for route, _role in observations}
                ),
                "tools": sorted(
                    {
                        str(tool)
                        for route, _role in observations
                        for tool in route["target"]["tools"]
                    }
                )[:25],
                "target_domains": sorted(
                    {str(route["target"]["domain"]) for route, _role in observations}
                )[:25],
                "security_target_count": sum(
                    route["target"]["domain"] in {"security", "supply-chain"}
                    for route, _role in observations
                ),
                "owners": sorted(
                    {
                        str(owner)
                        for route, _role in observations
                        for owner in route["owners"]
                    }
                )[:20],
                "validation_statuses": validation_counts,
                "mapped_test_files": sorted(
                    {
                        str(test)
                        for route, _role in observations
                        for test in route["validation"]["mapped_test_files"]
                    }
                )[:50],
                "evidence_artifacts": sorted(
                    {
                        str(artifact)
                        for route, _role in observations
                        for artifact in route["evidence_artifacts"]
                    }
                ),
                "recommended_action": _hotspot_action(
                    path, len(route_ids), validation_counts, observations
                ),
            }
        )
    result.sort(
        key=lambda item: (
            _priority_rank(str(item["priority"])),
            -len(item["route_ids"]),
            -len(item["target_ids"]),
            str(item["path"]),
        )
    )
    return result


def _hotspot_action(
    path: str,
    route_count: int,
    validation: dict[str, int],
    observations: list[tuple[dict[str, Any], str]],
) -> str:
    if validation["gap"]:
        return (
            f"Close the {validation['gap']} route validation gap(s) at {path} with "
            "one focused integration-test plan that exercises every affected target."
        )
    if validation["not-assessed"] or validation["partial"]:
        return (
            f"Retain change scope, line coverage, and focused-test execution for all "
            f"{route_count} routes through {path}, then assess them together."
        )
    security_targets = sum(
        route["target"]["domain"] in {"security", "supply-chain"}
        for route, _role in observations
    )
    if security_targets:
        return (
            f"Review {path} as a shared security control point and rerun the mapped "
            "tests for every affected route after remediation."
        )
    return (
        f"Coordinate remediation at {path} and use the shared route set to avoid "
        "duplicated regression testing."
    )


def _recommended_action(
    remediation: str, validation: dict[str, Any], exposure: dict[str, Any]
) -> str:
    if exposure:
        protection = str(exposure.get("protection_status") or "unknown")
        if protection in {"not-observed", "unknown"}:
            return (
                "Trace the concrete data classes across this static route, enforce "
                "allow-listing or redaction at the sink, then execute the mapped tests."
            )
    if validation.get("action"):
        return str(validation["action"])
    if not validation.get("mapped_test_files"):
        return (
            f"{remediation.rstrip()} Map focused tests to this entry-point route and "
            "retain their execution and coverage evidence."
        )[:2000]
    return remediation[:2000]


def _surface_action(surface: dict[str, Any], structural: dict[str, Any]) -> str:
    steps = _strings(surface.get("verification_steps"), 10)
    if structural.get("validation_action"):
        steps.append(str(structural["validation_action"]))
    if not steps:
        steps.append(
            "Trace concrete data classes across the route and verify filtering, redaction, and destination policy at the sink."
        )
    return " ".join(dict.fromkeys(steps))[:2000]


def _review_worthy_surface(surface: dict[str, Any], structural: dict[str, Any]) -> bool:
    return bool(
        surface.get("review_priority") == "high"
        or surface.get("data_classes")
        or structural.get("related_finding_ids")
        or _object(surface.get("sdk_dependency_context")).get("risk_present") is True
    )


def _surface_classifications(surface: dict[str, Any]) -> list[str]:
    family = str(surface.get("sink_family") or "unknown").upper().replace("_", "-")
    result = [f"SINK-{family}"]
    if surface.get("data_classes"):
        result.append("SENSITIVE-DATA-CONTEXT")
    if surface.get("protection_status") == "not-observed":
        result.append("PROTECTION-NOT-OBSERVED")
    return result
