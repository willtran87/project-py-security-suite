from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .advisory_fusion import build_advisory_clusters, refresh_advisory_decision
from .models import Finding, ToolRun, ToolStatus
from .ownership import owners_for_path, ownership_rules_from_artifact
from .validation_alignment import (
    build_test_execution_index,
    focused_test_execution,
    test_coverage_alignment,
)


_NAME_SEPARATOR = re.compile(r"[-_.]+")
_HIGH_VALUE_CLASSIFICATION = re.compile(
    r"^(?:CVE-|GHSA-|CWE-|OSV-|PYSEC-|LICENSE-|OWASP-|SLSA-|COSIGN-)"
)
_LANES: dict[str, frozenset[str]] = {
    "source_security": frozenset(
        {"bandit", "semgrep", "pysa", "codeql", "devskim", "flawfinder"}
    ),
    "structure_and_reachability": frozenset(
        {"graphify", "reachability", "tach", "vulture", "radon", "deptry"}
    ),
    "test_assurance": frozenset({"coverage", "diff-cover", "junit", "hypothesis"}),
    "source_composition": frozenset(
        {"cyclonedx-py", "osv-scanner", "pipdeptree", "guarddog"}
    ),
    "artifact_composition": frozenset({"syft", "grype", "trivy", "scancode"}),
    "provenance": frozenset(
        {"cosign", "in-toto", "reproducible-build", "pypi-attestations"}
    ),
}


def build_evidence_fusion(
    findings: list[Finding],
    artifacts: dict[str, Any],
    tool_runs: list[ToolRun],
) -> dict[str, Any]:
    """Cross-reference independent evidence without changing native severity."""
    source_components = _components(artifacts.get("sbom.cdx.json"))
    artifact_components = _components(artifacts.get("artifact-sbom.cdx.json"))
    source_files = _source_files(artifacts.get("source-inventory.json"))
    changed_lines = _changed_lines(artifacts.get("diff-coverage.json"))
    coverage = _coverage(artifacts.get("coverage-summary.json"))
    artifact_files = _artifact_files(artifacts.get("artifact-manifest.json"))
    classification_index = _classification_index(findings)
    package_findings = _package_finding_index(findings)
    findings_by_id = {finding.finding_id: finding for finding in findings}
    advisory_clusters = _enrich_advisory_clusters(
        build_advisory_clusters(findings), artifacts, findings
    )
    advisory_clusters_by_finding = {
        finding_id: cluster
        for cluster in advisory_clusters
        for finding_id in cluster["finding_ids"]
    }

    finding_contexts: list[dict[str, Any]] = []
    for finding in findings:
        context = _finding_context(
            finding,
            classification_index=classification_index,
            package_findings=package_findings,
            source_components=source_components,
            artifact_components=artifact_components,
            source_files=source_files,
            changed_lines=changed_lines,
            coverage=coverage,
            artifact_files=artifact_files,
            findings_by_id=findings_by_id,
            advisory_clusters_by_finding=advisory_clusters_by_finding,
        )
        finding.evidence["fusion"] = context
        finding_contexts.append({"finding_id": finding.finding_id, **context})

    package_lineage = _package_lineage(
        source_components, artifact_components, package_findings
    )
    lanes = _evidence_lanes(tool_runs, artifacts)
    hotspots = _compound_hotspots(artifacts.get("graph-analysis.json"))
    contradictions = [
        {
            "finding_id": item["finding_id"],
            "kind": "artifact-digest-mismatch",
            "message": (
                "finding artifact SHA-256 conflicts with the normalized "
                "artifact manifest"
            ),
        }
        for item in finding_contexts
        if item["artifact_context"].get("finding_sha256_matches_manifest") is False
    ]
    summary = {
        "findings_enriched": len(finding_contexts),
        "independently_corroborated": sum(
            item["corroboration"] in {"independent", "cross-stage"}
            for item in finding_contexts
        ),
        "cross_stage_findings": sum(
            item["corroboration"] == "cross-stage" for item in finding_contexts
        ),
        "changed_line_findings": sum(
            item["source_context"].get("changed_line") is True
            for item in finding_contexts
        ),
        "uncovered_findings": sum(
            item["source_context"].get("line_covered") is False
            for item in finding_contexts
        ),
        "package_lineages": len(package_lineage),
        "source_only_packages": sum(
            item["status"] == "source-only" for item in package_lineage
        ),
        "artifact_only_packages": sum(
            item["status"] == "artifact-only" for item in package_lineage
        ),
        "version_drift_packages": sum(
            item["status"] == "version-drift" for item in package_lineage
        ),
        "compound_hotspots": len(hotspots),
        "contradictions": len(contradictions),
        "distinct_advisories": len(advisory_clusters),
        "advisory_observations": sum(
            int(item["observation_count"]) for item in advisory_clusters
        ),
        "alias_collapsed_observations": sum(
            max(0, int(item["observation_count"]) - 1) for item in advisory_clusters
        ),
        "advisories_with_import_evidence": sum(
            item["dependency_usage"]["import_observed"] is True
            for item in advisory_clusters
        ),
        "advisories_in_executable_imports": sum(
            item["dependency_usage"]["assessment"] == "executable-import"
            for item in advisory_clusters
        ),
        "runtime_observed_dependency_advisories": sum(
            item["dependency_usage"]["assessment"] == "runtime-observed-import"
            for item in advisory_clusters
        ),
        "advisories_with_unused_declarations": sum(
            "unused-declaration" in item["dependency_usage"]["deptry_statuses"]
            for item in advisory_clusters
        ),
        "dependency_use_conflicts": sum(
            item["dependency_usage"]["signals_conflict"] for item in advisory_clusters
        ),
        "known_exploited_advisories": sum(
            item["threat_context"]["known_exploited"] for item in advisory_clusters
        ),
        "high_epss_advisories": sum(
            item["threat_context"]["epss_high"] for item in advisory_clusters
        ),
        "advisories_with_fixed_versions": sum(
            item["remediation_context"]["fix_available"] for item in advisory_clusters
        ),
        "p0_advisories": sum(
            item["remediation_context"]["priority"] == "P0"
            for item in advisory_clusters
        ),
        "advisories_requiring_vex_validation": sum(
            item["threat_context"]["vex_disposition"]
            in {"bounded-or-resolved-claim", "mixed"}
            for item in advisory_clusters
        ),
        "advisories_with_focused_tests": sum(
            bool(item["dependency_usage"]["recommended_test_files"])
            for item in advisory_clusters
        ),
        "advisories_with_passing_focused_test_evidence": sum(
            item["dependency_usage"]["focused_test_validation_status"] == "passed"
            for item in advisory_clusters
        ),
        "advisories_with_failing_focused_test_evidence": sum(
            item["dependency_usage"]["focused_test_validation_status"] == "failed"
            for item in advisory_clusters
        ),
        "advisories_with_unobserved_focused_tests": sum(
            bool(item["dependency_usage"]["unobserved_recommended_test_files"])
            for item in advisory_clusters
        ),
        "advisories_with_import_path_owners": sum(
            bool(item["dependency_usage"]["import_path_owners"])
            for item in advisory_clusters
        ),
        "advisories_with_uncovered_import_paths": sum(
            bool(item["dependency_usage"]["uncovered_import_paths"])
            for item in advisory_clusters
        ),
        "advisories_with_test_coverage_mismatch": sum(
            item["dependency_usage"]["test_coverage_alignment"] == "coverage-gap"
            for item in advisory_clusters
        ),
        "advisories_with_introducing_dependency_paths": sum(
            bool(item["dependency_usage"]["dependency_paths"])
            for item in advisory_clusters
        ),
        "advisories_with_dependency_environment_gaps": sum(
            item["dependency_usage"]["dependency_environment_warning"]
            for item in advisory_clusters
        ),
        "transitive_advisories_without_dependency_paths": sum(
            item["dependency_usage"]["source_relationship"] == "transitive"
            and not item["dependency_usage"]["dependency_paths"]
            for item in advisory_clusters
        ),
    }
    return {
        "schema_version": "1.3",
        "schema_id": "urn:project-py-security-suite:evidence-fusion:1.3",
        "authoritative": False,
        "purpose": (
            "bounded cross-reference and triage evidence; does not infer absence, "
            "runtime exploitability, or release approval"
        ),
        "summary": summary,
        "evidence_lanes": lanes,
        "finding_contexts": sorted(
            finding_contexts,
            key=lambda item: (
                _review_rank(str(item["review_tier"])),
                str(item["finding_id"]),
            ),
        ),
        "package_lineage": package_lineage,
        "advisory_clusters": advisory_clusters,
        "compound_hotspots": hotspots,
        "contradictions": contradictions,
        "limitations": [
            "Completed tools with no finding are not treated as proof of safety.",
            "Package name matching uses normalized Python distribution names and exact versions.",
            "Advisory aliases are clustered for triage; every native scanner observation remains retained as a finding.",
            "Dependency-use context is static triage evidence and never proves that a vulnerable function is or is not exploitable.",
            "Focused-test execution describes retained pre-remediation evidence and never proves that a future remediated build passed.",
            "Static graph and reachability evidence do not prove runtime exploitability.",
            "Fusion review tiers guide triage and never replace scanner severity or policy.",
        ],
    }


def _finding_context(
    finding: Finding,
    *,
    classification_index: dict[str, set[str]],
    package_findings: dict[str, set[str]],
    source_components: dict[str, set[str]],
    artifact_components: dict[str, set[str]],
    source_files: dict[str, dict[str, Any]],
    changed_lines: dict[str, dict[str, set[int]]],
    coverage: dict[str, dict[str, Any]],
    artifact_files: dict[str, dict[str, Any]],
    findings_by_id: dict[str, Finding],
    advisory_clusters_by_finding: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    location = finding.locations[0] if finding.locations else None
    path = _path(location.path) if location else ""
    line = location.start_line if location else None
    package = _package_name(location.package if location else None)
    related: set[str] = set()
    shared: list[str] = []
    for classification in finding.classifications:
        key = classification.upper().split(":", 1)[0]
        if _HIGH_VALUE_CLASSIFICATION.match(key):
            peers = classification_index.get(key, set()) - {finding.finding_id}
            if peers:
                related.update(peers)
                shared.append(key)
    if package:
        related.update(package_findings.get(package, set()) - {finding.finding_id})
    advisory_context = _advisory_context(
        advisory_clusters_by_finding.get(finding.finding_id)
    )
    related.update(set(advisory_context["finding_ids"]) - {finding.finding_id})

    graph = finding.evidence.get("graph_context")
    graph = graph if isinstance(graph, dict) else {}
    structural = finding.evidence.get("structural_synthesis")
    structural = structural if isinstance(structural, dict) else {}
    source_context = _source_context(
        path, line, source_files, changed_lines, coverage, graph
    )
    package_context = _package_context(
        package, source_components, artifact_components, package_findings
    )
    artifact_context = _artifact_context(finding, artifact_files)
    related_tools = _related_tools(related, findings_by_id)
    source_tools = {source.tool for source in finding.sources}
    corroboration = "single-tool"
    if package_context.get("cross_stage"):
        corroboration = "cross-stage"
    elif len(source_tools) > 1 or related_tools - source_tools:
        corroboration = "independent"
    elif graph or structural or source_context.get("coverage_percent") is not None:
        corroboration = "contextual"

    reasons = _review_reasons(
        finding,
        corroboration=corroboration,
        source_context=source_context,
        graph=graph,
        structural=structural,
        artifact_context=artifact_context,
    )
    return {
        "review_tier": _review_tier(finding, reasons),
        "review_reasons": reasons,
        "corroboration": corroboration,
        "related_finding_ids": sorted(related)[:50],
        "related_tools": sorted(related_tools),
        "shared_classifications": sorted(set(shared)),
        "source_context": source_context,
        "package_context": package_context,
        "advisory_context": advisory_context,
        "artifact_context": artifact_context,
        "structural_context": structural,
    }


def _source_context(
    path: str,
    line: int | None,
    source_files: dict[str, dict[str, Any]],
    changed_lines: dict[str, dict[str, set[int]]],
    coverage: dict[str, dict[str, Any]],
    graph: dict[str, Any],
) -> dict[str, Any]:
    change = changed_lines.get(path, {})
    changed = (
        None if line is None or not change else line in change.get("changed", set())
    )
    line_covered: bool | None = None
    coverage_record = coverage.get(path, {})
    if line is not None and coverage_record:
        missing = coverage_record.get("missing_lines", set())
        covered = coverage_record.get("covered_lines", set())
        if line in missing:
            line_covered = False
        elif line in covered:
            line_covered = True
    if changed is True:
        if line in change.get("violations", set()):
            line_covered = False
        elif line in change.get("covered", set()):
            line_covered = True
    corroborating = graph.get("corroborating_evidence", {})
    if not isinstance(corroborating, dict):
        corroborating = {}
    record = source_files.get(path, {})
    return {
        "path": path or None,
        "source_sha256": record.get("sha256"),
        "source_size_bytes": record.get("size_bytes"),
        "changed_line": changed,
        "line_covered": line_covered,
        "coverage_percent": coverage_record.get("percent"),
        "diff_coverage_percent": change.get("percent"),
        "reachability_states": corroborating.get("reachability_states", []),
        "runtime_observations": corroborating.get("runtime_observations", []),
        "graph_upstream_files": graph.get("two_hop_upstream_count"),
        "graph_downstream_files": graph.get("two_hop_downstream_count"),
        "graph_degree": graph.get("degree"),
        "maximum_complexity": corroborating.get("maximum_complexity"),
        "maximum_complexity_rank": corroborating.get("maximum_complexity_rank"),
    }


def _package_context(
    package: str,
    source_components: dict[str, set[str]],
    artifact_components: dict[str, set[str]],
    package_findings: dict[str, set[str]],
) -> dict[str, Any]:
    if not package:
        return {
            "package": None,
            "source_versions": [],
            "artifact_versions": [],
            "cross_stage": False,
            "related_package_findings": [],
        }
    source_versions = sorted(source_components.get(package, set()))
    artifact_versions = sorted(artifact_components.get(package, set()))
    return {
        "package": package,
        "source_versions": source_versions,
        "artifact_versions": artifact_versions,
        "cross_stage": bool(set(source_versions) & set(artifact_versions)),
        "related_package_findings": sorted(package_findings.get(package, set())),
    }


def _artifact_context(
    finding: Finding, artifact_files: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    evidence_path = finding.evidence.get("artifact_path")
    location_path = finding.locations[0].path if finding.locations else None
    path = _path(str(evidence_path or location_path or ""))
    match = artifact_files.get(path)
    if match is None:
        name = path.rsplit("/", 1)[-1]
        candidates = [
            value
            for key, value in artifact_files.items()
            if key.endswith("/" + name) or key == name
        ]
        match = candidates[0] if len(candidates) == 1 else None
    return {
        "manifest_bound": match is not None,
        "manifest_sha256": match.get("sha256") if match else None,
        "manifest_size_bytes": match.get("size_bytes") if match else None,
        "finding_sha256_matches_manifest": (
            str(finding.evidence.get("artifact_sha256")) == str(match.get("sha256"))
            if match and finding.evidence.get("artifact_sha256")
            else None
        ),
    }


def _review_reasons(
    finding: Finding,
    *,
    corroboration: str,
    source_context: dict[str, Any],
    graph: dict[str, Any],
    structural: dict[str, Any],
    artifact_context: dict[str, Any],
) -> list[str]:
    reasons: list[str] = []
    intelligence = finding.evidence.get("risk_intelligence")
    if isinstance(intelligence, dict) and intelligence.get("known_exploited"):
        reasons.append("known exploited vulnerability")
    if corroboration == "cross-stage":
        reasons.append("same package risk spans source declaration and built artifact")
    elif corroboration == "independent":
        reasons.append(
            "independent scanners share a high-value classification or package"
        )
    if source_context.get("changed_line") is True:
        reasons.append("finding is on a changed line")
    if source_context.get("line_covered") is False:
        reasons.append("finding line lacks retained test coverage")
    if (
        source_context.get("coverage_percent") is not None
        and float(source_context["coverage_percent"]) < 80
    ):
        reasons.append("containing file is below the coverage threshold")
    if int(graph.get("two_hop_upstream_count") or 0) >= 10:
        reasons.append("static graph indicates a broad upstream blast radius")
    if str(source_context.get("maximum_complexity_rank") or "").upper() in {
        "D",
        "E",
        "F",
    }:
        reasons.append("finding is in a high-complexity file")
    if structural.get("disposition") == "likely-removable":
        reasons.append("multiple structural signals support focused removal review")
    island = structural.get("island")
    if (
        isinstance(island, dict)
        and island.get("classification") == "latent-attack-surface"
    ):
        reasons.append("finding occurs in a latent attack-surface island")
    cycle = structural.get("import_cycle")
    if isinstance(cycle, dict) and cycle.get("priority") == "high":
        reasons.append("finding occurs in a high-priority import cycle")
    change = structural.get("change_impact")
    if isinstance(change, dict) and change.get("priority") == "high":
        reasons.append("finding occurs in a high-priority changed graph neighborhood")
    boundary = structural.get("island_boundary")
    if (
        isinstance(boundary, dict)
        and boundary.get("boundary_classification") == "candidate-missing-entry-point"
    ):
        reasons.append("island has concrete inbound paths but no modeled entry point")
    exposure = finding.evidence.get("data_exposure")
    if isinstance(exposure, dict):
        family = str(exposure.get("sink_family") or "external-disclosure")
        relevance = str(exposure.get("structural_relevance") or "unknown")
        priority = str(exposure.get("review_priority") or "medium")
        protection = str(exposure.get("protection_status") or "unknown")
        article = "an" if family[:1].casefold() in {"a", "e", "i", "o", "u"} else "a"
        reasons.append(f"sensitive-data flow reaches {article} {family} sink")
        if relevance in {"runtime-observed", "changed-code", "statically-connected"}:
            reasons.append(f"sensitive-data path is {relevance}")
        if priority == "high":
            reasons.append("sensitive-data analysis assigns high review priority")
        if protection == "not-observed":
            reasons.append("no explicit protection boundary was observed at the sink")
        elif protection == "pseudonymized":
            reasons.append("pseudonymized data remains linkable and requires review")
    if artifact_context.get("finding_sha256_matches_manifest") is False:
        reasons.append("finding artifact digest conflicts with the artifact manifest")
    return reasons


def _review_tier(finding: Finding, reasons: list[str]) -> str:
    severe = finding.severity.value in {"critical", "high"}
    urgent = "known exploited vulnerability" in reasons or (
        severe
        and "finding is on a changed line" in reasons
        and "finding line lacks retained test coverage" in reasons
    )
    if urgent:
        return "urgent"
    if severe and reasons:
        return "elevated"
    if len(reasons) >= 2:
        return "elevated"
    return "standard"


def _components(value: Any) -> dict[str, set[str]]:
    if not isinstance(value, dict) or not isinstance(value.get("components"), list):
        return {}
    result: dict[str, set[str]] = defaultdict(set)
    for item in value["components"]:
        if not isinstance(item, dict):
            continue
        name = _package_name(item.get("name"))
        version = str(item.get("version") or "unknown")[:300]
        if name:
            result[name].add(version)
    return dict(result)


def _enrich_advisory_clusters(
    clusters: list[dict[str, Any]],
    artifacts: dict[str, Any],
    findings: list[Finding],
) -> list[dict[str, Any]]:
    (
        relationships,
        dependency_paths,
        relationship_evidence,
        dependency_paths_truncated,
    ) = _source_dependency_relationships(artifacts.get("sbom.cdx.json"))
    environment_health, environment_health_evidence = _pipdeptree_health(
        artifacts.get("pipdeptree-summary.json")
    )
    imports, import_evidence = _external_imports(artifacts.get("graphify.json"))
    test_mappings, test_mapping_evidence = _dependency_test_mappings(
        artifacts.get("graphify.json")
    )
    test_executions, test_execution_evidence = build_test_execution_index(artifacts)
    reachability, reachability_evidence = _reachability_by_path(
        artifacts.get("reachability.json")
    )
    coverage = _coverage(artifacts.get("coverage-summary.json"))
    coverage_evidence = isinstance(artifacts.get("coverage-summary.json"), dict)
    owners_by_path = _owners_by_path(findings)
    ownership_rules = ownership_rules_from_artifact(artifacts.get("finding-delta.json"))
    ownership_evidence = _ownership_evidence_available(
        artifacts.get("finding-delta.json"), owners_by_path
    )
    deptry = _deptry_package_signals(findings)
    findings_by_id = {finding.finding_id: finding for finding in findings}
    for cluster in clusters:
        package = str(cluster["package"])
        import_records = imports.get(package, [])
        import_paths = sorted(
            {str(item["path"]) for item in import_records if item.get("path")}
        )[:50]
        validation = _dependency_validation_handoff(
            import_paths,
            import_records=import_records,
            test_mappings=test_mappings,
            test_mapping_evidence=test_mapping_evidence,
            test_executions=test_executions,
            test_execution_evidence=test_execution_evidence,
            owners_by_path=owners_by_path,
            ownership_rules=ownership_rules,
            ownership_evidence=ownership_evidence,
            coverage=coverage,
            coverage_evidence=coverage_evidence,
            reachability=reachability,
            reachability_evidence=reachability_evidence,
        )
        package_paths = dependency_paths.get(package, [])
        environment_warning = bool(
            environment_health_evidence and environment_health.get("healthy") is False
        )
        path_reachability = [
            reachability[path] for path in import_paths if path in reachability
        ]
        states = sorted(
            {str(state) for item in path_reachability for state in item["states"]}
        )
        runtime_observations = sorted(
            {
                str(observation)
                for item in path_reachability
                for observation in item["runtime_observations"]
            }
        )
        deptry_records = deptry.get(package, [])
        deptry_statuses = sorted({str(item["status"]) for item in deptry_records})
        import_observed = bool(import_records) if import_evidence else None
        reachability_complete = (
            reachability_evidence.get("complete")
            if isinstance(reachability_evidence.get("complete"), bool)
            else None
        )
        signals_conflict = bool(
            import_observed is True and "unused-declaration" in deptry_statuses
        )
        assessment = _dependency_use_assessment(
            import_observed=import_observed,
            states=states,
            runtime_observations=runtime_observations,
            reachability_complete=reachability_complete,
            deptry_statuses=deptry_statuses,
            signals_conflict=signals_conflict,
        )
        cluster["dependency_usage"] = {
            "assessment": assessment,
            "source_relationship": relationships.get(package, "unknown"),
            "relationship_evidence_available": relationship_evidence,
            "dependency_path_evidence_available": relationship_evidence,
            "dependency_paths": package_paths,
            "dependency_paths_truncated": dependency_paths_truncated,
            "introducing_packages": sorted(
                {
                    str(item["introducing_package"])
                    for item in package_paths
                    if item.get("introducing_package")
                }
            )[:25],
            "dependency_path_confidence": (
                "qualified"
                if package_paths and environment_warning
                else "high"
                if package_paths
                else "not-available"
            ),
            "environment_health_evidence_available": environment_health_evidence,
            "dependency_environment_health": environment_health,
            "dependency_environment_warning": environment_warning,
            "import_evidence_available": import_evidence,
            "import_observed": import_observed,
            "import_modules": sorted(
                {str(item["module"]) for item in import_records if item.get("module")}
            )[:50],
            "import_paths": import_paths,
            "reachability_evidence_available": bool(reachability_evidence),
            "reachability_complete": reachability_complete,
            "reachability_confidence": (
                str(reachability_evidence.get("confidence"))[:50]
                if reachability_evidence.get("confidence")
                else None
            ),
            "reachability_states": states,
            "runtime_observations": runtime_observations,
            "deptry_statuses": deptry_statuses,
            "deptry_finding_ids": sorted(
                {str(item["finding_id"]) for item in deptry_records}
            )[:50],
            "signals_conflict": signals_conflict,
            **validation,
            "evidence_artifacts": sorted(
                {
                    *(
                        name
                        for name, available in (
                            ("sbom.cdx.json", relationship_evidence),
                            ("graphify.json", import_evidence),
                            ("reachability.json", bool(reachability_evidence)),
                            ("coverage-summary.json", coverage_evidence),
                            ("finding-delta.json", ownership_evidence),
                            ("findings.json", bool(deptry_records)),
                            (
                                "pipdeptree-summary.json",
                                environment_health_evidence,
                            ),
                        )
                        if available
                    ),
                    *test_execution_evidence["sources"],
                }
            ),
        }
        refresh_advisory_decision(cluster, findings_by_id)
    return clusters


def _source_dependency_relationships(
    value: Any,
) -> tuple[dict[str, str], dict[str, list[dict[str, Any]]], bool, bool]:
    if not isinstance(value, dict):
        return {}, {}, False, False
    raw_components = value.get("components")
    raw_dependencies = value.get("dependencies")
    if not isinstance(raw_components, list) or not isinstance(raw_dependencies, list):
        return {}, {}, False, False
    if not raw_dependencies:
        return {}, {}, True, False
    packages_by_ref: dict[str, str] = {}
    versions_by_ref: dict[str, str] = {}
    for item in raw_components:
        if not isinstance(item, dict):
            continue
        reference = item.get("bom-ref")
        package = _package_name(item.get("name"))
        if isinstance(reference, str) and reference and package:
            packages_by_ref[reference] = package
            versions_by_ref[reference] = str(item.get("version") or "unknown")[:100]
    if not packages_by_ref:
        return {}, {}, True, False
    adjacency: dict[str, set[str]] = defaultdict(set)
    incoming: dict[str, int] = {reference: 0 for reference in packages_by_ref}
    for item in raw_dependencies:
        if not isinstance(item, dict) or not isinstance(item.get("ref"), str):
            continue
        source = str(item["ref"])
        depends_on = item.get("dependsOn")
        if not isinstance(depends_on, list):
            depends_on = []
        for raw_target in depends_on[:10_000]:
            if not isinstance(raw_target, str):
                continue
            adjacency[source].add(raw_target)
            if raw_target in incoming:
                incoming[raw_target] += 1
    metadata = value.get("metadata")
    metadata_component = (
        metadata.get("component") if isinstance(metadata, dict) else None
    )
    root_ref = (
        metadata_component.get("bom-ref")
        if isinstance(metadata_component, dict)
        and isinstance(metadata_component.get("bom-ref"), str)
        else None
    )
    if root_ref and root_ref in adjacency:
        direct_refs = adjacency.get(root_ref, set()) & packages_by_ref.keys()
    else:
        direct_refs = {reference for reference, count in incoming.items() if count == 0}
    relationships: dict[str, str] = {}
    for reference, package in packages_by_ref.items():
        relationship = "direct" if reference in direct_refs else "transitive"
        if relationships.get(package) != "direct":
            relationships[package] = relationship
    paths, truncated = _dependency_paths(
        packages_by_ref,
        versions_by_ref,
        adjacency,
        direct_refs,
    )
    return relationships, paths, True, truncated


def _dependency_paths(
    packages_by_ref: dict[str, str],
    versions_by_ref: dict[str, str],
    adjacency: dict[str, set[str]],
    direct_refs: set[str],
) -> tuple[dict[str, list[dict[str, Any]]], bool]:
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen: dict[str, set[tuple[str, ...]]] = defaultdict(set)
    queue: list[tuple[str, tuple[str, ...]]] = [
        (reference, (reference,)) for reference in sorted(direct_refs)
    ]
    cursor = 0
    steps = 0
    truncated = False
    while cursor < len(queue):
        reference, references = queue[cursor]
        cursor += 1
        steps += 1
        if steps > 100_000:
            truncated = True
            break
        package = packages_by_ref.get(reference)
        if package:
            labels = tuple(
                f"{packages_by_ref[item]}@{versions_by_ref.get(item, 'unknown')}"
                for item in references
                if item in packages_by_ref
            )
            if labels and labels not in seen[package]:
                if len(result[package]) >= 25:
                    truncated = True
                else:
                    seen[package].add(labels)
                    result[package].append(
                        {
                            "introducing_package": packages_by_ref[references[0]],
                            "path": list(labels),
                            "depth": len(labels) - 1,
                        }
                    )
        if len(references) >= 12:
            if adjacency.get(reference):
                truncated = True
            continue
        queue.extend(
            (child, (*references, child))
            for child in sorted(adjacency.get(reference, set()))
            if child in packages_by_ref and child not in references
        )
    for records in result.values():
        records.sort(key=lambda item: (int(item["depth"]), item["path"]))
    return dict(result), truncated


def _pipdeptree_health(value: Any) -> tuple[dict[str, Any], bool]:
    if not isinstance(value, dict) or not any(
        key in value
        for key in (
            "total_packages",
            "missing_dependencies",
            "cyclic_dependencies",
            "conflicting_dependencies",
        )
    ):
        return {}, False
    conflicts = value.get("conflicting_dependencies")
    conflicts = conflicts if isinstance(conflicts, dict) else {}

    def count(raw: Any) -> int:
        return (
            raw
            if isinstance(raw, int) and not isinstance(raw, bool) and raw >= 0
            else 0
        )

    health = {
        "total_packages": count(value.get("total_packages")),
        "direct_dependencies": count(value.get("direct_dependencies")),
        "transitive_dependencies": count(value.get("transitive_dependencies")),
        "max_depth": count(value.get("max_depth")),
        "missing_dependencies": count(value.get("missing_dependencies")),
        "cyclic_dependencies": count(value.get("cyclic_dependencies")),
        "conflicting_dependency_packages": count(conflicts.get("packages")),
        "conflicting_dependency_edges": count(conflicts.get("edges")),
    }
    health["healthy"] = not any(
        health[key]
        for key in (
            "missing_dependencies",
            "cyclic_dependencies",
            "conflicting_dependency_packages",
            "conflicting_dependency_edges",
        )
    )
    return health, True


def _dependency_test_mappings(
    value: Any,
) -> tuple[dict[str, dict[str, list[str]]], bool]:
    if not isinstance(value, dict):
        return {}, False
    topology = value.get("topology")
    if not isinstance(topology, dict) or not isinstance(
        topology.get("file_edges"), list
    ):
        return {}, False
    incoming: dict[str, set[str]] = defaultdict(set)
    for item in topology["file_edges"][:100_000]:
        if not isinstance(item, dict):
            continue
        relation = str(item.get("relation") or "")
        if relation not in {"calls", "imports", "imports_from", "references", "uses"}:
            continue
        source = _path(str(item.get("source") or ""))
        target = _path(str(item.get("target") or ""))
        if source and target and source != target:
            incoming[target].add(source)
    result: dict[str, dict[str, list[str]]] = {}
    for path in sorted(incoming)[:100_000]:
        direct = sorted(item for item in incoming[path] if _is_test_path(item))[:50]
        transitive = sorted(
            item
            for item in _bounded_graph_walk(incoming, path)
            if _is_test_path(item) and item not in direct
        )[:50]
        result[path] = {"direct": direct, "transitive": transitive}
    return result, True


def _bounded_graph_walk(adjacency: dict[str, set[str]], root: str) -> set[str]:
    visited: set[str] = set()
    frontier = {root}
    for _depth in range(2):
        following = {
            neighbor
            for current in frontier
            for neighbor in adjacency.get(current, set())
            if neighbor != root and neighbor not in visited
        }
        visited.update(following)
        frontier = following
        if not frontier or len(visited) >= 500:
            break
    return set(sorted(visited)[:500])


def _is_test_path(path: str) -> bool:
    normalized = "/" + path.casefold().strip("/")
    name = normalized.rsplit("/", 1)[-1]
    return (
        "/tests/" in normalized
        or "/test/" in normalized
        or name.startswith("test_")
        or name.endswith("_test.py")
    )


def _owners_by_path(findings: list[Finding]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        owners = finding.evidence.get("owners")
        if not isinstance(owners, list):
            continue
        normalized = {
            str(owner)[:256]
            for owner in owners[:20]
            if isinstance(owner, str) and owner
        }
        for location in finding.locations:
            path = _path(location.path)
            if path:
                result[path].update(normalized)
    return dict(result)


def _ownership_evidence_available(
    value: Any, owners_by_path: dict[str, set[str]]
) -> bool:
    if owners_by_path:
        return True
    if not isinstance(value, dict):
        return False
    count = value.get("ownership_rules")
    return isinstance(count, int) and not isinstance(count, bool) and count > 0


def _dependency_validation_handoff(
    import_paths: list[str],
    *,
    import_records: list[dict[str, Any]],
    test_mappings: dict[str, dict[str, list[str]]],
    test_mapping_evidence: bool,
    test_executions: dict[str, list[dict[str, str]]],
    test_execution_evidence: dict[str, Any],
    owners_by_path: dict[str, set[str]],
    ownership_rules: list[tuple[str, list[str]]],
    ownership_evidence: bool,
    coverage: dict[str, dict[str, Any]],
    coverage_evidence: bool,
    reachability: dict[str, dict[str, set[str]]],
    reachability_evidence: dict[str, Any],
) -> dict[str, Any]:
    direct = sorted(
        {
            test
            for path in import_paths
            for test in test_mappings.get(path, {}).get("direct", [])
        }
    )[:50]
    transitive = sorted(
        {
            test
            for path in import_paths
            for test in test_mappings.get(path, {}).get("transitive", [])
            if test not in direct
        }
    )[:50]
    ownership_records = [
        {
            "path": path,
            "owners": sorted(
                {
                    *owners_by_path.get(path, set()),
                    *owners_for_path(path, ownership_rules),
                }
            )[:20],
        }
        for path in import_paths
    ][:50]
    owners = sorted(
        {owner for record in ownership_records for owner in record["owners"]}
    )[:20]
    coverage_records = [
        {
            "path": path,
            "coverage_percent": (
                float(percent)
                if isinstance(
                    percent := coverage.get(path, {}).get("percent"), (int, float)
                )
                and not isinstance(percent, bool)
                and 0 <= float(percent) <= 100
                else None
            ),
        }
        for path in import_paths
    ][:50]
    uncovered = sorted(
        str(item["path"])
        for item in coverage_records
        if isinstance(item["coverage_percent"], (int, float))
        and float(item["coverage_percent"]) < 80
    )[:50]
    confidence = (
        "high"
        if direct
        else "medium"
        if transitive
        else "low"
        if test_mapping_evidence and import_paths
        else "not-available"
    )
    recommended = [*direct, *transitive][:50]
    execution = focused_test_execution(
        recommended,
        test_executions=test_executions,
        evidence=test_execution_evidence,
    )
    alignment = test_coverage_alignment(
        execution,
        coverage_evidence_available=coverage_evidence,
        coverage_gap=bool(uncovered),
        coverage_subject="the affected dependency import path(s)",
    )
    import_path_assessments = _dependency_import_path_assessments(
        import_paths,
        import_records=import_records,
        test_mappings=test_mappings,
        test_mapping_evidence=test_mapping_evidence,
        test_executions=test_executions,
        test_execution_evidence=test_execution_evidence,
        owners_by_path=owners_by_path,
        ownership_rules=ownership_rules,
        ownership_evidence=ownership_evidence,
        coverage=coverage,
        coverage_evidence=coverage_evidence,
        reachability=reachability,
        reachability_evidence=reachability_evidence,
    )
    return {
        "test_mapping_evidence_available": test_mapping_evidence,
        "recommended_test_files": recommended,
        "direct_test_files": direct,
        "transitive_test_files": transitive,
        "test_selection_confidence": confidence,
        **execution,
        **alignment,
        "ownership_evidence_available": ownership_evidence,
        "import_path_owners": owners,
        "import_path_ownership": ownership_records,
        "coverage_evidence_available": coverage_evidence,
        "import_path_coverage": coverage_records,
        "import_path_assessments": import_path_assessments,
        "uncovered_import_paths": uncovered,
    }


def _dependency_import_path_assessments(
    import_paths: list[str],
    *,
    import_records: list[dict[str, Any]],
    test_mappings: dict[str, dict[str, list[str]]],
    test_mapping_evidence: bool,
    test_executions: dict[str, list[dict[str, str]]],
    test_execution_evidence: dict[str, Any],
    owners_by_path: dict[str, set[str]],
    ownership_rules: list[tuple[str, list[str]]],
    ownership_evidence: bool,
    coverage: dict[str, dict[str, Any]],
    coverage_evidence: bool,
    reachability: dict[str, dict[str, set[str]]],
    reachability_evidence: dict[str, Any],
) -> list[dict[str, Any]]:
    modules_by_path: dict[str, set[str]] = defaultdict(set)
    lines_by_path: dict[str, set[int]] = defaultdict(set)
    for record in import_records:
        path = _path(str(record.get("path") or ""))
        if not path:
            continue
        module = record.get("module")
        if isinstance(module, str) and module:
            modules_by_path[path].add(module[:500])
        line = record.get("line")
        if isinstance(line, int) and not isinstance(line, bool) and line > 0:
            lines_by_path[path].add(line)
    reachability_complete = (
        reachability_evidence.get("complete")
        if isinstance(reachability_evidence.get("complete"), bool)
        else None
    )
    result: list[dict[str, Any]] = []
    for path in import_paths[:50]:
        mapping = test_mappings.get(path, {})
        direct = sorted(set(mapping.get("direct", [])))[:50]
        transitive = sorted(set(mapping.get("transitive", [])) - set(direct))[:50]
        selected = [*direct, *transitive][:50]
        confidence = (
            "high"
            if direct
            else "medium"
            if transitive
            else "low"
            if test_mapping_evidence
            else "not-available"
        )
        execution = focused_test_execution(
            selected,
            test_executions=test_executions,
            evidence=test_execution_evidence,
        )
        raw_percent = coverage.get(path, {}).get("percent")
        percent = (
            float(raw_percent)
            if isinstance(raw_percent, (int, float))
            and not isinstance(raw_percent, bool)
            and 0 <= float(raw_percent) <= 100
            else None
        )
        coverage_gap = isinstance(percent, float) and percent < 80
        alignment = test_coverage_alignment(
            execution,
            coverage_evidence_available=coverage_evidence,
            coverage_gap=coverage_gap,
            coverage_subject=f"dependency import path {path}",
        )
        reachability_record = reachability.get(path, {})
        states = sorted(str(item) for item in reachability_record.get("states", set()))
        observations = sorted(
            str(item) for item in reachability_record.get("runtime_observations", set())
        )
        result.append(
            {
                "path": path,
                "import_modules": sorted(modules_by_path[path])[:50],
                "import_lines": sorted(lines_by_path[path])[:100],
                "assessment": _dependency_use_assessment(
                    import_observed=True,
                    states=states,
                    runtime_observations=observations,
                    reachability_complete=reachability_complete,
                    deptry_statuses=[],
                    signals_conflict=False,
                ),
                "reachability_states": states,
                "runtime_observations": observations,
                "owners": sorted(
                    {
                        *owners_by_path.get(path, set()),
                        *owners_for_path(path, ownership_rules),
                    }
                )[:20],
                "ownership_evidence_available": ownership_evidence,
                "direct_test_files": direct,
                "transitive_test_files": transitive,
                "recommended_test_files": selected,
                "test_selection_confidence": confidence,
                **execution,
                "coverage_evidence_available": coverage_evidence,
                "coverage_percent": percent,
                "coverage_gap": coverage_gap if percent is not None else None,
                **alignment,
                "evidence_artifacts": sorted(
                    {
                        *(["graphify.json"] if test_mapping_evidence else []),
                        *(["reachability.json"] if reachability_evidence else []),
                        *(["finding-delta.json"] if ownership_evidence else []),
                        *(["coverage-summary.json"] if coverage_evidence else []),
                        *test_execution_evidence["sources"],
                    }
                ),
            }
        )
    return result


def _external_imports(value: Any) -> tuple[dict[str, list[dict[str, Any]]], bool]:
    if not isinstance(value, dict):
        return {}, False
    nodes = value.get("nodes")
    edges = value.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        return {}, False
    by_id = {
        str(item["id"]): item
        for item in nodes
        if isinstance(item, dict) and item.get("id")
    }
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        if not isinstance(edge, dict) or edge.get("relation") != "imports":
            continue
        target = by_id.get(str(edge.get("target") or ""))
        source = by_id.get(str(edge.get("source") or ""))
        if not isinstance(target, dict) or target.get("kind") != "external":
            continue
        external_name = str(target.get("label") or target.get("id") or "")
        package = _package_name(external_name.split(".", 1)[0])
        if not package:
            continue
        result[package].append(
            {
                "module": external_name[:500],
                "path": _path(str(source.get("path") or edge.get("path") or ""))
                if isinstance(source, dict)
                else _path(str(edge.get("path") or "")),
                "line": edge.get("line") if isinstance(edge.get("line"), int) else None,
            }
        )
    return dict(result), True


def _reachability_by_path(
    value: Any,
) -> tuple[dict[str, dict[str, set[str]]], dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(value.get("nodes"), list):
        return {}, {}
    analysis = value.get("analysis")
    analysis = analysis if isinstance(analysis, dict) else {}
    result: dict[str, dict[str, set[str]]] = {}
    for node in value["nodes"]:
        if not isinstance(node, dict) or not isinstance(node.get("path"), str):
            continue
        path = _path(node["path"])
        record = result.setdefault(
            path, {"states": set(), "runtime_observations": set()}
        )
        state = node.get("state")
        if isinstance(state, str) and state:
            record["states"].add(state)
        observation = node.get("runtime_observation")
        if isinstance(observation, str) and observation:
            record["runtime_observations"].add(observation)
    return result, {
        "complete": analysis.get("complete"),
        "confidence": analysis.get("confidence"),
    }


def _deptry_package_signals(
    findings: list[Finding],
) -> dict[str, list[dict[str, str]]]:
    statuses = {
        "DEP001": "undeclared-import",
        "DEP002": "unused-declaration",
        "DEP003": "transitive-import",
        "DEP004": "development-only-import",
    }
    result: dict[str, list[dict[str, str]]] = defaultdict(list)
    for finding in findings:
        rules = {
            source.rule_id: statuses[source.rule_id]
            for source in finding.sources
            if source.tool == "deptry" and source.rule_id in statuses
        }
        package = _package_name(finding.evidence.get("module"))
        if not package:
            continue
        for status in rules.values():
            result[package].append({"finding_id": finding.finding_id, "status": status})
    return dict(result)


def _dependency_use_assessment(
    *,
    import_observed: bool | None,
    states: list[str],
    runtime_observations: list[str],
    reachability_complete: bool | None,
    deptry_statuses: list[str],
    signals_conflict: bool,
) -> str:
    if signals_conflict:
        return "import-vs-unused-conflict"
    if import_observed is True:
        if "observed" in runtime_observations:
            return "runtime-observed-import"
        if reachability_complete is not True:
            return "imported-reachability-incomplete"
        if "executable" in states:
            return "executable-import"
        if "load-only" in states:
            return "load-only-import"
        if "disconnected" in states:
            return "disconnected-import"
        return "import-observed"
    if "unused-declaration" in deptry_statuses:
        return "declared-unused"
    if import_observed is False:
        return "import-not-observed"
    return "unknown"


def _advisory_context(cluster: dict[str, Any] | None) -> dict[str, Any]:
    if cluster is None:
        return {
            "cluster_id": None,
            "primary_identifier": None,
            "identifiers": [],
            "package": None,
            "versions": [],
            "finding_ids": [],
            "tools": [],
            "observation_count": 0,
            "alias_count": 0,
            "cross_tool": False,
            "dependency_usage": _empty_dependency_usage(),
            "threat_context": _empty_threat_context(),
            "remediation_context": _empty_remediation_context(),
        }
    return {
        key: cluster[key]
        for key in (
            "cluster_id",
            "primary_identifier",
            "identifiers",
            "package",
            "versions",
            "finding_ids",
            "tools",
            "observation_count",
            "alias_count",
            "cross_tool",
            "dependency_usage",
            "threat_context",
            "remediation_context",
        )
    }


def _empty_dependency_usage() -> dict[str, Any]:
    return {
        "assessment": "unknown",
        "source_relationship": "unknown",
        "relationship_evidence_available": False,
        "dependency_path_evidence_available": False,
        "dependency_paths": [],
        "dependency_paths_truncated": False,
        "introducing_packages": [],
        "dependency_path_confidence": "not-available",
        "environment_health_evidence_available": False,
        "dependency_environment_health": {},
        "dependency_environment_warning": False,
        "import_evidence_available": False,
        "import_observed": None,
        "import_modules": [],
        "import_paths": [],
        "reachability_evidence_available": False,
        "reachability_complete": None,
        "reachability_confidence": None,
        "reachability_states": [],
        "runtime_observations": [],
        "deptry_statuses": [],
        "deptry_finding_ids": [],
        "signals_conflict": False,
        "test_mapping_evidence_available": False,
        "recommended_test_files": [],
        "direct_test_files": [],
        "transitive_test_files": [],
        "test_selection_confidence": "not-available",
        "test_execution_evidence_available": False,
        "test_case_inventory_available": False,
        "test_case_inventory_complete": None,
        "test_execution_sources": [],
        "focused_test_execution": [],
        "focused_test_validation_status": "not-selected",
        "unobserved_recommended_test_files": [],
        "test_coverage_alignment": "not-selected",
        "validation_gap_reasons": [
            "No graph-selected focused test file was available."
        ],
        "ownership_evidence_available": False,
        "import_path_owners": [],
        "import_path_ownership": [],
        "coverage_evidence_available": False,
        "import_path_coverage": [],
        "import_path_assessments": [],
        "uncovered_import_paths": [],
        "evidence_artifacts": [],
    }


def _empty_threat_context() -> dict[str, Any]:
    return {
        "intelligence_available": False,
        "intelligence_sources": [],
        "cves": [],
        "known_exploited": False,
        "known_exploited_cves": [],
        "known_exploited_records": [],
        "epss_probability": None,
        "epss_percentile": None,
        "epss_high": False,
        "epss_records": [],
        "vex_states": [],
        "vex_disposition": "unassessed",
        "vex_records": [],
    }


def _empty_remediation_context() -> dict[str, Any]:
    return {
        "priority": "P4",
        "action_kind": "mitigate-or-replace",
        "fix_available": False,
        "fixed_version_candidates": [],
        "fixed_version_sources": [],
        "owners": [],
        "recommended_test_files": [],
        "test_selection_confidence": "not-available",
        "focused_test_validation_status": "not-selected",
        "test_coverage_alignment": "not-selected",
        "introducing_packages": [],
        "dependency_paths": [],
        "dependency_path_confidence": "not-available",
        "recommended_action": "Review and remediate the native advisory evidence.",
        "verification_steps": [],
        "evidence_basis": [],
        "uncertainties": [],
    }


def _package_lineage(
    source: dict[str, set[str]],
    artifact: dict[str, set[str]],
    package_findings: dict[str, set[str]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for name in sorted(source.keys() | artifact.keys()):
        source_versions = sorted(source.get(name, set()))
        artifact_versions = sorted(artifact.get(name, set()))
        if source_versions and artifact_versions:
            status = (
                "matched"
                if set(source_versions) == set(artifact_versions)
                else "version-drift"
            )
        elif source_versions:
            status = "source-only"
        else:
            status = "artifact-only"
        result.append(
            {
                "package": name,
                "source_versions": source_versions,
                "artifact_versions": artifact_versions,
                "status": status,
                "finding_ids": sorted(package_findings.get(name, set())),
            }
        )
    return result[:10_000]


def _classification_index(findings: list[Finding]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        for value in finding.classifications:
            key = value.upper().split(":", 1)[0]
            if _HIGH_VALUE_CLASSIFICATION.match(key):
                result[key].add(finding.finding_id)
    return result


def _package_finding_index(findings: list[Finding]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        for location in finding.locations:
            name = _package_name(location.package)
            if name:
                result[name].add(finding.finding_id)
    return result


def _source_files(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(value.get("files"), list):
        return {}
    return {
        _path(str(item["path"])): item
        for item in value["files"]
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }


def _artifact_files(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(value.get("artifacts"), list):
        return {}
    return {
        _path(str(item["path"])): item
        for item in value["artifacts"]
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }


def _coverage(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(value.get("files"), list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for item in value["files"]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        raw_summary = item.get("summary")
        summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
        result[_path(item["path"])] = {
            "percent": summary.get("percent_covered"),
            "missing_lines": _integers(item.get("missing_lines")),
            "covered_lines": _integers(item.get("covered_lines")),
        }
    return result


def _changed_lines(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(value.get("src_stats"), dict):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for raw_path, item in value["src_stats"].items():
        if not isinstance(item, dict):
            continue
        covered = _integers(item.get("covered_lines"))
        violations = _integers(item.get("violation_lines"))
        result[_path(str(raw_path))] = {
            "changed": covered | violations,
            "covered": covered,
            "violations": violations,
            "percent": item.get("percent_covered"),
        }
    return result


def _evidence_lanes(
    tool_runs: list[ToolRun], artifacts: dict[str, Any]
) -> list[dict[str, Any]]:
    statuses = {run.tool: run for run in tool_runs}
    result: list[dict[str, Any]] = []
    for lane, tools in _LANES.items():
        selected = sorted(tools & statuses.keys())
        completed = sorted(
            name for name in selected if statuses[name].status is ToolStatus.COMPLETED
        )
        gaps = sorted(
            name
            for name in selected
            if statuses[name].applicable
            and statuses[name].status is not ToolStatus.COMPLETED
        )
        result.append(
            {
                "lane": lane,
                "selected_tools": selected,
                "completed_tools": completed,
                "execution_gaps": gaps,
                "available_artifacts": sorted(
                    name for name in artifacts if _artifact_lane(name) == lane
                ),
            }
        )
    return result


def _artifact_lane(name: str) -> str:
    if name in {
        "graphify.json",
        "graph-analysis.json",
        "structural-synthesis.json",
        "reachability.json",
        "radon-complexity.json",
        "deptry-dependencies.json",
    }:
        return "structure_and_reachability"
    if name in {
        "coverage-summary.json",
        "diff-coverage.json",
        "junit-summary.json",
        "hypothesis-summary.json",
    }:
        return "test_assurance"
    if name == "sbom.cdx.json":
        return "source_composition"
    if name in {"artifact-sbom.cdx.json", "scancode-inventory.json"}:
        return "artifact_composition"
    if name in {"artifact-manifest.json", "reproducible-build-summary.json"}:
        return "provenance"
    return "other"


def _compound_hotspots(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(
        value.get("structural_hotspots"), list
    ):
        return []
    result = []
    for item in value["structural_hotspots"]:
        if not isinstance(item, dict):
            continue
        signals = ["high graph degree"]
        if (
            isinstance(item.get("coverage_percent"), (int, float))
            and float(item["coverage_percent"]) < 80
        ):
            signals.append("coverage below 80%")
        if str(item.get("maximum_complexity_rank") or "").upper() in {"D", "E", "F"}:
            signals.append("high complexity")
        if item.get("finding_ids"):
            signals.append("active findings")
        if len(signals) >= 2:
            result.append({**item, "signals": signals})
    return result[:25]


def _related_tools(related: set[str], findings_by_id: dict[str, Finding]) -> set[str]:
    tools: set[str] = set()
    for finding_id in related:
        finding = findings_by_id.get(finding_id)
        if finding is not None:
            tools.update(source.tool for source in finding.sources)
    return tools


def _integers(value: Any) -> set[int]:
    if not isinstance(value, list):
        return set()
    return {
        item for item in value if isinstance(item, int) and not isinstance(item, bool)
    }


def _package_name(value: Any) -> str:
    text = str(value or "").strip().casefold()
    if ":" in text and "@" in text:
        text = text.split(":", 1)[1].split("@", 1)[0]
    return _NAME_SEPARATOR.sub("-", text)


def _path(value: str) -> str:
    normalized = value.replace("\\", "/")
    return normalized[2:] if normalized.startswith("./") else normalized


def _review_rank(value: str) -> int:
    return {"urgent": 0, "elevated": 1, "standard": 2}.get(value, 3)
