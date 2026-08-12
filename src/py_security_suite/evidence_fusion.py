from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .models import Finding, ToolRun, ToolStatus


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
    }
    return {
        "schema_version": "1.0",
        "schema_id": "urn:project-py-security-suite:evidence-fusion:1.0",
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
        "compound_hotspots": hotspots,
        "contradictions": contradictions,
        "limitations": [
            "Completed tools with no finding are not treated as proof of safety.",
            "Package name matching uses normalized Python distribution names and exact versions.",
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
