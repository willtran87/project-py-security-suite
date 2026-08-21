from __future__ import annotations

import base64
import configparser
import csv
import hashlib
import io
import re
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from .models import Finding
from .path_safety import resolve_unlinked_path


_MAX_RELATIONSHIPS = 20_000
_MAX_RECORDS = 500
_MAX_WHEEL_MEMBERS = 100_000
_MAX_MEMBER_BYTES = 32 * 1024 * 1024
_MAX_WHEEL_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
_RECORD_HASH_ALGORITHMS = {"blake2b", "blake2s", "sha256", "sha384", "sha512"}
_VIRTUAL_ROOT = "<pysec-entry-root>"
_CONTROL_TERMS = (
    "auth",
    "authoriz",
    "filter",
    "guard",
    "policy",
    "redact",
    "sanit",
    "scrub",
    "validat",
)
_TELEMETRY_FAMILIES = {
    "analytics",
    "error-monitoring",
    "logging",
    "metrics",
    "observability",
    "telemetry",
    "url",
    "url-query",
}
_NATIVE_REDACTION_KINDS = {
    "redactor",
    "sanitiser",
    "sanitizer",
    "scrubber",
}
_REDACTION_TOKEN_PREFIXES = ("redact", "sanitis", "sanitiz", "scrub")


def build_advanced_analysis(
    target: Path,
    findings: list[Finding],
    artifacts: dict[str, Any],
) -> dict[str, Any]:
    """Build bounded, offline-only second-order evidence correlations.

    The result keeps structural inference separate from scanner-confirmed paths.
    It does not execute target code or treat missing evidence as proof of safety.
    """
    risk_paths = _object(artifacts.get("risk-paths.json"))
    controls = _control_topology(artifacts, risk_paths)
    taint_paths = _taint_paths(findings, risk_paths)
    artifact_parity = _artifact_route_parity(target, artifacts, risk_paths)
    traceability = _threat_control_test_traceability(findings, risk_paths, controls)
    mutations = _security_mutation_leverage(findings, risk_paths, controls)
    telemetry = _telemetry_privacy_topology(risk_paths, controls, taint_paths)
    dependency_routes = _dependency_trust_routes(risk_paths)
    nodes, edges, relationship_omitted = _evidence_relationships(
        controls=controls,
        taint_paths=taint_paths,
        artifact_parity=artifact_parity,
        traceability=traceability,
        mutations=mutations,
        telemetry=telemetry,
        dependency_routes=dependency_routes,
    )
    return {
        "schema_version": "1.0",
        "schema_id": "urn:project-py-security-suite:advanced-analysis:1.0",
        "authoritative": False,
        "purpose": (
            "Typed, bounded joins across static routes, scanner-confirmed taint paths, "
            "release artifacts, threats, controls, tests, mutations, telemetry sinks, "
            "and dependency trust evidence."
        ),
        "analysis_identity": {
            "source_sha256": str(
                _object(artifacts.get("source-inventory.json")).get("source_sha256")
                or ""
            ),
            "graph_source_sha256": str(
                _object(artifacts.get("graphify.json")).get("source_sha256") or ""
            ),
            "artifact_sha256": sorted(
                str(item.get("sha256"))
                for item in _objects(
                    _object(artifacts.get("artifact-manifest.json")).get("artifacts"),
                    _MAX_RECORDS,
                )
                if item.get("sha256")
            ),
        },
        "summary": {
            "relationship_nodes": len(nodes),
            "relationship_edges": len(edges),
            "control_points": len(controls),
            "mandatory_control_points": sum(
                item["topology_status"] == "mandatory" for item in controls
            ),
            "bypass_capable_control_points": sum(
                item["topology_status"] == "bypass-capable" for item in controls
            ),
            "shared_mandatory_security_route_points": sum(
                item["shared_mandatory_security_route_point"] for item in controls
            ),
            "scanner_confirmed_taint_paths": len(taint_paths),
            "retained_taint_steps": sum(len(item["steps"]) for item in taint_paths),
            "distribution_artifacts": len(artifact_parity),
            "published_entry_points": sum(
                len(item["published_entry_points"]) for item in artifact_parity
            ),
            "unmodeled_published_entry_points": sum(
                int(item["summary"]["unmodeled_entry_points"])
                for item in artifact_parity
            ),
            "wheel_record_integrity_gaps": sum(
                int(item["summary"]["record_integrity_gaps"])
                for item in artifact_parity
            ),
            "threat_control_test_records": len(traceability),
            "threats_without_control_evidence": sum(
                not item["control_point_ids"] for item in traceability
            ),
            "threats_without_test_evidence": sum(
                not item["test_files"] for item in traceability
            ),
            "security_control_mutations": len(mutations),
            "security_control_mutations_without_test_evidence": sum(
                not item["test_files"] for item in mutations
            ),
            "telemetry_privacy_routes": len(telemetry),
            "telemetry_routes_without_observed_protection": sum(
                item["protection_status"] in {"not-observed", "none", "unknown"}
                for item in telemetry
            ),
            "telemetry_routes_with_redaction_order_risk": sum(
                item["redaction_order"]
                in {
                    "export-before-redaction",
                    "redaction-not-on-all-confirmed-paths",
                }
                for item in telemetry
            ),
            "dependency_trust_routes": len(dependency_routes),
            "elevated_dependency_trust_routes": sum(
                item["review_tier"] in {"critical", "high"}
                for item in dependency_routes
            ),
        },
        "evidence_graph": {"nodes": nodes, "edges": edges},
        "control_topology": controls,
        "taint_paths": taint_paths,
        "artifact_route_parity": artifact_parity,
        "threat_control_test_traceability": traceability,
        "security_mutation_leverage": mutations,
        "telemetry_privacy_topology": telemetry,
        "dependency_trust_routes": dependency_routes,
        "truncation": {
            "relationship_items_omitted": relationship_omitted,
            "analysis_record_limit": _MAX_RECORDS,
        },
        "limitations": [
            "Structural dominance means every retained Graphify file path crosses a file; it does not prove that the file enforces a security control.",
            "A bypass-capable candidate means an alternate static file path exists; it does not prove runtime reachability or exploitability.",
            "Taint paths are scanner-confirmed only when the contributing adapter retained native path steps.",
            "Published artifact entry points are metadata-defined activation surfaces; plugin loading remains application dependent.",
            "Missing runtime, test, mutation, threat, or artifact evidence remains unknown and is never evidence of safety.",
        ],
    }


def _control_topology(
    artifacts: dict[str, Any], risk_paths: dict[str, Any]
) -> list[dict[str, Any]]:
    adjacency = _graph_adjacency(artifacts.get("graphify.json"))
    entry_paths = _entry_path_index(artifacts.get("reachability.json"))
    routes = _objects(risk_paths.get("routes"), _MAX_RECORDS)
    campaigns = {
        str(item.get("campaign_id")): item
        for item in _objects(risk_paths.get("validation_campaigns"), _MAX_RECORDS)
        if item.get("campaign_id")
    }
    hotspots = {
        str(item.get("hotspot_id")): item
        for item in _objects(risk_paths.get("convergence_hotspots"), _MAX_RECORDS)
        if item.get("hotspot_id")
    }
    observations = _control_observations(
        routes, campaigns, hotspots, adjacency, entry_paths
    )
    result = [
        _control_record(path, status, raw)
        for (path, status), raw in observations.items()
    ]
    return sorted(
        result,
        key=lambda item: (
            {
                "bypass-capable": 0,
                "not-established": 1,
                "mandatory": 2,
                "not-on-retained-route": 3,
            }.get(str(item["topology_status"]), 4),
            not bool(item["shared_mandatory_security_route_point"]),
            str(item["path"]),
        ),
    )[:_MAX_RECORDS]


def _control_observations(
    routes: list[dict[str, Any]],
    campaigns: dict[str, dict[str, Any]],
    hotspots: dict[str, dict[str, Any]],
    adjacency: dict[str, set[str]],
    entry_paths: dict[str, set[str]],
) -> dict[tuple[str, str], dict[str, Any]]:
    observations: dict[tuple[str, str], dict[str, Any]] = {}
    dominator_cache: dict[tuple[str, ...], dict[str, str]] = {}
    for route in routes:
        target = _object(route.get("target"))
        target_path = _path(target.get("path"))
        target_id = str(target.get("id") or "")
        if not target_path or not target_id:
            continue
        route_roots, entry_mapping_complete = _route_entry_paths(route, entry_paths)
        root_key = tuple(route_roots)
        if root_key not in dominator_cache:
            dominator_cache[root_key] = _immediate_dominators(adjacency, route_roots)
        idom = dominator_cache[root_key]
        dominance_established = (
            entry_mapping_complete and bool(route_roots) and target_path in idom
        )
        dominators = (
            set(_dominator_chain(idom, target_path)) if dominance_established else set()
        )
        route_files = {
            path
            for exposure in _objects(route.get("entry_point_exposures"), 100)
            for value in _strings(exposure.get("files"), 25)
            if (path := _path(value))
        }
        for path, candidate in _candidate_control_points(
            route, campaigns, hotspots
        ).items():
            status = (
                "not-established"
                if not dominance_established
                else "mandatory"
                if path in dominators
                else "bypass-capable"
                if path in route_files
                else "not-on-retained-route"
            )
            _observe_control(
                observations,
                path=path,
                status=status,
                candidate=candidate,
                route=route,
                target=target,
                target_id=target_id,
                target_path=target_path,
                campaigns=campaigns,
            )
    return observations


def _candidate_control_points(
    route: dict[str, Any],
    campaigns: dict[str, dict[str, Any]],
    hotspots: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    candidates: dict[str, dict[str, Any]] = {}
    for campaign_id in _strings(route.get("validation_campaign_ids"), 100):
        campaign = campaigns.get(campaign_id)
        hotspot = hotspots.get(
            str(campaign.get("hotspot_id") or "") if campaign else ""
        )
        if not campaign or not hotspot or hotspot.get("kind") != "shared-transit":
            continue
        if path := _path(campaign.get("path")):
            candidates[path] = {
                "campaign_ids": [campaign_id],
                "hotspot_ids": [str(hotspot["hotspot_id"])],
                "candidate_basis": "validation-campaign-control-point",
            }
    for hotspot_id in _strings(route.get("convergence_hotspot_ids"), 100):
        hotspot = hotspots.get(hotspot_id)
        if not hotspot or hotspot.get("kind") != "shared-transit":
            continue
        if path := _path(hotspot.get("path")):
            record = candidates.setdefault(
                path,
                {
                    "campaign_ids": [],
                    "hotspot_ids": [],
                    "candidate_basis": "shared-route-control-point",
                },
            )
            record["hotspot_ids"].append(hotspot_id)
    return candidates


def _observe_control(
    observations: dict[tuple[str, str], dict[str, Any]],
    *,
    path: str,
    status: str,
    candidate: dict[str, Any],
    route: dict[str, Any],
    target: dict[str, Any],
    target_id: str,
    target_path: str,
    campaigns: dict[str, dict[str, Any]],
) -> None:
    item = observations.setdefault(
        (path, status),
        {
            "candidate_bases": set(),
            "route_ids": set(),
            "target_ids": set(),
            "target_paths": set(),
            "entry_point_ids": set(),
            "campaign_ids": set(),
            "hotspot_ids": set(),
            "security_target_ids": set(),
            "test_files": set(),
            "candidate_test_files": set(),
            "test_evidence_statuses": set(),
            "owners": set(),
        },
    )
    item["candidate_bases"].add(candidate["candidate_basis"])
    item["route_ids"].add(str(route.get("route_id") or ""))
    item["target_ids"].add(target_id)
    item["target_paths"].add(target_path)
    if str(target.get("domain") or "") in {"security", "supply-chain"}:
        item["security_target_ids"].add(target_id)
    item["entry_point_ids"].update(
        str(entry["id"])
        for exposure in _objects(route.get("entry_point_exposures"), 100)
        if (entry := _object(exposure.get("entry_point"))).get("id")
    )
    item["campaign_ids"].update(candidate["campaign_ids"])
    item["hotspot_ids"].update(candidate["hotspot_ids"])
    item["owners"].update(_strings(route.get("owners"), 100))
    for campaign_id in candidate["campaign_ids"]:
        campaign = campaigns.get(campaign_id)
        if not campaign:
            continue
        assurance = _campaign_test_assurance([campaign])
        item["candidate_test_files"].update(assurance["candidate_test_files"])
        item["test_files"].update(assurance["verified_test_files"])
        item["test_evidence_statuses"].add(assurance["status"])


def _control_record(path: str, status: str, raw: dict[str, Any]) -> dict[str, Any]:
    security_targets = sorted(raw["security_target_ids"])
    shared_security_point = status == "mandatory" and len(security_targets) > 1
    return {
        "control_point_id": "control-" + _digest({"path": path, "status": status})[:16],
        "path": path,
        "topology_status": status,
        "candidate_bases": sorted(raw["candidate_bases"]),
        "route_ids": sorted(value for value in raw["route_ids"] if value),
        "target_ids": sorted(raw["target_ids"]),
        "target_paths": sorted(raw["target_paths"]),
        "entry_point_ids": sorted(raw["entry_point_ids"]),
        "campaign_ids": sorted(raw["campaign_ids"]),
        "hotspot_ids": sorted(raw["hotspot_ids"]),
        "security_target_ids": security_targets,
        "shared_mandatory_security_route_point": shared_security_point,
        "candidate_test_files": sorted(raw["candidate_test_files"]),
        "test_files": sorted(raw["test_files"]),
        "test_evidence_statuses": sorted(raw["test_evidence_statuses"]),
        "owners": sorted(raw["owners"]),
        "recommended_action": _control_action(status, shared_security_point),
        "evidence_artifacts": sorted(
            {
                "graphify.json",
                "reachability.json",
                "risk-paths.json",
                *(("junit-summary.json",) if raw["test_files"] else ()),
            }
        ),
        "interpretation": (
            "Route-scoped file-level graph dominance across the exact entry IDs "
            "retained for each route. Security-control behavior must be verified "
            "from implementation and scanner or test evidence. A selected test is "
            "only candidate evidence; retained test_files are source-bound, complete, "
            "case-level passing observations and do not prove security-test intent."
            if status != "not-established"
            else "Route-scoped dominance was not established because the retained "
            "entry identity could not be mapped to a graph root or the target was "
            "not reachable from that root in the retained Graphify topology."
        ),
    }


def _control_action(status: str, single_point: bool) -> str:
    if status == "bypass-capable":
        return (
            "Review the alternate Graphify paths and place enforcement at a common "
            "dominator or prove each branch applies an equivalent control with focused tests."
        )
    if single_point:
        return (
            "Treat this mandatory shared security-route point as critical integration "
            "scope: verify any intended controls, assign an owner, and require focused, "
            "negative, fuzz, and mutation evidence."
        )
    if status == "mandatory":
        return (
            "Verify whether this structurally mandatory integration point is intended "
            "to enforce a control; if so, bind focused tests to every protected route."
        )
    if status == "not-established":
        return (
            "Reconcile the route's exact entry ID with reachability and Graphify, then "
            "recompute dominance before treating the candidate as mandatory or bypassable."
        )
    return "Resolve why the candidate control is absent from retained entry-to-target routes."


def _taint_paths(
    findings: list[Finding], risk_paths: dict[str, Any]
) -> list[dict[str, Any]]:
    route_by_finding = {
        str(target.get("finding_id")): route
        for route in _objects(risk_paths.get("routes"), _MAX_RECORDS)
        if (target := _object(route.get("target"))).get("finding_id")
    }
    result: list[dict[str, Any]] = []
    for finding in findings:
        raw_flows = finding.evidence.get("sarif_code_flows")
        if not isinstance(raw_flows, list):
            continue
        route = route_by_finding.get(finding.finding_id, {})
        for flow_index, flow in enumerate(raw_flows[:10]):
            if not isinstance(flow, dict):
                continue
            steps = [_taint_step(step) for step in _objects(flow.get("steps"), 100)]
            if len(steps) < 2:
                continue
            semantic_basis = _taint_semantic_basis(flow, steps)
            if semantic_basis == "unclassified-code-flow":
                continue
            endpoints = _taint_endpoints(steps)
            if endpoints is None:
                continue
            source_index, sink_index = endpoints
            source = steps[source_index]
            sink = steps[sink_index]
            route_alignment = _taint_route_alignment(
                finding,
                route,
                steps[source_index : sink_index + 1],
                source,
                sink,
            )
            result.append(
                {
                    "taint_path_id": "taint-"
                    + _digest(
                        {
                            "finding": finding.finding_id,
                            "flow": flow_index,
                            "steps": [(step["path"], step["line"]) for step in steps],
                        }
                    )[:16],
                    "finding_id": finding.finding_id,
                    "tool": str(flow.get("tool") or _first_tool(finding)),
                    "rule_ids": sorted({source.rule_id for source in finding.sources}),
                    "classification": "scanner-confirmed-source-to-sink",
                    "route_id": route.get("route_id"),
                    "route_alignment": route_alignment,
                    "source": source,
                    "sink": sink,
                    "steps": steps,
                    "steps_omitted": max(
                        0, int(flow.get("step_count") or len(steps)) - len(steps)
                    ),
                    "citations": [
                        {
                            "kind": citation.kind,
                            "identifier": citation.identifier,
                            "title": citation.title,
                            "uri": citation.uri,
                        }
                        for citation in finding.citations[:10]
                    ],
                    "recommended_action": (
                        "Review the complete scanner-confirmed source-to-sink path, "
                        "place validation or sanitization before the sink, and bind a "
                        "negative regression test to the cited source and sink."
                        if route_alignment == "aligned"
                        else "Review the native scanner flow independently and do not "
                        "treat the retained entry-route model as corroboration. Reconcile "
                        "the exact source, sink, and ordered intermediate files before "
                        "using route reachability or validation evidence to prioritize it."
                    ),
                    "evidence_artifacts": ["findings.json", "risk-paths.json"],
                }
            )
    return result[:_MAX_RECORDS]


def _taint_step(step: dict[str, Any]) -> dict[str, Any]:
    sequence = step.get("sequence")
    execution_order = step.get("execution_order")
    nesting_level = step.get("nesting_level")
    return {
        "path": _path(step.get("path")) or "<repository>",
        "line": step.get("line") if isinstance(step.get("line"), int) else None,
        "message": str(step.get("message") or "")[:500],
        "sequence": sequence
        if isinstance(sequence, int) and not isinstance(sequence, bool)
        else None,
        "execution_order": execution_order
        if isinstance(execution_order, int) and not isinstance(execution_order, bool)
        else None,
        "nesting_level": nesting_level
        if isinstance(nesting_level, int) and not isinstance(nesting_level, bool)
        else None,
        "importance": str(step.get("importance") or "")[:100],
        "kinds": sorted(set(_strings(step.get("kinds"), 10))),
    }


def _taint_endpoints(steps: list[dict[str, Any]]) -> tuple[int, int] | None:
    source_markers = [
        index for index, step in enumerate(steps) if "source" in _taint_kinds(step)
    ]
    sink_markers = [
        index for index, step in enumerate(steps) if "sink" in _taint_kinds(step)
    ]
    source_index = source_markers[0] if source_markers else 0
    sink_index = sink_markers[-1] if sink_markers else len(steps) - 1
    return (source_index, sink_index) if source_index < sink_index else None


def _taint_semantic_basis(flow: dict[str, Any], steps: list[dict[str, Any]]) -> str:
    declared = str(flow.get("semantic_basis") or "").strip().casefold()
    if declared in {"native-source-sink-kinds", "security-path-problem"}:
        return declared
    source_positions = [
        index for index, step in enumerate(steps) if "source" in _taint_kinds(step)
    ]
    sink_positions = [
        index for index, step in enumerate(steps) if "sink" in _taint_kinds(step)
    ]
    if source_positions and sink_positions and source_positions[0] < sink_positions[-1]:
        return "native-source-sink-kinds"
    return "unclassified-code-flow"


def _taint_kinds(step: dict[str, Any]) -> set[str]:
    return {value.casefold() for value in _strings(step.get("kinds"), 10)}


def _taint_route_alignment(
    finding: Finding,
    route: dict[str, Any],
    steps: list[dict[str, Any]],
    source: dict[str, Any],
    sink: dict[str, Any],
) -> str:
    if not route or not _sink_matches_finding(finding, sink):
        return "not-established"
    flow_paths = _consecutive_paths(steps)
    if (
        not flow_paths
        or flow_paths[0] != source["path"]
        or flow_paths[-1] != sink["path"]
    ):
        return "not-established"
    for exposure in _objects(route.get("entry_point_exposures"), 100):
        route_paths = [
            path
            for value in _strings(exposure.get("files"), 100)
            if (path := _path(value))
        ]
        if _is_ordered_subsequence(flow_paths, route_paths):
            return "aligned"
    return "not-established"


def _sink_matches_finding(finding: Finding, sink: dict[str, Any]) -> bool:
    sink_path = str(sink.get("path") or "")
    sink_line = sink.get("line")
    for location in finding.locations:
        if location.path != sink_path:
            continue
        if (
            location.start_line is None
            or not isinstance(sink_line, int)
            or isinstance(sink_line, bool)
            or location.start_line == sink_line
        ):
            return True
    return False


def _consecutive_paths(steps: list[dict[str, Any]]) -> list[str]:
    paths: list[str] = []
    for step in steps:
        path = str(step.get("path") or "")
        if not path or path == "<repository>":
            return []
        if not paths or paths[-1] != path:
            paths.append(path)
    return paths


def _is_ordered_subsequence(values: list[str], sequence: list[str]) -> bool:
    if not values or not sequence:
        return False
    position = 0
    for candidate in sequence:
        if candidate == values[position]:
            position += 1
            if position == len(values):
                return True
    return False


def _artifact_route_parity(
    target: Path, artifacts: dict[str, Any], risk_paths: dict[str, Any]
) -> list[dict[str, Any]]:
    manifest = _object(artifacts.get("artifact-manifest.json"))
    graph_paths = {
        path
        for node in _objects(
            _object(artifacts.get("graphify.json")).get("nodes"), 250_000
        )
        if (path := _path(node.get("path")))
    }
    modeled_paths = {
        path
        for entry in _objects(
            _object(artifacts.get("reachability.json")).get("entry_points"), 500
        )
        if (path := _path(entry.get("path")))
    }
    result: list[dict[str, Any]] = []
    for record in _objects(manifest.get("artifacts"), _MAX_RECORDS):
        relative = _path(record.get("path"))
        if not relative or not relative.casefold().endswith(".whl"):
            continue
        candidate = resolve_unlinked_path(
            target / Path(relative), "distribution artifact", boundary=target
        )
        if not candidate.is_file():
            continue
        try:
            result.append(
                _wheel_route_parity(
                    candidate,
                    relative,
                    expected_sha256=str(record.get("sha256") or ""),
                    graph_paths=graph_paths,
                    modeled_paths=modeled_paths,
                    risk_paths_available=bool(risk_paths),
                )
            )
        except (
            OSError,
            RuntimeError,
            ValueError,
            zipfile.BadZipFile,
            configparser.Error,
        ) as exc:
            result.append(
                {
                    "artifact": relative,
                    "artifact_sha256": str(record.get("sha256") or ""),
                    "analysis_status": "invalid-or-unreadable",
                    "error": str(exc)[:500],
                    "published_entry_points": [],
                    "record_gaps": [],
                    "summary": {
                        "members": 0,
                        "entry_points": 0,
                        "unmodeled_entry_points": 0,
                        "record_integrity_gaps": 1,
                    },
                    "recommended_action": (
                        "Rebuild the wheel in the governed release lane and rerun "
                        "artifact route-parity analysis."
                    ),
                    "evidence_artifacts": ["artifact-manifest.json"],
                }
            )
    return result[:_MAX_RECORDS]


def _wheel_route_parity(
    wheel: Path,
    relative: str,
    *,
    expected_sha256: str,
    graph_paths: set[str],
    modeled_paths: set[str],
    risk_paths_available: bool,
) -> dict[str, Any]:
    actual_sha256 = _file_sha256(wheel)
    if expected_sha256 and actual_sha256 != expected_sha256.casefold():
        raise ValueError("wheel does not match artifact-manifest SHA-256")
    with zipfile.ZipFile(wheel) as archive:
        infos = archive.infolist()
        if len(infos) > _MAX_WHEEL_MEMBERS:
            raise ValueError("wheel member count exceeds analysis limit")
        names = {info.filename for info in infos}
        entry_names = sorted(
            name for name in names if name.endswith(".dist-info/entry_points.txt")
        )
        entry_points: list[dict[str, Any]] = []
        for name in entry_names[:10]:
            raw = _read_zip_member(archive, name)
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.read_string(raw.decode("utf-8"))
            for group in parser.sections():
                for name_value, target_value in parser.items(group):
                    module = target_value.split(":", maxsplit=1)[0].strip()
                    candidate_paths = _module_paths(module)
                    modeled = sorted(set(candidate_paths) & modeled_paths)
                    graphed = sorted(set(candidate_paths) & graph_paths)
                    status = (
                        "modeled-entry-point"
                        if modeled
                        else "graph-member-not-entry-modeled"
                        if graphed
                        else "module-not-in-source-graph"
                    )
                    entry_points.append(
                        {
                            "group": group[:200],
                            "name": name_value[:200],
                            "target": target_value[:500],
                            "module": module[:300],
                            "candidate_source_paths": candidate_paths,
                            "modeled_paths": modeled,
                            "graph_paths": graphed,
                            "activation_kind": (
                                "executable"
                                if group in {"console_scripts", "gui_scripts"}
                                else "plugin"
                            ),
                            "parity_status": status,
                            "recommended_action": _entry_point_action(status, group),
                        }
                    )
        record_names = sorted(
            info.filename
            for info in infos
            if info.filename.endswith(".dist-info/RECORD")
        )
        record_gaps = _wheel_member_integrity_gaps(infos)
        if len(record_names) != 1:
            record_gaps.append(
                {
                    "kind": "record-count",
                    "detail": f"expected one RECORD, found {len(record_names)}",
                }
            )
        else:
            record_gaps.extend(_record_integrity_gaps(archive, record_names[0], names))
    unmodeled = sum(
        item["parity_status"] != "modeled-entry-point" for item in entry_points
    )
    return {
        "artifact": relative,
        "artifact_sha256": actual_sha256,
        "analysis_status": "complete",
        "published_entry_points": entry_points[:_MAX_RECORDS],
        "record_gaps": record_gaps[:_MAX_RECORDS],
        "summary": {
            "members": len(infos),
            "entry_points": len(entry_points),
            "unmodeled_entry_points": unmodeled,
            "record_integrity_gaps": len(record_gaps),
        },
        "recommended_action": (
            "Model every production executable or plugin activation surface and "
            "resolve every RECORD identity gap before promotion."
            if unmodeled or record_gaps
            else "Retain artifact identity and entry-point parity evidence with the release."
        ),
        "evidence_artifacts": sorted(
            {
                "artifact-manifest.json",
                *(("risk-paths.json",) if risk_paths_available else ()),
            }
        ),
    }


def _wheel_member_integrity_gaps(
    infos: list[zipfile.ZipInfo],
) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    names: dict[str, int] = defaultdict(int)
    casefolded: dict[str, set[str]] = defaultdict(set)
    total_uncompressed = 0
    for info in infos:
        name = info.filename
        names[name] += 1
        casefolded[name.casefold()].add(name)
        total_uncompressed += max(0, info.file_size)
        components = name.split("/")
        checked_components = components[:-1] if name.endswith("/") else components
        unsafe_reason = (
            "absolute-or-drive-qualified"
            if name.startswith(("/", "\\")) or re.match(r"^[a-zA-Z]:", name)
            else "backslash-separator"
            if "\\" in name
            else "dot-or-empty-component"
            if any(component in {"", ".", ".."} for component in checked_components)
            else None
        )
        if unsafe_reason:
            gaps.append(
                {
                    "kind": "unsafe-member-name",
                    "path": name[:500],
                    "detail": unsafe_reason,
                }
            )
        unix_mode = (info.external_attr >> 16) & 0o170000
        if unix_mode == 0o120000:
            gaps.append({"kind": "symbolic-link-member", "path": name[:500]})
        if info.flag_bits & 0x1:
            gaps.append({"kind": "encrypted-member", "path": name[:500]})
        if info.file_size > _MAX_MEMBER_BYTES:
            gaps.append(
                {
                    "kind": "member-analysis-size-limit",
                    "path": name[:500],
                    "size_bytes": info.file_size,
                }
            )
        if info.file_size >= 1024 * 1024 and (
            info.compress_size == 0 or info.file_size / info.compress_size > 1000
        ):
            gaps.append(
                {
                    "kind": "suspicious-compression-ratio",
                    "path": name[:500],
                    "uncompressed_bytes": info.file_size,
                    "compressed_bytes": info.compress_size,
                }
            )
    gaps.extend(
        {
            "kind": "duplicate-member-name",
            "path": name[:500],
            "occurrences": count,
        }
        for name, count in sorted(names.items())
        if count > 1
    )
    gaps.extend(
        {
            "kind": "case-colliding-members",
            "paths": sorted(values)[:20],
        }
        for values in sorted(casefolded.values(), key=lambda item: sorted(item))
        if len(values) > 1
    )
    if total_uncompressed > _MAX_WHEEL_UNCOMPRESSED_BYTES:
        gaps.append(
            {
                "kind": "wheel-uncompressed-size-limit",
                "uncompressed_bytes": total_uncompressed,
                "limit_bytes": _MAX_WHEEL_UNCOMPRESSED_BYTES,
            }
        )
    return gaps[:_MAX_RECORDS]


def _record_integrity_gaps(
    archive: zipfile.ZipFile, record_name: str, members: set[str]
) -> list[dict[str, Any]]:
    raw = _read_zip_member(archive, record_name)
    rows = list(csv.reader(io.StringIO(raw.decode("utf-8"))))
    if len(rows) > _MAX_WHEEL_MEMBERS:
        raise ValueError("wheel RECORD exceeds analysis limit")
    recorded: set[str] = set()
    gaps: list[dict[str, Any]] = []
    for row in rows:
        if len(row) != 3 or not row[0]:
            gaps.append(
                {
                    "kind": "malformed-record-row",
                    "detail": "RECORD row is not path, hash, size",
                }
            )
            continue
        name, digest_value, size_value = row
        if name in recorded:
            gaps.append({"kind": "duplicate-record-row", "path": name[:500]})
        recorded.add(name)
        if name not in members:
            gaps.append({"kind": "record-member-missing", "path": name[:500]})
            continue
        info = archive.getinfo(name)
        signature = name.endswith((".dist-info/RECORD.jws", ".dist-info/RECORD.p7s"))
        if name == record_name:
            if digest_value or size_value:
                gaps.append(
                    {"kind": "record-self-metadata-present", "path": name[:500]}
                )
            continue
        if not size_value and not signature:
            gaps.append({"kind": "missing-record-size", "path": name[:500]})
        elif size_value:
            try:
                expected_size = int(size_value)
            except ValueError:
                gaps.append({"kind": "invalid-record-size", "path": name[:500]})
            else:
                if expected_size < 0:
                    gaps.append({"kind": "invalid-record-size", "path": name[:500]})
                elif expected_size != info.file_size:
                    gaps.append({"kind": "record-size-mismatch", "path": name[:500]})
        if not digest_value and not signature:
            gaps.append({"kind": "missing-record-hash", "path": name[:500]})
        elif digest_value:
            algorithm, separator, encoded = digest_value.partition("=")
            algorithm = algorithm.casefold()
            if (
                separator != "="
                or algorithm not in _RECORD_HASH_ALGORITHMS
                or not encoded
            ):
                gaps.append({"kind": "unsupported-record-hash", "path": name[:500]})
            elif info.file_size <= _MAX_MEMBER_BYTES:
                actual = (
                    base64.urlsafe_b64encode(
                        hashlib.new(algorithm, _read_zip_member(archive, name)).digest()
                    )
                    .rstrip(b"=")
                    .decode("ascii")
                )
                if actual != encoded:
                    gaps.append({"kind": "record-hash-mismatch", "path": name[:500]})
    unsigned = {
        name
        for name in members - recorded
        if not name.endswith((".dist-info/RECORD.jws", ".dist-info/RECORD.p7s"))
    }
    gaps.extend(
        {"kind": "unrecorded-member", "path": name[:500]}
        for name in sorted(unsigned)[:_MAX_RECORDS]
    )
    return gaps[:_MAX_RECORDS]


def _entry_point_action(status: str, group: str) -> str:
    if status == "modeled-entry-point":
        return "Retain this published activation surface in reachability and regression baselines."
    if status == "graph-member-not-entry-modeled":
        return (
            "Add the published target as a declared entry point or document why the "
            f"{group} activation surface is not production reachable."
        )
    return (
        "Reconcile the built wheel with reviewed source; the published target is absent "
        "from the retained source graph."
    )


def _threat_control_test_traceability(
    findings: list[Finding],
    risk_paths: dict[str, Any],
    controls: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    controls_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for control in controls:
        for target_path_value in _strings(control.get("target_paths"), 100):
            controls_by_path[target_path_value].append(control)
    campaigns_by_id = {
        str(campaign.get("campaign_id")): campaign
        for campaign in _objects(risk_paths.get("validation_campaigns"), _MAX_RECORDS)
        if campaign.get("campaign_id")
    }
    result: list[dict[str, Any]] = []
    for finding in findings:
        if "pytm" not in {source.tool for source in finding.sources}:
            continue
        finding_path = _path(finding.locations[0].path) if finding.locations else None
        path_controls = controls_by_path.get(finding_path or "", [])
        campaign_ids = sorted(
            {
                campaign_id
                for control in path_controls
                for campaign_id in _strings(control.get("campaign_ids"), 100)
            }
        )
        campaigns = [
            campaigns_by_id[campaign_id]
            for campaign_id in campaign_ids
            if campaign_id in campaigns_by_id
        ]
        test_assurance = _campaign_test_assurance(campaigns)
        candidate_tests = test_assurance["candidate_test_files"]
        verified_tests = test_assurance["verified_test_files"]
        result.append(
            {
                "traceability_id": "trace-"
                + _digest({"finding": finding.finding_id, "path": finding_path})[:16],
                "threat_finding_id": finding.finding_id,
                "path": finding_path or "<repository>",
                "line": finding.locations[0].start_line if finding.locations else None,
                "title": finding.title[:500],
                "classifications": list(finding.classifications)[:50],
                "control_point_ids": sorted(
                    str(item["control_point_id"]) for item in path_controls
                ),
                "control_statuses": sorted(
                    {str(item["topology_status"]) for item in path_controls}
                ),
                "campaign_ids": campaign_ids,
                "candidate_test_files": candidate_tests,
                "verified_test_files": verified_tests,
                "test_files": verified_tests,
                "test_evidence_status": test_assurance["status"],
                "test_execution_sources": test_assurance["execution_sources"],
                "source_revision_bindings": test_assurance["revision_bindings"],
                "semantic_test_intent": "not-established",
                "closure_status": (
                    "threat-without-control-evidence"
                    if not path_controls
                    else "mapped-control-and-source-bound-passing-test-candidate"
                    if verified_tests
                    else "control-without-current-passing-test-evidence"
                    if candidate_tests
                    else "control-without-test-candidate"
                ),
                "owners": sorted(
                    {
                        owner
                        for item in path_controls
                        for owner in _strings(item.get("owners"), 100)
                    }
                ),
                "recommended_action": (
                    "Review the threat, verify an exact enforcing control, and bind a "
                    "negative or abuse-case assertion to a source-bound passing test. "
                    "Selection and execution alone do not establish security-test intent."
                ),
                "evidence_artifacts": sorted(
                    {
                        "findings.json",
                        "risk-paths.json",
                        "pytm-summary.json",
                        *test_assurance["execution_sources"],
                    }
                ),
            }
        )
    return result[:_MAX_RECORDS]


def _campaign_test_assurance(
    campaigns: list[dict[str, Any]],
) -> dict[str, Any]:
    candidate_tests: set[str] = set()
    verified_tests: set[str] = set()
    focused_statuses: set[str] = set()
    revision_bindings: set[str] = set()
    execution_sources: set[str] = set()
    for campaign in campaigns:
        selected = set(_strings(campaign.get("selected_test_files"), 100))
        candidate_tests.update(selected)
        focused_status = str(
            campaign.get("focused_test_validation_status") or "not-available"
        )
        focused_statuses.add(focused_status)
        snapshot = _object(campaign.get("source_snapshot"))
        revision = str(snapshot.get("evidence_revision_binding") or "not-established")
        revision_bindings.add(revision)
        execution_sources.update(_strings(campaign.get("test_execution_sources"), 10))
        selected_bound = snapshot.get("selected_test_files_bound")
        source_bound = (
            revision == "aligned"
            and isinstance(selected_bound, int)
            and not isinstance(selected_bound, bool)
            and selected_bound == len(selected)
            and not _strings(snapshot.get("selected_test_files_missing"), 100)
        )
        execution_by_path = {
            str(item.get("path") or ""): str(item.get("status") or "")
            for item in _objects(campaign.get("focused_test_execution"), 100)
            if item.get("path")
        }
        if (
            selected
            and focused_status == "passed"
            and campaign.get("test_case_inventory_complete") is True
            and source_bound
        ):
            verified_tests.update(
                test for test in selected if execution_by_path.get(test) == "passed"
            )
    status = (
        "not-selected"
        if not candidate_tests
        else "source-bound-passing"
        if verified_tests == candidate_tests
        else "partially-source-bound-passing"
        if verified_tests
        else "failed"
        if "failed" in focused_statuses
        else "source-revision-mismatch"
        if "mismatch" in revision_bindings
        else "execution-or-binding-not-established"
    )
    return {
        "status": status,
        "candidate_test_files": sorted(candidate_tests)[:100],
        "verified_test_files": sorted(verified_tests)[:100],
        "focused_statuses": sorted(focused_statuses),
        "revision_bindings": sorted(revision_bindings),
        "execution_sources": sorted(execution_sources),
    }


def _security_mutation_leverage(
    findings: list[Finding],
    risk_paths: dict[str, Any],
    controls: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    controls_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for control in controls:
        controls_by_path[str(control["path"])].append(control)
    campaign_tests: dict[str, set[str]] = defaultdict(set)
    for campaign in _objects(risk_paths.get("validation_campaigns"), _MAX_RECORDS):
        path = _path(campaign.get("path"))
        if path:
            campaign_tests[path].update(
                _strings(campaign.get("selected_test_files"), 100)
            )
    result: list[dict[str, Any]] = []
    for finding in findings:
        if "mutmut" not in {source.tool for source in finding.sources}:
            continue
        path = _path(finding.locations[0].path) if finding.locations else None
        if not path:
            continue
        matches = controls_by_path.get(path, [])
        control_like = bool(matches) or any(
            term in path.casefold() for term in _CONTROL_TERMS
        )
        if not control_like:
            continue
        campaign_records = [
            campaign
            for campaign in _objects(
                risk_paths.get("validation_campaigns"), _MAX_RECORDS
            )
            if _path(campaign.get("path")) == path
        ]
        test_assurance = _campaign_test_assurance(campaign_records)
        result.append(
            {
                "mutation_leverage_id": "mutation-"
                + _digest({"finding": finding.finding_id, "path": path})[:16],
                "finding_id": finding.finding_id,
                "path": path,
                "line": finding.locations[0].start_line,
                "control_point_ids": sorted(
                    str(item["control_point_id"]) for item in matches
                ),
                "topology_statuses": sorted(
                    {str(item["topology_status"]) for item in matches}
                ),
                "candidate_test_files": sorted(campaign_tests.get(path, set())),
                "verified_test_files": test_assurance["verified_test_files"],
                "test_files": test_assurance["verified_test_files"],
                "test_evidence_status": test_assurance["status"],
                "validation_signal": "surviving-security-control-mutation",
                "recommended_action": (
                    "Add a focused negative test that fails for this mutation, verify "
                    "the control protects every applicable route, and rerun mutmut."
                ),
                "evidence_artifacts": ["mutmut-summary.json", "risk-paths.json"],
            }
        )
    return result[:_MAX_RECORDS]


def _telemetry_privacy_topology(
    risk_paths: dict[str, Any],
    controls: list[dict[str, Any]],
    taint_paths: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    controls_by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for control in controls:
        for target_id in _strings(control.get("target_ids"), 100):
            controls_by_target[target_id].append(control)
    taint_by_finding: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for path in taint_paths:
        taint_by_finding[str(path.get("finding_id") or "")].append(path)
    result: list[dict[str, Any]] = []
    for route in _objects(risk_paths.get("sensitive_data_routes"), _MAX_RECORDS):
        family = str(route.get("sink_family") or "unknown").casefold()
        if family not in _TELEMETRY_FAMILIES:
            continue
        target_id = str(route.get("target_id") or "")
        finding_id = str(route.get("finding_id") or "")
        path_controls = controls_by_target.get(target_id, [])
        flows = taint_by_finding.get(finding_id, [])
        redaction = _redaction_assessment(flows)
        redaction_order = str(redaction["status"])
        control_flow = _control_flow_assessments(path_controls, flows)
        result.append(
            {
                "privacy_route_id": "privacy-"
                + _digest({"route": route.get("sensitive_route_id"), "family": family})[
                    :16
                ],
                "sensitive_route_id": route.get("sensitive_route_id"),
                "route_id": route.get("route_id"),
                "finding_id": route.get("finding_id"),
                "path": route.get("path"),
                "line": route.get("line"),
                "sink_family": family,
                "trust_boundary": str(route.get("trust_boundary") or "unknown"),
                "data_classes": _strings(route.get("data_classes"), 50),
                "protection_status": str(route.get("protection_status") or "unknown"),
                "entry_point_ids": _strings(route.get("entry_point_ids"), 100),
                "entry_point_exposure_count": int(
                    route.get("entry_point_exposure_count") or 0
                ),
                "control_point_ids": sorted(
                    str(item["control_point_id"]) for item in path_controls
                ),
                "mandatory_control_point_ids": sorted(
                    str(item["control_point_id"])
                    for item in path_controls
                    if item["topology_status"] == "mandatory"
                ),
                "bypass_capable_control_point_ids": sorted(
                    str(item["control_point_id"])
                    for item in path_controls
                    if item["topology_status"] == "bypass-capable"
                ),
                "taint_path_ids": sorted(str(item["taint_path_id"]) for item in flows),
                "redaction_order": redaction_order,
                "redaction_evidence_basis": redaction["evidence_basis"],
                "redaction_evidence_quality": redaction["evidence_quality"],
                "redaction_path_assessments": redaction["path_assessments"],
                "control_flow_assessments": control_flow,
                "control_point_ids_observed_before_sink": sorted(
                    str(item["control_point_id"])
                    for item in control_flow
                    if item["taint_path_ids_observed_before_sink"]
                ),
                "control_point_ids_observed_on_every_aligned_path": sorted(
                    str(item["control_point_id"])
                    for item in control_flow
                    if item["flow_observation_status"]
                    == "observed-on-every-aligned-path"
                ),
                "validation_status": str(
                    route.get("validation_status") or "not-assessed"
                ),
                "owners": _strings(route.get("owners"), 100),
                "review_status": _privacy_review_status(
                    route,
                    path_controls,
                    redaction_order,
                    str(redaction["evidence_quality"]),
                    control_flow,
                ),
                "recommended_action": (
                    "Ensure minimization and redaction dominate every exporter path, "
                    "disable unnecessary header and URL-query capture, and bind a "
                    "synthetic sensitive-data canary test to each exporter branch."
                ),
                "citations": _objects(route.get("citations"), 20),
                "evidence_artifacts": sorted(
                    {"risk-paths.json", *(("findings.json",) if flows else ())}
                ),
            }
        )
    return result[:_MAX_RECORDS]


def _redaction_assessment(flows: list[dict[str, Any]]) -> dict[str, Any]:
    path_assessments: list[dict[str, Any]] = []
    for flow in flows:
        if flow.get("route_alignment") != "aligned":
            continue
        steps = _objects(flow.get("steps"), 100)
        endpoints = _taint_endpoints(steps)
        if endpoints is None:
            continue
        source_index, sink_index = endpoints
        markers = [
            (index, basis)
            for index, step in enumerate(steps)
            if (basis := _redaction_marker_basis(step)) is not None
        ]
        before = [
            (index, basis)
            for index, basis in markers
            if source_index < index < sink_index
        ]
        at_or_after = [
            (index, basis) for index, basis in markers if index >= sink_index
        ]
        incomplete = int(flow.get("steps_omitted") or 0) > 0
        if at_or_after:
            status = "export-before-redaction"
        elif before:
            status = "redaction-before-export"
        elif incomplete:
            status = "incomplete-path-evidence"
        else:
            status = "redaction-not-observed"
        path_assessments.append(
            {
                "taint_path_id": str(flow.get("taint_path_id") or ""),
                "status": status,
                "source_sequence": source_index,
                "sink_sequence": sink_index,
                "redaction_sequences": [index for index, _ in markers],
                "evidence_bases": sorted({basis for _, basis in markers}),
                "steps_omitted": int(flow.get("steps_omitted") or 0),
            }
        )
    statuses = {str(item["status"]) for item in path_assessments}
    if "export-before-redaction" in statuses:
        status = "export-before-redaction"
    elif statuses == {"redaction-before-export"}:
        status = "redaction-before-export"
    elif "redaction-before-export" in statuses and statuses - {
        "redaction-before-export"
    }:
        status = "redaction-not-on-all-confirmed-paths"
    else:
        status = "not-established"
    evidence_bases = sorted(
        {
            str(basis)
            for item in path_assessments
            for basis in _strings(item.get("evidence_bases"), 10)
        }
    )
    if status == "redaction-before-export" and all(
        "native-step-kind" in _strings(item.get("evidence_bases"), 10)
        for item in path_assessments
    ):
        evidence_quality = "native-on-every-aligned-path"
    elif evidence_bases:
        evidence_quality = "heuristic-or-partial"
    else:
        evidence_quality = "none"
    return {
        "status": status,
        "evidence_basis": evidence_bases or ["none"],
        "evidence_quality": evidence_quality,
        "path_assessments": path_assessments,
    }


def _redaction_marker_basis(step: dict[str, Any]) -> str | None:
    if _taint_kinds(step) & _NATIVE_REDACTION_KINDS:
        return "native-step-kind"
    value = f"{step.get('path', '')} {step.get('message', '')}".casefold()
    tokens = re.findall(r"[a-z0-9]+", value)
    if any(token.startswith(_REDACTION_TOKEN_PREFIXES) for token in tokens):
        return "heuristic-step-label"
    return None


def _control_flow_assessments(
    controls: list[dict[str, Any]], flows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    aligned: list[tuple[dict[str, Any], list[dict[str, Any]], int]] = []
    for flow in flows:
        if flow.get("route_alignment") != "aligned":
            continue
        steps = _objects(flow.get("steps"), 100)
        endpoints = _taint_endpoints(steps)
        if endpoints is not None:
            aligned.append((flow, steps, endpoints[1]))
    result: list[dict[str, Any]] = []
    for control in controls:
        control_path = str(control.get("path") or "")
        observed: list[str] = []
        not_observed: list[str] = []
        for flow, steps, sink_index in aligned:
            taint_path_id = str(flow.get("taint_path_id") or "")
            if any(
                str(step.get("path") or "") == control_path
                for step in steps[:sink_index]
            ):
                observed.append(taint_path_id)
            else:
                not_observed.append(taint_path_id)
        if not aligned:
            status = "not-established"
        elif observed and not not_observed:
            status = "observed-on-every-aligned-path"
        elif observed:
            status = "observed-on-some-aligned-paths"
        else:
            status = "not-observed-on-aligned-paths"
        result.append(
            {
                "control_point_id": str(control.get("control_point_id") or ""),
                "path": control_path,
                "topology_status": str(control.get("topology_status") or "unknown"),
                "flow_observation_status": status,
                "taint_path_ids_observed_before_sink": sorted(observed),
                "taint_path_ids_not_observed_before_sink": sorted(not_observed),
                "interpretation": (
                    "Exact file occurrence before the retained native sink; absence "
                    "does not prove runtime bypass because a scanner may omit "
                    "non-data-flow control frames."
                ),
            }
        )
    return result


def _privacy_review_status(
    route: dict[str, Any],
    controls: list[dict[str, Any]],
    redaction_order: str,
    redaction_evidence_quality: str,
    control_flow: list[dict[str, Any]],
) -> str:
    if redaction_order == "export-before-redaction":
        return "redaction-order-risk"
    if redaction_order == "redaction-not-on-all-confirmed-paths":
        return "redaction-path-gap"
    if str(route.get("protection_status") or "unknown") in {
        "not-observed",
        "none",
        "unknown",
    }:
        return "protection-gap"
    if any(item["topology_status"] == "bypass-capable" for item in controls):
        return "control-bypass-review"
    if not any(item["topology_status"] == "mandatory" for item in controls):
        return "mandatory-control-not-established"
    mandatory_ids = {
        str(item["control_point_id"])
        for item in controls
        if item["topology_status"] == "mandatory"
    }
    if any(
        str(item.get("control_point_id") or "") in mandatory_ids
        and item.get("flow_observation_status") != "observed-on-every-aligned-path"
        for item in control_flow
    ):
        return "control-flow-correlation-not-established"
    if redaction_order != "redaction-before-export":
        return "redaction-not-established"
    if redaction_evidence_quality != "native-on-every-aligned-path":
        return "redaction-effect-not-established"
    return "protected-static-route"


def _dependency_trust_routes(risk_paths: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for route in _objects(risk_paths.get("routes"), _MAX_RECORDS):
        target = _object(route.get("target"))
        if target.get("kind") != "dependency-advisory-import":
            continue
        context = _object(target.get("correlations"))
        lifecycle = _object(context.get("package_lifecycle"))
        assurance = _object(route.get("evidence_assurance"))
        artifact_exposure = _dependency_artifact_exposure(context, lifecycle)
        factors: list[str] = []
        if context.get("known_exploited") is True:
            factors.append("known-exploited")
        if context.get("epss_high") is True:
            factors.append("high-epss")
        if artifact_exposure["status"] == "affected-version-observed":
            factors.append("affected-version-observed-in-artifact")
        elif artifact_exposure["status"] == "package-observed-version-unresolved":
            factors.append("artifact-package-version-unresolved")
        elif artifact_exposure["status"] == "not-established":
            factors.append("artifact-composition-not-established")
        if artifact_exposure["status"] == "fixed-version-observed":
            factors.append("fixed-version-observed-in-artifact")
        if lifecycle.get("assessment") in {"version-drift", "artifact-only"}:
            factors.append(str(lifecycle["assessment"]))
        if assurance.get("review_status") != "assured":
            factors.append("scanner-assurance-gap")
        runtime = _object(route.get("runtime_context"))
        observations = _strings(runtime.get("observations"), 20)
        if "observed" in observations:
            factors.append("runtime-observed-importer")
        score = (
            4 * ("known-exploited" in factors)
            + 2 * ("high-epss" in factors)
            + 3 * ("affected-version-observed-in-artifact" in factors)
            + 1 * ("artifact-package-version-unresolved" in factors)
            + 1 * ("artifact-composition-not-established" in factors)
            + 2 * ("runtime-observed-importer" in factors)
            + 1 * ("scanner-assurance-gap" in factors)
        )
        tier = (
            "critical"
            if score >= 8
            else "high"
            if score >= 5
            else "medium"
            if score >= 2
            else "low"
        )
        result.append(
            {
                "dependency_trust_route_id": "dependency-trust-"
                + _digest({"route": route.get("route_id"), "target": target.get("id")})[
                    :16
                ],
                "route_id": route.get("route_id"),
                "target_id": target.get("id"),
                "path": target.get("path"),
                "package": context.get("package"),
                "primary_identifier": context.get("primary_identifier"),
                "identifiers": _strings(context.get("identifiers"), 100),
                "review_score": score,
                "review_tier": tier,
                "risk_factors": factors,
                "package_lifecycle": lifecycle,
                "artifact_exposure": artifact_exposure,
                "fix_available": context.get("fix_available") is True,
                "fixed_version_candidates": _strings(
                    context.get("fixed_version_candidates"), 50
                ),
                "validation_status": str(
                    _object(route.get("validation")).get("assessment_status")
                    or "not-assessed"
                ),
                "scanner_assurance_status": str(
                    assurance.get("review_status") or "not-assessed"
                ),
                "owners": _strings(route.get("owners"), 100),
                "recommended_action": (
                    "Confirm the exact affected package and importer, upgrade to an "
                    "approved fixed version, rebuild the final artifact, and validate "
                    "the retained entry route before closure."
                ),
                "evidence_artifacts": sorted(
                    {
                        "risk-paths.json",
                        "evidence-fusion.json",
                        *(_strings(lifecycle.get("evidence_artifacts"), 20)),
                    }
                ),
            }
        )
    return sorted(
        result,
        key=lambda item: (-int(item["review_score"]), str(item.get("package") or "")),
    )[:_MAX_RECORDS]


def _dependency_artifact_exposure(
    context: dict[str, Any], lifecycle: dict[str, Any]
) -> dict[str, Any]:
    advisory_versions = set(_strings(context.get("versions"), 50))
    artifact_versions = set(_strings(lifecycle.get("artifact_versions"), 50))
    fixed_versions = set(_strings(context.get("fixed_version_candidates"), 50))
    affected = sorted(advisory_versions & artifact_versions)
    fixed = sorted(fixed_versions & artifact_versions)
    assessment = str(lifecycle.get("assessment") or "not-established")
    comparison_available = lifecycle.get("comparison_available") is True
    package_observed = bool(artifact_versions) or assessment in {
        "artifact-only",
        "matched",
        "version-drift",
    }
    if lifecycle.get("artifact_inventory_available") is not True:
        status = "not-established"
    elif affected:
        status = "affected-version-observed"
    elif fixed and not affected:
        status = "fixed-version-observed"
    elif assessment == "package-not-observed" and comparison_available:
        status = "package-not-observed"
    elif package_observed:
        status = "package-observed-version-unresolved"
    else:
        status = "not-established"
    return {
        "status": status,
        "advisory_versions": sorted(advisory_versions),
        "artifact_versions": sorted(artifact_versions),
        "affected_artifact_versions": affected,
        "fixed_artifact_versions": fixed,
        "interpretation": (
            "Exact version-set comparison when both advisory and artifact versions "
            "are retained. Inventory availability alone is never package presence."
        ),
    }


def _evidence_relationships(
    **sections: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    nodes: dict[tuple[str, str], dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    def add_node(kind: str, identifier: str, label: str, artifacts: list[str]) -> None:
        if not identifier:
            return
        nodes.setdefault(
            (kind, identifier),
            {
                "node_id": f"{kind}:{identifier}",
                "kind": kind,
                "subject_id": identifier[:1000],
                "label": label[:1000],
                "evidence_artifacts": sorted(set(artifacts))[:25],
            },
        )

    def add_edge(
        source: str, target: str, relationship: str, artifacts: list[str]
    ) -> None:
        if not source or not target:
            return
        key = (source, target, relationship)
        edges.setdefault(
            key,
            {
                "edge_id": "edge-"
                + _digest(
                    {"source": source, "target": target, "relationship": relationship}
                )[:16],
                "source": source,
                "target": target,
                "relationship": relationship,
                "evidence_artifacts": sorted(set(artifacts))[:25],
            },
        )

    for item in sections.get("controls", []):
        identifier = str(item["control_point_id"])
        node_id = f"control:{identifier}"
        evidence = _strings(item.get("evidence_artifacts"), 25)
        add_node("control", identifier, str(item["path"]), evidence)
        for target_id in _strings(item.get("target_ids"), 100):
            add_node("risk-target", target_id, target_id, ["risk-paths.json"])
            add_edge(
                node_id, f"risk-target:{target_id}", "structurally-governs", evidence
            )
        candidate_tests = set(_strings(item.get("candidate_test_files"), 100))
        verified_tests = set(_strings(item.get("test_files"), 100))
        for test in sorted(candidate_tests):
            add_node("test", test, test, evidence)
            add_edge(
                f"test:{test}",
                node_id,
                (
                    "source-bound-passing-test-for-candidate-control"
                    if test in verified_tests
                    else "selected-for-candidate-control"
                ),
                evidence,
            )
    for item in sections.get("taint_paths", []):
        identifier = str(item["taint_path_id"])
        evidence = _strings(item.get("evidence_artifacts"), 25)
        add_node(
            "taint-path",
            identifier,
            str(_object(item.get("sink")).get("path") or identifier),
            evidence,
        )
        finding_id = str(item.get("finding_id") or "")
        add_node("finding", finding_id, finding_id, ["findings.json"])
        add_edge(
            f"taint-path:{identifier}",
            f"finding:{finding_id}",
            "confirms-data-flow-for",
            evidence,
        )
    for item in sections.get("artifact_parity", []):
        artifact = str(item.get("artifact") or "")
        evidence = _strings(item.get("evidence_artifacts"), 25)
        add_node("artifact", artifact, artifact, evidence)
        for entry in _objects(item.get("published_entry_points"), _MAX_RECORDS):
            subject = f"{artifact}#{entry.get('group')}:{entry.get('name')}"
            add_node(
                "published-entry",
                subject,
                str(entry.get("target") or subject),
                evidence,
            )
            add_edge(
                f"artifact:{artifact}",
                f"published-entry:{subject}",
                "publishes",
                evidence,
            )
    for section_name, id_key, node_kind in (
        ("traceability", "traceability_id", "threat-trace"),
        ("mutations", "mutation_leverage_id", "mutation"),
        ("telemetry", "privacy_route_id", "privacy-route"),
        ("dependency_routes", "dependency_trust_route_id", "dependency-route"),
    ):
        for item in sections.get(section_name, []):
            identifier = str(item.get(id_key) or "")
            evidence = _strings(item.get("evidence_artifacts"), 25)
            add_node(
                node_kind, identifier, str(item.get("path") or identifier), evidence
            )
            for control_id in _strings(item.get("control_point_ids"), 100):
                add_edge(
                    f"control:{control_id}",
                    f"{node_kind}:{identifier}",
                    "applies-to",
                    evidence,
                )
            if section_name == "telemetry":
                for assessment in _objects(
                    item.get("control_flow_assessments"), _MAX_RECORDS
                ):
                    control_id = str(assessment.get("control_point_id") or "")
                    for taint_path_id in _strings(
                        assessment.get("taint_path_ids_observed_before_sink"), 100
                    ):
                        add_edge(
                            f"control:{control_id}",
                            f"taint-path:{taint_path_id}",
                            "observed-before-native-sink-on",
                            ["findings.json", "risk-paths.json"],
                        )
    all_nodes = sorted(nodes.values(), key=lambda item: str(item["node_id"]))
    all_edges = sorted(edges.values(), key=lambda item: str(item["edge_id"]))
    total = len(all_nodes) + len(all_edges)
    if total <= _MAX_RELATIONSHIPS:
        return all_nodes, all_edges, 0
    retained_nodes = all_nodes[: _MAX_RELATIONSHIPS // 2]
    retained_ids = {str(item["node_id"]) for item in retained_nodes}
    retained_edges = [
        item
        for item in all_edges
        if item["source"] in retained_ids and item["target"] in retained_ids
    ][: _MAX_RELATIONSHIPS - len(retained_nodes)]
    return (
        retained_nodes,
        retained_edges,
        total - len(retained_nodes) - len(retained_edges),
    )


def _graph_adjacency(value: Any) -> dict[str, set[str]]:
    graph = _object(value)
    topology = _object(graph.get("topology"))
    result: dict[str, set[str]] = defaultdict(set)
    for edge in _objects(topology.get("file_edges"), 750_000):
        source = _path(edge.get("source"))
        target = _path(edge.get("target"))
        if source and target and source != target:
            result[source].add(target)
    return dict(result)


def _entry_path_index(value: Any) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for item in _objects(_object(value).get("entry_points"), 500):
        identifier = str(item.get("id") or "")
        path = _path(item.get("path"))
        if identifier and path:
            result[identifier].add(path)
    return dict(result)


def _route_entry_paths(
    route: dict[str, Any], entry_paths: dict[str, set[str]]
) -> tuple[list[str], bool]:
    result: set[str] = set()
    exposures = _objects(route.get("entry_point_exposures"), 100)
    if not exposures:
        return [], False
    complete = True
    for exposure in exposures:
        entry = _object(exposure.get("entry_point"))
        exposure_paths: set[str] = set()
        if direct_path := _path(entry.get("path")):
            exposure_paths.add(direct_path)
        exposure_paths.update(entry_paths.get(str(entry.get("id") or ""), set()))
        if not exposure_paths:
            complete = False
        result.update(exposure_paths)
    return sorted(result), complete


def _immediate_dominators(
    adjacency: dict[str, set[str]], roots: list[str]
) -> dict[str, str]:
    if not roots:
        return {}
    successors = {node: set(values) for node, values in adjacency.items()}
    successors[_VIRTUAL_ROOT] = set(roots)
    postorder: list[str] = []
    seen: set[str] = {_VIRTUAL_ROOT}
    stack: list[tuple[str, bool]] = [(_VIRTUAL_ROOT, False)]
    while stack:
        node, expanded = stack.pop()
        if expanded:
            postorder.append(node)
            continue
        stack.append((node, True))
        for child in sorted(successors.get(node, set()), reverse=True):
            if child not in seen:
                seen.add(child)
                stack.append((child, False))
    rpo = list(reversed(postorder))
    order = {node: index for index, node in enumerate(rpo)}
    predecessors: dict[str, set[str]] = defaultdict(set)
    for source, targets in successors.items():
        if source not in seen:
            continue
        for destination in targets:
            if destination in seen:
                predecessors[destination].add(source)
    idom: dict[str, str] = {_VIRTUAL_ROOT: _VIRTUAL_ROOT}

    def intersect(first: str, second: str) -> str:
        left, right = first, second
        while left != right:
            while order[left] > order[right]:
                left = idom[left]
            while order[right] > order[left]:
                right = idom[right]
        return left

    changed = True
    while changed:
        changed = False
        for node in rpo[1:]:
            available = [value for value in predecessors[node] if value in idom]
            if not available:
                continue
            new = min(available, key=order.__getitem__)
            for predecessor in available:
                if predecessor != new:
                    new = intersect(predecessor, new)
            if idom.get(node) != new:
                idom[node] = new
                changed = True
    return idom


def _dominator_chain(idom: dict[str, str], node: str) -> list[str]:
    if node not in idom:
        return []
    result: list[str] = []
    current = node
    seen: set[str] = set()
    while current not in seen and current in idom:
        seen.add(current)
        if current != _VIRTUAL_ROOT:
            result.append(current)
        parent = idom[current]
        if parent == current:
            break
        current = parent
    result.reverse()
    return result


def _module_paths(module: str) -> list[str]:
    stem = module.replace(".", "/").strip("/")
    if not stem:
        return []
    return [
        f"{stem}.py",
        f"{stem}/__init__.py",
        f"src/{stem}.py",
        f"src/{stem}/__init__.py",
    ]


def _read_zip_member(archive: zipfile.ZipFile, name: str) -> bytes:
    info = archive.getinfo(name)
    if info.file_size < 0 or info.file_size > _MAX_MEMBER_BYTES:
        raise ValueError(f"wheel member exceeds analysis limit: {name[:200]}")
    return archive.read(name)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _first_tool(finding: Finding) -> str:
    return finding.sources[0].tool if finding.sources else "unknown"


def _digest(value: Any) -> str:
    import json

    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _objects(value: Any, maximum: int) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value[:maximum] if isinstance(item, dict)]


def _strings(value: Any, maximum: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        str(item)[:1000] for item in value[:maximum] if isinstance(item, str) and item
    ]


def _path(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.replace("\\", "/").strip()
    if not normalized or normalized in {".", "<repository>", "<outside-target>"}:
        return None
    return normalized[:1000]
