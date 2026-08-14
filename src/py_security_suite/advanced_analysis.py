from __future__ import annotations

import base64
import configparser
import csv
import hashlib
import io
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
_EXPORT_TERMS = ("emit", "export", "log", "record", "send", "span", "telemetry")
_REDACTION_TERMS = ("filter", "redact", "sanitize", "scrub")


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
                item["redaction_order"] == "export-before-redaction"
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
    roots = _entry_paths(artifacts.get("reachability.json"))
    idom = _immediate_dominators(adjacency, roots)
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
    observations = _control_observations(routes, campaigns, hotspots, idom)
    result = [
        _control_record(path, status, raw)
        for (path, status), raw in observations.items()
    ]
    return sorted(
        result,
        key=lambda item: (
            {"bypass-capable": 0, "mandatory": 1, "not-on-retained-route": 2}.get(
                str(item["topology_status"]), 3
            ),
            not bool(item["shared_mandatory_security_route_point"]),
            str(item["path"]),
        ),
    )[:_MAX_RECORDS]


def _control_observations(
    routes: list[dict[str, Any]],
    campaigns: dict[str, dict[str, Any]],
    hotspots: dict[str, dict[str, Any]],
    idom: dict[str, str],
) -> dict[tuple[str, str], dict[str, Any]]:
    observations: dict[tuple[str, str], dict[str, Any]] = {}
    for route in routes:
        target = _object(route.get("target"))
        target_path = _path(target.get("path"))
        target_id = str(target.get("id") or "")
        if not target_path or not target_id:
            continue
        dominators = set(_dominator_chain(idom, target_path))
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
                "mandatory"
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
        item["test_files"].update(
            _strings(campaigns.get(campaign_id, {}).get("selected_test_files"), 100)
        )


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
        "test_files": sorted(raw["test_files"]),
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
            "Exact file-level graph dominance across declared entry roots. "
            "Security-control behavior must be verified from implementation "
            "and scanner or test evidence."
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
        route_files = set(_strings(route.get("files"), 25))
        for flow_index, flow in enumerate(raw_flows[:10]):
            if not isinstance(flow, dict):
                continue
            steps = [
                {
                    "path": _path(step.get("path")) or "<repository>",
                    "line": step.get("line")
                    if isinstance(step.get("line"), int)
                    else None,
                    "message": str(step.get("message") or "")[:500],
                }
                for step in _objects(flow.get("steps"), 100)
            ]
            if len(steps) < 2:
                continue
            step_paths = {str(step["path"]) for step in steps}
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
                    "route_alignment": (
                        "aligned"
                        if route_files and step_paths & route_files
                        else "not-established"
                    ),
                    "source": steps[0],
                    "sink": steps[-1],
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
                    ),
                    "evidence_artifacts": ["findings.json", "risk-paths.json"],
                }
            )
    return result[:_MAX_RECORDS]


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
        except (OSError, ValueError, zipfile.BadZipFile, configparser.Error) as exc:
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
            name for name in names if name.endswith(".dist-info/RECORD")
        )
        record_gaps: list[dict[str, Any]] = []
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
            "members": len(names),
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
        recorded.add(name)
        if name not in members:
            gaps.append({"kind": "record-member-missing", "path": name[:500]})
            continue
        info = archive.getinfo(name)
        if size_value:
            try:
                expected_size = int(size_value)
            except ValueError:
                gaps.append({"kind": "invalid-record-size", "path": name[:500]})
            else:
                if expected_size != info.file_size:
                    gaps.append({"kind": "record-size-mismatch", "path": name[:500]})
        if digest_value and name != record_name:
            algorithm, separator, encoded = digest_value.partition("=")
            if separator != "=" or algorithm != "sha256":
                gaps.append({"kind": "unsupported-record-hash", "path": name[:500]})
            elif info.file_size <= _MAX_MEMBER_BYTES:
                actual = (
                    base64.urlsafe_b64encode(
                        hashlib.sha256(_read_zip_member(archive, name)).digest()
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
    campaigns_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for campaign in _objects(risk_paths.get("validation_campaigns"), _MAX_RECORDS):
        if campaign_path := _path(campaign.get("path")):
            campaigns_by_path[campaign_path].append(campaign)
    result: list[dict[str, Any]] = []
    for finding in findings:
        if "pytm" not in {source.tool for source in finding.sources}:
            continue
        finding_path = _path(finding.locations[0].path) if finding.locations else None
        path_controls = controls_by_path.get(finding_path or "", [])
        campaigns = campaigns_by_path.get(finding_path or "", [])
        tests = sorted(
            {
                test
                for campaign in campaigns
                for test in _strings(campaign.get("selected_test_files"), 100)
            }
        )
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
                "test_files": tests[:100],
                "closure_status": (
                    "mapped-control-and-test"
                    if path_controls and tests
                    else "control-without-test"
                    if path_controls
                    else "threat-without-control-evidence"
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
                    "negative or abuse-case test to that control before closure."
                ),
                "evidence_artifacts": [
                    "findings.json",
                    "risk-paths.json",
                    "pytm-summary.json",
                ],
            }
        )
    return result[:_MAX_RECORDS]


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
        tests = sorted(campaign_tests.get(path, set()))
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
                "test_files": tests,
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
        redaction_order = _redaction_order(flows)
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
                "validation_status": str(
                    route.get("validation_status") or "not-assessed"
                ),
                "owners": _strings(route.get("owners"), 100),
                "review_status": _privacy_review_status(
                    route, path_controls, redaction_order
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


def _redaction_order(flows: list[dict[str, Any]]) -> str:
    observed_redaction = False
    for flow in flows:
        messages = [
            f"{step.get('path', '')} {step.get('message', '')}".casefold()
            for step in _objects(flow.get("steps"), 100)
        ]
        redact = next(
            (
                index
                for index, value in enumerate(messages)
                if any(term in value for term in _REDACTION_TERMS)
            ),
            None,
        )
        export = next(
            (
                index
                for index, value in enumerate(messages)
                if any(term in value for term in _EXPORT_TERMS)
            ),
            None,
        )
        if redact is not None:
            observed_redaction = True
        if redact is not None and export is not None and export < redact:
            return "export-before-redaction"
    return "redaction-before-export" if observed_redaction else "not-established"


def _privacy_review_status(
    route: dict[str, Any], controls: list[dict[str, Any]], redaction_order: str
) -> str:
    if redaction_order == "export-before-redaction":
        return "redaction-order-risk"
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
        factors: list[str] = []
        if context.get("known_exploited") is True:
            factors.append("known-exploited")
        if context.get("epss_high") is True:
            factors.append("high-epss")
        if lifecycle.get("artifact_inventory_available") is True:
            factors.append("present-in-artifact-inventory")
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
            + 2 * ("present-in-artifact-inventory" in factors)
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
        for test in _strings(item.get("test_files"), 100):
            add_node("test", test, test, evidence)
            add_edge(f"test:{test}", node_id, "validates-candidate-control", evidence)
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


def _entry_paths(value: Any) -> list[str]:
    return sorted(
        {
            path
            for item in _objects(_object(value).get("entry_points"), 500)
            if (path := _path(item.get("path")))
        }
    )


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
