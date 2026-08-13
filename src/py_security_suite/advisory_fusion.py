from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any

from .models import Finding
from .prioritization import finding_priority


_NAME_SEPARATOR = re.compile(r"[-_.]+")
_ADVISORY_IDENTIFIER = re.compile(r"^(?:CVE|GHSA|OSV|PYSEC)-[A-Z0-9._-]+$")
_SEVERITY_RANK = {
    "unknown": 0,
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}
_PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}


def build_advisory_clusters(findings: list[Finding]) -> list[dict[str, Any]]:
    """Cluster exact-package findings joined by transitive advisory aliases."""
    records: list[dict[str, Any]] = []
    for finding in findings:
        identifiers = _advisory_identifiers(finding)
        if not identifiers:
            continue
        packages: dict[str, set[str]] = defaultdict(set)
        paths: dict[str, set[str]] = defaultdict(set)
        for location in finding.locations:
            package = _package_name(location.package)
            if not package:
                continue
            if location.version:
                packages[package].add(str(location.version)[:300])
            else:
                packages.setdefault(package, set())
            if location.path:
                paths[package].add(_path(location.path))
        for package, versions in packages.items():
            records.append(
                {
                    "finding": finding,
                    "package": package,
                    "versions": versions,
                    "paths": paths[package],
                    "identifiers": identifiers,
                }
            )

    parent = list(range(len(records)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    identifier_owners: dict[tuple[str, str], int] = {}
    for index, record in enumerate(records):
        for identifier in record["identifiers"]:
            key = (str(record["package"]), str(identifier))
            owner = identifier_owners.setdefault(key, index)
            union(index, owner)

    groups: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for index, record in enumerate(records):
        groups[find(index)].append(record)

    clusters: list[dict[str, Any]] = []
    for grouped in groups.values():
        package = str(grouped[0]["package"])
        cluster_identifiers = sorted(
            {
                str(identifier)
                for record in grouped
                for identifier in record["identifiers"]
            }
        )
        primary = min(cluster_identifiers, key=_advisory_identifier_key)
        cluster_material = f"{package}|{primary}".encode()
        findings_by_id = {
            record["finding"].finding_id: record["finding"] for record in grouped
        }
        severities = sorted(
            {finding.severity.value for finding in findings_by_id.values()},
            key=lambda value: (-_SEVERITY_RANK.get(value, 0), value),
        )
        citations = _cluster_citations(findings_by_id, cluster_identifiers)
        tools = sorted(
            {
                source.tool
                for finding in findings_by_id.values()
                for source in finding.sources
            }
        )
        finding_ids = sorted(findings_by_id)
        scanner_observations = {
            (source.tool, source.rule_id)
            for finding in findings_by_id.values()
            for source in finding.sources
        }
        observation_count = len(scanner_observations) or len(finding_ids)
        cluster = {
                "cluster_id": "ADV-"
                + hashlib.sha256(cluster_material).hexdigest()[:12].upper(),
                "package": package,
                "versions": sorted(
                    {
                        str(version)
                        for record in grouped
                        for version in record["versions"]
                    }
                )[:50],
                "primary_identifier": primary,
                "identifiers": cluster_identifiers[:100],
                "finding_ids": finding_ids[:100],
                "tools": tools[:25],
                "source_paths": sorted(
                    {str(path) for record in grouped for path in record["paths"]}
                )[:50],
                "highest_severity": severities[0] if severities else "unknown",
                "observation_count": observation_count,
                "alias_count": max(0, len(cluster_identifiers) - 1),
                "cross_tool": len(tools) > 1,
                "citations": [citations[key] for key in sorted(citations)[:25]],
            }
        refresh_advisory_decision(cluster, findings_by_id)
        clusters.append(cluster)
    return sorted(
        clusters,
        key=lambda item: (
            -_SEVERITY_RANK.get(str(item["highest_severity"]), 0),
            str(item["package"]),
            str(item["primary_identifier"]),
        ),
    )[:10_000]


def refresh_advisory_decision(
    cluster: dict[str, Any], findings_by_id: dict[str, Finding]
) -> None:
    """Attach bounded threat and remediation context to one advisory cluster."""
    finding_ids = cluster.get("finding_ids")
    finding_ids = finding_ids if isinstance(finding_ids, list) else []
    selected = [
        findings_by_id[item]
        for item in finding_ids
        if isinstance(item, str) and item in findings_by_id
    ]
    threat = _threat_context(cluster, selected)
    cluster["threat_context"] = threat
    cluster["remediation_context"] = _remediation_context(
        cluster, selected, threat
    )


def _threat_context(
    cluster: dict[str, Any], findings: list[Finding]
) -> dict[str, Any]:
    cves = {
        str(item).upper()
        for item in cluster.get("identifiers", [])
        if isinstance(item, str) and item.upper().startswith("CVE-")
    }
    kev_cves: set[str] = set()
    kev_records: dict[str, dict[str, Any]] = {}
    epss_records: dict[str, dict[str, Any]] = {}
    vex_states: set[str] = set()
    vex_records: dict[tuple[str, str], dict[str, Any]] = {}
    intelligence_sources: set[str] = set()
    for finding in findings:
        intelligence = finding.evidence.get("risk_intelligence")
        if not isinstance(intelligence, dict):
            continue
        raw_cves = intelligence.get("cves")
        if isinstance(raw_cves, list):
            cves.update(
                str(item).upper()
                for item in raw_cves[:100]
                if isinstance(item, str) and item.upper().startswith("CVE-")
            )
        raw_kev = intelligence.get("known_exploited")
        if isinstance(raw_kev, list) and raw_kev:
            intelligence_sources.add("CISA-KEV")
            for item in raw_kev[:100]:
                if not isinstance(item, dict) or not item.get("cve"):
                    continue
                cve = str(item["cve"]).upper()[:100]
                kev_cves.add(cve)
                kev_records[cve] = {
                    "cve": cve,
                    "date_added": _bounded_text(item.get("date_added"), 30),
                    "due_date": _bounded_text(item.get("due_date"), 30),
                    "known_ransomware_campaign_use": _bounded_text(
                        item.get("known_ransomware_campaign_use"), 30
                    ),
                    "required_action": _bounded_text(
                        item.get("required_action"), 500
                    ),
                }
        raw_epss = intelligence.get("epss")
        if isinstance(raw_epss, list) and raw_epss:
            intelligence_sources.add("EPSS")
            for item in raw_epss[:100]:
                if not isinstance(item, dict) or not item.get("cve"):
                    continue
                cve = str(item["cve"]).upper()[:100]
                probability = item.get("probability")
                percentile = item.get("percentile")
                if not isinstance(probability, (int, float)) or isinstance(
                    probability, bool
                ):
                    continue
                if not isinstance(percentile, (int, float)) or isinstance(
                    percentile, bool
                ):
                    continue
                candidate = {
                    "cve": cve,
                    "probability": round(float(probability), 6),
                    "percentile": round(float(percentile), 6),
                }
                current = epss_records.get(cve)
                if current is None or candidate["probability"] > current["probability"]:
                    epss_records[cve] = candidate
        raw_vex = intelligence.get("vex")
        if isinstance(raw_vex, list) and raw_vex:
            intelligence_sources.add("CycloneDX-VEX")
            for item in raw_vex[:100]:
                if not isinstance(item, dict) or not item.get("state"):
                    continue
                cve = str(item.get("cve") or "unknown").upper()[:100]
                state = str(item["state"]).casefold()[:100]
                vex_states.add(state)
                response = item.get("response")
                vex_records[(cve, state)] = {
                    "cve": cve,
                    "state": state,
                    "justification": _bounded_text(item.get("justification"), 100),
                    "detail": _bounded_text(item.get("detail"), 500),
                    "response": _bounded_text_list(response, 20, 100),
                }
    probabilities = [
        float(item["probability"])
        for item in epss_records.values()
        if isinstance(item.get("probability"), (int, float))
        and 0 <= float(item["probability"]) <= 1
    ]
    percentiles = [
        float(item["percentile"])
        for item in epss_records.values()
        if isinstance(item.get("percentile"), (int, float))
        and 0 <= float(item["percentile"]) <= 1
    ]
    epss_high = any("EPSS-HIGH" in finding.classifications for finding in findings)
    return {
        "intelligence_available": bool(intelligence_sources),
        "intelligence_sources": sorted(intelligence_sources),
        "cves": sorted(cves)[:100],
        "known_exploited": bool(kev_cves),
        "known_exploited_cves": sorted(kev_cves)[:100],
        "known_exploited_records": [
            kev_records[key] for key in sorted(kev_records)[:100]
        ],
        "epss_probability": round(max(probabilities), 6) if probabilities else None,
        "epss_percentile": round(max(percentiles), 6) if percentiles else None,
        "epss_high": epss_high,
        "epss_records": [
            epss_records[key] for key in sorted(epss_records)[:100]
        ],
        "vex_states": sorted(vex_states)[:20],
        "vex_disposition": _vex_disposition(vex_states),
        "vex_records": [vex_records[key] for key in sorted(vex_records)[:100]],
    }


def _vex_disposition(states: set[str]) -> str:
    if not states:
        return "unassessed"
    if "exploitable" in states:
        return "exploitable"
    non_actionable = {
        "false_positive",
        "not_affected",
        "resolved",
        "resolved_with_pedigree",
    }
    if states <= non_actionable:
        return "bounded-or-resolved-claim"
    if len(states) > 1:
        return "mixed"
    return next(iter(states))


def _remediation_context(
    cluster: dict[str, Any],
    findings: list[Finding],
    threat: dict[str, Any],
) -> dict[str, Any]:
    fixed_by_tool: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        versions = _bounded_versions(finding.evidence.get("fixed_versions"))
        raw_sources = finding.evidence.get("fixed_versions_by_tool")
        attributed = False
        if isinstance(raw_sources, dict):
            for raw_tool, raw_versions in list(raw_sources.items())[:100]:
                tool_versions = _bounded_versions(raw_versions)
                tool = " ".join(str(raw_tool).split())[:100]
                if tool and tool_versions:
                    fixed_by_tool[tool].update(tool_versions)
                    attributed = True
        if versions and not attributed:
            tools = {source.tool for source in finding.sources}
            tool = next(iter(tools)) if len(tools) == 1 else "normalized-finding"
            fixed_by_tool[tool].update(versions)
    fixed_versions = sorted(
        {version for values in fixed_by_tool.values() for version in values}
    )[:100]
    priorities = [
        finding_priority(
            severity=finding.severity.value,
            classifications=finding.classifications,
            evidence=finding.evidence,
        )
        for finding in findings
    ]
    priority = min(priorities, key=lambda item: _PRIORITY_RANK[item], default="P4")
    usage = cluster.get("dependency_usage")
    usage = usage if isinstance(usage, dict) else {}
    assessment = str(usage.get("assessment") or "unknown")
    action_kind, action = _advisory_action(
        package=str(cluster.get("package") or "the affected package"),
        affected_versions=[
            str(item) for item in cluster.get("versions", []) if isinstance(item, str)
        ],
        fixed_versions=fixed_versions,
        priority=priority,
        known_exploited=threat["known_exploited"] is True,
        vex_disposition=str(threat["vex_disposition"]),
        assessment=assessment,
    )
    kev_records = threat.get("known_exploited_records")
    if isinstance(kev_records, list) and kev_records:
        record = kev_records[0] if isinstance(kev_records[0], dict) else {}
        required = _bounded_text(record.get("required_action"), 500)
        due = _bounded_text(record.get("due_date"), 30)
        if required:
            action += " CISA KEV direction: " + required
            if due:
                action += f" (catalog due date {due})."
            elif not action.endswith("."):
                action += "."
    basis = _remediation_basis(cluster, threat, usage)
    uncertainties = _remediation_uncertainties(threat, usage, fixed_versions)
    owners = _bounded_text_list(usage.get("import_path_owners"), 20, 256)
    tests = _bounded_text_list(usage.get("recommended_test_files"), 50, 4096)
    test_confidence = str(usage.get("test_selection_confidence") or "not-available")
    if test_confidence not in {"high", "medium", "low", "not-available"}:
        test_confidence = "not-available"
    return {
        "priority": priority,
        "action_kind": action_kind,
        "fix_available": bool(fixed_versions),
        "fixed_version_candidates": fixed_versions,
        "fixed_version_sources": [
            {"tool": tool, "versions": sorted(values)[:50]}
            for tool, values in sorted(fixed_by_tool.items())
        ][:25],
        "owners": owners,
        "recommended_test_files": tests,
        "test_selection_confidence": test_confidence,
        "recommended_action": action,
        "verification_steps": _advisory_verification_steps(
            cluster, threat, usage, fixed_versions
        ),
        "evidence_basis": basis,
        "uncertainties": uncertainties,
    }


def _advisory_action(
    *,
    package: str,
    affected_versions: list[str],
    fixed_versions: list[str],
    priority: str,
    known_exploited: bool,
    vex_disposition: str,
    assessment: str,
) -> tuple[str, str]:
    affected = ", ".join(affected_versions[:5]) or "the reported affected version"
    candidates = ", ".join(fixed_versions[:8])
    if vex_disposition == "bounded-or-resolved-claim":
        return (
            "validate-vex",
            f"Validate the VEX product, component, version, and justification against {package} {affected}; preserve the native finding until that bounded claim is approved, and remediate if its scope does not match.",
        )
    if assessment == "import-vs-unused-conflict":
        return (
            "resolve-evidence-conflict",
            f"Resolve the exact-import versus unused-declaration conflict for {package}; if retained, upgrade from {affected}"
            + (f" using an approved scanner-reported candidate ({candidates})" if candidates else " or apply a documented mitigation")
            + ", then rebuild and rescan.",
        )
    if assessment == "declared-unused":
        return (
            "remove-or-upgrade",
            f"Confirm dynamic and plugin loading, then remove unused {package}; if retained, upgrade from {affected}"
            + (f" using an approved scanner-reported candidate ({candidates})" if candidates else " and document compensating controls")
            + ", rebuild, and rescan.",
        )
    if fixed_versions:
        lead = "Immediately upgrade" if known_exploited or priority == "P0" else "Upgrade"
        return (
            "upgrade",
            f"{lead} {package} from {affected} using an organization-approved scanner-reported fixed-version candidate ({candidates}); regenerate lockfiles and artifacts, run focused tests, and rescan.",
        )
    lead = "Immediately assess" if known_exploited or priority == "P0" else "Assess"
    return (
        "mitigate-or-replace",
        f"{lead} removal, substitution, or compensating controls for {package} {affected}; no completed scanner reported a fixed-version candidate. Document the decision, rebuild, and rescan.",
    )


def _remediation_basis(
    cluster: dict[str, Any], threat: dict[str, Any], usage: dict[str, Any]
) -> list[str]:
    tools = [str(item) for item in cluster.get("tools", []) if isinstance(item, str)]
    basis = [
        f"{int(cluster.get('observation_count') or 1)} retained scanner observation(s) from {', '.join(tools) or 'unknown tools'}"
    ]
    alias_count = int(cluster.get("alias_count") or 0)
    if alias_count:
        basis.append(f"{alias_count} transitive advisory alias(es) joined exactly")
    if threat.get("known_exploited"):
        basis.append("offline CISA KEV snapshot match")
        raw_records = threat.get("known_exploited_records")
        records = raw_records if isinstance(raw_records, list) else []
        due_dates = sorted(
            {
                str(item.get("due_date"))
                for item in records
                if isinstance(item, dict) and item.get("due_date")
            }
        )
        if due_dates:
            basis.append("CISA KEV catalog due date(s): " + ", ".join(due_dates[:10]))
    if threat.get("epss_probability") is not None:
        basis.append(
            f"offline EPSS probability {float(threat['epss_probability']):.6f} / percentile {float(threat.get('epss_percentile') or 0):.6f}"
        )
    if threat.get("vex_states"):
        basis.append("VEX state(s): " + ", ".join(threat["vex_states"][:10]))
    assessment = str(usage.get("assessment") or "unknown")
    if assessment != "unknown":
        basis.append(f"dependency-use assessment {assessment}")
    relationship = str(usage.get("source_relationship") or "unknown")
    if relationship != "unknown":
        basis.append(f"source dependency relationship {relationship}")
    tests = usage.get("recommended_test_files")
    if isinstance(tests, list) and tests:
        basis.append(
            f"{len(tests)} graph-selected focused test file(s) with {usage.get('test_selection_confidence', 'unknown')} confidence"
        )
    owners = usage.get("import_path_owners")
    if isinstance(owners, list) and owners:
        basis.append("import-path owner(s): " + ", ".join(str(item) for item in owners[:10]))
    uncovered = usage.get("uncovered_import_paths")
    if isinstance(uncovered, list) and uncovered:
        basis.append("import path(s) below 80% coverage: " + ", ".join(str(item) for item in uncovered[:10]))
    return basis[:20]


def _remediation_uncertainties(
    threat: dict[str, Any], usage: dict[str, Any], fixed_versions: list[str]
) -> list[str]:
    values: list[str] = []
    if not fixed_versions:
        values.append("No completed scanner reported a fixed-version candidate.")
    if not threat.get("intelligence_available"):
        values.append("No matching offline KEV, EPSS, or VEX intelligence was available.")
    if usage.get("import_evidence_available") is not True:
        values.append("Exact static import evidence was unavailable.")
    elif usage.get("import_observed") is True and usage.get("reachability_complete") is not True:
        values.append("Import evidence exists, but reachability analysis is incomplete.")
    if usage.get("signals_conflict") is True:
        values.append("Graphify import evidence conflicts with deptry unused-declaration evidence.")
    if usage.get("import_observed") is True:
        if usage.get("test_mapping_evidence_available") is not True:
            values.append("Graphify file-topology evidence was unavailable for focused test selection.")
        elif not usage.get("recommended_test_files"):
            values.append("No direct or transitive test file was mapped to the exact importing path.")
        if usage.get("ownership_evidence_available") is not True:
            values.append("CODEOWNERS-derived ownership evidence was unavailable.")
        elif not usage.get("import_path_owners"):
            values.append("No retained CODEOWNERS-derived owner matched the exact importing path.")
        if usage.get("coverage_evidence_available") is not True:
            values.append("Retained file-coverage evidence was unavailable for the importing path.")
    if threat.get("vex_disposition") in {"bounded-or-resolved-claim", "mixed"}:
        values.append("VEX scope and justification require independent validation before disposition.")
    values.append("Package-level use evidence does not establish vulnerable-function exploitability.")
    return list(dict.fromkeys(values))[:20]


def _advisory_verification_steps(
    cluster: dict[str, Any],
    threat: dict[str, Any],
    usage: dict[str, Any],
    fixed_versions: list[str],
) -> list[str]:
    primary = str(cluster.get("primary_identifier") or cluster.get("cluster_id") or "the advisory")
    steps = [
        f"Review the cited native evidence for {primary}; confirm the package and affected version match the release candidate."
    ]
    if threat.get("vex_states"):
        steps.append("Validate VEX product/component/version scope, justification, and approval provenance; do not use VEX presence alone to suppress the finding.")
    kev_records = threat.get("known_exploited_records")
    if isinstance(kev_records, list) and kev_records:
        actions = [
            str(item.get("required_action"))
            for item in kev_records
            if isinstance(item, dict) and item.get("required_action")
        ]
        due_dates = [
            str(item.get("due_date"))
            for item in kev_records
            if isinstance(item, dict) and item.get("due_date")
        ]
        steps.append(
            "Satisfy the CISA KEV required action"
            + (": " + actions[0] if actions else "")
            + ("; catalog due date " + min(due_dates) if due_dates else "")
            + "."
        )
    if usage.get("signals_conflict") is True:
        steps.append("Resolve the Graphify-versus-deptry conflict by checking exact imports plus dynamic, plugin, and reflection-based loading.")
    elif usage.get("import_observed") is True:
        paths = [str(item) for item in usage.get("import_paths", []) if isinstance(item, str)]
        steps.append("Trace vulnerable API use from the exact importing file(s)" + (": " + ", ".join(paths[:5]) if paths else "") + ".")
    elif usage.get("assessment") == "declared-unused":
        steps.append("Confirm the package is not loaded dynamically or through plugins before removing it.")
    owners = usage.get("import_path_owners")
    if isinstance(owners, list) and owners:
        steps.append("Route implementation review to import-path owner(s): " + ", ".join(str(item) for item in owners[:10]) + ".")
    if fixed_versions:
        steps.append("Select an organization-approved candidate after reviewing release notes and compatibility; regenerate source locks and the built-artifact SBOM.")
    else:
        steps.append("Record removal, substitution, or compensating controls and an owner/date for rechecking fix availability.")
    tests = usage.get("recommended_test_files")
    steps.append(
        "Run focused regression/security tests"
        + (": " + ", ".join(str(item) for item in tests[:10]) if isinstance(tests, list) and tests else "")
        + "; rescan source and built artifacts, and verify the advisory is absent or explicitly governed."
    )
    return steps if len(steps) <= 6 else [*steps[:5], steps[-1]]


def _bounded_versions(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted(
        {
            text
            for item in value[:500]
            if isinstance(item, (str, int, float))
            and (text := " ".join(str(item).split())[:100])
            and not any(ord(character) < 32 for character in text)
        }
    )[:100]


def _bounded_text(value: Any, maximum: int) -> str:
    return " ".join(str(value or "").split())[:maximum]


def _bounded_text_list(value: Any, limit: int, maximum: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return list(
        dict.fromkeys(
            text
            for item in value[:limit]
            if (text := _bounded_text(item, maximum))
        )
    )


def _advisory_identifiers(finding: Finding) -> set[str]:
    candidates: list[Any] = list(finding.classifications)
    candidates.extend(citation.identifier for citation in finding.citations)
    aliases = finding.evidence.get("advisory_aliases")
    if isinstance(aliases, list):
        candidates.extend(aliases[:100])
    return {
        normalized
        for item in candidates
        if isinstance(item, str)
        and (normalized := item.strip().upper())
        and _ADVISORY_IDENTIFIER.fullmatch(normalized)
    }


def _cluster_citations(
    findings_by_id: dict[str, Finding], identifiers: list[str]
) -> dict[str, dict[str, Any]]:
    allowed = set(identifiers)
    result: dict[str, dict[str, Any]] = {}
    for finding in findings_by_id.values():
        for citation in finding.citations:
            identifier = citation.identifier.strip().upper()
            if citation.kind == "supporting_evidence" or identifier not in allowed:
                continue
            candidate = {
                "identifier": identifier,
                "title": citation.title,
                "uri": citation.uri,
            }
            current = result.get(identifier)
            if current is None or (
                "(alias of " in str(current["title"])
                and "(alias of " not in citation.title
            ):
                result[identifier] = candidate
    return result


def _advisory_identifier_key(identifier: str) -> tuple[int, str]:
    prefix = identifier.split("-", 1)[0]
    return ({"CVE": 0, "GHSA": 1, "PYSEC": 2, "OSV": 3}.get(prefix, 4), identifier)


def _package_name(value: Any) -> str:
    text = str(value or "").strip().casefold()
    if ":" in text and "@" in text:
        text = text.split(":", 1)[1].split("@", 1)[0]
    return _NAME_SEPARATOR.sub("-", text)


def _path(value: str) -> str:
    normalized = value.replace("\\", "/")
    return normalized[2:] if normalized.startswith("./") else normalized
