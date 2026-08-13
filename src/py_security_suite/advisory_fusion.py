from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any

from .models import Finding


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
        clusters.append(
            {
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
        )
    return sorted(
        clusters,
        key=lambda item: (
            -_SEVERITY_RANK.get(str(item["highest_severity"]), 0),
            str(item["package"]),
            str(item["primary_identifier"]),
        ),
    )[:10_000]


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
