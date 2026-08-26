from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Hashable
import hashlib
from typing import TypeVar

from .models import (
    Confidence,
    Finding,
    Severity,
    finding_identity,
)
from .strict_json import canonical_bytes


_SEVERITY_ORDER = {
    Severity.UNKNOWN: 0,
    Severity.INFORMATIONAL: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}
_CONFIDENCE_ORDER = {
    Confidence.UNKNOWN: 0,
    Confidence.LOW: 1,
    Confidence.MEDIUM: 2,
    Confidence.HIGH: 3,
}
_T = TypeVar("_T")
_RUNTIME_TOOLS = frozenset(
    {
        "browser-security",
        "authorization-security",
        "falco",
        "iast",
        "kubescape",
        "mobsf",
        "nuclei",
        "oast",
        "restler",
        "protocol-security",
        "prowler",
        "cloud-attack-path",
        "rasp",
        "tls-scan",
        "zap",
        "secret-verification",
    }
)
_DYNAMIC_TOOLS = _RUNTIME_TOOLS | frozenset(
    {
        "atheris",
        "clusterfuzzlite",
        "crosshair",
        "native-sanitizers",
        "polyglot",
        "fuzz-introspector",
        "schemathesis",
    }
)
_ENGINE_FAMILIES = {
    "ruff": "ruff",
    "ruff-quality": "ruff",
    "ruff-format": "ruff",
    "gitleaks": "gitleaks",
    "trufflehog": "trufflehog",
    "detect-secrets": "detect-secrets",
    "osv-scanner": "osv",
    "cyclonedx-py": "cyclonedx",
}


def correlate_findings(findings: list[Finding]) -> list[Finding]:
    grouped: dict[tuple[str, int | None, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        location = finding.locations[0] if finding.locations else None
        path = location.path if location else "<unknown>"
        line = location.start_line if location else None
        logical_rule = _logical_rule(finding)
        grouped[(path, line, logical_rule)].append(finding)

    correlated: list[Finding] = []
    partitioned: list[tuple[tuple[str, int | None, str], list[Finding]]] = []
    for key, observations in grouped.items():
        for flow_cluster in _flow_partitions(observations):
            partitioned.extend(
                (key, cluster) for cluster in _semantic_partitions(flow_cluster)
            )

    for (path, line, logical_rule), observations in partitioned:
        primary = observations[0]
        if len(observations) == 1:
            correlated.append(primary)
            continue
        cluster_flow_signatures = sorted(
            {signature for item in observations for signature in _flow_signatures(item)}
        )
        semantic_anchors = sorted(
            {anchor for item in observations for anchor in _semantic_anchors(item)}
        )
        finding_id, fingerprint = finding_identity(
            tool="suite",
            rule_id=logical_rule,
            path=path,
            start_line=line,
            advisory="|".join([*cluster_flow_signatures, *semantic_anchors]),
        )
        primary.finding_id = finding_id
        primary.fingerprint = fingerprint
        primary.severity = max(
            (item.severity for item in observations),
            key=lambda value: _SEVERITY_ORDER[value],
        )
        primary.confidence = max(
            (item.confidence for item in observations),
            key=lambda value: _CONFIDENCE_ORDER[value],
        )
        primary.sources = _unique(
            [source for item in observations for source in item.sources],
            key=lambda source: (source.tool, source.rule_id),
        )
        primary.citations = _unique(
            [citation for item in observations for citation in item.citations],
            key=lambda citation: (citation.kind, citation.identifier),
        )
        primary.classifications = list(
            dict.fromkeys(
                value for item in observations for value in item.classifications
            )
        )
        tools = sorted({source.tool for source in primary.sources})
        families = sorted({_engine_family(tool) for tool in tools})
        dynamic_tools = sorted(set(tools) & _DYNAMIC_TOOLS)
        flow_signatures = cluster_flow_signatures
        merged_flows = _merged_code_flows(observations)
        if merged_flows:
            primary.evidence["sarif_code_flows"] = merged_flows
        reproduction_bindings = [
            binding for item in observations for binding in _reproduction_bindings(item)
        ][:100]
        if reproduction_bindings:
            primary.evidence["reproduction_bindings"] = reproduction_bindings
        primary.evidence["cross_tool_corroboration"] = {
            "observation_count": len(observations),
            "tools": tools,
            "dynamic_tools": dynamic_tools,
            "runtime_observed": bool(set(tools) & _RUNTIME_TOOLS),
            "engine_families": families,
            "independent_perspectives": len(families),
            "flow_signatures": flow_signatures,
            "semantic_anchors": semantic_anchors,
            "observations": [_observation(item) for item in observations[:100]],
            "claim_boundary": (
                "Co-located observations with the same normalized weakness; this "
                "does not by itself prove exploitability or production exposure."
            ),
        }
        correlated.append(primary)

    return sorted(correlated, key=_sort_key)


def _flow_partitions(observations: list[Finding]) -> list[list[Finding]]:
    signatures = {
        signature for finding in observations for signature in _flow_signatures(finding)
    }
    if len(signatures) <= 1:
        return [observations]
    partitions: dict[str, list[Finding]] = defaultdict(list)
    unbound: list[Finding] = []
    for finding in observations:
        finding_signatures = _flow_signatures(finding)
        if len(finding_signatures) == 1:
            partitions[next(iter(finding_signatures))].append(finding)
        else:
            unbound.append(finding)
    result = [partitions[key] for key in sorted(partitions)]
    if unbound:
        result.append(unbound)
    return result


def _semantic_partitions(observations: list[Finding]) -> list[list[Finding]]:
    anchors = {
        anchor for finding in observations for anchor in _semantic_anchors(finding)
    }
    if len(anchors) <= 1:
        return [observations]
    partitions: dict[str, list[Finding]] = defaultdict(list)
    unbound: list[Finding] = []
    for finding in observations:
        finding_anchors = _semantic_anchors(finding)
        if len(finding_anchors) == 1:
            partitions[next(iter(finding_anchors))].append(finding)
        else:
            unbound.append(finding)
    result = [partitions[key] for key in sorted(partitions)]
    if unbound:
        result.append(unbound)
    return result


def _semantic_anchors(finding: Finding) -> set[str]:
    anchors: set[str] = set()
    for location in finding.locations:
        if location.package:
            anchors.add(
                f"package:{location.package.casefold()}@{location.version or '*'}"
            )
    for namespace in (
        "application_contracts",
        "advisory",
        "dependency",
        "framework_model_coverage",
    ):
        evidence = finding.evidence.get(namespace)
        if not isinstance(evidence, dict):
            continue
        for key in (
            "operation",
            "advisory_id",
            "symbol",
            "package",
            "framework",
        ):
            value = evidence.get(key)
            if isinstance(value, str) and value:
                anchors.add(f"{key}:{value.casefold()}")
    return anchors


def _flow_signatures(finding: Finding) -> set[str]:
    flows = finding.evidence.get("sarif_code_flows")
    if not isinstance(flows, list):
        return set()
    signatures: set[str] = set()
    for flow in flows:
        if not isinstance(flow, dict) or not isinstance(flow.get("steps"), list):
            continue
        steps = [
            {
                "path": str(step.get("path") or ""),
                "line": step.get("line"),
                "kinds": sorted(str(value) for value in step.get("kinds", [])),
            }
            for step in flow["steps"]
            if isinstance(step, dict)
        ]
        if len(steps) < 2:
            continue
        subject = {
            "semantic_basis": str(flow.get("semantic_basis") or ""),
            "steps": steps,
        }
        signatures.add(hashlib.sha256(canonical_bytes(subject)).hexdigest())
    return signatures


def _merged_code_flows(observations: list[Finding]) -> list[dict[str, object]]:
    values: dict[bytes, dict[str, object]] = {}
    for finding in observations:
        flows = finding.evidence.get("sarif_code_flows")
        if not isinstance(flows, list):
            continue
        for flow in flows:
            if isinstance(flow, dict):
                values.setdefault(canonical_bytes(flow), dict(flow))
    return [values[key] for key in sorted(values)][:50]


def _reproduction_bindings(finding: Finding) -> list[dict[str, object]]:
    raw = finding.evidence.get("reproduction_bindings")
    if isinstance(raw, list):
        return [dict(item) for item in raw if isinstance(item, dict)]
    single = finding.evidence.get("reproduction_binding")
    return [dict(single)] if isinstance(single, dict) else []


def _engine_family(tool: str) -> str:
    return _ENGINE_FAMILIES.get(tool, tool)


def _observation(finding: Finding) -> dict[str, object]:
    location = finding.locations[0] if finding.locations else None
    return {
        "finding_id": finding.finding_id,
        "fingerprint": finding.fingerprint,
        "tool_rules": sorted(
            {f"{source.tool}:{source.rule_id}" for source in finding.sources}
        ),
        "path": location.path if location else "<unknown>",
        "line": location.start_line if location else None,
        "flow_signatures": sorted(_flow_signatures(finding)),
        "semantic_anchors": sorted(_semantic_anchors(finding)),
    }


def _logical_rule(finding: Finding) -> str:
    for classification in finding.classifications:
        normalized = classification.upper().split(":", 1)[0]
        if normalized.startswith("CWE-"):
            return normalized
    if finding.sources:
        return finding.sources[0].rule_id
    return finding.title.casefold()


def _unique(values: list[_T], *, key: Callable[[_T], Hashable]) -> list[_T]:
    seen: set[Hashable] = set()
    result: list[_T] = []
    for value in values:
        identity = key(value)
        if identity not in seen:
            seen.add(identity)
            result.append(value)
    return result


def _sort_key(finding: Finding) -> tuple[int, str, int, str]:
    location = finding.locations[0] if finding.locations else None
    return (
        -_SEVERITY_ORDER[finding.severity],
        location.path if location else "",
        location.start_line or 0 if location else 0,
        finding.finding_id,
    )
