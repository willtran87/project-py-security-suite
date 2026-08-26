from __future__ import annotations

from collections import Counter
import hashlib
from typing import Any

from .models import Finding, ValidationStatus
from .strict_json import canonical_bytes


_RUNTIME_OBSERVATION_TOOLS = frozenset(
    {
        "browser-security",
        "falco",
        "iast",
        "kubescape",
        "mobsf",
        "nuclei",
        "protocol-security",
        "prowler",
        "rasp",
        "restler",
        "tls-scan",
        "zap",
    }
)
_REPRODUCTION_TOOLS = frozenset(
    {
        "atheris",
        "authorization-security",
        "clusterfuzzlite",
        "crosshair",
        "hypothesis",
        "iast",
        "native-sanitizers",
        "oast",
        "schemathesis",
        "secret-verification",
    }
)
_ORDER = {
    ValidationStatus.STATIC_CANDIDATE: 0,
    ValidationStatus.CORROBORATED: 1,
    ValidationStatus.STATIC_PATH_CONFIRMED: 2,
    ValidationStatus.RUNTIME_OBSERVED: 3,
    ValidationStatus.REPRODUCED: 4,
}


def apply_finding_validation(
    findings: list[Finding], artifacts: dict[str, Any]
) -> dict[str, Any]:
    """Assign conservative evidence tiers without inferring safety from absence."""

    runtime_locations = _runtime_observed_locations(
        artifacts.get("runtime-trace-correlation.json"),
        artifacts.get("boundary-graph.json"),
    )
    records: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for finding in findings:
        tools = sorted({source.tool for source in finding.sources})
        paths = sorted(
            {
                location.path
                for location in finding.locations
                if location.path and location.path != "<repository>"
            }
        )
        candidates: list[tuple[ValidationStatus, str]] = [
            (
                ValidationStatus.STATIC_CANDIDATE,
                "A scanner or bundled analyzer reported the condition.",
            )
        ]
        corroboration = finding.evidence.get("cross_tool_corroboration")
        corroborated = (
            isinstance(corroboration, dict)
            and int(corroboration.get("independent_perspectives") or 0) >= 2
        )
        if corroborated:
            candidates.append(
                (
                    ValidationStatus.CORROBORATED,
                    "At least two independent engine families observed the same normalized condition.",
                )
            )
        if _has_static_path(finding):
            candidates.append(
                (
                    ValidationStatus.STATIC_PATH_CONFIRMED,
                    "Native scanner evidence retained an ordered source-to-sink code path.",
                )
            )
        runtime_tools = sorted(set(tools) & _RUNTIME_OBSERVATION_TOOLS)
        traced_locations = _matching_runtime_locations(finding, runtime_locations)
        if runtime_tools or traced_locations:
            basis = (
                "Runtime-producing tool(s) observed the condition: "
                + ", ".join(runtime_tools)
                if runtime_tools
                else "Deployment-bound runtime traces exercised the finding's exact source location."
            )
            candidates.append((ValidationStatus.RUNTIME_OBSERVED, basis))
        candidate_reproduction_tools = sorted(set(tools) & _REPRODUCTION_TOOLS)
        valid_bindings, rejected_bindings = _validated_reproduction_bindings(
            finding, artifacts
        )
        reproduction_tools = candidate_reproduction_tools if valid_bindings else []
        if reproduction_tools:
            candidates.append(
                (
                    ValidationStatus.REPRODUCED,
                    "A failure- or exploit-oriented companion reproduced the condition: "
                    + ", ".join(reproduction_tools),
                )
            )
        status, reason = max(candidates, key=lambda item: _ORDER[item[0]])
        dimensions = _evidence_dimensions(
            finding,
            corroborated=corroborated,
            static_path=_has_static_path(finding),
            runtime_observed=bool(runtime_tools or traced_locations),
            reproduced=bool(reproduction_tools),
            artifacts=artifacts,
            valid_bindings=valid_bindings,
        )
        finding.validation_status = status
        finding.validation_reasons = [reason]
        finding.validation_limitations = _limitations(status)
        finding.evidence["validation"] = {
            "status": status.value,
            "reasons": list(finding.validation_reasons),
            "limitations": list(finding.validation_limitations),
            "runtime_tools": runtime_tools,
            "reproduction_tools": reproduction_tools,
            "reproduction_bindings": valid_bindings,
            "reproduction_bindings_rejected": rejected_bindings,
            "runtime_trace_locations": traced_locations,
            "dimensions": dimensions,
        }
        counts[status.value] += 1
        records.append(
            {
                "finding_id": finding.finding_id,
                "status": status.value,
                "reasons": list(finding.validation_reasons),
                "limitations": list(finding.validation_limitations),
                "tools": tools,
                "paths": paths,
                "runtime_tools": runtime_tools,
                "reproduction_tools": reproduction_tools,
                "reproduction_bindings": valid_bindings,
                "reproduction_bindings_rejected": rejected_bindings,
                "runtime_trace_locations": traced_locations,
                "dimensions": dimensions,
            }
        )
    records.sort(key=lambda item: str(item["finding_id"]))
    return {
        "schema_version": "1.0",
        "analysis": "conservative-finding-validation-tiers",
        "summary": {
            "findings": len(records),
            "by_status": {
                status.value: counts[status.value] for status in ValidationStatus
            },
            "runtime_observed_or_stronger": sum(
                count
                for name, count in counts.items()
                if _ORDER[ValidationStatus(name)]
                >= _ORDER[ValidationStatus.RUNTIME_OBSERVED]
            ),
            "reproduced": counts[ValidationStatus.REPRODUCED.value],
        },
        "records": records,
        "claim_boundary": (
            "Validation tier is a compatibility summary; dimensions retain independent "
            "evidence for reachability, attacker control, execution, effect, reproduction, "
            "and environment parity. "
            "Missing runtime evidence never disproves a finding or establishes a false positive."
        ),
    }


def _validated_reproduction_bindings(
    finding: Finding, artifacts: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[str]]:
    raw = finding.evidence.get("reproduction_bindings")
    if not isinstance(raw, list):
        single = finding.evidence.get("reproduction_binding")
        raw = [single] if isinstance(single, dict) else []
    source_inventory = artifacts.get("source-inventory.json")
    source_sha256 = (
        str(source_inventory.get("source_sha256") or "")
        if isinstance(source_inventory, dict)
        else ""
    )
    fingerprints = {finding.fingerprint}
    correlation = finding.evidence.get("cross_tool_corroboration")
    if isinstance(correlation, dict):
        for observation in correlation.get("observations", []):
            if isinstance(observation, dict):
                fingerprints.add(str(observation.get("fingerprint") or ""))
    required = {
        "schema_version",
        "source_sha256",
        "finding_fingerprint",
        "path",
        "line",
        "payload_sha256",
        "oracle",
        "impact_observed",
        "negative_control_passed",
        "environment_sha256",
        "deployment_sha256",
    }
    valid: list[dict[str, Any]] = []
    rejected: list[str] = []
    if len(raw) > 100:
        rejected.append(f"{len(raw) - 100} binding(s) exceeded the governed limit")
    for index, item in enumerate(raw[:100]):
        reason = ""
        if not isinstance(item, dict) or set(item) != required:
            reason = "fields do not match reproduction binding schema 1.0"
        elif item.get("schema_version") != "1.0":
            reason = "unsupported reproduction binding version"
        elif not source_sha256 or item.get("source_sha256") != source_sha256:
            reason = "source digest does not match the sealed inventory"
        elif str(item.get("finding_fingerprint") or "") not in fingerprints:
            reason = "finding fingerprint is not retained by correlation"
        elif len(str(item.get("finding_fingerprint") or "")) > 200:
            reason = "finding fingerprint exceeds the governed length"
        elif not _binding_location_matches(finding, item):
            reason = "reproduced location does not match the finding"
        elif any(
            not _digest(str(item.get(name) or ""))
            for name in (
                "payload_sha256",
                "environment_sha256",
                "deployment_sha256",
            )
        ):
            reason = "payload, environment, or deployment digest is invalid"
        elif (
            not str(item.get("oracle") or "").strip()
            or len(str(item.get("oracle") or "")) > 1000
        ):
            reason = "security oracle is empty or oversized"
        elif item.get("impact_observed") is not True:
            reason = "harmful effect was not observed"
        elif item.get("negative_control_passed") is not True:
            reason = "negative control did not pass"
        if reason:
            rejected.append(f"binding {index}: {reason}")
        else:
            valid.append(dict(item))
    return valid, rejected


def _binding_location_matches(finding: Finding, binding: dict[str, Any]) -> bool:
    path = str(binding.get("path") or "")
    line = binding.get("line")
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        return False
    return any(
        location.path == path
        and location.start_line is not None
        and location.start_line <= line <= (location.end_line or location.start_line)
        for location in finding.locations
    )


def _evidence_dimensions(
    finding: Finding,
    *,
    corroborated: bool,
    static_path: bool,
    runtime_observed: bool,
    reproduced: bool,
    artifacts: dict[str, Any],
    valid_bindings: list[dict[str, Any]],
) -> dict[str, str]:
    graph = finding.evidence.get("graph_context")
    corroborating = (
        graph.get("corroborating_evidence") if isinstance(graph, dict) else None
    )
    raw_states = (
        corroborating.get("reachability_states", [])
        if isinstance(corroborating, dict)
        else []
    )
    states = (
        {str(value) for value in raw_states} if isinstance(raw_states, list) else set()
    )
    attacker_control = _modeled_attacker_control(finding)
    runtime_trace = artifacts.get("runtime-trace-correlation.json")
    deployment = (
        str(runtime_trace.get("deployment_sha256") or "")
        if isinstance(runtime_trace, dict)
        else ""
    )
    binding_deployments = {
        str(item.get("deployment_sha256") or "") for item in valid_bindings
    }
    parity = "not-established"
    if reproduced and deployment:
        parity = "established" if deployment in binding_deployments else "conflicting"
    return {
        "condition_observed": "established",
        "independent_corroboration": (
            "established" if corroborated else "not-established"
        ),
        "static_source_to_sink": "established" if static_path else "not-established",
        "entry_point_reachability": (
            "established"
            if "executable" in states
            else "conflicting"
            if "disconnected" in states
            else "not-established"
        ),
        "attacker_control": "established" if attacker_control else "not-established",
        "runtime_execution": "established" if runtime_observed else "not-established",
        "harmful_effect": "established" if reproduced else "not-established",
        "reproduction": "established" if reproduced else "not-established",
        "production_environment_parity": parity,
    }


def _modeled_attacker_control(finding: Finding) -> bool:
    flows = finding.evidence.get("sarif_code_flows")
    if not isinstance(flows, list):
        return False
    for flow in flows:
        if not isinstance(flow, dict) or not isinstance(flow.get("steps"), list):
            continue
        steps = flow["steps"]
        if not steps or not isinstance(steps[0], dict):
            continue
        raw_kinds = steps[0].get("kinds", [])
        kinds = (
            {str(value).casefold() for value in raw_kinds}
            if isinstance(raw_kinds, list)
            else set()
        )
        if "source" in kinds or "user" in kinds or "remote" in kinds:
            return True
    return False


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _has_static_path(finding: Finding) -> bool:
    flows = finding.evidence.get("sarif_code_flows")
    if not isinstance(flows, list):
        return False
    return any(_valid_static_flow(flow) for flow in flows)


def _valid_static_flow(flow: object) -> bool:
    if not isinstance(flow, dict) or not _positive_integer(flow.get("step_count"), 2):
        return False
    steps = flow.get("steps")
    return (
        isinstance(steps, list)
        and len(steps) >= 2
        and all(
            isinstance(step, dict)
            and bool(str(step.get("path") or ""))
            and _positive_integer(step.get("line"), 1)
            for step in steps
        )
    )


def _positive_integer(value: object, minimum: int) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= minimum


def _runtime_observed_locations(
    trace_value: object, graph_value: object
) -> set[tuple[str, int]]:
    if (
        not isinstance(trace_value, dict)
        or trace_value.get("complete") is not True
        or not isinstance(graph_value, dict)
    ):
        return set()
    raw_edges = graph_value.get("edges")
    raw_traces = trace_value.get("traces")
    if not isinstance(raw_edges, list) or not isinstance(raw_traces, list):
        return set()
    edges = {
        hashlib.sha256(canonical_bytes(edge)).hexdigest(): edge
        for edge in raw_edges
        if isinstance(edge, dict)
    }
    locations: set[tuple[str, int]] = set()
    for trace in raw_traces:
        if not isinstance(trace, dict):
            continue
        edge = edges.get(str(trace.get("edge_sha256") or ""))
        if not isinstance(edge, dict):
            continue
        path = str(edge.get("source") or "")
        raw_line = edge.get("line")
        if (
            path
            and not isinstance(raw_line, bool)
            and isinstance(raw_line, int)
            and raw_line >= 1
        ):
            locations.add((path, raw_line))
    return locations


def _matching_runtime_locations(
    finding: Finding, observed: set[tuple[str, int]]
) -> list[str]:
    matches: set[str] = set()
    for location in finding.locations:
        if not location.path or location.start_line is None:
            continue
        end_line = location.end_line or location.start_line
        for path, line in observed:
            if path == location.path and location.start_line <= line <= end_line:
                matches.add(f"{path}:{line}")
    return sorted(matches)


def _limitations(status: ValidationStatus) -> list[str]:
    if status is ValidationStatus.REPRODUCED:
        return [
            "Reproduction is bound to the retained test or companion environment, not every production state."
        ]
    if status is ValidationStatus.RUNTIME_OBSERVED:
        return [
            "Runtime observation establishes execution, not necessarily attacker control or exploitability."
        ]
    if status is ValidationStatus.STATIC_PATH_CONFIRMED:
        return [
            "A static source-to-sink path depends on the contributing engine's framework and sanitizer models."
        ]
    if status is ValidationStatus.CORROBORATED:
        return [
            "Independent static observations can share the same missing framework or runtime assumption."
        ]
    return [
        "The condition has not been corroborated by a retained path or runtime observation."
    ]
