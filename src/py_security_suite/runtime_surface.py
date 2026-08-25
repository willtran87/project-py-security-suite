from __future__ import annotations

from typing import Any

from .models import ToolRun, ToolStatus


_RUNTIME_LANES = frozenset(
    {
        "ai-security",
        "authorization-security",
        "browser-security",
        "cloud-attack-path",
        "database-security",
        "event-security",
        "falco",
        "iast",
        "kubescape",
        "mobsf",
        "nuclei",
        "oast",
        "protocol-security",
        "prowler",
        "rasp",
        "restler",
        "surface-inventory",
        "tls-scan",
        "zap",
    }
)
_CONTEXT_FIELDS = ("surface_sha256", "deployment_sha256", "target_manifest_sha256")
_TRUTH_CRITICAL_LANES = frozenset(
    {
        "ai-security",
        "authorization-security",
        "cloud-attack-path",
        "database-security",
        "event-security",
        "nuclei",
        "prowler",
        "surface-inventory",
        "zap",
    }
)
_CORROBORATION_PEERS = {
    "cloud-attack-path": frozenset({"prowler"}),
    "nuclei": frozenset({"zap"}),
    "prowler": frozenset({"cloud-attack-path"}),
    "zap": frozenset({"nuclei"}),
}
_INDEPENDENCE_MARKERS = (
    "independent",
    "differential",
    "qualification",
    "corroborat",
    "multi-engine",
)


def runtime_surface_binding_artifact(
    tool_runs: list[ToolRun], artifacts: dict[str, Any]
) -> dict[str, Any]:
    """Bind runtime assurance lanes to one surface and semantic-truth denominator."""

    applicable = sorted(
        run.tool for run in tool_runs if run.tool in _RUNTIME_LANES and run.applicable
    )
    contexts: dict[str, dict[str, str]] = {}
    missing: list[str] = []
    invalid: list[str] = []
    truth_gaps: list[str] = []
    documents: dict[str, dict[str, Any]] = {}
    for tool in applicable:
        run = next(item for item in tool_runs if item.tool == tool)
        document = artifacts.get(f"{tool}-summary.json")
        if run.status is not ToolStatus.COMPLETED or not isinstance(document, dict):
            missing.append(tool)
            continue
        context = document.get("context")
        execution = document.get("execution")
        if not isinstance(context, dict) or not isinstance(execution, dict):
            invalid.append(tool)
            continue
        normalized = {field: str(context.get(field) or "") for field in _CONTEXT_FIELDS}
        if any(not _digest(value) for value in normalized.values()):
            invalid.append(tool)
            continue
        contexts[tool] = normalized
        documents[tool] = document
        expected = execution.get("canaries_expected")
        observed = execution.get("canaries_observed")
        if (
            isinstance(expected, bool)
            or not isinstance(expected, int)
            or expected < 1
            or observed != expected
        ):
            truth_gaps.append(tool)

    canonical = contexts.get("surface-inventory")
    mismatched = sorted(
        tool
        for tool, context in contexts.items()
        if canonical is not None and context != canonical
    )
    if applicable and canonical is None and "surface-inventory" not in missing:
        missing.append("surface-inventory")

    # A clean claim needs either independently qualified semantics in its own
    # evidence or a genuinely different producer observing the same denominator.
    for tool, document in documents.items():
        if tool not in _TRUTH_CRITICAL_LANES or document.get("findings"):
            continue
        execution = document.get("execution") or {}
        features = [str(item).casefold() for item in execution.get("features") or []]
        locally_independent = any(
            marker in feature
            for feature in features
            for marker in _INDEPENDENCE_MARKERS
        )
        producer = str(document.get("producer") or "")
        corroborated = any(
            peer in _CORROBORATION_PEERS.get(tool, frozenset())
            and peer_document.get("findings") == []
            and str(peer_document.get("producer") or "") not in {"", producer}
            and contexts.get(peer) == contexts.get(tool)
            for peer, peer_document in documents.items()
        )
        if not locally_independent and not corroborated:
            truth_gaps.append(tool)

    truth_gaps = sorted(set(truth_gaps))
    complete = bool(
        not applicable
        or (
            canonical is not None
            and not missing
            and not invalid
            and not mismatched
            and not truth_gaps
            and set(contexts) == set(applicable)
        )
    )
    return {
        "schema_version": "1.0",
        "analysis": "canonical-runtime-surface-and-truth-diversity",
        "complete": complete,
        "canonical_context": canonical,
        "applicable_lanes": applicable,
        "bound_lanes": sorted(contexts),
        "missing_lanes": sorted(set(missing)),
        "invalid_context_lanes": sorted(set(invalid)),
        "mismatched_context_lanes": mismatched,
        "truth_diversity_gaps": truth_gaps,
        "lane_contexts": contexts,
    }


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
