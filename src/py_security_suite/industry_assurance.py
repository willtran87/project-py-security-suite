from __future__ import annotations

import math
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from . import industry_resilience_catalog as resilience_catalog
from .benchmark_assurance import (
    BenchmarkAssuranceError,
    verify_execution_receipt_signature,
)
from .benchmark_protocols import validate_protocol_thresholds
from .industry_benchmark_scoring import (
    meets_protocol_thresholds as _meets_protocol_thresholds,
    protocol_acceptance as _protocol_acceptance,
    protocol_metrics_valid as _protocol_metrics_valid,
)
from .industry_benchmark_catalog import _BENCHMARKS, _STANDARDS_WATCHLIST
from .industry_extension_evidence import (
    industry_extension_runner_requirements,
    industry_extension_score_evidence_valid,
)
from .industry_profile_catalog import _ASSURANCE_PROFILES
from .industry_receipt_trust import receipt_authority_projection
from .industry_standards_catalog import _STANDARDS
from .path_safety import read_regular_file
from .prioritization import finding_priority
from .strict_json import loads as strict_loads


_POLICY_PATH = "security/industry-assurance-policy.json"
_MAX_POLICY_BYTES = 4 * 1024 * 1024
_DIGEST = "0123456789abcdef"


def _validate_builtin_catalog(
    standards: tuple[dict[str, Any], ...] | None = None,
    profiles: dict[str, dict[str, Any]] | None = None,
    benchmarks: tuple[dict[str, Any], ...] | None = None,
) -> None:
    """Fail closed when built-in catalog identities or references are corrupt."""
    standards = _STANDARDS if standards is None else standards
    profiles = _ASSURANCE_PROFILES if profiles is None else profiles
    benchmarks = _BENCHMARKS if benchmarks is None else benchmarks

    standard_ids = [item.get("id") for item in standards]
    benchmark_ids = [item.get("id") for item in benchmarks]
    for label, identifiers in (
        ("standard", standard_ids),
        ("benchmark", benchmark_ids),
    ):
        if any(
            not isinstance(identifier, str) or not identifier
            for identifier in identifiers
        ):
            raise ValueError(f"built-in {label} catalog contains an invalid identifier")
        if len(identifiers) != len(set(identifiers)):
            raise ValueError(f"built-in {label} catalog contains duplicate identifiers")

    known_standards = set(standard_ids)
    for profile_id, profile in profiles.items():
        if not profile_id or not isinstance(profile, dict):
            raise ValueError("built-in assurance profile has an invalid identity")
        references = list(profile.get("standards", []))
        controls = profile.get("controls", [])
        procedures = profile.get("procedures", [])
        if not references or not controls or not procedures:
            raise ValueError(
                f"assurance profile {profile_id!r} is structurally incomplete"
            )
        for row_name, rows, minimum_size in (
            ("control", controls, 4),
            ("procedure", procedures, 6),
        ):
            for row in rows:
                if not isinstance(row, tuple) or len(row) < minimum_size:
                    raise ValueError(
                        f"assurance profile {profile_id!r} has an invalid {row_name}"
                    )
                references.append(row[0])
        unresolved = sorted(
            {
                reference
                for reference in references
                if not isinstance(reference, str) or reference not in known_standards
            },
            key=str,
        )
        if unresolved:
            raise ValueError(
                f"assurance profile {profile_id!r} references unknown standards: "
                + ", ".join(map(str, unresolved))
            )


_validate_builtin_catalog()


_INTEROPERABILITY = (
    ("SARIF", "2.1.0", ("results.sarif",)),
    ("CycloneDX", "1.7", ("sbom.cdx.json", "artifact-sbom.cdx.json")),
    ("SPDX", "2.x/3.x", ("reuse-compliance.json",)),
    ("CycloneDX-VEX", "1.7", ("risk-intelligence.json",)),
    ("OpenVEX", "0.2", ("risk-intelligence.json",)),
    ("CSAF-VEX", "2.0", ("risk-intelligence.json",)),
    ("SCAP", "1.4", ("scap-results.xml", "scap-results.json")),
    ("OSCAL", "1.2.2", ("oscal-assessment-results.json",)),
    ("STIX", "2.1", ("security-automation-interoperability.json",)),
    ("TAXII", "2.1", ("security-automation-interoperability.json",)),
    ("FIRST-TLP", "2.0", ("security-automation-interoperability.json",)),
    ("FIRST-IEP", "2.0", ("security-automation-interoperability.json",)),
    ("VERIS", "1.3.6-policy-pinned", ("security-automation-interoperability.json",)),
    ("A2A", "1.0.0", ("security-automation-interoperability.json",)),
    ("W3C-VC", "2.0", ("security-automation-interoperability.json",)),
    ("OpenID4VP", "1.0", ("security-automation-interoperability.json",)),
    ("OpenID4VCI", "1.0", ("security-automation-interoperability.json",)),
    ("C2PA", "2.4", ("trust-policy-attestation.json",)),
    ("CACAO", "2.0", ("security-automation-interoperability.json",)),
    ("OpenC2", "1.0", ("security-automation-interoperability.json",)),
    ("OCSF", "policy-pinned", ("security-automation-interoperability.json",)),
    ("SCITT", "RFC-9943", ("security-automation-interoperability.json",)),
    ("COSE-Receipts", "RFC-9942", ("security-automation-interoperability.json",)),
    ("OpenAPI", "3.1.1-policy-pinned", ("security-automation-interoperability.json",)),
    ("AsyncAPI", "3.0.0-policy-pinned", ("security-automation-interoperability.json",)),
    ("GraphQL", "september-2025", ("security-automation-interoperability.json",)),
    ("JSON-Schema", "2020-12", ("security-automation-interoperability.json",)),
    (
        "OpenTelemetry-SemConv",
        "1.44.0-policy-pinned",
        ("security-automation-interoperability.json",),
    ),
)


def _evidence_stage(
    identifier: str, required: tuple[str, ...], artifacts: dict[str, Any]
) -> dict[str, Any]:
    present = [name for name in required if _complete_artifact(artifacts.get(name))]
    missing = [name for name in required if name not in present]
    return {
        "id": identifier,
        "evidence_required": list(required),
        "evidence_present": present,
        "complete": bool(required) and not missing,
        "gaps": [f"missing or incomplete artifact: {name}" for name in missing],
    }


def _lifecycle_traceability(
    artifacts: dict[str, Any], source_sha256: str
) -> dict[str, Any]:
    stages = [
        _evidence_stage(
            "requirements", ("security-requirements-coverage.json",), artifacts
        ),
        _evidence_stage(
            "architecture",
            ("static-architecture.json", "architecture-history.json"),
            artifacts,
        ),
        _evidence_stage("implementation", ("source-inventory.json",), artifacts),
        _evidence_stage(
            "verification", ("test-evidence.json", "effectiveness.json"), artifacts
        ),
        _evidence_stage("release", ("release-readiness.json",), artifacts),
        _evidence_stage("operation", ("operational-trend.json",), artifacts),
        _evidence_stage("retirement", ("closure-plan.json",), artifacts),
    ]
    requirements = artifacts.get("security-requirements-coverage.json")
    applicable = (
        requirements.get("applicable_requirements", 0)
        if isinstance(requirements, dict)
        else 0
    )
    evidenced = (
        requirements.get("evidenced_requirements", 0)
        if isinstance(requirements, dict)
        else 0
    )
    trace_complete = bool(
        isinstance(applicable, int)
        and not isinstance(applicable, bool)
        and isinstance(evidenced, int)
        and not isinstance(evidenced, bool)
        and applicable > 0
        and evidenced == applicable
        and requirements.get("complete") is True
        if isinstance(requirements, dict)
        else False
    )
    graph = _lifecycle_trace_graph(artifacts, source_sha256)
    complete = (
        bool(source_sha256)
        and trace_complete
        and all(stage["complete"] for stage in stages)
        and graph["complete"] is True
    )
    gaps = [gap for stage in stages for gap in stage["gaps"]]
    if not source_sha256:
        gaps.append("source inventory digest is missing")
    if not trace_complete:
        gaps.append("bidirectional requirements evidence is incomplete")
    gaps.extend(graph["gaps"])
    return {
        "schema_version": "1.0",
        "analysis": "software-and-system-life-cycle-traceability",
        "complete": complete,
        "source_sha256": source_sha256,
        "stages_assessed": len(stages),
        "stages_complete": sum(stage["complete"] for stage in stages),
        "stages": stages,
        "requirements_traceability": {
            "applicable_requirements": applicable
            if isinstance(applicable, int) and not isinstance(applicable, bool)
            else 0,
            "evidenced_requirements": evidenced
            if isinstance(evidenced, int) and not isinstance(evidenced, bool)
            else 0,
            "bidirectional_trace_complete": trace_complete,
        },
        "graph_traceability": graph,
        "gaps": list(dict.fromkeys(gaps))[:100],
        "claim_boundary": (
            "Stage evidence and requirement counts establish an auditable traceability "
            "surface; they do not prove that every life-cycle decision is correct."
        ),
    }


def _lifecycle_trace_graph(
    artifacts: dict[str, Any], source_sha256: str
) -> dict[str, Any]:
    raw = artifacts.get("lifecycle-traceability-evidence.json")
    gaps: list[str] = []
    expected_root = {
        "schema_version",
        "source_sha256",
        "nodes",
        "links",
        "change_sets",
        "review",
    }
    if not isinstance(raw, dict):
        gaps.append("governed lifecycle trace graph is missing")
        raw = {}
    elif set(raw) != expected_root or raw.get("schema_version") != "1.0":
        gaps.append("lifecycle trace graph does not match the governed root contract")
    if raw.get("source_sha256") != source_sha256 or not _digest(source_sha256):
        gaps.append("lifecycle trace graph is not bound to the scanned source")

    stages = (
        "requirements",
        "architecture",
        "implementation",
        "verification",
        "release",
        "operation",
        "retirement",
    )
    stage_order = {stage: index for index, stage in enumerate(stages)}
    raw_nodes = raw.get("nodes")
    raw_links = raw.get("links")
    raw_changes = raw.get("change_sets")
    nodes = raw_nodes if isinstance(raw_nodes, list) else []
    links = raw_links if isinstance(raw_links, list) else []
    changes = raw_changes if isinstance(raw_changes, list) else []
    if not isinstance(raw_nodes, list):
        gaps.append("lifecycle nodes must be an array")
    if not isinstance(raw_links, list):
        gaps.append("lifecycle links must be an array")
    if not isinstance(raw_changes, list):
        gaps.append("lifecycle change sets must be an array")
    if len(nodes) > 50_000 or len(links) > 100_000 or len(changes) > 10_000:
        gaps.append("lifecycle trace graph exceeds a governed record limit")
    nodes = nodes[:50_000]
    links = links[:100_000]
    changes = changes[:10_000]

    node_ids: set[str] = set()
    node_stages: dict[str, str] = {}
    applicable_nodes: set[str] = set()
    stages_present: set[str] = set()
    for index, node in enumerate(nodes):
        if not isinstance(node, dict) or set(node) != {
            "id",
            "stage",
            "artifact",
            "sha256",
            "subject_sha256",
            "applicable",
        }:
            gaps.append(f"lifecycle node {index} does not match its governed contract")
            continue
        identifier = str(node.get("id") or "")
        stage = str(node.get("stage") or "")
        if (
            not _text(identifier, 200)
            or identifier in node_ids
            or stage not in stage_order
            or not _artifact_name(node.get("artifact"))
            or not _digest(str(node.get("sha256") or ""))
            or node.get("subject_sha256") != source_sha256
            or not isinstance(node.get("applicable"), bool)
        ):
            gaps.append(f"lifecycle node {index} is invalid or source-unbound")
            continue
        node_ids.add(identifier)
        node_stages[identifier] = stage
        stages_present.add(stage)
        if node["applicable"] is True:
            applicable_nodes.add(identifier)

    for stage in stages:
        if stage not in stages_present:
            gaps.append(f"lifecycle graph has no node for stage: {stage}")

    outgoing: dict[str, set[str]] = {identifier: set() for identifier in node_ids}
    incoming: dict[str, set[str]] = {identifier: set() for identifier in node_ids}
    seen_links: set[tuple[str, str, str]] = set()
    allowed_link_types = {
        "derives",
        "implements",
        "verifies",
        "releases",
        "operates",
        "retires",
        "impacts",
    }
    for index, link in enumerate(links):
        if not isinstance(link, dict) or set(link) != {
            "source",
            "target",
            "type",
            "evidence_sha256",
        }:
            gaps.append(f"lifecycle link {index} does not match its governed contract")
            continue
        source = str(link.get("source") or "")
        target = str(link.get("target") or "")
        relation = str(link.get("type") or "")
        identity = (source, target, relation)
        if (
            source not in node_ids
            or target not in node_ids
            or source == target
            or relation not in allowed_link_types
            or identity in seen_links
            or not _digest(str(link.get("evidence_sha256") or ""))
        ):
            gaps.append(f"lifecycle link {index} is dangling, duplicate, or invalid")
            continue
        if stage_order[node_stages[source]] >= stage_order[node_stages[target]]:
            gaps.append(
                f"lifecycle link reverses stage direction: {source} -> {target}"
            )
            continue
        seen_links.add(identity)
        outgoing[source].add(target)
        incoming[target].add(source)

    for identifier in sorted(applicable_nodes):
        stage = node_stages[identifier]
        if stage != "requirements" and not incoming[identifier]:
            gaps.append(
                f"applicable lifecycle node has no upstream trace: {identifier}"
            )
        if stage != "retirement" and not outgoing[identifier]:
            gaps.append(
                f"applicable lifecycle node has no downstream trace: {identifier}"
            )

    requirement_nodes = {
        identifier
        for identifier in applicable_nodes
        if node_stages[identifier] == "requirements"
    }
    if not requirement_nodes:
        gaps.append("lifecycle graph has no applicable requirement node")
    nodes_reaching_retirement: set[str] = set()
    for requirement in requirement_nodes:
        pending = [requirement]
        visited = {requirement}
        reached_stages = {"requirements"}
        while pending:
            current = pending.pop()
            for target in outgoing[current]:
                reached_stages.add(node_stages[target])
                if target not in visited:
                    visited.add(target)
                    pending.append(target)
        if set(stages) <= reached_stages:
            nodes_reaching_retirement.add(requirement)
        else:
            missing = ", ".join(
                stage for stage in stages if stage not in reached_stages
            )
            gaps.append(
                f"requirement lacks end-to-end lifecycle coverage: {requirement} ({missing})"
            )

    change_ids: set[str] = set()
    verified_changes = 0
    for index, change in enumerate(changes):
        if not isinstance(change, dict) or set(change) != {
            "id",
            "changed_node_ids",
            "impact_node_ids",
            "verified",
            "evidence_sha256",
        }:
            gaps.append(f"change set {index} does not match its governed contract")
            continue
        identifier = str(change.get("id") or "")
        changed = change.get("changed_node_ids")
        impacts = change.get("impact_node_ids")
        valid_nodes = (
            isinstance(changed, list)
            and bool(changed)
            and isinstance(impacts, list)
            and bool(impacts)
            and len(changed) == len(set(changed))
            and len(impacts) == len(set(impacts))
            and set(changed) <= node_ids
            and set(impacts) <= node_ids
        )
        if (
            not _text(identifier, 200)
            or identifier in change_ids
            or not valid_nodes
            or not isinstance(change.get("verified"), bool)
            or not _digest(str(change.get("evidence_sha256") or ""))
        ):
            gaps.append(f"change set {index} is invalid or references unknown nodes")
            continue
        change_ids.add(identifier)
        changed_ids = set(cast(list[str], changed))
        impact_ids = set(cast(list[str], impacts))
        expected_impacts: set[str] = set()
        pending = list(changed_ids)
        visited = set(changed_ids)
        while pending:
            current = pending.pop()
            for target in outgoing[current]:
                expected_impacts.add(target)
                if target not in visited:
                    visited.add(target)
                    pending.append(target)
        if changed_ids & impact_ids or impact_ids != expected_impacts:
            gaps.append(
                f"change set does not exactly cover downstream graph impact: {identifier}"
            )
        if change["verified"] is True:
            verified_changes += 1
        else:
            gaps.append(f"change impact is not independently verified: {identifier}")
    if not change_ids:
        gaps.append("lifecycle graph has no verified change-impact sample")

    review = raw.get("review")
    reviewer_count = 0
    approved = False
    if isinstance(review, dict):
        reviewers = review.get("independent_reviewers")
        reviewer_count = (
            len(reviewers)
            if isinstance(reviewers, list)
            and len(reviewers) == len(set(reviewers))
            and all(_text(value, 200) for value in reviewers)
            else 0
        )
        approved = review.get("approved") is True
    review_time_valid = bool(
        isinstance(review, dict) and _iso_timestamp(review.get("reviewed_at"))
    )
    if review_time_valid:
        try:
            review_record = cast(dict[str, Any], review)
            review_time_valid = datetime.fromisoformat(
                str(review_record["reviewed_at"]).replace("Z", "+00:00")
            ) <= datetime.now(UTC)
        except ValueError:
            review_time_valid = False
    if (
        not isinstance(review, dict)
        or set(review)
        != {"reviewed_at", "independent_reviewers", "approved", "approval_sha256"}
        or not review_time_valid
        or reviewer_count < 2
        or not approved
        or not _digest(str(review.get("approval_sha256") or ""))
    ):
        gaps.append("independent lifecycle trace review and approval are incomplete")

    unique_gaps = list(dict.fromkeys(gaps))[:100]
    return {
        "applicable": isinstance(
            artifacts.get("lifecycle-traceability-evidence.json"), dict
        ),
        "nodes": len(node_ids),
        "links": len(seen_links),
        "applicable_nodes": len(applicable_nodes),
        "requirements_with_end_to_end_trace": len(nodes_reaching_retirement),
        "change_sets": len(change_ids),
        "verified_change_sets": verified_changes,
        "independent_reviewers": reviewer_count,
        "approved": approved,
        "complete": not unique_gaps,
        "gaps": unique_gaps,
    }


def _architecture_evaluation(artifacts: dict[str, Any]) -> dict[str, Any]:
    criteria = [
        _evidence_stage("stakeholder-concerns", ("domain-assurance.json",), artifacts),
        _evidence_stage(
            "quality-attributes",
            ("static-architecture.json", "code-health.json"),
            artifacts,
        ),
        _evidence_stage("risk-and-threat-paths", ("risk-paths.json",), artifacts),
        _evidence_stage(
            "decisions-and-change", ("architecture-history.json",), artifacts
        ),
        _evidence_stage(
            "structural-corroboration", ("structural-synthesis.json",), artifacts
        ),
        _evidence_stage(
            "independent-review", ("audit-package-verification.json",), artifacts
        ),
    ]
    gaps = [gap for criterion in criteria for gap in criterion["gaps"]]
    return {
        "schema_version": "1.0",
        "analysis": "scenario-based-architecture-evaluation",
        "complete": all(criterion["complete"] for criterion in criteria),
        "criteria_assessed": len(criteria),
        "criteria_satisfied": sum(criterion["complete"] for criterion in criteria),
        "criteria": criteria,
        "gaps": list(dict.fromkeys(gaps))[:100],
        "claim_boundary": (
            "Evidence-surface completion supports architecture evaluation but does not "
            "replace stakeholder judgment or certify an architecture."
        ),
    }


def _process_capability_assessment(artifacts: dict[str, Any]) -> dict[str, Any]:
    definitions = (
        (
            "requirements",
            ("security-requirements-coverage.json", "lifecycle-traceability.json"),
        ),
        (
            "implementation-quality",
            ("code-health.json", "static-architecture.json"),
        ),
        ("verification", ("test-evidence.json", "effectiveness.json")),
        (
            "build-and-release",
            ("release-readiness.json", "security-passport.json"),
        ),
        (
            "vulnerability-response",
            ("risk-intelligence.json", "closure-plan.json"),
        ),
        (
            "incident-and-operation",
            ("operational-trend.json", "procedure-assessment.json"),
        ),
        (
            "governance-and-improvement",
            ("capability-manifest.json", "audit-package-verification.json"),
        ),
    )
    dimensions: list[dict[str, Any]] = []
    for identifier, required in definitions:
        present = [name for name in required if name in artifacts]
        complete_evidence = [
            name for name in required if _complete_artifact(artifacts.get(name))
        ]
        independent = _complete_artifact(
            artifacts.get("audit-package-verification.json")
        )
        level = (
            3
            if len(complete_evidence) == len(required) and independent
            else 2
            if len(complete_evidence) == len(required)
            else 1
            if present
            else 0
        )
        gaps = [
            f"missing or incomplete artifact: {name}"
            for name in required
            if name not in complete_evidence
        ]
        if level == 2:
            gaps.append("independent audit-package verification is missing")
        dimensions.append(
            {
                "id": identifier,
                "capability_level": level,
                "evidence_required": list(required),
                "evidence_present": complete_evidence,
                "gaps": gaps,
            }
        )
    minimum = min((int(item["capability_level"]) for item in dimensions), default=0)
    gaps = [str(gap) for item in dimensions for gap in item["gaps"]]
    return {
        "schema_version": "1.0",
        "analysis": "software-process-capability-assessment",
        "complete": minimum >= 2,
        "measurement_scale": "ISO-IEC-33020-inspired-bounded-levels-0-through-3",
        "minimum_capability_level": minimum,
        "dimensions_assessed": len(dimensions),
        "dimensions_level_2_or_higher": sum(
            item["capability_level"] >= 2 for item in dimensions
        ),
        "dimensions": dimensions,
        "gaps": list(dict.fromkeys(gaps))[:100],
        "claim_boundary": (
            "These bounded evidence levels are readiness indicators, not an ISO/IEC "
            "33000-series conformant assessment or maturity certification."
        ),
    }


def _prioritization_calibration(artifacts: dict[str, Any]) -> dict[str, Any]:
    value = artifacts.get("prioritization-calibration-evidence.json")
    gaps: list[str] = []
    metrics: dict[str, Any] = {}
    snapshots: dict[str, Any] = {}
    samples = 0
    hours: Any = None
    if not isinstance(value, dict):
        gaps.append("prioritization calibration evidence is missing")
    else:
        snapshots_value = value.get("snapshots")
        metrics_value = value.get("metrics")
        snapshots = snapshots_value if isinstance(snapshots_value, dict) else {}
        metrics = metrics_value if isinstance(metrics_value, dict) else {}
        samples_value = value.get("samples")
        samples = (
            samples_value
            if isinstance(samples_value, int)
            and not isinstance(samples_value, bool)
            and samples_value >= 1
            else 0
        )
        for name in ("corpus_sha256", "outcomes_sha256"):
            if not _digest(str(value.get(name) or "")):
                gaps.append(f"{name} is missing or invalid")
        for name in ("epss_sha256", "kev_sha256"):
            if not _digest(str(snapshots.get(name) or "")):
                gaps.append(f"snapshot {name} is missing or invalid")
        if value.get("point_in_time") is not True:
            gaps.append("point-in-time evaluation is not proven")
        if value.get("future_data_excluded") is not True:
            gaps.append("future-data exclusion is not proven")
        if value.get("replay_protected") is not True:
            gaps.append("replay protection is missing")
        authority = value.get("authority")
        if (
            not isinstance(authority, dict)
            or authority.get("organization_approved") is not True
        ):
            gaps.append("organization-approved outcome authority is missing")
        if samples < 100:
            gaps.append("fewer than 100 temporal observations were evaluated")
        for name in (
            "brier_score",
            "expected_calibration_error",
            "recall_at_budget",
            "effort",
        ):
            if not _ratio(metrics.get(name)):
                gaps.append(f"metric {name} is missing or invalid")
        hours = metrics.get("kev_time_to_prioritize_hours")
        if (
            isinstance(hours, bool)
            or not isinstance(hours, (int, float))
            or not math.isfinite(float(hours))
            or float(hours) < 0
        ):
            gaps.append("metric kev_time_to_prioritize_hours is missing or invalid")
    return {
        "schema_version": "1.0",
        "analysis": "point-in-time-vulnerability-prioritization-calibration",
        "complete": not gaps,
        "samples": samples,
        "point_in_time": bool(
            isinstance(value, dict) and value.get("point_in_time") is True
        ),
        "future_data_excluded": bool(
            isinstance(value, dict) and value.get("future_data_excluded") is True
        ),
        "replay_protected": bool(
            isinstance(value, dict) and value.get("replay_protected") is True
        ),
        "corpus_sha256": str(value.get("corpus_sha256") or "")
        if isinstance(value, dict)
        else "",
        "outcomes_sha256": str(value.get("outcomes_sha256") or "")
        if isinstance(value, dict)
        else "",
        "snapshots": {
            "epss_sha256": str(snapshots.get("epss_sha256") or ""),
            "kev_sha256": str(snapshots.get("kev_sha256") or ""),
        },
        "metrics": {
            "brier_score": metrics.get("brier_score")
            if _ratio(metrics.get("brier_score"))
            else None,
            "expected_calibration_error": metrics.get("expected_calibration_error")
            if _ratio(metrics.get("expected_calibration_error"))
            else None,
            "recall_at_budget": metrics.get("recall_at_budget")
            if _ratio(metrics.get("recall_at_budget"))
            else None,
            "effort": metrics.get("effort") if _ratio(metrics.get("effort")) else None,
            "kev_time_to_prioritize_hours": hours
            if isinstance(hours, (int, float))
            and not isinstance(hours, bool)
            and math.isfinite(float(hours))
            and float(hours) >= 0
            else None,
        },
        "gaps": gaps[:100],
        "claim_boundary": (
            "Calibration is valid only for the pinned observation window, snapshots, "
            "outcome authority, population, and remediation budget."
        ),
    }


def _applicable_profiles(policy: dict[str, Any]) -> set[str]:
    return {
        str(item["id"])
        for item in policy.get("profiles", [])
        if isinstance(item, dict) and item.get("applicable") is True
    }


def _governed_assessment_row(
    value: object, identifier: str, *, require_independence: bool = True
) -> tuple[dict[str, Any], list[str]]:
    row = value if isinstance(value, dict) else {}
    gaps: list[str] = []
    for name in ("scope_sha256", "evidence_sha256", "method_sha256", "report_sha256"):
        if not _digest(str(row.get(name) or "")):
            gaps.append(f"{identifier} {name} is missing or invalid")
    if not _text(row.get("version"), 100):
        gaps.append(f"{identifier} version is missing")
    assessor = row.get("assessor")
    if not isinstance(assessor, dict):
        gaps.append(f"{identifier} assessor identity is missing")
    else:
        if not _text(assessor.get("identity"), 300):
            gaps.append(f"{identifier} assessor identity is missing")
        if require_independence and assessor.get("independent") is not True:
            gaps.append(f"{identifier} assessor independence is not proven")
        if not _digest(str(assessor.get("competency_sha256") or "")):
            gaps.append(f"{identifier} assessor competency digest is missing")
    authority = row.get("authority")
    if (
        not isinstance(authority, dict)
        or authority.get("organization_approved") is not True
    ):
        gaps.append(f"{identifier} organization-approved authority is missing")
    if row.get("replay_protected") is not True:
        gaps.append(f"{identifier} replay protection is missing")
    return {
        "id": identifier,
        "version": str(row.get("version") or ""),
        "scope_sha256": str(row.get("scope_sha256") or ""),
        "evidence_sha256": str(row.get("evidence_sha256") or ""),
        "method_sha256": str(row.get("method_sha256") or ""),
        "report_sha256": str(row.get("report_sha256") or ""),
        "assessor": {
            "identity": str(assessor.get("identity") or "")
            if isinstance(assessor, dict)
            else "",
            "independent": bool(
                isinstance(assessor, dict) and assessor.get("independent") is True
            ),
            "competency_sha256": str(assessor.get("competency_sha256") or "")
            if isinstance(assessor, dict)
            else "",
        },
        "replay_protected": row.get("replay_protected") is True,
        "complete": not gaps,
        "gaps": gaps,
    }, gaps


def _maturity_model_assessment(
    artifacts: dict[str, Any], policy: dict[str, Any]
) -> dict[str, Any]:
    selected = _applicable_profiles(policy)
    required: list[str] = []
    for profile, models in {
        "devsecops-maturity": ("OWASP-DSOVS", "OWASP-DSOMM"),
        "test-maturity": ("TMMI",),
        "external-maturity-comparison": ("BSIMM", "CMMI-DEV"),
        "australian-essential-eight": ("ASD-ESSENTIAL-EIGHT",),
    }.items():
        if profile in selected:
            required.extend(models)
    raw = artifacts.get("maturity-model-evidence.json")
    supplied = raw.get("models", []) if isinstance(raw, dict) else []
    indexed = {str(item.get("id")): item for item in supplied if isinstance(item, dict)}
    rows: list[dict[str, Any]] = []
    gaps: list[str] = []
    for identifier in required:
        row, row_gaps = _governed_assessment_row(indexed.get(identifier), identifier)
        source = indexed.get(identifier)
        reviewers = (
            source.get("independent_reviewers") if isinstance(source, dict) else None
        )
        domains = source.get("domains") if isinstance(source, dict) else None
        if (
            isinstance(reviewers, bool)
            or not isinstance(reviewers, int)
            or reviewers < 2
        ):
            row_gaps.append(f"{identifier} requires at least two independent reviewers")
        if (
            not isinstance(domains, list)
            or not domains
            or not all(_text(item, 200) for item in domains)
        ):
            row_gaps.append(f"{identifier} assessed domains are missing")
        row["independent_reviewers"] = (
            reviewers
            if isinstance(reviewers, int) and not isinstance(reviewers, bool)
            else 0
        )
        row["domains"] = domains if isinstance(domains, list) else []
        row["complete"] = not row_gaps
        row["gaps"] = row_gaps
        rows.append(row)
        gaps.extend(row_gaps)
    return {
        "schema_version": "1.0",
        "analysis": "governed-maturity-model-assessment",
        "applicable": bool(required),
        "required_models": required,
        "models_assessed": len(rows),
        "models_complete": sum(item["complete"] for item in rows),
        "complete": not gaps,
        "models": rows,
        "gaps": gaps[:100],
        "claim_boundary": "Maturity ratings are evidence-bound point-in-time assessments, not certification or permission to reproduce licensed model text.",
    }


def _security_automation_interoperability(
    artifacts: dict[str, Any], policy: dict[str, Any]
) -> dict[str, Any]:
    selected = _applicable_profiles(policy)
    required: list[str] = []
    for profile, protocols in {
        "security-automation-interoperability": (
            "OASIS-CACAO",
            "OASIS-OPENC2",
            "OCSF",
        ),
        "security-data-interoperability": ("OASIS-STIX", "OASIS-TAXII"),
        "supply-chain-transparency-consumer": (
            "IETF-RFC-9942",
            "IETF-RFC-9943",
        ),
        "runtime-contract-interoperability": (
            "OPENAPI-SPECIFICATION",
            "ASYNCAPI-SPECIFICATION",
            "GRAPHQL-SPECIFICATION",
            "JSON-SCHEMA",
            "OPENTELEMETRY-SEMCONV",
        ),
    }.items():
        if profile in selected:
            required.extend(protocols)
    required = list(dict.fromkeys(required))
    applicable = bool(required)
    raw = artifacts.get("security-automation-evidence.json")
    supplied = raw.get("protocols", []) if isinstance(raw, dict) else []
    indexed = {str(item.get("id")): item for item in supplied if isinstance(item, dict)}
    rows: list[dict[str, Any]] = []
    gaps: list[str] = []
    for identifier in required:
        source = indexed.get(identifier, {})
        row_gaps: list[str] = []
        if not _text(source.get("version"), 100):
            row_gaps.append(f"{identifier} version is missing")
        for name in ("schema_sha256", "fixtures_sha256", "report_sha256"):
            if not _digest(str(source.get(name) or "")):
                row_gaps.append(f"{identifier} {name} is missing or invalid")
        for name in ("positive_cases", "negative_cases"):
            count = source.get(name)
            if isinstance(count, bool) or not isinstance(count, int) or count < 1:
                row_gaps.append(f"{identifier} {name} are missing")
        if source.get("round_trip_validated") is not True:
            row_gaps.append(f"{identifier} round-trip validation is missing")
        if source.get("semantic_equivalence_validated") is not True:
            row_gaps.append(f"{identifier} semantic-equivalence validation is missing")
        authority = source.get("authority")
        if (
            not isinstance(authority, dict)
            or authority.get("organization_approved") is not True
        ):
            row_gaps.append(f"{identifier} organization-approved authority is missing")
        if source.get("replay_protected") is not True:
            row_gaps.append(f"{identifier} replay protection is missing")
        rows.append(
            {
                "id": identifier,
                "version": str(source.get("version") or ""),
                "schema_sha256": str(source.get("schema_sha256") or ""),
                "fixtures_sha256": str(source.get("fixtures_sha256") or ""),
                "report_sha256": str(source.get("report_sha256") or ""),
                "positive_cases": source.get("positive_cases")
                if isinstance(source.get("positive_cases"), int)
                and not isinstance(source.get("positive_cases"), bool)
                else 0,
                "negative_cases": source.get("negative_cases")
                if isinstance(source.get("negative_cases"), int)
                and not isinstance(source.get("negative_cases"), bool)
                else 0,
                "round_trip_validated": source.get("round_trip_validated") is True,
                "semantic_equivalence_validated": source.get(
                    "semantic_equivalence_validated"
                )
                is True,
                "replay_protected": source.get("replay_protected") is True,
                "complete": not row_gaps,
                "gaps": row_gaps,
            }
        )
        gaps.extend(row_gaps)
    return {
        "schema_version": "1.0",
        "analysis": "security-automation-interoperability-conformance",
        "applicable": applicable,
        "protocols_required": required,
        "protocols_assessed": len(rows),
        "protocols_complete": sum(item["complete"] for item in rows),
        "complete": not gaps,
        "protocols": rows,
        "gaps": gaps[:100],
        "claim_boundary": "Conformance is limited to the pinned schemas, fixtures, implementations, and semantic assertions tested.",
    }


def _external_conformity_assessment(
    artifacts: dict[str, Any], policy: dict[str, Any]
) -> dict[str, Any]:
    selected = _applicable_profiles(policy)
    required: list[str] = []
    for profile, schemes in {
        "ai-conformity-quality": ("ISO-IEC-42006", "CSA-AICM"),
        "cloud-independent-assurance": ("CSA-STAR",),
        "federal-vulnerability-disclosure": ("NIST-SP-800-216",),
        "consumer-product-regulation": ("UK-PSTI", "ETSI-EN-18031"),
        "detection-product-evaluation": ("MITRE-ATTACK-EVALUATIONS",),
        "external-maturity-comparison": ("LICENSED-NORMATIVE-CATALOG",),
        "uk-cyber-resilience": ("NCSC-CAF", "NCSC-CYBER-ESSENTIALS"),
        "cisa-cross-sector-cpg": ("CISA-CPG",),
        "automotive-software-update": ("ISO-24089",),
        "energy-product-security": ("IEC-62351", "UL-2900"),
        "enhanced-cui-assurance": ("NIST-SP-800-172A",),
        "continuous-security-monitoring": ("NIST-SP-800-137A", "NISTIR-8212"),
        "digital-forensics-readiness": ("ISO-IEC-27037", "ISO-IEC-27041"),
        "accessibility-quality": ("W3C-WCAG", "ETSI-EN-301-549", "US-SECTION-508"),
        "audit-assessment-integrity": (
            "ISO-IEC-27006-1",
            "ISO-IEC-17021-1",
            "ISO-IEC-17029",
        ),
        "security-evaluator-competence": (
            "ISO-IEC-19896-1",
            "ISO-IEC-19896-2",
            "ISO-IEC-19896-3",
        ),
    }.items():
        if profile in selected:
            required.extend(schemes)
    raw = artifacts.get("external-conformity-evidence.json")
    supplied = raw.get("assessments", []) if isinstance(raw, dict) else []
    indexed = {str(item.get("id")): item for item in supplied if isinstance(item, dict)}
    rows: list[dict[str, Any]] = []
    gaps: list[str] = []
    for identifier in required:
        row, row_gaps = _governed_assessment_row(indexed.get(identifier), identifier)
        source = indexed.get(identifier)
        source = source if isinstance(source, dict) else {}
        if not _text(source.get("valid_at_assessment"), 100):
            row_gaps.append(f"{identifier} assessment validity date is missing")
        if not _text(source.get("applicability_basis"), 1000):
            row_gaps.append(f"{identifier} applicability basis is missing")
        credential = source.get("assessor_credential")
        if not isinstance(credential, dict):
            row_gaps.append(f"{identifier} assessor credential evidence is missing")
            credential = {}
        for name in (
            "credential_id_sha256",
            "registry_snapshot_sha256",
            "registry_signature_sha256",
        ):
            if not _digest(str(credential.get(name) or "")):
                row_gaps.append(
                    f"{identifier} assessor credential {name} is missing or invalid"
                )
        if not _text(credential.get("issuer"), 300) or not _text(
            credential.get("scheme"), 300
        ):
            row_gaps.append(
                f"{identifier} assessor credential issuer or scheme is missing"
            )
        if credential.get("status") != "active":
            row_gaps.append(f"{identifier} assessor credential is not active")
        if credential.get("revocation_checked") is not True:
            row_gaps.append(
                f"{identifier} assessor credential revocation was not checked"
            )
        if credential.get("signature_validated") is not True:
            row_gaps.append(
                f"{identifier} assessor registry signature is not validated"
            )
        for name in ("valid_from", "valid_until", "checked_at"):
            if not _iso_timestamp(credential.get(name)):
                row_gaps.append(
                    f"{identifier} assessor credential {name} is missing or invalid"
                )
        row["valid_at_assessment"] = str(source.get("valid_at_assessment") or "")
        row["applicability_basis"] = str(source.get("applicability_basis") or "")
        row["assessor_credential"] = {
            "issuer": str(credential.get("issuer") or ""),
            "scheme": str(credential.get("scheme") or ""),
            "credential_id_sha256": str(credential.get("credential_id_sha256") or ""),
            "registry_snapshot_sha256": str(
                credential.get("registry_snapshot_sha256") or ""
            ),
            "registry_signature_sha256": str(
                credential.get("registry_signature_sha256") or ""
            ),
            "status": str(credential.get("status") or ""),
            "valid_from": str(credential.get("valid_from") or ""),
            "valid_until": str(credential.get("valid_until") or ""),
            "checked_at": str(credential.get("checked_at") or ""),
            "revocation_checked": credential.get("revocation_checked") is True,
            "signature_validated": credential.get("signature_validated") is True,
        }
        row["complete"] = not row_gaps
        row["gaps"] = row_gaps
        rows.append(row)
        gaps.extend(row_gaps)
    return {
        "schema_version": "1.0",
        "analysis": "external-conformity-and-normative-evidence",
        "applicable": bool(required),
        "schemes_required": required,
        "schemes_assessed": len(rows),
        "schemes_complete": sum(item["complete"] for item in rows),
        "complete": not gaps,
        "assessments": rows,
        "gaps": gaps[:100],
        "claim_boundary": "The artifact records scoped evidence and assessor claims; only the issuing authority can confer certification, legal conformity, or registry status.",
    }


def _assurance_case_assessment(artifacts: dict[str, Any]) -> dict[str, Any]:
    raw = artifacts.get("structured-assurance-case.json")
    gaps: list[str] = []
    claims: list[Any] = []
    evidence: list[Any] = []
    relationships: list[Any] = []
    model: dict[str, Any] = {}
    review: dict[str, Any] = {}
    scope_sha256 = ""
    case_id = ""
    if not isinstance(raw, dict):
        gaps.append("structured-assurance-case.json is missing")
    else:
        case_id = str(raw.get("case_id") or "")
        scope_sha256 = str(raw.get("scope_sha256") or "")
        supplied_model = raw.get("model")
        supplied_claims = raw.get("claims")
        supplied_evidence = raw.get("evidence")
        supplied_relationships = raw.get("relationships")
        supplied_review = raw.get("review")
        model = supplied_model if isinstance(supplied_model, dict) else {}
        claims = supplied_claims if isinstance(supplied_claims, list) else []
        evidence = supplied_evidence if isinstance(supplied_evidence, list) else []
        relationships = (
            supplied_relationships if isinstance(supplied_relationships, list) else []
        )
        review = supplied_review if isinstance(supplied_review, dict) else {}
        if (
            set(raw)
            != {
                "schema_version",
                "case_id",
                "scope_sha256",
                "model",
                "claims",
                "evidence",
                "relationships",
                "review",
            }
            or raw.get("schema_version") != "1.0"
        ):
            gaps.append("assurance case envelope does not match schema version 1.0")
    if not _text(case_id, 200):
        gaps.append("assurance case identifier is missing or invalid")
    if not _digest(scope_sha256):
        gaps.append("assurance case scope digest is missing or invalid")
    expected_model = {
        "format",
        "version",
        "schema_sha256",
        "model_sha256",
        "schema_validated",
        "semantic_validated",
        "round_trip_validated",
    }
    if (
        set(model) != expected_model
        or model.get("format") != "OMG-SACM"
        or model.get("version") != "2.3"
        or not _digest(str(model.get("schema_sha256") or ""))
        or not _digest(str(model.get("model_sha256") or ""))
        or any(
            model.get(name) is not True
            for name in (
                "schema_validated",
                "semantic_validated",
                "round_trip_validated",
            )
        )
    ):
        gaps.append(
            "SACM 2.3 syntax, semantics, digest, or round-trip evidence is incomplete"
        )
    claim_ids: set[str] = set()
    top_level: set[str] = set()
    defeaters: set[str] = set()
    claim_status: dict[str, str] = {}
    minimum_confidence = review.get("minimum_confidence")
    valid_minimum = (
        isinstance(minimum_confidence, (int, float))
        and not isinstance(minimum_confidence, bool)
        and 0 <= float(minimum_confidence) <= 1
    )
    minimum_confidence_value = (
        float(cast(int | float, minimum_confidence)) if valid_minimum else 0.0
    )
    for index, claim in enumerate(claims[:20_000]):
        if not isinstance(claim, dict) or set(claim) != {
            "id",
            "type",
            "statement",
            "status",
            "confidence",
            "applicable",
            "top_level",
        }:
            gaps.append(f"claim {index} does not match the governed claim contract")
            continue
        identifier = str(claim.get("id") or "")
        claim_type = claim.get("type")
        status = claim.get("status")
        confidence = claim.get("confidence")
        confidence_is_number = isinstance(confidence, (int, float)) and not isinstance(
            confidence, bool
        )
        confidence_value = (
            float(cast(int | float, confidence)) if confidence_is_number else -1.0
        )
        if (
            not _text(identifier, 200)
            or identifier in claim_ids
            or claim_type
            not in {"claim", "assumption", "context", "justification", "defeater"}
            or status
            not in {"supported", "unsupported", "defeated", "resolved", "accepted-risk"}
            or not _text(claim.get("statement"), 4000)
            or not 0 <= confidence_value <= 1
            or not isinstance(claim.get("applicable"), bool)
            or not isinstance(claim.get("top_level"), bool)
        ):
            gaps.append(
                f"claim {index} identity, type, status, confidence, or text is invalid"
            )
            continue
        claim_ids.add(identifier)
        claim_status[identifier] = str(status)
        if claim["top_level"] is True and claim["applicable"] is True:
            top_level.add(identifier)
            if status not in {"supported", "accepted-risk"}:
                gaps.append(f"top-level claim is unresolved: {identifier}")
            if valid_minimum and confidence_value < minimum_confidence_value:
                gaps.append(f"top-level claim confidence is below policy: {identifier}")
        if claim_type == "defeater" and claim["applicable"] is True:
            defeaters.add(identifier)
            if status not in {"resolved", "accepted-risk"}:
                gaps.append(f"defeater is unresolved: {identifier}")
    if len(claims) > 20_000:
        gaps.append("assurance case exceeds the maximum claim count")
    if not top_level:
        gaps.append("assurance case has no applicable top-level claim")
    evidence_ids: set[str] = set()
    now = datetime.now(UTC)
    for index, item in enumerate(evidence[:100_000]):
        if not isinstance(item, dict) or set(item) != {
            "id",
            "artifact",
            "sha256",
            "subject_sha256",
            "collected_at",
            "valid_until",
            "verified",
        }:
            gaps.append(
                f"evidence {index} does not match the governed evidence contract"
            )
            continue
        identifier = str(item.get("id") or "")
        valid_until = item.get("valid_until")
        if (
            not _text(identifier, 200)
            or identifier in evidence_ids
            or identifier in claim_ids
            or not _artifact_name(item.get("artifact"))
            or not _digest(str(item.get("sha256") or ""))
            or not _digest(str(item.get("subject_sha256") or ""))
            or not _iso_timestamp(item.get("collected_at"))
            or (valid_until is not None and not _iso_timestamp(valid_until))
            or not isinstance(item.get("verified"), bool)
        ):
            gaps.append(
                f"evidence {index} identity, digest, time, or verification is invalid"
            )
            continue
        evidence_ids.add(identifier)
        if item["subject_sha256"] != scope_sha256:
            gaps.append(
                f"evidence subject is outside assurance-case scope: {identifier}"
            )
        if item["verified"] is not True:
            gaps.append(f"evidence is not independently verified: {identifier}")
        if valid_until is not None:
            try:
                expires = datetime.fromisoformat(
                    str(valid_until).replace("Z", "+00:00")
                )
                if expires <= now:
                    gaps.append(f"evidence is stale: {identifier}")
            except ValueError:
                pass
    if len(evidence) > 100_000:
        gaps.append("assurance case exceeds the maximum evidence count")
    known_nodes = claim_ids | evidence_ids
    incoming_support: set[str] = set()
    used_evidence: set[str] = set()
    support_graph: dict[str, set[str]] = {identifier: set() for identifier in claim_ids}
    relation_pairs: dict[tuple[str, str], set[str]] = {}
    seen_relationships: set[tuple[str, str, str]] = set()
    for index, relation in enumerate(relationships[:200_000]):
        if not isinstance(relation, dict) or set(relation) != {
            "source",
            "target",
            "type",
            "rationale",
        }:
            gaps.append(
                f"relationship {index} does not match the governed relationship contract"
            )
            continue
        source = str(relation.get("source") or "")
        target = str(relation.get("target") or "")
        relation_type = str(relation.get("type") or "")
        identity = (source, target, relation_type)
        if (
            source not in known_nodes
            or target not in claim_ids
            or source == target
            or relation_type
            not in {"supports", "challenges", "rebuts", "contextualizes", "assumes"}
            or identity in seen_relationships
            or not _text(relation.get("rationale"), 2000)
        ):
            gaps.append(
                f"relationship {index} is dangling, duplicated, self-referential, or invalid"
            )
            continue
        seen_relationships.add(identity)
        relation_pairs.setdefault((source, target), set()).add(relation_type)
        if source in evidence_ids:
            used_evidence.add(source)
        if relation_type == "supports":
            incoming_support.add(target)
            if source in claim_ids:
                support_graph[source].add(target)
    if len(relationships) > 200_000:
        gaps.append("assurance case exceeds the maximum relationship count")
    for (source, target), types in relation_pairs.items():
        if "supports" in types and types & {"challenges", "rebuts"}:
            gaps.append(f"contradictory relationship semantics: {source} -> {target}")
    for identifier in sorted(top_level):
        if (
            claim_status.get(identifier) == "supported"
            and identifier not in incoming_support
        ):
            gaps.append(
                f"supported top-level claim has no incoming support: {identifier}"
            )
    for identifier in sorted(evidence_ids - used_evidence):
        gaps.append(
            f"orphaned evidence is not cited by the assurance case: {identifier}"
        )
    indegree = {identifier: 0 for identifier in claim_ids}
    for targets in support_graph.values():
        for target in targets:
            indegree[target] += 1
    ready = sorted(identifier for identifier, degree in indegree.items() if degree == 0)
    processed = 0
    cursor = 0
    while cursor < len(ready):
        identifier = ready[cursor]
        cursor += 1
        processed += 1
        for target in sorted(support_graph.get(identifier, ())):
            indegree[target] -= 1
            if indegree[target] == 0:
                ready.append(target)
    if processed != len(claim_ids):
        gaps.append("claim support graph contains a cycle")
    if (
        set(review)
        != {
            "reviewed_at",
            "independent_reviewers",
            "minimum_confidence",
            "approved",
            "approval_sha256",
        }
        or not _iso_timestamp(review.get("reviewed_at"))
        or not _count(review.get("independent_reviewers"), 2)
        or not valid_minimum
        or review.get("approved") is not True
        or not _digest(str(review.get("approval_sha256") or ""))
    ):
        gaps.append(
            "independent review, confidence policy, or approval evidence is incomplete"
        )
    unique_gaps = list(dict.fromkeys(gaps))[:200]
    return {
        "schema_version": "1.0",
        "analysis": "structured-assurance-case-conformance",
        "applicable": isinstance(raw, dict),
        "case_id": case_id,
        "scope_sha256": scope_sha256,
        "model_format": str(model.get("format") or ""),
        "model_version": str(model.get("version") or ""),
        "claims_assessed": min(len(claims), 20_000),
        "top_level_claims": len(top_level),
        "defeaters_assessed": len(defeaters),
        "evidence_assessed": min(len(evidence), 100_000),
        "relationships_assessed": min(len(relationships), 200_000),
        "independent_reviewers": review.get("independent_reviewers")
        if _count(review.get("independent_reviewers"))
        else 0,
        "complete": not unique_gaps,
        "gaps": unique_gaps,
        "claim_boundary": "This assessment validates the supplied assurance-case structure, graph semantics, subject binding, freshness, and review evidence; it does not independently prove that the underlying system claims are true.",
    }


def _threat_model_assessment(
    artifacts: dict[str, Any], source_sha256: str
) -> dict[str, Any]:
    raw = artifacts.get("threat-model-evidence.json")
    gaps: list[str] = []
    expected_root = {
        "schema_version",
        "model_id",
        "source_sha256",
        "architecture_sha256",
        "methodology",
        "reviewed_at",
        "assets",
        "components",
        "trust_boundaries",
        "data_flows",
        "assumptions",
        "mitigations",
        "tests",
        "threats",
        "change_triggers",
        "review",
    }
    if not isinstance(raw, dict):
        gaps.append("threat-model evidence is missing")
        raw = {}
    elif set(raw) != expected_root or raw.get("schema_version") != "1.0":
        gaps.append("threat-model evidence does not match the governed root contract")

    def records(name: str, maximum: int = 10_000) -> list[Any]:
        value = raw.get(name)
        if not isinstance(value, list):
            gaps.append(f"{name} must be an array")
            return []
        if len(value) > maximum:
            gaps.append(f"{name} exceeds the maximum record count")
        return value[:maximum]

    def collect_ids(
        name: str, rows: list[Any], required: set[str]
    ) -> tuple[set[str], dict[str, dict[str, Any]]]:
        identifiers: set[str] = set()
        accepted: dict[str, dict[str, Any]] = {}
        for index, item in enumerate(rows):
            if not isinstance(item, dict) or set(item) != required:
                gaps.append(
                    f"{name} record {index} does not match its governed contract"
                )
                continue
            identifier = str(item.get("id") or "")
            if not _text(identifier, 200) or identifier in identifiers:
                gaps.append(f"{name} record {index} has an invalid or duplicate id")
                continue
            identifiers.add(identifier)
            accepted[identifier] = item
        return identifiers, accepted

    model_id = str(raw.get("model_id") or "")
    evidence_source = str(raw.get("source_sha256") or "")
    architecture_sha256 = str(raw.get("architecture_sha256") or "")
    if not _text(model_id, 200):
        gaps.append("model_id is missing or invalid")
    if not _digest(evidence_source) or evidence_source != source_sha256:
        gaps.append("threat-model source digest is missing or does not match the scan")
    if not _digest(architecture_sha256):
        gaps.append("architecture digest is missing or invalid")
    if not _text(raw.get("methodology"), 200):
        gaps.append("threat-model methodology is missing")
    model_reviewed_at = raw.get("reviewed_at")
    if not _iso_timestamp(model_reviewed_at):
        gaps.append("threat-model review timestamp is missing or invalid")
    else:
        try:
            if datetime.fromisoformat(
                str(model_reviewed_at).replace("Z", "+00:00")
            ) > datetime.now(UTC):
                gaps.append("threat-model review timestamp is in the future")
        except ValueError:
            pass

    asset_rows = records("assets")
    component_rows = records("components")
    boundary_rows = records("trust_boundaries")
    flow_rows = records("data_flows")
    assumption_rows = records("assumptions")
    mitigation_rows = records("mitigations")
    test_rows = records("tests")
    threat_rows = records("threats")
    trigger_rows = records("change_triggers", 2_000)

    asset_ids, assets = collect_ids(
        "asset",
        asset_rows,
        {"id", "title", "owner", "classification", "criticality"},
    )
    component_ids, components = collect_ids(
        "component", component_rows, {"id", "name", "kind", "zone", "owner"}
    )
    boundary_ids, boundaries = collect_ids(
        "trust-boundary",
        boundary_rows,
        {"id", "from_zone", "to_zone", "control_ids"},
    )
    flow_ids, flows = collect_ids(
        "data-flow",
        flow_rows,
        {
            "id",
            "source_component",
            "destination_component",
            "data_classes",
            "boundary_ids",
            "encrypted",
            "authenticated",
        },
    )
    assumption_ids, assumptions = collect_ids(
        "assumption",
        assumption_rows,
        {"id", "statement", "owner", "status", "expires_at"},
    )
    mitigation_ids, mitigations = collect_ids(
        "mitigation",
        mitigation_rows,
        {"id", "title", "owner", "status", "control_ids", "evidence"},
    )
    test_ids, tests = collect_ids(
        "test",
        test_rows,
        {
            "id",
            "threat_ids",
            "kind",
            "negative_case",
            "result",
            "evidence_sha256",
            "subject_sha256",
        },
    )
    threat_ids, threats = collect_ids(
        "threat",
        threat_rows,
        {
            "id",
            "title",
            "category",
            "asset_ids",
            "component_ids",
            "flow_ids",
            "boundary_ids",
            "preconditions",
            "attack_steps",
            "likelihood",
            "impact",
            "risk_score",
            "status",
            "mitigation_ids",
            "test_ids",
            "residual_risk",
            "owner",
            "acceptance",
        },
    )
    trigger_ids, triggers = collect_ids(
        "change-trigger",
        trigger_rows,
        {"id", "artifact", "sha256", "assessed"},
    )

    if not asset_ids:
        gaps.append("threat model has no assets")
    if not component_ids:
        gaps.append("threat model has no components")
    if not boundary_ids:
        gaps.append("threat model has no trust boundaries")
    if not flow_ids:
        gaps.append("threat model has no data flows")
    if not threat_ids:
        gaps.append("threat model has no threats")
    if not trigger_ids:
        gaps.append("threat model has no architecture change triggers")

    for identifier, item in assets.items():
        criticality = item.get("criticality")
        if (
            not _text(item.get("title"), 500)
            or not _text(item.get("owner"), 200)
            or item.get("classification")
            not in {"public", "internal", "confidential", "restricted"}
            or not isinstance(criticality, int)
            or isinstance(criticality, bool)
            or not 1 <= criticality <= 5
        ):
            gaps.append(f"asset metadata is incomplete or invalid: {identifier}")

    component_zones: dict[str, str] = {}
    for identifier, item in components.items():
        zone = str(item.get("zone") or "")
        if (
            not _text(item.get("name"), 500)
            or not _text(item.get("kind"), 200)
            or not _text(zone, 200)
            or not _text(item.get("owner"), 200)
        ):
            gaps.append(f"component metadata is incomplete: {identifier}")
        else:
            component_zones[identifier] = zone

    for identifier, item in boundaries.items():
        controls = item.get("control_ids")
        if (
            not _text(item.get("from_zone"), 200)
            or not _text(item.get("to_zone"), 200)
            or item.get("from_zone") == item.get("to_zone")
            or not isinstance(controls, list)
            or not controls
            or any(not _text(value, 200) for value in controls)
            or len(set(controls)) != len(controls)
        ):
            gaps.append(f"trust boundary is incomplete or invalid: {identifier}")

    sensitive_classes = {
        "credentials",
        "secrets",
        "personal",
        "health",
        "payment",
        "cryptographic-keys",
    }
    cross_boundary_flows: set[str] = set()
    modeled_cross_boundary_flows: set[str] = set()
    for identifier, item in flows.items():
        source = str(item.get("source_component") or "")
        destination = str(item.get("destination_component") or "")
        classes = item.get("data_classes")
        references = item.get("boundary_ids")
        valid_references = (
            isinstance(references, list)
            and len(references) == len(set(references))
            and all(value in boundary_ids for value in references)
        )
        if (
            source not in component_ids
            or destination not in component_ids
            or source == destination
            or not isinstance(classes, list)
            or not classes
            or any(not _text(value, 200) for value in classes)
            or not valid_references
            or not isinstance(item.get("encrypted"), bool)
            or not isinstance(item.get("authenticated"), bool)
        ):
            gaps.append(f"data flow is dangling or invalid: {identifier}")
            continue
        source_zone = component_zones.get(source)
        destination_zone = component_zones.get(destination)
        if source_zone != destination_zone:
            cross_boundary_flows.add(identifier)
            exact_boundaries = [
                value
                for value in cast(list[str], references)
                if boundaries.get(value, {}).get("from_zone") == source_zone
                and boundaries.get(value, {}).get("to_zone") == destination_zone
            ]
            if exact_boundaries:
                modeled_cross_boundary_flows.add(identifier)
            else:
                gaps.append(
                    f"cross-zone flow has no matching directional trust boundary: {identifier}"
                )
            if sensitive_classes & set(cast(list[str], classes)) and (
                item["encrypted"] is not True or item["authenticated"] is not True
            ):
                gaps.append(
                    f"sensitive cross-zone flow lacks authenticated encryption: {identifier}"
                )

    now = datetime.now(UTC)
    open_assumptions = 0
    for identifier, item in assumptions.items():
        status = item.get("status")
        expires_at = item.get("expires_at")
        if (
            not _text(item.get("statement"), 2000)
            or not _text(item.get("owner"), 200)
            or status not in {"validated", "open", "rejected"}
            or (expires_at is not None and not _iso_timestamp(expires_at))
        ):
            gaps.append(f"assumption is incomplete or invalid: {identifier}")
            continue
        if status != "validated":
            open_assumptions += 1
            gaps.append(f"assumption is unresolved: {identifier}")
        if expires_at is not None:
            try:
                if (
                    datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
                    <= now
                ):
                    gaps.append(f"assumption is stale: {identifier}")
            except ValueError:
                pass

    verified_mitigations: set[str] = set()
    for identifier, item in mitigations.items():
        evidence = item.get("evidence")
        evidence_valid = isinstance(evidence, list) and bool(evidence)
        if evidence_valid:
            for record in cast(list[Any], evidence):
                if (
                    not isinstance(record, dict)
                    or set(record) != {"artifact", "sha256", "subject_sha256"}
                    or not _artifact_name(record.get("artifact"))
                    or not _digest(str(record.get("sha256") or ""))
                    or record.get("subject_sha256") != source_sha256
                ):
                    evidence_valid = False
                    break
        controls = item.get("control_ids")
        if (
            not _text(item.get("title"), 1000)
            or not _text(item.get("owner"), 200)
            or item.get("status") not in {"planned", "implemented", "verified"}
            or not isinstance(controls, list)
            or not controls
            or any(not _text(value, 200) for value in controls)
            or len(set(controls)) != len(controls)
            or (item.get("status") == "verified" and not evidence_valid)
        ):
            gaps.append(f"mitigation is incomplete or unsupported: {identifier}")
        elif item.get("status") == "verified":
            verified_mitigations.add(identifier)

    passed_negative_tests: set[str] = set()
    threat_tests: dict[str, set[str]] = {identifier: set() for identifier in threat_ids}
    for identifier, item in tests.items():
        linked = item.get("threat_ids")
        valid_links = (
            isinstance(linked, list)
            and bool(linked)
            and len(linked) == len(set(linked))
            and all(value in threat_ids for value in linked)
        )
        if (
            not valid_links
            or not _text(item.get("kind"), 200)
            or not isinstance(item.get("negative_case"), bool)
            or item.get("result") not in {"passed", "failed", "not-executed"}
            or not _digest(str(item.get("evidence_sha256") or ""))
            or item.get("subject_sha256") != source_sha256
        ):
            gaps.append(f"threat test is dangling, unbound, or invalid: {identifier}")
            continue
        for threat_id in cast(list[str], linked):
            threat_tests[threat_id].add(identifier)
        if item["negative_case"] is True and item["result"] == "passed":
            passed_negative_tests.add(identifier)

    assets_with_threats: set[str] = set()
    threats_with_mitigations: set[str] = set()
    threats_with_verification: set[str] = set()
    unresolved_high_risk = 0
    for identifier, item in threats.items():
        likelihood = item.get("likelihood")
        impact = item.get("impact")
        risk_score = item.get("risk_score")
        residual_risk = item.get("residual_risk")
        linked_assets = item.get("asset_ids")
        linked_components = item.get("component_ids")
        linked_flows = item.get("flow_ids")
        linked_boundaries = item.get("boundary_ids")
        linked_mitigations = item.get("mitigation_ids")
        linked_tests = item.get("test_ids")
        references = (
            ("asset", linked_assets, asset_ids, True),
            ("component", linked_components, component_ids, False),
            ("flow", linked_flows, flow_ids, False),
            ("boundary", linked_boundaries, boundary_ids, False),
            ("mitigation", linked_mitigations, mitigation_ids, False),
            ("test", linked_tests, test_ids, False),
        )
        valid_references = True
        for label, values, known, required in references:
            if (
                not isinstance(values, list)
                or (required and not values)
                or len(values) != len(set(values))
                or any(value not in known for value in values)
            ):
                gaps.append(f"threat {identifier} has invalid {label} references")
                valid_references = False
        valid_scores = (
            isinstance(likelihood, int)
            and not isinstance(likelihood, bool)
            and 1 <= likelihood <= 5
            and isinstance(impact, int)
            and not isinstance(impact, bool)
            and 1 <= impact <= 5
            and isinstance(risk_score, int)
            and not isinstance(risk_score, bool)
            and risk_score == likelihood * impact
            and isinstance(residual_risk, int)
            and not isinstance(residual_risk, bool)
            and 0 <= residual_risk <= risk_score
        )
        if (
            not _text(item.get("title"), 1000)
            or not _text(item.get("category"), 200)
            or not _text(item.get("owner"), 200)
            or item.get("status") not in {"open", "mitigated", "accepted"}
            or not isinstance(item.get("preconditions"), list)
            or not item.get("preconditions")
            or any(not _text(value, 1000) for value in item.get("preconditions", []))
            or not isinstance(item.get("attack_steps"), list)
            or not item.get("attack_steps")
            or any(not _text(value, 1000) for value in item.get("attack_steps", []))
            or not valid_scores
        ):
            gaps.append(
                f"threat semantics or risk calculation is invalid: {identifier}"
            )
        if valid_references and isinstance(linked_assets, list):
            assets_with_threats.update(cast(list[str], linked_assets))
        verified_links = (
            isinstance(linked_mitigations, list)
            and bool(linked_mitigations)
            and set(linked_mitigations) <= verified_mitigations
        )
        passed_links = (
            isinstance(linked_tests, list)
            and bool(linked_tests)
            and set(linked_tests) <= passed_negative_tests
            and set(linked_tests) <= threat_tests.get(identifier, set())
        )
        if linked_mitigations:
            threats_with_mitigations.add(identifier)
        if passed_links:
            threats_with_verification.add(identifier)
        status = item.get("status")
        if status == "mitigated" and (not verified_links or not passed_links):
            gaps.append(
                f"mitigated threat lacks verified controls or passing negative tests: {identifier}"
            )
        if status == "open":
            gaps.append(f"threat remains open: {identifier}")
        if status == "accepted":
            acceptance = item.get("acceptance")
            valid_acceptance = (
                isinstance(acceptance, dict)
                and set(acceptance) == {"approved_by", "expires_at", "evidence_sha256"}
                and _text(acceptance.get("approved_by"), 200)
                and _iso_timestamp(acceptance.get("expires_at"))
                and _digest(str(acceptance.get("evidence_sha256") or ""))
            )
            if valid_acceptance:
                try:
                    acceptance_record = cast(dict[str, Any], acceptance)
                    valid_acceptance = (
                        datetime.fromisoformat(
                            str(acceptance_record["expires_at"]).replace("Z", "+00:00")
                        )
                        > now
                    )
                except ValueError:
                    valid_acceptance = False
            if not valid_acceptance:
                gaps.append(f"accepted threat lacks current approval: {identifier}")
        elif item.get("acceptance") is not None:
            gaps.append(f"non-accepted threat carries risk acceptance: {identifier}")
        if isinstance(risk_score, int) and risk_score >= 15 and status == "open":
            unresolved_high_risk += 1

    for identifier in sorted(asset_ids - assets_with_threats):
        gaps.append(f"asset has no linked threat: {identifier}")
    for identifier in sorted(
        mitigation_ids
        - set().union(
            *(set(item.get("mitigation_ids", [])) for item in threats.values())
        )
    ):
        gaps.append(f"mitigation is orphaned: {identifier}")
    for identifier in sorted(test_ids - set().union(*threat_tests.values())):
        gaps.append(f"threat test is orphaned: {identifier}")

    assessed_triggers = 0
    architecture_artifacts = {
        "application-contract-analysis.json",
        "architecture-history.json",
        "boundary-graph.json",
        "domain-assurance.json",
        "source-inventory.json",
        "static-architecture.json",
    }
    for identifier, item in triggers.items():
        if (
            not _artifact_name(item.get("artifact"))
            or item.get("artifact") not in architecture_artifacts
            or not _digest(str(item.get("sha256") or ""))
            or not isinstance(item.get("assessed"), bool)
        ):
            gaps.append(f"architecture change trigger is invalid: {identifier}")
        elif item["assessed"] is True:
            assessed_triggers += 1
        else:
            gaps.append(
                f"architecture change has not been threat-modeled: {identifier}"
            )

    review = raw.get("review")
    independent_reviewers = 0
    approved = False
    if isinstance(review, dict):
        reviewers = review.get("independent_reviewers")
        independent_reviewers = (
            len(reviewers)
            if isinstance(reviewers, list)
            and len(reviewers) == len(set(reviewers))
            and all(_text(value, 200) for value in reviewers)
            else 0
        )
        approved = review.get("approved") is True
    owner_ids = {
        str(item.get("owner"))
        for collection in (assets, components, assumptions, mitigations, threats)
        for item in collection.values()
        if _text(item.get("owner"), 200)
    }
    reviewers_are_independent = bool(
        isinstance(review, dict)
        and isinstance(review.get("independent_reviewers"), list)
        and not (set(review["independent_reviewers"]) & owner_ids)
    )
    if (
        not isinstance(review, dict)
        or set(review)
        != {"reviewed_at", "independent_reviewers", "approved", "approval_sha256"}
        or not _iso_timestamp(review.get("reviewed_at"))
        or review.get("reviewed_at") != model_reviewed_at
        or independent_reviewers < 2
        or not reviewers_are_independent
        or not approved
        or not _digest(str(review.get("approval_sha256") or ""))
    ):
        gaps.append("independent threat-model review and approval are incomplete")

    unique_gaps = list(dict.fromkeys(gaps))[:200]
    return {
        "schema_version": "1.0",
        "analysis": "threat-model-quality-assessment",
        "applicable": isinstance(artifacts.get("threat-model-evidence.json"), dict),
        "model_id": model_id,
        "source_sha256": evidence_source if _digest(evidence_source) else "",
        "architecture_sha256": architecture_sha256
        if _digest(architecture_sha256)
        else "",
        "scope": {
            "assets": len(asset_ids),
            "components": len(component_ids),
            "trust_boundaries": len(boundary_ids),
            "data_flows": len(flow_ids),
            "assumptions": len(assumption_ids),
            "threats": len(threat_ids),
            "mitigations": len(mitigation_ids),
            "tests": len(test_ids),
            "change_triggers": len(trigger_ids),
        },
        "coverage": {
            "assets_with_threats": len(assets_with_threats),
            "cross_boundary_flows": len(cross_boundary_flows),
            "cross_boundary_flows_modeled": len(modeled_cross_boundary_flows),
            "threats_with_mitigations": len(threats_with_mitigations),
            "threats_with_verification": len(threats_with_verification),
            "verified_mitigations": len(verified_mitigations),
            "passed_negative_tests": len(passed_negative_tests),
            "open_assumptions": open_assumptions,
            "unresolved_high_risk": unresolved_high_risk,
            "change_triggers_assessed": assessed_triggers,
        },
        "review": {
            "independent_reviewers": independent_reviewers,
            "approved": approved,
        },
        "complete": not unique_gaps,
        "gaps": unique_gaps,
        "claim_boundary": (
            "This assessment checks threat-model structure, traceability, risk arithmetic, "
            "control and negative-test evidence, change coverage, and independent review. "
            "It does not prove that every possible threat was discovered or that controls "
            "remain effective outside the bound evidence."
        ),
    }


def _foundational_assurance_artifacts(
    artifacts: dict[str, Any], source_sha256: str, policy: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    threat_model = _threat_model_assessment(artifacts, source_sha256)
    lifecycle = _lifecycle_traceability(artifacts, source_sha256)
    architecture = _architecture_evaluation(artifacts)
    intermediate = {
        **artifacts,
        "lifecycle-traceability.json": lifecycle,
        "architecture-evaluation.json": architecture,
    }
    capability = _process_capability_assessment(intermediate)
    prioritization = _prioritization_calibration(artifacts)
    maturity = _maturity_model_assessment(artifacts, policy)
    automation = _security_automation_interoperability(artifacts, policy)
    conformity = _external_conformity_assessment(artifacts, policy)
    assurance_case = _assurance_case_assessment(artifacts)
    return {
        "lifecycle-traceability.json": lifecycle,
        "architecture-evaluation.json": architecture,
        "process-capability-assessment.json": capability,
        "prioritization-calibration.json": prioritization,
        "maturity-model-assessment.json": maturity,
        "security-automation-interoperability.json": automation,
        "external-conformity-assessment.json": conformity,
        "assurance-case-assessment.json": assurance_case,
        "threat-model-assessment.json": threat_model,
    }


def build_industry_assurance(
    target: Path,
    artifacts: dict[str, Any],
    findings: list[Any] | None = None,
    *,
    receipt_trust_policy: dict[str, Any] | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Build bounded benchmark, procedure, standards, and OSCAL artifacts."""

    target = target.resolve()
    policy, errors = _load_policy(target)
    if (
        policy.get("schema_version") == "1.3"
        and any(item.get("enabled") is True for item in policy["benchmarks"])
        and receipt_trust_policy is None
    ):
        errors.append(
            "enabled protocol benchmarks require a root-signed deployment receipt "
            "authority policy outside the target workspace"
        )
    source_sha256 = _source_sha256(artifacts)
    foundational = _foundational_assurance_artifacts(artifacts, source_sha256, policy)
    profiles = _profile_registry(policy)
    enriched_artifacts = {**artifacts, **foundational}
    registry = _benchmark_registry(policy, source_sha256, receipt_trust_policy)
    scorecard = _benchmark_scorecard(
        target, enriched_artifacts, registry, source_sha256
    )
    delta = _benchmark_delta(target, policy, scorecard, errors)
    benchmark_artifacts = {
        "benchmark-registry.json": registry,
        "benchmark-scorecard.json": scorecard,
        "benchmark-delta.json": delta,
    }
    procedures = _procedure_assessment(
        policy, {**enriched_artifacts, **benchmark_artifacts}, errors
    )
    prioritization = _standardized_prioritization(findings or [])
    observed_artifacts = {
        **enriched_artifacts,
        **benchmark_artifacts,
        "procedure-assessment.json": procedures,
        "standardized-prioritization.json": prioritization,
    }
    initial_crosswalk = _crosswalk(observed_artifacts)
    assessment = _assessment(policy, observed_artifacts, initial_crosswalk, errors)
    oscal = _oscal_documents(assessment, procedures, source_sha256)
    generated_artifacts = {
        **observed_artifacts,
        "control-assessment.json": assessment,
        **oscal,
    }
    crosswalk = _crosswalk(generated_artifacts)
    industry = {
        "schema_version": "1.0",
        "analysis": "industry-standards-and-benchmark-assurance",
        "complete": not errors
        and assessment["complete"] is True
        and procedures["complete"] is True
        and (
            scorecard["benchmarks_enabled"] == 0
            or (scorecard["complete"] is True and scorecard["passed"] is True)
        ),
        "policy_present": policy["present"],
        "policy_path": _POLICY_PATH if policy["present"] else None,
        "standards_registered": len(crosswalk["catalogs"]),
        "benchmarks_registered": len(registry["benchmarks"]),
        "assurance_profiles_available": profiles["profiles_available"],
        "assurance_profiles_selected": profiles["profiles_selected"],
        "controls_assessed": assessment["controls_assessed"],
        "controls_satisfied": assessment["controls_satisfied"],
        "procedures_assessed": procedures["procedures_assessed"],
        "procedures_satisfied": procedures["procedures_satisfied"],
        "benchmarks_executed": scorecard["benchmarks_executed"],
        "oscal_models_emitted": len(oscal),
        "foundational_assurance": {
            name: value["complete"] for name, value in foundational.items()
        },
        "interoperability": _interoperability(generated_artifacts),
        "artifact_contracts": [
            "standards-crosswalk.json",
            "assurance-profile-registry.json",
            "control-assessment.json",
            "procedure-assessment.json",
            "standardized-prioritization.json",
            "benchmark-registry.json",
            "benchmark-scorecard.json",
            "benchmark-delta.json",
            "lifecycle-traceability.json",
            "architecture-evaluation.json",
            "process-capability-assessment.json",
            "prioritization-calibration.json",
            "maturity-model-assessment.json",
            "security-automation-interoperability.json",
            "external-conformity-assessment.json",
            "assurance-case-assessment.json",
            "threat-model-assessment.json",
            "oscal-catalog.json",
            "oscal-profile.json",
            "oscal-component-definition.json",
            "oscal-system-security-plan.json",
            "oscal-assessment-plan.json",
            "oscal-assessment-results.json",
            "oscal-poam.json",
        ],
        "parse_errors": errors[:100],
        "claim_boundary": (
            "Registration or evidence mapping is not certification. Benchmark scores "
            "apply only to the pinned corpus, tool set, source, and execution environment."
        ),
    }
    return {
        "industry-assurance.json": industry,
        "standards-crosswalk.json": crosswalk,
        "assurance-profile-registry.json": profiles,
        "control-assessment.json": assessment,
        "procedure-assessment.json": procedures,
        "standardized-prioritization.json": prioritization,
        "benchmark-registry.json": registry,
        "benchmark-scorecard.json": scorecard,
        "benchmark-delta.json": delta,
        **foundational,
        **oscal,
    }, errors


def _profile_registry(policy: dict[str, Any]) -> dict[str, Any]:
    selections = {str(item["id"]): item for item in policy.get("profiles", [])}
    profiles = []
    for identifier, profile in _ASSURANCE_PROFILES.items():
        selection = selections.get(identifier)
        profiles.append(
            {
                "id": identifier,
                "standards": list(profile["standards"]),
                "controls": len(profile["controls"]),
                "procedures": len(profile["procedures"]),
                "selected": selection is not None,
                "applicable": (
                    selection["applicable"] if selection is not None else None
                ),
                "procedure_execution": (
                    selection["procedure_execution"] if selection is not None else None
                ),
            }
        )
    return {
        "schema_version": "1.0",
        "analysis": "industry-assurance-profile-registry",
        "profiles_available": len(profiles),
        "profiles_selected": len(selections),
        "profiles": profiles,
        "claim_boundary": (
            "Selecting a profile expands evidence-backed controls and procedures; "
            "it does not establish certification, legal applicability, or assessor approval."
        ),
    }


def _load_policy(target: Path) -> tuple[dict[str, Any], list[str]]:
    default = {
        "present": False,
        "enforce": False,
        "profiles": [],
        "controls": [],
        "procedures": [],
        "benchmarks": [],
        "benchmark_baseline_path": None,
    }
    path = target / _POLICY_PATH
    if not path.is_file():
        return default, []
    try:
        _, payload = read_regular_file(
            path,
            "industry assurance policy",
            maximum_bytes=_MAX_POLICY_BYTES,
            boundary=target,
        )
        value = strict_loads(payload)
        _validate_policy(value)
        return {"present": True, **_expand_policy_profiles(value)}, []
    except (OSError, TypeError, ValueError) as exc:
        return {**default, "present": True}, [f"{_POLICY_PATH}: {type(exc).__name__}"]


def _validate_policy(value: object) -> None:
    version_1_0 = {
        "schema_version",
        "enforce",
        "controls",
        "benchmarks",
        "benchmark_baseline_path",
    }
    version_1_1 = {*version_1_0, "procedures"}
    version_1_2 = {*version_1_1, "profiles"}
    version_1_3 = version_1_2
    if not isinstance(value, dict):
        raise ValueError("invalid industry assurance policy")
    version = value.get("schema_version")
    expected = (
        version_1_0
        if version == "1.0"
        else version_1_1
        if version == "1.1"
        else version_1_2
        if version == "1.2"
        else version_1_3
    )
    if (
        version not in {"1.0", "1.1", "1.2", "1.3"}
        or set(value) != expected
        or not isinstance(value.get("enforce"), bool)
    ):
        raise ValueError("invalid industry assurance policy")
    controls = value.get("controls")
    procedures = value.get("procedures", [])
    profiles = value.get("profiles", [])
    benchmarks = value.get("benchmarks")
    if (
        not isinstance(controls, list)
        or len(controls) > 10_000
        or not isinstance(procedures, list)
        or len(procedures) > 20_000
        or not isinstance(profiles, list)
        or len(profiles) > len(_ASSURANCE_PROFILES)
        or not isinstance(benchmarks, list)
        or len(benchmarks) > len(_BENCHMARKS)
    ):
        raise ValueError("industry assurance policy collections are invalid")
    seen_profiles: set[str] = set()
    for profile in profiles:
        if not isinstance(profile, dict) or set(profile) != {
            "id",
            "applicable",
            "procedure_execution",
        }:
            raise ValueError("industry assurance profile fields are invalid")
        identifier = str(profile.get("id") or "")
        if (
            identifier not in _ASSURANCE_PROFILES
            or identifier in seen_profiles
            or not isinstance(profile.get("applicable"), bool)
            or profile.get("procedure_execution") not in {"planned", "executed"}
        ):
            raise ValueError("industry assurance profile is invalid")
        seen_profiles.add(identifier)
    known_standards = {item["id"] for item in _STANDARDS}
    known_benchmarks = {item["id"] for item in _BENCHMARKS}
    identities: set[tuple[str, str]] = set()
    for control in controls:
        if not isinstance(control, dict) or set(control) != {
            "standard",
            "control_id",
            "objective",
            "applicable",
            "evidence_artifacts",
        }:
            raise ValueError("industry assurance control fields are invalid")
        identity = (str(control.get("standard")), str(control.get("control_id")))
        evidence = control.get("evidence_artifacts")
        if (
            identity[0] not in known_standards
            or identity in identities
            or not _text(identity[1], 160)
            or not _text(control.get("objective"), 1000)
            or not isinstance(control.get("applicable"), bool)
            or not isinstance(evidence, list)
            or len(evidence) > 100
            or not all(_artifact_name(item) for item in evidence)
        ):
            raise ValueError("industry assurance control is invalid")
        identities.add(identity)
    procedure_identities: set[tuple[str, str]] = set()
    for procedure in procedures:
        required_procedure_fields = {
            "standard",
            "procedure_id",
            "objective",
            "applicable",
            "execution",
            "test_type",
            "authorization_required",
            "evidence_artifacts",
        }
        if (
            not isinstance(procedure, dict)
            or set(procedure) != required_procedure_fields
        ):
            raise ValueError("industry assurance procedure fields are invalid")
        identity = (
            str(procedure.get("standard")),
            str(procedure.get("procedure_id")),
        )
        evidence = procedure.get("evidence_artifacts")
        if (
            identity[0] not in known_standards
            or identity in procedure_identities
            or not _text(identity[1], 160)
            or not _text(procedure.get("objective"), 1000)
            or not isinstance(procedure.get("applicable"), bool)
            or procedure.get("execution") not in {"planned", "executed"}
            or procedure.get("test_type")
            not in {"examine", "interview", "test", "static", "dynamic", "manual"}
            or not isinstance(procedure.get("authorization_required"), bool)
            or not isinstance(evidence, list)
            or len(evidence) > 100
            or not all(_artifact_name(item) for item in evidence)
        ):
            raise ValueError("industry assurance procedure is invalid")
        procedure_identities.add(identity)
    seen: set[str] = set()
    for benchmark in benchmarks:
        legacy_benchmark_fields = {
            "id",
            "enabled",
            "corpus_sha256",
            "evidence_artifact",
            "minimum_precision",
            "minimum_recall",
            "minimum_f1",
            "maximum_false_positive_rate",
        }
        protocol_benchmark_fields = {
            "id",
            "enabled",
            "corpus_sha256",
            "evidence_artifact",
            "thresholds",
            "adapter_manifest",
        }
        allowed_fields = (
            {frozenset(protocol_benchmark_fields)}
            if version == "1.3"
            else {
                frozenset(legacy_benchmark_fields),
                frozenset({*legacy_benchmark_fields, "adapter_manifest"}),
            }
        )
        if not isinstance(benchmark, dict) or set(benchmark) not in allowed_fields:
            raise ValueError("industry benchmark fields are invalid")
        identifier = str(benchmark.get("id") or "")
        digest = str(benchmark.get("corpus_sha256") or "")
        if (
            identifier not in known_benchmarks
            or identifier in seen
            or not isinstance(benchmark.get("enabled"), bool)
            or not _digest(digest)
            or not _artifact_name(benchmark.get("evidence_artifact"))
            or (
                benchmark.get("adapter_manifest") is not None
                and not _safe_relative(benchmark.get("adapter_manifest"))
            )
        ):
            raise ValueError("industry benchmark declaration is invalid")
        if version == "1.3":
            threshold_gaps = validate_protocol_thresholds(
                _benchmark_protocol(identifier), benchmark.get("thresholds")
            )
            if threshold_gaps:
                raise ValueError("; ".join(threshold_gaps))
        else:
            for name in (
                "minimum_precision",
                "minimum_recall",
                "minimum_f1",
                "maximum_false_positive_rate",
            ):
                if not _ratio(benchmark.get(name)):
                    raise ValueError("industry benchmark threshold is invalid")
        seen.add(identifier)
    baseline = value.get("benchmark_baseline_path")
    if baseline is not None and not _safe_relative(baseline):
        raise ValueError("benchmark baseline path is unsafe")


def _expand_policy_profiles(value: dict[str, Any]) -> dict[str, Any]:
    expanded = {
        **value,
        "profiles": list(value.get("profiles", [])),
        "controls": [dict(item) for item in value["controls"]],
        "procedures": [dict(item) for item in value.get("procedures", [])],
    }
    control_identities = {
        (str(item["standard"]), str(item["control_id"]))
        for item in expanded["controls"]
    }
    procedure_identities = {
        (str(item["standard"]), str(item["procedure_id"]))
        for item in expanded["procedures"]
    }
    for selection in expanded["profiles"]:
        profile = _ASSURANCE_PROFILES[str(selection["id"])]
        applicable = selection["applicable"] is True
        for standard, control_id, objective, evidence in profile["controls"]:
            identity = (standard, control_id)
            if identity in control_identities:
                raise ValueError("profile control duplicates an explicit control")
            expanded["controls"].append(
                {
                    "standard": standard,
                    "control_id": control_id,
                    "objective": objective,
                    "applicable": applicable,
                    "evidence_artifacts": list(evidence),
                }
            )
            control_identities.add(identity)
        for (
            standard,
            procedure_id,
            objective,
            test_type,
            authorization_required,
            evidence,
        ) in profile["procedures"]:
            identity = (standard, procedure_id)
            if identity in procedure_identities:
                raise ValueError("profile procedure duplicates an explicit procedure")
            expanded["procedures"].append(
                {
                    "standard": standard,
                    "procedure_id": procedure_id,
                    "objective": objective,
                    "applicable": applicable,
                    "execution": selection["procedure_execution"],
                    "test_type": test_type,
                    "authorization_required": authorization_required,
                    "evidence_artifacts": list(evidence),
                }
            )
            procedure_identities.add(identity)
    if len(expanded["controls"]) > 10_000 or len(expanded["procedures"]) > 20_000:
        raise ValueError("expanded industry assurance policy is too large")
    return expanded


def _crosswalk(artifacts: dict[str, Any]) -> dict[str, Any]:
    catalogs = []
    mappings = []
    raw_lifecycle = artifacts.get("standards-lifecycle-evidence.json")
    supplied_records = (
        raw_lifecycle.get("records", []) if isinstance(raw_lifecycle, dict) else []
    )
    supplied_ids = [
        str(item.get("id"))
        for item in supplied_records
        if isinstance(item, dict) and item.get("id")
    ]
    known_catalog_ids = {str(item["id"]) for item in _STANDARDS}
    duplicate_ids = sorted(
        identifier for identifier, count in Counter(supplied_ids).items() if count > 1
    )
    unknown_ids = sorted(set(supplied_ids) - known_catalog_ids)
    lifecycle_input_gaps = [
        *(f"duplicate lifecycle record: {identifier}" for identifier in duplicate_ids),
        *(f"unknown lifecycle record: {identifier}" for identifier in unknown_ids),
    ]
    lifecycle_index = {
        str(item.get("id")): item
        for item in supplied_records
        if isinstance(item, dict) and item.get("id")
    }
    lifecycle_records: list[dict[str, Any]] = []
    for standard in _STANDARDS:
        present = [name for name in standard["evidence"] if name in artifacts]
        catalogs.append(
            {key: value for key, value in standard.items() if key != "evidence"}
        )
        mappings.append(
            {
                "standard": standard["id"],
                "evidence_artifacts": list(standard["evidence"]),
                "evidence_present": present,
                "mapping_status": "evidence-surface-present"
                if present
                else "not-observed",
            }
        )
        expected = standard.get("lifecycle")
        expected = expected if isinstance(expected, dict) else {}
        supplied = lifecycle_index.get(str(standard["id"]))
        supplied = supplied if isinstance(supplied, dict) else {}
        lifecycle_gaps: list[str] = []
        for field in (
            "source_sha256",
            "signature_sha256",
            "change_report_sha256",
        ):
            if not _digest(str(supplied.get(field) or "")):
                lifecycle_gaps.append(f"{field} is missing or invalid")
        if supplied.get("source_reference") != standard["reference"]:
            lifecycle_gaps.append(
                "source_reference does not match the catalog publisher reference"
            )
        if supplied.get("signature_validated") is not True or not _text(
            supplied.get("signer_identity"), 500
        ):
            lifecycle_gaps.append(
                "source signature validation or signer identity is missing"
            )
        if supplied.get("publisher_identity_validated") is not True:
            lifecycle_gaps.append("publisher identity validation is missing")
        if not _iso_timestamp(supplied.get("observed_at")):
            lifecycle_gaps.append("observed_at is missing or invalid")
        if not _text(supplied.get("approved_by"), 300) or not _iso_timestamp(
            supplied.get("approved_at")
        ):
            lifecycle_gaps.append(
                "human approval identity or time is missing or invalid"
            )
        if supplied.get("human_approved") is not True:
            lifecycle_gaps.append("human promotion approval is missing")
        supplied_status = str(supplied.get("edition_status") or "")
        expected_status = str(
            expected.get("edition_status") or supplied_status or "unreviewed"
        )
        if expected and supplied and supplied_status != expected_status:
            lifecycle_gaps.append("edition status does not match the catalog")
        elif supplied and supplied_status not in {
            "final",
            "historical",
            "final-under-review",
            "policy-pinned",
        }:
            lifecycle_gaps.append("edition status is missing or invalid")
        published = str(expected.get("published") or supplied.get("published") or "")
        if supplied and not _text(published, 100):
            lifecycle_gaps.append("publication date or policy pin is missing")
        lifecycle_records.append(
            {
                "id": standard["id"],
                "edition_status": expected_status,
                "published": published,
                "catalog_observed_at": str(expected.get("observed_at") or ""),
                "evidence_observed_at": str(supplied.get("observed_at") or ""),
                "source_sha256": str(supplied.get("source_sha256") or ""),
                "source_reference": str(supplied.get("source_reference") or ""),
                "signature_sha256": str(supplied.get("signature_sha256") or ""),
                "signature_validated": supplied.get("signature_validated") is True,
                "signer_identity": str(supplied.get("signer_identity") or ""),
                "publisher_identity_validated": supplied.get(
                    "publisher_identity_validated"
                )
                is True,
                "change_report_sha256": str(supplied.get("change_report_sha256") or ""),
                "human_approved": supplied.get("human_approved") is True,
                "approved_by": str(supplied.get("approved_by") or ""),
                "approved_at": str(supplied.get("approved_at") or ""),
                "supersedes": list(expected.get("supersedes", [])),
                "superseded_by": list(expected.get("superseded_by", [])),
                "complete": not lifecycle_gaps,
                "gaps": lifecycle_gaps,
            }
        )
    lifecycle_complete = sum(item["complete"] for item in lifecycle_records)
    return {
        "schema_version": "1.0",
        "analysis": "versioned-industry-standards-crosswalk",
        "catalogs_registered": len(catalogs),
        "catalogs": catalogs,
        "mappings": mappings,
        "watchlist": [dict(item) for item in _STANDARDS_WATCHLIST],
        "lifecycle_governance": {
            "evidence_artifact": "standards-lifecycle-evidence.json",
            "catalogs_assessed": len(lifecycle_records),
            "catalogs_complete": lifecycle_complete,
            "input_records": len(supplied_records),
            "input_gaps": lifecycle_input_gaps,
            "complete": lifecycle_complete == len(lifecycle_records)
            and not lifecycle_input_gaps,
            "promotion_requires_human_approval": True,
            "signed_source_snapshot_required": True,
            "source_digest_required": True,
            "publisher_change_report_required": True,
            "records": lifecycle_records,
            "claim_boundary": "Catalog registration is not a current-edition claim until a signed, digest-bound publisher snapshot, change report, observation time, and human promotion approval are complete.",
        },
        "claim_boundary": "A crosswalk identifies related evidence surfaces; it does not establish control conformance or certification.",
    }


def _assessment(
    policy: dict[str, Any],
    artifacts: dict[str, Any],
    crosswalk: dict[str, Any],
    errors: list[str],
) -> dict[str, Any]:
    controls = []
    for value in policy["controls"]:
        evidence = list(value["evidence_artifacts"])
        present = [name for name in evidence if _complete_artifact(artifacts.get(name))]
        missing = [name for name in evidence if name not in present]
        applicable = value["applicable"] is True
        status = (
            "not-applicable"
            if not applicable
            else "satisfied"
            if evidence and not missing
            else "gap"
        )
        controls.append(
            {
                "standard": value["standard"],
                "control_id": value["control_id"],
                "objective": value["objective"],
                "applicable": applicable,
                "status": status,
                "evidence_required": evidence,
                "evidence_present": present,
                "gaps": [f"missing or incomplete artifact: {name}" for name in missing],
            }
        )
    counts = Counter(item["status"] for item in controls)
    applicable_count = sum(item["applicable"] for item in controls)
    satisfied = counts["satisfied"]
    complete = not errors and (not policy["enforce"] or satisfied == applicable_count)
    return {
        "schema_version": "1.0",
        "analysis": "evidence-backed-industry-control-assessment",
        "complete": complete,
        "policy_present": policy["present"],
        "enforced": policy["enforce"],
        "catalogs_registered": crosswalk["catalogs_registered"],
        "controls_assessed": len(controls),
        "applicable_controls": applicable_count,
        "controls_satisfied": satisfied,
        "status_counts": {
            name: counts.get(name, 0) for name in ("satisfied", "gap", "not-applicable")
        },
        "controls": controls,
        "parse_errors": errors[:100],
        "claim_boundary": "Only declared controls with complete named evidence are satisfied; assessment is not third-party certification.",
    }


def _procedure_assessment(
    policy: dict[str, Any], artifacts: dict[str, Any], errors: list[str]
) -> dict[str, Any]:
    procedures = []
    for value in policy.get("procedures", []):
        evidence = list(value["evidence_artifacts"])
        present = [name for name in evidence if _complete_artifact(artifacts.get(name))]
        missing = [name for name in evidence if name not in present]
        applicable = value["applicable"] is True
        executed = value["execution"] == "executed"
        authorization = (
            "not-required"
            if value["authorization_required"] is False
            else "validated"
            if any(_authorization_validated(artifacts.get(name)) for name in present)
            else "required-not-proven"
        )
        status = "not-applicable"
        gaps: list[str] = []
        if applicable and not executed:
            status = "planned"
            gaps.append("procedure is applicable but has not been executed")
        elif applicable and (missing or not evidence):
            status = "evidence-gap"
            gaps.extend(f"missing or incomplete artifact: {name}" for name in missing)
            if not evidence:
                gaps.append("procedure has no declared evidence artifact")
        elif applicable and authorization == "required-not-proven":
            status = "authorization-gap"
            gaps.append(
                "authorized execution is required but not proven by retained evidence"
            )
        elif applicable:
            status = "satisfied"
        procedures.append(
            {
                "standard": value["standard"],
                "procedure_id": value["procedure_id"],
                "objective": value["objective"],
                "applicable": applicable,
                "execution": value["execution"],
                "test_type": value["test_type"],
                "authorization_required": value["authorization_required"],
                "authorization_status": authorization,
                "status": status,
                "evidence_required": evidence,
                "evidence_present": present,
                "gaps": gaps,
            }
        )
    counts = Counter(item["status"] for item in procedures)
    applicable_count = sum(item["applicable"] for item in procedures)
    satisfied = counts["satisfied"]
    complete = not errors and (not policy["enforce"] or satisfied == applicable_count)
    return {
        "schema_version": "1.0",
        "analysis": "versioned-security-test-procedure-assessment",
        "complete": complete,
        "policy_present": policy["present"],
        "enforced": policy["enforce"],
        "procedures_assessed": len(procedures),
        "applicable_procedures": applicable_count,
        "procedures_satisfied": satisfied,
        "status_counts": {
            name: counts.get(name, 0)
            for name in (
                "satisfied",
                "planned",
                "evidence-gap",
                "authorization-gap",
                "not-applicable",
            )
        },
        "procedures": procedures,
        "parse_errors": errors[:100],
        "claim_boundary": (
            "A procedure is satisfied only when it was declared executed, every named "
            "artifact is complete, and required authorization is explicitly proven."
        ),
    }


def _authorization_validated(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    if value.get("authorization_validated") is True or value.get("authorized") is True:
        return True
    evidence = value.get("evidence")
    execution = value.get("execution")
    return bool(
        isinstance(evidence, dict)
        and evidence.get("execution_complete") is True
        and isinstance(execution, dict)
        and execution.get("authorization_validated") is True
    )


def _standardized_prioritization(findings: list[Any]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for finding in findings[:1_000_000]:
        evidence = getattr(finding, "evidence", {})
        evidence = evidence if isinstance(evidence, dict) else {}
        classifications = getattr(finding, "classifications", [])
        classifications = classifications if isinstance(classifications, list) else []
        severity = str(getattr(finding, "severity", "unknown"))
        intelligence = evidence.get("risk_intelligence")
        intelligence = intelligence if isinstance(intelligence, dict) else {}
        validation = evidence.get("validation")
        validation = validation if isinstance(validation, dict) else {}
        cvss = _validated_cvss(evidence.get("cvss"))
        ssvc = _ssvc_decision(severity, intelligence, validation, evidence.get("ssvc"))
        rows.append(
            {
                "finding_id": str(getattr(finding, "finding_id", "")),
                "native_severity": severity,
                "operational_priority": finding_priority(
                    severity=severity,
                    classifications=classifications,
                    evidence=evidence,
                ),
                "cvss": cvss,
                "ssvc": ssvc,
            }
        )
    rows.sort(key=lambda item: item["finding_id"])
    return {
        "schema_version": "1.0",
        "analysis": "cvss-4-and-ssvc-compatible-prioritization",
        "findings": len(rows),
        "cvss_scored": sum(item["cvss"]["status"] == "scored" for item in rows),
        "ssvc_decided": sum(item["ssvc"]["status"] == "decided" for item in rows),
        "records": rows,
        "claim_boundary": (
            "CVSS vectors are retained only when supplied as complete source evidence. "
            "SSVC outcomes remain undecided unless every decision factor is explicit; "
            "native severity is never converted into a fabricated CVSS vector."
        ),
    }


def _validated_cvss(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {
            "version": "4.0",
            "status": "not-scored",
            "vector": None,
            "score": None,
            "reason": "complete CVSS v4 source evidence was not supplied",
        }
    vector = str(value.get("vector") or "")
    score = value.get("score")
    if (
        vector.startswith("CVSS:4.0/")
        and isinstance(score, (int, float))
        and not isinstance(score, bool)
        and math.isfinite(float(score))
        and 0 <= float(score) <= 10
    ):
        return {
            "version": "4.0",
            "status": "scored",
            "vector": vector[:500],
            "score": round(float(score), 1),
            "reason": "retained source-provided CVSS v4 vector and score",
        }
    return {
        "version": "4.0",
        "status": "invalid-source-evidence",
        "vector": None,
        "score": None,
        "reason": "CVSS evidence did not contain a valid v4 vector and bounded score",
    }


def _ssvc_decision(
    severity: str,
    intelligence: dict[str, Any],
    validation: dict[str, Any],
    supplied: object,
) -> dict[str, Any]:
    supplied_factors = supplied if isinstance(supplied, dict) else {}
    factors = {
        "exploitation": supplied_factors.get("exploitation"),
        "automatable": supplied_factors.get("automatable"),
        "technical_impact": supplied_factors.get("technical_impact"),
        "mission_prevalence": supplied_factors.get("mission_prevalence"),
    }
    if factors["exploitation"] is None:
        if intelligence.get("known_exploited"):
            factors["exploitation"] = "active"
        elif validation.get("status") == "reproduced":
            factors["exploitation"] = "poc"
    if factors["technical_impact"] is None and severity in {"critical", "high"}:
        factors["technical_impact"] = "total"
    allowed = {
        "exploitation": {"none", "poc", "active"},
        "automatable": {"no", "yes"},
        "technical_impact": {"partial", "total"},
        "mission_prevalence": {"minimal", "support", "essential"},
    }
    complete = all(factors[name] in allowed[name] for name in factors)
    outcome = supplied_factors.get("outcome") if complete else None
    if outcome not in {"defer", "scheduled", "out-of-cycle", "immediate"}:
        outcome = None
    return {
        "model": "CISA-SSVC",
        "status": "decided" if complete and outcome else "insufficient-context",
        "factors": factors,
        "outcome": outcome,
        "reason": (
            "all decision factors and the source outcome were retained"
            if complete and outcome
            else "one or more SSVC decision factors or the source outcome are missing"
        ),
    }


def _benchmark_registry(
    policy: dict[str, Any],
    source_sha256: str,
    receipt_trust_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    declarations = {item["id"]: item for item in policy["benchmarks"]}
    receipt_authorities, receipt_policy_identity = receipt_authority_projection(
        receipt_trust_policy
    )
    benchmarks = []
    tasks = []
    for registered in _BENCHMARKS:
        declaration = declarations.get(registered["id"])
        enabled = bool(declaration and declaration["enabled"])
        entry = {
            **registered,
            "runner_contract": _benchmark_runner_contract(registered),
            "enabled": enabled,
            "corpus_sha256": declaration["corpus_sha256"] if declaration else None,
            "evidence_artifact": declaration["evidence_artifact"]
            if declaration
            else None,
            "adapter_manifest": declaration.get("adapter_manifest")
            if declaration
            else None,
            "trusted_receipt_signer_key_ids": (
                [item["key_id"] for item in receipt_authorities] if enabled else []
            ),
            "trusted_receipt_authorities": (
                [dict(item) for item in receipt_authorities] if enabled else []
            ),
            "thresholds": (
                declaration["thresholds"]
                if declaration and policy["schema_version"] == "1.3"
                else {}
                if declaration
                and _benchmark_protocol(str(registered["id"])) != "classification"
                else {
                    name: declaration[name]
                    for name in (
                        "minimum_precision",
                        "minimum_recall",
                        "minimum_f1",
                        "maximum_false_positive_rate",
                    )
                }
                if declaration
                else None
            ),
        }
        benchmarks.append(entry)
        if enabled:
            if declaration is None:  # pragma: no cover - established by enabled
                raise AssertionError("enabled benchmark lacks a declaration")
            adapter_manifest = declaration.get("adapter_manifest")
            command = (
                [
                    "pysec",
                    "benchmark-run",
                    adapter_manifest,
                    "--workspace",
                    "${PYSEC_BENCHMARK_WORKSPACE}",
                    "--output",
                    declaration["evidence_artifact"],
                ]
                if adapter_manifest
                else [
                    "pysec",
                    "benchmark",
                    "${PYSEC_BENCHMARK_REPORT}",
                    "--corpus",
                    "${PYSEC_BENCHMARK_CORPUS}",
                    "--corpus-sha256",
                    declaration["corpus_sha256"],
                    "--format",
                    "json",
                    "--output",
                    declaration["evidence_artifact"],
                ]
            )
            tasks.append(
                {
                    "benchmark_id": registered["id"],
                    "lane": registered["lane"],
                    "command": command,
                    "execution_mode": "adapter"
                    if adapter_manifest
                    else "report-scoring",
                    "requires_operator_authorization": bool(adapter_manifest),
                    "authorization_flag": "--authorize-execution"
                    if adapter_manifest
                    else None,
                    "network_policy": "deny",
                    "disposable_target_required": registered["lane"]
                    == "authorized-companion",
                    "source_bound": bool(source_sha256),
                    "runner_contract": _benchmark_runner_contract(registered),
                }
            )
    return {
        "schema_version": "1.0",
        "analysis": "industry-benchmark-registry",
        "source_sha256": source_sha256,
        "receipt_authority_policy": receipt_policy_identity,
        "benchmarks_registered": len(benchmarks),
        "benchmarks_enabled": sum(item["enabled"] for item in benchmarks),
        "benchmarks": benchmarks,
        "tasks": tasks,
        "required_metrics": [
            "precision",
            "recall",
            "specificity",
            "f1",
            "mcc",
            "balanced_accuracy",
            "false_positive_rate",
            "youden_j",
        ],
        "required_strata": [
            "cwe",
            "language",
            "parser_variant",
            "boundary_type",
            "severity",
            "mutation_operator",
        ],
        "claim_boundary": "External vulnerable applications and corpora execute only in separately authorized disposable companion lanes.",
    }


def _benchmark_protocol(identifier: str) -> str:
    if identifier in resilience_catalog.RESILIENCE_BENCHMARK_PROTOCOLS:
        return resilience_catalog.RESILIENCE_BENCHMARK_PROTOCOLS[identifier]
    protocols = {
        "temporal-calibration": {
            "epss-kev-temporal-backtest",
            "openssf-criticality-score-calibration",
            "weakness-prioritization-temporal-calibration",
        },
        "verification-competition": {
            "sv-comp",
            "formal-methods-tool-disagreement-assurance",
        },
        "test-generation": {"test-comp"},
        "fuzzing-statistical": {
            "google-fuzzbench",
            "magma-ground-truth",
            "oss-fuzz-clusterfuzzlite",
            "fuzzing-crash-holdout",
        },
        "stochastic-adversarial": {
            "cyberseceval-4",
            "mlcommons-ailuminate",
            "agentic-security-holdout",
            "agentdojo",
            "harmbench",
            "agentharm",
            "garak-llm-probe-conformance",
            "nist-aria-inspect-evaluation",
            "ai-conformity-quality",
            "ai-agentic-testing-conformance",
            "nist-dioptra-ai-evaluation",
            "pyrit-ai-red-team",
            "mlcommons-ailuminate-safety",
            "mlcommons-ailuminate-jailbreak",
            "oss-crs-crsbench",
            "darpa-aixcc-autonomous-vulnerability-remediation",
        },
        "assessor-agreement": {
            "architecture-evaluation-scenarios",
            "process-capability-assessor-agreement",
            "owasp-dsovs-maturity",
            "owasp-dsomm-maturity",
            "tmmi-assessment",
            "bsimm-cmmi-cohort",
            "regional-cyber-maturity-assessment",
            "iscm-program-assessment",
            "security-evaluator-calibration",
            "risk-technique-calibration",
            "cis-ram-attack-path-analysis",
            "enterprise-architecture-governance",
            "it-quality-governance-assessor-agreement",
            "first-csirt-psirt-maturity-assessment",
            "ieee-ai-governance-wellbeing-assessment",
            "isms-implementation-process-assessment",
            "ffiec-it-handbook-assessment",
            "bsi-c5-cloud-assurance-assessment",
            "linddun-privacy-threat-model-conformance",
            "tisax-vda-isa-assessment",
            "hitrust-csf-assessment",
            "nist-supplier-due-diligence",
            "owasp-samm-assessment-benchmark",
            "process-supplier-assessor-outcome-calibration",
            "secure-information-sharing-competence-assurance",
            "automotive-spice-capability-assurance",
        },
        "biometric-performance": {"biometric-performance-pad"},
        "proficiency-testing": {
            "interlaboratory-proficiency-testing",
            "ilac-laboratory-operating-assurance",
        },
        "detection-evaluation": {
            "atomic-red-team",
            "mitre-caldera",
            "mitre-attack-evaluations",
            "tiber-eu-threat-led-red-team",
            "amtso-malware-protection-evaluation",
            "rasp-prevention-effectiveness",
        },
        "conformance": {
            "mitre-emb3d-property-threat-conformance",
            "owasp-business-logic-abuse-top10-conformance",
            "cncf-supply-chain-best-practices-v2-conformance",
            "sigstore-client-conformance",
            "slsa-verifier-conformance",
            "nist-acvp-cryptography",
            "w3c-wpt-webauthn",
            "disa-stig-scap-conformance",
            "iec-62443-system-conformance",
            "iec-62443-patch-management-exercise",
            "do355-continuing-airworthiness-exercise",
            "iacs-maritime-cyber-conformance",
            "swift-cscf-independent-assessment",
            "ccsds-space-mission-link-security",
            "ecss-space-software-product-assurance",
            "regional-financial-technology-resilience-assurance",
            "cwe-mapping-conformance",
            "csa-star-caiq-conformance",
            "cacao-openc2-ocsf-interoperability",
            "psti-en18031-product-conformance",
            "scitt-transparency-conformance",
            "cloud-native-api-service-mesh-conformance",
            "api-contract-spec-conformance",
            "opentelemetry-semantic-conformance",
            "s2c2f-consumer-dependency-conformance",
            "multicloud-kubernetes-attack-paths",
            "securitytxt-patch-operations-conformance",
            "automotive-software-update-conformance",
            "energy-product-security-conformance",
            "cisa-sbom-minimum-elements-conformance",
            "enhanced-cui-oscal-conformance",
            "nist-developer-verification-conformance",
            "crypto-lifecycle-agility-conformance",
            "ict-continuity-recovery-exercise",
            "digital-forensics-chain-of-custody",
            "wcag-accessibility-conformance",
            "w3c-act-rules-conformance",
            "cloud-native-chaos-resilience",
            "kubernetes-sonobuoy-conformance",
            "firmware-resilience-measured-boot",
            "access-control-policy-model-conformance",
            "differential-privacy-implementation-evaluation",
            "square-quality-measurement",
            "cis-cat-scap-platform-conformance",
            "c2sp-wycheproof",
            "nist-cfreds-cftt",
            "iso-29119-test-process-conformance",
            "square-quality-in-use-cloud",
            "tls-protocol-conformance",
            "reproducible-build-variation",
            "cisa-secure-by-design-negative-assurance",
            "dice-attestation-conformance",
            "telecom-security-controls-conformance",
            "nice-workforce-coverage",
            "penetration-test-engagement-quality",
            "dora-delivery-outcomes",
            "structured-assurance-case-conformance",
            "integrity-vv-conformance",
            "cmvp-fips-140-3-validation",
            "iso-19790-24759-module-conformance",
            "service-management-security-integration",
            "owasp-cornucopia-threat-model",
            "nist-8286-enterprise-risk-register",
            "square-quality-governance",
            "iso-42106-differentiated-ai-benchmarking",
            "owasp-aisvs-conformance",
            "iso-25058-ai-quality-evaluation",
            "eucc-scheme-assurance",
            "cisa-secure-software-attestation",
            "ieee-7000-ai-ethics-conformance",
            "ai-use-case-security-privacy",
            "nist-csf-profile-gap-reassessment",
            "privacy-engineering-pet-conformance",
            "mcp-client-server-security-conformance",
            "aws-fsbp-securityhub-conformance",
            "microsoft-mcsb-defender-conformance",
            "gcp-enterprise-foundations-conformance",
            "memory-safety-engineering-conformance",
            "organizational-resilience-bia-exercise",
            "openssf-best-practices-badge-conformance",
            "a2a-protocol-security-conformance",
            "sesip-iot-platform-evaluation-conformance",
            "first-tlp-iep-information-handling-conformance",
            "veris-incident-schema-conformance",
            "w3c-web-platform-defense-conformance",
            "dora-level2-technical-standards-conformance",
            "fcc-cyber-trust-mark-conformance",
            "openid-digital-credential-conformance",
            "cisa-scuba-saas-posture-conformance",
            "cis-kubernetes-hardening-conformance",
            "gsma-nesas-scas-assurance",
            "c2pa-content-credentials-conformance",
            "pci-payment-acceptance-conformance",
            "oidf-fapi-conformance",
            "fedramp-20x-continuous-validation",
            "fido2-authenticator-conformance",
            "eudi-wallet-functional-conformance",
            "pci-secure-software-conformance",
            "nis2-implementing-regulation-conformance",
            "openssf-security-insights-conformance",
            "guac-interoperability",
            "gittuf-source-policy-conformance",
            "owasp-kubernetes-top10-conformance",
            "owasp-cicd-top10-conformance",
            "sbomit-build-observed-sbom",
            "owasp-mobile-top10-conformance",
            "owasp-smart-contract-top10-conformance",
            "cncf-cloud-native-security-controls-conformance",
            "scim-lifecycle-security-conformance",
            "openid-shared-signals-conformance",
            "spiffe-workload-identity-conformance",
            "openssf-model-signing-conformance",
            "cyclonedx-mlbom-conformance",
            "uptane-ota-security-conformance",
            "authzen-authorization-api-conformance",
            "openid-federation-conformance",
            "nist-hpc-ai-infrastructure-assurance",
            "iso-24760-identity-management-assurance",
            "iso-5259-6-data-quality-visualization",
            "medical-device-cybersecurity-assurance",
            "autonomous-physical-ai-safety",
            "critical-c-cpp-coding-conformance",
            "confidential-computing-attestation-conformance",
            "vvsg-voting-system-assurance",
            "critical-sector-safety-security-assurance",
            "stateful-smart-contract-security",
            "devsecops-test-maturity-longitudinal",
            "detection-product-longitudinal-calibration",
            "nss-dod-authorization-assurance",
            "zero-trust-zig-microsegmentation-assurance",
            "healthcare-operational-resilience-assurance",
            "aircraft-system-safety-development-assurance",
            "maritime-operational-cyber-resilience-assurance",
            "incident-privacy-outcome-exercise-calibration",
            "semi-fab-equipment-cybersecurity-assurance",
            "api-1164-pipeline-control-resilience",
            "gxp-part11-data-integrity-assurance",
            "fbi-cjis-security-policy-assurance",
            "iec-61511-sis-safety-security-assurance",
            "bacnet-secure-connect-assurance",
            "industrial-robotics-safety-security-assurance",
            "data-centre-facility-resilience-assurance",
            "water-sector-cyber-resilience-assurance",
            "public-safety-communications-assurance",
            "global-gxp-data-integrity-assurance",
            "transit-cybersecurity-resilience-assurance",
            "emergency-incident-coordination-assurance",
            "gas-scada-cryptographic-assurance",
        },
    }
    for protocol, identifiers in protocols.items():
        if identifier in identifiers:
            return protocol
    return "classification"


def _finite_number(value: object, minimum: float | None = None) -> bool:
    return bool(
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and (minimum is None or float(value) >= minimum)
    )


def _count(value: object, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _benchmark_scorecard(
    target: Path,
    artifacts: dict[str, Any],
    registry: dict[str, Any],
    source_sha256: str,
) -> dict[str, Any]:
    rows = []
    for benchmark in registry["benchmarks"]:
        if not benchmark["enabled"]:
            continue
        value = artifacts.get(benchmark["evidence_artifact"])
        evidence_source = "governed-artifact" if isinstance(value, dict) else "missing"
        if not isinstance(value, dict):
            try:
                _, payload = read_regular_file(
                    target / benchmark["evidence_artifact"],
                    "benchmark evidence",
                    maximum_bytes=_MAX_POLICY_BYTES,
                    boundary=target,
                )
                loaded = strict_loads(payload)
                value = loaded if isinstance(loaded, dict) else None
                evidence_source = "sealed-snapshot" if value is not None else "invalid"
            except (OSError, TypeError, ValueError):
                value = None
        valid = _benchmark_evidence(value, benchmark)
        reproducibility_gaps = _benchmark_reproducibility_gaps(value, benchmark)
        reproducibility_complete = not reproducibility_gaps
        metrics = value.get("metrics", {}) if valid and isinstance(value, dict) else {}
        protocol_metrics = (
            value.get("protocol_metrics", {})
            if valid and isinstance(value, dict)
            else {}
        )
        protocol = _benchmark_protocol(str(benchmark["id"]))
        thresholds = benchmark["thresholds"] or {}
        passed = bool(
            valid
            and reproducibility_complete
            and (
                _meets_thresholds(metrics, thresholds)
                if protocol == "classification"
                else _protocol_metrics_valid(protocol, protocol_metrics)
                and _protocol_acceptance(value)
                and (
                    not thresholds
                    or _meets_protocol_thresholds(protocol_metrics, thresholds)
                )
            )
        )
        rows.append(
            {
                "benchmark_id": benchmark["id"],
                "benchmark_protocol": protocol,
                "corpus_sha256": benchmark["corpus_sha256"],
                "evidence_artifact": benchmark["evidence_artifact"],
                "evidence_source": evidence_source,
                "evidence_present": isinstance(value, dict),
                "evidence_valid": valid,
                "reproducibility_complete": reproducibility_complete,
                "passed": passed,
                "metrics": {
                    name: metrics.get(name) for name in registry["required_metrics"]
                },
                "protocol_metrics": protocol_metrics,
                "gaps": (
                    []
                    if passed
                    else [
                        *_benchmark_gaps(
                            value,
                            valid,
                            metrics,
                            thresholds,
                            protocol,
                            protocol_metrics,
                        ),
                        *reproducibility_gaps,
                    ]
                ),
            }
        )
    executed = sum(item["evidence_valid"] for item in rows)
    passed_count = sum(item["passed"] for item in rows)
    benchmark_scope = [
        {
            "benchmark_id": item["benchmark_id"],
            "benchmark_protocol": item["benchmark_protocol"],
            "corpus_sha256": item["corpus_sha256"],
        }
        for item in rows
    ]
    return {
        "schema_version": "1.0",
        "analysis": "industry-benchmark-scorecard",
        "source_sha256": source_sha256,
        "benchmarks_enabled": len(rows),
        "benchmarks_executed": executed,
        "benchmarks_passed": passed_count,
        "complete": executed == len(rows),
        "passed": bool(rows) and passed_count == len(rows),
        "benchmarks": rows,
        "benchmark_scope": benchmark_scope,
        "aggregate_metrics": _aggregate_metrics(rows),
        "claim_boundary": "Scores are corpus-specific measurements and do not prove absence of vulnerabilities in other software.",
    }


def _benchmark_evidence(value: object, benchmark: dict[str, Any]) -> bool:
    if not isinstance(value, dict) or value.get("verdict") not in {"pass", "fail"}:
        return False
    corpus = value.get("corpus")
    protocol = _benchmark_protocol(str(benchmark["id"]))
    metrics = value.get("metrics")
    scoring_valid = (
        isinstance(metrics, dict)
        and all(
            name in metrics for name in ("precision", "recall", "specificity", "f1")
        )
        if protocol == "classification"
        else _protocol_metrics_valid(protocol, value.get("protocol_metrics"))
        and _protocol_acceptance(value)
    )
    return bool(
        isinstance(corpus, dict)
        and corpus.get("sha256") == benchmark["corpus_sha256"]
        and scoring_valid
        and value.get("replay_protected") is True
        and isinstance(corpus.get("authority"), dict)
        and corpus["authority"].get("organization_approved") is True
    )


_LABORATORY_QUALIFIED_BENCHMARKS = (
    frozenset(
        {
            "disa-stig-scap-conformance",
            "iec-62443-system-conformance",
            "process-capability-assessor-agreement",
            "architecture-evaluation-scenarios",
            "iec-62443-patch-management-exercise",
            "do355-continuing-airworthiness-exercise",
            "iacs-maritime-cyber-conformance",
            "swift-cscf-independent-assessment",
            "ccsds-space-mission-link-security",
            "ecss-space-software-product-assurance",
            "regional-financial-technology-resilience-assurance",
            "secure-information-sharing-competence-assurance",
            "regional-cyber-maturity-assessment",
            "automotive-software-update-conformance",
            "energy-product-security-conformance",
            "enhanced-cui-oscal-conformance",
            "ict-continuity-recovery-exercise",
            "digital-forensics-chain-of-custody",
            "nist-cfreds-cftt",
            "w3c-act-rules-conformance",
            "cis-cat-scap-platform-conformance",
            "iso-29119-test-process-conformance",
            "square-quality-in-use-cloud",
            "risk-technique-calibration",
            "tls-protocol-conformance",
            "reproducible-build-variation",
            "cisa-secure-by-design-negative-assurance",
            "amtso-malware-protection-evaluation",
            "dice-attestation-conformance",
            "telecom-security-controls-conformance",
            "nice-workforce-coverage",
            "penetration-test-engagement-quality",
            "dora-delivery-outcomes",
            "cmvp-fips-140-3-validation",
            "iso-19790-24759-module-conformance",
            "biometric-performance-pad",
            "interlaboratory-proficiency-testing",
            "eucc-scheme-assurance",
            "mcp-client-server-security-conformance",
            "aws-fsbp-securityhub-conformance",
            "microsoft-mcsb-defender-conformance",
            "gcp-enterprise-foundations-conformance",
            "first-csirt-psirt-maturity-assessment",
            "memory-safety-engineering-conformance",
            "ieee-ai-governance-wellbeing-assessment",
            "organizational-resilience-bia-exercise",
            "openssf-best-practices-badge-conformance",
            "isms-implementation-process-assessment",
            "a2a-protocol-security-conformance",
            "sesip-iot-platform-evaluation-conformance",
            "w3c-web-platform-defense-conformance",
            "dora-level2-technical-standards-conformance",
            "ffiec-it-handbook-assessment",
            "bsi-c5-cloud-assurance-assessment",
            "fcc-cyber-trust-mark-conformance",
            "openid-digital-credential-conformance",
            "cisa-scuba-saas-posture-conformance",
            "cis-kubernetes-hardening-conformance",
            "linddun-privacy-threat-model-conformance",
            "rasp-prevention-effectiveness",
            "gsma-nesas-scas-assurance",
            "tisax-vda-isa-assessment",
            "c2pa-content-credentials-conformance",
            "pci-payment-acceptance-conformance",
            "oidf-fapi-conformance",
            "fedramp-20x-continuous-validation",
            "fido2-authenticator-conformance",
            "eudi-wallet-functional-conformance",
            "hitrust-csf-assessment",
            "pci-secure-software-conformance",
            "nis2-implementing-regulation-conformance",
            "nist-supplier-due-diligence",
            "owasp-samm-assessment-benchmark",
            "oss-crs-crsbench",
            "openssf-package-analysis-malicious-packages",
            "owasp-kubernetes-top10-conformance",
            "owasp-cicd-top10-conformance",
            "authzen-authorization-api-conformance",
            "openid-federation-conformance",
            "nist-hpc-ai-infrastructure-assurance",
            "iso-24760-identity-management-assurance",
            "iso-5259-6-data-quality-visualization",
            "medical-device-cybersecurity-assurance",
            "autonomous-physical-ai-safety",
            "critical-c-cpp-coding-conformance",
            "confidential-computing-attestation-conformance",
            "vvsg-voting-system-assurance",
            "critical-sector-safety-security-assurance",
            "stateful-smart-contract-security",
            "devsecops-test-maturity-longitudinal",
            "detection-product-longitudinal-calibration",
            "nss-dod-authorization-assurance",
            "zero-trust-zig-microsegmentation-assurance",
            "healthcare-operational-resilience-assurance",
            "aircraft-system-safety-development-assurance",
            "ilac-laboratory-operating-assurance",
            "maritime-operational-cyber-resilience-assurance",
            "weakness-prioritization-temporal-calibration",
            "formal-methods-tool-disagreement-assurance",
            "process-supplier-assessor-outcome-calibration",
            "incident-privacy-outcome-exercise-calibration",
        }
    )
    | resilience_catalog.RESILIENCE_BENCHMARK_IDS
)


def _benchmark_runner_contract(benchmark: dict[str, Any]) -> dict[str, Any]:
    identifier = str(benchmark["id"])
    protocol = _benchmark_protocol(identifier)
    stochastic = identifier in {
        "cyberseceval-4",
        "mlcommons-ailuminate",
        "agentic-security-holdout",
        "agentdojo",
        "harmbench",
        "agentharm",
        "garak-llm-probe-conformance",
        "nist-aria-inspect-evaluation",
        "ai-agentic-testing-conformance",
        "pyrit-ai-red-team",
        "mlcommons-ailuminate-safety",
        "mlcommons-ailuminate-jailbreak",
        "oss-crs-crsbench",
    }
    continuous_fuzzing = identifier == "oss-fuzz-clusterfuzzlite"
    laboratory_qualified = identifier in _LABORATORY_QUALIFIED_BENCHMARKS
    required_execution_evidence = [
        "verified-report-checksum",
        "corpus-revision",
        "dataset-license-digest",
        "label-authority-digest",
        "contamination-manifest",
        "split-strategy",
        "runner-identity",
        "target-or-fixture-digest",
        "tool-and-query-versions",
        "environment-fingerprint",
        "oracle-manifest",
        "negative-controls",
        "isolation-receipt",
        "runner-oci-image-digest",
        "runner-sbom-digest",
        "runner-provenance-digest",
        "runner-image-sbom-provenance-subject-binding",
        "resource-limit-receipt",
        "resource-limit-enforcement",
        "network-policy-digest",
        "egress-transcript-digest",
        "network-and-egress-enforcement",
        "target-cleanup-destruction-receipt",
        "cleanup-validation",
        "trusted-time",
        "replay-protection",
    ]
    required_execution_evidence.append(
        "confusion-matrix" if protocol == "classification" else "protocol-metrics"
    )
    if protocol != "classification":
        required_execution_evidence.append("acceptance-criteria-digest")
    required_execution_evidence += list(
        industry_extension_runner_requirements(identifier)
    )
    if laboratory_qualified:
        required_execution_evidence.extend(
            [
                "method-validation-digest",
                "evaluator-competency-digest",
                "impartiality-review-digest",
                "measurement-traceability-digest",
            ]
        )
    if identifier == "epss-kev-temporal-backtest":
        required_execution_evidence.extend(
            [
                "point-in-time-snapshot-digests",
                "future-data-exclusion",
                "outcome-authority-digest",
                "calibration-and-budget-metrics",
            ]
        )
    if identifier in {"sv-comp", "test-comp"}:
        required_execution_evidence.extend(
            [
                "competition-task-definition-digest",
                "validated-witness-or-test-suite-digest",
                "resource-limit-receipt",
            ]
        )
    if identifier in {"sigstore-client-conformance", "slsa-verifier-conformance"}:
        required_execution_evidence.extend(
            [
                "conformance-suite-digest",
                "trust-root-digest",
                "identity-policy-digest",
                "negative-verification-cases",
            ]
        )
    if identifier == "scitt-transparency-conformance":
        required_execution_evidence.extend(
            [
                "scitt-registration-policy-digest",
                "cose-trust-root-digest",
                "signed-statement-and-receipt-fixtures",
                "inclusion-and-consistency-proofs",
                "equivocation-and-replay-negative-cases",
            ]
        )
    if identifier in {
        "cloud-native-api-service-mesh-conformance",
        "multicloud-kubernetes-attack-paths",
    }:
        required_execution_evidence.extend(
            [
                "disposable-cloud-target-receipt",
                "tenant-and-workload-identity-map",
                "gateway-and-service-mesh-policy-digest",
                "control-plane-and-data-plane-observations",
                "destructive-action-authorization",
            ]
        )
    if identifier in {
        "api-contract-spec-conformance",
        "opentelemetry-semantic-conformance",
    }:
        required_execution_evidence.extend(
            [
                "official-schema-or-specification-digest",
                "positive-negative-and-downgrade-fixtures",
                "round-trip-semantic-equivalence-report",
                "unknown-field-and-version-drift-results",
            ]
        )
    if identifier == "ai-agentic-testing-conformance":
        required_execution_evidence.extend(
            [
                "model-and-agent-configuration-digest",
                "tool-authority-and-memory-boundary-manifest",
                "stochastic-seed-and-sampling-policy",
                "test-oracle-and-human-review-digest",
                "utility-and-security-confidence-intervals",
            ]
        )
    if identifier in {
        "harmbench",
        "agentharm",
        "garak-llm-probe-conformance",
        "pyrit-ai-red-team",
        "mlcommons-ailuminate-safety",
        "mlcommons-ailuminate-jailbreak",
    }:
        required_execution_evidence.extend(
            [
                "target-and-evaluator-model-configuration-digests",
                "attack-probe-detector-and-template-manifest",
                "seed-sampling-temperature-and-repetition-policy",
                "harmful-output-handling-and-human-adjudication-policy",
                "scorer-prompt-injection-and-manipulation-negative-tests",
                "public-corpus-contamination-assessment",
                "private-holdout-security-and-utility-results",
                "attack-success-and-utility-confidence-intervals",
            ]
        )
    if identifier == "agentharm":
        required_execution_evidence.extend(
            [
                "tool-authority-and-side-effect-boundary-manifest",
                "synthetic-secret-account-and-resource-manifest",
                "step-budget-kill-switch-reset-and-destruction-receipts",
            ]
        )
    if identifier == "garak-llm-probe-conformance":
        required_execution_evidence.extend(
            [
                "garak-lock-plugin-allowlist-and-dependency-digests",
                "probe-detector-compatibility-and-calibration-results",
                "generator-rate-token-cost-and-credential-boundary-receipts",
            ]
        )
    if identifier == "pyrit-ai-red-team":
        required_execution_evidence.extend(
            [
                "pyrit-release-lock-and-environment-digest",
                "scenario-objective-technique-and-converter-manifest",
                "target-scorer-memory-and-authority-boundary-manifest",
                "scorer-calibration-and-cross-evaluator-results",
                "step-token-time-spend-kill-switch-reset-and-cleanup-receipts",
            ]
        )
    if identifier == "nist-8286-enterprise-risk-register":
        required_execution_evidence.extend(
            [
                "nist-8286-series-and-schema-digests",
                "risk-register-and-detail-record-validation-results",
                "estimation-prioritization-and-response-reperformance",
                "risk-rollup-lineage-correlation-and-unit-analysis",
                "business-impact-appetite-tolerance-and-mutation-results",
            ]
        )
    if identifier == "cis-ram-attack-path-analysis":
        required_execution_evidence.extend(
            [
                "cis-ram-edition-license-and-risk-criteria-digests",
                "control-attack-model-veris-and-asset-scope-digests",
                "blinded-assessor-labels-and-agreement",
                "expectancy-impact-safeguard-and-treatment-reperformance",
                "sensitivity-adjudication-and-risk-acceptance-ledger",
            ]
        )
    if identifier == "square-quality-governance":
        required_execution_evidence.extend(
            [
                "licensed-25001-requirement-set-digest",
                "quality-plan-method-tool-and-measurement-digests",
                "competence-independence-and-resource-records",
                "evaluation-decision-and-feedback-trace",
                "management-fault-injection-results",
            ]
        )
    if identifier == "iso-42106-differentiated-ai-benchmarking":
        required_execution_evidence.extend(
            [
                "licensed-42106-guidance-and-quality-model-digests",
                "complexity-context-stakeholder-and-strata-design",
                "sample-repetition-uncertainty-and-aggregation-plan",
                "metamorphic-rank-stability-and-evaluator-robustness-results",
                "differentiated-threshold-decision-and-claim-boundary-record",
            ]
        )
    if identifier == "enterprise-architecture-governance":
        required_execution_evidence.extend(
            [
                "licensed-framework-edition-and-requirement-map-digests",
                "architecture-model-exchange-and-semantic-validation",
                "stakeholder-concern-decision-waiver-and-roadmap-trace",
                "blinded-assessor-agreement-and-adjudication",
                "quantitative-risk-sensitivity-and-claim-boundary-record",
            ]
        )
    additional_contract_evidence = {
        "owasp-aisvs-conformance": (
            "aisvs-release-requirement-and-level-digests",
            "ai-system-boundary-and-applicability-map",
            "requirement-control-test-evidence-trace",
            "prompt-data-model-tool-and-memory-negative-cases",
            "mutation-independent-review-and-adjudication-results",
        ),
        "iso-25058-ai-quality-evaluation": (
            "licensed-25058-criteria-and-quality-model-digests",
            "context-stakeholder-measure-and-threshold-plan",
            "dataset-strata-uncertainty-and-limitation-manifest",
            "reperformance-metamorphic-and-adverse-case-results",
            "independent-decision-and-monitoring-record",
        ),
        "eucc-scheme-assurance": (
            "eucc-regulation-amendment-and-sota-digests",
            "cc-cem-protection-profile-and-security-target-map",
            "itsef-certification-body-accreditation-and-authority-record",
            "certificate-product-version-configuration-and-registry-binding",
            "assurance-continuity-vulnerability-and-change-results",
        ),
        "cisa-secure-software-attestation": (
            "common-form-and-ssdf-claim-map-digests",
            "producer-product-version-and-release-subject-binding",
            "signatory-authority-signature-time-and-revocation-record",
            "practice-evidence-exception-and-compensating-control-trace",
            "forgery-replay-staleness-and-change-trigger-results",
        ),
        "ieee-7000-ai-ethics-conformance": (
            "licensed-ieee-7000-series-criteria-digests",
            "stakeholder-value-harm-and-requirement-trace",
            "transparency-privacy-bias-and-boundary-test-plan",
            "fail-safe-intervention-recovery-and-appeal-results",
            "subgroup-uncertainty-tradeoff-and-adjudication-record",
        ),
        "ai-use-case-security-privacy": (
            "licensed-24030-27563-criteria-and-use-case-digests",
            "domain-context-stakeholder-data-and-boundary-model",
            "security-privacy-risk-control-and-assurance-plan",
            "normal-adverse-out-of-domain-and-misuse-results",
            "residual-risk-limitation-and-independent-review-record",
        ),
        "it-quality-governance-assessor-agreement": (
            "licensed-38500-9001-requirement-map-digests",
            "governance-quality-risk-and-performance-case-set",
            "blinded-assessor-labels-agreement-and-competence",
            "nonconformity-corrective-action-and-improvement-trace",
            "adjudication-decision-and-claim-boundary-record",
        ),
        "nist-csf-profile-gap-reassessment": (
            "csf-2-core-sp-1301-and-informative-reference-digests",
            "organizational-scope-current-and-target-profile-digests",
            "gap-risk-priority-action-owner-and-dependency-trace",
            "identifier-mutation-regression-and-reassessment-results",
            "approval-exception-expiry-and-progress-record",
        ),
        "mlcommons-ailuminate-safety": (
            "ailuminate-safety-release-and-assessment-standard-digests",
            "sut-locale-persona-hazard-and-prompt-split-manifest",
            "evaluator-ensemble-calibration-and-reference-system-digests",
            "public-private-contamination-and-grading-results",
            "harmful-output-utility-uncertainty-and-claim-boundary-record",
        ),
        "mlcommons-ailuminate-jailbreak": (
            "ailuminate-jailbreak-release-attack-and-baseline-digests",
            "sut-attack-scenario-locale-and-protected-split-manifest",
            "evaluator-ensemble-calibration-and-reference-system-digests",
            "naive-versus-jailbreak-safety-and-grading-results",
            "contamination-variance-utility-and-claim-boundary-record",
        ),
        "privacy-engineering-pet-conformance": (
            "licensed-27561-27564-27565-criteria-digests",
            "privacy-objective-model-data-flow-and-attacker-boundary",
            "zkp-statement-relation-setup-parameter-and-implementation-digests",
            "malformed-replay-linkability-composition-and-differential-results",
            "cryptographic-review-residual-risk-and-agility-record",
        ),
        "mcp-client-server-security-conformance": (
            "mcp-2025-11-25-schema-security-and-feature-digests",
            "client-server-proxy-transport-and-capability-matrix",
            "oauth-discovery-resource-scope-token-and-redirect-results",
            "tool-resource-prompt-elicitation-sampling-and-task-policy-trace",
            "malformed-drift-confused-deputy-ssrf-injection-replay-and-cleanup-results",
        ),
        "aws-fsbp-securityhub-conformance": (
            "fsbp-control-snapshot-and-securityhub-model-digests",
            "aws-account-ou-region-resource-and-coverage-inventory",
            "securityhub-finding-suppression-exception-and-remediation-trace",
            "independent-inventory-drift-and-negative-case-results",
            "cloudtrail-cleanup-rescan-and-claim-boundary-record",
        ),
        "microsoft-mcsb-defender-conformance": (
            "mcsb-v1-control-and-service-baseline-digests",
            "azure-tenant-management-group-subscription-and-resource-inventory",
            "defender-assessment-exemption-and-remediation-trace",
            "resource-graph-drift-and-negative-case-results",
            "activity-log-cleanup-rescan-and-preview-separation-record",
        ),
        "gcp-enterprise-foundations-conformance": (
            "gcp-foundation-guide-and-terraform-revision-digests",
            "gcp-organization-folder-project-resource-and-identity-inventory",
            "organization-policy-architecture-scc-deviation-and-remediation-trace",
            "asset-inventory-drift-and-negative-case-results",
            "audit-log-cleanup-rescan-and-claim-boundary-record",
        ),
        "first-csirt-psirt-maturity-assessment": (
            "first-framework-maturity-and-metric-digests",
            "mandate-constituency-service-role-and-competence-map",
            "incident-vulnerability-disclosure-coordination-and-outcome-results",
            "blinded-assessor-agreement-conflict-and-adjudication-record",
            "capability-gap-owner-milestone-and-reassessment-trace",
        ),
        "memory-safety-engineering-conformance": (
            "unsafe-language-construct-ffi-dependency-and-reachability-inventory",
            "production-build-toolchain-hardening-and-mitigation-digests",
            "static-sanitizer-fuzz-crash-and-regression-results",
            "privilege-exposure-consequence-exception-and-residual-risk-trace",
            "migration-roadmap-parity-performance-and-reassessment-record",
        ),
        "ieee-ai-governance-wellbeing-assessment": (
            "licensed-ieee-2863-and-7010-criteria-digests",
            "ai-governance-authority-role-lifecycle-and-provider-map",
            "stakeholder-domain-indicator-baseline-and-impact-results",
            "blinded-reviewer-agreement-tradeoff-and-adjudication-record",
            "monitoring-appeal-incident-retirement-and-improvement-trace",
        ),
        "organizational-resilience-bia-exercise": (
            "licensed-22316-and-22317-criteria-digests",
            "product-service-activity-resource-and-dependency-model",
            "impact-tolerance-rto-rpo-capacity-and-assumption-record",
            "disruption-degradation-failover-restoration-and-reconciliation-results",
            "safety-cleanup-variance-improvement-and-reassessment-trace",
        ),
        "openssf-best-practices-badge-conformance": (
            "openssf-baseline-and-metal-criteria-digests",
            "project-identity-response-export-and-repository-snapshot",
            "criterion-applicability-answer-source-and-freshness-map",
            "stale-link-disabled-control-inflated-level-and-identity-results",
            "recomputed-level-independent-sample-and-claim-boundary-record",
        ),
        "isms-implementation-process-assessment": (
            "licensed-27003-and-27022-criteria-digests",
            "isms-scope-process-interface-control-measure-and-record-map",
            "implementation-tailoring-capability-and-improvement-results",
            "blinded-assessor-agreement-conflict-and-adjudication-record",
            "conformity-capability-and-certification-claim-boundary-review",
        ),
        "a2a-protocol-security-conformance": (
            "a2a-1.0.0-proto-specification-tck-and-sdk-digests",
            "agent-card-jws-provider-endpoint-version-binding-and-tenant-results",
            "principal-skill-task-message-artifact-and-subscription-authorization-trace",
            "http-json-jsonrpc-grpc-stream-and-webhook-interoperability-results",
            "downgrade-cross-tenant-credential-ssrf-replay-race-and-cleanup-results",
        ),
        "sesip-iot-platform-evaluation-conformance": (
            "sesip-1.2-en17927-criteria-profile-and-mapping-digests",
            "toe-platform-part-product-version-configuration-and-asset-boundary",
            "sfr-spp-sar-assurance-level-threat-and-environment-trace",
            "composition-certificate-vulnerability-change-and-expiry-results",
            "scheme-laboratory-evaluator-authority-and-negative-claim-record",
        ),
        "first-tlp-iep-information-handling-conformance": (
            "first-tlp-2.0-iep-2.0-framework-json-and-policy-digests",
            "label-recipient-community-action-attribution-and-redistribution-results",
            "stix-taxii-json-roundtrip-and-semantic-equivalence-report",
            "policy-reference-immutability-overlap-date-and-unknown-policy-results",
            "downgrade-removal-unauthorized-sharing-and-audit-negative-cases",
        ),
        "veris-incident-schema-conformance": (
            "veris-1.3.6-schema-vocabulary-and-example-digests",
            "deidentified-incident-and-golden-classification-set-digests",
            "actor-action-asset-attribute-timeline-impact-and-unknown-results",
            "roundtrip-aggregate-deidentification-and-analytic-equivalence-results",
            "schema-validity-versus-incident-truth-claim-boundary-record",
        ),
        "w3c-web-platform-defense-conformance": (
            "w3c-csp2-sri1-and-web-platform-test-digests",
            "browser-policy-header-resource-origin-and-engine-manifest",
            "nonce-hash-source-frame-form-base-connect-report-and-integrity-results",
            "redirect-cors-cdn-substitution-multi-policy-and-fallback-results",
            "cross-engine-block-report-recovery-and-limitation-record",
        ),
        "dora-level2-technical-standards-conformance": (
            "eu-1772-1774-2956-301-302-1190-consolidated-act-digests",
            "entity-applicability-ict-risk-control-critical-function-and-dependency-map",
            "incident-classification-timeline-template-and-secure-channel-results",
            "entity-group-provider-contract-function-location-and-register-results",
            "tlpt-scope-tester-safety-finding-remediation-closure-and-claim-record",
        ),
        "ffiec-it-handbook-assessment": (
            "ffiec-dam-2024-aio-2021-information-security-2016-digests",
            "institution-service-provider-scope-risk-and-applicability-record",
            "development-architecture-operations-security-and-incident-results",
            "blinded-examiner-agreement-competence-conflict-and-adjudication-record",
            "retired-cat-exclusion-and-handbook-claim-boundary-review",
        ),
        "bsi-c5-cloud-assurance-assessment": (
            "bsi-c5-2020-criteria-and-evaluation-guidance-digests",
            "cloud-service-boundary-location-subservice-and-description-map",
            "control-customer-responsibility-deviation-and-incident-results",
            "blinded-assessor-agreement-independence-conflict-and-adjudication-record",
            "attestation-versus-certification-claim-boundary-review",
        ),
        "fcc-cyber-trust-mark-conformance": (
            "fcc-24-26-baseline-test-procedure-and-program-digests",
            "iot-product-component-software-support-and-configuration-boundary",
            "recognized-laboratory-test-report-remediation-and-renewal-results",
            "applicant-authorization-qr-registry-and-consumer-information-trace",
            "forgery-copied-label-redirect-expiry-withdrawal-and-overclaim-results",
        ),
        "openid-digital-credential-conformance": (
            "vc-data-model-data-integrity-status-openid-and-haip-specification-digests",
            "issuer-wallet-verifier-format-cryptosuite-and-trust-policy-matrix",
            "issuance-presentation-selective-disclosure-status-and-holder-binding-results",
            "malformed-replay-downgrade-confusion-correlation-and-privacy-negative-cases",
            "official-conformance-suite-report-and-certification-claim-boundary-record",
        ),
        "cisa-scuba-saas-posture-conformance": (
            "scuba-m365-gws-baseline-assessment-tool-and-policy-snapshot-digests",
            "tenant-service-license-identity-resource-and-api-coverage-inventory",
            "read-only-posture-result-exception-owner-expiry-and-remediation-trace",
            "independent-drift-unassessed-resource-and-regression-results",
            "authorization-minimization-cleanup-and-production-mutation-claim-record",
        ),
        "cis-kubernetes-hardening-conformance": (
            "licensed-cis-kubernetes-2.0.1-criteria-and-tool-digests",
            "cluster-version-role-control-plane-node-workload-and-applicability-map",
            "automated-and-manual-check-evidence-exception-and-remediation-trace",
            "admission-runtime-network-rbac-secret-and-audit-negative-cases",
            "independent-rescan-drift-and-no-certification-claim-record",
        ),
        "linddun-privacy-threat-model-conformance": (
            "linddun-pro-methodology-taxonomy-and-template-digests",
            "data-flow-entity-trust-boundary-asset-purpose-and-data-subject-model",
            "threat-tree-elicitation-misuse-case-mitigation-and-test-trace",
            "blinded-assessor-labels-agreement-omission-mutation-and-adjudication-results",
            "residual-privacy-risk-approval-expiry-and-reassessment-record",
        ),
        "owasp-benchmark-ast-modality-comparison": (
            "owasp-benchmark-release-label-and-category-digests",
            "sast-dast-iast-tool-version-configuration-and-capability-manifest",
            "matched-corpus-target-build-request-and-observation-boundary",
            "per-modality-confusion-matrices-overlap-latency-and-resource-results",
            "unsupported-language-runtime-and-rasp-separation-claim-boundary-record",
        ),
        "rasp-prevention-effectiveness": (
            "rasp-agent-policy-runtime-and-application-fixture-digests",
            "attack-technique-route-data-flow-and-protection-coverage-manifest",
            "blocked-observed-bypassed-false-positive-latency-and-stability-results",
            "instrumentation-health-tamper-bypass-fail-open-and-fail-closed-cases",
            "kill-switch-reset-cleanup-and-non-production-claim-boundary-record",
        ),
        "gsma-nesas-scas-assurance": (
            "nesas-3.0-scas-release-and-product-applicability-digests",
            "vendor-development-security-process-and-network-product-boundary",
            "accredited-laboratory-evaluator-method-tool-and-competency-record",
            "scas-functional-robustness-penetration-vulnerability-and-retest-results",
            "scheme-report-vulnerability-change-and-no-certification-claim-record",
        ),
        "tisax-vda-isa-assessment": (
            "licensed-vda-isa-6.0.3-and-tisax-handbook-criteria-digests",
            "scope-locations-objectives-protection-needs-participant-and-provider-map",
            "control-maturity-evidence-finding-corrective-action-and-follow-up-trace",
            "blinded-assessor-agreement-independence-conflict-and-adjudication-results",
            "result-sharing-label-expiry-and-no-suite-issued-label-claim-record",
        ),
        "c2pa-content-credentials-conformance": (
            "c2pa-2.4-specification-schema-test-and-trust-list-digests",
            "asset-manifest-claim-assertion-ingredient-signature-and-trust-policy-map",
            "create-read-validate-roundtrip-edit-redaction-and-revocation-results",
            "tamper-unknown-signer-replay-misbinding-parser-and-resource-negative-cases",
            "provenance-versus-content-truth-and-identity-claim-boundary-record",
        ),
        "pci-payment-acceptance-conformance": (
            "licensed-mpoc-p2pe-program-requirement-and-test-procedure-digests",
            "solution-component-payment-flow-account-data-key-and-applicability-map",
            "laboratory-control-domain-test-evidence-exception-and-remediation-trace",
            "tamper-overlay-debug-rooting-key-substitution-decryption-and-update-cases",
            "synthetic-data-cleanup-and-no-pci-listing-or-validation-claim-record",
        ),
        "oidf-fapi-conformance": (
            "fapi-2.0-final-attacker-model-message-signing-and-suite-digests",
            "authorization-server-client-resource-server-profile-and-key-boundary",
            "par-jarm-dpop-or-mtls-token-issuer-audience-and-replay-results",
            "downgrade-algorithm-confusion-key-substitution-ssrf-and-misbinding-cases",
            "official-suite-report-and-no-certification-claim-boundary-record",
        ),
        "fedramp-20x-continuous-validation": (
            "fedramp-20x-class-rule-ksi-and-validation-code-digests",
            "cloud-service-offering-boundary-goal-measure-and-owner-map",
            "independent-validation-sample-and-continuous-monitoring-results",
            "stale-evidence-boundary-drift-measure-gaming-and-failure-cases",
            "marketplace-status-agency-decision-and-no-authorization-claim-record",
        ),
        "fido2-authenticator-conformance": (
            "ctap-2.2-webauthn-mds-and-functional-suite-digests",
            "client-authenticator-rp-origin-credential-transport-and-aaguid-map",
            "functional-transport-user-verification-and-metadata-results",
            "malformed-cbor-downgrade-replay-revocation-and-recovery-cases",
            "official-suite-report-and-no-fido-certification-claim-record",
        ),
        "eudi-wallet-functional-conformance": (
            "eudi-acts-arf-3.0.0-fcaf-and-reference-fixture-digests",
            "wallet-unit-provider-issuer-rp-trust-list-pid-and-eaa-boundary",
            "issuance-presentation-wallet-to-wallet-and-lifecycle-results",
            "over-request-replay-downgrade-registration-recovery-and-privacy-cases",
            "member-state-certification-and-no-legal-conformity-claim-record",
        ),
        "hitrust-csf-assessment": (
            "licensed-hitrust-csf-11.8.0-and-assurance-program-digests",
            "assessment-type-scope-factor-requirement-and-inheritance-map",
            "blinded-assessor-agreement-quality-assurance-and-scoring-results",
            "scope-drift-stale-evidence-maturity-inflation-and-conflict-cases",
            "report-validity-corrective-action-and-no-certification-claim-record",
        ),
        "pci-secure-software-conformance": (
            "licensed-pci-secure-software-2.0-secure-slc-1.1-and-program-digests",
            "product-sdk-module-sensitive-asset-lifecycle-and-listing-boundary",
            "product-lifecycle-delta-vulnerability-and-annual-attestation-results",
            "scope-omission-change-tier-api-component-and-stale-listing-cases",
            "assessor-authority-synthetic-data-and-no-pci-validation-claim-record",
        ),
        "nis2-implementing-regulation-conformance": (
            "nis2-implementing-regulation-2024-2690-and-enisa-guidance-digests",
            "entity-service-sector-member-state-measure-and-evidence-map",
            "technical-control-effectiveness-incident-and-supply-chain-results",
            "applicability-asset-continuity-threshold-timing-and-exception-cases",
            "legal-guidance-boundary-and-no-regulatory-notification-claim-record",
        ),
        "nist-supplier-due-diligence": (
            "nist-sp-1326-and-csrm-source-snapshot-digests",
            "supplier-product-ownership-provenance-dependency-and-source-map",
            "blinded-risk-decision-contract-monitoring-and-reassessment-results",
            "alias-ownership-staleness-conflict-concentration-and-deception-cases",
            "confidence-gaps-and-no-absence-of-adverse-data-assurance-record",
        ),
        "owasp-samm-assessment-benchmark": (
            "owasp-samm-2.1.0-model-assessment-toolbox-and-dataset-digests",
            "organization-scope-practice-activity-quality-criteria-and-evidence-map",
            "blinded-assessor-agreement-roadmap-and-reassessment-results",
            "partial-criteria-stale-evidence-scope-drift-and-level-inflation-cases",
            "cohort-size-privacy-representativeness-and-no-certification-claim-record",
        ),
    }
    required_execution_evidence.extend(additional_contract_evidence.get(identifier, ()))
    if identifier == "owasp-cornucopia-threat-model":
        required_execution_evidence.extend(
            [
                "cornucopia-edition-language-license-and-card-digests",
                "architecture-boundary-and-applicability-map",
                "card-threat-control-test-and-risk-trace",
                "omission-mutation-and-negative-case-results",
                "blinded-independent-review-and-adjudication",
            ]
        )
    if identifier == "s2c2f-consumer-dependency-conformance":
        required_execution_evidence.extend(
            [
                "dependency-admission-policy-digest",
                "package-origin-and-integrity-receipts",
                "substitution-and-quarantine-negative-cases",
                "compromise-response-exercise",
            ]
        )
    if identifier == "securitytxt-patch-operations-conformance":
        required_execution_evidence.extend(
            [
                "security-txt-parser-and-http-transcript",
                "asset-and-patch-inventory-digest",
                "risk-prioritization-and-exception-records",
                "rollback-and-post-deployment-verification",
            ]
        )
    if identifier in {
        "automotive-software-update-conformance",
        "energy-product-security-conformance",
    }:
        required_execution_evidence.extend(
            [
                "licensed-requirement-set-digest",
                "representative-product-configuration",
                "safety-and-availability-impact-review",
                "negative-case-and-recovery-transcript",
            ]
        )
    if identifier in {
        "architecture-evaluation-scenarios",
        "process-capability-assessor-agreement",
        "cis-ram-attack-path-analysis",
        "enterprise-architecture-governance",
        "it-quality-governance-assessor-agreement",
    }:
        required_execution_evidence.extend(
            ["blinded-assessor-labels", "inter-rater-agreement"]
        )
    if identifier == "cwe-mapping-conformance":
        required_execution_evidence.extend(
            ["cwe-release-digest", "mapping-abstraction-policy-digest"]
        )
    if identifier == "structured-assurance-case-conformance":
        required_execution_evidence.extend(
            [
                "sacm-metamodel-and-schema-digest",
                "claim-argument-evidence-graph-digest",
                "defeater-and-confidence-policy-digest",
                "graph-mutation-and-semantic-validation-results",
                "independent-assurance-case-review",
            ]
        )
    if identifier == "integrity-vv-conformance":
        required_execution_evidence.extend(
            [
                "ieee-1012-requirement-set-digest",
                "integrity-level-classification-record",
                "vv-independence-and-competence-record",
                "system-software-hardware-interface-trace",
                "reuse-cots-and-anomaly-disposition-evidence",
            ]
        )
    if identifier == "cmvp-fips-140-3-validation":
        required_execution_evidence.extend(
            [
                "cmvp-scheme-publication-snapshot-digest",
                "cmvp-referenced-edition-map",
                "module-security-policy-and-boundary-digest",
                "algorithm-and-module-certificate-status-snapshot",
                "implementation-guidance-and-test-decision-trace",
            ]
        )
    if identifier == "iso-19790-24759-module-conformance":
        required_execution_evidence.extend(
            [
                "licensed-19790-24759-requirement-set-digest",
                "module-level-boundary-and-configuration-digest",
                "vendor-evidence-and-test-assertion-trace",
                "calibration-uncertainty-and-deviation-record",
                "fault-and-non-invasive-test-authorization",
            ]
        )
    if identifier == "biometric-performance-pad":
        required_execution_evidence.extend(
            [
                "consent-privacy-and-retention-governance",
                "sample-size-and-demographic-analysis-plan",
                "locked-threshold-and-sensor-configuration-digest",
                "presentation-attack-instrument-manifest",
                "stratified-confidence-interval-report",
            ]
        )
    if identifier == "service-management-security-integration":
        required_execution_evidence.extend(
            [
                "licensed-20000-1-27013-requirement-map-digest",
                "service-configuration-and-ownership-baseline",
                "change-release-deployment-trace",
                "incident-problem-supplier-continuity-trace",
                "fault-recovery-and-corrective-action-results",
            ]
        )
    if identifier == "interlaboratory-proficiency-testing":
        required_execution_evidence.extend(
            [
                "proficiency-scheme-plan-digest",
                "homogeneity-stability-and-assigned-value-evidence",
                "participant-scope-blinding-and-confidentiality-record",
                "agreement-bias-drift-and-outlier-analysis",
                "appeal-adjudication-and-corrective-action-ledger",
            ]
        )
    return {
        "adapter": identifier,
        "protocol": protocol,
        "expected_results": (
            "organization-approved-labels"
            if benchmark["version"] == "organization-pinned"
            else "official-corpus-labels"
        ),
        "minimum_repetitions": {
            "google-fuzzbench": 20,
            "magma-ground-truth": 10,
            "oss-fuzz-clusterfuzzlite": 3,
        }.get(
            identifier,
            3
            if identifier == "oss-crs-crsbench" or continuous_fuzzing
            else (5 if stochastic else 1),
        ),
        "required_execution_evidence": list(dict.fromkeys(required_execution_evidence)),
        "score_semantics": (
            [
                "precision",
                "recall",
                "false-positive-rate",
                "youden-j",
                "wilson-95-percent-confidence-interval",
            ]
            if protocol == "classification"
            else [
                protocol,
                "protocol-specific-acceptance-criteria",
                "reproducibility-evidence",
            ]
        ),
    }


def _benchmark_reproducibility_gaps(
    value: object, benchmark: dict[str, Any] | None = None
) -> list[str]:
    if not isinstance(value, dict):
        return []
    report = value.get("report")
    matrix = value.get("confusion_matrix")
    corpus = value.get("corpus")
    time_authority = value.get("time_authority")
    gaps = []
    if value.get("schema_version") in {"1.1", "1.2"}:
        authorities = (
            benchmark.get("trusted_receipt_authorities")
            if isinstance(benchmark, dict)
            else None
        )
        if not isinstance(authorities, list) or not authorities:
            gaps.append(
                "benchmark execution receipt signature lacks lifecycle-aware trusted-party admission"
            )
        else:
            try:
                authority_index = {
                    ("execution-receipt", str(item["key_id"])): item
                    for item in authorities
                }
                verify_execution_receipt_signature(
                    value,
                    {
                        "schema_version": "1.1",
                        "authority_index": authority_index,
                    },
                )
            except BenchmarkAssuranceError:
                gaps.append("benchmark execution receipt signature is invalid")
    sufficiency = value.get("statistical_sufficiency")
    if isinstance(sufficiency, dict) and sufficiency.get("enforced") is True:
        if sufficiency.get("complete") is not True:
            gaps.append("benchmark statistical sufficiency is incomplete")
        execution = value.get("execution_context")
        if not isinstance(execution, dict):
            gaps.append("benchmark statistical design evidence is missing")
        else:
            for name in (
                "power_analysis_sha256",
                "leakage_check_sha256",
                "duplicate_check_sha256",
            ):
                if not _digest(str(execution.get(name) or "")):
                    gaps.append(f"benchmark {name} is missing or invalid")
            if execution.get("holdout_sequestered") is not True:
                gaps.append("benchmark holdout sequestration is not proven")
            repetitions = execution.get("repetitions")
            if (
                isinstance(repetitions, bool)
                or not isinstance(repetitions, int)
                or repetitions < 3
            ):
                gaps.append("benchmark repeated-run evidence is insufficient")
    if not isinstance(report, dict) or not _digest(
        str(report.get("checksums_sha256") or "")
    ):
        gaps.append("verified report checksum is missing")
    protocol = (
        _benchmark_protocol(str(benchmark.get("id")))
        if isinstance(benchmark, dict)
        else "classification"
    )
    if protocol == "classification" and (
        not isinstance(matrix, dict)
        or any(
            not isinstance(matrix.get(name), int) or isinstance(matrix.get(name), bool)
            for name in (
                "true_positive",
                "true_negative",
                "false_positive",
                "false_negative",
            )
        )
    ):
        gaps.append("complete confusion matrix is missing")
    if protocol != "classification":
        if not _protocol_metrics_valid(protocol, value.get("protocol_metrics")):
            gaps.append(f"valid {protocol} protocol metrics are missing")
        if not _protocol_acceptance(value):
            gaps.append(
                "approved protocol-specific acceptance criteria are missing or unmet"
            )
    if not isinstance(corpus, dict) or not _text(corpus.get("revision"), 200):
        gaps.append("corpus revision is missing")
    if (
        not isinstance(time_authority, dict)
        or time_authority.get("validated") is not True
    ):
        gaps.append("trusted evaluation time is not validated")
    if value.get("replay_protected") is not True:
        gaps.append("evaluation replay protection is missing")
    identifier = str(benchmark.get("id")) if isinstance(benchmark, dict) else ""
    if not industry_extension_score_evidence_valid(value, identifier):
        gaps.append("suite-owned industry extension evidence is missing or invalid")
    contract = benchmark.get("runner_contract") if isinstance(benchmark, dict) else None
    requires_qualified_context = isinstance(benchmark, dict) and (
        benchmark.get("version") == "organization-pinned"
        or benchmark.get("lane") == "authorized-companion"
    )
    if requires_qualified_context:
        execution = value.get("execution_context")
        if not isinstance(execution, dict):
            gaps.append("qualified benchmark execution context is missing")
        else:
            for name in (
                "target_sha256",
                "environment_sha256",
                "toolset_sha256",
                "oracle_sha256",
                "isolation_receipt_sha256",
                "runner_oci_image_sha256",
                "runner_sbom_sha256",
                "runner_provenance_sha256",
                "resource_limits_sha256",
                "network_policy_sha256",
                "egress_transcript_sha256",
                "cleanup_receipt_sha256",
                "dataset_license_sha256",
                "label_authority_sha256",
                "contamination_manifest_sha256",
            ):
                if not _digest(str(execution.get(name) or "")):
                    gaps.append(f"benchmark execution {name} is missing or invalid")
            if not _text(execution.get("runner_identity"), 300) or not _text(
                execution.get("runner_version"), 100
            ):
                gaps.append("benchmark runner identity or version is missing")
            if execution.get("isolation_validated") is not True:
                gaps.append("benchmark execution isolation is not validated")
            if execution.get("network_isolation_validated") is not True:
                gaps.append("benchmark network isolation is not validated")
            if execution.get("target_destroyed") is not True:
                gaps.append("benchmark target cleanup and destruction is not proven")
            for field, description in (
                ("runner_image_pinned", "runner OCI image pinning"),
                ("runner_sbom_matches_image", "runner SBOM subject binding"),
                ("runner_provenance_verified", "runner provenance verification"),
                (
                    "provenance_subject_matches_image",
                    "runner provenance subject binding",
                ),
                ("resource_limits_enforced", "resource-limit enforcement"),
                ("network_policy_enforced", "network-policy enforcement"),
                ("egress_transcript_complete", "egress transcript completeness"),
                ("cleanup_validated", "target cleanup validation"),
            ):
                if execution.get(field) is not True:
                    gaps.append(f"benchmark {description} is not proven")
            for name in ("positive_controls", "negative_controls"):
                count = execution.get(name)
                if isinstance(count, bool) or not isinstance(count, int) or count < 1:
                    gaps.append(f"benchmark {name} are missing")
            if execution.get("split_strategy") not in {
                "official-fixed",
                "project-split",
                "time-split",
            }:
                gaps.append("benchmark split strategy is missing or invalid")
            if (
                isinstance(benchmark, dict)
                and benchmark.get("version") == "organization-pinned"
            ):
                reviewers = execution.get("independent_reviewers")
                if (
                    isinstance(reviewers, bool)
                    or not isinstance(reviewers, int)
                    or reviewers < 2
                ):
                    gaps.append("benchmark requires at least two independent reviewers")
            if (
                isinstance(benchmark, dict)
                and benchmark.get("id") == "scanner-scale-determinism"
            ):
                for name in ("wall_time_ms", "peak_memory_bytes"):
                    measurement = execution.get(name)
                    if (
                        isinstance(measurement, bool)
                        or not isinstance(measurement, int)
                        or measurement < 1
                    ):
                        gaps.append(f"benchmark {name} measurement is missing")
                deterministic_runs = execution.get("deterministic_runs")
                if (
                    isinstance(deterministic_runs, bool)
                    or not isinstance(deterministic_runs, int)
                    or deterministic_runs < 3
                ):
                    gaps.append("benchmark requires at least three deterministic runs")
            if (
                isinstance(benchmark, dict)
                and benchmark.get("id") in _LABORATORY_QUALIFIED_BENCHMARKS
            ):
                for name in (
                    "method_validation_sha256",
                    "evaluator_competency_sha256",
                    "impartiality_review_sha256",
                    "measurement_traceability_sha256",
                ):
                    if not _digest(str(execution.get(name) or "")):
                        gaps.append(
                            f"laboratory qualification {name} is missing or invalid"
                        )
            identifier = str(benchmark.get("id")) if isinstance(benchmark, dict) else ""
            if identifier == "epss-kev-temporal-backtest":
                for name in (
                    "epss_snapshot_sha256",
                    "kev_snapshot_sha256",
                    "outcome_authority_sha256",
                ):
                    if not _digest(str(execution.get(name) or "")):
                        gaps.append(f"temporal benchmark {name} is missing or invalid")
                if execution.get("point_in_time") is not True:
                    gaps.append(
                        "temporal benchmark point-in-time execution is not proven"
                    )
                if execution.get("future_data_excluded") is not True:
                    gaps.append(
                        "temporal benchmark future-data exclusion is not proven"
                    )
                for name in (
                    "brier_score",
                    "expected_calibration_error",
                    "recall_at_budget",
                    "effort",
                ):
                    if not _ratio(execution.get(name)):
                        gaps.append(f"temporal benchmark {name} is missing or invalid")
            if identifier in {"sv-comp", "test-comp"}:
                for name in (
                    "task_definition_sha256",
                    "validated_witness_sha256",
                    "resource_limits_sha256",
                ):
                    if not _digest(str(execution.get(name) or "")):
                        gaps.append(
                            f"competition benchmark {name} is missing or invalid"
                        )
            if identifier in {
                "sigstore-client-conformance",
                "slsa-verifier-conformance",
            }:
                for name in (
                    "conformance_suite_sha256",
                    "trust_root_sha256",
                    "identity_policy_sha256",
                ):
                    if not _digest(str(execution.get(name) or "")):
                        gaps.append(f"signing conformance {name} is missing or invalid")
                negative_cases = execution.get("negative_verification_cases")
                if (
                    isinstance(negative_cases, bool)
                    or not isinstance(negative_cases, int)
                    or negative_cases < 1
                ):
                    gaps.append("signing conformance negative cases are missing")
            if identifier in {
                "architecture-evaluation-scenarios",
                "process-capability-assessor-agreement",
                "it-quality-governance-assessor-agreement",
            }:
                agreement = execution.get("inter_rater_agreement")
                if not (
                    _ratio(agreement)
                    and isinstance(agreement, (int, float))
                    and not isinstance(agreement, bool)
                    and float(agreement) >= 0.8
                ):
                    gaps.append(
                        "independent assessor agreement is missing or below 0.8"
                    )
                if execution.get("assessors_blinded") is not True:
                    gaps.append("independent assessors were not blinded")
            if identifier == "cwe-mapping-conformance":
                for name in (
                    "cwe_release_sha256",
                    "mapping_policy_sha256",
                ):
                    if not _digest(str(execution.get(name) or "")):
                        gaps.append(f"CWE mapping {name} is missing or invalid")
            specialized_digests = {
                "structured-assurance-case-conformance": (
                    "sacm_schema_sha256",
                    "assurance_graph_sha256",
                    "defeater_policy_sha256",
                    "mutation_report_sha256",
                    "independent_review_sha256",
                ),
                "integrity-vv-conformance": (
                    "ieee_1012_requirements_sha256",
                    "integrity_classification_sha256",
                    "vv_independence_sha256",
                    "interface_trace_sha256",
                    "anomaly_disposition_sha256",
                ),
                "cmvp-fips-140-3-validation": (
                    "cmvp_scheme_snapshot_sha256",
                    "referenced_edition_map_sha256",
                    "module_security_policy_sha256",
                    "certificate_status_snapshot_sha256",
                    "test_decision_trace_sha256",
                ),
                "iso-19790-24759-module-conformance": (
                    "licensed_requirements_sha256",
                    "module_claims_sha256",
                    "test_assertion_trace_sha256",
                    "calibration_uncertainty_sha256",
                    "fault_test_authorization_sha256",
                ),
                "biometric-performance-pad": (
                    "privacy_governance_sha256",
                    "analysis_plan_sha256",
                    "locked_threshold_sha256",
                    "attack_instrument_manifest_sha256",
                    "stratified_report_sha256",
                ),
                "service-management-security-integration": (
                    "licensed_requirement_map_sha256",
                    "service_baseline_sha256",
                    "change_trace_sha256",
                    "incident_continuity_trace_sha256",
                    "corrective_action_sha256",
                ),
                "interlaboratory-proficiency-testing": (
                    "proficiency_plan_sha256",
                    "assigned_value_evidence_sha256",
                    "participant_blinding_sha256",
                    "statistical_analysis_sha256",
                    "corrective_action_ledger_sha256",
                ),
                "nist-8286-enterprise-risk-register": (
                    "nist_8286_schema_set_sha256",
                    "risk_register_validation_sha256",
                    "risk_estimation_reperformance_sha256",
                    "risk_rollup_analysis_sha256",
                    "bia_appetite_mutation_sha256",
                ),
                "cis-ram-attack-path-analysis": (
                    "cis_ram_criteria_sha256",
                    "attack_model_scope_sha256",
                    "assessor_labels_sha256",
                    "risk_reperformance_sha256",
                    "adjudication_ledger_sha256",
                ),
                "square-quality-governance": (
                    "licensed_25001_requirements_sha256",
                    "quality_plan_methods_sha256",
                    "competence_resources_sha256",
                    "evaluation_decision_trace_sha256",
                    "fault_injection_results_sha256",
                ),
                "iso-42106-differentiated-ai-benchmarking": (
                    "licensed_42106_guidance_sha256",
                    "differentiation_design_sha256",
                    "sampling_uncertainty_plan_sha256",
                    "metamorphic_stability_results_sha256",
                    "claim_boundary_record_sha256",
                ),
                "enterprise-architecture-governance": (
                    "licensed_framework_map_sha256",
                    "model_semantics_validation_sha256",
                    "architecture_decision_trace_sha256",
                    "assessor_adjudication_sha256",
                    "risk_sensitivity_record_sha256",
                ),
                "pyrit-ai-red-team": (
                    "pyrit_environment_lock_sha256",
                    "scenario_technique_manifest_sha256",
                    "target_authority_boundary_sha256",
                    "scorer_calibration_sha256",
                    "execution_cleanup_receipts_sha256",
                ),
                "owasp-aisvs-conformance": (
                    "aisvs_release_sha256",
                    "ai_boundary_applicability_sha256",
                    "requirement_evidence_trace_sha256",
                    "negative_case_results_sha256",
                    "mutation_adjudication_sha256",
                ),
                "iso-25058-ai-quality-evaluation": (
                    "licensed_25058_criteria_sha256",
                    "quality_evaluation_plan_sha256",
                    "dataset_uncertainty_manifest_sha256",
                    "metamorphic_results_sha256",
                    "independent_decision_sha256",
                ),
                "eucc-scheme-assurance": (
                    "eucc_scheme_sota_sha256",
                    "cc_cem_security_target_map_sha256",
                    "laboratory_authority_sha256",
                    "certificate_subject_binding_sha256",
                    "assurance_continuity_results_sha256",
                ),
                "cisa-secure-software-attestation": (
                    "common_form_ssdf_map_sha256",
                    "release_subject_binding_sha256",
                    "signatory_authority_sha256",
                    "practice_exception_trace_sha256",
                    "forgery_replay_results_sha256",
                ),
                "ieee-7000-ai-ethics-conformance": (
                    "licensed_ieee_criteria_sha256",
                    "stakeholder_value_trace_sha256",
                    "transparency_privacy_bias_plan_sha256",
                    "failsafe_appeal_results_sha256",
                    "subgroup_adjudication_sha256",
                ),
                "ai-use-case-security-privacy": (
                    "licensed_use_case_criteria_sha256",
                    "domain_boundary_model_sha256",
                    "security_privacy_assurance_plan_sha256",
                    "adverse_use_case_results_sha256",
                    "residual_risk_review_sha256",
                ),
                "it-quality-governance-assessor-agreement": (
                    "licensed_governance_quality_map_sha256",
                    "assessment_case_set_sha256",
                    "assessor_agreement_sha256",
                    "corrective_action_trace_sha256",
                    "adjudication_record_sha256",
                ),
                "nist-csf-profile-gap-reassessment": (
                    "csf_sp1301_source_sha256",
                    "current_target_profiles_sha256",
                    "gap_action_trace_sha256",
                    "reassessment_results_sha256",
                    "approval_exception_record_sha256",
                ),
                "mlcommons-ailuminate-safety": (
                    "ailuminate_release_sha256",
                    "hazard_prompt_split_sha256",
                    "evaluator_calibration_sha256",
                    "contamination_grading_sha256",
                    "uncertainty_claim_record_sha256",
                ),
                "mlcommons-ailuminate-jailbreak": (
                    "ailuminate_jailbreak_release_sha256",
                    "attack_protected_split_sha256",
                    "evaluator_calibration_sha256",
                    "jailbreak_grading_sha256",
                    "variance_claim_record_sha256",
                ),
                "privacy-engineering-pet-conformance": (
                    "licensed_privacy_criteria_sha256",
                    "privacy_attacker_model_sha256",
                    "zkp_implementation_parameters_sha256",
                    "pet_adversarial_results_sha256",
                    "cryptographic_review_sha256",
                ),
            }
            for name in specialized_digests.get(str(identifier), ()):
                if not _digest(str(execution.get(name) or "")):
                    gaps.append(f"{identifier} execution {name} is missing or invalid")
            if identifier == "biometric-performance-pad":
                if execution.get("threshold_locked_before_test") is not True:
                    gaps.append(
                        "biometric decision threshold was not locked before test"
                    )
                if execution.get("consent_and_privacy_validated") is not True:
                    gaps.append(
                        "biometric consent and privacy governance is not validated"
                    )
                if execution.get("operator_blinded") is not True:
                    gaps.append("biometric evaluation operator is not blinded")
            if identifier == "interlaboratory-proficiency-testing":
                if execution.get("assigned_values_sequestered") is not True:
                    gaps.append("proficiency assigned values were not sequestered")
                if execution.get("participants_blinded") is not True:
                    gaps.append("proficiency participants were not blinded")
                if execution.get("collusion_controls_validated") is not True:
                    gaps.append("proficiency collusion controls are not validated")
    if isinstance(contract, dict):
        repetitions = value.get("execution_context", {}).get("repetitions")
        minimum = contract.get("minimum_repetitions")
        if (
            isinstance(minimum, int)
            and minimum > 1
            and (
                isinstance(repetitions, bool)
                or not isinstance(repetitions, int)
                or repetitions < minimum
            )
        ):
            gaps.append(f"benchmark repetitions are below required minimum {minimum}")
    return gaps


def _meets_thresholds(metrics: dict[str, Any], thresholds: dict[str, Any]) -> bool:
    return (
        all(
            isinstance(metrics.get(name), (int, float))
            and float(metrics[name]) >= float(thresholds[threshold])
            for name, threshold in (
                ("precision", "minimum_precision"),
                ("recall", "minimum_recall"),
                ("f1", "minimum_f1"),
            )
        )
        and isinstance(metrics.get("false_positive_rate"), (int, float))
        and float(metrics["false_positive_rate"])
        <= float(thresholds["maximum_false_positive_rate"])
    )


def _benchmark_gaps(
    value: object,
    valid: bool,
    metrics: dict[str, Any],
    thresholds: dict[str, Any],
    protocol: str = "classification",
    protocol_metrics: object = None,
) -> list[str]:
    if not isinstance(value, dict):
        return ["benchmark evidence is missing"]
    if not valid:
        return [
            "benchmark evidence lacks approved corpus authority, replay protection, or digest binding"
        ]
    if protocol != "classification":
        gaps = []
        if not _protocol_metrics_valid(protocol, protocol_metrics):
            gaps.append(f"{protocol} protocol metrics are invalid")
        if not _protocol_acceptance(value):
            gaps.append(
                "protocol-specific acceptance criteria are missing, unapproved, or unmet"
            )
        if thresholds and not _meets_protocol_thresholds(protocol_metrics, thresholds):
            gaps.append("protocol metrics do not meet the declared thresholds")
        return gaps
    gaps = []
    for metric, threshold, direction in (
        ("precision", "minimum_precision", "minimum"),
        ("recall", "minimum_recall", "minimum"),
        ("f1", "minimum_f1", "minimum"),
        ("false_positive_rate", "maximum_false_positive_rate", "maximum"),
    ):
        observed = metrics.get(metric)
        limit = thresholds[threshold]
        if (
            not isinstance(observed, (int, float))
            or (direction == "minimum" and observed < limit)
            or (direction == "maximum" and observed > limit)
        ):
            gaps.append(f"{metric} does not meet {threshold}={limit}")
    return gaps


def _aggregate_metrics(rows: list[dict[str, Any]]) -> dict[str, float | None]:
    result: dict[str, float | None] = {}
    for name in (
        "precision",
        "recall",
        "specificity",
        "f1",
        "mcc",
        "balanced_accuracy",
        "false_positive_rate",
        "youden_j",
    ):
        values = [
            float(row["metrics"][name])
            for row in rows
            if row["evidence_valid"]
            and isinstance(row["metrics"].get(name), (int, float))
        ]
        result[name] = round(sum(values) / len(values), 6) if values else None
    return result


def _benchmark_delta(
    target: Path, policy: dict[str, Any], scorecard: dict[str, Any], errors: list[str]
) -> dict[str, Any]:
    path_value = policy.get("benchmark_baseline_path")
    baseline: dict[str, Any] | None = None
    if path_value:
        try:
            path = target / str(path_value)
            _, payload = read_regular_file(
                path,
                "benchmark baseline",
                maximum_bytes=_MAX_POLICY_BYTES,
                boundary=target,
            )
            loaded = strict_loads(payload)
            if (
                not isinstance(loaded, dict)
                or loaded.get("analysis") != "industry-benchmark-scorecard"
            ):
                raise ValueError("invalid benchmark baseline")
            baseline = loaded
        except (OSError, TypeError, ValueError) as exc:
            errors.append(f"{path_value}: {type(exc).__name__}")
    current = scorecard["aggregate_metrics"]
    previous = baseline.get("aggregate_metrics", {}) if baseline else {}
    deltas = {
        name: round(float(current[name]) - float(previous[name]), 6)
        if isinstance(current.get(name), (int, float))
        and isinstance(previous.get(name), (int, float))
        else None
        for name in current
    }
    regressions = [
        name
        for name, value in deltas.items()
        if isinstance(value, float)
        and (
            (name == "false_positive_rate" and value > 0)
            or (name != "false_positive_rate" and value < 0)
        )
    ]
    current_protocol = {
        str(row["benchmark_id"]): {
            str(name): float(value)
            for name, value in row.get("protocol_metrics", {}).items()
            if _finite_number(value)
        }
        for row in scorecard.get("benchmarks", [])
        if isinstance(row, dict) and row.get("benchmark_protocol") != "classification"
    }
    baseline_protocol = {
        str(row["benchmark_id"]): {
            str(name): float(value)
            for name, value in row.get("protocol_metrics", {}).items()
            if _finite_number(value)
        }
        for row in (baseline.get("benchmarks", []) if baseline else [])
        if isinstance(row, dict) and row.get("benchmark_protocol") != "classification"
    }
    protocol_metric_deltas = {
        identifier: {
            name: round(value - baseline_protocol[identifier][name], 6)
            if identifier in baseline_protocol and name in baseline_protocol[identifier]
            else None
            for name, value in metrics.items()
        }
        for identifier, metrics in current_protocol.items()
    }
    baseline_pass = {
        str(row.get("benchmark_id")): row.get("passed") is True
        for row in (baseline.get("benchmarks", []) if baseline else [])
        if isinstance(row, dict)
    }
    current_pass = {
        str(row.get("benchmark_id")): row.get("passed") is True
        for row in scorecard.get("benchmarks", [])
        if isinstance(row, dict)
    }
    protocol_regressions = sorted(
        identifier
        for identifier, passed in current_pass.items()
        if baseline_pass.get(identifier) is True and not passed
    )
    return {
        "schema_version": "1.0",
        "analysis": "industry-benchmark-delta",
        "baseline_present": baseline is not None,
        "comparable": baseline is not None
        and baseline.get("benchmark_scope") == scorecard.get("benchmark_scope"),
        "current_metrics": current,
        "baseline_metrics": previous,
        "metric_deltas": deltas,
        "regressions": regressions,
        "current_protocol_metrics": current_protocol,
        "baseline_protocol_metrics": baseline_protocol,
        "protocol_metric_deltas": protocol_metric_deltas,
        "protocol_regressions": protocol_regressions,
        "claim_boundary": "A delta is comparable only for the same benchmark families and pinned corpus digests.",
    }


def _oscal_documents(
    assessment: dict[str, Any], procedures: dict[str, Any], source_sha256: str
) -> dict[str, dict[str, Any]]:
    identity = uuid.uuid5(
        uuid.NAMESPACE_URL, f"pysec:{source_sha256 or 'unknown'}:industry-assessment"
    )
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    metadata = {
        "title": "Python Security Suite industry assurance package",
        "last-modified": now,
        "version": "1.0",
        "oscal-version": "1.2.2",
    }
    controls = [
        {
            "standard": item["standard"],
            "control_id": item["control_id"],
            "objective": item["objective"],
            "status": item["status"],
            "evidence_present": item["evidence_present"],
            "gaps": item["gaps"],
        }
        for item in assessment["controls"]
    ]
    controls.extend(
        {
            "standard": item["standard"],
            "control_id": item["procedure_id"],
            "objective": item["objective"],
            "status": item["status"],
            "evidence_present": item["evidence_present"],
            "gaps": item["gaps"],
        }
        for item in procedures["procedures"]
    )
    if not controls:
        controls.append(
            {
                "standard": "PYSEC",
                "control_id": "assurance-package",
                "objective": (
                    "Describe the suite assurance component and its repository-scoped "
                    "assessment boundary without asserting an external control outcome."
                ),
                "status": "satisfied",
                "evidence_present": [],
                "gaps": [],
            }
        )
    oscal_ids = {
        (item["standard"], item["control_id"]): _oscal_control_id(
            item["standard"], item["control_id"]
        )
        for item in controls
    }
    catalog = {
        "catalog": {
            "uuid": str(uuid.uuid5(identity, "catalog")),
            "metadata": {**metadata, "title": "Repository assurance control catalog"},
            "groups": [
                {
                    "id": "pysec-assurance",
                    "title": "Repository-scoped assurance objectives",
                    "controls": [
                        {
                            "id": oscal_ids[(item["standard"], item["control_id"])],
                            "title": f"{item['standard']} {item['control_id']}",
                            "props": [
                                {
                                    "name": "source-standard",
                                    "value": item["standard"],
                                },
                                {
                                    "name": "source-control-id",
                                    "value": item["control_id"],
                                },
                            ],
                            "parts": [
                                {
                                    "id": oscal_ids[
                                        (item["standard"], item["control_id"])
                                    ]
                                    + "-statement",
                                    "name": "statement",
                                    "prose": item["objective"],
                                }
                            ],
                        }
                        for item in controls
                    ],
                }
            ],
        }
    }
    profile = {
        "profile": {
            "uuid": str(uuid.uuid5(identity, "profile")),
            "metadata": {**metadata, "title": "Repository assurance profile"},
            "imports": [{"href": "oscal-catalog.json", "include-all": {}}],
            "merge": {"as-is": True},
        }
    }
    implemented = []
    for item in controls:
        implementation = {
            "uuid": str(
                uuid.uuid5(
                    identity, f"implemented:{item['standard']}:{item['control_id']}"
                )
            ),
            "control-id": oscal_ids[(item["standard"], item["control_id"])],
            "description": item["objective"],
            "props": [{"name": "assessment-status", "value": item["status"]}],
        }
        if item["evidence_present"]:
            implementation["links"] = [
                {"href": name, "rel": "evidence"} for name in item["evidence_present"]
            ]
        implemented.append(implementation)
    component = {
        "component-definition": {
            "uuid": str(uuid.uuid5(identity, "component-definition")),
            "metadata": {**metadata, "title": "Suite component definition"},
            "components": [
                {
                    "uuid": str(uuid.uuid5(identity, "component")),
                    "type": "software",
                    "title": "Python Security Suite",
                    "description": "Repository-scoped security and quality assurance evidence producer.",
                    "control-implementations": [
                        {
                            "uuid": str(uuid.uuid5(identity, "control-implementation")),
                            "source": "oscal-profile.json",
                            "description": "Evidence-backed implementation statements.",
                            "implemented-requirements": implemented,
                        }
                    ],
                }
            ],
        }
    }
    ssp_implemented = [
        {name: value for name, value in item.items() if name != "description"}
        for item in implemented
    ]
    system_id = source_sha256 or str(identity)
    ssp = {
        "system-security-plan": {
            "uuid": str(uuid.uuid5(identity, "ssp")),
            "metadata": {**metadata, "title": "Repository system security plan"},
            "import-profile": {"href": "oscal-profile.json"},
            "system-characteristics": {
                "system-ids": [
                    {
                        "identifier-type": "urn:project-py-security-suite:source-sha256",
                        "id": system_id,
                    }
                ],
                "system-name": "Scanned repository",
                "description": "The digest-bound repository and retained assurance evidence.",
                "security-sensitivity-level": "moderate",
                "system-information": {
                    "information-types": [
                        {
                            "uuid": str(uuid.uuid5(identity, "information-type")),
                            "title": "Repository assurance evidence",
                            "description": (
                                "Source, scanner, benchmark, and governance evidence "
                                "bound to the assessed repository digest."
                            ),
                        }
                    ]
                },
                "security-impact-level": {
                    "security-objective-confidentiality": "moderate",
                    "security-objective-integrity": "moderate",
                    "security-objective-availability": "moderate",
                },
                "status": {"state": "operational"},
                "authorization-boundary": {
                    "description": "Limited to the source digest and named evidence artifacts."
                },
            },
            "system-implementation": {
                "components": [
                    {
                        "uuid": str(uuid.uuid5(identity, "system-component")),
                        "type": "software",
                        "title": "Python Security Suite",
                        "description": "Assurance evidence producer.",
                        "status": {"state": "operational"},
                    }
                ],
            },
            "control-implementation": {
                "description": "Repository-owned implementations and evidence mappings.",
                "implemented-requirements": ssp_implemented,
            },
        }
    }
    reviewed_controls = {
        "control-selections": [
            {
                "description": "Policy-declared controls and procedures",
                "include-controls": [
                    {"control-id": oscal_ids[(item["standard"], item["control_id"])]}
                    for item in controls
                ],
            }
        ]
    }
    assessment_plan = {
        "assessment-plan": {
            "uuid": str(uuid.uuid5(identity, "assessment-plan")),
            "metadata": {**metadata, "title": "Repository assurance assessment plan"},
            "import-ssp": {"href": "oscal-system-security-plan.json"},
            "reviewed-controls": reviewed_controls,
            "assessment-subjects": [
                {
                    "type": "component",
                    "include-subjects": [
                        {
                            "subject-uuid": str(
                                uuid.uuid5(identity, "system-component")
                            ),
                            "type": "component",
                        }
                    ],
                }
            ],
        }
    }
    findings = []
    observations = []
    for index, control in enumerate(controls):
        observation_uuid = str(
            uuid.uuid5(
                identity,
                f"observation:{index}:{control['standard']}:{control['control_id']}",
            )
        )
        observation = {
            "uuid": observation_uuid,
            "title": control["objective"],
            "description": "; ".join(control["evidence_present"])
            or "No retained evidence",
            "methods": ["EXAMINE"],
            "collected": now,
        }
        if control["evidence_present"]:
            observation["relevant-evidence"] = [
                {"description": name, "href": name}
                for name in control["evidence_present"]
            ]
        observations.append(observation)
        if control["status"] not in {"satisfied", "not-applicable"}:
            findings.append(
                {
                    "uuid": str(uuid.uuid5(identity, f"finding:{index}")),
                    "title": f"{control['standard']} {control['control_id']} evidence gap",
                    "description": "; ".join(control["gaps"]),
                    "target": {
                        "type": "objective-id",
                        "target-id": oscal_ids[
                            (control["standard"], control["control_id"])
                        ],
                        "status": {"state": "not-satisfied"},
                    },
                    "related-observations": [{"observation-uuid": observation_uuid}],
                }
            )
    result_record = {
        "uuid": str(uuid.uuid5(identity, "result")),
        "title": "Evidence-backed industry standards assessment",
        "description": assessment["claim_boundary"],
        "start": now,
        "reviewed-controls": reviewed_controls,
        "observations": observations,
    }
    if findings:
        result_record["findings"] = findings
    results = {
        "assessment-results": {
            "uuid": str(identity),
            "metadata": {
                **metadata,
                "title": "Repository assurance assessment results",
            },
            "import-ap": {"href": "oscal-assessment-plan.json"},
            "results": [result_record],
        }
    }
    poam_items = [
        {
            "uuid": str(
                uuid.uuid5(identity, f"poam:{item['standard']}:{item['control_id']}")
            ),
            "title": f"Resolve {item['standard']} {item['control_id']} assurance gap",
            "description": "; ".join(item["gaps"]),
            "related-observations": [
                {
                    "observation-uuid": str(
                        uuid.uuid5(
                            identity,
                            f"observation:{index}:{item['standard']}:{item['control_id']}",
                        )
                    )
                }
            ],
        }
        for index, item in enumerate(controls)
        if item["status"] not in {"satisfied", "not-applicable"}
    ]
    if not poam_items:
        poam_items.append(
            {
                "uuid": str(uuid.uuid5(identity, "poam:continuous-reassessment")),
                "title": "Maintain repository assurance evidence",
                "description": (
                    "Reassess the digest-bound repository when its source, policy, "
                    "scanner portfolio, or governed benchmark corpus changes."
                ),
                "props": [
                    {
                        "name": "item-kind",
                        "value": "continuous-reassessment",
                    }
                ],
            }
        )
    poam: dict[str, Any] = {
        "plan-of-action-and-milestones": {
            "uuid": str(uuid.uuid5(identity, "poam")),
            "metadata": {**metadata, "title": "Repository assurance POA&M"},
            "import-ssp": {"href": "oscal-system-security-plan.json"},
            "system-id": {
                "identifier-type": "urn:project-py-security-suite:source-sha256",
                "id": system_id,
            },
        }
    }
    poam["plan-of-action-and-milestones"]["poam-items"] = poam_items
    return {
        "oscal-catalog.json": catalog,
        "oscal-profile.json": profile,
        "oscal-component-definition.json": component,
        "oscal-system-security-plan.json": ssp,
        "oscal-assessment-plan.json": assessment_plan,
        "oscal-assessment-results.json": results,
        "oscal-poam.json": poam,
    }


def _oscal_control_id(standard: str, control_id: str) -> str:
    raw = f"{standard}-{control_id}".casefold()
    normalized = "".join(character if character.isalnum() else "-" for character in raw)
    normalized = "-".join(part for part in normalized.split("-") if part)
    digest = uuid.uuid5(uuid.NAMESPACE_URL, f"{standard}:{control_id}").hex[:10]
    return f"{normalized[:100]}-{digest}"


def _interoperability(artifacts: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    intelligence = artifacts.get("risk-intelligence.json")
    vex_formats = (
        set(intelligence.get("vex_formats", []))
        if isinstance(intelligence, dict)
        and isinstance(intelligence.get("vex_formats"), list)
        else set()
    )
    vex_versions = (
        intelligence.get("vex_versions", {})
        if isinstance(intelligence, dict)
        and isinstance(intelligence.get("vex_versions"), dict)
        else {}
    )
    automation = artifacts.get("security-automation-interoperability.json")
    protocol_rows = (
        automation.get("protocols", [])
        if isinstance(automation, dict)
        and isinstance(automation.get("protocols"), list)
        else []
    )
    protocol_index = {
        str(item.get("id")): item for item in protocol_rows if isinstance(item, dict)
    }
    interoperability_protocol_ids = {
        "STIX": "OASIS-STIX",
        "TAXII": "OASIS-TAXII",
        "CACAO": "OASIS-CACAO",
        "OpenC2": "OASIS-OPENC2",
        "OCSF": "OCSF",
        "SCITT": "IETF-RFC-9943",
        "COSE-Receipts": "IETF-RFC-9942",
        "OpenAPI": "OPENAPI-SPECIFICATION",
        "AsyncAPI": "ASYNCAPI-SPECIFICATION",
        "GraphQL": "GRAPHQL-SPECIFICATION",
        "JSON-Schema": "JSON-SCHEMA",
        "OpenTelemetry-SemConv": "OPENTELEMETRY-SEMCONV",
    }
    for name, version, evidence in _INTEROPERABILITY:
        present = any(item in artifacts for item in evidence)
        observed_versions: list[str] = []
        if name == "CycloneDX":
            observed_versions = sorted(
                {
                    str(value.get("specVersion"))
                    for artifact_name in evidence
                    if isinstance((value := artifacts.get(artifact_name)), dict)
                    and value.get("specVersion")
                }
            )
            present = version in observed_versions
        if name in {"CycloneDX-VEX", "OpenVEX", "CSAF-VEX"}:
            format_name = name.casefold().replace("-vex", "")
            versions = vex_versions.get(format_name, [])
            observed_versions = (
                sorted(str(item) for item in versions)
                if isinstance(versions, list)
                else []
            )
            present = format_name in vex_formats and version in observed_versions
        if name == "OSCAL":
            document = artifacts.get("oscal-assessment-results.json")
            root = (
                document.get("assessment-results")
                if isinstance(document, dict)
                else None
            )
            metadata = root.get("metadata") if isinstance(root, dict) else None
            observed = (
                metadata.get("oscal-version") if isinstance(metadata, dict) else None
            )
            observed_versions = [str(observed)] if observed else []
            present = version in observed_versions
        protocol_id = interoperability_protocol_ids.get(name)
        if protocol_id:
            protocol = protocol_index.get(protocol_id)
            observed = protocol.get("version") if isinstance(protocol, dict) else None
            observed_versions = [str(observed)] if observed else []
            present = bool(
                isinstance(protocol, dict) and protocol.get("complete") is True
            )
        rows.append(
            {
                "format": name,
                "version": version,
                "status": "supported" if present else "not-observed",
                "observed_versions": observed_versions,
                "evidence_artifacts": list(evidence),
            }
        )
    return rows


def _source_sha256(artifacts: dict[str, Any]) -> str:
    value = artifacts.get("source-inventory.json")
    digest = str(value.get("source_sha256") or "") if isinstance(value, dict) else ""
    return digest if _digest(digest) else ""


def _complete_artifact(value: object) -> bool:
    return isinstance(value, dict) and value.get("complete") is not False


def _artifact_name(value: object) -> bool:
    return (
        _text(value, 200)
        and Path(str(value)).name == str(value)
        and str(value).endswith(".json")
    )


def _safe_relative(value: object) -> bool:
    if not _text(value, 500):
        return False
    path = Path(str(value))
    return not path.is_absolute() and ".." not in path.parts


def _digest(value: str) -> bool:
    return len(value) == 64 and all(character in _DIGEST for character in value)


def _ratio(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and 0 <= float(value) <= 1
    )


def _iso_timestamp(value: object) -> bool:
    if not _text(value, 100):
        return False
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _text(value: object, maximum: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum
