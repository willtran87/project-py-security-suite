"""Secret provenance assessments and secret/exposure route intersections."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .risk_path_values import _object, _strings
from .models import Citation, Finding, FindingStatus
from .risk_path_common import (
    _MAX_ROUTE_HOPS,
    _MAX_SENSITIVE_ROUTE_CITATIONS,
    _RISK_PATH_REFERENCE,
    _citation_records,
    _digest,
    _objects,
    _optional_boolean,
    _optional_string,
    _ordered_strings,
    _priority_rank,
)


__all__ = [
    "_attach_secret_exposure_advisory_intersections",
    "_attach_secret_exposure_intersections",
    "_attach_secret_provenance",
    "_secret_exposure_advisory_intersections",
    "_secret_exposure_intersections",
    "_secret_finding_count",
    "_secret_provenance_assessments",
]


_MAX_CONTEXT_SECRET_EXPOSURE_INTERSECTIONS = 25


_MAX_CONTEXT_SECRET_EXPOSURE_ADVISORY_INTERSECTIONS = 25


_SECRET_AREAS = frozenset({"secrets", "secrets-history"})


def _secret_provenance_assessments(
    findings: list[Finding],
    targets: list[dict[str, Any]],
    routed_target_ids: set[str],
) -> list[dict[str, Any]]:
    """Join redacted secret candidates to content, history, and assurance lanes."""
    targets_by_finding = {
        str(target["finding_id"]): target
        for target in targets
        if target.get("kind") == "finding" and target.get("finding_id")
    }
    result: list[dict[str, Any]] = []
    for finding in findings:
        if not _is_secret_finding(finding):
            continue
        target = targets_by_finding.get(finding.finding_id)
        if target is None:
            continue
        applicability = _object(target.get("route_applicability"))
        assurance = _object(target.get("evidence_assurance"))
        lifecycle = _object(target.get("change_lifecycle_attribution"))
        content_lane = str(
            applicability.get("classification") or "outside-python-runtime-model"
        )
        tools = sorted({source.tool for source in finding.sources})[:25]
        rules = sorted({source.rule_id for source in finding.sources})[:50]
        verification_status = _secret_verification_status(finding)
        history_status = _secret_history_status(finding, tools)
        redacted = finding.evidence.get("redacted") is True
        disposition = _secret_review_disposition(content_lane)
        record = {
            "secret_context_id": "secret-context-"
            + _digest(
                {
                    "finding_id": finding.finding_id,
                    "path": target["path"],
                    "line": target.get("line"),
                    "content_lane": content_lane,
                }
            )[:16],
            "finding_id": finding.finding_id,
            "priority": target["priority"],
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "path": target["path"],
            "line": target.get("line"),
            "label": target["label"],
            "content_lane": content_lane,
            "review_disposition": disposition,
            "route_status": (
                "routed" if str(target["id"]) in routed_target_ids else "unrouted"
            ),
            "route_assessment": str(
                applicability.get("assessment") or "not-route-applicable"
            ),
            "source_inventory_available": bool(
                applicability.get("source_inventory_available")
            ),
            "source_inventory_member": _optional_boolean(
                applicability.get("source_inventory_member")
            ),
            "graph_available": bool(applicability.get("graph_available")),
            "graph_path_member": _optional_boolean(
                applicability.get("graph_path_member")
            ),
            "artifact_manifest_available": bool(
                applicability.get("artifact_manifest_available")
            ),
            "artifact_manifest_member": _optional_boolean(
                applicability.get("artifact_manifest_member")
            ),
            "redacted": redacted,
            "verification_status": verification_status,
            "history_status": history_status,
            "history_commit": _secret_history_commit(finding),
            "scanner_tools": tools,
            "scanner_rules": rules,
            "independent_scanner_count": len(tools),
            "scanner_perspective": (
                "multi-scanner" if len(tools) > 1 else "single-scanner"
            ),
            "evidence_assurance_status": str(
                assurance.get("review_status") or "not-assessed"
            ),
            "lifecycle_status": str(
                lifecycle.get("lifecycle_status") or finding.status.value
            ),
            "change_scope": str(lifecycle.get("change_scope") or "not-established"),
            "owners": _strings(target.get("owners"), 100),
            "classifications": _strings(target.get("classifications"), 50),
            "secret_exposure_intersection_ids": [],
            "secret_exposure_intersections": [],
            "secret_exposure_intersections_omitted": 0,  # nosec B105
            "citations": _citation_records(
                finding.citations,
                limit=_MAX_SENSITIVE_ROUTE_CITATIONS,
                default_kind="reference",
            ),
            "evidence_artifacts": sorted(
                {
                    "findings.json",
                    "risk-paths.json",
                    *_strings(applicability.get("evidence_artifacts"), 10),
                    *_strings(assurance.get("evidence_artifacts"), 10),
                    *_strings(lifecycle.get("evidence_artifacts"), 10),
                }
            ),
            "recommended_action": _secret_provenance_action(
                content_lane=content_lane,
                verification_status=verification_status,
                history_status=history_status,
                redacted=redacted,
            ),
        }
        result.append(record)
    return sorted(
        result,
        key=lambda item: (
            _priority_rank(str(item["priority"])),
            0 if item["verification_status"] == "verified" else 1,
            str(item["path"]),
            int(item["line"] or 0),
            str(item["secret_context_id"]),
        ),
    )


def _secret_exposure_intersections(
    secret_assessments: list[dict[str, Any]],
    sensitive_routes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Join production secret candidates to exact sink or bounded route files."""
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for secret in secret_assessments:
        if secret.get("content_lane") != "python-runtime-source":
            continue
        secret_path = str(secret.get("path") or "")
        if not secret_path:
            continue
        for sensitive in sensitive_routes:
            route_files = _ordered_strings(
                sensitive.get("route_files"), _MAX_ROUTE_HOPS + 1
            )
            sink_path = str(sensitive.get("path") or "")
            if secret_path == sink_path:
                association_kind = "exact-path"
            elif secret_path in route_files:
                association_kind = "upstream-route"
            else:
                continue
            pair = (
                str(secret.get("secret_context_id") or ""),
                str(sensitive.get("sensitive_route_id") or ""),
            )
            if not all(pair) or pair in seen:
                continue
            seen.add(pair)
            secret_route_index = max(
                index for index, path in enumerate(route_files) if path == secret_path
            )
            distance_to_sink = max(0, len(route_files) - 1 - secret_route_index)
            temporal_alignment = _secret_route_temporal_alignment(
                str(secret.get("history_status") or "not-established")
            )
            candidate_assurance = str(
                secret.get("evidence_assurance_status") or "not-assessed"
            )
            sensitive_assurance = str(
                sensitive.get("evidence_assurance_status") or "not-assessed"
            )
            validation_handoff = _object(sensitive.get("validation_handoff"))
            combined_assurance_prerequisite_met = (
                candidate_assurance == "assured"
                and sensitive_assurance == "assured"
                and validation_handoff.get("campaign_assurance_prerequisite_met")
                is True
            )
            protection_status = str(sensitive.get("protection_status") or "unknown")
            risk_factors = [
                (
                    "exact-file-secret-and-sensitive-sink"
                    if association_kind == "exact-path"
                    else "secret-on-bounded-route-to-sensitive-sink"
                )
            ]
            if secret.get("verification_status") == "verified":
                risk_factors.append("scanner-verified-secret-candidate")
            if temporal_alignment == "history-to-current-route":
                risk_factors.append("history-current-route-revision-gap")
            if protection_status in {"not-observed", "none", "unknown"}:
                risk_factors.append("sink-protection-not-observed")
            if sensitive.get("evidence_basis") == "scanner-confirmed-source-to-sink":
                risk_factors.append("scanner-confirmed-sensitive-data-concern")
            if candidate_assurance != "assured" or sensitive_assurance != "assured":
                risk_factors.append("contributing-evidence-assurance-gap")
            finding_ids = sorted(
                {
                    str(secret["finding_id"]),
                    *(
                        [str(sensitive["finding_id"])]
                        if sensitive.get("finding_id")
                        else []
                    ),
                }
            )
            owners = sorted(
                {
                    *_strings(secret.get("owners"), 100),
                    *_strings(sensitive.get("owners"), 100),
                }
            )[:100]
            citations = _citation_records(
                [
                    *_objects(secret.get("citations"), 10),
                    *_objects(sensitive.get("citations"), 10),
                ],
                limit=20,
                default_kind="reference",
            )
            priority = sorted(
                [str(secret.get("priority") or "P4"), str(sensitive["priority"])],
                key=_priority_rank,
            )[0]
            intersection_id = (
                "secret-exposure-"
                + _digest(
                    {
                        "secret_context_id": pair[0],
                        "sensitive_route_id": pair[1],
                        "association_kind": association_kind,
                    }
                )[:16]
            )
            action = _secret_exposure_action(
                association_kind=association_kind,
                temporal_alignment=temporal_alignment,
                verification_status=str(
                    secret.get("verification_status") or "not-established"
                ),
                protection_status=protection_status,
            )
            handoff_action = str(validation_handoff.get("recommended_action") or "")
            if handoff_action:
                action = (action + " " + handoff_action)[:2000]
            validation_gap_reasons = _strings(validation_handoff.get("gap_reasons"), 20)
            if candidate_assurance != "assured":
                validation_gap_reasons.append(
                    "Secret-candidate scanner evidence is not fully assured."
                )
            if sensitive_assurance != "assured":
                validation_gap_reasons.append(
                    "Sensitive-sink scanner evidence is not fully assured."
                )
            if temporal_alignment != "aligned-current-tree":
                validation_gap_reasons.append(
                    "Secret and sink evidence require current-revision alignment."
                )
            result.append(
                {
                    "intersection_id": intersection_id,
                    "priority": priority,
                    "association_kind": association_kind,
                    "temporal_alignment": temporal_alignment,
                    "secret_context_id": pair[0],
                    "secret_finding_id": str(secret["finding_id"]),
                    "secret_path": secret_path,
                    "secret_line": secret.get("line"),
                    "secret_verification_status": str(
                        secret.get("verification_status") or "not-established"
                    ),
                    "secret_history_status": str(
                        secret.get("history_status") or "not-established"
                    ),
                    "secret_scanner_tools": _strings(secret.get("scanner_tools"), 25),
                    "secret_assurance_status": candidate_assurance,
                    "sensitive_route_id": pair[1],
                    "route_id": str(sensitive["route_id"]),
                    "sensitive_finding_id": _optional_string(
                        sensitive.get("finding_id")
                    ),
                    "sink_path": sink_path,
                    "sink_line": sensitive.get("line"),
                    "sink_family": str(sensitive.get("sink_family") or "unknown"),
                    "sink": _optional_string(sensitive.get("sink")),
                    "sdk": _optional_string(sensitive.get("sdk")),
                    "trust_boundary": str(sensitive.get("trust_boundary") or "unknown"),
                    "protection_status": protection_status,
                    "data_classes": _strings(sensitive.get("data_classes"), 25),
                    "sensitive_evidence_basis": str(sensitive["evidence_basis"]),
                    "sensitive_source_tools": _strings(
                        sensitive.get("source_tools"), 25
                    ),
                    "sensitive_assurance_status": sensitive_assurance,
                    "validation_status": str(
                        sensitive.get("validation_status") or "not-assessed"
                    ),
                    "validation_handoff": validation_handoff,
                    "combined_assurance_prerequisite_met": combined_assurance_prerequisite_met,
                    "canary_validation_status": "not-established",
                    "recommended_test_files": _strings(
                        validation_handoff.get("candidate_test_files"), 50
                    ),
                    "intersection_validation_gap_reasons": validation_gap_reasons[:25],
                    "route_files": route_files,
                    "secret_route_index": secret_route_index,
                    "distance_to_sink": distance_to_sink,
                    "entry_point_ids": _strings(sensitive.get("entry_point_ids"), 100),
                    "entry_point_runtime_statuses": _object(
                        sensitive.get("entry_point_runtime_statuses")
                    ),
                    "owners": owners,
                    "ownership_coordination_status": (
                        "unassigned"
                        if not owners
                        else "single-owner"
                        if len(owners) == 1
                        else "cross-owner"
                    ),
                    "finding_ids": finding_ids,
                    "risk_factors": risk_factors,
                    "citations": citations,
                    "evidence_artifacts": sorted(
                        {
                            "findings.json",
                            "data-exposure.json",
                            "graphify.json",
                            "risk-paths.json",
                            *_strings(secret.get("evidence_artifacts"), 25),
                            *_strings(sensitive.get("evidence_artifacts"), 25),
                        }
                    ),
                    "recommended_action": action,
                    "interpretation": (
                        "Static file-route co-location only; this record does not prove "
                        "that the redacted candidate is a credential, that a symbol or "
                        "value flows to the sink, that the route executes, or that a "
                        "disclosure occurred."
                    ),
                }
            )
    return sorted(
        result,
        key=lambda item: (
            _priority_rank(str(item["priority"])),
            0 if item["association_kind"] == "exact-path" else 1,
            int(item["distance_to_sink"]),
            str(item["secret_path"]),
            str(item["sink_path"]),
            str(item["intersection_id"]),
        ),
    )


def _secret_route_temporal_alignment(history_status: str) -> str:
    if history_status == "current-tree":
        return "aligned-current-tree"
    if history_status == "history-evidence":
        return "history-to-current-route"
    return "not-established"


def _secret_exposure_action(
    *,
    association_kind: str,
    temporal_alignment: str,
    verification_status: str,
    protection_status: str,
) -> str:
    relationship = (
        "the exact source file containing both the redacted candidate and sink"
        if association_kind == "exact-path"
        else "the bounded Graphify file route from the candidate file to the sink"
    )
    result = (
        f"Review {relationship} in a protected workspace. Trace the actual symbol-level "
        "flow, confirm credential validity and ownership without copying the value, "
        "and add a synthetic-canary test proving secrets are minimized or redacted "
        "before the cited boundary."
    )
    if verification_status == "verified":
        result += " Revoke and rotate the verified candidate while confirming scope."
    if temporal_alignment == "history-to-current-route":
        result += (
            " Establish revision alignment before relating the historical candidate "
            "to the current sink route, and review reachable history if it was real."
        )
    if protection_status in {"not-observed", "none", "unknown"}:
        result += " Implement or document an effective pre-sink protection control."
    return result[:2000]


def _compact_secret_exposure_intersection(
    value: dict[str, Any],
) -> dict[str, Any]:
    keys = (
        "intersection_id",
        "priority",
        "association_kind",
        "temporal_alignment",
        "secret_context_id",
        "secret_finding_id",
        "secret_path",
        "secret_line",
        "secret_verification_status",
        "secret_assurance_status",
        "sensitive_route_id",
        "route_id",
        "sensitive_finding_id",
        "sink_path",
        "sink_line",
        "sink_family",
        "sink",
        "sdk",
        "trust_boundary",
        "protection_status",
        "sensitive_evidence_basis",
        "sensitive_assurance_status",
        "validation_status",
        "validation_handoff",
        "combined_assurance_prerequisite_met",
        "canary_validation_status",
        "recommended_test_files",
        "intersection_validation_gap_reasons",
        "secret_exposure_advisory_intersection_ids",
        "secret_exposure_advisory_intersections",
        "secret_exposure_advisory_intersections_omitted",
        "distance_to_sink",
        "owners",
        "finding_ids",
        "risk_factors",
        "citations",
        "evidence_artifacts",
        "recommended_action",
        "interpretation",
    )
    return {key: value[key] for key in keys}


def _attach_secret_exposure_intersections(
    secret_assessments: list[dict[str, Any]],
    sensitive_routes: list[dict[str, Any]],
    intersections: list[dict[str, Any]],
) -> None:
    by_secret: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_sensitive: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for intersection in intersections:
        by_secret[str(intersection["secret_context_id"])].append(intersection)
        by_sensitive[str(intersection["sensitive_route_id"])].append(intersection)
    for records, key_name, index in (
        (secret_assessments, "secret_context_id", by_secret),
        (sensitive_routes, "sensitive_route_id", by_sensitive),
    ):
        for record in records:
            matches = index.get(str(record[key_name]), [])
            record["secret_exposure_intersection_ids"] = [
                str(item["intersection_id"]) for item in matches
            ]
            record["secret_exposure_intersections"] = [
                _compact_secret_exposure_intersection(item)
                for item in matches[:_MAX_CONTEXT_SECRET_EXPOSURE_INTERSECTIONS]
            ]
            record["secret_exposure_intersections_omitted"] = max(
                0, len(matches) - _MAX_CONTEXT_SECRET_EXPOSURE_INTERSECTIONS
            )


def _secret_exposure_advisory_intersections(
    secret_intersections: list[dict[str, Any]],
    advisory_intersections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Join secret/sink and sink/advisory evidence at the identical sink route."""
    advisories_by_sink_route: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for advisory in advisory_intersections:
        advisories_by_sink_route[str(advisory["sink_route_id"])].append(advisory)
    result: list[dict[str, Any]] = []
    for secret in secret_intersections:
        for advisory in advisories_by_sink_route.get(str(secret["route_id"]), []):
            secret_id = str(secret["intersection_id"])
            advisory_id = str(advisory["intersection_id"])
            intersection_id = (
                "secret-exposure-advisory-"
                + _digest(
                    {
                        "secret_exposure_intersection_id": secret_id,
                        "exposure_advisory_intersection_id": advisory_id,
                        "sink_route_id": secret["route_id"],
                    }
                )[:16]
            )
            validation_handoff = _object(secret.get("validation_handoff"))
            advisory_validation = _object(advisory.get("validation_statuses"))
            advisory_assurance = _object(advisory.get("evidence_assurance_statuses"))
            combined_assurance = (
                secret.get("combined_assurance_prerequisite_met") is True
                and advisory_assurance.get("sink") == "assured"
                and advisory_assurance.get("dependency") == "assured"
            )
            owners = sorted(
                {
                    *_strings(secret.get("owners"), 100),
                    *_strings(advisory.get("owners"), 100),
                }
            )[:100]
            finding_ids = sorted(
                {
                    *_strings(secret.get("finding_ids"), 100),
                    *_strings(advisory.get("finding_ids"), 100),
                }
            )[:100]
            risk_factors = [
                "secret-candidate-and-advisory-at-identical-sensitive-route"
            ]
            if advisory.get("known_exploited") is True:
                risk_factors.append("known-exploited-dependency")
            if advisory.get("epss_high") is True:
                risk_factors.append("high-epss-dependency")
            if advisory.get("fix_available") is True:
                risk_factors.append("dependency-fix-available")
            if secret.get("secret_verification_status") == "verified":
                risk_factors.append("scanner-verified-secret-candidate")
            if secret.get("temporal_alignment") != "aligned-current-tree":
                risk_factors.append("secret-sink-temporal-alignment-gap")
            if secret.get("protection_status") in {
                "not-observed",
                "none",
                "unknown",
            }:
                risk_factors.append("sink-protection-not-observed")
            if not combined_assurance:
                risk_factors.append("combined-evidence-assurance-gap")
            if (
                validation_handoff.get("supporting_evidence_readiness")
                != "supporting-evidence-ready"
            ):
                risk_factors.append("validation-supporting-evidence-gap")
            if secret.get("canary_validation_status") != "established":
                risk_factors.append("synthetic-canary-not-established")
            citations = _citation_records(
                [
                    *_objects(secret.get("citations"), 20),
                    *_objects(advisory.get("advisory_citations"), 25),
                ],
                limit=30,
                default_kind="reference",
            )
            priorities = sorted(
                [str(secret.get("priority") or "P4"), str(advisory["priority"])],
                key=_priority_rank,
            )
            result.append(
                {
                    "intersection_id": intersection_id,
                    "priority": priorities[0],
                    "evidence_basis": "identical-sensitive-route-join",
                    "secret_exposure_intersection_id": secret_id,
                    "exposure_advisory_intersection_id": advisory_id,
                    "secret_context_id": str(secret["secret_context_id"]),
                    "secret_finding_id": str(secret["secret_finding_id"]),
                    "secret_path": str(secret["secret_path"]),
                    "secret_line": secret.get("secret_line"),
                    "secret_verification_status": str(
                        secret["secret_verification_status"]
                    ),
                    "secret_history_status": str(
                        secret.get("secret_history_status") or "not-established"
                    ),
                    "secret_assurance_status": str(secret["secret_assurance_status"]),
                    "secret_sink_association_kind": str(secret["association_kind"]),
                    "secret_distance_to_sink": int(secret["distance_to_sink"]),
                    "temporal_alignment": str(secret["temporal_alignment"]),
                    "sensitive_route_id": str(secret["sensitive_route_id"]),
                    "sink_route_id": str(advisory["sink_route_id"]),
                    "sink_path": str(advisory["path"]),
                    "sink_line": advisory.get("line"),
                    "sink_family": str(advisory["sink_family"]),
                    "sdk": _optional_string(advisory.get("sdk")),
                    "trust_boundary": str(advisory["trust_boundary"]),
                    "protection_status": str(advisory["protection_status"]),
                    "sensitive_evidence_basis": str(secret["sensitive_evidence_basis"]),
                    "sink_assurance_status": str(
                        advisory_assurance.get("sink") or "not-assessed"
                    ),
                    "dependency_route_id": str(advisory["dependency_route_id"]),
                    "advisory_cluster_id": str(advisory["advisory_cluster_id"]),
                    "primary_identifier": str(advisory["primary_identifier"]),
                    "package": str(advisory["package"]),
                    "known_exploited": advisory.get("known_exploited") is True,
                    "epss_high": advisory.get("epss_high") is True,
                    "fix_available": advisory.get("fix_available") is True,
                    "package_lifecycle": _object(advisory.get("package_lifecycle")),
                    "dependency_assurance_status": str(
                        advisory_assurance.get("dependency") or "not-assessed"
                    ),
                    "entry_point_ids": _strings(advisory.get("entry_point_ids"), 100),
                    "entry_point_runtime_statuses": _object(
                        advisory.get("entry_point_runtime_statuses")
                    ),
                    "validation_statuses": {
                        "secret_sink": str(
                            secret.get("validation_status") or "not-assessed"
                        ),
                        "sink": str(advisory_validation.get("sink") or "not-assessed"),
                        "dependency": str(
                            advisory_validation.get("dependency") or "not-assessed"
                        ),
                    },
                    "validation_handoff": validation_handoff,
                    "combined_assurance_prerequisite_met": combined_assurance,
                    "canary_validation_status": str(
                        secret.get("canary_validation_status") or "not-established"
                    ),
                    "recommended_test_files": _strings(
                        secret.get("recommended_test_files"), 50
                    ),
                    "owners": owners,
                    "ownership_coordination_status": (
                        "unassigned"
                        if not owners
                        else "single-owner"
                        if len(owners) == 1
                        else "cross-owner"
                    ),
                    "finding_ids": finding_ids,
                    "risk_factors": risk_factors,
                    "citations": citations,
                    "evidence_artifacts": sorted(
                        {
                            "risk-paths.json",
                            *_strings(secret.get("evidence_artifacts"), 25),
                            *_strings(advisory.get("evidence_artifacts"), 25),
                        }
                    ),
                    "recommended_action": _secret_exposure_advisory_action(
                        secret, advisory, validation_handoff
                    ),
                    "interpretation": (
                        "This record joins two derived ledgers only because they cite "
                        "the identical retained sensitive route. It does not establish "
                        "credential validity, symbol-level value flow, runtime "
                        "disclosure, vulnerable-function execution, or exploitability."
                    ),
                }
            )
    return sorted(
        result,
        key=lambda item: (
            _priority_rank(str(item["priority"])),
            0 if item["known_exploited"] else 1,
            0
            if item["secret_verification_status"] == "verified"  # noqa: S105  # pragma: allowlist secret
            else 1,
            str(item["sink_path"]),
            str(item["intersection_id"]),
        ),
    )


def _secret_exposure_advisory_action(
    secret: dict[str, Any],
    advisory: dict[str, Any],
    validation_handoff: dict[str, Any],
) -> str:
    action = (
        "In a protected workspace, trace the candidate symbol to the cited sink and "
        "establish whether the advisory's vulnerable function can process boundary "
        "data. Add an explicit synthetic credential-canary assertion, verify "
        "pre-sink minimization or masking, apply the retained dependency remediation "
        "or governed VEX disposition, and rerun the candidate tests."
    )
    if secret.get("secret_verification_status") == "verified":
        action += " Revoke and rotate the verified candidate while confirming scope."
    if secret.get("temporal_alignment") != "aligned-current-tree":
        action += (
            " Align secret, sink, advisory, and test evidence to one source revision."
        )
    if advisory.get("fix_available") is True:
        action += " Verify the fixed package version in the built artifact."
    if (
        validation_handoff.get("supporting_evidence_readiness")
        != "supporting-evidence-ready"
    ):
        action += (
            " Resolve retained test, coverage, revision, and assurance gaps first."
        )
    return action[:2000]


def _compact_secret_exposure_advisory_intersection(
    value: dict[str, Any],
) -> dict[str, Any]:
    return dict(value)


def _attach_secret_exposure_advisory_intersections(
    secret_intersections: list[dict[str, Any]],
    advisory_intersections: list[dict[str, Any]],
    sensitive_routes: list[dict[str, Any]],
    compounds: list[dict[str, Any]],
) -> None:
    by_secret: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_advisory: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_sensitive: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for compound in compounds:
        by_secret[str(compound["secret_exposure_intersection_id"])].append(compound)
        by_advisory[str(compound["exposure_advisory_intersection_id"])].append(compound)
        by_sensitive[str(compound["sensitive_route_id"])].append(compound)
    for records, key_name, index in (
        (secret_intersections, "intersection_id", by_secret),
        (advisory_intersections, "intersection_id", by_advisory),
        (sensitive_routes, "sensitive_route_id", by_sensitive),
    ):
        for record in records:
            matches = index.get(str(record[key_name]), [])
            record["secret_exposure_advisory_intersection_ids"] = [
                str(item["intersection_id"]) for item in matches
            ]
            record["secret_exposure_advisory_intersections"] = [
                _compact_secret_exposure_advisory_intersection(item)
                for item in matches[
                    :_MAX_CONTEXT_SECRET_EXPOSURE_ADVISORY_INTERSECTIONS
                ]
            ]
            record["secret_exposure_advisory_intersections_omitted"] = max(
                0,
                len(matches) - _MAX_CONTEXT_SECRET_EXPOSURE_ADVISORY_INTERSECTIONS,
            )


def _is_secret_finding(finding: Finding) -> bool:
    return (
        finding.status is not FindingStatus.SUPPRESSED
        and finding.area.casefold() in _SECRET_AREAS
    )


def _secret_finding_count(findings: list[Finding]) -> int:
    return sum(_is_secret_finding(finding) for finding in findings)


def _secret_verification_status(finding: Finding) -> str:
    native = {source.native_severity.casefold() for source in finding.sources}
    if finding.evidence.get("verified") is True or "verified" in native:
        return "verified"
    if finding.evidence.get("verification_enabled") is False:
        return "verification-disabled"
    if native & {"potential-secret", "secret", "unverified"}:
        return "unverified"
    return "not-established"


def _secret_history_status(finding: Finding, tools: list[str]) -> str:
    scan_mode = str(finding.evidence.get("scan_mode") or "").casefold()
    if scan_mode == "git":
        return "history-evidence"
    if scan_mode == "dir":
        return "current-tree"
    if set(tools) & {
        "bandit",
        "detect-secrets",
        "ruff",
        "ruff-quality",
        "semgrep",
        "trufflehog",
    }:
        return "current-tree"
    if finding.area.casefold() == "secrets-history":
        return "history-evidence"
    return "not-established"


def _secret_history_commit(finding: Finding) -> str | None:
    value = finding.evidence.get("commit")
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized[:64] if normalized else None


def _secret_review_disposition(content_lane: str) -> str:
    return {
        "python-runtime-source": "production-source-review",
        "test-validation-source": "test-fixture-review",
        "generated-evidence": "generated-evidence-review",
        "artifact-control": "artifact-material-review",
        "outside-python-runtime-model": "repository-control-review",
    }.get(content_lane, "repository-control-review")


def _secret_provenance_action(
    *,
    content_lane: str,
    verification_status: str,
    history_status: str,
    redacted: bool,
) -> str:
    actions = {
        "python-runtime-source": (
            "Validate the candidate in the protected checkout; if real, revoke and "
            "rotate it, remove it from maintained source and applicable history, and "
            "replace it with an approved secret-store reference."
        ),
        "test-validation-source": (
            "Prove the test value is synthetic and nonfunctional, document its fixture "
            "purpose, and use only a narrow rule/path allowlist; if it is real, rotate "
            "it and remove it from source and applicable history."
        ),
        "generated-evidence": (
            "Determine in the protected workspace whether the redacted candidate is a "
            "credential or deterministic digest/receipt. If real, rotate it, purge the "
            "generated artifact, and sanitize its producer; if deterministic evidence, "
            "use only a narrow artifact/rule exclusion that preserves other secret scans."
        ),
        "artifact-control": (
            "Inspect the producing build and release material in a protected workspace; "
            "rotate and purge real credentials from artifacts and caches, or narrowly "
            "govern a proven non-secret digest without weakening artifact scanning."
        ),
        "outside-python-runtime-model": (
            "Validate the repository or configuration candidate in its native evidence "
            "lane; rotate and remove real credentials, or narrowly govern proven "
            "non-secret test/configuration data without adding a Python entry point."
        ),
    }
    result = actions.get(content_lane, actions["outside-python-runtime-model"])
    if verification_status == "verified":
        result = (
            "Treat scanner verification as urgent evidence, while independently "
            "confirming scope and credential ownership. " + result
        )
    elif verification_status in {"verification-disabled", "not-established"}:
        result += (
            " Credential validity was not established; do not copy the value into "
            "tickets or reports while validating it."
        )
    if history_status == "history-evidence":
        result += (
            " Review the cited commit and reachable history; removal from the current "
            "tree alone is not sufficient for a real credential."
        )
    if not redacted:
        result += (
            " Confirm every generated report path redacts the candidate before the "
            "report leaves the protected boundary."
        )
    return result[:2000]


def _attach_secret_provenance(
    findings: list[Finding], assessments: list[dict[str, Any]]
) -> None:
    by_finding = {
        str(item["finding_id"]): item for item in assessments if item.get("finding_id")
    }
    for finding in findings:
        assessment = by_finding.get(finding.finding_id)
        if assessment is None:
            continue
        finding.evidence["secret_provenance"] = assessment
        if not any(
            citation.identifier == "pysec-secret-provenance"
            for citation in finding.citations
        ):
            finding.citations.append(
                Citation(
                    kind="supporting_evidence",
                    identifier="pysec-secret-provenance",
                    title="Suite secret candidate provenance synthesis",
                    uri=_RISK_PATH_REFERENCE,
                )
            )
        if assessment.get("secret_exposure_intersection_ids") and not any(
            citation.identifier == "pysec-secret-exposure-route"
            for citation in finding.citations
        ):
            finding.citations.append(
                Citation(
                    kind="supporting_evidence",
                    identifier="pysec-secret-exposure-route",
                    title="Suite bounded secret-to-sensitive-sink route intersection",
                    uri=_RISK_PATH_REFERENCE,
                )
            )
