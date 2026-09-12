"""Pure risk-route summary calculations, separated from graph construction."""

from typing import Any
from .risk_path_values import _object, _strings, _nonnegative_integer


def summarize_graph_available(graph_available: Any) -> dict[str, Any]:
    return {"graph_available": graph_available}


def summarize_reachability(reachability: Any) -> dict[str, Any]:
    return {
        "reachability_available": isinstance(reachability, dict)
        and reachability.get("schema_version") == "1.2"
    }


def summarize_entry_points(entry_points: Any) -> dict[str, Any]:
    return {"entry_points": len(entry_points)}


def summarize_candidate_targets_and_dependency_targets_omitted(
    candidate_targets: Any, dependency_targets_omitted: Any
) -> dict[str, Any]:
    return {
        "candidate_targets": len(candidate_targets) + dependency_targets_omitted,
        "dependency_advisory_import_targets": sum(
            (
                target["kind"] == "dependency-advisory-import"
                for target in candidate_targets
            )
        )
        + dependency_targets_omitted,
    }


def summarize_targets(targets: Any) -> dict[str, Any]:
    return {
        "targets_analyzed": len(targets),
        "route_applicable_targets": sum(
            (
                target["route_applicability"]["assessment"] == "route-applicable"
                for target in targets
            )
        ),
        "route_not_applicable_targets": sum(
            (
                target["route_applicability"]["assessment"] == "not-route-applicable"
                for target in targets
            )
        ),
    }


def summarize_candidate_targets(candidate_targets: Any) -> dict[str, Any]:
    return {
        "finding_targets": sum(
            (target["kind"] == "finding" for target in candidate_targets)
        ),
        "sink_surface_targets": sum(
            (target["kind"] == "sink-surface" for target in candidate_targets)
        ),
    }


def summarize_routed(routed: Any) -> dict[str, Any]:
    return {
        "routed_targets": len(routed),
        "routed_findings": sum(
            (route["target"]["kind"] == "finding" for route in routed)
        ),
        "routed_sink_surfaces": sum(
            (route["target"]["kind"] == "sink-surface" for route in routed)
        ),
        "routed_dependency_advisory_imports": sum(
            (
                route["target"]["kind"] == "dependency-advisory-import"
                for route in routed
            )
        ),
        "assured_evidence_routes": sum(
            (
                route["evidence_assurance"]["review_status"] == "assured"
                for route in routed
            )
        ),
        "single_perspective_routes": sum(
            (
                route["evidence_assurance"]["perspective_assessment"] == "single-tool"
                for route in routed
            )
        ),
        "independently_corroborated_routes": sum(
            (
                route["evidence_assurance"]["perspective_assessment"]
                == "independent-corroboration"
                for route in routed
            )
        ),
        "routes_with_tool_trust_gaps": sum(
            (
                route["evidence_assurance"]["review_status"] == "trust-gap"
                for route in routed
            )
        ),
        "routes_with_tool_execution_gaps": sum(
            (
                route["evidence_assurance"]["review_status"] == "execution-gap"
                for route in routed
            )
        ),
        "routes_without_tool_assurance": sum(
            (
                route["evidence_assurance"]["review_status"]
                in {"not-assessed", "derived-analysis"}
                for route in routed
            )
        ),
        "routes_with_comparable_finding_lifecycle": sum(
            (
                _object(route.get("change_lifecycle_attribution")).get("baseline_state")
                == "comparable"
                for route in routed
            )
        ),
        "routes_without_comparable_finding_lifecycle": sum(
            (
                route["target"]["kind"] == "finding"
                and _object(route.get("change_lifecycle_attribution")).get(
                    "baseline_state"
                )
                != "comparable"
                for route in routed
            )
        ),
        "baseline_new_or_regressed_routes": sum(
            (
                _object(route.get("change_lifecycle_attribution")).get(
                    "lifecycle_status"
                )
                in {"new", "regression"}
                and _object(route.get("change_lifecycle_attribution")).get(
                    "baseline_state"
                )
                == "comparable"
                for route in routed
            )
        ),
        "baseline_new_or_regressed_changed_routes": sum(
            (
                _object(route.get("change_lifecycle_attribution")).get("classification")
                in {"baseline-new-on-changed-line", "regression-on-changed-line"}
                for route in routed
            )
        ),
        "baseline_new_or_regressed_changed_routes_with_validation_gaps": sum(
            (
                _object(route.get("change_lifecycle_attribution")).get("review_signal")
                == "baseline-new-or-regressed-change-gap"
                for route in routed
            )
        ),
        "existing_finding_routes_at_changed_lines": sum(
            (
                _object(route.get("change_lifecycle_attribution")).get("classification")
                == "existing-on-changed-line"
                for route in routed
            )
        ),
        "distinct_routed_dependency_advisories": len(
            {
                str(route["correlations"]["advisory_cluster_id"])
                for route in routed
                if route["target"]["kind"] == "dependency-advisory-import"
            }
        ),
        "known_exploited_dependency_routes": sum(
            (
                route["target"]["kind"] == "dependency-advisory-import"
                and route["correlations"].get("known_exploited") is True
                for route in routed
            )
        ),
        "high_epss_dependency_routes": sum(
            (
                route["target"]["kind"] == "dependency-advisory-import"
                and route["correlations"].get("epss_high") is True
                for route in routed
            )
        ),
        "dependency_routes_with_fixed_versions": sum(
            (
                route["target"]["kind"] == "dependency-advisory-import"
                and route["correlations"].get("fix_available") is True
                for route in routed
            )
        ),
        "dependency_routes_with_validation_gaps": sum(
            (
                route["target"]["kind"] == "dependency-advisory-import"
                and route["validation"]["assessment_status"] == "gap"
                for route in routed
            )
        ),
        "dependency_routes_at_changed_importers": sum(
            (
                route["target"]["kind"] == "dependency-advisory-import"
                and isinstance(route["correlations"].get("change_risk_score"), int)
                for route in routed
            )
        ),
        "dependency_routes_with_uncovered_changed_lines": sum(
            (
                route["target"]["kind"] == "dependency-advisory-import"
                and bool(route["correlations"].get("uncovered_changed_lines"))
                for route in routed
            )
        ),
        "dependency_routes_with_comparable_package_lifecycle": sum(
            (
                route["target"]["kind"] == "dependency-advisory-import"
                and _object(route["correlations"].get("package_lifecycle")).get(
                    "comparison_available"
                )
                is True
                for route in routed
            )
        ),
        "dependency_routes_with_version_drift": sum(
            (
                route["target"]["kind"] == "dependency-advisory-import"
                and _object(route["correlations"].get("package_lifecycle")).get(
                    "assessment"
                )
                == "version-drift"
                for route in routed
            )
        ),
        "dependency_routes_source_only_in_comparable_inventory": sum(
            (
                route["target"]["kind"] == "dependency-advisory-import"
                and _object(route["correlations"].get("package_lifecycle")).get(
                    "assessment"
                )
                == "source-only"
                for route in routed
            )
        ),
        "dependency_routes_artifact_only_in_comparable_inventory": sum(
            (
                route["target"]["kind"] == "dependency-advisory-import"
                and _object(route["correlations"].get("package_lifecycle")).get(
                    "assessment"
                )
                == "artifact-only"
                for route in routed
            )
        ),
        "dependency_routes_with_composition_evidence_gaps": sum(
            (
                route["target"]["kind"] == "dependency-advisory-import"
                and _object(route["correlations"].get("package_lifecycle")).get(
                    "assessment"
                )
                in {
                    "source-inventory-unavailable",
                    "artifact-inventory-unavailable",
                    "composition-inventories-unavailable",
                    "package-not-observed",
                }
                for route in routed
            )
        ),
        "dependency_routes_with_exact_fixed_version_in_artifact": sum(
            (
                route["target"]["kind"] == "dependency-advisory-import"
                and _object(route["correlations"].get("package_lifecycle")).get(
                    "artifact_fixed_version_exact_match"
                )
                is True
                for route in routed
            )
        ),
        "runtime_observed_routes": sum(
            ("observed" in route["runtime_context"]["observations"] for route in routed)
        ),
        "coverage_gap_routes": sum(
            (route["validation"]["line_covered"] is False for route in routed)
        ),
        "validation_assessed_routes": sum(
            (
                route["validation"]["assessment_status"]
                in {"aligned", "gap", "partial"}
                for route in routed
            )
        ),
        "validation_unassessed_routes": sum(
            (
                route["validation"]["assessment_status"] == "not-assessed"
                for route in routed
            )
        ),
        "owned_routes": sum((bool(route["owners"]) for route in routed)),
    }


def summarize_unrouted(unrouted: Any) -> dict[str, Any]:
    return {
        "unrouted_targets": len(unrouted),
        "unrouted_route_applicable_targets": sum(
            (
                item["route_applicability"]["assessment"] == "route-applicable"
                for item in unrouted
            )
        ),
        "unrouted_expected_non_runtime_targets": sum(
            (
                item["route_applicability"]["assessment"] == "not-route-applicable"
                for item in unrouted
            )
        ),
        "unrouted_targets_missing_graph_membership": sum(
            (
                item["route_applicability"]["assessment"] == "route-applicable"
                and item["route_applicability"]["graph_path_member"] is False
                for item in unrouted
            )
        ),
        "unrouted_targets_without_entry_route": sum(
            (
                item["route_applicability"]["assessment"] == "route-applicable"
                and item["route_applicability"]["graph_path_member"] is True
                for item in unrouted
            )
        ),
        "unrouted_by_applicability_class": {
            classification: sum(
                (
                    item["route_applicability"]["classification"] == classification
                    for item in unrouted
                )
            )
            for classification in (
                "python-runtime-source",
                "artifact-control",
                "generated-evidence",
                "test-validation-source",
                "outside-python-runtime-model",
            )
        },
        "unrouted_dependency_advisory_imports": sum(
            (
                target["target"]["kind"] == "dependency-advisory-import"
                for target in unrouted
            )
        ),
    }


def summarize_unrouted_structural_intersections(
    all_unrouted_structural_intersections: Any,
) -> dict[str, Any]:
    return {
        "unrouted_structural_intersections": len(all_unrouted_structural_intersections),
        "unrouted_targets_in_disconnected_islands": len(
            {
                str(item["target_id"])
                for item in all_unrouted_structural_intersections
                if item["island_state"] == "disconnected"
            }
        ),
        "unrouted_targets_with_runtime_counter_evidence": len(
            {
                str(item["target_id"])
                for item in all_unrouted_structural_intersections
                if item["runtime_observation"] == "observed"
            }
        ),
        "unrouted_targets_with_dead_code_corroboration": len(
            {
                str(item["target_id"])
                for item in all_unrouted_structural_intersections
                if item["dead_code_finding_ids"]
            }
        ),
        "unrouted_targets_with_candidate_entry_paths": len(
            {
                str(item["target_id"])
                for item in all_unrouted_structural_intersections
                if item["candidate_entry_paths"]
            }
        ),
        "unrouted_structural_intersections_with_validation_gaps": sum(
            (
                item["target_validation"]["assessment_status"] in {"gap", "partial"}
                for item in all_unrouted_structural_intersections
            )
        ),
    }


def summarize_routes(retained_routes: Any) -> dict[str, Any]:
    return {
        "retained_entry_point_exposures": sum(
            (len(route["entry_point_exposures"]) for route in retained_routes)
        ),
        "observed_entry_point_exposures": sum(
            (
                exposure["runtime_context"]["assessment"] == "observed"
                for route in retained_routes
                for exposure in route["entry_point_exposures"]
            )
        ),
        "unobserved_entry_point_exposures": sum(
            (
                exposure["runtime_context"]["assessment"] == "not-observed"
                for route in retained_routes
                for exposure in route["entry_point_exposures"]
            )
        ),
        "entry_point_exposures_without_runtime_evidence": sum(
            (
                exposure["runtime_context"]["assessment"] == "not-available"
                for route in retained_routes
                for exposure in route["entry_point_exposures"]
            )
        ),
        "multi_entry_routes_with_unobserved_interfaces": sum(
            (
                int(route["entry_point_exposure_count"]) > 1
                and any(
                    (
                        exposure["runtime_context"]["assessment"] == "not-observed"
                        for exposure in route["entry_point_exposures"]
                    )
                )
                for route in retained_routes
            )
        ),
        "multi_entry_routes_with_runtime_evidence_gaps": sum(
            (
                int(route["entry_point_exposure_count"]) > 1
                and any(
                    (
                        exposure["runtime_context"]["assessment"] == "not-available"
                        for exposure in route["entry_point_exposures"]
                    )
                )
                for route in retained_routes
            )
        ),
        "routes_with_multiple_entry_points": sum(
            (int(route["entry_point_exposure_count"]) > 1 for route in retained_routes)
        ),
        "security_routes_with_multiple_entry_points": sum(
            (
                int(route["entry_point_exposure_count"]) > 1
                and route["target"]["domain"] in {"security", "supply-chain"}
                for route in retained_routes
            )
        ),
        "maximum_entry_points_per_route": max(
            (int(route["entry_point_exposure_count"]) for route in retained_routes),
            default=0,
        ),
        "routes_with_entry_point_exposure_truncation": sum(
            (
                int(route["entry_point_exposures_omitted"]) > 0
                for route in retained_routes
            )
        ),
        "routes_with_ownership_evidence": sum(
            (
                _object(route.get("ownership_context")).get("evidence_available")
                is True
                for route in retained_routes
            )
        ),
        "routes_crossing_ownership_boundaries": sum(
            (
                (
                    _nonnegative_integer(
                        _object(route.get("ownership_context")).get("boundary_count")
                    )
                    or 0
                )
                > 0
                for route in retained_routes
            )
        ),
        "routes_with_unowned_segments": sum(
            (
                bool(_object(route.get("ownership_context")).get("unowned_files"))
                for route in retained_routes
            )
        ),
        "routes_without_ownership_evidence": sum(
            (
                _object(route.get("ownership_context")).get("evidence_available")
                is not True
                for route in retained_routes
            )
        ),
        "ownership_boundaries": sum(
            (
                _nonnegative_integer(
                    _object(route.get("ownership_context")).get("boundary_count")
                )
                or 0
                for route in retained_routes
            )
        ),
        "distinct_route_owners": len(
            {
                owner
                for route in retained_routes
                for owner in _strings(
                    _object(route.get("ownership_context")).get("distinct_owners"), 100
                )
            }
        ),
    }


def summarize_exposure_advisory_intersections(
    all_exposure_advisory_intersections: Any,
) -> dict[str, Any]:
    return {
        "exposure_advisory_intersections": len(all_exposure_advisory_intersections),
        "known_exploited_exposure_advisory_intersections": sum(
            (item["known_exploited"] for item in all_exposure_advisory_intersections)
        ),
        "unprotected_exposure_advisory_intersections": sum(
            (
                item["protection_status"] == "not-observed"
                for item in all_exposure_advisory_intersections
            )
        ),
        "exposure_advisory_intersections_with_validation_gaps": sum(
            (
                "gap" in item["validation_statuses"].values()
                for item in all_exposure_advisory_intersections
            )
        ),
    }


def summarize_sensitive_data_routes(all_sensitive_data_routes: Any) -> dict[str, Any]:
    return {
        "sensitive_data_routes": len(all_sensitive_data_routes),
        "scanner_confirmed_sensitive_data_routes": sum(
            (
                item["evidence_basis"] == "scanner-confirmed-source-to-sink"
                for item in all_sensitive_data_routes
            )
        ),
        "inventory_sensitive_data_routes": sum(
            (
                item["evidence_basis"] == "inventory-review-surface"
                for item in all_sensitive_data_routes
            )
        ),
        "sensitive_data_routes_without_observed_protection": sum(
            (
                item["protection_status"] in {"not-observed", "unknown"}
                for item in all_sensitive_data_routes
            )
        ),
        "sensitive_data_routes_with_runtime_observed_entry_points": sum(
            (
                item["entry_point_runtime_statuses"]["observed"] > 0
                for item in all_sensitive_data_routes
            )
        ),
        "sensitive_data_routes_with_validation_gaps": sum(
            (item["validation_status"] == "gap" for item in all_sensitive_data_routes)
        ),
        "sensitive_data_routes_with_assurance_gaps": sum(
            (
                item["evidence_assurance_status"] != "assured"
                for item in all_sensitive_data_routes
            )
        ),
        "sensitive_data_routes_crossing_ownership_boundaries": sum(
            (item["ownership_boundaries"] > 0 for item in all_sensitive_data_routes)
        ),
        "sensitive_data_routes_with_multiple_entry_points": sum(
            (
                item["entry_point_exposure_count"] > 1
                for item in all_sensitive_data_routes
            )
        ),
        "sensitive_data_routes_with_citations": sum(
            (bool(item["citations"]) for item in all_sensitive_data_routes)
        ),
        "sensitive_data_routes_without_citations": sum(
            (not item["citations"] for item in all_sensitive_data_routes)
        ),
    }


def summarize_secret_provenance_assessments(
    all_secret_provenance_assessments: Any,
) -> dict[str, Any]:
    return {
        "secret_candidates_assessed": len(all_secret_provenance_assessments),
        "production_source_secret_candidates": sum(
            (
                item["content_lane"] == "python-runtime-source"
                for item in all_secret_provenance_assessments
            )
        ),
        "test_source_secret_candidates": sum(
            (
                item["content_lane"] == "test-validation-source"
                for item in all_secret_provenance_assessments
            )
        ),
        "generated_evidence_secret_candidates": sum(
            (
                item["content_lane"] == "generated-evidence"
                for item in all_secret_provenance_assessments
            )
        ),
        "artifact_secret_candidates": sum(
            (
                item["content_lane"] == "artifact-control"
                for item in all_secret_provenance_assessments
            )
        ),
        "repository_control_secret_candidates": sum(
            (
                item["content_lane"] == "outside-python-runtime-model"
                for item in all_secret_provenance_assessments
            )
        ),
        "history_secret_candidates": sum(
            (
                item["history_status"] == "history-evidence"
                for item in all_secret_provenance_assessments
            )
        ),
        "verified_secret_candidates": sum(
            (
                item["verification_status"] == "verified"
                for item in all_secret_provenance_assessments
            )
        ),
        "secret_candidates_without_verification": sum(
            (
                item["verification_status"] != "verified"
                for item in all_secret_provenance_assessments
            )
        ),
        "multi_scanner_secret_candidates": sum(
            (
                item["scanner_perspective"] == "multi-scanner"
                for item in all_secret_provenance_assessments
            )
        ),
        "secret_candidates_with_assurance_gaps": sum(
            (
                item["evidence_assurance_status"] != "assured"
                for item in all_secret_provenance_assessments
            )
        ),
        "secret_candidates_without_redaction_marker": sum(
            (not item["redacted"] for item in all_secret_provenance_assessments)
        ),
    }


def summarize_secret_exposure_intersections(
    all_secret_exposure_intersections: Any,
) -> dict[str, Any]:
    return {
        "secret_exposure_intersections": len(all_secret_exposure_intersections),
        "exact_path_secret_exposure_intersections": sum(
            (
                item["association_kind"] == "exact-path"
                for item in all_secret_exposure_intersections
            )
        ),
        "upstream_route_secret_exposure_intersections": sum(
            (
                item["association_kind"] == "upstream-route"
                for item in all_secret_exposure_intersections
            )
        ),
        "verified_secret_exposure_intersections": sum(
            (
                item["secret_verification_status"] == "verified"  # noqa: S105  # nosec B105  # pragma: allowlist secret - assessment status
                for item in all_secret_exposure_intersections
            )
        ),
        "history_secret_exposure_intersections": sum(
            (
                item["temporal_alignment"] == "history-to-current-route"
                for item in all_secret_exposure_intersections
            )
        ),
        "unprotected_secret_exposure_intersections": sum(
            (
                item["protection_status"] in {"not-observed", "none", "unknown"}
                for item in all_secret_exposure_intersections
            )
        ),
        "scanner_confirmed_secret_exposure_intersections": sum(
            (
                item["sensitive_evidence_basis"] == "scanner-confirmed-source-to-sink"
                for item in all_secret_exposure_intersections
            )
        ),
        "secret_exposure_intersections_with_assurance_gaps": sum(
            (
                item["secret_assurance_status"] != "assured"  # noqa: S105  # nosec B105  # pragma: allowlist secret - assessment status
                or item["sensitive_assurance_status"] != "assured"
                for item in all_secret_exposure_intersections
            )
        ),
        "secret_exposure_intersections_with_candidate_tests": sum(
            (
                bool(item["recommended_test_files"])
                for item in all_secret_exposure_intersections
            )
        ),
        "secret_exposure_intersections_without_candidate_tests": sum(
            (
                not item["recommended_test_files"]
                for item in all_secret_exposure_intersections
            )
        ),
        "secret_exposure_intersections_with_validation_evidence_gaps": sum(
            (
                _object(item["validation_handoff"]).get("supporting_evidence_readiness")
                != "supporting-evidence-ready"
                for item in all_secret_exposure_intersections
            )
        ),
        "secret_exposure_intersections_with_revision_gaps": sum(
            (
                _object(item["validation_handoff"]).get("source_revision_aligned")
                is not True
                for item in all_secret_exposure_intersections
            )
        ),
        "secret_exposure_intersections_with_failing_tests": sum(
            (
                "failed"
                in _strings(
                    _object(item["validation_handoff"]).get("focused_test_statuses"), 10
                )
                for item in all_secret_exposure_intersections
            )
        ),
        "secret_exposure_intersections_with_assurance_prerequisite_gaps": sum(
            (
                item["combined_assurance_prerequisite_met"] is not True
                for item in all_secret_exposure_intersections
            )
        ),
        "secret_exposure_intersections_without_canary_validation": sum(
            (
                item["canary_validation_status"] != "established"
                for item in all_secret_exposure_intersections
            )
        ),
    }


def summarize_secret_exposure_advisory_intersections(
    all_secret_exposure_advisory_intersections: Any,
) -> dict[str, Any]:
    return {
        "secret_exposure_advisory_intersections": len(
            all_secret_exposure_advisory_intersections
        ),
        "known_exploited_secret_exposure_advisory_intersections": sum(
            (
                item["known_exploited"]
                for item in all_secret_exposure_advisory_intersections
            )
        ),
        "verified_secret_exposure_advisory_intersections": sum(
            (
                item["secret_verification_status"] == "verified"  # noqa: S105  # nosec B105 - assessment status
                for item in all_secret_exposure_advisory_intersections
            )
        ),
        "unprotected_secret_exposure_advisory_intersections": sum(
            (
                item["protection_status"] in {"not-observed", "none", "unknown"}
                for item in all_secret_exposure_advisory_intersections
            )
        ),
        "fix_available_secret_exposure_advisory_intersections": sum(
            (
                item["fix_available"]
                for item in all_secret_exposure_advisory_intersections
            )
        ),
        "runtime_observed_secret_exposure_advisory_intersections": sum(
            (
                int(item["entry_point_runtime_statuses"]["observed"]) > 0
                for item in all_secret_exposure_advisory_intersections
            )
        ),
        "secret_exposure_advisory_intersections_with_validation_gaps": sum(
            (
                item["validation_handoff"]["supporting_evidence_readiness"]
                != "supporting-evidence-ready"
                or any(
                    (
                        status != "aligned"
                        for status in item["validation_statuses"].values()
                    )
                )
                for item in all_secret_exposure_advisory_intersections
            )
        ),
        "secret_exposure_advisory_intersections_with_assurance_gaps": sum(
            (
                not item["combined_assurance_prerequisite_met"]
                for item in all_secret_exposure_advisory_intersections
            )
        ),
        "secret_exposure_advisory_intersections_with_temporal_gaps": sum(
            (
                item["temporal_alignment"] != "aligned-current-tree"
                for item in all_secret_exposure_advisory_intersections
            )
        ),
        "secret_exposure_advisory_intersections_without_canary_validation": sum(
            (
                item["canary_validation_status"] != "established"
                for item in all_secret_exposure_advisory_intersections
            )
        ),
    }


def summarize_validation_gaps(validation_gaps: Any) -> dict[str, Any]:
    return {"validation_gap_routes": validation_gaps}


def summarize_convergence_hotspots(convergence_hotspots: Any) -> dict[str, Any]:
    return {
        "convergence_hotspots": len(convergence_hotspots),
        "shared_control_points": sum(
            (
                hotspot["kind"] != "target-concentration"
                for hotspot in convergence_hotspots
            )
        ),
        "routes_in_convergence_hotspots": len(
            {
                route_id
                for hotspot in convergence_hotspots
                for route_id in hotspot["route_ids"]
            }
        ),
    }


def summarize_owner_work_queues(owner_work_queues: Any) -> dict[str, Any]:
    return {
        "owner_work_queues": len(owner_work_queues),
        "owner_queues_with_exposure_advisory_intersections": sum(
            (
                bool(queue["exposure_advisory_intersection_ids"])
                for queue in owner_work_queues
            )
        ),
    }


def summarize_validation_campaigns(validation_campaigns: Any) -> dict[str, Any]:
    return {
        "validation_campaigns": len(validation_campaigns),
        "campaigns_with_selected_tests": sum(
            (bool(campaign["selected_test_files"]) for campaign in validation_campaigns)
        ),
        "campaigns_with_failing_tests": sum(
            (
                campaign["focused_test_validation_status"] == "failed"
                for campaign in validation_campaigns
            )
        ),
        "campaigns_with_coverage_gaps": sum(
            (
                campaign["test_coverage_alignment"] == "coverage-gap"
                for campaign in validation_campaigns
            )
        ),
        "campaigns_with_changed_controls": sum(
            (
                isinstance(campaign["control_point_context"]["change_risk_score"], int)
                for campaign in validation_campaigns
            )
        ),
        "campaigns_with_uncovered_changed_lines": sum(
            (
                bool(campaign["control_point_context"]["uncovered_changed_lines"])
                for campaign in validation_campaigns
            )
        ),
        "campaigns_with_runtime_observation_gaps": sum(
            (
                any(
                    (
                        factor["id"] == "runtime-observation-gap"
                        for factor in campaign["review_factors"]
                    )
                )
                for campaign in validation_campaigns
            )
        ),
        "campaigns_with_assured_route_evidence": sum(
            (
                campaign["route_evidence_assurance"]["tool_assurance_prerequisite_met"]
                is True
                for campaign in validation_campaigns
            )
        ),
        "campaigns_blocked_by_route_assurance": sum(
            (
                campaign["route_evidence_assurance"]["tool_assurance_prerequisite_met"]
                is not True
                for campaign in validation_campaigns
            )
        ),
        "campaigns_with_route_trust_gaps": sum(
            (
                int(campaign["route_evidence_assurance"]["route_statuses"]["trust-gap"])
                > 0
                for campaign in validation_campaigns
            )
        ),
        "campaigns_with_route_execution_gaps": sum(
            (
                int(
                    campaign["route_evidence_assurance"]["route_statuses"][
                        "execution-gap"
                    ]
                )
                > 0
                for campaign in validation_campaigns
            )
        ),
        "campaigns_with_unassessed_route_evidence": sum(
            (
                bool(campaign["route_evidence_assurance"]["route_ids_missing"])
                or int(
                    campaign["route_evidence_assurance"]["route_statuses"][
                        "not-assessed"
                    ]
                )
                > 0
                for campaign in validation_campaigns
            )
        ),
        "campaigns_with_route_perspective_gaps": sum(
            (
                int(
                    campaign["route_evidence_assurance"]["route_statuses"][
                        "perspective-gap"
                    ]
                )
                > 0
                for campaign in validation_campaigns
            )
        ),
        "campaigns_with_qualified_shared_test_evidence": sum(
            (
                campaign["shared_test_evidence_quality"]["assessment"] == "qualified"
                for campaign in validation_campaigns
            )
        ),
        "campaigns_with_weak_shared_test_evidence": sum(
            (
                campaign["shared_test_evidence_quality"]["assessment"]
                in {"weak", "not-established"}
                for campaign in validation_campaigns
            )
        ),
        "campaigns_aligned_current_evidence": sum(
            (
                campaign["test_coverage_alignment"] == "aligned-current-evidence"
                for campaign in validation_campaigns
            )
        ),
        "campaigns_requiring_evidence": sum(
            (
                campaign["test_coverage_alignment"]
                in {
                    "not-selected",
                    "test-evidence-not-available",
                    "tests-not-observed",
                    "tests-incomplete",
                    "coverage-not-available",
                }
                for campaign in validation_campaigns
            )
        ),
        "unique_campaign_test_files": len(
            {
                str(path)
                for campaign in validation_campaigns
                for path in campaign["selected_test_files"]
            }
        ),
        "campaigns_by_review_tier": {
            tier: sum(
                (campaign["review_tier"] == tier for campaign in validation_campaigns)
            )
            for tier in ("critical", "high", "medium", "low")
        },
        "campaigns_revision_aligned": sum(
            (
                campaign["source_snapshot"]["evidence_revision_binding"] == "aligned"
                for campaign in validation_campaigns
            )
        ),
        "campaigns_revision_mismatched": sum(
            (
                campaign["source_snapshot"]["evidence_revision_binding"] == "mismatch"
                for campaign in validation_campaigns
            )
        ),
        "campaigns_revision_unverified": sum(
            (
                campaign["source_snapshot"]["evidence_revision_binding"] == "unverified"
                for campaign in validation_campaigns
            )
        ),
        "campaigns_revision_unbound": sum(
            (
                campaign["source_snapshot"]["evidence_revision_binding"]
                == "not-established"
                for campaign in validation_campaigns
            )
        ),
        "campaigns_with_source_bound_control_points": sum(
            (
                campaign["source_snapshot"]["control_point_binding"] is not None
                for campaign in validation_campaigns
            )
        ),
        "selected_test_source_bindings": sum(
            (
                int(campaign["source_snapshot"]["selected_test_files_bound"])
                for campaign in validation_campaigns
            )
        ),
    }


def summarize_validation_test_hotspots(validation_test_hotspots: Any) -> dict[str, Any]:
    return {
        "shared_validation_test_hotspots": len(validation_test_hotspots),
        "campaigns_using_shared_tests": len(
            {
                campaign_id
                for hotspot in validation_test_hotspots
                for campaign_id in hotspot["campaign_ids"]
            }
        ),
        "routes_using_shared_tests": len(
            {
                route_id
                for hotspot in validation_test_hotspots
                for route_id in hotspot["route_ids"]
            }
        ),
        "single_test_dependency_campaigns": len(
            {
                campaign_id
                for hotspot in validation_test_hotspots
                for campaign_id in hotspot["single_test_dependency_campaign_ids"]
            }
        ),
        "shared_test_hotspots_strong": sum(
            (
                hotspot["validation_quality_assessment"] == "strong"
                for hotspot in validation_test_hotspots
            )
        ),
        "shared_test_hotspots_qualified": sum(
            (
                hotspot["validation_quality_assessment"] == "qualified"
                for hotspot in validation_test_hotspots
            )
        ),
        "shared_test_hotspots_weak": sum(
            (
                hotspot["validation_quality_assessment"] == "weak"
                for hotspot in validation_test_hotspots
            )
        ),
        "shared_test_hotspots_not_established": sum(
            (
                hotspot["validation_quality_assessment"] == "not-established"
                for hotspot in validation_test_hotspots
            )
        ),
        "shared_test_files_with_findings": sum(
            (
                bool(hotspot["test_file_finding_ids"])
                for hotspot in validation_test_hotspots
            )
        ),
        "shared_test_files_with_high_severity_findings": sum(
            (
                hotspot["test_file_highest_severity"] in {"critical", "high"}
                for hotspot in validation_test_hotspots
            )
        ),
        "cross_owner_shared_test_files": sum(
            (
                hotspot["test_owner_alignment"] == "coordination-needed"
                for hotspot in validation_test_hotspots
            )
        ),
        "unowned_shared_test_files": sum(
            (
                hotspot["test_owner_alignment"] == "unowned"
                for hotspot in validation_test_hotspots
            )
        ),
    }


def summarize_route_priorities(route_priorities: Any) -> dict[str, Any]:
    return {
        "routes_by_priority": {
            priority: route_priorities.get(priority, 0)
            for priority in ("P0", "P1", "P2", "P3", "P4")
        }
    }
