from __future__ import annotations

import json
import unittest
from typing import Any
from unittest.mock import patch

from jsonschema import Draft202012Validator

from py_security_suite.closure_plan import _finding_items
from py_security_suite.models import (
    Citation,
    Confidence,
    Finding,
    FindingStatus,
    Location,
    Severity,
    Source,
    json_ready,
)
from py_security_suite.report_inspection import read_bundled_schema
from py_security_suite.reports import (
    _html_risk_path_context,
    _html_secret_provenance_context,
    _markdown_risk_path_context,
    _markdown_secret_provenance_context,
    _render_risk_path_summary,
    _risk_advisory_citations_text,
    render_sarif,
)
from py_security_suite.risk_paths import build_risk_paths


class RiskPathTests(unittest.TestCase):
    def test_route_citation_renderer_rejects_unsafe_markdown_uri(self) -> None:
        rendered = _risk_advisory_citations_text(
            [
                {
                    "identifier": "CWE-532",
                    "title": "Logging guidance",
                    "uri": "https://example.test/reference_(unsafe)",
                }
            ]
        )

        self.assertEqual(rendered, "`CWE-532`")

    def test_routes_findings_and_sensitive_surfaces_from_declared_entry_points(
        self,
    ) -> None:
        finding = _finding("src/sink.py", 9)
        finding.evidence["owners"] = ["@security-team"]
        finding.evidence["fusion"] = {
            "review_tier": "elevated",
            "review_reasons": ["finding line lacks retained test coverage"],
            "related_finding_ids": ["PYSEC-RELATED"],
            "related_tools": ["semgrep"],
            "source_context": {
                "changed_line": True,
                "line_covered": False,
                "coverage_percent": 55.5,
                "reachability_states": ["executable"],
                "runtime_observations": ["observed"],
            },
        }
        finding.evidence["structural_synthesis"] = {
            "change_impact": {
                "associated_test_files": ["tests/test_sink.py"],
                "focused_test_validation_status": "passed",
                "test_coverage_alignment": "coverage-gap",
                "validation_gap_reasons": [
                    "Focused tests passed, but the finding line was uncovered."
                ],
                "validation_action": "Extend the focused sink test.",
            }
        }
        artifacts = _artifacts()
        _add_multi_entry_paths(artifacts)

        result = build_risk_paths([finding], artifacts)

        self.assertEqual(result["summary"]["routed_targets"], 2)
        self.assertEqual(result["summary"]["routed_findings"], 1)
        self.assertEqual(result["summary"]["routed_sink_surfaces"], 1)
        self.assertEqual(result["summary"]["coverage_gap_routes"], 2)
        self.assertEqual(result["summary"]["validation_gap_routes"], 2)
        self.assertEqual(result["summary"]["validation_assessed_routes"], 2)
        self.assertEqual(result["summary"]["validation_unassessed_routes"], 0)
        self.assertEqual(result["summary"]["convergence_hotspots"], 2)
        self.assertEqual(result["summary"]["shared_control_points"], 1)
        self.assertEqual(result["summary"]["routes_in_convergence_hotspots"], 2)
        self.assertEqual(result["summary"]["owner_work_queues"], 1)
        self.assertEqual(result["summary"]["validation_campaigns"], 2)
        self.assertEqual(result["summary"]["shared_validation_test_hotspots"], 1)
        self.assertEqual(result["summary"]["campaigns_using_shared_tests"], 2)
        self.assertEqual(result["summary"]["routes_using_shared_tests"], 2)
        self.assertEqual(result["summary"]["single_test_dependency_campaigns"], 2)
        self.assertEqual(result["summary"]["campaigns_with_selected_tests"], 2)
        self.assertEqual(result["summary"]["campaigns_with_failing_tests"], 0)
        self.assertEqual(result["summary"]["campaigns_with_coverage_gaps"], 1)
        self.assertEqual(result["summary"]["campaigns_with_changed_controls"], 1)
        self.assertEqual(result["summary"]["campaigns_with_uncovered_changed_lines"], 1)
        self.assertEqual(
            result["summary"]["campaigns_with_runtime_observation_gaps"], 1
        )
        self.assertEqual(result["summary"]["campaigns_aligned_current_evidence"], 1)
        self.assertEqual(result["summary"]["campaigns_requiring_evidence"], 0)
        self.assertEqual(result["summary"]["unique_campaign_test_files"], 1)
        self.assertEqual(
            result["summary"]["campaigns_by_review_tier"],
            {"critical": 2, "high": 0, "medium": 0, "low": 0},
        )
        self.assertEqual(result["summary"]["campaigns_with_assured_route_evidence"], 2)
        self.assertEqual(result["summary"]["campaigns_blocked_by_route_assurance"], 0)
        self.assertEqual(result["summary"]["campaigns_with_route_perspective_gaps"], 2)
        self.assertEqual(result["summary"]["campaigns_revision_unbound"], 2)
        self.assertEqual(
            result["summary"]["campaigns_with_source_bound_control_points"], 2
        )
        self.assertEqual(result["summary"]["selected_test_source_bindings"], 2)
        self.assertEqual(result["summary"]["retained_entry_point_exposures"], 6)
        self.assertEqual(result["summary"]["observed_entry_point_exposures"], 2)
        self.assertEqual(result["summary"]["unobserved_entry_point_exposures"], 2)
        self.assertEqual(
            result["summary"]["entry_point_exposures_without_runtime_evidence"],
            2,
        )
        self.assertEqual(
            result["summary"]["multi_entry_routes_with_unobserved_interfaces"], 2
        )
        self.assertEqual(
            result["summary"]["multi_entry_routes_with_runtime_evidence_gaps"], 2
        )
        self.assertEqual(result["summary"]["routes_with_multiple_entry_points"], 2)
        self.assertEqual(result["summary"]["assured_evidence_routes"], 0)
        self.assertEqual(result["summary"]["single_perspective_routes"], 1)
        self.assertEqual(result["summary"]["independently_corroborated_routes"], 0)
        self.assertEqual(result["summary"]["routes_with_tool_trust_gaps"], 0)
        self.assertEqual(result["summary"]["routes_with_tool_execution_gaps"], 0)
        self.assertEqual(result["summary"]["routes_without_tool_assurance"], 1)
        self.assertEqual(result["summary"]["routes_with_ownership_evidence"], 0)
        self.assertEqual(result["summary"]["routes_without_ownership_evidence"], 2)
        self.assertEqual(
            result["summary"]["security_routes_with_multiple_entry_points"], 2
        )
        self.assertEqual(result["summary"]["maximum_entry_points_per_route"], 3)
        queue = result["owner_work_queues"][0]
        self.assertEqual(queue["campaigns_with_uncovered_changed_lines"], 1)
        self.assertEqual(queue["campaigns_with_runtime_observation_gaps"], 1)
        self.assertEqual(queue["shared_validation_test_files"], 1)
        self.assertEqual(len(queue["validation_test_hotspot_ids"]), 1)
        self.assertEqual(queue["multi_entry_routes"], 2)
        self.assertEqual(
            queue["retained_entry_point_ids"],
            ["entry:cli", "entry:cli-module", "entry:worker"],
        )
        self.assertIn("interface-specific validation", queue["recommended_action"])
        self.assertEqual(
            queue["entry_point_runtime_statuses"],
            {"observed": 1, "not-observed": 1, "not-available": 1},
        )
        self.assertEqual(queue["unobserved_entry_point_ids"], ["entry:worker"])
        self.assertEqual(
            queue["entry_points_without_runtime_evidence"], ["entry:cli-module"]
        )
        self.assertEqual(
            queue["evidence_assurance_statuses"],
            {
                "assured": 0,
                "perspective-gap": 1,
                "trust-gap": 0,
                "execution-gap": 0,
                "not-assessed": 0,
                "derived-analysis": 1,
            },
        )
        self.assertEqual(queue["single_perspective_routes"], 1)
        self.assertEqual(queue["routes_without_ownership_evidence"], 2)
        self.assertIn("representative runtime evidence", queue["recommended_action"])
        self.assertIn("Model exact reachability nodes", queue["recommended_action"])
        finding_route = next(
            route for route in result["routes"] if route["target"]["kind"] == "finding"
        )
        self.assertEqual(
            finding_route["files"],
            ["src/cli.py", "src/service.py", "src/sink.py"],
        )
        self.assertEqual(
            [edge["relation"] for edge in finding_route["edges"]],
            ["calls", "calls"],
        )
        self.assertEqual(finding_route["owners"], ["@security-team"])
        self.assertEqual(
            finding_route["ownership_context"]["coordination_status"],
            "not-established",
        )
        self.assertEqual(finding_route["entry_point_exposure_count"], 3)
        self.assertTrue(finding_route["entry_point_exposures"][0]["primary"])
        self.assertEqual(
            {
                item["entry_point"]["id"]
                for item in finding_route["entry_point_exposures"]
            },
            {"entry:cli", "entry:cli-module", "entry:worker"},
        )
        runtime_by_entry = {
            item["entry_point"]["id"]: item["runtime_context"]["assessment"]
            for item in finding_route["entry_point_exposures"]
        }
        self.assertEqual(
            runtime_by_entry,
            {
                "entry:cli": "observed",
                "entry:cli-module": "not-available",
                "entry:worker": "not-observed",
            },
        )
        self.assertEqual(len(finding_route["convergence_hotspot_ids"]), 2)
        self.assertEqual(
            finding_route["evidence_assurance"]["review_status"],
            "perspective-gap",
        )
        self.assertEqual(
            finding_route["evidence_assurance"]["approved_tools"], ["semgrep"]
        )
        self.assertEqual(
            finding_route["evidence_assurance"]["perspective_assessment"],
            "single-tool",
        )
        self.assertEqual(len(finding_route["validation_campaign_ids"]), 2)
        self.assertEqual(
            finding_route["validation"]["mapped_test_files"],
            ["tests/test_sink.py"],
        )
        self.assertEqual(finding.evidence["risk_path"]["status"], "routed")
        self.assertEqual(finding.evidence["risk_path"]["entry_point_exposure_count"], 3)
        self.assertEqual(len(finding.evidence["risk_path"]["validation_campaigns"]), 2)
        self.assertEqual(
            len(finding.evidence["risk_path"]["validation_test_hotspot_ids"]), 1
        )
        campaigns = result["validation_campaigns"]
        test_hotspot = result["validation_test_hotspots"][0]
        self.assertEqual(test_hotspot["test_path"], "tests/test_sink.py")
        self.assertEqual(len(test_hotspot["campaign_ids"]), 2)
        self.assertEqual(
            test_hotspot["control_point_paths"], ["src/service.py", "src/sink.py"]
        )
        self.assertEqual(test_hotspot["execution_statuses"], ["passed"])
        self.assertEqual(test_hotspot["observed_case_count"], 1)
        self.assertTrue(test_hotspot["source_binding_consistent"])
        self.assertEqual(test_hotspot["source_binding"]["path"], "tests/test_sink.py")
        self.assertEqual(len(test_hotspot["single_test_dependency_campaign_ids"]), 2)
        self.assertTrue(
            all(
                campaign["shared_test_hotspot_ids"] == [test_hotspot["test_hotspot_id"]]
                for campaign in campaigns
            )
        )
        self.assertEqual(
            {campaign["test_selection_confidence"] for campaign in campaigns},
            {"high", "medium"},
        )
        self.assertTrue(
            all(
                campaign["selected_test_files"] == ["tests/test_sink.py"]
                for campaign in campaigns
            )
        )
        self.assertEqual(
            {
                campaign["source_snapshot"]["evidence_revision_binding"]
                for campaign in campaigns
            },
            {"not-established"},
        )
        self.assertTrue(
            all(
                campaign["source_snapshot"]["control_point_binding"]
                for campaign in campaigns
            )
        )
        self.assertEqual(
            {campaign["review_tier"] for campaign in campaigns}, {"critical"}
        )
        self.assertTrue(
            all(
                campaign["review_score_model"] == "shared-control-review-v5"
                for campaign in campaigns
            )
        )
        self.assertEqual(test_hotspot["validation_quality_assessment"], "qualified")
        self.assertEqual(test_hotspot["test_owner_alignment"], "not-established")
        self.assertEqual(test_hotspot["test_file_finding_ids"], [])
        self.assertEqual(result["summary"]["shared_test_hotspots_qualified"], 1)
        self.assertEqual(
            result["summary"]["campaigns_with_qualified_shared_test_evidence"], 2
        )
        self.assertTrue(
            all(
                campaign["shared_test_evidence_quality"]["assessment"] == "qualified"
                for campaign in campaigns
            )
        )
        self.assertTrue(
            all(
                campaign["route_evidence_assurance"]["tool_assurance_prerequisite_met"]
                for campaign in campaigns
            )
        )
        self.assertTrue(
            all(
                campaign["route_evidence_assurance"]["route_statuses"][
                    "perspective-gap"
                ]
                == 1
                for campaign in campaigns
            )
        )
        self.assertTrue(all(campaign["review_factors"] for campaign in campaigns))
        campaigns_by_path = {campaign["path"]: campaign for campaign in campaigns}
        sink_campaign = campaigns_by_path["src/sink.py"]
        service_campaign = campaigns_by_path["src/service.py"]
        self.assertEqual(
            sink_campaign["control_point_context"]["change_risk_score"], 85
        )
        self.assertEqual(
            sink_campaign["control_point_context"]["uncovered_changed_lines"], [9]
        )
        self.assertTrue(
            {"changed-control-risk", "uncovered-changed-lines"}.issubset(
                {factor["id"] for factor in sink_campaign["review_factors"]}
            )
        )
        self.assertIn(
            "runtime-observation-gap",
            {factor["id"] for factor in service_campaign["review_factors"]},
        )
        self.assertTrue(
            all(
                campaign["focused_test_validation_status"] == "passed"
                for campaign in campaigns
            )
        )
        self.assertEqual(
            {campaign["test_coverage_alignment"] for campaign in campaigns},
            {"aligned-current-evidence", "coverage-gap"},
        )
        self.assertTrue(
            all(
                campaign["coverage_evidence_scope"] == "aggregate-retained-file"
                and campaign["coverage_attribution"] == "not-established"
                for campaign in campaigns
            )
        )
        self.assertTrue(
            any(
                citation.identifier == "pysec-static-risk-route"
                for citation in finding.citations
            )
        )
        schema = json.loads(read_bundled_schema("risk-paths-1.0"))
        Draft202012Validator(schema).validate(result)

        rendered = "\n".join(_render_risk_path_summary(result))
        self.assertIn("Static risk routes", rendered)
        self.assertIn("src/cli.py → src/service.py → src/sink.py", rendered)
        self.assertIn("@security-team", rendered)
        self.assertIn("Shared route control points", rendered)
        self.assertIn("Route owner queues", rendered)
        self.assertIn("Shared validation campaigns", rendered)
        self.assertIn("Shared validation-test hotspots", rendered)
        self.assertIn(test_hotspot["test_hotspot_id"], rendered)
        self.assertIn("sole dependency `2`", rendered)
        self.assertIn("revision `not-established`", rendered)
        self.assertIn("route evidence perspective-gap", rendered)
        self.assertIn("change risk 85 (high)", rendered)
        self.assertIn("uncovered changed lines 9", rendered)
        self.assertIn("runtime not-observed", rendered)
        self.assertIn("changed-control-risk +15", rendered)
        self.assertIn("3 declared entry-point route(s)", rendered)
        self.assertIn("src/worker.py", rendered)
        self.assertIn("runtime observed/unobserved/unavailable 1/1/1", rendered)
        self.assertIn("evidence perspective-gap", rendered)
        html_context = _html_risk_path_context(finding)
        self.assertIn("changed-control-risk +15", html_context)
        self.assertIn("uncovered changed lines 9", html_context)
        self.assertIn(test_hotspot["test_hotspot_id"], html_context)
        self.assertIn("tests/test_sink.py", rendered)
        self.assertIn("src/service.py", rendered)
        sarif = render_sarif([finding])
        properties = sarif["runs"][0]["results"][0]["properties"]
        self.assertEqual(properties["risk_path"]["status"], "routed")
        self.assertEqual(properties["risk_path"]["entry_point_exposure_count"], 3)
        self.assertEqual(
            properties["risk_path"]["evidence_assurance"]["review_status"],
            "perspective-gap",
        )
        self.assertEqual(
            properties["risk_path"]["validation_test_hotspot_ids"],
            [test_hotspot["test_hotspot_id"]],
        )
        closure = _finding_items([json_ready(finding)])[0]
        self.assertIn("risk-paths.json", closure["evidence_refs"])
        self.assertEqual(
            closure["details"]["risk_path"]["route_id"],
            finding_route["route_id"],
        )
        self.assertEqual(
            closure["details"]["risk_path"]["convergence_hotspot_ids"],
            finding_route["convergence_hotspot_ids"],
        )
        self.assertEqual(
            closure["details"]["risk_path"]["validation_campaign_ids"],
            finding_route["validation_campaign_ids"],
        )
        self.assertEqual(
            closure["details"]["risk_path"]["entry_point_exposure_count"], 3
        )
        self.assertIn("src/worker.py", closure["evidence_refs"])
        self.assertIn("tests/test_sink.py", closure["evidence_refs"])
        self.assertIn("effectiveness.json", closure["evidence_refs"])
        self.assertIn("scanner-trust.json", closure["evidence_refs"])
        closure_campaigns = closure["details"]["risk_path"]["validation_campaigns"]
        self.assertTrue(
            any(
                campaign["control_point_context"].get("change_risk_score") == 85
                for campaign in closure_campaigns
            )
        )
        self.assertTrue(
            any(
                "Shared validation-test hotspots" in item
                for item in closure["acceptance_criteria"]
            )
        )
        self.assertTrue(
            any(
                "uncovered changed lines" in item
                for item in closure["acceptance_criteria"]
            )
        )
        self.assertTrue(
            any(
                "Runtime evidence observes" in item
                for item in closure["acceptance_criteria"]
            )
        )
        self.assertTrue(
            any(
                factor.get("id") == "runtime-observation-gap"
                for campaign in closure_campaigns
                for factor in campaign["review_factors"]
            )
        )
        self.assertTrue(
            any(
                "validation assessment" in item
                for item in closure["acceptance_criteria"]
            )
        )
        self.assertTrue(
            any(
                "every retained declared entry-point route" in item
                for item in closure["acceptance_criteria"]
            )
        )
        self.assertTrue(
            any(
                "previously unobserved declared interface" in item
                for item in closure["acceptance_criteria"]
            )
        )
        self.assertTrue(
            any(
                "joined to its exact reachability node" in item
                for item in closure["acceptance_criteria"]
            )
        )
        self.assertTrue(
            any(
                "independent applicable analysis" in item
                for item in closure["acceptance_criteria"]
            )
        )
        self.assertTrue(
            any(
                "single-perspective routes" in item
                for item in closure["acceptance_criteria"]
            )
        )

    def test_cross_references_route_files_to_ownership_handoffs(self) -> None:
        artifacts = _artifacts()
        _add_multi_entry_paths(artifacts)
        artifacts["finding-delta.json"] = {
            "schema_version": "1.1",
            "configured": False,
            "ownership_rule_details": [
                {"pattern": "src/cli.py", "owners": ["@platform-team"]},
                {"pattern": "src/service.py", "owners": ["@service-team"]},
                {"pattern": "src/sink.py", "owners": ["@security-team"]},
            ],
        }
        finding = _finding("src/sink.py", 9)
        finding.evidence["owners"] = ["@security-team"]

        result = build_risk_paths([finding], artifacts)

        route = next(
            item for item in result["routes"] if item["target"]["kind"] == "finding"
        )
        ownership = route["ownership_context"]
        self.assertTrue(ownership["evidence_available"])
        self.assertEqual(ownership["ownership_rules"], 3)
        self.assertEqual(ownership["coordination_status"], "unowned-segment")
        self.assertEqual(
            ownership["distinct_owners"],
            ["@platform-team", "@security-team", "@service-team"],
        )
        self.assertEqual(ownership["target_owner_alignment"], "aligned")
        self.assertEqual(ownership["unowned_files"], ["src/worker.py"])
        self.assertEqual(ownership["boundary_count"], 3)
        handoffs = {
            (
                boundary["source"],
                boundary["target"],
                tuple(boundary["source_owners"]),
                tuple(boundary["target_owners"]),
            )
            for boundary in ownership["boundaries"]
        }
        self.assertEqual(
            handoffs,
            {
                (
                    "src/cli.py",
                    "src/service.py",
                    ("@platform-team",),
                    ("@service-team",),
                ),
                (
                    "src/service.py",
                    "src/sink.py",
                    ("@service-team",),
                    ("@security-team",),
                ),
                (
                    "src/worker.py",
                    "src/service.py",
                    (),
                    ("@service-team",),
                ),
            },
        )
        exposures = {
            item["entry_point"]["id"]: item for item in route["entry_point_exposures"]
        }
        self.assertEqual(
            [record["owners"] for record in exposures["entry:cli"]["ownership_path"]],
            [["@platform-team"], ["@service-team"], ["@security-team"]],
        )
        self.assertEqual(exposures["entry:worker"]["ownership_path"][0]["owners"], [])
        self.assertEqual(len(exposures["entry:worker"]["ownership_boundary_ids"]), 2)
        self.assertEqual(result["summary"]["routes_with_ownership_evidence"], 2)
        self.assertEqual(result["summary"]["routes_crossing_ownership_boundaries"], 2)
        self.assertEqual(result["summary"]["routes_with_unowned_segments"], 2)
        self.assertEqual(result["summary"]["ownership_boundaries"], 6)
        self.assertEqual(result["summary"]["distinct_route_owners"], 3)
        queues = {item["owner"]: item for item in result["owner_work_queues"]}
        self.assertEqual(
            set(queues),
            {"@platform-team", "@security-team", "@service-team", "Unassigned"},
        )
        security_queue = queues["@security-team"]
        self.assertEqual(
            security_queue["collaborating_owners"],
            ["@platform-team", "@service-team"],
        )
        self.assertEqual(security_queue["ownership_boundaries"], 3)
        self.assertEqual(security_queue["unowned_route_files"], ["src/worker.py"])
        self.assertIn("exact ownership handoff", security_queue["recommended_action"])
        self.assertIn("Assign CODEOWNERS", security_queue["recommended_action"])
        finding_context = finding.evidence["risk_path"]["ownership_context"]
        self.assertEqual(finding_context["coordination_status"], "unowned-segment")
        rendered = "\n".join(_render_risk_path_summary(result))
        self.assertIn("ownership unowned-segment", rendered)
        self.assertIn("unowned-segment", rendered)
        self.assertIn("@platform-team", rendered)
        markdown_context = "\n".join(_markdown_risk_path_context(finding))
        self.assertIn("Route ownership", markdown_context)
        self.assertIn("handoffs 3", markdown_context)
        self.assertIn("unowned files 1", _html_risk_path_context(finding))
        sarif = render_sarif([finding])
        sarif_ownership = sarif["runs"][0]["results"][0]["properties"]["risk_path"][
            "ownership_context"
        ]
        self.assertEqual(sarif_ownership["target_owner_alignment"], "aligned")
        closure = _finding_items([json_ready(finding)])[0]
        self.assertIn("finding-delta.json", closure["evidence_refs"])
        self.assertIn("src/worker.py", closure["evidence_refs"])
        self.assertEqual(
            closure["details"]["risk_path"]["ownership_context"]["boundary_count"],
            3,
        )
        self.assertTrue(
            any(
                "previously unowned" in criterion
                for criterion in closure["acceptance_criteria"]
            )
        )
        self.assertTrue(
            any(
                "ownership handoff" in criterion
                for criterion in closure["acceptance_criteria"]
            )
        )
        schema = json.loads(read_bundled_schema("risk-paths-1.0"))
        Draft202012Validator(schema).validate(result)

    def test_route_ownership_detects_target_owner_mismatch(self) -> None:
        artifacts = _artifacts()
        artifacts["finding-delta.json"] = {
            "schema_version": "1.1",
            "configured": False,
            "ownership_rule_details": [
                {"pattern": "src/*.py", "owners": ["@application-team"]},
            ],
        }
        finding = _finding("src/sink.py", 9)
        finding.evidence["owners"] = ["@security-team"]

        result = build_risk_paths([finding], artifacts)

        route = next(
            item for item in result["routes"] if item["target"]["kind"] == "finding"
        )
        self.assertEqual(
            route["ownership_context"]["target_owner_alignment"], "mismatch"
        )
        closure = _finding_items([json_ready(finding)])[0]
        self.assertTrue(
            any(
                "CODEOWNERS assignment agree" in criterion
                for criterion in closure["acceptance_criteria"]
            )
        )

    def test_cross_references_comparable_lifecycle_change_and_validation(self) -> None:
        artifacts = _artifacts()
        artifacts["finding-delta.json"] = {
            "schema_version": "1.1",
            "configured": True,
            "comparison": {"comparable": True, "reasons": []},
            "counts": {"new": 1, "existing": 0, "regression": 0, "resolved": 0},
        }
        finding = _finding("src/sink.py", 9)
        finding.evidence["owners"] = ["@security-team"]
        finding.evidence["fusion"] = {
            "corroboration": "independent",
            "source_context": {
                "changed_line": True,
                "line_covered": False,
                "coverage_percent": 55.5,
                "reachability_states": ["executable"],
                "runtime_observations": ["observed"],
            },
        }

        result = build_risk_paths([finding], artifacts)

        route = next(
            item for item in result["routes"] if item["target"]["kind"] == "finding"
        )
        attribution = route["change_lifecycle_attribution"]
        self.assertEqual(attribution["baseline_state"], "comparable")
        self.assertEqual(attribution["lifecycle_status"], "new")
        self.assertEqual(attribution["classification"], "baseline-new-on-changed-line")
        self.assertEqual(
            attribution["review_signal"],
            "baseline-new-or-regressed-change-gap",
        )
        self.assertEqual(
            attribution["entry_point_runtime_statuses"],
            {"observed": 1, "not-observed": 0, "not-available": 0},
        )
        self.assertIn("entry-runtime:observed:1", attribution["review_factors"])
        self.assertEqual(
            result["summary"]["routes_with_comparable_finding_lifecycle"], 1
        )
        self.assertEqual(result["summary"]["baseline_new_or_regressed_routes"], 1)
        self.assertEqual(
            result["summary"]["baseline_new_or_regressed_changed_routes"], 1
        )
        self.assertEqual(
            result["summary"][
                "baseline_new_or_regressed_changed_routes_with_validation_gaps"
            ],
            1,
        )
        queue = next(
            item
            for item in result["owner_work_queues"]
            if item["owner"] == "@security-team"
        )
        self.assertEqual(queue["baseline_new_or_regressed_changed_routes"], 1)
        self.assertEqual(
            queue["baseline_new_or_regressed_changed_routes_with_validation_gaps"],
            1,
        )
        self.assertIn("before release", queue["recommended_action"])
        self.assertEqual(
            finding.evidence["risk_path"]["change_lifecycle_attribution"][
                "classification"
            ],
            "baseline-new-on-changed-line",
        )
        rendered = "\n".join(_render_risk_path_summary(result))
        self.assertIn("Baseline-new or regressed routes on changed lines", rendered)
        self.assertIn("baseline-new-on-changed-line", rendered)
        markdown_context = "\n".join(_markdown_risk_path_context(finding))
        self.assertIn("Change/lifecycle attribution", markdown_context)
        self.assertIn("baseline-new-on-changed-line", markdown_context)
        self.assertIn("baseline-new-on-changed-line", _html_risk_path_context(finding))
        sarif = render_sarif([finding])
        sarif_attribution = sarif["runs"][0]["results"][0]["properties"]["risk_path"][
            "change_lifecycle_attribution"
        ]
        self.assertEqual(
            sarif_attribution["review_signal"],
            "baseline-new-or-regressed-change-gap",
        )
        closure = _finding_items([json_ready(finding)])[0]
        self.assertIn("finding-delta.json", closure["evidence_refs"])
        self.assertEqual(
            closure["details"]["risk_path"]["change_lifecycle_attribution"][
                "classification"
            ],
            "baseline-new-on-changed-line",
        )
        self.assertTrue(
            any(
                "baseline-new or regressed changed-line finding" in criterion
                for criterion in closure["acceptance_criteria"]
            )
        )
        schema = json.loads(read_bundled_schema("risk-paths-1.0"))
        Draft202012Validator(schema).validate(result)

    def test_change_lifecycle_attribution_fails_closed_without_comparison(self) -> None:
        scenarios = (
            (None, "not-established"),
            (
                {"schema_version": "1.0", "configured": False},
                "not-configured",
            ),
            (
                {
                    "schema_version": "1.1",
                    "configured": True,
                    "comparison": {
                        "comparable": False,
                        "reasons": ["scanner set differs"],
                    },
                },
                "incomparable",
            ),
        )
        for delta, expected in scenarios:
            with self.subTest(expected=expected):
                artifacts = _artifacts()
                if delta is not None:
                    artifacts["finding-delta.json"] = delta
                finding = _finding("src/sink.py", 9)
                finding.status = FindingStatus.NEW
                finding.evidence["fusion"] = {
                    "source_context": {"changed_line": True, "line_covered": False}
                }

                result = build_risk_paths([finding], artifacts)

                route = next(
                    item
                    for item in result["routes"]
                    if item["target"]["kind"] == "finding"
                )
                attribution = route["change_lifecycle_attribution"]
                self.assertEqual(attribution["baseline_state"], expected)
                self.assertEqual(
                    attribution["review_signal"], "baseline-not-established"
                )
                self.assertNotEqual(
                    attribution["classification"], "baseline-new-on-changed-line"
                )
                self.assertEqual(
                    result["summary"]["baseline_new_or_regressed_routes"], 0
                )
                self.assertEqual(
                    result["summary"]["routes_without_comparable_finding_lifecycle"],
                    1,
                )

    def test_distinguishes_regressed_and_modified_existing_finding_routes(self) -> None:
        scenarios = (
            (
                FindingStatus.REGRESSION,
                "regression-on-changed-line",
                "baseline-new-or-regressed-change-gap",
            ),
            (
                FindingStatus.EXISTING,
                "existing-on-changed-line",
                "existing-change-gap",
            ),
        )
        for status, classification, signal in scenarios:
            with self.subTest(status=status.value):
                artifacts = _artifacts()
                artifacts["finding-delta.json"] = {
                    "schema_version": "1.1",
                    "configured": True,
                    "comparison": {"comparable": True, "reasons": []},
                }
                finding = _finding("src/sink.py", 9)
                finding.status = status
                finding.evidence["baseline"] = {
                    "match_strategy": "exact",
                    "previous_finding_id": "PYSEC-PREVIOUS",
                    "previous_fingerprint": "f" * 64,
                    "previous_status": (
                        "resolved" if status is FindingStatus.REGRESSION else "new"
                    ),
                }
                finding.evidence["fusion"] = {
                    "source_context": {"changed_line": True, "line_covered": False}
                }

                result = build_risk_paths([finding], artifacts)

                route = next(
                    item
                    for item in result["routes"]
                    if item["target"]["kind"] == "finding"
                )
                attribution = route["change_lifecycle_attribution"]
                self.assertEqual(attribution["classification"], classification)
                self.assertEqual(attribution["review_signal"], signal)
                self.assertEqual(
                    attribution["baseline_match"]["previous_finding_id"],
                    "PYSEC-PREVIOUS",
                )
                if status is FindingStatus.EXISTING:
                    self.assertEqual(
                        result["summary"]["existing_finding_routes_at_changed_lines"],
                        1,
                    )
                else:
                    self.assertEqual(
                        result["summary"]["baseline_new_or_regressed_changed_routes"],
                        1,
                    )

    def test_route_evidence_assurance_fails_closed_by_exact_contributing_tool(
        self,
    ) -> None:
        scenarios = (
            ("approved", "completed", True, "assured"),
            ("approval-gap", "completed", False, "trust-gap"),
            ("execution-gap", "unavailable", True, "execution-gap"),
            ("not-applicable", "skipped", True, "execution-gap"),
            (None, None, None, "not-assessed"),
        )
        schema = json.loads(read_bundled_schema("risk-paths-1.0"))
        for assurance, status, approved, expected in scenarios:
            with self.subTest(expected=expected):
                artifacts = _artifacts()
                finding = _finding("src/sink.py", 9)
                finding.evidence["fusion"] = {
                    "corroboration": "independent",
                    "source_context": {},
                }
                posture = artifacts["effectiveness.json"]["tool_posture"]
                if assurance is None:
                    artifacts["effectiveness.json"]["tool_posture"] = [
                        item for item in posture if item["tool"] != "semgrep"
                    ]
                else:
                    record = next(item for item in posture if item["tool"] == "semgrep")
                    record["assurance_status"] = assurance
                    record["status"] = status
                    record["executable_organization_approved"] = approved

                result = build_risk_paths([finding], artifacts)
                route = next(
                    item
                    for item in result["routes"]
                    if item["target"]["kind"] == "finding"
                )

                self.assertEqual(route["evidence_assurance"]["review_status"], expected)
                self.assertEqual(
                    finding.evidence["risk_path"]["evidence_assurance"][
                        "review_status"
                    ],
                    expected,
                )
                if expected == "assured":
                    self.assertEqual(result["summary"]["assured_evidence_routes"], 1)
                elif expected == "trust-gap":
                    self.assertEqual(
                        result["summary"]["routes_with_tool_trust_gaps"], 2
                    )
                elif expected == "execution-gap":
                    self.assertEqual(
                        result["summary"]["routes_with_tool_execution_gaps"], 2
                    )
                else:
                    self.assertIn(
                        "semgrep", route["evidence_assurance"]["unassessed_tools"]
                    )
                Draft202012Validator(schema).validate(result)

    def test_campaign_revision_binding_distinguishes_aligned_and_mismatched_evidence(
        self,
    ) -> None:
        aligned_artifacts = _artifacts()
        aggregate = aligned_artifacts["source-inventory.json"]["source_sha256"]
        _bind_test_evidence(aligned_artifacts, aggregate)

        aligned = build_risk_paths([_finding("src/sink.py", 9)], aligned_artifacts)

        self.assertEqual(aligned["summary"]["campaigns_revision_aligned"], 2)
        self.assertEqual(aligned["summary"]["campaigns_revision_unbound"], 0)
        self.assertTrue(
            all(
                campaign["source_snapshot"]["evidence_revision_binding"] == "aligned"
                for campaign in aligned["validation_campaigns"]
            )
        )
        self.assertTrue(
            all(
                binding["binding_verified"]
                and binding["status"] == "aligned"
                and binding["evidence_sha256"]
                and binding["binding_file"]
                for campaign in aligned["validation_campaigns"]
                for binding in campaign["source_snapshot"]["evidence_source_bindings"]
            )
        )

        mismatched_artifacts = _artifacts()
        _bind_test_evidence(mismatched_artifacts, "f" * 64)

        mismatched = build_risk_paths(
            [_finding("src/sink.py", 9)], mismatched_artifacts
        )

        self.assertEqual(mismatched["summary"]["campaigns_revision_mismatched"], 2)
        self.assertTrue(
            all(
                campaign["source_snapshot"]["evidence_revision_binding"] == "mismatch"
                and campaign["recommended_action"].startswith("Discard mismatched")
                and any(
                    factor["id"] == "evidence-revision-mismatch"
                    for factor in campaign["review_factors"]
                )
                for campaign in mismatched["validation_campaigns"]
            )
        )
        schema = json.loads(read_bundled_schema("risk-paths-1.0"))
        Draft202012Validator(schema).validate(mismatched)

    def test_campaigns_fail_closed_when_route_scanner_assurance_is_not_met(
        self,
    ) -> None:
        artifacts = _artifacts()
        record = next(
            item
            for item in artifacts["effectiveness.json"]["tool_posture"]
            if item["tool"] == "semgrep"
        )
        record["assurance_status"] = "approval-gap"
        record["executable_organization_approved"] = False
        finding = _finding("src/sink.py", 9)

        result = build_risk_paths([finding], artifacts)

        self.assertEqual(result["summary"]["campaigns_with_assured_route_evidence"], 0)
        self.assertEqual(result["summary"]["campaigns_blocked_by_route_assurance"], 2)
        self.assertEqual(result["summary"]["campaigns_with_route_trust_gaps"], 2)
        for campaign in result["validation_campaigns"]:
            assurance = campaign["route_evidence_assurance"]
            self.assertEqual(assurance["assessment"], "trust-gap")
            self.assertFalse(assurance["tool_assurance_prerequisite_met"])
            self.assertEqual(assurance["trust_gap_tools"], ["semgrep"])
            self.assertEqual(assurance["routes_expected"], assurance["routes_assessed"])
            self.assertIn(
                "route-tool-trust-gap",
                {factor["id"] for factor in campaign["review_factors"]},
            )
            self.assertTrue(
                campaign["recommended_action"].startswith(
                    "Verify executable integrity and obtain organization approval"
                )
            )
        queue = result["owner_work_queues"][0]
        self.assertEqual(queue["campaigns_blocked_by_route_assurance"], 2)
        closure = _finding_items([json_ready(finding)])[0]
        closure_campaigns = closure["details"]["risk_path"]["validation_campaigns"]
        self.assertTrue(
            all(
                campaign["route_evidence_assurance"]["tool_assurance_prerequisite_met"]
                is False
                for campaign in closure_campaigns
            )
        )
        self.assertTrue(
            any(
                "organization-approved evidence" in criterion
                for criterion in closure["acceptance_criteria"]
            )
        )
        rendered = "\n".join(_render_risk_path_summary(result))
        self.assertIn("route evidence trust-gap", rendered)
        Draft202012Validator(
            json.loads(read_bundled_schema("risk-paths-1.0"))
        ).validate(result)

    def test_campaigns_distinguish_route_execution_and_unassessed_gaps(self) -> None:
        scenarios = (
            (
                "execution-gap",
                "route-tool-execution-gap",
                "execution_gap_tools",
                "Complete the exact contributing scanner runs",
            ),
            (
                "not-assessed",
                "route-tool-assurance-unassessed",
                "unassessed_tools",
                "Establish execution and trust posture",
            ),
        )
        for expected, factor_id, tool_key, action_start in scenarios:
            with self.subTest(expected=expected):
                artifacts = _artifacts()
                posture = artifacts["effectiveness.json"]["tool_posture"]
                record = next(item for item in posture if item["tool"] == "semgrep")
                if expected == "execution-gap":
                    record["status"] = "unavailable"
                    record["assurance_status"] = "execution-gap"
                else:
                    artifacts["effectiveness.json"]["tool_posture"] = [
                        item for item in posture if item["tool"] != "semgrep"
                    ]

                result = build_risk_paths([_finding("src/sink.py", 9)], artifacts)

                self.assertEqual(
                    result["summary"]["campaigns_blocked_by_route_assurance"], 2
                )
                for campaign in result["validation_campaigns"]:
                    assurance = campaign["route_evidence_assurance"]
                    self.assertEqual(assurance["assessment"], expected)
                    self.assertEqual(assurance[tool_key], ["semgrep"])
                    self.assertIn(
                        factor_id,
                        {factor["id"] for factor in campaign["review_factors"]},
                    )
                    self.assertTrue(
                        campaign["recommended_action"].startswith(action_start)
                    )

    def test_campaign_revision_binding_rejects_unverified_matching_digest(
        self,
    ) -> None:
        artifacts = _artifacts()
        aggregate = artifacts["source-inventory.json"]["source_sha256"]
        artifacts["coverage-summary.json"]["source_sha256"] = aggregate
        _bind_test_evidence_artifact(
            artifacts["junit-summary.json"],
            aggregate,
            evidence_sha256="e" * 64,
        )

        finding = _finding("src/sink.py", 9)
        result = build_risk_paths([finding], artifacts)

        self.assertEqual(result["summary"]["campaigns_revision_aligned"], 0)
        self.assertEqual(result["summary"]["campaigns_revision_mismatched"], 0)
        self.assertEqual(result["summary"]["campaigns_revision_unverified"], 2)
        self.assertEqual(result["summary"]["campaigns_revision_unbound"], 0)
        for campaign in result["validation_campaigns"]:
            snapshot = campaign["source_snapshot"]
            self.assertEqual(snapshot["evidence_revision_binding"], "unverified")
            coverage_binding = next(
                item
                for item in snapshot["evidence_source_bindings"]
                if item["artifact"] == "coverage-summary.json"
            )
            self.assertEqual(coverage_binding["status"], "unverified")
            self.assertFalse(coverage_binding["binding_verified"])
            self.assertIsNone(coverage_binding["evidence_sha256"])
            self.assertTrue(
                any(
                    factor["id"] == "evidence-binding-unverified"
                    for factor in campaign["review_factors"]
                )
            )
            self.assertIn("verified payload binding", campaign["recommended_action"])
        queue = result["owner_work_queues"][0]
        self.assertEqual(queue["campaigns_revision_unverified"], 2)
        self.assertIn(
            "lacks a verified payload-binding receipt", queue["recommended_action"]
        )
        rendered = "\n".join(_render_risk_path_summary(result))
        self.assertIn(
            "Campaign evidence digest-matched but binding-unverified", rendered
        )
        self.assertIn("mismatch/unverified/unbound `0/2/0`", rendered)
        self.assertIn("revision `unverified`", rendered)
        sarif = render_sarif([finding])
        sarif_campaigns = sarif["runs"][0]["results"][0]["properties"]["risk_path"][
            "validation_campaigns"
        ]
        self.assertTrue(
            all(
                campaign["source_snapshot"]["evidence_revision_binding"] == "unverified"
                for campaign in sarif_campaigns
            )
        )
        closure = _finding_items([json_ready(finding)])[0]
        closure_campaigns = closure["details"]["risk_path"]["validation_campaigns"]
        self.assertTrue(
            all(
                campaign["source_snapshot"]["evidence_source_bindings"]
                for campaign in closure_campaigns
            )
        )
        self.assertTrue(
            any(
                "producer-verified payload-binding receipt" in criterion
                for criterion in closure["acceptance_criteria"]
            )
        )
        schema = json.loads(read_bundled_schema("risk-paths-1.0"))
        Draft202012Validator(schema).validate(result)

    def test_entry_point_exposure_is_exact_and_bounded(self) -> None:
        artifacts = _artifacts()
        _add_multi_entry_paths(artifacts)

        with patch("py_security_suite.risk_paths._MAX_ENTRY_POINT_EXPOSURES", 1):
            result = build_risk_paths([_finding("src/sink.py", 9)], artifacts)

        routes = result["routes"]
        self.assertTrue(routes)
        self.assertTrue(
            all(route["entry_point_exposure_count"] == 3 for route in routes)
        )
        self.assertTrue(
            all(len(route["entry_point_exposures"]) == 1 for route in routes)
        )
        self.assertTrue(
            all(route["entry_point_exposures"][0]["primary"] for route in routes)
        )
        self.assertTrue(
            all(route["entry_point_exposures_omitted"] == 2 for route in routes)
        )
        self.assertEqual(
            result["summary"]["routes_with_entry_point_exposure_truncation"], 2
        )
        self.assertEqual(result["truncation"]["entry_point_exposures_omitted"], 4)
        retained_ids = {
            exposure["entry_point"]["id"]
            for route in routes
            for exposure in route["entry_point_exposures"]
        }
        self.assertNotIn("entry:unrelated", retained_ids)
        schema = json.loads(read_bundled_schema("risk-paths-1.0"))
        Draft202012Validator(schema).validate(result)

    def test_routes_dependency_advisories_through_exact_importers(self) -> None:
        finding = _finding("requirements.txt", 1)
        artifacts = _artifacts()
        _add_multi_entry_paths(artifacts)
        artifacts["evidence-fusion.json"] = {
            "schema_version": "1.3",
            "advisory_clusters": [_dependency_advisory_cluster()],
            "package_lineage": [
                _package_lineage("version-drift", ["1.0.0"], ["1.1.0"])
            ],
            "evidence_lanes": _composition_lanes(),
        }
        artifacts["structural-synthesis.json"]["change_impact_assessments"].append(
            {
                "path": "src/service.py",
                "classification": "changed-lines-under-tested",
                "priority": "high",
                "risk_score": 70,
                "changed_lines": 2,
                "uncovered_changed_lines": [4],
                "changed_line_coverage_percent": 50.0,
            }
        )
        service_coverage = artifacts["coverage-summary.json"]["files"][0]
        service_coverage["missing_lines"] = [4]
        service_coverage["summary"]["percent_covered"] = 90.0

        result = build_risk_paths([finding], artifacts)

        summary = result["summary"]
        self.assertEqual(summary["dependency_advisory_import_targets"], 1)
        self.assertEqual(summary["routed_dependency_advisory_imports"], 1)
        self.assertEqual(summary["unrouted_dependency_advisory_imports"], 0)
        self.assertEqual(summary["distinct_routed_dependency_advisories"], 1)
        self.assertEqual(summary["known_exploited_dependency_routes"], 1)
        self.assertEqual(summary["high_epss_dependency_routes"], 1)
        self.assertEqual(summary["dependency_routes_with_fixed_versions"], 1)
        self.assertEqual(summary["dependency_routes_with_validation_gaps"], 1)
        self.assertEqual(summary["dependency_routes_at_changed_importers"], 1)
        self.assertEqual(summary["dependency_routes_with_uncovered_changed_lines"], 1)
        self.assertEqual(
            summary["dependency_routes_with_comparable_package_lifecycle"], 1
        )
        self.assertEqual(summary["dependency_routes_with_version_drift"], 1)
        self.assertEqual(summary["dependency_routes_with_composition_evidence_gaps"], 0)
        route = next(
            item
            for item in result["routes"]
            if item["target"]["kind"] == "dependency-advisory-import"
        )
        self.assertEqual(route["target"]["path"], "src/service.py")
        self.assertIsNone(route["target"]["finding_id"])
        self.assertEqual(route["priority"], "P0")
        self.assertEqual(route["files"], ["src/cli.py", "src/service.py"])
        self.assertEqual(route["owners"], ["@import-owner"])
        self.assertEqual(route["correlations"]["import_lines"], [7])
        self.assertEqual(
            route["correlations"]["dependency_usage_assessment"],
            "executable-import",
        )
        self.assertEqual(route["validation"]["assessment_status"], "gap")
        self.assertEqual(
            route["validation"]["mapped_test_files"], ["tests/test_sink.py"]
        )
        self.assertEqual(
            route["correlations"]["advisory_cluster_id"], "ADV-ABCDEF123456"
        )
        self.assertEqual(
            route["correlations"]["related_finding_ids"], ["PYSEC-RISK-PATH"]
        )
        self.assertTrue(route["correlations"]["known_exploited"])
        self.assertEqual(route["correlations"]["fixed_version_candidates"], ["2.0.0"])
        self.assertEqual(route["correlations"]["change_risk_score"], 70)
        self.assertEqual(route["correlations"]["uncovered_changed_lines"], [4])
        self.assertEqual(route["entry_point_exposure_count"], 3)
        self.assertEqual(
            route["correlations"]["package_lifecycle"]["assessment"],
            "version-drift",
        )
        self.assertIn("evidence-fusion.json", route["evidence_artifacts"])

        risk_path = finding.evidence["risk_path"]
        self.assertEqual(risk_path["status"], "routed")
        self.assertEqual(risk_path["target_kind"], "dependency-advisory-import")
        self.assertEqual(risk_path["route_id"], route["route_id"])
        self.assertEqual(len(risk_path["dependency_advisory_routes"]), 1)
        self.assertEqual(
            risk_path["dependency_advisory_import_paths"], ["src/service.py"]
        )
        self.assertEqual(
            risk_path["dependency_advisory_cluster_ids"], ["ADV-ABCDEF123456"]
        )
        self.assertEqual(
            risk_path["dependency_advisory_routes"][0]["route_id"],
            route["route_id"],
        )
        self.assertEqual(
            risk_path["dependency_advisory_routes"][0]["entry_point_exposure_count"],
            3,
        )
        rendered = "\n".join(_render_risk_path_summary(result))
        self.assertIn("Routed dependency-advisory imports", rendered)
        self.assertIn("GHSA-DEMO-1234", rendered)
        self.assertIn("https://example.test/GHSA-DEMO-1234", rendered)
        self.assertIn("vulnerable-function invocation", rendered)
        self.assertIn("uncovered changed lines 4", rendered)
        self.assertIn("import lines `7`", rendered)
        self.assertIn("lifecycle version-drift", rendered)
        markdown_context = "\n".join(_markdown_risk_path_context(finding))
        self.assertIn("Dependency exposure routes", markdown_context)
        self.assertIn("src/service.py", markdown_context)
        html_context = _html_risk_path_context(finding)
        self.assertIn("Dependency exposure routes", html_context)
        self.assertIn("https://example.test/GHSA-DEMO-1234", html_context)
        sarif = render_sarif([finding])
        sarif_risk_path = sarif["runs"][0]["results"][0]["properties"]["risk_path"]
        self.assertEqual(
            sarif_risk_path["dependency_advisory_route_ids"], [route["route_id"]]
        )
        closure = _finding_items([json_ready(finding)])[0]
        closure_risk = closure["details"]["risk_path"]
        self.assertEqual(
            closure_risk["dependency_advisory_import_paths"], ["src/service.py"]
        )
        self.assertIn("evidence-fusion.json", closure["evidence_refs"])
        self.assertTrue(
            any(
                "vulnerable-function invocation" in criterion
                for criterion in closure["acceptance_criteria"]
            )
        )
        self.assertTrue(
            any(
                "uncovered changed line" in criterion
                for criterion in closure["acceptance_criteria"]
            )
        )
        self.assertTrue(
            any(
                "Dependency remediation validation covers every retained" in criterion
                for criterion in closure["acceptance_criteria"]
            )
        )
        self.assertTrue(
            any(
                "Source and built-artifact package versions agree" in criterion
                for criterion in closure["acceptance_criteria"]
            )
        )
        schema = json.loads(read_bundled_schema("risk-paths-1.0"))
        Draft202012Validator(schema).validate(result)

    def test_dependency_package_lifecycle_fails_closed_on_inventory_gaps(
        self,
    ) -> None:
        scenarios = [
            ("matched", ["1.0.0"], ["1.0.0"], True, True, "matched", True),
            (
                "version-drift",
                ["1.0.0"],
                ["2.0.0"],
                True,
                True,
                "version-drift",
                False,
            ),
            ("source-only", ["1.0.0"], [], True, True, "source-only", None),
            ("artifact-only", [], ["1.0.0"], True, True, "artifact-only", None),
            (
                "source-only",
                ["1.0.0"],
                [],
                True,
                False,
                "artifact-inventory-unavailable",
                None,
            ),
        ]
        schema = json.loads(read_bundled_schema("risk-paths-1.0"))
        for (
            status,
            source_versions,
            artifact_versions,
            source_available,
            artifact_available,
            expected,
            versions_match,
        ) in scenarios:
            with self.subTest(expected=expected, status=status):
                artifacts = _artifacts()
                artifacts["evidence-fusion.json"] = {
                    "schema_version": "1.3",
                    "advisory_clusters": [_dependency_advisory_cluster()],
                    "package_lineage": [
                        _package_lineage(status, source_versions, artifact_versions)
                    ],
                    "evidence_lanes": _composition_lanes(
                        source=source_available,
                        artifact=artifact_available,
                    ),
                }

                result = build_risk_paths([_finding("requirements.txt", 1)], artifacts)

                route = next(
                    item
                    for item in result["routes"]
                    if item["target"]["kind"] == "dependency-advisory-import"
                )
                lifecycle = route["correlations"]["package_lifecycle"]
                self.assertEqual(lifecycle["assessment"], expected)
                self.assertEqual(
                    lifecycle["source_artifact_versions_match"], versions_match
                )
                self.assertEqual(
                    lifecycle["comparison_available"],
                    source_available and artifact_available,
                )
                if artifact_versions == ["2.0.0"]:
                    self.assertTrue(lifecycle["artifact_fixed_version_exact_match"])
                    self.assertEqual(
                        result["summary"][
                            "dependency_routes_with_exact_fixed_version_in_artifact"
                        ],
                        1,
                    )
                if expected == "artifact-inventory-unavailable":
                    self.assertEqual(
                        result["summary"][
                            "dependency_routes_source_only_in_comparable_inventory"
                        ],
                        0,
                    )
                    self.assertEqual(
                        result["summary"][
                            "dependency_routes_with_composition_evidence_gaps"
                        ],
                        1,
                    )
                Draft202012Validator(schema).validate(result)

        artifacts = _artifacts()
        artifacts["evidence-fusion.json"] = {
            "schema_version": "1.3",
            "advisory_clusters": [_dependency_advisory_cluster()],
            "package_lineage": [],
            "evidence_lanes": _composition_lanes(),
        }
        absent = build_risk_paths([_finding("requirements.txt", 1)], artifacts)
        absent_route = next(
            item
            for item in absent["routes"]
            if item["target"]["kind"] == "dependency-advisory-import"
        )
        self.assertEqual(
            absent_route["correlations"]["package_lifecycle"]["assessment"],
            "package-not-observed",
        )
        Draft202012Validator(schema).validate(absent)

    def test_dependency_routes_do_not_share_importer_validation_or_owners(
        self,
    ) -> None:
        artifacts = _artifacts()
        cluster = _dependency_advisory_cluster()
        usage = cluster["dependency_usage"]
        usage["import_paths"] = ["src/service.py", "src/sink.py"]
        usage["import_path_assessments"] = [
            _import_path_assessment(
                "src/service.py",
                owners=["@service-owner"],
                tests=["tests/test_sink.py"],
                coverage_percent=100.0,
                alignment="aligned-current-evidence",
                gap_reasons=[],
            ),
            _import_path_assessment(
                "src/sink.py",
                owners=[],
                tests=[],
                coverage_percent=55.5,
                alignment="coverage-gap",
                gap_reasons=["Exact importer coverage is below 80%."],
            ),
        ]
        artifacts["evidence-fusion.json"] = {
            "schema_version": "1.3",
            "advisory_clusters": [cluster],
            "package_lineage": [_package_lineage("artifact-only", [], ["1.0.0"])],
            "evidence_lanes": _composition_lanes(),
        }

        result = build_risk_paths([_finding("requirements.txt", 1)], artifacts)

        routes = {
            route["target"]["path"]: route
            for route in result["routes"]
            if route["target"]["kind"] == "dependency-advisory-import"
        }
        service = routes["src/service.py"]
        sink = routes["src/sink.py"]
        self.assertEqual(service["owners"], ["@service-owner"])
        self.assertEqual(service["validation"]["assessment_status"], "aligned")
        self.assertEqual(
            service["validation"]["mapped_test_files"], ["tests/test_sink.py"]
        )
        self.assertEqual(sink["owners"], [])
        self.assertEqual(sink["validation"]["assessment_status"], "gap")
        self.assertEqual(sink["validation"]["mapped_test_files"], [])
        self.assertEqual(
            sink["validation"]["gap_reasons"],
            ["Exact importer coverage is below 80%."],
        )
        self.assertIn("Add a focused test", sink["recommended_action"])
        self.assertEqual(result["summary"]["dependency_routes_with_validation_gaps"], 1)
        schema = json.loads(read_bundled_schema("risk-paths-1.0"))
        Draft202012Validator(schema).validate(result)

    def test_joins_sensitive_sdk_sink_to_exact_advisory_importer(self) -> None:
        finding = _finding("requirements.txt", 1)
        artifacts = _artifacts()
        _add_multi_entry_paths(artifacts)
        cluster = _dependency_advisory_cluster()
        usage = cluster["dependency_usage"]
        usage["import_paths"] = ["src/sink.py"]
        usage["import_path_assessments"] = [
            _import_path_assessment(
                "src/sink.py",
                owners=["@observability"],
                tests=["tests/test_sink.py"],
                coverage_percent=55.5,
                alignment="coverage-gap",
                gap_reasons=["Exact SDK importer coverage is below 80%."],
            )
        ]
        artifacts["evidence-fusion.json"] = {
            "schema_version": "1.3",
            "advisory_clusters": [cluster],
            "package_lineage": [_package_lineage("artifact-only", [], ["1.0.0"])],
            "evidence_lanes": _composition_lanes(),
        }
        surface = artifacts["data-exposure.json"]["sink_surfaces"][0]
        surface["sdk"] = "Sentry SDK"
        surface["trust_boundary"] = "external-observability"
        surface["sdk_dependency_context"] = {
            "risk_present": True,
            "risk_tier": "high",
            "advisory_clusters": [cluster],
        }

        result = build_risk_paths([finding], artifacts)

        self.assertEqual(result["summary"]["exposure_advisory_intersections"], 1)
        self.assertEqual(
            result["summary"]["known_exploited_exposure_advisory_intersections"],
            1,
        )
        self.assertEqual(
            result["summary"]["unprotected_exposure_advisory_intersections"], 1
        )
        self.assertEqual(
            result["summary"]["exposure_advisory_intersections_with_validation_gaps"],
            1,
        )
        intersection = result["exposure_advisory_intersections"][0]
        self.assertEqual(intersection["path"], "src/sink.py")
        self.assertEqual(intersection["line"], 9)
        self.assertEqual(intersection["package"], "demo-package")
        self.assertEqual(intersection["sdk"], "Sentry SDK")
        self.assertEqual(intersection["trust_boundary"], "external-observability")
        self.assertEqual(intersection["protection_status"], "not-observed")
        self.assertEqual(intersection["data_classes"], ["credential"])
        self.assertTrue(intersection["known_exploited"])
        self.assertEqual(intersection["validation_statuses"]["dependency"], "gap")
        self.assertEqual(intersection["entry_point_exposure_count"], 3)
        self.assertEqual(
            intersection["entry_point_runtime_statuses"],
            {"observed": 1, "not-observed": 1, "not-available": 1},
        )
        self.assertEqual(
            intersection["entry_point_ids"],
            ["entry:cli", "entry:cli-module", "entry:worker"],
        )
        self.assertEqual(
            intersection["package_lifecycle"]["assessment"], "artifact-only"
        )
        self.assertEqual(len(intersection["route_ids"]), 2)
        intersecting_routes = [
            route
            for route in result["routes"]
            if intersection["intersection_id"]
            in route["exposure_advisory_intersection_ids"]
        ]
        self.assertEqual(
            {route["target"]["kind"] for route in intersecting_routes},
            {"sink-surface", "dependency-advisory-import"},
        )
        intersection_queues = [
            queue
            for queue in result["owner_work_queues"]
            if intersection["intersection_id"]
            in queue["exposure_advisory_intersection_ids"]
        ]
        self.assertEqual(
            {queue["owner"] for queue in intersection_queues},
            {"@observability", "@security-team"},
        )
        self.assertTrue(
            all(
                queue["exposure_advisory_intersections"] == 1
                for queue in intersection_queues
            )
        )
        self.assertEqual(
            result["summary"]["owner_queues_with_exposure_advisory_intersections"],
            2,
        )
        self.assertTrue(
            all(
                "boundary controls and dependency remediation"
                in queue["recommended_action"]
                for queue in intersection_queues
            )
        )
        risk_path = finding.evidence["risk_path"]
        self.assertEqual(
            risk_path["exposure_advisory_intersection_ids"],
            [intersection["intersection_id"]],
        )
        self.assertEqual(
            risk_path["exposure_advisory_intersections"][0]["package"],
            "demo-package",
        )
        self.assertEqual(
            risk_path["exposure_advisory_intersections"][0][
                "entry_point_exposure_count"
            ],
            3,
        )
        rendered = "\n".join(_render_risk_path_summary(result))
        self.assertIn("Sensitive-boundary dependency intersections", rendered)
        self.assertIn("external-observability", rendered)
        self.assertIn("not prove sensitive data reached the SDK", rendered)
        self.assertIn("lifecycle artifact-only", rendered)
        markdown = "\n".join(_markdown_risk_path_context(finding))
        self.assertIn("Sensitive-boundary dependency intersection", markdown)
        html = _html_risk_path_context(finding)
        self.assertIn("Sensitive-boundary dependency intersection", html)
        sarif = render_sarif([finding])
        sarif_risk = sarif["runs"][0]["results"][0]["properties"]["risk_path"]
        self.assertEqual(
            sarif_risk["exposure_advisory_intersection_ids"],
            [intersection["intersection_id"]],
        )
        closure = _finding_items([json_ready(finding)])[0]
        closure_risk = closure["details"]["risk_path"]
        self.assertEqual(
            closure_risk["exposure_advisory_intersection_ids"],
            [intersection["intersection_id"]],
        )
        self.assertTrue(
            any(
                "data minimization" in criterion
                for criterion in closure["acceptance_criteria"]
            )
        )
        schema = json.loads(read_bundled_schema("risk-paths-1.0"))
        Draft202012Validator(schema).validate(result)

    def test_sensitive_data_routes_join_entry_boundary_assurance_and_validation(
        self,
    ) -> None:
        finding = _finding("src/sink.py", 9)
        finding.evidence["data_exposure"] = {
            "concern": "sensitive-information-in-logs",
            "sink_family": "logging",
            "sink": "logger.info",
            "sdk": "structlog",
            "confidence": "high",
            "data_classes": ["credential", "private-data"],
            "trust_boundary": "persistent-log-storage",
            "protection_status": "not-observed",
            "risk_factors": ["credential-material", "persistent-destination"],
            "review_priority": "high",
        }
        finding.citations.append(
            Citation(
                kind="standard",
                identifier="CWE-532",
                title="Insertion of Sensitive Information into Log File",
                uri="https://cwe.mitre.org/data/definitions/532.html",
            )
        )
        artifacts = _artifacts()
        artifacts["data-exposure.json"]["standards"] = [
            {
                "identifier": "CWE-201",
                "title": "Insertion of Sensitive Information Into Sent Data",
                "uri": "https://cwe.mitre.org/data/definitions/201.html",
            },
            {
                "identifier": "OTEL-SENSITIVE-DATA",
                "title": "OpenTelemetry handling sensitive data",
                "uri": "https://opentelemetry.io/docs/security/handling-sensitive-data/",
            },
        ]

        with patch("py_security_suite.risk_paths._MAX_SENSITIVE_DATA_ROUTES", 1):
            result = build_risk_paths([finding], artifacts)

        self.assertEqual(result["summary"]["sensitive_data_routes"], 2)
        self.assertEqual(
            result["summary"]["scanner_confirmed_sensitive_data_routes"], 1
        )
        self.assertEqual(result["summary"]["inventory_sensitive_data_routes"], 1)
        self.assertEqual(len(result["sensitive_data_routes"]), 1)
        self.assertEqual(result["truncation"]["sensitive_data_routes_omitted"], 1)
        self.assertEqual(
            result["summary"]["sensitive_data_routes_without_observed_protection"],
            2,
        )
        self.assertEqual(
            result["summary"][
                "sensitive_data_routes_with_runtime_observed_entry_points"
            ],
            2,
        )
        self.assertEqual(
            result["summary"]["sensitive_data_routes_with_validation_gaps"], 1
        )
        self.assertEqual(
            result["summary"]["sensitive_data_routes_with_assurance_gaps"], 2
        )
        self.assertEqual(result["summary"]["sensitive_data_routes_with_citations"], 2)
        self.assertEqual(
            result["summary"]["sensitive_data_routes_without_citations"], 0
        )
        confirmed = next(
            item
            for item in result["sensitive_data_routes"]
            if item["evidence_basis"] == "scanner-confirmed-source-to-sink"
        )
        self.assertEqual(confirmed["finding_id"], finding.finding_id)
        self.assertEqual(confirmed["sink_family"], "logging")
        self.assertEqual(confirmed["sink"], "logger.info")
        self.assertEqual(confirmed["sdk"], "structlog")
        self.assertEqual(confirmed["data_classes"], ["credential", "private-data"])
        self.assertEqual(confirmed["trust_boundary"], "persistent-log-storage")
        self.assertEqual(confirmed["protection_status"], "not-observed")
        self.assertEqual(
            confirmed["citations"],
            [
                {
                    "kind": "standard",
                    "identifier": "CWE-532",
                    "title": "Insertion of Sensitive Information into Log File",
                    "uri": "https://cwe.mitre.org/data/definitions/532.html",
                }
            ],
        )
        self.assertEqual(confirmed["entry_point_ids"], ["entry:cli"])
        self.assertEqual(
            confirmed["entry_point_runtime_statuses"],
            {"observed": 1, "not-observed": 0, "not-available": 0},
        )
        self.assertEqual(
            finding.evidence["risk_path"]["sensitive_data_route"]["sensitive_route_id"],
            confirmed["sensitive_route_id"],
        )
        rendered = "\n".join(_render_risk_path_summary(result))
        self.assertIn("End-to-end sensitive-data routes", rendered)
        self.assertIn("scanner-confirmed-source-to-sink", rendered)
        self.assertIn("CWE-532", rendered)
        inventory_route = next(
            item
            for item in result["routes"]
            if item["target"]["kind"] == "sink-surface"
        )
        self.assertEqual(
            [
                item["identifier"]
                for item in inventory_route["correlations"]["citations"]
            ],
            ["CWE-201", "OTEL-SENSITIVE-DATA"],
        )
        markdown = "\n".join(_markdown_risk_path_context(finding))
        self.assertIn("End-to-end sensitive-data route", markdown)
        self.assertIn(
            "[CWE-532](https://cwe.mitre.org/data/definitions/532.html)", markdown
        )
        self.assertIn("not proof of disclosure", markdown)
        html = _html_risk_path_context(finding)
        self.assertIn("End-to-end sensitive-data route", html)
        self.assertIn("CWE-532", html)
        sarif_route = render_sarif([finding])["runs"][0]["results"][0]["properties"][
            "risk_path"
        ]["sensitive_data_route"]
        self.assertEqual(sarif_route["citations"], confirmed["citations"])
        closure = _finding_items([json_ready(finding)])[0]
        closure_route = closure["details"]["risk_path"]["sensitive_data_route"]
        self.assertEqual(
            closure_route["sensitive_route_id"], confirmed["sensitive_route_id"]
        )
        self.assertIn("data-exposure.json", closure["evidence_refs"])
        self.assertEqual(closure_route["citations"], confirmed["citations"])
        self.assertTrue(
            any(
                "synthetic sensitive canaries" in criterion
                for criterion in closure["acceptance_criteria"]
            )
        )
        Draft202012Validator(
            json.loads(read_bundled_schema("risk-paths-1.0"))
        ).validate(result)

    def test_sensitive_data_route_surfaces_missing_citation_as_closure_gap(
        self,
    ) -> None:
        finding = _finding("src/sink.py", 9)
        finding.evidence["data_exposure"] = {
            "concern": "sensitive-information-in-logs",
            "sink_family": "logging",
            "sink": "logger.info",
            "confidence": "high",
            "data_classes": ["credential"],
            "trust_boundary": "persistent-log-storage",
            "protection_status": "not-observed",
            "risk_factors": ["credential-material"],
            "review_priority": "high",
        }

        result = build_risk_paths([finding], _artifacts())

        self.assertEqual(result["summary"]["sensitive_data_routes_with_citations"], 0)
        self.assertEqual(
            result["summary"]["sensitive_data_routes_without_citations"], 2
        )
        self.assertEqual(
            finding.evidence["risk_path"]["sensitive_data_route"]["citations"], []
        )
        closure = _finding_items([json_ready(finding)])[0]
        self.assertTrue(
            any(
                "security-practice citation" in criterion
                for criterion in closure["acceptance_criteria"]
            )
        )
        Draft202012Validator(
            json.loads(read_bundled_schema("risk-paths-1.0"))
        ).validate(result)

    def test_secret_provenance_joins_content_history_assurance_and_closure(
        self,
    ) -> None:
        production = _secret_finding(
            "PYSEC-SECRET-PRODUCTION",
            "src/sink.py",
            9,
            tool="trufflehog",
            native_severity="verified",
            evidence={"redacted": True, "verified": True},
        )
        generated = _secret_finding(
            "PYSEC-SECRET-GENERATED",
            "junit.xml.pysec-binding.json",
            1,
            tool="detect-secrets",
            native_severity="potential-secret",
            evidence={"redacted": True},
        )
        history = _secret_finding(
            "PYSEC-SECRET-HISTORY",
            ".env.example",
            2,
            area="secrets-history",
            tool="gitleaks",
            native_severity="secret",
            evidence={
                "redacted": True,
                "scan_mode": "git",
                "commit": "a" * 40,
            },
        )

        result = build_risk_paths([production, generated, history], _artifacts())

        summary = result["summary"]
        self.assertEqual(summary["secret_candidates"], 3)
        self.assertEqual(summary["secret_candidates_assessed"], 3)
        self.assertEqual(summary["production_source_secret_candidates"], 1)
        self.assertEqual(summary["generated_evidence_secret_candidates"], 1)
        self.assertEqual(summary["repository_control_secret_candidates"], 1)
        self.assertEqual(summary["history_secret_candidates"], 1)
        self.assertEqual(summary["verified_secret_candidates"], 1)
        self.assertEqual(summary["secret_candidates_without_verification"], 2)
        self.assertEqual(summary["secret_candidates_without_redaction_marker"], 0)
        self.assertEqual(
            result["truncation"]["secret_provenance_assessments_omitted"], 0
        )
        by_id = {
            item["finding_id"]: item for item in result["secret_provenance_assessments"]
        }
        production_context = by_id[production.finding_id]
        self.assertEqual(production_context["content_lane"], "python-runtime-source")
        self.assertEqual(production_context["route_status"], "routed")
        self.assertEqual(production_context["verification_status"], "verified")
        self.assertEqual(
            production_context["review_disposition"], "production-source-review"
        )
        generated_context = by_id[generated.finding_id]
        self.assertEqual(generated_context["content_lane"], "generated-evidence")
        self.assertEqual(generated_context["route_status"], "unrouted")
        self.assertFalse(generated_context["source_inventory_member"])
        self.assertIn(
            "deterministic digest/receipt", generated_context["recommended_action"]
        )
        history_context = by_id[history.finding_id]
        self.assertEqual(history_context["history_status"], "history-evidence")
        self.assertEqual(history_context["history_commit"], "a" * 40)
        self.assertIn("current tree alone", history_context["recommended_action"])
        self.assertEqual(
            generated.evidence["secret_provenance"]["secret_context_id"],
            generated_context["secret_context_id"],
        )
        self.assertTrue(
            any(
                citation.identifier == "pysec-secret-provenance"
                for citation in generated.citations
            )
        )
        rendered = "\n".join(_render_risk_path_summary(result))
        self.assertIn("Secret candidate provenance", rendered)
        self.assertIn("generated-evidence-review", rendered)
        markdown = "\n".join(_markdown_risk_path_context(generated))
        self.assertNotIn("Secret candidate provenance", markdown)
        report_context = "\n".join(_markdown_secret_provenance_context(generated))
        self.assertIn("Secret candidate provenance", report_context)
        self.assertIn("not an automatic false-positive", report_context)
        html = _html_secret_provenance_context(generated)
        self.assertIn("Secret candidate provenance", html)
        sarif = render_sarif([generated])
        self.assertEqual(
            sarif["runs"][0]["results"][0]["properties"]["secret_provenance"][
                "secret_context_id"
            ],
            generated_context["secret_context_id"],
        )
        closure = _finding_items([json_ready(generated)])[0]
        self.assertEqual(
            closure["details"]["secret_provenance"]["content_lane"],
            "generated-evidence",
        )
        self.assertIn("source-inventory.json", closure["evidence_refs"])
        self.assertTrue(
            any(
                "deterministic evidence" in criterion
                for criterion in closure["acceptance_criteria"]
            )
        )
        self.assertNotIn("must-not-be-retained", json.dumps(json_ready(result)))
        Draft202012Validator(
            json.loads(read_bundled_schema("risk-paths-1.0"))
        ).validate(result)

    def test_secret_provenance_bound_is_explicit(self) -> None:
        findings = [
            _secret_finding(
                f"PYSEC-SECRET-{index}",
                f"tests/test_secret_{index}.py",
                1,
                tool="detect-secrets",
                native_severity="potential-secret",
                evidence={"redacted": True},
            )
            for index in range(2)
        ]

        with patch(
            "py_security_suite.risk_paths._MAX_SECRET_PROVENANCE_ASSESSMENTS", 1
        ):
            result = build_risk_paths(findings, _artifacts())

        self.assertEqual(result["summary"]["secret_candidates"], 2)
        self.assertEqual(result["summary"]["secret_candidates_assessed"], 2)
        self.assertEqual(len(result["secret_provenance_assessments"]), 1)
        self.assertEqual(
            result["truncation"]["secret_provenance_assessments_omitted"], 1
        )

    def test_exposure_advisory_intersection_requires_exact_path_and_package(
        self,
    ) -> None:
        artifacts = _artifacts()
        cluster = _dependency_advisory_cluster()
        surface = artifacts["data-exposure.json"]["sink_surfaces"][0]
        surface["sdk"] = "Sentry SDK"
        surface["data_classes"] = []
        surface["review_priority"] = "medium"
        surface["structural_context"]["related_finding_ids"] = []
        surface["sdk_dependency_context"] = {
            "risk_present": True,
            "risk_tier": "high",
            "advisory_clusters": [cluster],
        }
        artifacts["evidence-fusion.json"] = {
            "schema_version": "1.3",
            "advisory_clusters": [cluster],
        }

        path_mismatch = build_risk_paths([_finding("requirements.txt", 1)], artifacts)

        self.assertEqual(path_mismatch["summary"]["exposure_advisory_intersections"], 0)
        self.assertEqual(path_mismatch["summary"]["sink_surface_targets"], 1)

        usage = cluster["dependency_usage"]
        usage["import_paths"] = ["src/sink.py"]
        usage["import_path_assessments"] = [
            _import_path_assessment(
                "src/sink.py",
                owners=[],
                tests=[],
                coverage_percent=55.5,
                alignment="coverage-gap",
                gap_reasons=["Coverage gap."],
            )
        ]
        surface["sdk_dependency_context"]["risk_present"] = False

        unconfirmed_risk = build_risk_paths(
            [_finding("requirements.txt", 1)], artifacts
        )

        self.assertEqual(
            unconfirmed_risk["summary"]["exposure_advisory_intersections"], 0
        )
        mismatched_cluster = json.loads(json.dumps(cluster))
        mismatched_cluster["package"] = "different-package"
        surface["sdk_dependency_context"]["risk_present"] = True
        surface["sdk_dependency_context"]["advisory_clusters"] = [mismatched_cluster]

        package_mismatch = build_risk_paths(
            [_finding("requirements.txt", 1)], artifacts
        )

        self.assertEqual(
            package_mismatch["summary"]["exposure_advisory_intersections"], 0
        )
        schema = json.loads(read_bundled_schema("risk-paths-1.0"))
        Draft202012Validator(schema).validate(package_mismatch)

    def test_unrouted_target_is_preserved_as_an_evidence_gap(self) -> None:
        finding = _finding("src/dynamic_plugin.py", 4)
        artifacts = _artifacts()

        result = build_risk_paths([finding], artifacts)

        self.assertEqual(result["summary"]["routed_targets"], 1)
        self.assertEqual(result["summary"]["unrouted_targets"], 1)
        self.assertEqual(result["summary"]["validation_unassessed_routes"], 0)
        record = result["unrouted_targets"][0]
        self.assertEqual(record["target"]["finding_id"], "PYSEC-RISK-PATH")
        self.assertIn("absent from the retained Graphify", record["reason"])
        self.assertEqual(
            record["route_applicability"]["classification"],
            "python-runtime-source",
        )
        self.assertTrue(result["summary"]["unrouted_targets_missing_graph_membership"])
        self.assertEqual(finding.evidence["risk_path"]["status"], "unrouted")
        self.assertIn("not proof", "\n".join(_render_risk_path_summary(result)))

    def test_unrouted_targets_are_dispositioned_by_native_evidence_lane(
        self,
    ) -> None:
        def candidate(path: str, identifier: str) -> Finding:
            finding = _finding(path, 1)
            finding.finding_id = identifier
            finding.fingerprint = "sha256:" + identifier.casefold()
            return finding

        artifact = candidate("src/sink.py", "PYSEC-ARTIFACT")
        artifact.area = "artifact-source-parity"
        artifact.sources = [
            Source(
                tool="check-wheel-contents",
                rule_id="WHEEL-SOURCE-PARITY",
                message="mismatch",
            )
        ]
        generated = candidate("coverage.json", "PYSEC-GENERATED")
        binding_receipt = candidate(
            "coverage.json.pysec-binding.json", "PYSEC-BINDING-RECEIPT"
        )
        test_source = candidate("tests/test_sink.py", "PYSEC-TEST")
        repository_control = candidate("pyproject.toml", "PYSEC-CONFIG")
        python_gap = candidate("src/dynamic_plugin.py", "PYSEC-PYTHON-GAP")
        findings = [
            artifact,
            generated,
            binding_receipt,
            test_source,
            repository_control,
            python_gap,
        ]
        artifacts = _artifacts()
        artifacts.pop("data-exposure.json", None)
        artifacts.pop("evidence-fusion.json", None)
        artifacts["artifact-manifest.json"] = {
            "schema_version": "1.0",
            "artifacts": [
                {"path": "dist/example.whl", "sha256": "f" * 64, "size_bytes": 1}
            ],
        }

        result = build_risk_paths(findings, artifacts)

        self.assertEqual(result["summary"]["route_applicable_targets"], 1)
        self.assertEqual(result["summary"]["route_not_applicable_targets"], 5)
        self.assertEqual(result["summary"]["unrouted_route_applicable_targets"], 1)
        self.assertEqual(result["summary"]["unrouted_expected_non_runtime_targets"], 5)
        self.assertEqual(
            result["summary"]["unrouted_by_applicability_class"],
            {
                "python-runtime-source": 1,
                "artifact-control": 1,
                "generated-evidence": 2,
                "test-validation-source": 1,
                "outside-python-runtime-model": 1,
            },
        )
        by_id = {
            item["target"]["finding_id"]: item for item in result["unrouted_targets"]
        }
        self.assertEqual(
            by_id["PYSEC-ARTIFACT"]["route_applicability"]["classification"],
            "artifact-control",
        )
        self.assertEqual(
            by_id["PYSEC-GENERATED"]["route_applicability"]["classification"],
            "generated-evidence",
        )
        self.assertEqual(
            by_id["PYSEC-BINDING-RECEIPT"]["route_applicability"]["classification"],
            "generated-evidence",
        )
        self.assertEqual(
            by_id["PYSEC-TEST"]["route_applicability"]["classification"],
            "test-validation-source",
        )
        self.assertEqual(
            by_id["PYSEC-CONFIG"]["route_applicability"]["classification"],
            "outside-python-runtime-model",
        )
        self.assertIn(
            "do not add a Python entry point",
            by_id["PYSEC-ARTIFACT"]["recommended_action"],
        )
        closure = _finding_items([json_ready(artifact)])[0]
        self.assertEqual(
            closure["details"]["risk_path"]["route_applicability"]["classification"],
            "artifact-control",
        )
        self.assertTrue(
            any(
                "native evidence lane" in criterion
                for criterion in closure["acceptance_criteria"]
            )
        )
        rendered = "\n".join(_render_risk_path_summary(result))
        self.assertIn("Actionable Python route gaps", rendered)
        self.assertIn("artifact-control", rendered)
        finding_context = "\n".join(_markdown_risk_path_context(artifact))
        self.assertIn("native evidence lane", finding_context)
        self.assertNotIn("entry point..", finding_context)
        self.assertNotIn("entry point..", _html_risk_path_context(artifact))
        Draft202012Validator(
            json.loads(read_bundled_schema("risk-paths-1.0"))
        ).validate(result)

    def test_dependency_import_target_bound_reports_exact_omissions(self) -> None:
        artifacts = _artifacts()
        cluster = _dependency_advisory_cluster()
        usage = cluster["dependency_usage"]
        usage["import_paths"] = [
            "src/service.py",
            "src/sink.py",
            "src/third_importer.py",
        ]
        artifacts["evidence-fusion.json"] = {
            "schema_version": "1.3",
            "advisory_clusters": [cluster],
        }

        with patch("py_security_suite.risk_paths._MAX_TARGETS", 2):
            result = build_risk_paths([_finding("src/sink.py", 9)], artifacts)

        self.assertEqual(result["summary"]["dependency_advisory_import_targets"], 3)
        self.assertEqual(
            result["truncation"]["dependency_advisory_import_targets_omitted"], 1
        )
        self.assertEqual(result["summary"]["candidate_targets"], 5)
        self.assertEqual(result["summary"]["targets_analyzed"], 2)
        self.assertEqual(result["truncation"]["targets_omitted"], 3)
        schema = json.loads(read_bundled_schema("risk-paths-1.0"))
        Draft202012Validator(schema).validate(result)

    def test_missing_graph_and_entry_points_do_not_claim_clean_routes(self) -> None:
        finding = _finding("src/sink.py", 9)

        result = build_risk_paths([finding], {})

        self.assertFalse(result["summary"]["graph_available"])
        self.assertFalse(result["summary"]["reachability_available"])
        self.assertEqual(result["summary"]["routed_targets"], 0)
        self.assertEqual(result["summary"]["unrouted_targets"], 1)
        self.assertEqual(result["summary"]["validation_assessed_routes"], 0)
        self.assertEqual(result["summary"]["validation_unassessed_routes"], 0)
        self.assertEqual(
            result["unrouted_targets"][0]["reason"],
            "declared entry-point evidence is unavailable",
        )
        schema = json.loads(read_bundled_schema("risk-paths-1.0"))
        Draft202012Validator(schema).validate(result)

    def test_declared_same_file_entry_route_does_not_require_graphify(self) -> None:
        finding = _finding("src/sink.py", 9)
        artifacts = {
            "reachability.json": {
                "schema_version": "1.2",
                "entry_points": [
                    {
                        "id": "entry:sink",
                        "kind": "project-scripts",
                        "declared_as": "example.sink:main",
                        "path": "src/sink.py",
                        "line": 1,
                    }
                ],
                "nodes": [],
            }
        }

        result = build_risk_paths([finding], artifacts)

        self.assertEqual(result["summary"]["routed_targets"], 1)
        route = result["routes"][0]
        self.assertEqual(route["hop_count"], 0)
        self.assertEqual(route["files"], ["src/sink.py"])
        self.assertNotIn("graphify.json", route["evidence_artifacts"])
        self.assertEqual(route["validation"]["assessment_status"], "not-assessed")

    def test_available_but_inconclusive_evidence_is_partial_not_aligned(self) -> None:
        finding = _finding("src/sink.py", 9)
        finding.evidence["fusion"] = {
            "source_context": {
                "changed_line": False,
                "line_covered": None,
            }
        }

        result = build_risk_paths([finding], _artifacts())

        route = next(
            item for item in result["routes"] if item["target"]["kind"] == "finding"
        )
        self.assertEqual(route["validation"]["assessment_status"], "partial")
        self.assertIn(
            "target line coverage is not established",
            route["validation"]["assessment_reasons"],
        )

    def test_validation_campaigns_fail_closed_for_missing_or_failing_cases(
        self,
    ) -> None:
        finding = _finding("src/sink.py", 9)
        finding.evidence["structural_synthesis"] = {
            "change_impact": {"direct_test_files": ["tests/test_sink.py"]}
        }
        missing = _artifacts()
        missing.pop("junit-summary.json")

        missing_result = build_risk_paths([finding], missing)

        self.assertTrue(missing_result["validation_campaigns"])
        self.assertTrue(
            all(
                campaign["test_coverage_alignment"] == "test-evidence-not-available"
                for campaign in missing_result["validation_campaigns"]
            )
        )
        self.assertEqual(missing_result["summary"]["campaigns_requiring_evidence"], 2)

        failing = _artifacts()
        failing["junit-summary.json"]["test_cases"][0]["result"] = "failure"
        failing_result = build_risk_paths([_finding("src/sink.py", 9)], failing)

        self.assertEqual(failing_result["summary"]["campaigns_with_failing_tests"], 2)
        self.assertTrue(
            all(
                campaign["test_coverage_alignment"] == "tests-failing"
                for campaign in failing_result["validation_campaigns"]
            )
        )
        self.assertTrue(
            all(
                next(
                    factor
                    for factor in campaign["review_factors"]
                    if factor["id"] == "focused-test-state"
                )["evidence_artifacts"]
                == ["junit-summary.json"]
                for campaign in failing_result["validation_campaigns"]
            )
        )

    def test_shared_test_source_identity_requires_every_campaign_binding(
        self,
    ) -> None:
        artifacts = _artifacts()
        artifacts.pop("source-inventory.json")

        result = build_risk_paths([_finding("src/sink.py", 9)], artifacts)

        hotspot = result["validation_test_hotspots"][0]
        self.assertIsNone(hotspot["source_binding"])
        self.assertFalse(hotspot["source_binding_consistent"])
        self.assertIn("not established", hotspot["recommended_action"])
        self.assertIn(
            "source `not established`",
            "\n".join(_render_risk_path_summary(result)),
        )


def _finding(path: str, line: int) -> Finding:
    return Finding(
        finding_id="PYSEC-RISK-PATH",
        fingerprint="sha256:risk-path",
        title="Sensitive output",
        description="Sensitive data reaches an output.",
        impact="Data may leave a trust boundary.",
        remediation="Filter the data before output.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        area="data-exposure",
        domain="security",
        classifications=["CWE-532"],
        locations=[Location(path=path, start_line=line)],
        sources=[Source(tool="semgrep", rule_id="python.leak", message="leak")],
    )


def _secret_finding(
    finding_id: str,
    path: str,
    line: int,
    *,
    tool: str,
    native_severity: str,
    evidence: dict[str, Any],
    area: str = "secrets",
) -> Finding:
    rule_id = f"{tool}.credential-candidate"
    return Finding(
        finding_id=finding_id,
        fingerprint=f"sha256:{finding_id.casefold()}",
        title="Redacted credential candidate",
        description="A scanner identified a credential-shaped value; it was discarded.",
        impact="A real credential could permit unauthorized access.",
        remediation="Validate without copying the value, then rotate and remove it if real.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        area=area,
        domain="security",
        classifications=["CWE-798"],
        locations=[Location(path=path, start_line=line)],
        sources=[
            Source(
                tool=tool,
                rule_id=rule_id,
                message="redacted credential candidate",
                native_severity=native_severity,
            )
        ],
        citations=[
            Citation(
                kind="taxonomy",
                identifier="CWE-798",
                title="Use of Hard-coded Credentials",
                uri="https://cwe.mitre.org/data/definitions/798.html",
            )
        ],
        evidence=dict(evidence),
    )


def _artifacts() -> dict[str, Any]:
    return {
        "source-inventory.json": {
            "schema_version": "1.0",
            "scope": ".",
            "source_sha256": "a" * 64,
            "total_files": 4,
            "total_bytes": 400,
            "files": [
                {"path": "src/service.py", "sha256": "b" * 64, "size_bytes": 100},
                {"path": "src/sink.py", "sha256": "c" * 64, "size_bytes": 100},
                {"path": "tests/test_sink.py", "sha256": "d" * 64, "size_bytes": 100},
                {"path": "src/cli.py", "sha256": "e" * 64, "size_bytes": 100},
            ],
        },
        "graphify.json": {
            "schema_version": "1.0",
            "topology": {
                "file_edges": [
                    {
                        "source": "src/cli.py",
                        "target": "src/service.py",
                        "relation": "calls",
                    },
                    {
                        "source": "src/service.py",
                        "target": "src/sink.py",
                        "relation": "calls",
                    },
                    {
                        "source": "tests/test_sink.py",
                        "target": "src/service.py",
                        "relation": "calls",
                    },
                ]
            },
        },
        "reachability.json": {
            "schema_version": "1.2",
            "entry_points": [
                {
                    "id": "entry:cli",
                    "kind": "project-scripts",
                    "declared_as": "example.cli:main",
                    "path": "src/cli.py",
                    "line": 3,
                    "target": "symbol:example.cli:main",
                }
            ],
            "nodes": [
                {
                    "id": "symbol:example.cli:main",
                    "path": "src/cli.py",
                    "state": "executable",
                    "runtime_observation": "observed",
                },
                {
                    "path": "src/service.py",
                    "state": "executable",
                    "runtime_observation": "not-observed",
                },
                {
                    "path": "src/sink.py",
                    "state": "executable",
                    "runtime_observation": "observed",
                },
            ],
        },
        "coverage-summary.json": {
            "files": [
                {
                    "path": "src/service.py",
                    "missing_lines": [],
                    "summary": {"percent_covered": 100.0},
                },
                {
                    "path": "src/sink.py",
                    "missing_lines": [9],
                    "summary": {"percent_covered": 55.5},
                },
            ]
        },
        "diff-coverage.json": {"src_stats": {}},
        "effectiveness.json": {
            "schema_version": "1.1",
            "tool_posture": [
                _tool_posture("semgrep", "source-security"),
                _tool_posture("osv-scanner", "source-composition"),
                _tool_posture("pip-audit", "source-composition"),
            ],
        },
        "junit-summary.json": {
            "summary": {"tests": 1, "failures": 0, "errors": 0, "skipped": 0},
            "test_case_inventory_complete": True,
            "test_cases": [
                {
                    "file": "tests/test_sink.py",
                    "result": "passed",
                    "file_attribution": "producer",
                }
            ],
        },
        "structural-synthesis.json": {
            "schema_version": "1.2",
            "finding_assessments": [
                {
                    "path": "src/service.py",
                    "degree": 50,
                    "maximum_complexity": 25,
                    "maximum_complexity_rank": "D",
                    "reachability_states": ["executable"],
                },
                {
                    "path": "src/sink.py",
                    "degree": 80,
                    "maximum_complexity": 35,
                    "maximum_complexity_rank": "E",
                    "reachability_states": ["executable"],
                },
            ],
            "change_impact_assessments": [
                {
                    "path": "src/sink.py",
                    "classification": "changed-lines-under-tested",
                    "priority": "high",
                    "risk_score": 85,
                    "changed_lines": 4,
                    "uncovered_changed_lines": [9],
                    "changed_line_coverage_percent": 75.0,
                }
            ],
        },
        "data-exposure.json": {
            "schema_version": "1.5",
            "sink_surfaces": [
                {
                    "path": "src/sink.py",
                    "line": 9,
                    "label": "sensitive telemetry",
                    "sink_family": "telemetry",
                    "scope": "production",
                    "review_priority": "high",
                    "data_classes": ["credential"],
                    "protection_status": "not-observed",
                    "verification_steps": ["Verify redaction at the sink."],
                    "sdk_dependency_context": {},
                    "structural_context": {
                        "context_available": True,
                        "changed_line": True,
                        "line_covered": False,
                        "coverage_percent": 55.5,
                        "reachability_states": ["executable"],
                        "runtime_observations": ["observed"],
                        "related_finding_ids": ["PYSEC-RISK-PATH"],
                        "related_tools": ["semgrep"],
                        "owners": ["@security-team"],
                        "mapped_test_files": ["tests/test_sink.py"],
                        "focused_test_validation_status": "passed",
                        "test_coverage_alignment": "coverage-gap",
                        "validation_gap_reasons": ["Sink line is uncovered."],
                        "validation_action": "Extend the focused sink test.",
                        "structural_risk_ids": ["cycle-sink"],
                    },
                }
            ],
        },
    }


def _tool_posture(tool: str, lane: str) -> dict[str, Any]:
    return {
        "tool": tool,
        "status": "completed",
        "applicable": True,
        "evidence_lane": lane,
        "normalized_findings": 1,
        "unique_normalized_findings": 1,
        "executable_integrity_verified": True,
        "executable_organization_approved": True,
        "executable_unchanged": True,
        "auxiliary_executable_present": False,
        "auxiliary_executable_integrity_verified": None,
        "auxiliary_executable_organization_approved": None,
        "auxiliary_executable_unchanged": None,
        "assurance_status": "approved",
    }


def _bind_test_evidence(artifacts: dict[str, Any], source_sha256: str) -> None:
    _bind_test_evidence_artifact(
        artifacts["coverage-summary.json"],
        source_sha256,
        evidence_sha256="c" * 64,
    )
    _bind_test_evidence_artifact(
        artifacts["junit-summary.json"],
        source_sha256,
        evidence_sha256="d" * 64,
    )


def _bind_test_evidence_artifact(
    document: dict[str, Any],
    source_sha256: str,
    *,
    evidence_sha256: str,
) -> None:
    document["source_sha256"] = source_sha256
    document["evidence_binding"] = {
        "schema_version": "1.0",
        "evidence_sha256": evidence_sha256,
        "binding_file": "evidence.pysec-binding.json",
        "verified": True,
    }


def _dependency_advisory_cluster() -> dict[str, Any]:
    return {
        "cluster_id": "ADV-ABCDEF123456",
        "package": "demo-package",
        "versions": ["1.0.0"],
        "primary_identifier": "GHSA-DEMO-1234",
        "identifiers": ["GHSA-DEMO-1234", "CVE-2026-1234"],
        "finding_ids": ["PYSEC-RISK-PATH"],
        "tools": ["osv-scanner", "pip-audit"],
        "highest_severity": "critical",
        "citations": [
            {
                "identifier": "GHSA-DEMO-1234",
                "title": "Demonstration advisory",
                "uri": "https://example.test/GHSA-DEMO-1234",
            }
        ],
        "dependency_usage": {
            "assessment": "executable-import",
            "source_relationship": "direct",
            "dependency_paths": [
                {
                    "introducing_package": "demo-package",
                    "path": ["demo-package"],
                    "depth": 0,
                }
            ],
            "dependency_path_confidence": "high",
            "import_modules": ["demo_package"],
            "import_paths": ["src/service.py", "src/service.py"],
            "recommended_test_files": ["tests/test_sink.py"],
            "focused_test_validation_status": "passed",
            "test_coverage_alignment": "coverage-gap",
            "validation_gap_reasons": ["Importer has uncovered executable lines."],
            "import_path_owners": ["@dependency-team"],
            "import_path_ownership": [
                {"path": "src/service.py", "owners": ["@import-owner"]}
            ],
            "import_path_coverage": [
                {"path": "src/service.py", "coverage_percent": 90.0}
            ],
            "import_path_assessments": [
                _import_path_assessment(
                    "src/service.py",
                    owners=["@import-owner"],
                    tests=["tests/test_sink.py"],
                    coverage_percent=90.0,
                    alignment="coverage-gap",
                    gap_reasons=["Importer has uncovered executable lines."],
                )
            ],
            "uncovered_import_paths": ["src/service.py"],
            "evidence_artifacts": [
                "graphify.json",
                "coverage-summary.json",
                "junit-summary.json",
            ],
        },
        "threat_context": {
            "known_exploited": True,
            "epss_probability": 0.91,
            "epss_percentile": 0.99,
            "epss_high": True,
            "vex_disposition": "unassessed",
            "intelligence_sources": ["risk-intelligence.json"],
        },
        "remediation_context": {
            "priority": "P0",
            "action_kind": "upgrade",
            "fix_available": True,
            "fixed_version_candidates": ["2.0.0"],
            "owners": ["@dependency-team"],
            "recommended_action": "Upgrade demo-package to 2.0.0.",
        },
    }


def _add_multi_entry_paths(artifacts: dict[str, Any]) -> None:
    artifacts["reachability.json"]["entry_points"].extend(
        [
            {
                "id": "entry:cli-module",
                "kind": "python-main",
                "declared_as": "src/cli.py",
                "path": "src/cli.py",
                "line": 1,
                "target": "module:example.cli",
            },
            {
                "id": "entry:worker",
                "kind": "worker",
                "declared_as": "example.worker:run",
                "path": "src/worker.py",
                "line": 2,
                "target": "symbol:example.worker:run",
            },
            {
                "id": "entry:unrelated",
                "kind": "project-scripts",
                "declared_as": "example.unrelated:main",
                "path": "src/unrelated.py",
                "line": 2,
                "target": "symbol:example.unrelated:main",
            },
        ]
    )
    artifacts["graphify.json"]["topology"]["file_edges"].append(
        {
            "source": "src/worker.py",
            "target": "src/service.py",
            "relation": "calls",
        }
    )
    artifacts["reachability.json"]["nodes"].extend(
        [
            {
                "id": "symbol:example.worker:run",
                "path": "src/worker.py",
                "state": "executable",
                "runtime_observation": "not-observed",
            },
            {
                "id": "symbol:example.unrelated:main",
                "path": "src/unrelated.py",
                "state": "executable",
                "runtime_observation": "observed",
            },
        ]
    )


def _package_lineage(
    status: str, source_versions: list[str], artifact_versions: list[str]
) -> dict[str, Any]:
    return {
        "package": "demo-package",
        "source_versions": source_versions,
        "artifact_versions": artifact_versions,
        "status": status,
        "finding_ids": ["PYSEC-RISK-PATH"],
    }


def _composition_lanes(
    *, source: bool = True, artifact: bool = True
) -> list[dict[str, Any]]:
    return [
        {
            "lane": "source_composition",
            "available_artifacts": ["sbom.cdx.json"] if source else [],
            "execution_gaps": [] if source else ["source SBOM unavailable"],
        },
        {
            "lane": "artifact_composition",
            "available_artifacts": ["artifact-sbom.cdx.json"] if artifact else [],
            "execution_gaps": [] if artifact else ["artifact SBOM unavailable"],
        },
    ]


def _import_path_assessment(
    path: str,
    *,
    owners: list[str],
    tests: list[str],
    coverage_percent: float,
    alignment: str,
    gap_reasons: list[str],
) -> dict[str, object]:
    selected = bool(tests)
    return {
        "path": path,
        "import_modules": ["demo_package"],
        "import_lines": [7],
        "assessment": "executable-import",
        "reachability_states": ["executable"],
        "runtime_observations": ["not-observed"],
        "owners": owners,
        "ownership_evidence_available": True,
        "direct_test_files": tests,
        "transitive_test_files": [],
        "recommended_test_files": tests,
        "test_selection_confidence": "high" if selected else "low",
        "test_execution_evidence_available": True,
        "test_case_inventory_available": True,
        "test_case_inventory_complete": True,
        "test_execution_sources": ["junit-summary.json"],
        "focused_test_validation_status": "passed" if selected else "not-selected",
        "focused_test_execution": (
            [
                {
                    "path": tests[0],
                    "status": "passed",
                    "tests": 1,
                    "passed": 1,
                    "failures": 0,
                    "errors": 0,
                    "skipped": 0,
                    "sources": ["junit-summary.json"],
                    "path_attributions": ["producer"],
                }
            ]
            if selected
            else []
        ),
        "unobserved_recommended_test_files": [],
        "coverage_evidence_available": True,
        "coverage_percent": coverage_percent,
        "coverage_gap": coverage_percent < 80,
        "test_coverage_alignment": alignment,
        "validation_gap_reasons": gap_reasons,
        "evidence_artifacts": [
            "graphify.json",
            "reachability.json",
            "coverage-summary.json",
            "junit-summary.json",
        ],
    }
