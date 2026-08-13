from __future__ import annotations

import json
import unittest
from typing import Any
from unittest.mock import patch

from jsonschema import Draft202012Validator

from py_security_suite.closure_plan import _finding_items
from py_security_suite.models import (
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
    json_ready,
)
from py_security_suite.report_inspection import read_bundled_schema
from py_security_suite.reports import (
    _html_risk_path_context,
    _markdown_risk_path_context,
    _render_risk_path_summary,
    render_sarif,
)
from py_security_suite.risk_paths import build_risk_paths


class RiskPathTests(unittest.TestCase):
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
            {"critical": 1, "high": 1, "medium": 0, "low": 0},
        )
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
            {campaign["review_tier"] for campaign in campaigns}, {"critical", "high"}
        )
        self.assertTrue(
            all(
                campaign["review_score_model"] == "shared-control-review-v2"
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
        aligned_artifacts["coverage-summary.json"]["source_sha256"] = aggregate
        aligned_artifacts["junit-summary.json"]["source_sha256"] = aggregate

        aligned = build_risk_paths([_finding("src/sink.py", 9)], aligned_artifacts)

        self.assertEqual(aligned["summary"]["campaigns_revision_aligned"], 2)
        self.assertEqual(aligned["summary"]["campaigns_revision_unbound"], 0)
        self.assertTrue(
            all(
                campaign["source_snapshot"]["evidence_revision_binding"] == "aligned"
                for campaign in aligned["validation_campaigns"]
            )
        )

        mismatched_artifacts = _artifacts()
        mismatched_artifacts["coverage-summary.json"]["source_sha256"] = "f" * 64
        mismatched_artifacts["junit-summary.json"]["source_sha256"] = "e" * 64

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
        self.assertIn("no declared-entry-point route", record["reason"])
        self.assertEqual(finding.evidence["risk_path"]["status"], "unrouted")
        self.assertIn("not proof", "\n".join(_render_risk_path_summary(result)))

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
