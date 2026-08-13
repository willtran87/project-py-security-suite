from __future__ import annotations

import json
import unittest

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
from py_security_suite.reports import _render_risk_path_summary, render_sarif
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
        self.assertEqual(result["summary"]["campaigns_with_selected_tests"], 2)
        self.assertEqual(result["summary"]["campaigns_with_failing_tests"], 0)
        self.assertEqual(result["summary"]["campaigns_with_coverage_gaps"], 1)
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
        self.assertEqual(len(finding_route["convergence_hotspot_ids"]), 2)
        self.assertEqual(len(finding_route["validation_campaign_ids"]), 2)
        self.assertEqual(
            finding_route["validation"]["mapped_test_files"],
            ["tests/test_sink.py"],
        )
        self.assertEqual(finding.evidence["risk_path"]["status"], "routed")
        self.assertEqual(len(finding.evidence["risk_path"]["validation_campaigns"]), 2)
        campaigns = result["validation_campaigns"]
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
                campaign["review_score_model"] == "shared-control-review-v1"
                for campaign in campaigns
            )
        )
        self.assertTrue(all(campaign["review_factors"] for campaign in campaigns))
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
        self.assertIn("revision `not-established`", rendered)
        self.assertIn("tests/test_sink.py", rendered)
        self.assertIn("src/service.py", rendered)
        sarif = render_sarif([finding])
        properties = sarif["runs"][0]["results"][0]["properties"]
        self.assertEqual(properties["risk_path"]["status"], "routed")
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
        self.assertIn("tests/test_sink.py", closure["evidence_refs"])
        self.assertTrue(
            any(
                "validation assessment" in item
                for item in closure["acceptance_criteria"]
            )
        )

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


def _artifacts() -> dict[str, object]:
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
                }
            ],
            "nodes": [
                {
                    "path": "src/sink.py",
                    "state": "executable",
                    "runtime_observation": "observed",
                }
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
