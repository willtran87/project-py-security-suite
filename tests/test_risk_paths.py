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
        self.assertEqual(
            finding_route["validation"]["mapped_test_files"],
            ["tests/test_sink.py"],
        )
        self.assertEqual(finding.evidence["risk_path"]["status"], "routed")
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
        self.assertTrue(
            any(
                "validation assessment" in item
                for item in closure["acceptance_criteria"]
            )
        )

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
        "coverage-summary.json": {"files": []},
        "diff-coverage.json": {"src_stats": {}},
        "junit-summary.json": {"summary": {}},
        "structural-synthesis.json": {"schema_version": "1.2"},
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
