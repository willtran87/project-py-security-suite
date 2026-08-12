from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from py_security_suite.adapters.graphify import GraphifyAdapter
from py_security_suite.config import ToolConfig
from py_security_suite.graph_analysis import apply_graph_context
from py_security_suite.models import Confidence, Finding, Location, Severity, Source


class GraphifyAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.target = Path(self.enterContext(temporary)).resolve()
        (self.target / "app.py").write_text(
            "def main():\n    return 1\n", encoding="utf-8"
        )

    def test_command_is_code_only_local_and_single_worker(self) -> None:
        adapter = GraphifyAdapter(ToolConfig(), 1024)
        output = self.target / "temp" / "graphify-out" / "graph.json"
        command = adapter.build_file_command("graphify", self.target, output)
        self.assertIn("--code-only", command)
        self.assertIn("--no-cluster", command)
        self.assertEqual(command[command.index("--max-workers") + 1], "1")
        self.assertNotIn("--backend", command)

    def test_normalizes_graph_and_correlates_blast_radius(self) -> None:
        payload = json.dumps(
            {
                "nodes": [
                    {
                        "id": "a",
                        "label": "main",
                        "source_file": "app.py",
                        "source_location": "L1",
                        "_origin": "ast",
                        "_callable": True,
                    },
                    {
                        "id": "b",
                        "label": "helper",
                        "source_file": "helper.py",
                        "source_location": "L3",
                        "_origin": "ast",
                    },
                ],
                "edges": [
                    {
                        "source": "a",
                        "target": "b",
                        "relation": "calls",
                        "confidence": "EXTRACTED",
                        "source_file": "app.py",
                        "source_location": "L2",
                        "_origin": "ast",
                    }
                ],
                "hyperedges": [],
                "input_tokens": 0,
                "output_tokens": 0,
            }
        )
        artifact = GraphifyAdapter(ToolConfig(), 4096).derived_artifacts(
            payload, self.target
        )["graphify.json"]
        self.assertFalse(artifact["mode"]["model_calls"])
        self.assertEqual(artifact["summary"]["relations"], {"calls": 1})
        finding = Finding(
            finding_id="PYSEC-TEST",
            fingerprint="sha256:test",
            title="Example",
            description="Example",
            impact="Example",
            remediation="Example",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            area="test",
            locations=[Location(path="helper.py", start_line=3)],
            sources=[Source(tool="bandit", rule_id="B001", message="Example")],
        )
        analysis = apply_graph_context(
            [finding],
            {
                "graphify.json": artifact,
                "coverage-summary.json": {
                    "files": [
                        {
                            "path": "helper.py",
                            "summary": {"percent_covered": 42.0},
                        }
                    ]
                },
                "reachability.json": {
                    "nodes": [
                        {
                            "path": "helper.py",
                            "state": "executable",
                            "runtime_observation": "observed",
                        }
                    ]
                },
                "radon-complexity.json": {
                    "files": {
                        str(self.target / "helper.py"): [
                            {"name": "helper", "complexity": 24, "rank": "D"}
                        ]
                    }
                },
            },
        )
        self.assertIsNotNone(analysis)
        self.assertEqual(finding.evidence["graph_context"]["two_hop_upstream_count"], 1)
        corroboration = finding.evidence["graph_context"]["corroborating_evidence"]
        self.assertEqual(corroboration["coverage_percent"], 42.0)
        self.assertEqual(corroboration["reachability_states"], ["executable"])
        self.assertEqual(corroboration["maximum_complexity_rank"], "D")
        self.assertTrue(
            any(c.identifier == "graphify-code-graph" for c in finding.citations)
        )

    def test_rejects_non_ast_or_model_assisted_evidence(self) -> None:
        adapter = GraphifyAdapter(ToolConfig(), 4096)
        base = {
            "nodes": [],
            "edges": [],
            "hyperedges": [],
            "input_tokens": 1,
            "output_tokens": 0,
        }
        with self.assertRaisesRegex(ValueError, "model tokens"):
            adapter.parse(json.dumps(base), self.target)
        base["input_tokens"] = 0
        base["nodes"] = [
            {"id": "x", "label": "x", "source_file": "app.py", "_origin": "llm"}
        ]
        with self.assertRaisesRegex(ValueError, "not deterministic AST evidence"):
            adapter.parse(json.dumps(base), self.target)

    def test_closes_implicit_external_package_endpoints(self) -> None:
        payload = json.dumps(
            {
                "nodes": [
                    {
                        "id": "project",
                        "label": "project",
                        "source_file": "pyproject.toml",
                        "_origin": "ast",
                    }
                ],
                "edges": [
                    {
                        "source": "project",
                        "target": "pkg_external",
                        "relation": "depends_on",
                        "source_file": "pyproject.toml",
                        "_origin": "ast",
                    }
                ],
                "hyperedges": [],
                "input_tokens": 0,
                "output_tokens": 0,
            }
        )
        artifact = GraphifyAdapter(ToolConfig(), 4096).derived_artifacts(
            payload, self.target
        )["graphify.json"]
        external = next(
            node for node in artifact["nodes"] if node["id"] == "pkg_external"
        )
        self.assertEqual(external["kind"], "external")
        self.assertEqual(external["path"], ".")


if __name__ == "__main__":
    unittest.main()
