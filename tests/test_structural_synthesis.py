from __future__ import annotations

import json
import unittest
from typing import Any, cast

from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.models import Confidence, Finding, Location, Severity, Source
from py_security_suite.report_inspection import read_bundled_schema
from py_security_suite.reports import (
    _markdown_structural_context,
    render_sarif,
    render_sonarqube_external_issues,
)
from py_security_suite.structural_synthesis import build_structural_synthesis


def _finding(
    finding_id: str,
    *,
    tool: str,
    path: str,
    line: int,
    domain: str = "quality",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        fingerprint=f"sha256:{finding_id.casefold()}",
        title=f"{tool} finding",
        description="unused function 'unused'"
        if tool == "vulture"
        else "Detected issue",
        impact="Impact",
        remediation="Review and remediate",
        severity=Severity.HIGH if domain == "security" else Severity.LOW,
        confidence=Confidence.HIGH,
        area="dead-code" if tool == "vulture" else "source-security",
        domain=domain,
        locations=[Location(path=path, start_line=line, end_line=line)],
        sources=[Source(tool=tool, rule_id="rule", message="Detected")],
    )


def _graph(*, inbound_dead: bool = False) -> dict[str, object]:
    file_edges: list[dict[str, object]] = [
        {
            "source": "src/a.py",
            "target": "src/b.py",
            "relation": "imports",
            "count": 1,
        },
        {
            "source": "src/b.py",
            "target": "src/a.py",
            "relation": "imports",
            "count": 1,
        },
    ]
    edges: list[dict[str, object]] = []
    if inbound_dead:
        file_edges.append(
            {
                "source": "src/live.py",
                "target": "src/dead.py",
                "relation": "imports",
                "count": 1,
            }
        )
        edges.append(
            {
                "source": "live-caller",
                "target": "dead-symbol",
                "relation": "calls",
                "path": "src/live.py",
                "line": 2,
            }
        )
    return {
        "schema_version": "1.0",
        "nodes": [
            {
                "id": "dead-symbol",
                "path": "src/dead.py",
                "line": 10,
                "label": "unused()",
            },
            {
                "id": "nearby-live-symbol",
                "path": "src/dead.py",
                "line": 11,
                "label": "nearby_live()",
            },
            {
                "id": "live-caller",
                "path": "src/live.py",
                "line": 2,
                "label": "caller",
            },
        ],
        "edges": edges,
        "topology": {"file_edges": file_edges},
    }


def _reachability(*, observed: bool = False) -> dict[str, object]:
    state = "load-only" if observed else "disconnected"
    observation = "observed" if observed else "not-observed"
    return {
        "nodes": [
            {
                "id": "symbol:dead",
                "path": "src/dead.py",
                "start_line": 10,
                "end_line": 20,
                "state": state,
                "runtime_observation": observation,
            }
        ],
        "islands": [
            {
                "id": "island-dead",
                "kind": "symbol-island",
                "state": state,
                "confidence": "high",
                "lines_of_code": 240,
                "paths": ["src/dead.py"],
                "primary_path": "src/dead.py",
                "primary_start_line": 10,
                "primary_end_line": 20,
                "runtime_observation": observation,
                "reportable": True,
            }
        ],
    }


def _coverage(*, covered: bool = False) -> dict[str, object]:
    return {
        "files": [
            {
                "path": "src/dead.py",
                "missing_lines": [] if covered else [12],
                "summary": {"percent_covered": 100.0 if covered else 0.0},
            }
        ]
    }


class StructuralSynthesisTests(unittest.TestCase):
    def test_cross_checks_dead_code_as_likely_removable(self) -> None:
        dead = _finding("DEAD", tool="vulture", path="src/dead.py", line=12)
        result = build_structural_synthesis(
            [dead],
            {
                "graphify.json": _graph(),
                "reachability.json": _reachability(),
                "coverage-summary.json": _coverage(),
            },
        )

        self.assertIsNotNone(result)
        result = cast(dict[str, Any], result)
        assessment = result["dead_code_assessments"][0]
        self.assertEqual(assessment["disposition"], "likely-removable")
        self.assertEqual(assessment["confidence"], "high")
        self.assertEqual(
            dead.evidence["structural_synthesis"]["disposition"],
            "likely-removable",
        )
        self.assertIn(
            "graphify-code-graph", {citation.identifier for citation in dead.citations}
        )

    def test_runtime_and_graph_references_prevent_removal_conclusion(self) -> None:
        dead = _finding("DYNAMIC", tool="vulture", path="src/dead.py", line=12)
        result = build_structural_synthesis(
            [dead],
            {
                "graphify.json": _graph(inbound_dead=True),
                "reachability.json": _reachability(observed=True),
                "coverage-summary.json": _coverage(covered=True),
            },
        )

        result = cast(dict[str, Any], result)
        assessment = result["dead_code_assessments"][0]
        self.assertEqual(assessment["disposition"], "likely-dynamic")
        self.assertTrue(assessment["inbound_symbol_references"])
        self.assertIn("observed", assessment["runtime_observations"])

    def test_classifies_security_inside_disconnected_island_as_latent_surface(
        self,
    ) -> None:
        dead = _finding("DEAD", tool="vulture", path="src/dead.py", line=12)
        security = _finding(
            "SECURITY",
            tool="bandit",
            path="src/dead.py",
            line=14,
            domain="security",
        )
        result = build_structural_synthesis(
            [dead, security],
            {
                "graphify.json": _graph(),
                "reachability.json": _reachability(),
                "coverage-summary.json": _coverage(),
            },
        )

        result = cast(dict[str, Any], result)
        island = result["island_assessments"][0]
        self.assertEqual(island["classification"], "latent-attack-surface")
        self.assertEqual(island["priority"], "high")
        self.assertIn("SECURITY", island["security_finding_ids"])
        self.assertEqual(
            security.evidence["structural_synthesis"]["island"]["classification"],
            "latent-attack-surface",
        )

    def test_correlates_import_cycles_with_tach_and_security_findings(self) -> None:
        tach = _finding("TACH", tool="tach", path="src/a.py", line=1)
        security = _finding(
            "SECURITY", tool="bandit", path="src/b.py", line=1, domain="security"
        )
        result = build_structural_synthesis(
            [tach, security], {"graphify.json": _graph()}
        )

        result = cast(dict[str, Any], result)
        cycle = result["import_cycles"][0]
        self.assertEqual(cycle["paths"], ["src/a.py", "src/b.py"])
        self.assertEqual(cycle["tach_finding_ids"], ["TACH"])
        self.assertEqual(cycle["security_finding_ids"], ["SECURITY"])
        self.assertEqual(cycle["priority"], "high")

    def test_output_validates_against_bundled_schema(self) -> None:
        result = build_structural_synthesis([], {"graphify.json": _graph()})
        result = cast(dict[str, Any], result)
        schema = json.loads(read_bundled_schema("structural-synthesis-1.1"))
        Draft202012Validator(schema).validate(result)

    def test_structural_context_is_portable_in_reports(self) -> None:
        dead = _finding("DEAD", tool="vulture", path="src/dead.py", line=12)
        result = build_structural_synthesis(
            [dead],
            {
                "graphify.json": _graph(),
                "reachability.json": _reachability(),
                "coverage-summary.json": _coverage(),
            },
        )
        self.assertIsNotNone(result)

        markdown = "\n".join(_markdown_structural_context(dead))
        sarif = render_sarif([dead])
        sonar = render_sonarqube_external_issues([dead])
        self.assertIn("likely-removable", markdown)
        self.assertEqual(
            sarif["runs"][0]["results"][0]["properties"]["structural_synthesis"][
                "disposition"
            ],
            "likely-removable",
        )
        self.assertIn(
            "Structural synthesis",
            sonar["issues"][0]["primaryLocation"]["message"],
        )

    def test_returns_none_without_structural_artifacts(self) -> None:
        self.assertIsNone(build_structural_synthesis([], {}))


if __name__ == "__main__":
    unittest.main()
