from __future__ import annotations

import unittest

from py_security_suite.models import Confidence, Finding, Location, Severity, Source
from py_security_suite.reports import (
    _markdown_structural_context,
    _render_structural_summary,
    render_sonarqube_external_issues,
)
from py_security_suite.structural_leverage import build_structural_leverage


def _finding(path: str = "src/core.py") -> Finding:
    return Finding(
        finding_id="FINDING",
        fingerprint="sha256:finding",
        title="Security finding",
        description="Detected issue",
        impact="Impact",
        remediation="Remediate and retest",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        area="source-security",
        domain="security",
        locations=[Location(path=path, start_line=10, end_line=10)],
        sources=[Source(tool="bandit", rule_id="B001", message="Detected")],
    )


def _graph(file_edges: list[dict[str, object]]) -> dict[str, object]:
    return {
        "nodes": [],
        "edges": [],
        "topology": {"file_edges": file_edges},
    }


def _diff(path: str, *, covered: list[int], uncovered: list[int]) -> dict[str, object]:
    total = len(covered) + len(uncovered)
    return {
        "src_stats": {
            path: {
                "covered_lines": covered,
                "violation_lines": uncovered,
                "percent_covered": (len(covered) / total) * 100 if total else 100,
            }
        }
    }


class StructuralLeverageTests(unittest.TestCase):
    def test_maps_changed_file_to_direct_tests_and_attaches_finding_context(
        self,
    ) -> None:
        finding = _finding()
        result = build_structural_leverage(
            [finding],
            {
                "graphify.json": _graph(
                    [
                        {
                            "source": "tests/test_core.py",
                            "target": "src/core.py",
                            "relation": "calls",
                            "count": 3,
                        }
                    ]
                ),
                "diff-coverage.json": _diff(
                    "src/core.py", covered=[8, 9], uncovered=[10]
                ),
                "junit-summary.json": {
                    "test_case_inventory_complete": True,
                    "test_cases": [
                        {
                            "file": "tests/test_core.py",
                            "result": "passed",
                            "file_attribution": "producer",
                        }
                    ],
                },
            },
            [],
            [],
        )

        impact = result["change_impact_assessments"][0]
        self.assertEqual(impact["classification"], "changed-lines-under-tested")
        self.assertEqual(impact["direct_test_files"], ["tests/test_core.py"])
        self.assertEqual(impact["test_selection_confidence"], "high")
        self.assertEqual(impact["focused_test_validation_status"], "passed")
        self.assertEqual(impact["test_coverage_alignment"], "coverage-gap")
        self.assertEqual(
            result["summary"]["passing_focused_tests_with_coverage_gaps"], 1
        )
        self.assertIn("every cited changed", impact["validation_action"])
        context = finding.evidence["structural_synthesis"]["change_impact"]
        self.assertEqual(context["uncovered_changed_lines"], [10])
        self.assertIn(
            "graph-guided-test-selection",
            {citation.identifier for citation in finding.citations},
        )

    def test_maps_transitive_tests_and_identifies_unmapped_changes(self) -> None:
        mapped = build_structural_leverage(
            [],
            {
                "graphify.json": _graph(
                    [
                        {
                            "source": "tests/test_api.py",
                            "target": "src/service.py",
                            "relation": "calls",
                            "count": 1,
                        },
                        {
                            "source": "src/service.py",
                            "target": "src/core.py",
                            "relation": "calls",
                            "count": 1,
                        },
                    ]
                ),
                "diff-coverage.json": _diff("src/core.py", covered=[10], uncovered=[]),
            },
            [],
            [],
        )
        unmapped = build_structural_leverage(
            [],
            {
                "graphify.json": _graph([]),
                "diff-coverage.json": _diff("src/orphan.py", covered=[], uncovered=[4]),
            },
            [],
            [],
        )

        self.assertEqual(
            mapped["change_impact_assessments"][0]["transitive_test_files"],
            ["tests/test_api.py"],
        )
        self.assertEqual(
            unmapped["change_impact_assessments"][0]["classification"],
            "changed-without-mapped-tests",
        )
        self.assertEqual(unmapped["summary"]["changed_files_without_mapped_tests"], 1)

    def test_change_validation_distinguishes_aligned_and_failing_evidence(
        self,
    ) -> None:
        base = {
            "graphify.json": _graph(
                [
                    {
                        "source": "tests/test_core.py",
                        "target": "src/core.py",
                        "relation": "calls",
                        "count": 1,
                    }
                ]
            ),
            "diff-coverage.json": _diff("src/core.py", covered=[10], uncovered=[]),
        }
        aligned = build_structural_leverage(
            [],
            {
                **base,
                "junit-summary.json": {
                    "test_case_inventory_complete": True,
                    "test_cases": [{"file": "tests/test_core.py", "result": "passed"}],
                },
            },
            [],
            [],
        )
        failing = build_structural_leverage(
            [],
            {
                **base,
                "junit-summary.json": {
                    "test_case_inventory_complete": True,
                    "test_cases": [{"file": "tests/test_core.py", "result": "failure"}],
                },
            },
            [],
            [],
        )

        self.assertEqual(
            aligned["change_impact_assessments"][0]["test_coverage_alignment"],
            "aligned-current-evidence",
        )
        self.assertEqual(aligned["summary"]["validation_aligned_changed_files"], 1)
        self.assertEqual(
            failing["change_impact_assessments"][0]["test_coverage_alignment"],
            "tests-failing",
        )
        self.assertEqual(
            failing["summary"]["changed_files_with_failing_focused_tests"], 1
        )

    def test_maps_package_surface_to_tests_of_exported_modules(self) -> None:
        result = build_structural_leverage(
            [],
            {
                "graphify.json": _graph(
                    [
                        {
                            "source": "src/package/__init__.py",
                            "target": "src/package/service.py",
                            "relation": "re_exports",
                            "count": 1,
                        },
                        {
                            "source": "tests/test_service.py",
                            "target": "src/package/service.py",
                            "relation": "calls",
                            "count": 2,
                        },
                    ]
                ),
                "diff-coverage.json": _diff(
                    "src/package/__init__.py", covered=[1], uncovered=[]
                ),
            },
            [],
            [],
        )

        impact = result["change_impact_assessments"][0]
        self.assertEqual(impact["classification"], "package-surface-change")
        self.assertEqual(impact["associated_test_files"], ["tests/test_service.py"])
        self.assertEqual(result["summary"]["changed_files_without_mapped_tests"], 0)

    def test_corroborates_uncovered_disconnected_orphan_with_vulture(self) -> None:
        result = build_structural_leverage(
            [],
            {
                "graphify.json": {
                    "nodes": [
                        {
                            "id": "orphan",
                            "path": "src/orphan.py",
                            "line": 10,
                            "label": "unused()",
                            "callable": True,
                        }
                    ],
                    "edges": [],
                    "topology": {"file_edges": []},
                },
                "reachability.json": {
                    "nodes": [
                        {
                            "path": "src/orphan.py",
                            "start_line": 10,
                            "end_line": 12,
                            "state": "disconnected",
                            "runtime_observation": "not-observed",
                        }
                    ]
                },
                "coverage-summary.json": {
                    "files": [
                        {
                            "path": "src/orphan.py",
                            "missing_lines": [10],
                            "summary": {"percent_covered": 0},
                        }
                    ]
                },
            },
            [],
            [
                {
                    "finding_id": "VULTURE",
                    "path": "src/orphan.py",
                    "line": 10,
                }
            ],
        )

        candidate = result["orphan_symbol_candidates"][0]
        self.assertEqual(candidate["classification"], "corroborated-dead-code")
        self.assertEqual(candidate["confidence"], "high")
        self.assertEqual(candidate["vulture_finding_id"], "VULTURE")

    def test_runtime_observation_excludes_orphan_conclusion(self) -> None:
        result = build_structural_leverage(
            [],
            {
                "graphify.json": {
                    "nodes": [
                        {
                            "id": "dynamic",
                            "path": "src/plugin.py",
                            "line": 5,
                            "label": "plugin()",
                            "callable": True,
                        }
                    ],
                    "edges": [],
                    "topology": {"file_edges": []},
                },
                "reachability.json": {
                    "nodes": [
                        {
                            "path": "src/plugin.py",
                            "start_line": 5,
                            "end_line": 8,
                            "state": "load-only",
                            "runtime_observation": "observed",
                        }
                    ]
                },
                "coverage-summary.json": {
                    "files": [
                        {
                            "path": "src/plugin.py",
                            "missing_lines": [5],
                            "summary": {"percent_covered": 0},
                        }
                    ]
                },
            },
            [],
            [],
        )

        self.assertEqual(result["orphan_symbol_candidates"], [])

    def test_distinguishes_test_only_and_missing_entry_point_boundaries(self) -> None:
        islands = [
            {
                "island_id": "test-island",
                "state": "disconnected",
                "runtime_observation": "not-observed",
                "paths": ["src/fixture.py"],
            },
            {
                "island_id": "entry-island",
                "state": "disconnected",
                "runtime_observation": "not-observed",
                "paths": ["src/plugin.py"],
            },
        ]
        result = build_structural_leverage(
            [],
            {
                "graphify.json": _graph(
                    [
                        {
                            "source": "tests/test_fixture.py",
                            "target": "src/fixture.py",
                            "relation": "calls",
                            "count": 1,
                        },
                        {
                            "source": "src/registry.py",
                            "target": "src/plugin.py",
                            "relation": "references",
                            "count": 2,
                        },
                    ]
                )
            },
            islands,
            [],
        )

        boundaries = {
            item["island_id"]: item for item in result["island_boundary_assessments"]
        }
        self.assertEqual(
            boundaries["test-island"]["boundary_classification"],
            "test-only-or-fixture",
        )
        self.assertEqual(
            boundaries["entry-island"]["boundary_classification"],
            "candidate-missing-entry-point",
        )
        self.assertEqual(
            boundaries["entry-island"]["candidate_entry_paths"],
            ["src/registry.py"],
        )

    def test_change_impact_is_readable_in_portable_reports(self) -> None:
        finding = _finding()
        leverage = build_structural_leverage(
            [finding],
            {
                "graphify.json": _graph(
                    [
                        {
                            "source": "tests/test_core.py",
                            "target": "src/core.py",
                            "relation": "calls",
                            "count": 1,
                        }
                    ]
                ),
                "diff-coverage.json": _diff("src/core.py", covered=[8], uncovered=[10]),
            },
            [],
            [],
        )
        document = {
            "summary": leverage["summary"],
            "island_assessments": [],
            "change_impact_assessments": leverage["change_impact_assessments"],
            "orphan_symbol_candidates": [
                {
                    "label": "unused()",
                    "path": "src/orphan.py",
                    "line": 12,
                    "classification": "corroborated-dead-code",
                    "confidence": "high",
                    "recommended_action": "Remove it after focused review.",
                }
            ],
            "island_boundary_assessments": [
                {
                    "island_id": "plugin-island",
                    "boundary_classification": "candidate-missing-entry-point",
                    "boundary_relation_count": 2,
                    "candidate_entry_paths": ["src/registry.py"],
                    "recommended_action": "Model the registry entry point.",
                }
            ],
        }

        summary = "\n".join(_render_structural_summary(document))
        finding_text = "\n".join(_markdown_structural_context(finding))
        sonar = render_sonarqube_external_issues([finding])
        self.assertIn("Graph-recommended test files", summary)
        self.assertIn(r"tests/test\_core.py", summary)
        self.assertIn("Structural orphan", summary)
        self.assertIn("src/orphan.py:12", summary)
        self.assertIn("Island boundary review", summary)
        self.assertIn("changed-lines-under-tested", finding_text)
        self.assertIn(
            "change impact changed-lines-under-tested",
            sonar["issues"][0]["primaryLocation"]["message"],
        )


if __name__ == "__main__":
    unittest.main()
