from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from py_security_suite.adapters.reachability import ReachabilityAdapter
from py_security_suite.config import ToolConfig
from py_security_suite.models import Confidence, Severity
from py_security_suite.reachability import analyze_project


class ReachabilityAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        package = self.root / "src" / "example"
        package.mkdir(parents=True)
        (self.root / "pyproject.toml").write_text(
            """
[project]
name = "reachability-fixture"
version = "1.0"

[project.scripts]
fixture = "example.cli:main"

[tool.setuptools.packages.find]
where = ["src"]
""".strip(),
            encoding="utf-8",
        )
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "cli.py").write_text(
            "from .service import run\n\ndef main():\n    return run()\n",
            encoding="utf-8",
        )
        (package / "service.py").write_text(
            "def helper():\n    return 1\n\ndef run():\n    return helper()\n",
            encoding="utf-8",
        )
        (package / "unused.py").write_text(
            "from .orphan import abandoned\n\ndef legacy():\n    return abandoned()\n",
            encoding="utf-8",
        )
        (package / "orphan.py").write_text(
            "def abandoned():\n    return 'old'\n",
            encoding="utf-8",
        )

    def test_discovers_entry_point_sequences_and_unreachable_module_island(
        self,
    ) -> None:
        document = analyze_project(self.root, minimum_island_loc=1)

        self.assertTrue(document["analysis"]["complete"])
        self.assertFalse(document["analysis"]["target_code_executed"])
        self.assertEqual(document["schema_version"], "1.1")
        self.assertEqual(
            document["analysis"]["reachability_model"],
            "executable-load-only-disconnected",
        )
        self.assertEqual(document["summary"]["entry_points"], 1)
        self.assertEqual(document["summary"]["unreachable_modules"], 2)
        self.assertEqual(document["summary"]["executable_nodes"], 3)
        island = next(
            item for item in document["islands"] if item["kind"] == "module-island"
        )
        self.assertEqual(island["modules"], ["example.orphan", "example.unused"])
        self.assertTrue(island["reportable"])
        sequences = document["representative_sequences"][0]["representative_paths"]
        rendered = "\n".join(" -> ".join(item["sequence"]) for item in sequences)
        self.assertIn("example.cli:main", rendered)
        self.assertIn("example.service:run", rendered)
        self.assertIn("example.service:helper", rendered)
        self.assertTrue(
            all(
                edge["kind"] == "call" and edge["confidence"] == "high"
                for sequence in sequences
                for edge in sequence["edges"]
            )
        )

    def test_separates_load_only_definitions_from_executable_calls(self) -> None:
        package = self.root / "src" / "example"
        (package / "catalog.py").write_text(
            "def registered_but_not_called():\n"
            "    return 'available'\n\n"
            "EXPORTED = registered_but_not_called\n",
            encoding="utf-8",
        )
        (package / "cli.py").write_text(
            "from . import catalog\n"
            "from .service import run\n\n"
            "def main():\n"
            "    _ = catalog.EXPORTED\n"
            "    return run()\n",
            encoding="utf-8",
        )

        document = analyze_project(self.root, minimum_island_loc=1)
        nodes = {item["id"]: item for item in document["nodes"]}
        candidate = nodes["symbol:example.catalog:registered_but_not_called"]

        self.assertEqual(candidate["state"], "load-only")
        self.assertTrue(candidate["reachable"])
        self.assertEqual(candidate["reachability"]["edge_kind"], "definition")
        self.assertEqual(nodes["symbol:example.service:run"]["state"], "executable")
        self.assertEqual(nodes["symbol:example.unused:legacy"]["state"], "disconnected")
        self.assertGreater(document["summary"]["load_only_nodes"], 0)
        load_only = [
            item for item in document["islands"] if item["state"] == "load-only"
        ]
        self.assertTrue(load_only)
        self.assertIn(
            "example.catalog:registered_but_not_called",
            {symbol for item in load_only for symbol in item.get("symbols", [])},
        )

    def test_bounded_polymorphic_dispatch_marks_implementations_executable(
        self,
    ) -> None:
        package = self.root / "src" / "example"
        (package / "workers.py").write_text(
            "class First:\n"
            "    def execute(self):\n"
            "        return 1\n\n"
            "class Second:\n"
            "    def execute(self):\n"
            "        return 2\n",
            encoding="utf-8",
        )
        (package / "cli.py").write_text(
            "from .workers import First, Second\n\n"
            "def main():\n"
            "    workers = [First(), Second()]\n"
            "    return [worker.execute() for worker in workers]\n",
            encoding="utf-8",
        )

        document = analyze_project(self.root, minimum_island_loc=1)
        nodes = {item["id"]: item for item in document["nodes"]}
        dispatch_edges = [
            edge
            for edge in document["edges"]
            if edge["kind"] == "dispatch" and edge["target"].endswith(".execute")
        ]

        self.assertEqual(
            nodes["symbol:example.workers:First.execute"]["state"], "executable"
        )
        self.assertEqual(
            nodes["symbol:example.workers:Second.execute"]["state"], "executable"
        )
        self.assertEqual(len(dispatch_edges), 2)
        self.assertTrue(all(edge["confidence"] == "medium" for edge in dispatch_edges))
        self.assertIn("polymorphic-dispatch", document["dynamic_features"])

    def test_recognized_ast_visitor_hooks_are_framework_dispatch(self) -> None:
        package = self.root / "src" / "example"
        (package / "visitor.py").write_text(
            "import ast\n\n"
            "class Names(ast.NodeVisitor):\n"
            "    def visit_Name(self, node):\n"
            "        return node.id\n",
            encoding="utf-8",
        )
        (package / "cli.py").write_text(
            "from .visitor import Names\n\ndef main():\n    return Names()\n",
            encoding="utf-8",
        )

        document = analyze_project(self.root, minimum_island_loc=1)
        nodes = {item["id"]: item for item in document["nodes"]}
        hook = nodes["symbol:example.visitor:Names.visit_Name"]

        self.assertEqual(hook["state"], "executable")
        self.assertEqual(hook["reachability"]["edge_kind"], "framework-dispatch")
        self.assertEqual(hook["reachability"]["confidence"], "high")

    def test_coverage_evidence_corroborates_static_states_without_reclassifying(
        self,
    ) -> None:
        package = self.root / "src" / "example"
        (package / "catalog.py").write_text(
            "def callback():\n    return 'observed indirectly'\n",
            encoding="utf-8",
        )
        (package / "cli.py").write_text(
            "from . import catalog\n"
            "from .service import run\n\n"
            "def main():\n"
            "    return run()\n",
            encoding="utf-8",
        )
        coverage = self.root / "coverage.json"
        coverage.write_text(
            json.dumps(
                {
                    "files": {
                        "src/example/catalog.py": {"executed_lines": [1, 2]},
                        "src/example/service.py": {"executed_lines": [1, 2, 4, 5]},
                    }
                }
            ),
            encoding="utf-8",
        )

        document = analyze_project(
            self.root,
            minimum_island_loc=1,
            coverage_path=Path("coverage.json"),
        )
        nodes = {item["id"]: item for item in document["nodes"]}
        callback = nodes["symbol:example.catalog:callback"]

        self.assertEqual(callback["state"], "load-only")
        self.assertEqual(callback["runtime_observation"], "observed")
        self.assertTrue(document["analysis"]["coverage_evidence"]["valid"])
        self.assertGreaterEqual(document["summary"]["observed_load_only_nodes"], 1)
        island = next(
            item
            for item in document["islands"]
            if "example.catalog:callback" in item.get("symbols", [])
        )
        self.assertEqual(island["runtime_observation"], "observed")

    def test_invalid_coverage_evidence_fails_closed(self) -> None:
        coverage = self.root / "coverage.json"
        coverage.write_text(
            json.dumps({"files": {"../outside.py": {"executed_lines": [1]}}}),
            encoding="utf-8",
        )

        document = analyze_project(
            self.root,
            coverage_path=coverage,
        )

        self.assertFalse(document["analysis"]["complete"])
        self.assertEqual(document["analysis"]["confidence"], "low")
        self.assertFalse(document["analysis"]["coverage_evidence"]["valid"])
        self.assertTrue(
            any("coverage source path escapes" in error for error in document["errors"])
        )

    def test_configured_and_framework_roots_are_conservative(self) -> None:
        handler = self.root / "src" / "example" / "web.py"
        handler.write_text(
            "class Router:\n"
            "    def get(self, path):\n"
            "        return lambda function: function\n\n"
            "router = Router()\n\n"
            "@router.get('/health')\n"
            "def health():\n"
            "    return 'ok'\n",
            encoding="utf-8",
        )
        document = analyze_project(
            self.root,
            configured_entry_points=("example.service:run",),
            minimum_island_loc=1,
        )
        kinds = {item["kind"] for item in document["entry_points"]}
        self.assertIn("configured", kinds)
        self.assertIn("framework-decorator", kinds)
        self.assertNotIn(
            "example.web:health",
            {
                symbol
                for island in document["islands"]
                for symbol in island.get("symbols", [])
            },
        )

    def test_dynamic_loading_is_disclosed_and_lowers_confidence(self) -> None:
        service = self.root / "src" / "example" / "service.py"
        service.write_text(
            "import importlib\n\ndef run():\n"
            "    return importlib.import_module('example.plugin')\n",
            encoding="utf-8",
        )
        document = analyze_project(self.root, minimum_island_loc=1)
        self.assertEqual(document["analysis"]["confidence"], "medium")
        self.assertIn("importlib.import_module", document["dynamic_features"])
        self.assertTrue(
            any("Dynamic loading" in warning for warning in document["warnings"])
        )

    def test_missing_and_invalid_roots_make_conclusions_incomplete(self) -> None:
        (self.root / "pyproject.toml").write_text(
            "[project]\nname = 'fixture'\nversion = '1.0'\n"
            "[tool.setuptools.packages.find]\nwhere = ['src']\n",
            encoding="utf-8",
        )
        document = analyze_project(
            self.root,
            minimum_island_loc=1,
            discover_framework_roots=False,
        )
        self.assertFalse(document["analysis"]["complete"])
        self.assertEqual(document["analysis"]["confidence"], "low")
        self.assertEqual(document["summary"]["entry_points"], 0)
        self.assertTrue(any("No resolvable" in item for item in document["warnings"]))

        invalid = analyze_project(
            self.root,
            configured_entry_points=("example.missing:main",),
            discover_framework_roots=False,
        )
        self.assertTrue(
            any("could not be resolved" in item for item in invalid["errors"])
        )

    def test_parse_errors_and_escaping_source_roots_are_explicit(self) -> None:
        (self.root / "src" / "example" / "broken.py").write_text(
            "def invalid(:\n",
            encoding="utf-8",
        )
        document = analyze_project(self.root)
        self.assertFalse(document["analysis"]["complete"])
        self.assertEqual(document["analysis"]["confidence"], "low")
        self.assertTrue(any("broken.py" in item for item in document["errors"]))
        self.assertTrue(
            any("could not be analyzed" in item for item in document["warnings"])
        )

        with self.assertRaisesRegex(ValueError, "escapes the target"):
            analyze_project(
                self.root,
                configured_source_roots=("../outside",),
            )

    def test_root_layout_main_guard_and_symbol_island(self) -> None:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        (root / "main.py").write_text(
            "def live():\n"
            "    return 1\n\n"
            "def obsolete():\n"
            "    return 2\n\n"
            "if __name__ == '__main__':\n"
            "    live()\n",
            encoding="utf-8",
        )
        document = analyze_project(root, minimum_island_loc=1)
        self.assertIn(
            "python-main", {entry["kind"] for entry in document["entry_points"]}
        )
        self.assertIn(
            "main:obsolete",
            {
                symbol
                for island in document["islands"]
                for symbol in island.get("symbols", [])
            },
        )
        self.assertIn("used repository root", document["scope"]["notes"][0])

    def test_poetry_plugin_declaration_and_dynamic_constructs(self) -> None:
        (self.root / "pyproject.toml").write_text(
            "[tool.setuptools.packages.find]\nwhere = ['src']\n\n"
            "[tool.poetry.scripts]\n"
            "fixture = { reference = 'example.cli:main' }\n",
            encoding="utf-8",
        )
        dynamic_call = "ev" + "al"
        (self.root / "src" / "example" / "plugin.py").write_text(
            f"from .orphan import *\n\ndef activate():\n    return {dynamic_call}('1')\n",
            encoding="utf-8",
        )
        document = analyze_project(
            self.root,
            configured_entry_points=("example.plugin:activate", "example.service"),
            minimum_island_loc=1,
        )
        kinds = {entry["kind"] for entry in document["entry_points"]}
        self.assertIn("poetry-script", kinds)
        self.assertIn("configured", kinds)
        self.assertIn("wildcard-import", document["dynamic_features"])
        self.assertIn("eval", document["dynamic_features"])


class ReachabilityAdapterTests(unittest.TestCase):
    def test_adapter_normalizes_island_and_retains_graph_artifact(self) -> None:
        document = {
            "schema_version": "1.1",
            "analysis": {"confidence": "medium"},
            "summary": {"entry_points": 2},
            "entry_points": [],
            "representative_sequences": [],
            "islands": [
                {
                    "id": "symbol-island-fixture",
                    "kind": "symbol-island",
                    "primary_module": "example.legacy",
                    "primary_symbol": "obsolete",
                    "modules": ["example.legacy"],
                    "module_count": 1,
                    "symbol_count": 3,
                    "symbols": ["example.legacy:obsolete"],
                    "lines_of_code": 1200,
                    "paths": ["src/example/legacy.py"],
                    "reportable": True,
                    "reason": "no static path",
                }
            ],
            "nodes": [],
            "edges": [],
            "dynamic_features": ["importlib.import_module"],
            "warnings": [],
            "errors": [],
        }
        payload = json.dumps(document)
        adapter = ReachabilityAdapter(
            ToolConfig(
                executable="pysec",
                minimum_island_loc=75,
                entry_points=("example.plugin:load",),
                source_roots=("src",),
                discover_framework_roots=False,
                coverage_path=Path("coverage.json"),
            ),
            1024 * 1024,
        )

        findings = adapter.parse(payload, Path("."))
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(finding.confidence, Confidence.MEDIUM)
        self.assertEqual(finding.area, "code-reachability")
        self.assertIn("CWE-561", finding.classifications)
        self.assertEqual(finding.locations[0].path, "src/example/legacy.py")
        self.assertEqual(
            adapter.derived_artifacts(payload, Path("."))["reachability.json"],
            document,
        )
        command = adapter.build_command("pysec", Path("."))
        self.assertIn("--minimum-island-loc", command)
        self.assertIn("--no-framework-roots", command)
        self.assertIn("--coverage", command)

    def test_load_only_candidate_is_precise_and_does_not_assert_dead_code(self) -> None:
        document = {
            "schema_version": "1.1",
            "analysis": {"confidence": "high"},
            "summary": {"entry_points": 1},
            "entry_points": [],
            "representative_sequences": [],
            "islands": [
                {
                    "id": "load-only-fixture",
                    "kind": "load-only-symbol-island",
                    "state": "load-only",
                    "primary_module": "example.handlers",
                    "primary_symbol": "legacy_callback",
                    "primary_path": "src/example/handlers.py",
                    "primary_start_line": 41,
                    "primary_end_line": 55,
                    "modules": ["example.handlers"],
                    "module_count": 1,
                    "symbol_count": 1,
                    "symbols": ["example.handlers:legacy_callback"],
                    "lines_of_code": 15,
                    "paths": ["src/example/handlers.py"],
                    "reportable": True,
                    "reason": "loaded but no direct call path",
                }
            ],
            "nodes": [],
            "edges": [],
            "dynamic_features": [],
            "warnings": [],
            "errors": [],
        }

        finding = ReachabilityAdapter(ToolConfig(), 1024).parse(
            json.dumps(document), Path(".")
        )[0]

        self.assertEqual(finding.severity, Severity.LOW)
        self.assertIn("Load-only code candidate", finding.title)
        self.assertIn("PYREACH-LOAD-ONLY-CANDIDATE", finding.classifications)
        self.assertNotIn("CWE-561", finding.classifications)
        self.assertEqual(finding.locations[0].start_line, 41)
        self.assertEqual(finding.locations[0].end_line, 55)
        self.assertEqual(finding.evidence["state"], "load-only")

    def test_runtime_observed_candidate_reports_model_gap_not_dead_code(self) -> None:
        document = {
            "schema_version": "1.1",
            "analysis": {"confidence": "medium"},
            "summary": {"entry_points": 1},
            "entry_points": [],
            "representative_sequences": [],
            "islands": [
                {
                    "id": "observed-fixture",
                    "kind": "load-only-symbol-island",
                    "state": "load-only",
                    "runtime_observation": "observed",
                    "primary_module": "example.hooks",
                    "primary_symbol": "callback",
                    "primary_path": "src/example/hooks.py",
                    "primary_start_line": 9,
                    "primary_end_line": 12,
                    "modules": ["example.hooks"],
                    "module_count": 1,
                    "symbol_count": 1,
                    "lines_of_code": 4,
                    "paths": ["src/example/hooks.py"],
                    "reportable": True,
                }
            ],
            "nodes": [],
            "edges": [],
            "dynamic_features": [],
            "warnings": [],
            "errors": [],
        }

        finding = ReachabilityAdapter(ToolConfig(), 1024).parse(
            json.dumps(document), Path(".")
        )[0]

        self.assertEqual(finding.severity, Severity.INFORMATIONAL)
        self.assertIn("Runtime-observed static candidate", finding.title)
        self.assertIn("PYREACH-OBSERVED-STATIC-GAP", finding.classifications)
        self.assertNotIn("CWE-561", finding.classifications)

    def test_missing_roots_and_analysis_errors_are_actionable(self) -> None:
        document = {
            "schema_version": "1.1",
            "analysis": {"confidence": "low"},
            "summary": {"entry_points": 0},
            "entry_points": [],
            "representative_sequences": [],
            "islands": [],
            "nodes": [],
            "edges": [],
            "dynamic_features": [],
            "warnings": [],
            "errors": ["src/broken.py:7: invalid syntax"],
        }
        findings = ReachabilityAdapter(ToolConfig(), 1024).parse(
            json.dumps(document), Path(".")
        )
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(item.severity is Severity.MEDIUM for item in findings))
        self.assertEqual(findings[0].locations[0].path, "src/broken.py")

    def test_applicability_validation_and_unknown_values_are_bounded(self) -> None:
        adapter = ReachabilityAdapter(ToolConfig(), 1024)
        with tempfile.TemporaryDirectory() as directory:
            self.assertIn(
                "no Python", adapter.not_applicable_reason(Path(directory)) or ""
            )
        with self.assertRaisesRegex(ValueError, "schema version"):
            adapter.parse('{"schema_version":"2.0"}', Path("."))

        finding = adapter.parse(
            json.dumps(
                {
                    "schema_version": "1.1",
                    "analysis": {"confidence": "unexpected"},
                    "summary": {"entry_points": 1},
                    "entry_points": [],
                    "representative_sequences": [],
                    "islands": [
                        {
                            "reportable": True,
                            "kind": "module-island",
                            "lines_of_code": "invalid",
                        }
                    ],
                    "nodes": [],
                    "edges": [],
                    "dynamic_features": [],
                    "warnings": [],
                    "errors": [],
                }
            ),
            Path("."),
        )[0]
        self.assertEqual(finding.confidence, Confidence.UNKNOWN)
        self.assertEqual(finding.evidence["lines_of_code"], 0)


if __name__ == "__main__":
    unittest.main()
