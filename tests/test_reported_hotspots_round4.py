from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

from py_security_suite.adapters.devskim import DevSkimAdapter
from py_security_suite.adapters.radon import (
    RadonAdapter,
    _flatten_blocks,
    _integer as radon_integer,
    _rank_severity,
)
from py_security_suite.adapters.reuse import ReuseAdapter, _issues, _rule_title
from py_security_suite.adapters.ruff import (
    RuffAdapter,
    _integer as ruff_integer,
    _rule_metadata,
    _safe_uri as ruff_safe_uri,
)
from py_security_suite.adapters.sarif import (
    _area,
    _classifications,
    _derived_help_uri,
    _domain,
    _integer as sarif_integer,
    _location,
    _locations,
    _message,
    _object,
    _object_list,
    _rule_classification,
    _rule_index,
    _safe_uri as sarif_safe_uri,
    _sarif_severity,
    _tags,
    _uri_path,
    parse_sarif_findings,
)
from py_security_suite.config import ToolConfig
from py_security_suite.inventory import (
    _declares_dependencies,
    _distribution_files,
    _is_excluded,
    inventory_target,
)
from py_security_suite.models import Severity


class RemainingAdapterContractTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(temporary)).resolve()

    def test_devskim_mirror_lifecycle_and_local_rules_command(self) -> None:
        rules = self.root / "devskim-rules"
        rules.mkdir()
        adapter = DevSkimAdapter(ToolConfig(rules_path=rules), 4096)
        mirror = self.root / "mirror"
        mirror.mkdir()
        sentinel = object()
        with (
            patch(
                "py_security_suite.adapters.devskim.mirrored_source_tree",
                return_value=nullcontext(mirror),
            ),
            patch(
                "py_security_suite.adapters.devskim.ScannerAdapter.run",
                return_value=sentinel,
            ),
        ):
            self.assertIs(adapter.run(self.root), sentinel)
        self.assertIsNone(adapter._scan_root)
        command = adapter.build_command("devskim", self.root)
        self.assertEqual(command[command.index("-r") + 1], str(rules))
        self.assertEqual(command[command.index("-I") + 1], str(self.root))

    def test_radon_applicability_nested_blocks_and_rejection_paths(self) -> None:
        adapter = RadonAdapter(ToolConfig(), 4096)
        self.assertIn("no Python", adapter.not_applicable_reason(self.root) or "")
        (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
        self.assertIsNone(adapter.not_applicable_reason(self.root))
        self.assertEqual(adapter.build_command("radon", self.root)[1], "cc")
        with self.assertRaisesRegex(TypeError, "must be an object"):
            adapter.parse("[]", self.root)
        with self.assertRaisesRegex(TypeError, "file entry must be a list"):
            adapter.parse('{"app.py":{}}', self.root)
        with self.assertRaisesRegex(TypeError, "block must be an object"):
            _flatten_blocks([1])
        with self.assertRaisesRegex(TypeError, "methods must be a list"):
            _flatten_blocks([{"methods": {}}])
        nested = _flatten_blocks(
            [
                {
                    "name": "container",
                    "methods": [{"name": "method"}],
                    "closures": [{"name": "closure"}],
                }
            ]
        )
        self.assertEqual(
            [item["name"] for item in nested], ["container", "method", "closure"]
        )
        with self.assertRaisesRegex(TypeError, "integer value is invalid"):
            radon_integer({"bad": 1})
        self.assertEqual(_rank_severity("E"), Severity.HIGH)
        self.assertEqual(_rank_severity("D"), Severity.MEDIUM)
        self.assertEqual(_rank_severity("C"), Severity.LOW)

    def test_reuse_applicability_issue_shapes_and_artifact(self) -> None:
        adapter = ReuseAdapter(ToolConfig(), 4096)
        self.assertIn("opt-in marker", adapter.not_applicable_reason(self.root) or "")
        (self.root / "REUSE.toml").write_text("version = 1\n", encoding="utf-8")
        self.assertIsNone(adapter.not_applicable_reason(self.root))
        self.assertEqual(
            adapter.build_command("reuse", self.root), ["reuse", "lint", "--json"]
        )
        with self.assertRaisesRegex(TypeError, "must be an object"):
            adapter.parse("[]", self.root)
        document = {
            "non_compliant": {
                "bad_licenses": {"LICENSE": "invalid identifier"},
                "deprecated_licenses": "ignored shape",
                "missing_licenses": [{"file": "LICENSES/MISSING.txt"}],
                "read_errors": [{"name": "unreadable.py", "message": "read failed"}],
                "invalid_spdx_expressions": ["src/legacy.py"],
            }
        }
        issues = _issues(document)
        self.assertEqual(len(issues), 4)
        findings = adapter.parse(json.dumps(document), self.root)
        self.assertEqual(len(findings), 4)
        self.assertEqual(_issues({"non_compliant": []}), [])
        self.assertEqual(_rule_title("missing-license"), "missing license")
        artifact = adapter.derived_artifacts(json.dumps(document), self.root)
        self.assertIn("reuse-compliance.json", artifact)

    def test_ruff_applicability_environment_guards_and_metadata_fallback(self) -> None:
        adapter = RuffAdapter(ToolConfig(), 4096)
        self.assertIn("no Python", adapter.not_applicable_reason(self.root) or "")
        (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
        self.assertIsNone(adapter.not_applicable_reason(self.root))
        self.assertEqual(adapter.environment().extra["RUFF_NO_CACHE"], "1")
        self.assertIn("--isolated", adapter.build_command("ruff", self.root))
        with self.assertRaisesRegex(TypeError, "must be a list"):
            adapter.parse("{}", self.root)
        with self.assertRaisesRegex(TypeError, "result must be an object"):
            adapter.parse("[1]", self.root)
        finding = adapter.parse(
            '[{"code":"S000","message":"fixture","filename":"app.py",'
            '"location":[],"end_location":[],"url":"relative"}]',
            self.root,
        )[0]
        self.assertIsNone(finding.locations[0].start_line)
        self.assertEqual(_rule_metadata("S000"), (Severity.MEDIUM, "python-code", []))
        self.assertIsNone(ruff_integer([]))
        self.assertIsNone(ruff_safe_uri("relative"))


class SarifNormalizationContractTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(temporary)).resolve()

    def test_sarif_shape_helpers_reject_and_normalize_defensively(self) -> None:
        with self.assertRaisesRegex(TypeError, "list of objects"):
            _object_list({}, "runs")
        with self.assertRaisesRegex(TypeError, "list of objects"):
            _object_list([1], "runs")
        self.assertEqual(_object([]), {})
        self.assertEqual(_object({"value": 1}), {"value": 1})
        self.assertEqual(_rule_index([]), {})
        self.assertEqual(_rule_index({"rules": {"bad": 1}}), {})
        self.assertEqual(_rule_index({"rules": [1, {"name": "missing id"}]}), {})
        self.assertEqual(_message(" value "), "value")
        self.assertEqual(_message({"markdown": " formatted "}), "formatted")
        self.assertEqual(_message([]), "")

    def test_sarif_location_uri_and_integer_fallbacks(self) -> None:
        self.assertEqual(_location({}, self.root).path, "<repository>")
        location = _location(
            {
                "locations": [
                    {
                        "physicalLocation": [],
                    }
                ]
            },
            self.root,
        )
        self.assertEqual(location.path, "<repository>")
        location = _location(
            {
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": [],
                            "region": [],
                        }
                    }
                ]
            },
            self.root,
        )
        self.assertEqual(location.path, "<repository>")
        self.assertEqual(_uri_path("src/example%20file.py"), "src/example file.py")
        self.assertEqual(_uri_path("file:///C:/repo/app.py"), "C:/repo/app.py")
        self.assertEqual(_uri_path("C:/repo/app.py"), "C:/repo/app.py")
        self.assertEqual(
            _uri_path("https://user:secret@example.test/app.py"),
            "<external-artifact>",
        )
        self.assertIsNone(sarif_integer([]))
        self.assertIsNone(sarif_safe_uri("relative"))

    def test_sarif_locations_are_bounded_deduplicated_and_auditable(self) -> None:
        primary = {
            "physicalLocation": {
                "artifactLocation": {"uri": "src/primary.py"},
                "region": {"startLine": 7},
            }
        }
        raw_locations: list[object] = [
            primary,
            primary,
            "invalid",
            {"physicalLocation": {"region": {"startLine": True}}},
            {"physicalLocation": {"region": {"startLine": 1.5}}},
        ]
        raw_locations.extend(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f"src/secondary-{index}.py"},
                    "region": {"startLine": index + 1},
                }
            }
            for index in range(30)
        )

        locations, summary = _locations({"locations": raw_locations}, self.root)

        self.assertEqual(len(locations), 25)
        self.assertEqual(locations[0].path, "src/primary.py")
        self.assertEqual(locations[0].start_line, 7)
        self.assertEqual(summary["reported_count"], 35)
        self.assertEqual(summary["retained_count"], 25)
        self.assertEqual(summary["duplicate_count"], 1)
        self.assertEqual(summary["invalid_count"], 3)
        self.assertEqual(summary["limit_omitted_count"], 6)
        self.assertEqual(summary["omitted_count"], 10)
        self.assertTrue(summary["truncated"])

    def test_sarif_severity_classification_domain_and_help_mapping(self) -> None:
        self.assertEqual(
            _sarif_severity(None, {"security-severity": 9.1}, {}), Severity.CRITICAL
        )
        self.assertEqual(
            _sarif_severity(None, {"security-severity": 7.2}, {}), Severity.HIGH
        )
        self.assertEqual(
            _sarif_severity(None, {"security-severity": 4.5}, {}), Severity.MEDIUM
        )
        self.assertEqual(
            _sarif_severity(None, {"security-severity": 0.1}, {}), Severity.LOW
        )
        self.assertEqual(_sarif_severity("note", {}, {}), Severity.INFORMATIONAL)
        classifications = _classifications(
            {"classifications": ["external/cwe/cwe-79", "OWASP-A03", "MITRE-T1059"]},
            {},
        )
        self.assertEqual(classifications, ["CWE-79", "OWASP-A03", "MITRE-T1059"])
        self.assertEqual(_tags({"tags": "Quality"}, {}), ["quality"])
        self.assertEqual(_domain(["quality"]), "quality")
        self.assertEqual(_domain(["quality", "security"]), "security")
        self.assertEqual(_area(["readability"], "fallback"), "code-quality")
        self.assertEqual(_area([], "fallback"), "fallback")
        self.assertEqual(_rule_classification("tool", "rule/value"), "TOOL-RULE-VALUE")
        self.assertIsNone(_derived_help_uri("devskim", "DS1001"))
        self.assertIn(
            "py-sql-injection", _derived_help_uri("codeql", "py/sql-injection") or ""
        )

    def test_sarif_quality_finding_uses_safe_defaults_without_location(self) -> None:
        payload = json.dumps(
            {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "rules": [
                                    {
                                        "id": "py/fixture-quality",
                                        "shortDescription": "Fixture quality rule",
                                        "properties": {"tags": ["quality"]},
                                    }
                                ]
                            }
                        },
                        "results": [
                            {
                                "ruleId": "py/fixture-quality",
                                "message": {"text": "Improve clarity"},
                            }
                        ],
                    }
                ]
            }
        )
        finding = parse_sarif_findings(
            payload,
            self.root,
            tool_name="codeql",
            default_area="fallback",
            default_impact="fallback impact",
            default_remediation="fallback action",
        )[0]
        self.assertEqual(finding.domain, "quality")
        self.assertEqual(finding.locations[0].path, "<repository>")
        self.assertEqual(finding.area, "fallback")
        self.assertIn("implementation mistake", finding.impact)
        self.assertIn("focused test", finding.remediation)


class InventoryContractTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(temporary)).resolve()

    def test_dependency_declaration_variants_are_detected(self) -> None:
        pyproject = self.root / "pyproject.toml"
        pyproject.write_text("not valid = [", encoding="utf-8")
        self.assertTrue(_declares_dependencies(self.root))
        pyproject.write_text(
            '[project.optional-dependencies]\nsecurity = ["fixture>=1"]\n',
            encoding="utf-8",
        )
        self.assertTrue(_declares_dependencies(self.root))
        pyproject.write_text(
            '[tool.poetry.dependencies]\npython = ">=3.11"\nfixture = ">=1"\n',
            encoding="utf-8",
        )
        self.assertTrue(_declares_dependencies(self.root))
        pyproject.write_text(
            '[dependency-groups]\ndev = ["fixture>=1"]\n', encoding="utf-8"
        )
        self.assertTrue(_declares_dependencies(self.root))

    def test_requirements_and_empty_metadata_decisions(self) -> None:
        pyproject = self.root / "pyproject.toml"
        pyproject.write_text('[project]\nname = "fixture"\n', encoding="utf-8")
        requirements = self.root / "requirements.txt"
        requirements.write_text("# comment\n--index-url local\n", encoding="utf-8")
        self.assertFalse(_declares_dependencies(self.root))
        requirements.write_text("fixture==1\n", encoding="utf-8")
        self.assertTrue(_declares_dependencies(self.root))
        with patch.object(Path, "read_text", side_effect=OSError("fixture")):
            self.assertTrue(_declares_dependencies(self.root))

    def test_inventory_exclusions_and_distribution_filtering(self) -> None:
        excluded = self.root / "excluded"
        nested = excluded / "nested"
        nested.mkdir(parents=True)
        included = self.root / "included.py"
        included.write_text("value = 1\n", encoding="utf-8")
        self.assertTrue(_is_excluded(excluded, (excluded,)))
        self.assertTrue(_is_excluded(nested, (excluded,)))
        self.assertFalse(_is_excluded(included, (excluded,)))
        self.assertEqual(_distribution_files(self.root), [])
        dist = self.root / "dist"
        dist.mkdir()
        for name in ("fixture.whl", "fixture.tar.gz", "fixture.zip", "ignored.txt"):
            (dist / name).write_bytes(b"fixture")
        self.assertEqual(
            _distribution_files(self.root),
            ["dist/fixture.tar.gz", "dist/fixture.whl", "dist/fixture.zip"],
        )
        inventory = inventory_target(self.root, excluded_paths=(excluded,))
        self.assertEqual(inventory.python_files, 1)


if __name__ == "__main__":
    unittest.main()
