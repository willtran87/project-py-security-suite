from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from py_security_suite.adapters.actionlint import ActionlintAdapter
from py_security_suite.adapters.devskim import DevSkimAdapter
from py_security_suite.adapters.flawfinder import FlawfinderAdapter
from py_security_suite.adapters.hadolint import HadolintAdapter
from py_security_suite.adapters.mypy import MypyAdapter
from py_security_suite.adapters.tach import TachAdapter
from py_security_suite.adapters.vulture import VultureAdapter
from py_security_suite.config import ToolConfig


class MaturityAdapterTests(unittest.TestCase):
    def test_mypy_normalizes_json_lines_without_source_excerpt(self) -> None:
        adapter = MypyAdapter(ToolConfig(), 1024)
        payload = json.dumps(
            {
                "file": "src/example.py",
                "line": 7,
                "column": 4,
                "message": "Incompatible return value type",
                "severity": "error",
                "code": "return-value",
            }
        )
        finding = adapter.parse(payload, Path("."))[0]
        self.assertEqual(finding.domain, "quality")
        self.assertEqual(finding.area, "type-safety")
        self.assertEqual(finding.sources[0].tool, "mypy")
        self.assertEqual(finding.classifications, ["MYPY-RETURN-VALUE"])
        self.assertEqual(finding.evidence, {})

    def test_vulture_retains_only_structured_confidence(self) -> None:
        adapter = VultureAdapter(ToolConfig(), 1024)
        finding = adapter.parse(
            "src/example.py:12: unused function 'legacy' (100% confidence)\n",
            Path("."),
        )[0]
        self.assertEqual(finding.domain, "quality")
        self.assertEqual(finding.area, "dead-code")
        self.assertEqual(finding.evidence, {"confidence_percent": 100})

    def test_tach_normalizes_architecture_boundary_violation(self) -> None:
        adapter = TachAdapter(ToolConfig(), 1024)
        finding = adapter.parse(
            "src/example/api.py[L17]: Cannot import 'example.persistence'. "
            "Module 'example.api' cannot depend on 'example.persistence'.\n",
            Path("."),
        )[0]
        self.assertEqual(finding.domain, "quality")
        self.assertEqual(finding.area, "architecture")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.locations[0].start_line, 17)
        self.assertEqual(finding.sources[0].tool, "tach")
        self.assertEqual(finding.sources[0].rule_id, "forbidden-dependency")

    def test_tach_requires_a_repository_architecture_contract(self) -> None:
        adapter = TachAdapter(ToolConfig(), 1024)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "app.py").write_text("value = 1\n", encoding="utf-8")
            self.assertIn(
                "tach.toml",
                adapter.not_applicable_reason(target) or "",
            )
            (target / "tach.toml").write_text(
                'source_roots = ["."]\n', encoding="utf-8"
            )
            self.assertIsNone(adapter.not_applicable_reason(target))

    def test_actionlint_omits_workflow_snippet_from_evidence(self) -> None:
        adapter = ActionlintAdapter(ToolConfig(), 1024)
        finding = adapter.parse(
            json.dumps(
                [
                    {
                        "message": "property is not defined",
                        "filepath": ".github/workflows/ci.yml",
                        "line": 8,
                        "column": 2,
                        "kind": "expression",
                        "snippet": "${{ secrets.VALUE }}",
                    }
                ]
            ),
            Path("."),
        )[0]
        self.assertEqual(finding.domain, "quality")
        self.assertEqual(finding.sources[0].tool, "actionlint")
        self.assertEqual(finding.evidence, {})
        self.assertNotIn("secrets.VALUE", json.dumps(finding.evidence))

    def test_hadolint_maps_native_rule_and_severity(self) -> None:
        adapter = HadolintAdapter(ToolConfig(), 1024)
        finding = adapter.parse(
            json.dumps(
                [
                    {
                        "code": "DL3002",
                        "column": 1,
                        "file": "Dockerfile",
                        "level": "warning",
                        "line": 3,
                        "message": "Last USER should not be root",
                    }
                ]
            ),
            Path("."),
        )[0]
        self.assertEqual(finding.domain, "security")
        self.assertEqual(finding.area, "container-hardening")
        self.assertEqual(finding.classifications, ["HADOLINT-DL3002"])

    def test_sarif_adapters_retain_tool_attribution(self) -> None:
        sarif = json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "scanner",
                                "rules": [
                                    {
                                        "id": "DS1001",
                                        "shortDescription": {"text": "Risky call"},
                                        "helpUri": "https://example.invalid/DS1001",
                                    }
                                ],
                            }
                        },
                        "results": [
                            {
                                "ruleId": "DS1001",
                                "level": "warning",
                                "message": {"text": "Risky call found"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {
                                                "uri": "src/example.py"
                                            },
                                            "region": {"startLine": 4},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
        devskim = DevSkimAdapter(ToolConfig(), 1024).parse(sarif, Path("."))[0]
        flawfinder = FlawfinderAdapter(ToolConfig(), 1024).parse(sarif, Path("."))[0]
        self.assertEqual(devskim.sources[0].tool, "devskim")
        self.assertEqual(devskim.area, "code-security-pattern")
        self.assertEqual(flawfinder.sources[0].tool, "flawfinder")
        self.assertEqual(flawfinder.area, "native-code")

    def test_devskim_command_avoids_duplicate_secret_rule(self) -> None:
        adapter = DevSkimAdapter(ToolConfig(), 1024)
        command = adapter.build_command("devskim", Path("."))
        self.assertIn("--ignore-rule-ids", command)
        self.assertEqual(
            command[command.index("--ignore-rule-ids") + 1],
            "DS173237",
        )

    def test_applicability_ignores_generated_native_sources(self) -> None:
        adapter = FlawfinderAdapter(ToolConfig(), 1024)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            generated = target / ".pysec-tools" / "vendor.c"
            generated.parent.mkdir()
            generated.write_text("int main(void) { return 0; }", encoding="utf-8")
            self.assertIsNotNone(adapter.not_applicable_reason(target))
            source = target / "extension.c"
            source.write_text("int main(void) { return 0; }", encoding="utf-8")
            self.assertIsNone(adapter.not_applicable_reason(target))


if __name__ == "__main__":
    unittest.main()
