from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from py_security_suite.adapters.codeql import CodeQlAdapter
from py_security_suite.adapters.cyclonedx import CycloneDxAdapter
from py_security_suite.adapters.gitleaks import GitleaksAdapter
from py_security_suite.adapters.guarddog import GuardDogAdapter
from py_security_suite.adapters.pysa import PysaAdapter
from py_security_suite.adapters.ruff import RuffAdapter
from py_security_suite.adapters.scancode import ScanCodeAdapter
from py_security_suite.adapters.trivy import TrivyAdapter
from py_security_suite.adapters.zizmor import ZizmorAdapter
from py_security_suite.config import ToolConfig
from py_security_suite.models import Severity, json_ready


class AdditionalAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.target = Path(self.enterContext(temporary)).resolve()

    def test_ruff_security_json_is_normalized(self) -> None:
        payload = json.dumps(
            [
                {
                    "code": "S602",
                    "filename": str(self.target / "app.py"),
                    "message": "subprocess call with shell=True",
                    "location": {"row": 4, "column": 1},
                    "end_location": {"row": 4, "column": 10},
                    "url": "https://docs.astral.sh/ruff/rules/subprocess-popen-with-shell-equals-true/",
                }
            ]
        )
        finding = RuffAdapter(ToolConfig(), 4096).parse(payload, self.target)[0]
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertIn("CWE-78", finding.classifications)
        self.assertEqual(finding.locations[0].path, "app.py")

    def test_cyclonedx_is_retained_as_a_derived_artifact(self) -> None:
        payload = json.dumps(
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
        )
        adapter = CycloneDxAdapter(ToolConfig(), 4096)
        self.assertEqual(adapter.parse(payload, self.target), [])
        self.assertEqual(
            adapter.derived_artifacts(payload, self.target)["sbom.cdx.json"][
                "bomFormat"
            ],
            "CycloneDX",
        )

    def test_zizmor_sarif_is_normalized(self) -> None:
        payload = _sarif(
            rule_id="template-injection",
            path=".github/workflows/ci.yml",
            line=12,
        )
        finding = ZizmorAdapter(ToolConfig(), 4096).parse(payload, self.target)[0]
        self.assertEqual(finding.area, "ci-cd")
        self.assertEqual(finding.locations[0].start_line, 12)

    def test_pysa_data_flow_json_is_normalized(self) -> None:
        payload = json.dumps(
            [
                {
                    "line": 9,
                    "path": "app.py",
                    "code": 5001,
                    "name": "Possible shell injection",
                    "description": "UserControlled reaches RemoteCodeExecution",
                }
            ]
        )
        finding = PysaAdapter(ToolConfig(), 4096).parse(payload, self.target)[0]
        self.assertEqual(finding.area, "injection")
        self.assertIn("CWE-78", finding.classifications)

    def test_trivy_misconfiguration_json_is_normalized(self) -> None:
        payload = json.dumps(
            {
                "Results": [
                    {
                        "Target": "Dockerfile",
                        "Misconfigurations": [
                            {
                                "ID": "DS002",
                                "Title": "Image user should not be root",
                                "Description": "Container runs as root",
                                "Resolution": "Add a non-root USER",
                                "Severity": "HIGH",
                                "CauseMetadata": {
                                    "StartLine": 7,
                                    "EndLine": 7,
                                },
                            }
                        ],
                    }
                ]
            }
        )
        finding = TrivyAdapter(ToolConfig(), 4096).parse(payload, self.target)[0]
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.area, "deployment-configuration")

    def test_guarddog_never_retains_matched_code(self) -> None:
        payload = json.dumps(
            {
                "issues": 1,
                "risks": [
                    {
                        "severity": "high",
                        "threat_rule": "exec-base64",
                        "threat_description": "Encoded execution",
                        "threat_location": "package/setup.py:8",
                        "file_path": "package/setup.py",
                        "threat_code": "must-not-be-retained()",
                        "mitre_tactics": ["execution"],
                    }
                ],
            }
        )
        finding = GuardDogAdapter(ToolConfig(), 4096).parse(payload, self.target)[0]
        self.assertNotIn("must-not-be-retained", json.dumps(json_ready(finding)))
        self.assertEqual(finding.area, "package-integrity")

    @unittest.skipUnless(os.name == "nt", "native Windows applicability")
    def test_guarddog_is_not_applicable_to_native_windows(self) -> None:
        (self.target / "app.py").write_text("pass\n", encoding="utf-8")
        reason = GuardDogAdapter(ToolConfig(), 4096).not_applicable_reason(self.target)
        self.assertIn("does not support native Windows", reason or "")

    def test_scancode_unknown_license_is_actionable_and_inventory_is_compact(
        self,
    ) -> None:
        payload = json.dumps(
            {
                "files": [
                    {
                        "path": "vendor/example.py",
                        "license_detections": [
                            {
                                "license_expression": "unknown-license-reference",
                                "matches": [{"start_line": 1, "end_line": 3}],
                            }
                        ],
                    }
                ]
            }
        )
        adapter = ScanCodeAdapter(ToolConfig(), 4096)
        finding = adapter.parse(payload, self.target)[0]
        artifact = adapter.derived_artifacts(payload, self.target)
        self.assertEqual(finding.area, "license-governance")
        self.assertIn("scancode-inventory.json", artifact)
        (self.target / "pyproject.toml").write_text(
            "[project]\nname = 'example'\n",
            encoding="utf-8",
        )
        (self.target / "build").mkdir()
        command = adapter.build_command("scancode", self.target)
        self.assertEqual(command[-1], str(self.target))
        self.assertNotIn("--copyright", command)
        self.assertNotIn("build", command)

    def test_gitleaks_report_is_redacted_during_normalization(self) -> None:
        report = self.target / "gitleaks.json"
        report.write_text(
            json.dumps(
                [
                    {
                        "RuleID": "generic-api-key",
                        "Description": "Generic API key",
                        "File": "settings.py",
                        "StartLine": 2,
                        "Commit": "abc123",
                        "Secret": "must-not-be-retained",  # nosec B105  # pragma: allowlist secret
                        "Match": "token=must-not-be-retained",  # nosec B105  # pragma: allowlist secret
                    }
                ]
            ),
            encoding="utf-8",
        )
        adapter = GitleaksAdapter(ToolConfig(), 4096)
        adapter._report_path = report
        finding = adapter.parse("", self.target)[0]
        self.assertNotIn("must-not-be-retained", json.dumps(json_ready(finding)))
        self.assertTrue(finding.evidence["redacted"])
        self.assertFalse(report.exists())

    def test_gitleaks_uses_local_config_and_current_tree_mode(self) -> None:
        (self.target / "app.py").write_text("pass\n", encoding="utf-8")
        rules = self.target / "gitleaks.toml"
        rules.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
        adapter = GitleaksAdapter(ToolConfig(rules_path=rules), 4096)
        command = adapter.build_command("gitleaks", self.target)
        self.assertEqual(command[1], "dir")
        self.assertEqual(command[command.index("--config") + 1], str(rules))

    def test_codeql_sarif_is_normalized(self) -> None:
        payload = _sarif(rule_id="py/sql-injection", path="db.py", line=21)
        finding = CodeQlAdapter(ToolConfig(), 4096).parse(payload, self.target)[0]
        self.assertEqual(finding.area, "data-flow")
        self.assertEqual(finding.locations[0].path, "db.py")
        self.assertEqual(finding.classifications, ["CODEQL-PY-SQL-INJECTION"])

    def test_codeql_quality_metadata_is_preserved(self) -> None:
        document = json.loads(
            _sarif(
                rule_id="py/implicit-string-concatenation-in-list",
                path="src/app.py",
                line=8,
            )
        )
        rule = document["runs"][0]["tool"]["driver"]["rules"][0]
        rule.pop("helpUri")
        rule["properties"] = {
            "tags": ["quality", "maintainability", "external/cwe/cwe-665"],
            "problem.severity": "warning",
            "precision": "high",
        }
        document["runs"][0]["results"][0].pop("level")
        finding = CodeQlAdapter(ToolConfig(), 4096).parse(
            json.dumps(document), self.target
        )[0]
        self.assertEqual(finding.domain, "quality")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.confidence.value, "high")
        self.assertEqual(finding.classifications, ["CWE-665"])
        self.assertIn("codeql-query-help", finding.citations[0].uri or "")


def _sarif(*, rule_id: str, path: str, line: int) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "fixture",
                            "rules": [
                                {
                                    "id": rule_id,
                                    "shortDescription": {"text": rule_id},
                                    "helpUri": "https://example.invalid/rule",
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": rule_id,
                            "level": "error",
                            "message": {"text": "Example security finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": path},
                                        "region": {
                                            "startLine": line,
                                            "endLine": line,
                                        },
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )


if __name__ == "__main__":
    unittest.main()
