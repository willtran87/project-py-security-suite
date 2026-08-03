from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from py_security_suite.adapters.checkov import CheckovAdapter
from py_security_suite.adapters.cosign import CosignAdapter
from py_security_suite.adapters.deptry import DeptryAdapter
from py_security_suite.adapters.diff_cover import DiffCoverAdapter
from py_security_suite.adapters.psscriptanalyzer import PSScriptAnalyzerAdapter
from py_security_suite.adapters.pyright import PyrightAdapter
from py_security_suite.adapters.scorecard import ScorecardAdapter
from py_security_suite.adapters.shellcheck import ShellCheckAdapter
from py_security_suite.config import ToolConfig
from py_security_suite.evidence_ingest import _scorecard_document


class InsightAdapterTests(unittest.TestCase):
    def test_deptry_preserves_rule_module_and_location(self) -> None:
        payload = json.dumps(
            [
                {
                    "error": {
                        "code": "DEP004",
                        "message": "runtime_lib imported but declared as dev",
                    },
                    "module": "runtime_lib",
                    "location": {"file": "src/app.py", "line": 8, "column": 0},
                }
            ]
        )
        finding = DeptryAdapter(ToolConfig(), 4096).parse(payload, Path("."))[0]
        self.assertEqual(finding.sources[0].tool, "deptry")
        self.assertEqual(finding.classifications, ["DEPTRY-DEP004"])
        self.assertEqual(finding.locations[0].start_line, 8)
        self.assertEqual(finding.evidence["module"], "runtime_lib")

    def test_deptry_scans_src_layout_and_uses_project_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "src").mkdir()
            command = DeptryAdapter(ToolConfig(), 4096).build_file_command(
                "deptry", target, target / "result.json"
            )
        self.assertEqual(Path(command[1]).name, "src")
        self.assertIn("--config", command)

    def test_diff_cover_reports_changed_uncovered_line(self) -> None:
        payload = json.dumps(
            {
                "total_percent_covered": 50,
                "total_num_violations": 1,
                "num_changed_lines": 2,
                "src_stats": {
                    "src/app.py": {
                        "percent_covered": 50,
                        "violation_lines": [12],
                        "covered_lines": [13],
                        "violations": [12],
                    }
                },
            }
        )
        findings = DiffCoverAdapter(
            ToolConfig(minimum_coverage_percent=80), 4096
        ).parse(payload, Path("."))
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[1].locations[0].start_line, 12)
        self.assertEqual(findings[1].domain, "testing")

    def test_diff_cover_does_not_flag_files_above_threshold(self) -> None:
        payload = json.dumps(
            {
                "total_percent_covered": 93,
                "total_num_violations": 3,
                "num_changed_lines": 49,
                "src_stats": {
                    "src/app.py": {
                        "percent_covered": 93.88,
                        "violation_lines": [10, 20, 30],
                        "covered_lines": list(range(1, 47)),
                    }
                },
            }
        )
        findings = DiffCoverAdapter(
            ToolConfig(minimum_coverage_percent=80), 4096
        ).parse(payload, Path("."))
        self.assertEqual(findings, [])

    def test_shellcheck_maps_rule_and_precise_range(self) -> None:
        payload = json.dumps(
            [
                {
                    "file": "scripts/deploy.sh",
                    "line": 4,
                    "endLine": 4,
                    "column": 3,
                    "endColumn": 8,
                    "level": "warning",
                    "code": 2086,
                    "message": "Double quote to prevent globbing",
                }
            ]
        )
        finding = ShellCheckAdapter(ToolConfig(), 4096).parse(payload, Path("."))[0]
        self.assertEqual(finding.classifications, ["SC2086"])
        self.assertEqual(finding.sources[0].tool, "shellcheck")
        self.assertIn("SC2086", finding.citations[0].uri or "")

    def test_psscriptanalyzer_maps_native_diagnostic(self) -> None:
        payload = json.dumps(
            [
                {
                    "RuleName": "PSAvoidUsingInvokeExpression",
                    "Severity": "Warning",
                    "ScriptPath": "scripts/run.ps1",
                    "Line": 7,
                    "EndLine": 7,
                    "Message": "Invoke-Expression is used",
                }
            ]
        )
        finding = PSScriptAnalyzerAdapter(ToolConfig(), 4096).parse(payload, Path("."))[
            0
        ]
        self.assertEqual(finding.area, "powershell-safety")
        self.assertEqual(finding.locations[0].start_line, 7)
        self.assertEqual(finding.sources[0].tool, "psscriptanalyzer")

    def test_pyright_converts_zero_based_lines(self) -> None:
        payload = json.dumps(
            {
                "generalDiagnostics": [
                    {
                        "file": "src/app.py",
                        "severity": "error",
                        "message": "Type is incompatible",
                        "rule": "reportAssignmentType",
                        "range": {
                            "start": {"line": 2, "character": 0},
                            "end": {"line": 2, "character": 4},
                        },
                    }
                ]
            }
        )
        finding = PyrightAdapter(ToolConfig(), 4096).parse(payload, Path("."))[0]
        self.assertEqual(finding.locations[0].start_line, 3)
        self.assertEqual(finding.sources[0].tool, "pyright")

    def test_pyright_project_does_not_override_configured_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "src").mkdir()
            cli = target / "index.js"
            rules = target / "pyrightconfig.json"
            adapter = PyrightAdapter(
                ToolConfig(database_path=cli, rules_path=rules), 4096
            )
            command = adapter.build_command("node", target)
        self.assertIn("--project", command)
        self.assertEqual(command[-1], str((target / "src").resolve()))

    def test_checkov_command_disables_downloads_and_normalizes_policy(self) -> None:
        adapter = CheckovAdapter(ToolConfig(), 4096)
        command = adapter.build_command("checkov", Path("."))
        self.assertIn("--skip-download", command)
        self.assertEqual(
            command[command.index("--download-external-modules") + 1], "false"
        )
        payload = json.dumps(
            {
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_DOCKER_3",
                            "check_name": "Ensure a user is created",
                            "file_path": "Dockerfile",
                            "resource": "Dockerfile",
                            "check_result": {"start_line": 1, "end_line": 4},
                        }
                    ]
                }
            }
        )
        finding = adapter.parse(payload, Path("."))[0]
        self.assertEqual(finding.classifications, ["CKV_DOCKER_3"])
        self.assertEqual(finding.locations[0].start_line, 1)

    def test_cosign_requires_explicit_offline_trust_configuration(self) -> None:
        config = ToolConfig(certificate_identity="release@example.test")
        error = CosignAdapter(config, 4096).prerequisite_error()
        self.assertIn("certificate_oidc_issuer", error or "")

    def test_scorecard_evidence_is_bounded_and_actionable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scorecard.json"
            path.write_text(
                json.dumps(
                    {
                        "repo": {"name": "github.com/example/project"},
                        "score": 6.5,
                        "date": "2026-01-01",
                        "checks": [
                            {
                                "name": "Branch-Protection",
                                "score": 3,
                                "reason": "Branch protection is weak",
                                "details": ["detail"],
                                "documentation": {
                                    "url": "https://github.com/ossf/scorecard/blob/main/docs/checks.md"
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            normalized = _scorecard_document(path)
        finding = ScorecardAdapter(ToolConfig(), 4096).parse(
            json.dumps(normalized), Path(".")
        )[0]
        self.assertEqual(finding.domain, "governance")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(finding.sources[0].tool, "scorecard")


if __name__ == "__main__":
    unittest.main()
