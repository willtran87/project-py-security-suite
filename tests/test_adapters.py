from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from py_security_suite.adapters.bandit import BanditAdapter
from py_security_suite.adapters.detect_secrets import DetectSecretsAdapter
from py_security_suite.adapters.osv import OsvScannerAdapter
from py_security_suite.adapters.semgrep import SemgrepAdapter
from py_security_suite.config import ToolConfig
from py_security_suite.models import Severity, json_ready


class AdapterParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.target = Path(self.temp.name).resolve()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_bandit_json_is_normalized(self) -> None:
        payload = json.dumps(
            {
                "results": [
                    {
                        "filename": str(self.target / "src" / "app.py"),
                        "line_number": 9,
                        "end_line_number": 9,
                        "test_id": "B602",
                        "test_name": "subprocess_popen_with_shell_equals_true",
                        "issue_text": "subprocess call with shell=True",
                        "issue_severity": "HIGH",
                        "issue_confidence": "HIGH",
                        "issue_cwe": {"id": 78},
                    }
                ]
            }
        )
        finding = BanditAdapter(ToolConfig(), 4096).parse(payload, self.target)[0]
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.locations[0].path, "src/app.py")
        self.assertIn("CWE-78", finding.classifications)

    def test_bandit_uses_native_absolute_exclusion_paths(self) -> None:
        command = BanditAdapter(ToolConfig(), 4096).build_command(
            "bandit", self.target
        )
        self.assertEqual(command[command.index("-r") + 1], str(self.target))
        excluded_paths = command[command.index("-x") + 1].split(",")
        self.assertEqual(
            excluded_paths[:2],
            [
                str((self.target / ".artifacts").resolve()),
                str((self.target / ".git").resolve()),
            ],
        )
        self.assertIn(str((self.target / ".pysec-tools").resolve()), excluded_paths)
        self.assertIn(str((self.target / "build").resolve()), excluded_paths)
        self.assertTrue(all(Path(path).is_absolute() for path in excluded_paths))

    def test_semgrep_json_preserves_rule_and_citations(self) -> None:
        payload = json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.subprocess-shell-true",
                        "path": "src/job.py",
                        "start": {"line": 12},
                        "end": {"line": 12},
                        "extra": {
                            "message": "Avoid shell=True",
                            "severity": "ERROR",
                            "metadata": {
                                "cwe": ["CWE-78"],
                                "confidence": "HIGH",
                                "category": "injection",
                            },
                        },
                    }
                ]
            }
        )
        finding = SemgrepAdapter(ToolConfig(), 4096).parse(payload, self.target)[0]
        self.assertEqual(finding.sources[0].rule_id, "python.subprocess-shell-true")
        self.assertEqual(finding.area, "injection")
        self.assertEqual(finding.severity, Severity.HIGH)

    def test_detect_secrets_never_retains_secret_hash(self) -> None:
        payload = json.dumps(
            {
                "results": {
                    "settings.py": [
                        {
                            "type": "Secret Keyword",
                            "line_number": 3,
                            "hashed_secret": "must-not-be-retained",  # nosec B105  # pragma: allowlist secret
                        }
                    ]
                }
            }
        )
        finding = DetectSecretsAdapter(ToolConfig(), 4096).parse(
            payload, self.target
        )[0]
        serialized = json.dumps(json_ready(finding))
        self.assertNotIn("must-not-be-retained", serialized)
        self.assertTrue(finding.evidence["redacted"])

    def test_detect_secrets_exclusion_accepts_both_path_separators(self) -> None:
        (self.target / ".pysec-tools").mkdir()
        (self.target / ".artifacts").mkdir()
        (self.target / "src").mkdir()
        (self.target / "pyproject.toml").touch()
        command = DetectSecretsAdapter(ToolConfig(), 4096).build_command(
            "detect-secrets", self.target
        )
        self.assertEqual(command[1:4], ["--cores", "1", "scan"])
        scan_arguments = command[4 : command.index("--all-files")]
        self.assertIn(str((self.target / "src").resolve()), scan_arguments)
        self.assertIn(str((self.target / "pyproject.toml").resolve()), scan_arguments)
        self.assertNotIn(str((self.target / ".pysec-tools").resolve()), scan_arguments)
        self.assertNotIn(str((self.target / ".artifacts").resolve()), scan_arguments)
        pattern = command[command.index("--exclude-files") + 1]

        self.assertIsNotNone(re.search(pattern, ".artifacts/report.json"))
        self.assertIsNotNone(re.search(pattern, r".pysec-tools\Scripts\tool.exe"))

    def test_osv_v2_json_is_normalized(self) -> None:
        payload = json.dumps(
            {
                "results": [
                    {
                        "source": {"path": "uv.lock"},
                        "packages": [
                            {
                                "package": {
                                    "name": "example",
                                    "version": "1.0",
                                    "ecosystem": "PyPI",
                                },
                                "vulnerabilities": [
                                    {
                                        "id": "GHSA-AAAA-BBBB-CCCC",
                                        "summary": "Example vulnerability",
                                        "database_specific": {
                                            "severity": "CRITICAL"
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        )
        finding = OsvScannerAdapter(ToolConfig(), 4096).parse(
            payload, self.target
        )[0]
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.locations[0].package, "example")
        self.assertEqual(finding.citations[0].identifier, "GHSA-AAAA-BBBB-CCCC")

    def test_osv_empty_results_are_valid(self) -> None:
        findings = OsvScannerAdapter(ToolConfig(), 4096).parse(
            json.dumps({"results": None}), self.target
        )
        self.assertEqual(findings, [])

    def test_osv_scans_the_resolved_target(self) -> None:
        command = OsvScannerAdapter(ToolConfig(), 4096).build_command(
            "osv-scanner", self.target
        )
        self.assertEqual(command[-1], str(self.target))


if __name__ == "__main__":
    unittest.main()
