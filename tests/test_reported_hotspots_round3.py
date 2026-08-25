from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from py_security_suite.adapters.bandit import (
    BanditAdapter,
    _area_for,
    _bandit_classifications,
    _guidance_for,
    _integer as bandit_integer,
    _safe_uri,
)
from py_security_suite.adapters.checkov import (
    CheckovAdapter,
    _finding as checkov_finding,
    _integer as checkov_integer,
    _severity as checkov_severity,
)
from py_security_suite.adapters.deptry import (
    DeptryAdapter,
    _impact,
    _integer as deptry_integer,
    _remediation,
    _severity as deptry_severity,
)
from py_security_suite.adapters.flawfinder import FlawfinderAdapter
from py_security_suite.adapters.gitleaks import (
    GitleaksAdapter,
    _integer as gitleaks_integer,
)
from py_security_suite.adapters.guarddog import GuardDogAdapter, _location
from py_security_suite.adapters.osv import OsvScannerAdapter, _native_severity
from py_security_suite.adapters.pyright import (
    PyrightAdapter,
    _one_based,
    _severity as pyright_severity,
    _summary,
)
from py_security_suite.adapters.scorecard import (
    ScorecardAdapter,
    _number,
    _severity as scorecard_severity,
)
from py_security_suite.adapters.tach import TachAdapter, _rule_id, _title
from py_security_suite.config import ToolConfig
from py_security_suite.models import Severity, ToolStatus


class ReportedSecurityAdapterContractTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(temporary)).resolve()

    def test_bandit_rejects_malformed_results_and_maps_guidance(self) -> None:
        adapter = BanditAdapter(ToolConfig(), 4096)
        with self.assertRaisesRegex(TypeError, "results must be a list"):
            adapter.parse('{"results":{}}', self.root)
        with self.assertRaisesRegex(TypeError, "result must be an object"):
            adapter.parse('{"results":[1]}', self.root)
        self.assertIsNone(bandit_integer([]))
        self.assertIsNone(_safe_uri("relative/rule"))
        self.assertEqual(_bandit_classifications({"issue_cwe": []}), [])
        self.assertEqual(_area_for("B105", [], "fixture"), "secrets")
        self.assertEqual(_area_for("custom", [], "SQL injection"), "injection")
        self.assertEqual(_area_for("custom", [], "weak crypto hash"), "cryptography")
        self.assertEqual(
            _area_for("custom", [], "unsafe pickle deserialize"),
            "unsafe-deserialization",
        )
        self.assertEqual(_area_for("custom", [], "generic issue"), "python-code")
        self.assertIn("Assertions", _guidance_for("B101")[0])
        self.assertIn("credential", _guidance_for("B105")[0])
        self.assertIn("temporary", _guidance_for("B108")[0])
        self.assertIn("Process-launching", _guidance_for("B404")[0])
        self.assertIn("without a shell", _guidance_for("B603")[0])
        self.assertIn("flagged Python", _guidance_for("custom")[0])

    def test_checkov_applicability_offline_command_and_parser_guards(self) -> None:
        adapter = CheckovAdapter(ToolConfig(), 4096)
        self.assertIn("no supported", adapter.not_applicable_reason(self.root) or "")
        dockerfile = self.root / "Dockerfile"
        dockerfile.write_text("FROM scratch\n", encoding="utf-8")
        self.assertIsNone(adapter.not_applicable_reason(self.root))
        environment = adapter.environment().extra
        self.assertEqual(environment["DOWNLOAD_EXTERNAL_MODULES"], "false")
        python_prefix = adapter.version_command("python.exe")
        self.assertIn("from checkov.main", python_prefix[2])
        self.assertEqual(adapter.version_command("checkov"), ["checkov", "--version"])
        self.assertIn("--skip-download", adapter.build_command("checkov", self.root))
        with self.assertRaisesRegex(TypeError, "report must be an object"):
            adapter.parse("[1]", self.root)
        with self.assertRaisesRegex(TypeError, "results must be an object"):
            adapter.parse('{"results":[]}', self.root)
        with self.assertRaisesRegex(TypeError, "failed_checks must be a list"):
            adapter.parse(
                '{"results":{"passed_checks":[],"failed_checks":{},"skipped_checks":[]}}',
                self.root,
            )
        with self.assertRaisesRegex(TypeError, "finding must be an object"):
            checkov_finding([], self.root)
        finding = checkov_finding(
            {
                "check_id": "CKV_FIXTURE",
                "check_result": [],
                "severity": "critical",
                "guideline": "relative",
            },
            self.root,
        )
        self.assertIsNone(finding.locations[0].start_line)
        self.assertEqual(finding.severity, Severity.CRITICAL)
        with self.assertRaisesRegex(ValueError, "empty report"):
            adapter.derived_artifacts("", self.root)
        self.assertIsNone(checkov_integer([]))
        self.assertEqual(checkov_severity("high"), Severity.HIGH)
        self.assertEqual(checkov_severity("low"), Severity.LOW)
        self.assertEqual(checkov_severity("unknown"), Severity.MEDIUM)

    def test_deptry_applicability_guards_artifact_and_rule_guidance(self) -> None:
        adapter = DeptryAdapter(ToolConfig(), 4096)
        self.assertIn(
            "dependency declaration", adapter.not_applicable_reason(self.root) or ""
        )
        (self.root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        self.assertIn("no Python", adapter.not_applicable_reason(self.root) or "")
        (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
        self.assertIsNone(adapter.not_applicable_reason(self.root))
        command = adapter.build_file_command(
            "deptry", self.root, self.root / "out.json"
        )
        self.assertEqual(Path(command[1]), self.root)
        with self.assertRaisesRegex(TypeError, "JSON list"):
            adapter.parse("{}", self.root)
        with self.assertRaisesRegex(TypeError, "finding must be an object"):
            adapter.parse("[1]", self.root)
        with self.assertRaisesRegex(TypeError, "error and location objects"):
            adapter.parse('[{"error":[],"location":{}}]', self.root)
        artifact = adapter.derived_artifacts("", self.root)
        self.assertEqual(artifact["deptry-dependencies.json"]["findings"], [])
        self.assertIsNone(deptry_integer([]))
        self.assertEqual(deptry_severity("DEP001"), Severity.MEDIUM)
        self.assertEqual(deptry_severity("DEP002"), Severity.LOW)
        for rule in ("DEP001", "DEP003", "DEP004", "DEP002"):
            with self.subTest(rule=rule):
                self.assertTrue(_impact(rule))
                self.assertTrue(_remediation(rule, "fixture"))

    def test_gitleaks_preflight_report_lifecycle_and_malformed_values(self) -> None:
        adapter = GitleaksAdapter(ToolConfig(), 4096)
        self.assertIn("no files", adapter.not_applicable_reason(self.root) or "")
        (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
        self.assertIsNone(adapter.not_applicable_reason(self.root))
        self.assertIsNone(adapter.prerequisite_error())
        missing = GitleaksAdapter(
            ToolConfig(rules_path=self.root / "missing.toml"), 4096
        )
        self.assertIn("does not exist", missing.prerequisite_error() or "")
        with self.assertRaisesRegex(ValueError, "not initialized"):
            adapter.parse("", self.root)
        adapter._report_path = self.root / "absent.json"
        self.assertEqual(adapter.parse("", self.root), [])
        report = self.root / "invalid.json"
        report.write_text("{}", encoding="utf-8")
        adapter._report_path = report
        with self.assertRaisesRegex(TypeError, "must be a list"):
            adapter.parse("", self.root)
        report.write_text(
            '[1,{"Description":"fixture","StartLine":[]} ]', encoding="utf-8"
        )
        adapter._report_path = report
        finding = adapter.parse("", self.root)[0]
        self.assertIsNone(finding.locations[0].start_line)
        self.assertIsNone(gitleaks_integer([]))
        (self.root / ".git").mkdir()
        command = adapter.build_command("gitleaks", self.root)
        self.assertEqual(command[1], "git")
        cleanup = adapter._report_path
        if cleanup is None:
            self.fail("Gitleaks did not initialize its report path")
        cleanup.write_text("[]", encoding="utf-8")
        result = adapter.run(self.root)
        self.assertIn(
            result.tool_run.status, {ToolStatus.COMPLETED, ToolStatus.UNAVAILABLE}
        )
        self.assertFalse(cleanup.exists())

    def test_guarddog_platform_applicability_environment_and_parser_shapes(
        self,
    ) -> None:
        adapter = GuardDogAdapter(ToolConfig(), 4096)
        with patch(
            "py_security_suite.adapters.guarddog.os", SimpleNamespace(name="posix")
        ):
            self.assertIn("no Python", adapter.not_applicable_reason(self.root) or "")
            (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
            self.assertIsNone(adapter.not_applicable_reason(self.root))
        if os.name == "nt":
            self.assertIn(
                "native Windows", adapter.not_applicable_reason(self.root) or ""
            )
        self.assertEqual(adapter.environment().extra["GUARDDOG_PARALLELISM"], "1")
        self.assertIn(
            "--exit-non-zero-on-finding", adapter.build_command("guarddog", self.root)
        )
        with self.assertRaisesRegex(TypeError, "object or list"):
            adapter.parse("1", self.root)
        self.assertEqual(adapter.parse("[1]", self.root), [])
        with self.assertRaisesRegex(TypeError, "risks must be a list"):
            adapter.parse('{"risks":{"bad":1}}', self.root)
        self.assertEqual(
            _location("module.py:not-a-line"), ("module.py:not-a-line", None)
        )
        self.assertEqual(_location("module.py:8"), ("module.py", 8))

    def test_osv_offline_preflight_environment_and_parser_guards(self) -> None:
        adapter = OsvScannerAdapter(ToolConfig(), 4096)
        self.assertIn("database_path", adapter.prerequisite_error() or "")
        with self.assertRaisesRegex(ValueError, "database_path"):
            adapter.environment()
        missing = OsvScannerAdapter(
            ToolConfig(database_path=self.root / "missing"), 4096
        )
        self.assertIn("does not exist", missing.prerequisite_error() or "")
        database = self.root / "osv-db"
        database.mkdir()
        configured = OsvScannerAdapter(ToolConfig(database_path=database), 4096)
        self.assertIn("all.zip", configured.prerequisite_error() or "")
        (database / "all.zip").write_bytes(b"fixture")
        self.assertIsNone(configured.prerequisite_error())
        self.assertEqual(
            configured.environment().extra["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"],
            str(database),
        )
        self.assertIn("--offline", configured.build_command("osv-scanner", self.root))
        with self.assertRaisesRegex(TypeError, "results must be a list"):
            configured.parse('{"results":{"bad":1}}', self.root)
        with self.assertRaisesRegex(TypeError, "result must be an object"):
            configured.parse('{"results":[1]}', self.root)
        self.assertEqual(
            configured.parse('{"results":[{"packages":{}}]}', self.root), []
        )
        with self.assertRaisesRegex(TypeError, "package result must be an object"):
            configured.parse('{"results":[{"packages":[1]}]}', self.root)
        payload = json.dumps(
            {
                "results": [
                    {
                        "source": [],
                        "packages": [
                            {"package": [], "vulnerabilities": {}},
                            {"vulnerabilities": [1, {"id": "OSV-FIXTURE"}]},
                        ],
                    }
                ]
            }
        )
        finding = configured.parse(payload, self.root)[0]
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(
            _native_severity({"database_specific": {"severity": "low"}}), "low"
        )
        self.assertEqual(
            _native_severity({"ecosystem_specific": {"severity": "medium"}}), "medium"
        )


class ReportedQualityAdapterContractTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(temporary)).resolve()

    def test_flawfinder_mirrors_applicable_source_and_restores_scan_root(self) -> None:
        adapter = FlawfinderAdapter(ToolConfig(), 4096)
        self.assertIn("no C or C++", adapter.not_applicable_reason(self.root) or "")
        skipped = adapter.run(self.root)
        self.assertEqual(skipped.tool_run.status, ToolStatus.SKIPPED)
        source = self.root / "extension.c"
        source.write_text("int value = 1;\n", encoding="utf-8")
        mirror = self.root / "mirror"
        mirror.mkdir()
        sentinel = object()
        with (
            patch(
                "py_security_suite.adapters.flawfinder.mirrored_source_tree",
                return_value=nullcontext(mirror),
            ),
            patch(
                "py_security_suite.adapters.flawfinder.ScannerAdapter.run",
                return_value=sentinel,
            ),
        ):
            self.assertIs(adapter.run(self.root), sentinel)
        self.assertIsNone(adapter._scan_root)
        self.assertEqual(
            adapter.build_command("flawfinder", self.root)[-1], str(self.root)
        )

    def test_pyright_preflight_commands_guards_and_helpers(self) -> None:
        adapter = PyrightAdapter(ToolConfig(), 4096)
        self.assertIn("no Python", adapter.not_applicable_reason(self.root) or "")
        (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
        self.assertIsNone(adapter.not_applicable_reason(self.root))
        self.assertIn("CLI", adapter.prerequisite_error() or "")
        with self.assertRaisesRegex(ValueError, "CLI path"):
            adapter.version_command("node")
        with self.assertRaisesRegex(ValueError, "CLI path"):
            adapter.build_command("node", self.root)
        cli = self.root / "index.js"
        cli.write_text("", encoding="utf-8")
        cli_only = PyrightAdapter(ToolConfig(database_path=cli), 4096)
        self.assertIn("configuration", cli_only.prerequisite_error() or "")
        with self.assertRaisesRegex(ValueError, "configuration"):
            cli_only.build_command("node", self.root)
        rules = self.root / "pyrightconfig.json"
        rules.write_text("{}", encoding="utf-8")
        configured = PyrightAdapter(
            ToolConfig(database_path=cli, rules_path=rules), 4096
        )
        self.assertIsNone(configured.prerequisite_error())
        self.assertEqual(configured.version_command("node")[-1], "--version")
        self.assertEqual(
            configured.build_command("node", self.root)[-1], str(self.root)
        )
        with self.assertRaisesRegex(TypeError, "must be an object"):
            configured.parse("[]", self.root)
        with self.assertRaisesRegex(TypeError, "generalDiagnostics must be a list"):
            configured.parse('{"generalDiagnostics":{}}', self.root)
        with self.assertRaisesRegex(TypeError, "diagnostic must be an object"):
            configured.parse('{"generalDiagnostics":[1]}', self.root)
        finding = configured.parse(
            '{"generalDiagnostics":[{"severity":"information","range":[],'
            '"message":"first line\\nsecond line"}]}',
            self.root,
        )[0]
        self.assertEqual(finding.severity, Severity.INFORMATIONAL)
        self.assertIsNone(finding.locations[0].start_line)
        self.assertIsNone(_one_based([]))
        self.assertEqual(pyright_severity("warning"), Severity.LOW)
        self.assertEqual(pyright_severity("unknown"), Severity.UNKNOWN)
        self.assertTrue(_summary("x" * 150).endswith("..."))

    def test_scorecard_evidence_contract_parser_guards_and_severity(self) -> None:
        adapter = ScorecardAdapter(ToolConfig(), 4096)
        self.assertIn(
            "no pre-generated", adapter.not_applicable_reason(self.root) or ""
        )
        evidence = self.root / "scorecard.json"
        evidence.write_text("{}", encoding="utf-8")
        configured = ScorecardAdapter(ToolConfig(artifacts_path=evidence), 4096)
        self.assertIsNone(configured.not_applicable_reason(self.root))
        self.assertEqual(
            configured.build_command("pysec-evidence", self.root)[1], "scorecard"
        )
        with self.assertRaisesRegex(TypeError, "must be an object"):
            configured.parse("[]", self.root)
        with self.assertRaisesRegex(TypeError, "checks must be a list"):
            configured.parse('{"kind":"scorecard","checks":{}}', self.root)
        with self.assertRaisesRegex(TypeError, "check must be an object"):
            configured.parse('{"kind":"scorecard","checks":[1]}', self.root)
        self.assertEqual(
            configured.parse(
                '{"kind":"scorecard","checks":[{"name":"Perfect","score":10}]}',
                self.root,
            ),
            [],
        )
        finding = configured.parse(
            '{"kind":"scorecard","checks":[{"score":8,"documentation":[]}]}',
            self.root,
        )[0]
        self.assertEqual(finding.severity, Severity.LOW)
        with self.assertRaisesRegex(TypeError, "invalid Scorecard score"):
            _number([])
        self.assertEqual(scorecard_severity(3), Severity.HIGH)
        self.assertEqual(scorecard_severity(6), Severity.MEDIUM)
        self.assertEqual(scorecard_severity(9), Severity.LOW)

    def test_tach_applicability_command_parser_rejection_and_rule_mapping(self) -> None:
        adapter = TachAdapter(ToolConfig(), 4096)
        self.assertIn("no Python", adapter.not_applicable_reason(self.root) or "")
        (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
        self.assertIn("tach.toml", adapter.not_applicable_reason(self.root) or "")
        (self.root / "tach.toml").write_text(
            'source_roots = ["src"]\n', encoding="utf-8"
        )
        self.assertIsNone(adapter.not_applicable_reason(self.root))
        self.assertEqual(adapter.environment().extra["NO_COLOR"], "1")
        self.assertEqual(
            adapter.build_command("tach", self.root)[:2], ["tach", "check"]
        )
        self.assertEqual(adapter.parse("\nstatus line\n", self.root), [])
        with self.assertRaisesRegex(ValueError, "unexpected Tach location"):
            adapter.parse("unparsed.py[Lbad]: malformed\n", self.root)
        cases = {
            "module is not public": "public-interface",
            "cyclic import detected": "dependency-cycle",
            "unused dependency": "unused-dependency",
            "module cannot import peer": "forbidden-dependency",
            "other architecture concern": "architecture-contract",
        }
        for message, expected in cases.items():
            with self.subTest(message=message):
                self.assertEqual(_rule_id(message), expected)
        self.assertEqual(_title("short"), "short")
        self.assertTrue(_title("x" * 130).endswith("..."))


if __name__ == "__main__":
    unittest.main()
