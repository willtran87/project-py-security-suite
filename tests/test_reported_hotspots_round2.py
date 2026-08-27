from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing, nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from py_security_suite.adapters.diff_cover import DiffCoverAdapter, _integer, _number
from py_security_suite.adapters.grype import (
    GrypeAdapter,
    _grype_database_freshness_error,
)
from py_security_suite.adapters.mypy import MypyAdapter
from py_security_suite.adapters.psscriptanalyzer import (
    PSScriptAnalyzerAdapter,
    _quote,
    _severity as powershell_severity,
)
from py_security_suite.adapters.pylint import (
    PylintAdapter,
    _area as pylint_area,
    _severity as pylint_severity,
)
from py_security_suite.adapters.pypi_attestations import (
    PyPiAttestationsAdapter,
    _provenance_file,
)
from py_security_suite.adapters.semgrep import (
    SemgrepAdapter,
    _classifications,
    _line,
    _safe_uri,
)
from py_security_suite.adapters.syft import SyftAdapter, _document
from py_security_suite.adapters.trufflehog import TruffleHogAdapter, _location
from py_security_suite.config import ToolConfig
from py_security_suite.correlation import correlate_findings
from py_security_suite.execution import RawExecution
from py_security_suite.models import (
    Citation,
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
    ToolStatus,
)


def _execution(
    command: list[str],
    *,
    exit_code: int | None = 0,
    stderr: str = "",
    timed_out: bool = False,
) -> RawExecution:
    return RawExecution(
        command=command,
        exit_code=exit_code,
        stdout="",
        stderr=stderr,
        duration_seconds=0.01,
        timed_out=timed_out,
    )


class StaticAdapterContractTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(temporary)).resolve()
        self.rules = self.root / "rules.ini"
        self.rules.write_text("[fixture]\n", encoding="utf-8")

    def test_semgrep_local_rules_environment_command_and_parser_guards(self) -> None:
        adapter = SemgrepAdapter(ToolConfig(), 4096)
        self.assertIn("rules_path", adapter.prerequisite_error() or "")
        with self.assertRaisesRegex(ValueError, "rules_path"):
            adapter.build_command("semgrep", self.root)
        missing = SemgrepAdapter(ToolConfig(rules_path=self.root / "missing"), 4096)
        self.assertIn("do not exist", missing.prerequisite_error() or "")
        configured = SemgrepAdapter(ToolConfig(rules_path=self.rules), 4096)
        self.assertIsNone(configured.prerequisite_error())
        environment = configured.environment().extra
        self.assertIn("HOME", environment)
        self.assertIn("XDG_CACHE_HOME", environment)
        command = configured.build_command("semgrep", self.root)
        self.assertIn("--metrics=off", command)
        self.assertIn("--disable-version-check", command)
        with self.assertRaisesRegex(TypeError, "results must be a list"):
            configured.parse('{"results":{}}', self.root)
        with self.assertRaisesRegex(TypeError, "result must be an object"):
            configured.parse('{"results":[1]}', self.root)
        with self.assertRaisesRegex(TypeError, "extra must be an object"):
            configured.parse('{"results":[{"extra":1}]}', self.root)
        finding = configured.parse(
            json.dumps(
                {
                    "results": [
                        {
                            "check_id": "fixture",
                            "path": "app.py",
                            "start": {"line": "bad"},
                            "end": [],
                            "extra": {
                                "message": "fixture",
                                "metadata": {
                                    "cwe": ["CWE-79", "CWE-79"],
                                    "owasp": "A03",
                                    "source": "file:///local",
                                },
                            },
                        }
                    ]
                }
            ),
            self.root,
        )[0]
        self.assertIsNone(finding.locations[0].start_line)
        self.assertEqual(finding.classifications, ["CWE-79", "A03"])
        self.assertIsNone(finding.citations[0].uri)
        self.assertIsNone(_line([]))
        self.assertEqual(_classifications({"cwe": "CWE-89"}), ["CWE-89"])
        secure = "https" + "://example.test/rule"
        self.assertEqual(_safe_uri(secure), secure)

    def test_mypy_preflight_command_json_lines_and_severity(self) -> None:
        adapter = MypyAdapter(ToolConfig(), 4096)
        self.assertIn("no Python", adapter.not_applicable_reason(self.root) or "")
        self.assertIn("configuration", adapter.prerequisite_error() or "")
        with self.assertRaisesRegex(ValueError, "rules path"):
            adapter.build_command("mypy", self.root)
        (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
        configured = MypyAdapter(ToolConfig(rules_path=self.rules), 4096)
        self.assertIsNone(configured.not_applicable_reason(self.root))
        self.assertIsNone(configured.prerequisite_error())
        command = configured.build_command("mypy", self.root)
        self.assertIn("--no-site-packages", command)
        self.assertIn("--follow-imports=normal", command)
        with self.assertRaisesRegex(TypeError, "JSON line"):
            configured.parse("[]", self.root)
        payload = "\n" + json.dumps(
            {
                "file": "app.py",
                "line": "bad",
                "end_line": 4,
                "severity": "note",
                "message": "fixture note",
            }
        )
        finding = configured.parse(payload, self.root)[0]
        self.assertEqual(finding.severity, Severity.LOW)
        self.assertIsNone(finding.locations[0].start_line)
        self.assertEqual(finding.locations[0].end_line, 4)

    def test_powershell_preflight_environment_command_and_severity_matrix(self) -> None:
        adapter = PSScriptAnalyzerAdapter(ToolConfig(), 4096)
        self.assertIn("no PowerShell", adapter.not_applicable_reason(self.root) or "")
        self.assertIn("settings", adapter.prerequisite_error() or "")
        self.assertEqual(adapter.environment().extra, {})
        with self.assertRaisesRegex(ValueError, "settings path"):
            adapter.build_command("pwsh", self.root)
        script = self.root / "it's.ps1"
        script.write_text("Write-Output ok\n", encoding="utf-8")
        module = self.root / "modules"
        module.mkdir()
        configured = PSScriptAnalyzerAdapter(
            ToolConfig(rules_path=self.rules, database_path=module), 4096
        )
        self.assertIsNone(configured.not_applicable_reason(self.root))
        self.assertIsNone(configured.prerequisite_error())
        self.assertEqual(configured.environment().extra["PSModulePath"], str(module))
        self.assertIn("Import-Module", configured.version_command("pwsh")[-1])
        self.assertIn("it''s.ps1", configured.build_command("pwsh", self.root)[-1])
        self.assertEqual(_quote(script), str(script).replace("'", "''"))
        with self.assertRaisesRegex(TypeError, "must be a list"):
            configured.parse("{}", self.root)
        with self.assertRaisesRegex(TypeError, "must be an object"):
            configured.parse("[1]", self.root)
        finding = configured.parse(
            '[{"RuleName":"PSAvoidUsingWriteHost","Line":"bad"}]', self.root
        )[0]
        self.assertEqual(finding.severity, Severity.INFORMATIONAL)
        self.assertIsNone(finding.locations[0].start_line)
        self.assertEqual(
            powershell_severity("PSReviewUnusedParameter", "Warning"), Severity.LOW
        )

    def test_pylint_preflight_command_parser_path_and_metadata_helpers(self) -> None:
        adapter = PylintAdapter(ToolConfig(), 4096)
        self.assertIn("no Python", adapter.not_applicable_reason(self.root) or "")
        self.assertIn("configuration", adapter.prerequisite_error() or "")
        with self.assertRaisesRegex(ValueError, "rules path"):
            adapter.build_command("pylint", self.root)
        source = self.root / "app.py"
        source.write_text("value = 1\n", encoding="utf-8")
        configured = PylintAdapter(ToolConfig(rules_path=self.rules), 4096)
        self.assertIsNone(configured.not_applicable_reason(self.root))
        self.assertIsNone(configured.prerequisite_error())
        self.assertIn("--persistent=no", configured.build_command("pylint", self.root))
        with self.assertRaisesRegex(TypeError, "messages list"):
            configured.parse("[]", self.root)
        with self.assertRaisesRegex(TypeError, "message must be an object"):
            configured.parse('{"messages":[1]}', self.root)
        configured._scan_root = self.root
        finding = configured.parse(
            json.dumps(
                {
                    "messages": [
                        {
                            "message-id": "E0001",
                            "symbol": "broad-exception-caught",
                            "type": "fatal",
                            "absolutePath": str(source),
                            "line": "bad",
                        }
                    ],
                    "score": 9.5,
                }
            ),
            self.root,
        )[0]
        self.assertEqual(finding.locations[0].path, "app.py")
        self.assertEqual(finding.area, "exception-handling")
        self.assertEqual(finding.severity, Severity.MEDIUM)
        artifact = configured.derived_artifacts('{"messages":[],"score":10}', self.root)
        self.assertEqual(artifact["pylint-summary.json"]["message_count"], 0)
        self.assertEqual(pylint_severity("warning"), Severity.LOW)
        self.assertEqual(pylint_severity("convention"), Severity.INFORMATIONAL)
        self.assertEqual(pylint_area("logging-fstring-interpolation"), "logging")
        self.assertEqual(pylint_area("unused-argument"), "api-contract")
        self.assertEqual(pylint_area("too-many-branches"), "design-complexity")

    def test_trufflehog_preflight_redacted_location_shapes_and_command(self) -> None:
        adapter = TruffleHogAdapter(ToolConfig(), 4096)
        empty_root = self.root / "empty"
        empty_root.mkdir()
        self.assertIn("no files", adapter.not_applicable_reason(empty_root) or "")
        self.assertIn("exclude-path", adapter.prerequisite_error() or "")
        with self.assertRaisesRegex(ValueError, "exclude paths"):
            adapter.build_command("trufflehog", self.root)
        (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
        configured = TruffleHogAdapter(ToolConfig(rules_path=self.rules), 4096)
        self.assertIsNone(configured.not_applicable_reason(self.root))
        self.assertIsNone(configured.prerequisite_error())
        command = configured.build_command("trufflehog", self.root)
        self.assertIn("--no-verification", command)
        self.assertIn("--no-update", command)
        with self.assertRaisesRegex(TypeError, "must be an object"):
            configured.parse("[]", self.root)
        finding = configured.parse(
            json.dumps(
                {
                    "detector_name": "Fixture",
                    "source_metadata": {
                        "data": {"filesystem": {"path": "app.py", "line": "bad"}}
                    },
                    "verified": True,
                    "decoder_name": "plain",
                }
            ),
            self.root,
        )[0]
        self.assertEqual(finding.confidence, Confidence.HIGH)
        self.assertIsNone(finding.locations[0].start_line)
        self.assertEqual(_location([]), ("<repository>", None))
        self.assertEqual(_location({"Data": []}), ("<repository>", None))
        self.assertEqual(
            _location({"Data": {"Filesystem": []}}), ("<repository>", None)
        )


class EvidenceAndArtifactAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(temporary)).resolve()

    def test_diff_cover_applicability_command_ordering_and_type_guards(self) -> None:
        adapter = DiffCoverAdapter(ToolConfig(), 4096)
        self.assertIn("coverage.xml", adapter.not_applicable_reason(self.root) or "")
        coverage = self.root / "coverage.xml"
        coverage.write_text("<coverage/>", encoding="utf-8")
        configured = DiffCoverAdapter(
            ToolConfig(artifacts_path=coverage, compare_branch="main"), 4096
        )
        self.assertIn("Git history", configured.not_applicable_reason(self.root) or "")
        (self.root / ".git").mkdir()
        self.assertIsNone(configured.not_applicable_reason(self.root))
        command = configured.build_file_command(
            "diff-cover", self.root, self.root / "out.json"
        )
        self.assertEqual(command[-2:], ["--compare-branch", "main"])
        with self.assertRaisesRegex(TypeError, "must be an object"):
            configured.parse("[]", self.root)
        with self.assertRaisesRegex(TypeError, "src_stats"):
            configured.parse('{"src_stats":[]}', self.root)
        with self.assertRaisesRegex(TypeError, "statistics"):
            configured.parse('{"src_stats":{"app.py":1}}', self.root)
        with self.assertRaisesRegex(TypeError, "violation_lines"):
            configured.parse(
                '{"src_stats":{"app.py":{"violation_lines":{"bad":1}}}}', self.root
            )
        payload = json.dumps(
            {
                "total_percent_covered": 100,
                "num_changed_lines": 2,
                "src_stats": {
                    "b.py": {"percent_covered": 50, "violation_lines": [9]},
                    "a.py": {"percent_covered": 20, "violation_lines": ["bad"]},
                },
            }
        )
        with self.assertRaisesRegex(TypeError, "invalid diff-cover integer"):
            configured.parse(payload, self.root)
        artifact = configured.derived_artifacts('{"src_stats":{}}', self.root)
        self.assertEqual(artifact["diff-coverage.json"]["schema_version"], "1.0")
        with self.assertRaisesRegex(TypeError, "integer"):
            _integer("bad")
        with self.assertRaisesRegex(TypeError, "number"):
            _number("bad")

    def test_syft_contract_and_guarded_extraction_cleanup(self) -> None:
        adapter = SyftAdapter(ToolConfig(artifacts_path=Path("dist")), 4096)
        self.assertIn("no built", adapter.not_applicable_reason(self.root) or "")
        self.assertEqual(
            adapter.environment().extra["SYFT_CHECK_FOR_APP_UPDATE"], "false"
        )
        self.assertIn("cyclonedx-json@1.7", adapter.build_command("syft", self.root))
        with self.assertRaisesRegex(TypeError, "must be an object"):
            _document("[]")
        with self.assertRaisesRegex(ValueError, "not a CycloneDX"):
            adapter.parse("{}", self.root)
        self.assertEqual(
            adapter.parse('{"bomFormat":"CycloneDX","specVersion":"1.7"}', self.root),
            [],
        )

        dist = self.root / "dist"
        dist.mkdir()
        (dist / "fixture.whl").write_bytes(b"fixture")
        with (
            patch(
                "py_security_suite.adapters.syft.extracted_distribution_tree",
                return_value=nullcontext(self.root / "expanded"),
            ),
            patch.object(
                adapter, "_prepare_executable", return_value=(None, "missing")
            ),
        ):
            result = adapter.run(self.root)
        self.assertEqual(result.tool_run.status, ToolStatus.UNAVAILABLE)
        self.assertIsNone(adapter._scan_root)

    def test_grype_preflight_environment_command_and_parser_variants(self) -> None:
        adapter = GrypeAdapter(ToolConfig(artifacts_path=Path("dist")), 4096)
        self.assertIn("no built", adapter.not_applicable_reason(self.root) or "")
        self.assertIn("database", adapter.prerequisite_error() or "")
        missing = GrypeAdapter(
            ToolConfig(
                database_path=self.root / "missing", artifacts_path=Path("dist")
            ),
            4096,
        )
        self.assertIn("does not exist", missing.prerequisite_error() or "")
        environment = adapter.environment().extra
        self.assertEqual(environment["GRYPE_DB_AUTO_UPDATE"], "false")
        self.assertIn("dir:", adapter.build_command("grype", self.root)[1])
        with self.assertRaisesRegex(TypeError, "matches must be a list"):
            adapter.parse('{"matches":{"bad":1}}', self.root)
        self.assertEqual(adapter.parse('{"matches":[1]}', self.root), [])
        self.assertEqual(
            adapter.parse(
                '{"matches":[{"vulnerability":[1],"artifact":{}}]}', self.root
            ),
            [],
        )
        payload = json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {
                            "id": "CVE-2026-1",
                            "severity": "high",
                            "fix": {"versions": ["2.0"]},
                            "urls": ["file:///bad", "https://example.test/CVE-2026-1"],
                        },
                        "artifact": {
                            "name": "fixture",
                            "version": "1.0",
                            "type": "python",
                            "locations": [1],
                        },
                    }
                ]
            }
        )
        finding = adapter.parse(payload, self.root)[0]
        self.assertIn("2.0", finding.remediation)
        self.assertEqual(finding.locations[0].path, "<artifact>")

    def test_grype_freshness_uses_internal_build_timestamp(self) -> None:
        database_root = self.root / "grype-db"
        database_root.mkdir()
        self.assertIn(
            "was not found",
            _grype_database_freshness_error(database_root, 10) or "",
        )
        database = database_root / "vulnerability.db"
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                "CREATE TABLE db_metadata (build_timestamp datetime NOT NULL)"
            )
            connection.commit()
        self.assertIn(
            "metadata is invalid",
            _grype_database_freshness_error(database_root, 10) or "",
        )
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                "INSERT INTO db_metadata VALUES (?)", (datetime.now(UTC).isoformat(),)
            )
            connection.commit()
        configured = GrypeAdapter(ToolConfig(database_path=database_root), 4096)
        self.assertIsNone(configured.prerequisite_error())
        naive = datetime.now(UTC).replace(tzinfo=None).isoformat()
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("UPDATE db_metadata SET build_timestamp = ?", (naive,))
            connection.commit()
        self.assertIsNone(_grype_database_freshness_error(database_root, 10))
        stale = (datetime.now(UTC) - timedelta(days=11)).isoformat()
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("UPDATE db_metadata SET build_timestamp = ?", (stale,))
            connection.commit()
        self.assertIn(
            "11.0 days old",
            _grype_database_freshness_error(database_root, 10) or "",
        )
        future = (datetime.now(UTC) + timedelta(days=2)).isoformat()
        with closing(sqlite3.connect(database)) as connection:
            connection.execute("UPDATE db_metadata SET build_timestamp = ?", (future,))
            connection.commit()
        self.assertIn(
            "future", _grype_database_freshness_error(database_root, 10) or ""
        )
        duplicate = database_root / "nested" / "vulnerability.db"
        duplicate.parent.mkdir()
        duplicate.write_bytes(b"invalid")
        self.assertIn(
            "exactly one", _grype_database_freshness_error(database_root, 10) or ""
        )

    def test_pypi_attestation_preflight_environment_and_run_outcomes(self) -> None:
        config = ToolConfig(
            executable="pypi-attestations",
            artifacts_path=Path("dist"),
            provenance_path=Path("dist"),
        )
        adapter = PyPiAttestationsAdapter(config, 4096)
        self.assertIn("no built", adapter.not_applicable_reason(self.root) or "")
        skipped = adapter.run(self.root)
        self.assertEqual(skipped.tool_run.status, ToolStatus.SKIPPED)
        dist = self.root / "dist"
        dist.mkdir()
        artifact = dist / "fixture.whl"
        artifact.write_bytes(b"fixture")
        self.assertIn(
            "Trusted Publisher", adapter.not_applicable_reason(self.root) or ""
        )
        self.assertIn("repository_url", adapter.prerequisite_error() or "")
        invalid_url = PyPiAttestationsAdapter(
            ToolConfig(repository_url="file:///repository"), 4096
        )
        self.assertIn("HTTPS", invalid_url.prerequisite_error() or "")
        self.assertEqual(adapter.environment().extra, {})
        with self.assertRaises(NotImplementedError):
            adapter.build_command("pypi-attestations", self.root)
        self.assertEqual(adapter.parse("", self.root), [])
        self.assertEqual(adapter.parse("{}", self.root), [])

        trust = self.root / "trust"
        trust.mkdir()
        configured = PyPiAttestationsAdapter(
            ToolConfig(
                executable="pypi-attestations",
                artifacts_path=Path("dist"),
                provenance_path=Path("dist"),
                repository_url="https://github.com/example/project",
                database_path=trust,
            ),
            4096,
        )
        self.assertIsNone(configured.not_applicable_reason(self.root))
        self.assertIsNone(configured.prerequisite_error())
        self.assertEqual(configured.environment().extra["HOME"], str(trust))
        with (
            patch.object(
                configured, "_prepare_executable", return_value=("attest", None)
            ),
            patch.object(configured, "_detect_version", return_value="attest 1"),
            patch.object(configured, "_executable_changed_error", return_value=None),
        ):
            missing_result = configured.run(self.root)
        self.assertEqual(missing_result.tool_run.status, ToolStatus.COMPLETED)
        self.assertEqual(
            missing_result.findings[0].sources[0].rule_id, "PYPI-ATTESTATION-MISSING"
        )
        self.assertIsNone(_provenance_file(dist, artifact))

        provenance = dist / f"{artifact.name}.provenance.json"
        provenance.write_text("{}", encoding="utf-8")
        cases = (
            (
                "invalid",
                _execution(["attest"], exit_code=1, stderr="invalid"),
                None,
                ToolStatus.COMPLETED,
            ),
            (
                "timeout",
                _execution(["attest"], timed_out=True),
                None,
                ToolStatus.TIMED_OUT,
            ),
            ("changed", _execution(["attest"]), "attest changed", ToolStatus.FAILED),
        )
        for name, execution, changed, expected in cases:
            with self.subTest(name=name):
                with (
                    patch.object(
                        configured, "_prepare_executable", return_value=("attest", None)
                    ),
                    patch.object(
                        configured, "_detect_version", return_value="attest 1"
                    ),
                    patch.object(
                        configured, "_executable_changed_error", return_value=changed
                    ),
                    patch(
                        "py_security_suite.adapters.pypi_attestations.run_command",
                        return_value=execution,
                    ),
                ):
                    result = configured.run(self.root)
                self.assertEqual(result.tool_run.status, expected)
                if name == "invalid":
                    self.assertEqual(
                        result.findings[0].sources[0].rule_id,
                        "PYPI-ATTESTATION-INVALID",
                    )


class CorrelationTests(unittest.TestCase):
    @staticmethod
    def _finding(
        tool: str,
        rule: str,
        *,
        severity: Severity,
        confidence: Confidence,
        classification: str = "CWE-79:2021",
        location: bool = True,
    ) -> Finding:
        return Finding(
            finding_id=f"{tool}-{rule}",
            fingerprint=f"sha256:{'a' * 64}",
            title=f"{tool} finding",
            description="fixture",
            impact="fixture",
            remediation="fixture",
            severity=severity,
            confidence=confidence,
            area="fixture",
            classifications=[classification] if classification else [],
            locations=[Location(path="app.py", start_line=7)] if location else [],
            sources=[Source(tool=tool, rule_id=rule, message="fixture")],
            citations=[Citation(kind="tool_rule", identifier=rule, title=rule)],
        )

    def test_correlation_merges_cwe_observations_and_preserves_maximum_risk(
        self,
    ) -> None:
        first = self._finding(
            "semgrep",
            "rule-a",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
        )
        duplicate = self._finding(
            "bandit",
            "rule-b",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
        )
        result = correlate_findings([first, duplicate])
        self.assertEqual(len(result), 1)
        merged = result[0]
        self.assertEqual(merged.severity, Severity.HIGH)
        self.assertEqual(merged.confidence, Confidence.HIGH)
        self.assertEqual(
            {source.tool for source in merged.sources}, {"semgrep", "bandit"}
        )
        self.assertEqual(merged.classifications, ["CWE-79:2021"])

    def test_correlation_handles_singletons_missing_locations_and_rule_fallbacks(
        self,
    ) -> None:
        singleton = self._finding(
            "ruff",
            "S001",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            classification="",
        )
        no_source = self._finding(
            "fixture",
            "none",
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.LOW,
            classification="",
            location=False,
        )
        no_source.sources = []
        result = correlate_findings([no_source, singleton])
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], singleton)

    def test_correlation_marks_runtime_corroboration_without_claiming_exploitability(
        self,
    ) -> None:
        static = self._finding(
            "codeql",
            "py/sql-injection",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            classification="CWE-89",
        )
        runtime = self._finding(
            "iast",
            "sql-injection",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            classification="CWE-89",
        )

        merged = correlate_findings([static, runtime])[0]

        corroboration = merged.evidence["cross_tool_corroboration"]
        self.assertTrue(corroboration["runtime_observed"])
        self.assertEqual(corroboration["dynamic_tools"], ["iast"])
        self.assertIn("does not by itself prove", corroboration["claim_boundary"])

    def test_correlation_does_not_merge_distinct_data_flows_at_same_sink(self) -> None:
        first = self._finding(
            "codeql",
            "py/sql-injection",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            classification="CWE-89",
        )
        second = self._finding(
            "semgrep",
            "sql-injection",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            classification="CWE-89",
        )
        first.evidence["sarif_code_flows"] = [
            {
                "steps": [
                    {"path": "request.py", "line": 1},
                    {"path": "app.py", "line": 7},
                ]
            }
        ]
        second.evidence["sarif_code_flows"] = [
            {"steps": [{"path": "config.py", "line": 2}, {"path": "app.py", "line": 7}]}
        ]

        result = correlate_findings([first, second])

        self.assertEqual(len(result), 2)

    def test_correlation_preserves_secondary_flow_and_counts_engine_families(
        self,
    ) -> None:
        first = self._finding(
            "ruff",
            "S001",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
        )
        second = self._finding(
            "ruff-quality",
            "S001",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
        )
        second.evidence["sarif_code_flows"] = [
            {"steps": [{"path": "input.py", "line": 1}, {"path": "app.py", "line": 7}]}
        ]

        merged = correlate_findings([first, second])[0]

        self.assertEqual(len(merged.evidence["sarif_code_flows"]), 1)
        corroboration = merged.evidence["cross_tool_corroboration"]
        self.assertEqual(corroboration["engine_families"], ["ruff"])
        self.assertEqual(corroboration["independent_perspectives"], 1)

    def test_correlation_separates_distinct_semantic_subjects_without_flows(
        self,
    ) -> None:
        first = self._finding(
            "semgrep",
            "auth-check",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            classification="CWE-862",
        )
        second = self._finding(
            "codeql",
            "auth-check",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            classification="CWE-862",
        )
        first.evidence["application_contracts"] = {"operation": "GET /admin"}
        second.evidence["application_contracts"] = {"operation": "POST /billing"}

        result = correlate_findings([first, second])

        self.assertEqual(len(result), 2)

    def test_correlation_joins_exact_semantic_subject_across_reported_lines(
        self,
    ) -> None:
        first = self._finding(
            "semgrep",
            "auth-check",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            classification="CWE-862",
        )
        second = self._finding(
            "codeql",
            "auth-check",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            classification="CWE-862",
        )
        first.evidence["application_contracts"] = {"operation": "GET /admin"}
        second.evidence["application_contracts"] = {"operation": "GET /admin"}
        second.locations = [Location(path="app.py", start_line=12)]

        merged = correlate_findings([first, second])

        self.assertEqual(len(merged), 1)
        self.assertEqual(
            merged[0].evidence["cross_tool_corroboration"]["independent_perspectives"],
            2,
        )

    def test_correlation_joins_matching_flow_sink_across_primary_locations(
        self,
    ) -> None:
        first = self._finding(
            "semgrep",
            "sql",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            classification="CWE-89",
        )
        second = self._finding(
            "codeql",
            "sql",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            classification="CWE-89",
        )
        second.locations = [Location(path="query.py", start_line=30)]
        flow = {
            "steps": [
                {"path": "request.py", "line": 1},
                {"path": "query.py", "line": 30},
            ]
        }
        first.evidence["sarif_code_flows"] = [flow]
        second.evidence["sarif_code_flows"] = [flow]

        self.assertEqual(len(correlate_findings([first, second])), 1)


if __name__ == "__main__":
    unittest.main()
