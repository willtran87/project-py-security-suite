"""Regression tests for fail-closed scanner parsing and archive handling."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import marshal
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

from py_security_suite import (
    audit_package,
    bytecode_analysis,
    evidence_ingest,
    native_bundle,
)
from py_security_suite.adapters import artifacts
from py_security_suite.adapters.actionlint import ActionlintAdapter
from py_security_suite.adapters.bandit import BanditAdapter
from py_security_suite.adapters.common import (
    contains_regular_file,
    native_suppression_markers,
)
from py_security_suite.adapters.detect_secrets import (
    INLINE_ALLOWLIST_FILTER,
    DetectSecretsAdapter,
)
from py_security_suite.adapters.gitleaks import GitleaksAdapter
from py_security_suite.adapters.hadolint import HadolintAdapter
from py_security_suite.adapters.mypy import MypyAdapter
from py_security_suite.adapters.portfolio import KubeLinterAdapter, ValeAdapter
from py_security_suite.adapters.ruff import RuffAdapter
from py_security_suite.adapters.sarif import parse_sarif_findings
from py_security_suite.adapters.semgrep import SemgrepAdapter
from py_security_suite.adapters.shellcheck import ShellCheckAdapter
from py_security_suite.adapters.trufflehog import TruffleHogAdapter
from py_security_suite.adapters.wheel_contents import CheckWheelContentsAdapter
from py_security_suite.audit_package import create_audit_package, verify_audit_package
from py_security_suite.bytecode_analysis import analyze_python_bytecode
from py_security_suite.confidential_archive import _extract_archive
from py_security_suite.config import ToolConfig
from py_security_suite.execution import RawExecution
from py_security_suite.models import Severity
from py_security_suite.path_safety import (
    archive_member_key,
    contained_archive_destination,
    portable_archive_member,
)
from py_security_suite.standards_monitor import _extract_semantic_sections
from py_security_suite.strict_json import dumps as strict_dumps
from py_security_suite.strict_json import loads as strict_loads


def _execution(exit_code: int, stdout: str = "") -> RawExecution:
    return RawExecution(
        command=["scanner"],
        exit_code=exit_code,
        stdout=stdout,
        stderr="fatal: scanner failed",
        duration_seconds=0.0,
    )


class _TemporaryRoot(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(temporary)).resolve()


class GitleaksFailClosedTests(_TemporaryRoot):
    def _adapter_with_report(
        self, report: str | None, exit_code: int
    ) -> GitleaksAdapter:
        adapter = GitleaksAdapter(ToolConfig(), 4096)
        adapter._report_path = self.root / "report.json"
        if report is not None:
            adapter._report_path.write_text(report, encoding="utf-8")
        adapter.result_payload(_execution(exit_code))
        return adapter

    def test_missing_report_is_a_parse_error_not_a_clean_pass(self) -> None:
        for exit_code in (0, 1):
            with self.subTest(exit_code=exit_code):
                adapter = self._adapter_with_report(None, exit_code)
                with self.assertRaisesRegex(ValueError, "did not write"):
                    adapter.parse("", self.root)

    def test_exit_one_with_empty_report_is_rejected(self) -> None:
        for report in ("", "[]"):
            with self.subTest(report=report):
                adapter = self._adapter_with_report(report, 1)
                with self.assertRaises(ValueError):
                    adapter.parse("", self.root)
        self.assertEqual(self._adapter_with_report("[]", 0).parse("", self.root), [])

    def test_command_disables_target_controlled_suppression(self) -> None:
        (self.root / "app.py").write_text("x = 1\n", encoding="utf-8")
        (self.root / ".gitleaks.toml").write_text("[allowlist]\n", encoding="utf-8")
        adapter = GitleaksAdapter(ToolConfig(), 4096)
        command = adapter.build_command("gitleaks", self.root)
        try:
            self.assertIn("--ignore-gitleaks-allow", command)
            config = Path(command[command.index("--config") + 1])
            self.assertNotEqual(config.parent, self.root)
            self.assertIn("useDefault = true", config.read_text(encoding="utf-8"))
            ignore = Path(command[command.index("--gitleaks-ignore-path") + 1])
            self.assertEqual(ignore.read_bytes(), b"")
            self.assertNotEqual(ignore.parent, self.root)
        finally:
            for path in (adapter._ignore_path, adapter._config_path):
                if path is not None:
                    path.unlink(missing_ok=True)

    def test_target_gitleaksignore_entries_are_unaccepted_findings(self) -> None:
        (self.root / ".gitleaksignore").write_text(
            "# comment\nabc:app.py:generic-api-key:3\n\n", encoding="utf-8"
        )
        findings = self._adapter_with_report("[]", 0).parse("", self.root)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].sources[0].rule_id, "gitleaks.native-suppression")
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertEqual(findings[0].locations[0].start_line, 2)

    def test_malformed_leak_entry_raises(self) -> None:
        adapter = self._adapter_with_report('["not-an-object"]', 1)
        with self.assertRaisesRegex(TypeError, "must be an object"):
            adapter.parse("", self.root)


class SecretApplicabilityTests(_TemporaryRoot):
    def test_nested_only_files_are_applicable(self) -> None:
        nested = self.root / "a" / "b"
        nested.mkdir(parents=True)
        for adapter in (
            GitleaksAdapter(ToolConfig(), 4096),
            TruffleHogAdapter(ToolConfig(), 4096),
        ):
            self.assertIsNotNone(adapter.not_applicable_reason(self.root))
        (nested / "secret.env").write_text("TOKEN=x\n", encoding="utf-8")
        for adapter in (
            GitleaksAdapter(ToolConfig(), 4096),
            TruffleHogAdapter(ToolConfig(), 4096),
        ):
            self.assertIsNone(adapter.not_applicable_reason(self.root))

    def test_applicability_walk_is_bounded_and_fails_closed(self) -> None:
        for index in range(5):
            (self.root / f"d{index}").mkdir()
        self.assertTrue(contains_regular_file(self.root, entry_limit=2))
        self.assertFalse(contains_regular_file(self.root))


class TruffleHogSuppressionTests(_TemporaryRoot):
    def test_inline_ignore_comments_become_findings(self) -> None:
        target = self.root / "target"
        (target / "pkg").mkdir(parents=True)
        (target / "pkg" / "config.py").write_text(
            "a = 1\nkey = 'x'  # trufflehog:ignore\n", encoding="utf-8"
        )
        (target / "build").mkdir()
        (target / "build" / "gen.py").write_text(
            "k = 1  # trufflehog:ignore\n", encoding="utf-8"
        )
        excludes = self.root / "excludes.txt"
        excludes.write_text(r"(^|[/\\])build([/\\]|$)" + "\n", encoding="utf-8")
        findings = TruffleHogAdapter(ToolConfig(rules_path=excludes), 4096).parse(
            "", target
        )
        self.assertEqual(
            [
                (item.locations[0].path, item.locations[0].start_line)
                for item in findings
            ],
            [("pkg/config.py", 2)],
        )
        self.assertEqual(
            findings[0].sources[0].rule_id, "trufflehog.native-suppression"
        )

    def test_marker_walk_budget_fails_closed(self) -> None:
        (self.root / "a.txt").write_text("x\n", encoding="utf-8")
        (self.root / "b.txt").write_text("y\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "file budget"):
            native_suppression_markers(self.root, b"m", file_limit=1)
        with self.assertRaisesRegex(ValueError, "byte budget"):
            native_suppression_markers(self.root, b"m", byte_limit=1)


class NativeSuppressionFlagTests(_TemporaryRoot):
    def test_bandit_run_decides_suite_status_on_the_real_target(self) -> None:
        (self.root / "a.py").write_text("x = 1\n", encoding="utf-8")
        observed: list[tuple[bool, Path]] = []

        def fake_run(adapter: BanditAdapter, mirror: Path) -> object:
            observed.append((adapter._suite_target, mirror))
            return SimpleNamespace(findings=[])

        for suite in (True, False):
            with (
                patch(
                    "py_security_suite.adapters.bandit.is_suite_repository",
                    return_value=suite,
                ) as decided,
                patch(
                    "py_security_suite.adapters.base.ScannerAdapter.run",
                    autospec=True,
                    side_effect=fake_run,
                ),
                patch("py_security_suite.adapters.bandit.refine_literal_sql"),
            ):
                BanditAdapter(ToolConfig(), 4096).run(self.root)
            decided.assert_called_once_with(self.root)
        self.assertEqual([flag for flag, _ in observed], [True, False])
        self.assertTrue(all(mirror != self.root for _, mirror in observed))

    def test_bandit_and_semgrep_ignore_inline_suppressions(self) -> None:
        self.assertIn(
            "--ignore-nosec",
            BanditAdapter(ToolConfig(), 4096).build_command("bandit", self.root),
        )
        rules = self.root / "rules.yml"
        rules.write_text("rules: []\n", encoding="utf-8")
        self.assertIn(
            "--disable-nosem",
            SemgrepAdapter(ToolConfig(rules_path=rules), 4096).build_command(
                "semgrep", self.root
            ),
        )
        suite_bandit = BanditAdapter(ToolConfig(), 4096)
        suite_bandit._suite_target = True
        self.assertNotIn(
            "--ignore-nosec", suite_bandit.build_command("bandit", self.root)
        )
        suite = SemgrepAdapter(ToolConfig(rules_path=rules), 4096)
        suite._suite_target = True
        self.assertNotIn("--disable-nosem", suite.build_command("semgrep", self.root))


class DetectSecretsAllowlistTests(_TemporaryRoot):
    def test_inline_allowlist_pragmas_are_disabled_for_targets(self) -> None:
        (self.root / "app.py").write_text("x = 1\n", encoding="utf-8")
        command = DetectSecretsAdapter(ToolConfig(), 4096).build_command(
            "detect-secrets", self.root
        )
        index = command.index("--disable-filter")
        self.assertEqual(command[index + 1], INLINE_ALLOWLIST_FILTER)
        suite_command = DetectSecretsAdapter(ToolConfig(), 4096).build_command(
            "detect-secrets", Path(__file__).resolve().parents[1]
        )
        self.assertNotIn("--disable-filter", suite_command)

    def test_pinned_detect_secrets_reports_allowlisted_secret(self) -> None:
        configured = os.environ.get("PYSEC_TEST_DETECT_SECRETS")
        executable = (
            Path(configured)
            if configured
            else Path(sys.prefix) / "Scripts" / "detect-secrets.exe"
        )
        if not executable.is_file():
            executable = Path(sys.prefix) / "bin" / "detect-secrets"
        if not executable.is_file():
            self.skipTest("detect-secrets is not installed in this environment")
        # Synthetic token shape for the pinned-scanner check.
        # pragma: allowlist nextline secret
        token = "ghp_" + "opTEIy39wHRhXPzb8LPRweTAUj4kT35wmqyS"
        (self.root / "c.py").write_text(
            f'token = "{token}"  # pragma: allowlist secret\n', encoding="utf-8"
        )
        adapter = DetectSecretsAdapter(ToolConfig(), 1 << 20)
        command = adapter.build_command(str(executable), self.root)
        completed = subprocess.run(  # noqa: S603  # nosec B603
            command, cwd=self.root, capture_output=True, text=True, check=True
        )
        self.assertTrue(adapter.parse(completed.stdout, self.root))


class FailureExitTests(_TemporaryRoot):
    def test_exit_one_without_output_is_rejected(self) -> None:
        for adapter in (
            HadolintAdapter(ToolConfig(), 4096),
            ShellCheckAdapter(ToolConfig(), 4096),
            ActionlintAdapter(ToolConfig(), 4096),
            CheckWheelContentsAdapter(ToolConfig(), 4096),
            MypyAdapter(ToolConfig(), 4096),
            RuffAdapter(ToolConfig(), 4096),
            ValeAdapter(ToolConfig(), 4096),
            KubeLinterAdapter(ToolConfig(), 4096),
        ):
            with self.subTest(adapter=adapter.name):
                with self.assertRaisesRegex(ValueError, "without producing"):
                    adapter.result_payload(_execution(1, "  \n"))
                self.assertEqual(adapter.result_payload(_execution(0, "")), "")

    def test_exit_one_with_empty_result_list_is_rejected(self) -> None:
        cases = (
            (HadolintAdapter(ToolConfig(), 4096), "[]"),
            (ShellCheckAdapter(ToolConfig(), 4096), '{"comments": []}'),
            (ActionlintAdapter(ToolConfig(), 4096), "[]"),
            (RuffAdapter(ToolConfig(), 4096), "[]"),
            (KubeLinterAdapter(ToolConfig(), 4096), '{"Reports": []}'),
            (ValeAdapter(ToolConfig(), 4096), "{}"),
        )
        for adapter, payload in cases:
            with self.subTest(adapter=adapter.name):
                adapter.result_payload(_execution(1, payload))
                with self.assertRaisesRegex(ValueError, "reported no results"):
                    adapter.parse(payload, self.root)

    def test_wheel_contents_exit_one_requires_a_parsed_issue(self) -> None:
        adapter = CheckWheelContentsAdapter(
            ToolConfig(artifacts_path=Path("dist")), 4096
        )
        adapter.result_payload(_execution(1, "Traceback: boom\n"))
        with self.assertRaisesRegex(ValueError, "reported no results"):
            adapter.parse("Traceback: boom\n", self.root)

    def test_shellcheck_json1_comments_are_parsed(self) -> None:
        payload = json.dumps(
            {
                "comments": [
                    {
                        "file": "run.sh",
                        "line": 2,
                        "endLine": 2,
                        "level": "warning",
                        "code": 2086,
                        "message": "Double quote",
                    }
                ]
            }
        )
        adapter = ShellCheckAdapter(ToolConfig(), 4096)
        adapter.result_payload(_execution(1, payload))
        finding = adapter.parse(payload, self.root)[0]
        self.assertEqual(finding.classifications, ["SC2086"])

    def test_kube_linter_rejects_non_object_output(self) -> None:
        with self.assertRaisesRegex(TypeError, "must be an object"):
            KubeLinterAdapter(ToolConfig(), 4096).parse("[]", self.root)


class SarifKindTests(_TemporaryRoot):
    def test_unknown_result_kind_keeps_failure_severity(self) -> None:
        def document(kind: str) -> str:
            return json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {"driver": {"name": "fixture", "rules": []}},
                            "results": [
                                {
                                    "ruleId": "R1",
                                    "kind": kind,
                                    "level": "error",
                                    "message": {"text": "critical issue"},
                                }
                            ],
                        }
                    ],
                }
            )

        def severity(kind: str) -> Severity:
            findings = parse_sarif_findings(
                document(kind),
                self.root,
                tool_name="fixture",
                default_area="test",
                default_impact="impact",
                default_remediation="fix",
            )
            return findings[0].severity

        self.assertEqual(severity("fail"), severity("bogus-kind"))
        self.assertNotEqual(severity("bogus-kind"), Severity.INFORMATIONAL)


class NativeBundleRequirementTests(unittest.TestCase):
    def test_only_pep508_name_requirements_are_accepted(self) -> None:
        for accepted in (
            "requests",
            "requests[socks]>=2.0,<3",
            "pkg==1.0 ; python_version >= '3.11'",
        ):
            self.assertEqual(native_bundle._requirement_text(accepted), accepted)
        for rejected in (
            "./evil",
            "evil.tar.gz/../x",
            "C:\\wheels\\evil.whl",
            "../evil-1.0.tar.gz",
            "pkg @ file:///tmp/pkg",
            "pkg@https://example.test/pkg.whl",
            "/abs/path",
            "-e .",
        ):
            with self.subTest(requirement=rejected):
                with self.assertRaises(ValueError):
                    native_bundle._requirement_text(rejected)

    def test_dry_run_never_builds_source_distributions(self) -> None:
        captured: list[list[str]] = []

        def fake_run(command: list[str], **_: object) -> RawExecution:
            captured.append(command)
            return _execution(1)

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(native_bundle, "run_command", side_effect=fake_run),
        ):
            root = Path(directory)
            native_bundle._resolve_environment(
                Path("python"), root, root, {"name": "core", "requirements": ["x"]}
            )
        self.assertIn("--only-binary=:all:", captured[0])


class ArchiveMemberTests(_TemporaryRoot):
    def test_portable_member_rejects_windows_escapes(self) -> None:
        for name in (
            "C:/x",
            "C:x",
            "file.txt:stream",
            "a\x00b",
            "a\\b",
            "/abs",
            "a/../b",
            "./a",
            "CON",
            "con.txt",
            "dir/LPT1.log",
            "trailing.",
            "trailing ",
            "",
        ):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    portable_archive_member(name)
        self.assertEqual(portable_archive_member("a/b.txt"), PurePosixPath("a/b.txt"))
        self.assertEqual(
            archive_member_key(PurePosixPath("Caf\u00e9")),
            archive_member_key(PurePosixPath("CAFE\u0301")),
        )

    def test_contained_destination_rejects_symlink_escape(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        staging = self.root / "staging"
        staging.mkdir()
        try:
            (staging / "link").symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("symlinks are unavailable")
        with self.assertRaisesRegex(ValueError, "escapes extraction root"):
            contained_archive_destination(staging, PurePosixPath("link/x"))

    def test_confidential_extraction_rejects_drive_and_collisions(self) -> None:
        for members in (["C:/escape.txt"], ["a.txt", "A.txt"], ["nul.json"]):
            with self.subTest(members=members):
                archive = self.root / "bundle.zip"
                with zipfile.ZipFile(archive, "w") as bundle:
                    for name in members:
                        bundle.writestr(name, "x")
                staging = self.root / f"staging-{len(list(self.root.iterdir()))}"
                staging.mkdir()
                with self.assertRaises(ValueError):
                    _extract_archive(archive, staging)

    def _wheel(self, name: str, members: dict[str, bytes]) -> None:
        dist = self.root / "dist"
        dist.mkdir(exist_ok=True)
        with zipfile.ZipFile(dist / name, "w") as wheel:
            for member, data in members.items():
                wheel.writestr(member, data)

    def test_artifact_extraction_rejects_case_and_nfc_collisions(self) -> None:
        for members in (
            {"pkg/a.py": b"1", "PKG/A.py": b"2"},
            {"caf\u00e9.py": b"1", "cafe\u0301.py": b"2"},
            {"pkg/a.py": b"1", "pkg/a.py/": b""},
        ):
            with self.subTest(members=list(members)):
                for old in (
                    (self.root / "dist").glob("*")
                    if (self.root / "dist").exists()
                    else ()
                ):
                    old.unlink()
                self._wheel("x-1.0-py3-none-any.whl", members)
                with self.assertRaisesRegex(ValueError, "collide"):
                    with artifacts.extracted_distribution_tree(
                        self.root, ToolConfig(artifacts_path=Path("dist"))
                    ):
                        pass

    def test_artifact_expansion_budget_is_global(self) -> None:
        self._wheel("a-1.0-py3-none-any.whl", {"a.py": b"x" * 60})
        self._wheel("b-1.0-py3-none-any.whl", {"b.py": b"x" * 60})
        config = ToolConfig(artifacts_path=Path("dist"))
        with patch.object(artifacts, "_MAX_TOTAL_BYTES", 100):
            with self.assertRaisesRegex(ValueError, "total expansion limit"):
                with artifacts.extracted_distribution_tree(self.root, config):
                    pass
        with patch.object(artifacts, "_MAX_TOTAL_BYTES", 200):
            with artifacts.extracted_distribution_tree(self.root, config) as tree:
                self.assertEqual(len(list(tree.iterdir())), 2)


class AuditPackageBindingTests(_TemporaryRoot):
    @patch("py_security_suite.audit_package.verify_report")
    def test_verification_rechecks_evidence_report_binding(self, verify_mock) -> None:
        verify_mock.return_value = {
            "scan_id": "scan-1",
            "checksums_sha256": "c" * 64,
            "outcome": "pass",
        }
        report = self.root / "report"
        report.mkdir()
        (report / "findings.json").write_text("{}", encoding="utf-8")
        evidence = self.root / "evidence.json"
        evidence.write_text(
            json.dumps({"report": {"checksums_sha256": "c" * 64}}), encoding="utf-8"
        )
        package = self.root / "audit.zip"
        create_audit_package(
            report,
            package,
            evidence=(
                (
                    "readiness",
                    evidence,
                    hashlib.sha256(evidence.read_bytes()).hexdigest(),
                ),
            ),
        )
        # Re-seal the package with evidence bound to a different report while
        # keeping every per-file digest in the manifest self-consistent.
        unbound = json.dumps({"report": {"checksums_sha256": "d" * 64}}).encode()
        with zipfile.ZipFile(package) as source:
            entries = {name: source.read(name) for name in source.namelist()}
        manifest = json.loads(entries["audit-manifest.json"])
        for record in manifest["files"]:
            if record["path"] == "evidence/readiness.json":
                record["sha256"] = hashlib.sha256(unbound).hexdigest()
                record["size_bytes"] = len(unbound)
        entries["evidence/readiness.json"] = unbound
        entries["audit-manifest.json"] = json.dumps(manifest).encode()
        tampered = self.root / "tampered.zip"
        with zipfile.ZipFile(tampered, "w") as target:
            for name, data in entries.items():
                target.writestr(name, data)
        with self.assertRaisesRegex(ValueError, "not bound to this report"):
            verify_audit_package(
                tampered,
                package_sha256=hashlib.sha256(tampered.read_bytes()).hexdigest(),
            )

    def test_safe_archive_names_reject_drive_and_device_paths(self) -> None:
        for name in ("C:/x", "report/C:x", "report/nul", "report/a\x00", "x/"):
            self.assertFalse(audit_package._safe_archive_name(name))
        self.assertTrue(audit_package._safe_archive_name("report/findings.json"))


class BytecodeLineTests(unittest.TestCase):
    def test_line_numbers_come_from_each_instruction(self) -> None:
        source = "x = 1\n\nimport os\n\ndef f():\n    y = 2\n    return eval('1')\n"
        code = compile(source, "fixture.py", "exec")
        payload = importlib.util.MAGIC_NUMBER + b"\x00" * 12 + marshal.dumps(code)
        edges = analyze_python_bytecode(payload)
        self.assertIn([3, "module-import", "os"], edges)
        self.assertIn([7, "dynamic-dispatch", "eval"], edges)

    def test_instruction_line_supports_every_python_shape(self) -> None:
        positions = SimpleNamespace(lineno=9)
        cases = (
            (SimpleNamespace(line_number=4, starts_line=True), 4),
            (SimpleNamespace(line_number=None, positions=positions), 9),
            (SimpleNamespace(positions=None, starts_line=7), 7),
            (
                SimpleNamespace(
                    positions=SimpleNamespace(lineno=None), starts_line=True
                ),
                None,
            ),
            (SimpleNamespace(starts_line=None), None),
        )
        for instruction, expected in cases:
            with self.subTest(instruction=instruction):
                self.assertEqual(
                    bytecode_analysis._instruction_line(cast(Any, instruction)),
                    expected,
                )

    def test_shared_code_objects_are_analyzed_once(self) -> None:
        inner = compile("import os\n", "inner.py", "exec")
        outer = compile("pass\n", "outer.py", "exec").replace(co_consts=(inner, inner))
        payload = importlib.util.MAGIC_NUMBER + b"\x00" * 12 + marshal.dumps(outer)
        self.assertEqual(analyze_python_bytecode(payload), [[1, "module-import", "os"]])

    def test_limits_and_malformed_payloads_fail_closed(self) -> None:
        code = compile("import os\nimport sys\n", "fixture.py", "exec")
        payload = importlib.util.MAGIC_NUMBER + b"\x00" * 12 + marshal.dumps(code)
        for name, value in (
            ("_MAX_CODE_OBJECTS", 0),
            ("_MAX_INSTRUCTIONS", 1),
            ("_MAX_EDGES", 0),
        ):
            with self.subTest(limit=name), patch.object(bytecode_analysis, name, value):
                with self.assertRaisesRegex(ValueError, "limit exceeded|invalid"):
                    analyze_python_bytecode(payload)
        header = importlib.util.MAGIC_NUMBER + b"\x00" * 12
        for bad in (
            b"short",
            b"\x00" * 16 + marshal.dumps(code),
            header + b"\xff\xff",
            header + marshal.dumps(42),
        ):
            with self.subTest(payload=bad[:20]):
                with self.assertRaises(ValueError):
                    analyze_python_bytecode(bad)


class JUnitTests(_TemporaryRoot):
    def _document(self, xml: str) -> dict[str, object]:
        report = self.root / "junit.xml"
        report.write_text(xml, encoding="utf-8")
        return evidence_ingest._junit_document(report)

    def test_failure_outranks_skipped(self) -> None:
        document = self._document(
            "<testsuite><testcase name='t'><skipped/><failure message='boom'/>"
            "</testcase><testcase name='u'><skipped/><error/></testcase></testsuite>"
        )
        totals = document["totals"]
        assert isinstance(totals, dict)
        self.assertEqual(
            (totals["failures"], totals["errors"], totals["skipped"]), (1, 1, 0)
        )
        failures = document["failures"]
        assert isinstance(failures, list)
        self.assertEqual(len(failures), 2)

    def test_time_must_stay_finite(self) -> None:
        for xml in (
            "<testsuite><testcase name='t' time='inf'/></testsuite>",
            "<testsuite><testcase name='t' time='1e308'/>"
            "<testcase name='u' time='1e308'/></testsuite>",
        ):
            with self.subTest(xml=xml):
                with self.assertRaisesRegex(TypeError, "finite|expected a number"):
                    self._document(xml)

    def test_failures_list_is_bounded(self) -> None:
        cases = "".join(
            f"<testcase name='t{n}'><failure/></testcase>" for n in range(3)
        )
        with patch.object(evidence_ingest, "_MAX_JUNIT_FAILURES", 2):
            document = self._document(f"<testsuite>{cases}</testsuite>")
        failures = document["failures"]
        assert isinstance(failures, list)
        self.assertEqual(len(failures), 2)
        self.assertFalse(document["failure_inventory_complete"])


class EvidenceNumberTests(unittest.TestCase):
    def test_numbers_must_be_ascii_without_separators(self) -> None:
        for value in ("\u0661\u0662", "\uff11", "1_000", "0x10", " ", "1.5"):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    evidence_ingest._integer(value)
        for value in ("1_0.5", "\u0661.5", "nan", "inf", True):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    evidence_ingest._number(value)
        self.assertEqual(evidence_ingest._integer("-42"), -42)
        self.assertEqual(evidence_ingest._number("85.5"), 85.5)
        self.assertEqual(evidence_ingest._number(3), 3.0)

    def test_percent_covered_is_cross_checked(self) -> None:
        consistent = {
            "covered_lines": 8,
            "num_statements": 10,
            "covered_branches": 1,
            "num_branches": 2,
            "percent_covered": 75.0,
        }
        self.assertEqual(
            evidence_ingest._coverage_summary(consistent)["percent_covered"], 75.0
        )
        for override in (
            {"percent_covered": 99.0},
            {"covered_lines": 11},
            {"percent_covered": 120.0},
            {"covered_lines": -1},
        ):
            with self.subTest(override=override):
                with self.assertRaises(ValueError):
                    evidence_ingest._coverage_summary(consistent | override)

    def test_serialization_failure_is_reported_not_raised(self) -> None:
        with (
            patch.object(
                evidence_ingest,
                "_scorecard_document",
                return_value={"bad": float("nan")},
            ),
            tempfile.NamedTemporaryFile(suffix=".json") as handle,
        ):
            status = evidence_ingest.main(["scorecard", handle.name])
        self.assertEqual(status, 2)


class StrictJsonTests(unittest.TestCase):
    def test_recursion_is_a_value_error(self) -> None:
        with self.assertRaises(ValueError):
            strict_loads("[" * 200_000 + "]" * 200_000)

    def test_byte_cap_precedes_parsing(self) -> None:
        with self.assertRaisesRegex(ValueError, "byte limit"):
            strict_loads(b"[1, 2, 3]", maximum_bytes=4)
        self.assertEqual(strict_loads("[1]", maximum_bytes=3), [1])

    def test_lone_surrogates_are_rejected(self) -> None:
        for payload in ('"\\ud800"', '{"\\udc00": 1}', '["a\\ud83d"]'):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(ValueError, "surrogate"):
                    strict_loads(payload)
        self.assertEqual(strict_loads('"\\ud83d\\ude00"'), "\U0001f600")
        with self.assertRaises(ValueError):
            strict_dumps({"value": "\ud800"})


class StandardsXmlTests(unittest.TestCase):
    def test_deep_xml_section_text_is_linear(self) -> None:
        depth = 2_000
        payload = (
            "".join(f"<n id='e{i}'>t{i}" for i in range(depth)) + "</n>" * depth
        ).encode()
        sections = _extract_semantic_sections(payload, "application/xml")
        self.assertEqual(sections["e5"], "t5")
        self.assertLessEqual(
            sum(len(value) for value in sections.values()), len(payload)
        )


if __name__ == "__main__":
    unittest.main()
