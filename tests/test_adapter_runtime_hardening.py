from __future__ import annotations

import json
import hashlib
import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from py_security_suite.adapters.codeql import CodeQlAdapter, _copy_target
from py_security_suite.adapters.common import database_freshness_error
from py_security_suite.adapters.cosign import CosignAdapter, _bundle_for
from py_security_suite.adapters.cyclonedx import CycloneDxAdapter, _document
from py_security_suite.adapters.file_output import JsonFileScannerAdapter
from py_security_suite.adapters.pypi_attestations import (
    PyPiAttestationsAdapter,
    _provenance_file,
)
from py_security_suite.adapters.ruff_quality import (
    RuffQualityAdapter,
    _area,
    _classification,
    _severity,
)
from py_security_suite.config import ToolConfig
from py_security_suite.execution import RawExecution
from py_security_suite.models import Finding, ToolStatus


def _execution(
    command: list[str],
    *,
    exit_code: int | None = 0,
    timed_out: bool = False,
    stderr: str = "",
) -> RawExecution:
    return RawExecution(
        command=command,
        exit_code=exit_code,
        stdout="",
        stderr=stderr,
        duration_seconds=0.01,
        timed_out=timed_out,
    )


class _FixtureFileAdapter(JsonFileScannerAdapter):
    name = "fixture-file"

    def build_file_command(
        self, executable: str, target: Path, output: Path
    ) -> list[str]:
        return [executable, "--output", str(output)]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = json.loads(payload)
        if not isinstance(document, dict):
            raise TypeError("fixture output must be an object")
        return []

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, object]:
        return {"fixture.json": json.loads(payload)}


class FileOutputRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.target = Path(self.enterContext(temporary)).resolve()

    def _adapter(self, maximum: int = 1024) -> _FixtureFileAdapter:
        adapter = _FixtureFileAdapter(
            ToolConfig(executable="approved-fixture", timeout_seconds=3), maximum
        )
        self.enterContext(
            patch.object(
                adapter, "_prepare_executable", return_value=("approved-fixture", None)
            )
        )
        self.enterContext(
            patch.object(adapter, "_detect_version", return_value="fixture 1.0")
        )
        self.enterContext(
            patch.object(adapter, "_executable_changed_error", return_value=None)
        )
        return adapter

    def test_file_adapter_completes_and_retains_derived_artifact(self) -> None:
        adapter = self._adapter()

        def successful(command: list[str], **_kwargs: object) -> RawExecution:
            Path(command[-1]).write_text('{"findings": []}', encoding="utf-8")
            return _execution(command)

        with patch(
            "py_security_suite.adapters.file_output.run_command",
            side_effect=successful,
        ):
            result = adapter.run(self.target)

        self.assertEqual(result.tool_run.status, ToolStatus.COMPLETED)
        self.assertEqual(result.tool_run.version, "fixture 1.0")
        self.assertEqual(result.artifacts["fixture.json"], {"findings": []})

    def test_file_adapter_rejects_missing_oversized_and_malformed_output(self) -> None:
        cases = ("missing", "oversized", "malformed")
        for case in cases:
            with self.subTest(case=case):
                adapter = self._adapter(maximum=64)

                def invalid(
                    command: list[str], case: str = case, **_kwargs: object
                ) -> RawExecution:
                    output = Path(command[-1])
                    if case == "oversized":
                        output.write_bytes(b"x" * 65)
                    elif case == "malformed":
                        output.write_text("not-json", encoding="utf-8")
                    return _execution(command)

                with patch(
                    "py_security_suite.adapters.file_output.run_command",
                    side_effect=invalid,
                ):
                    result = adapter.run(self.target)

                self.assertEqual(result.tool_run.status, ToolStatus.PARSE_ERROR)
                self.assertIn(
                    "could not parse fixture-file output", result.tool_run.error or ""
                )

    def test_file_adapter_maps_timeout_exit_and_integrity_failures(self) -> None:
        cases = (
            (_execution(["fixture"], timed_out=True), None, ToolStatus.TIMED_OUT),
            (_execution(["fixture"], exit_code=9), None, ToolStatus.FAILED),
            (
                _execution(["fixture"]),
                "scanner executable changed during execution",
                ToolStatus.FAILED,
            ),
        )
        for execution, changed_error, expected in cases:
            with self.subTest(expected=expected):
                adapter = self._adapter()
                if changed_error:
                    self.enterContext(
                        patch.object(
                            adapter,
                            "_executable_changed_error",
                            return_value=changed_error,
                        )
                    )
                with patch(
                    "py_security_suite.adapters.file_output.run_command",
                    return_value=execution,
                ):
                    result = adapter.run(self.target)
                self.assertEqual(result.tool_run.status, expected)

    def test_file_adapter_preflight_results_are_explicit(self) -> None:
        adapter = _FixtureFileAdapter(ToolConfig(executable="missing"), 1024)
        with patch.object(adapter, "not_applicable_reason", return_value="no input"):
            skipped = adapter.run(self.target)
        with patch.object(
            adapter, "_prepare_executable", return_value=(None, "bad hash")
        ):
            unavailable = adapter.run(self.target)

        self.assertEqual(skipped.tool_run.status, ToolStatus.SKIPPED)
        self.assertFalse(skipped.tool_run.applicable)
        self.assertEqual(unavailable.tool_run.status, ToolStatus.UNAVAILABLE)
        self.assertEqual(unavailable.tool_run.error, "bad hash")


class SpecializedAdapterRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.target = Path(self.enterContext(temporary)).resolve()
        (self.target / "app.py").write_text("value = 1\n", encoding="utf-8")

    def test_codeql_mirror_excludes_scanner_state(self) -> None:
        (self.target / ".git").mkdir()
        (self.target / ".git" / "config").write_text("secret", encoding="utf-8")
        (self.target / ".github" / "codeql").mkdir(parents=True)
        (self.target / ".github" / "codeql" / "override.yml").write_text(
            "queries: []", encoding="utf-8"
        )
        (self.target / "pkg").mkdir()
        (self.target / "pkg" / "module.py").write_text("pass\n", encoding="utf-8")
        destination = self.target / "mirror"

        _copy_target(self.target, destination)

        self.assertTrue((destination / "pkg" / "module.py").is_file())
        self.assertFalse((destination / ".git").exists())
        self.assertFalse((destination / ".github" / "codeql").exists())

    def test_codeql_completed_run_uses_only_generated_sarif(self) -> None:
        adapter = CodeQlAdapter(ToolConfig(executable="run-codeql"), 4096)

        def run_codeql(command: list[str], **kwargs: object) -> RawExecution:
            cwd = Path(str(kwargs["cwd"]))
            report = cwd / ".codeql" / "reports" / "python-fixture.sarif"
            report.parent.mkdir(parents=True)
            report.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")
            return _execution(command)

        with (
            patch.object(adapter, "prerequisite_error", return_value=None),
            patch.object(
                adapter, "_prepare_executable", return_value=("run-codeql", None)
            ),
            patch.object(adapter, "_detect_version", return_value="CodeQL 2.0"),
            patch.object(adapter, "_executable_changed_error", return_value=None),
            patch.object(adapter, "_auxiliary_changed_error", return_value=None),
            patch(
                "py_security_suite.adapters.codeql.run_command", side_effect=run_codeql
            ),
        ):
            result = adapter.run(self.target)

        self.assertEqual(result.tool_run.status, ToolStatus.COMPLETED)
        self.assertTrue(result.diagnostic["target_mirrored"])
        self.assertFalse(result.diagnostic["repository_codeql_config_used"])
        self.assertFalse(result.diagnostic["auto_download_allowed"])

    def test_codeql_failure_and_missing_report_fail_closed(self) -> None:
        cases = (
            (_execution(["run-codeql"], timed_out=True), ToolStatus.TIMED_OUT),
            (_execution(["run-codeql"], exit_code=4), ToolStatus.FAILED),
            (_execution(["run-codeql"]), ToolStatus.PARSE_ERROR),
        )
        for execution, expected in cases:
            with self.subTest(expected=expected):
                adapter = CodeQlAdapter(ToolConfig(executable="run-codeql"), 4096)
                with (
                    patch.object(adapter, "prerequisite_error", return_value=None),
                    patch.object(
                        adapter,
                        "_prepare_executable",
                        return_value=("run-codeql", None),
                    ),
                    patch.object(adapter, "_detect_version", return_value="CodeQL 2.0"),
                    patch.object(
                        adapter, "_executable_changed_error", return_value=None
                    ),
                    patch.object(
                        adapter, "_auxiliary_changed_error", return_value=None
                    ),
                    patch(
                        "py_security_suite.adapters.codeql.run_command",
                        return_value=execution,
                    ),
                ):
                    result = adapter.run(self.target)
                self.assertEqual(result.tool_run.status, expected)

    def test_artifact_verifiers_report_missing_offline_evidence(self) -> None:
        dist = self.target / "dist"
        dist.mkdir()
        artifact = dist / "fixture-1.0-py3-none-any.whl"
        artifact.write_bytes(b"wheel")
        trust = self.target / "trust"
        trust.mkdir()
        key = trust / "cosign.pub"
        key.write_text("fixture-key", encoding="utf-8")

        pypi = PyPiAttestationsAdapter(
            ToolConfig(
                executable="pypi-attestations",
                artifacts_path=Path("dist"),
                provenance_path=Path("dist"),
                database_path=trust,
                repository_url="https://github.com/example/project",
            ),
            4096,
        )
        cosign = CosignAdapter(
            ToolConfig(
                executable="cosign",
                artifacts_path=Path("dist"),
                provenance_path=Path("dist"),
                public_key_path=key,
                public_key_sha256=hashlib.sha256(b"fixture-key").hexdigest(),
            ),
            4096,
        )
        for adapter in (pypi, cosign):
            with (
                patch.object(
                    adapter,
                    "_prepare_executable",
                    return_value=(adapter.config.executable, None),
                ),
                patch.object(adapter, "_detect_version", return_value="fixture 1.0"),
                patch.object(adapter, "_executable_changed_error", return_value=None),
            ):
                result = adapter.run(self.target)
            self.assertEqual(result.tool_run.status, ToolStatus.COMPLETED)
            self.assertEqual(result.tool_run.finding_count, 1)
            self.assertEqual(result.findings[0].severity.value, "high")
            self.assertTrue(result.findings[0].citations)
            self.assertEqual(
                result.findings[0].evidence["artifact_path"],
                "dist/fixture-1.0-py3-none-any.whl",
            )
            self.assertEqual(result.findings[0].evidence["artifact_size_bytes"], 5)
            self.assertEqual(
                len(str(result.findings[0].evidence["artifact_sha256"])), 64
            )
        self.assertIsNone(_provenance_file(dist, artifact))
        self.assertIsNone(_bundle_for(dist, artifact))

    def test_cosign_version_uses_machine_readable_output(self) -> None:
        adapter = CosignAdapter(ToolConfig(executable="cosign"), 4096)
        execution = RawExecution(
            command=["cosign", "version", "--json"],
            exit_code=0,
            stdout=json.dumps({"gitVersion": "v3.1.2"}),
            stderr="",
            duration_seconds=0.01,
            timed_out=False,
        )
        with patch(
            "py_security_suite.adapters.cosign.run_command", return_value=execution
        ):
            self.assertEqual(
                adapter._detect_version("cosign", self.target), "cosign v3.1.2"
            )

        cases = (
            (
                RawExecution(
                    command=["cosign"],
                    exit_code=0,
                    stdout="GitVersion: v3.2.0",
                    stderr="",
                    duration_seconds=0.01,
                    timed_out=False,
                ),
                "cosign v3.2.0",
            ),
            (_execution(["cosign"], exit_code=1), "unknown"),
            (_execution(["cosign"], timed_out=True), "unknown"),
            (_execution(["cosign"]), "unknown"),
        )
        for result, expected in cases:
            with (
                self.subTest(expected=expected),
                patch(
                    "py_security_suite.adapters.cosign.run_command", return_value=result
                ),
            ):
                self.assertEqual(
                    adapter._detect_version("cosign", self.target), expected
                )

    def test_cyclonedx_selects_only_locked_inputs(self) -> None:
        requirements = self.target / "requirements.txt"
        requirements.write_text("package>=1\n", encoding="utf-8")
        adapter = CycloneDxAdapter(ToolConfig(), 4096)
        self.assertIsNone(adapter._input(self.target))

        requirements.write_text("package==1.0\n", encoding="utf-8")
        command = adapter.build_command("cyclonedx-py", self.target)
        self.assertEqual(command[1], "requirements")
        self.assertIn("--output-reproducible", command)
        self.assertEqual(
            _document('{"bomFormat":"CycloneDX"}')["bomFormat"], "CycloneDX"
        )
        with self.assertRaisesRegex(TypeError, "must be an object"):
            _document("[]")

    def test_cyclonedx_generates_sbom_from_frozen_offline_uv_export(self) -> None:
        (self.target / "pyproject.toml").write_text(
            '[project]\nname = "fixture"\nversion = "1.0"\n', encoding="utf-8"
        )
        (self.target / "uv.lock").write_text("version = 1\n", encoding="utf-8")
        adapter = CycloneDxAdapter(
            ToolConfig(executable="cyclonedx-py", auxiliary_executable="uv"), 4096
        )
        adapter._auxiliary_path = Path("uv")

        def commands(command: list[str], **_kwargs: object) -> RawExecution:
            if command[0] == "uv":
                output = Path(command[command.index("--output-file") + 1])
                output.write_text("defusedxml==0.7.1\n", encoding="utf-8")
                return _execution(command)
            return RawExecution(
                command=command,
                exit_code=0,
                stdout='{"bomFormat":"CycloneDX","components":[]}',
                stderr="",
                duration_seconds=0.01,
            )

        with (
            patch.object(adapter, "_prepare_uv", return_value=None),
            patch.object(
                adapter, "_prepare_executable", return_value=("cyclonedx-py", None)
            ),
            patch.object(adapter, "_detect_version", return_value="cyclonedx 7.3"),
            patch.object(adapter, "_executable_changed_error", return_value=None),
            patch.object(adapter, "_auxiliary_changed_error", return_value=None),
            patch(
                "py_security_suite.adapters.cyclonedx.run_command", side_effect=commands
            ),
        ):
            result = adapter.run(self.target)

        self.assertEqual(result.tool_run.status, ToolStatus.COMPLETED)
        self.assertEqual(result.diagnostic["dependency_source"], "uv.lock")
        self.assertTrue(result.diagnostic["lock_export_frozen"])
        self.assertTrue(result.diagnostic["lock_export_offline"])
        self.assertEqual(result.artifacts["sbom.cdx.json"]["bomFormat"], "CycloneDX")

    def test_ruff_quality_reclassifies_correctness_rules(self) -> None:
        payload = json.dumps(
            [
                {
                    "code": "C901",
                    "message": "function is too complex",
                    "filename": str(self.target / "app.py"),
                    "location": {"row": 1},
                    "end_location": {"row": 1},
                    "url": "https://docs.astral.sh/ruff/rules/complex-structure/",
                }
            ]
        )
        adapter = RuffQualityAdapter(ToolConfig(), 4096)
        finding = adapter.parse(payload, self.target)[0]
        command = adapter.build_command("ruff", self.target)

        self.assertEqual(finding.domain, "quality")
        self.assertEqual(finding.area, "complexity")
        self.assertEqual(finding.severity.value, "low")
        self.assertEqual(finding.classifications, ["MCCABE-C901"])
        self.assertIn("E9,F,B,C90,DTZ,PERF,PLC,PLE,PLW,RET,RUF,SIM,TRY,UP", command)
        self.assertIn("lint.mccabe.max-complexity=15", command)

    def test_ruff_quality_metadata_covers_supported_rule_families(self) -> None:
        cases = (
            ("C901", "complexity", "MCCABE-C901", "low"),
            ("PERF401", "performance", "PERFLINT-PERF401", "low"),
            ("DTZ001", "time-correctness", "FLAKE8-DATETIMEZ-DTZ001", "medium"),
            ("PLW0603", "code-correctness", "PYLINT-PLW0603", "medium"),
            ("RET505", "control-flow", "FLAKE8-RETURN-RET505", "medium"),
            ("SIM102", "control-flow", "FLAKE8-SIMPLIFY-SIM102", "medium"),
            ("TRY301", "control-flow", "TRYCERATOPS-TRY301", "medium"),
            ("UP001", "compatibility", "PYUPGRADE-UP001", "low"),
            ("E902", "code-correctness", "PYCODESTYLE-E902", "medium"),
            ("F401", "code-correctness", "PYFLAKES-F401", "medium"),
            ("B006", "code-correctness", "BUGBEAR-B006", "medium"),
            ("RUF001", "code-correctness", "RUFF-RUF001", "medium"),
            ("X001", "code-correctness", "RUFF-X001", "low"),
        )
        for rule_id, area, classification, severity in cases:
            with self.subTest(rule_id=rule_id):
                self.assertEqual(_area(rule_id), area)
                self.assertEqual(_classification(rule_id), classification)
                self.assertEqual(_severity(rule_id).value, severity)

    def test_database_freshness_fails_closed_for_missing_or_stale_marker(self) -> None:
        database = self.target / "database"
        database.mkdir()
        self.assertIn(
            "was not found", database_freshness_error(database, "snapshot.db", 10) or ""
        )

        marker = database / "snapshot.db"
        marker.write_bytes(b"approved fixture database")
        self.assertIsNone(database_freshness_error(database, "snapshot.db", 10))

        stale = datetime.now(UTC) - timedelta(days=11)
        os.utime(marker, (stale.timestamp(), stale.timestamp()))
        self.assertIn(
            "maximum allowed age",
            database_freshness_error(database, "snapshot.db", 10) or "",
        )


if __name__ == "__main__":
    unittest.main()
