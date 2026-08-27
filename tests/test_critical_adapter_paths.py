from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from py_security_suite.adapters.codeql import CodeQlAdapter, _copy_target
from py_security_suite.adapters.cyclonedx import (
    CycloneDxAdapter,
    _has_pinned_requirement,
)
from py_security_suite.config import ToolConfig
from py_security_suite.execution import RawExecution
from py_security_suite.models import ToolStatus


def _execution(
    command: list[str],
    *,
    exit_code: int | None = 0,
    stdout: str = "",
    stderr: str = "",
    timed_out: bool = False,
) -> RawExecution:
    return RawExecution(
        command=command,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=0.01,
        timed_out=timed_out,
    )


class CodeQlGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(temporary)).resolve()
        self.executable = self.root / "codeql.exe"
        self.executable.write_bytes(b"codeql fixture")
        self.home = self.root / "home"
        self.pack = self.home / ".codeql" / "packages" / "codeql" / "python-queries"

    def _adapter(
        self,
        *,
        auxiliary_executable_sha256: str = "",
        include_home: bool = True,
    ) -> CodeQlAdapter:
        return CodeQlAdapter(
            ToolConfig(
                executable="run-codeql",
                auxiliary_executable=str(self.executable),
                auxiliary_executable_sha256=auxiliary_executable_sha256,
                database_path=self.home if include_home else None,
            ),
            256,
        )

    def test_applicability_command_and_sarif_parser(self) -> None:
        adapter = self._adapter()
        self.assertIn("no Python", adapter.not_applicable_reason(self.root) or "")
        skipped = adapter.run(self.root)
        self.assertEqual(skipped.tool_run.status, ToolStatus.SKIPPED)
        self.assertFalse(skipped.tool_run.applicable)
        (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
        self.assertIsNone(adapter.not_applicable_reason(self.root))
        self.assertEqual(
            adapter.build_command("run-codeql", self.root),
            ["run-codeql", "--lang", "python", "--config", "", "--quiet"],
        )
        finding_payload = json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "CodeQL",
                                "rules": [
                                    {
                                        "id": "py/sql-injection",
                                        "shortDescription": {"text": "SQL injection"},
                                    }
                                ],
                            }
                        },
                        "results": [
                            {
                                "ruleId": "py/sql-injection",
                                "level": "error",
                                "message": {"text": "tainted SQL"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": 1},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )
        finding = adapter.parse(finding_payload, self.root)[0]
        self.assertEqual(finding.sources[0].tool, "codeql")
        self.assertEqual(finding.locations[0].path, "app.py")

    def test_prerequisite_errors_are_specific_and_integrity_checked(self) -> None:
        adapter = self._adapter()
        with patch(
            "py_security_suite.adapters.codeql.resolve_executable", return_value=None
        ):
            self.assertIn("pre-staged CodeQL", adapter.prerequisite_error() or "")
        with (
            patch(
                "py_security_suite.adapters.codeql.resolve_executable",
                return_value=str(self.executable),
            ),
            patch("py_security_suite.adapters.codeql.sha256_file", side_effect=OSError),
        ):
            self.assertIn("could not be hashed", adapter.prerequisite_error() or "")

        digest = "a" * 64
        mismatch = self._adapter(auxiliary_executable_sha256="b" * 64)
        with (
            patch(
                "py_security_suite.adapters.codeql.resolve_executable",
                return_value=str(self.executable),
            ),
            patch("py_security_suite.adapters.codeql.sha256_file", return_value=digest),
        ):
            self.assertIn("approved digest", mismatch.prerequisite_error() or "")

        no_home = self._adapter(include_home=False)
        with (
            patch(
                "py_security_suite.adapters.codeql.resolve_executable",
                return_value=str(self.executable),
            ),
            patch("py_security_suite.adapters.codeql.sha256_file", return_value=digest),
        ):
            self.assertIn(
                "isolated run-codeql home", no_home.prerequisite_error() or ""
            )

        with patch(
            "py_security_suite.adapters.codeql.resolve_executable",
            return_value=str(self.executable),
        ):
            self.assertIn("query pack is missing", adapter.prerequisite_error() or "")
            self.pack.mkdir(parents=True)
            self.assertIsNone(adapter.prerequisite_error())

    def test_environment_and_version_detection_are_bounded(self) -> None:
        adapter = self._adapter()
        adapter._auxiliary_path = self.executable
        environment = adapter.environment()
        self.assertEqual(environment.extra["HOME"], str(self.home.resolve()))
        self.assertEqual(environment.extra["USERPROFILE"], str(self.home.resolve()))
        self.assertEqual(environment.extra["RCQL_DOWNLOAD_RETRY_ATTEMPTS"], "1")
        self.assertEqual(
            Path(environment.extra["PATH"].split(os.pathsep)[0]), self.executable.parent
        )
        cases = (
            (_execution(["codeql"], exit_code=1), "unknown"),
            (_execution(["codeql"], timed_out=True), "unknown"),
            (
                _execution(
                    ["codeql"], stdout="CodeQL command-line toolchain 2.20\nmore"
                ),
                "2.20",
            ),
        )
        for execution, expected in cases:
            with (
                self.subTest(expected=expected),
                patch(
                    "py_security_suite.adapters.codeql.run_command",
                    return_value=execution,
                ),
            ):
                self.assertIn(
                    expected, adapter._detect_version("run-codeql", self.root)
                )
        adapter._auxiliary_path = None
        with patch(
            "py_security_suite.adapters.codeql.resolve_executable", return_value=None
        ):
            self.assertIn("unknown", adapter._detect_version("run-codeql", self.root))

    def test_run_preflight_and_generated_report_failures_fail_closed(self) -> None:
        (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
        adapter = self._adapter()
        with (
            patch.object(adapter, "prerequisite_error", return_value="missing pack"),
            patch.object(adapter, "_prepare_executable", return_value=(None, None)),
        ):
            self.assertEqual(
                adapter.run(self.root).tool_run.status, ToolStatus.UNAVAILABLE
            )

        cases = ("multiple", "oversized", "malformed", "changed")
        for case in cases:
            with self.subTest(case=case):
                adapter = self._adapter()

                def execute(
                    command: list[str], case: str = case, **kwargs: object
                ) -> RawExecution:
                    mirror = Path(str(kwargs["cwd"]))
                    reports = mirror / ".codeql" / "reports"
                    reports.mkdir(parents=True)
                    if case == "multiple":
                        (reports / "python-one.sarif").write_text(
                            "{}", encoding="utf-8"
                        )
                        (reports / "python-two.sarif").write_text(
                            "{}", encoding="utf-8"
                        )
                    elif case == "oversized":
                        (reports / "python-one.sarif").write_bytes(b"x" * 257)
                    elif case == "malformed":
                        (reports / "python-one.sarif").write_text(
                            "not-json", encoding="utf-8"
                        )
                    return _execution(command)

                with (
                    patch.object(adapter, "prerequisite_error", return_value=None),
                    patch.object(
                        adapter,
                        "_prepare_executable",
                        return_value=("run-codeql", None),
                    ),
                    patch.object(adapter, "_detect_version", return_value="CodeQL 2"),
                    patch.object(
                        adapter,
                        "_executable_changed_error",
                        return_value="runner changed" if case == "changed" else None,
                    ),
                    patch.object(
                        adapter, "_auxiliary_changed_error", return_value=None
                    ),
                    patch(
                        "py_security_suite.adapters.codeql.run_command",
                        side_effect=execute,
                    ),
                ):
                    result = adapter.run(self.root)
                self.assertIn(
                    result.tool_run.status, {ToolStatus.FAILED, ToolStatus.PARSE_ERROR}
                )

    def test_auxiliary_change_detection_and_mirror_symlink_exclusion(self) -> None:
        adapter = self._adapter()
        self.assertIsNone(adapter._auxiliary_changed_error())
        adapter._auxiliary_path = self.executable
        adapter._auxiliary_sha256 = "a" * 64
        with patch(
            "py_security_suite.adapters.codeql.sha256_file", side_effect=OSError
        ):
            self.assertIn("unreadable", adapter._auxiliary_changed_error() or "")
        with patch(
            "py_security_suite.adapters.codeql.sha256_file", return_value="b" * 64
        ):
            self.assertIn("changed", adapter._auxiliary_changed_error() or "")
        with patch(
            "py_security_suite.adapters.codeql.sha256_file", return_value="a" * 64
        ):
            self.assertIsNone(adapter._auxiliary_changed_error())

        source = self.root / "source"
        source.mkdir()
        (source / "keep.py").write_text("pass\n", encoding="utf-8")
        link = source / "linked.py"
        try:
            link.symlink_to(source / "keep.py")
        except OSError:
            self.skipTest("symlinks are not available")
        destination = self.root / "copy"
        _copy_target(source, destination)
        self.assertTrue((destination / "keep.py").is_file())
        self.assertFalse((destination / "linked.py").exists())


class CycloneDxGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(temporary)).resolve()
        self.uv = self.root / "uv.exe"
        self.uv.write_bytes(b"uv fixture")

    def _adapter(
        self,
        maximum: int = 256,
        *,
        auxiliary_executable_sha256: str = "",
    ) -> CycloneDxAdapter:
        return CycloneDxAdapter(
            ToolConfig(
                executable="cyclonedx-py",
                auxiliary_executable=str(self.uv),
                auxiliary_executable_sha256=auxiliary_executable_sha256,
            ),
            maximum,
        )

    def _enable_uv_input(self) -> None:
        (self.root / "pyproject.toml").write_text(
            "[project]\nname='x'\n", encoding="utf-8"
        )
        (self.root / "uv.lock").write_text("version = 1\n", encoding="utf-8")

    def test_input_selection_commands_and_payload_guards(self) -> None:
        adapter = self._adapter()
        self.assertIn(
            "no supported locked", adapter.not_applicable_reason(self.root) or ""
        )
        with patch.object(
            adapter, "_prepare_executable", return_value=(None, "missing")
        ):
            self.assertEqual(adapter.run(self.root).tool_run.status, ToolStatus.SKIPPED)
        with self.assertRaisesRegex(ValueError, "not available"):
            adapter.build_command("cyclonedx-py", self.root)
        (self.root / "Pipfile.lock").write_text("{}", encoding="utf-8")
        self.assertIsNone(adapter.not_applicable_reason(self.root))
        self.assertEqual(adapter.build_command("cyclonedx-py", self.root)[1], "pipenv")
        (self.root / "Pipfile.lock").unlink()
        (self.root / "pyproject.toml").write_text(
            "[project]\nname='x'\n", encoding="utf-8"
        )
        (self.root / "poetry.lock").write_text("package = []\n", encoding="utf-8")
        self.assertEqual(adapter.build_command("cyclonedx-py", self.root)[1], "poetry")
        (self.root / "poetry.lock").unlink()
        self._enable_uv_input()
        with self.assertRaisesRegex(ValueError, "two-stage export"):
            adapter.build_command("cyclonedx-py", self.root)
        self.assertEqual(
            adapter.parse(
                '{"bomFormat":"CycloneDX","specVersion":"1.7","components":[]}',
                self.root,
            ),
            [],
        )
        self.assertEqual(
            adapter.derived_artifacts('{"bomFormat":"CycloneDX"}', self.root)[
                "sbom.cdx.json"
            ]["bomFormat"],
            "CycloneDX",
        )
        with self.assertRaisesRegex(ValueError, "not a CycloneDX"):
            adapter.parse("{}", self.root)
        with self.assertRaisesRegex(TypeError, "components must be a list"):
            adapter.parse(
                '{"bomFormat":"CycloneDX","specVersion":"1.7","components":{}}',
                self.root,
            )

    def test_uv_preparation_hashes_and_pins_the_auxiliary(self) -> None:
        adapter = self._adapter()
        with patch(
            "py_security_suite.adapters.cyclonedx.resolve_executable", return_value=None
        ):
            self.assertIn("pre-staged uv", adapter._prepare_uv() or "")
        with (
            patch(
                "py_security_suite.adapters.cyclonedx.resolve_executable",
                return_value=str(self.uv),
            ),
            patch(
                "py_security_suite.adapters.cyclonedx.sha256_file", side_effect=OSError
            ),
        ):
            self.assertIn("could not be hashed", adapter._prepare_uv() or "")
        mismatch = self._adapter(auxiliary_executable_sha256="b" * 64)
        with (
            patch(
                "py_security_suite.adapters.cyclonedx.resolve_executable",
                return_value=str(self.uv),
            ),
            patch(
                "py_security_suite.adapters.cyclonedx.sha256_file",
                return_value="a" * 64,
            ),
        ):
            self.assertIn("approved digest", mismatch._prepare_uv() or "")
        approved = self._adapter(auxiliary_executable_sha256="a" * 64)
        with (
            patch(
                "py_security_suite.adapters.cyclonedx.resolve_executable",
                return_value=str(self.uv),
            ),
            patch(
                "py_security_suite.adapters.cyclonedx.sha256_file",
                return_value="a" * 64,
            ),
        ):
            self.assertIsNone(approved._prepare_uv())
        self.assertTrue(approved._auxiliary_integrity_verified)

    def test_auxiliary_change_detection_is_fail_closed(self) -> None:
        adapter = self._adapter()
        self.assertIsNone(adapter._auxiliary_changed_error())
        adapter._auxiliary_path = self.uv
        adapter._auxiliary_sha256 = "a" * 64
        with patch(
            "py_security_suite.adapters.cyclonedx.sha256_file", side_effect=OSError
        ):
            self.assertIn("unreadable", adapter._auxiliary_changed_error() or "")
        with patch(
            "py_security_suite.adapters.cyclonedx.sha256_file", return_value="b" * 64
        ):
            self.assertIn("changed", adapter._auxiliary_changed_error() or "")
        with patch(
            "py_security_suite.adapters.cyclonedx.sha256_file", return_value="a" * 64
        ):
            self.assertIsNone(adapter._auxiliary_changed_error())

    def test_uv_export_failure_matrix_is_explicit(self) -> None:
        self._enable_uv_input()
        unavailable = self._adapter()
        with (
            patch.object(unavailable, "_prepare_uv", return_value="uv unavailable"),
            patch.object(unavailable, "_prepare_executable", return_value=(None, None)),
        ):
            self.assertEqual(
                unavailable.run(self.root).tool_run.status, ToolStatus.UNAVAILABLE
            )

        cases = (
            ("changed", ToolStatus.FAILED),
            ("timeout", ToolStatus.TIMED_OUT),
            ("exit", ToolStatus.FAILED),
            ("missing", ToolStatus.PARSE_ERROR),
            ("oversized", ToolStatus.PARSE_ERROR),
        )
        for case, expected in cases:
            with self.subTest(case=case):
                adapter = self._adapter(maximum=32)
                adapter._auxiliary_path = self.uv

                def export(
                    command: list[str], case: str = case, **_kwargs: object
                ) -> RawExecution:
                    if case == "oversized":
                        output = Path(command[command.index("--output-file") + 1])
                        output.write_bytes(b"x" * 33)
                    return _execution(
                        command,
                        exit_code=2 if case == "exit" else 0,
                        timed_out=case == "timeout",
                    )

                with (
                    patch.object(adapter, "_prepare_uv", return_value=None),
                    patch.object(
                        adapter,
                        "_prepare_executable",
                        return_value=("cyclonedx-py", None),
                    ),
                    patch.object(
                        adapter, "_detect_version", return_value="cyclonedx 7"
                    ),
                    patch.object(
                        adapter,
                        "_executable_changed_error",
                        return_value="scanner changed" if case == "changed" else None,
                    ),
                    patch.object(
                        adapter, "_auxiliary_changed_error", return_value=None
                    ),
                    patch(
                        "py_security_suite.adapters.cyclonedx.run_command",
                        side_effect=export,
                    ),
                ):
                    result = adapter.run(self.root)
                self.assertEqual(result.tool_run.status, expected)

    def test_generation_failure_matrix_is_explicit(self) -> None:
        self._enable_uv_input()
        cases = (
            ("changed", ToolStatus.FAILED),
            ("timeout", ToolStatus.TIMED_OUT),
            ("exit", ToolStatus.FAILED),
            ("malformed", ToolStatus.PARSE_ERROR),
        )
        for case, expected in cases:
            with self.subTest(case=case):
                adapter = self._adapter(maximum=256)
                adapter._auxiliary_path = self.uv
                calls = 0

                def execute(
                    command: list[str], case: str = case, **_kwargs: object
                ) -> RawExecution:
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        output = Path(command[command.index("--output-file") + 1])
                        output.write_text("package==1\n", encoding="utf-8")
                        return _execution(command)
                    return _execution(
                        command,
                        exit_code=3 if case == "exit" else 0,
                        stdout="not-json"
                        if case == "malformed"
                        else '{"bomFormat":"CycloneDX"}',
                        timed_out=case == "timeout",
                    )

                unchanged_calls = 0

                def changed(case: str = case) -> str | None:
                    nonlocal unchanged_calls
                    unchanged_calls += 1
                    return (
                        "scanner changed"
                        if case == "changed" and unchanged_calls == 2
                        else None
                    )

                with (
                    patch.object(adapter, "_prepare_uv", return_value=None),
                    patch.object(
                        adapter,
                        "_prepare_executable",
                        return_value=("cyclonedx-py", None),
                    ),
                    patch.object(
                        adapter, "_detect_version", return_value="cyclonedx 7"
                    ),
                    patch.object(
                        adapter, "_executable_changed_error", side_effect=changed
                    ),
                    patch.object(
                        adapter, "_auxiliary_changed_error", return_value=None
                    ),
                    patch(
                        "py_security_suite.adapters.cyclonedx.run_command",
                        side_effect=execute,
                    ),
                ):
                    result = adapter.run(self.root)
                self.assertEqual(result.tool_run.status, expected)

    def test_pinned_requirement_detection_ignores_options_and_errors(self) -> None:
        requirements = self.root / "requirements.txt"
        requirements.write_text(
            "# comment\n-r base.txt\ngit+https://example.invalid/x\npackage>=1\n",
            encoding="utf-8",
        )
        self.assertFalse(_has_pinned_requirement(requirements))
        requirements.write_text("package==1\n", encoding="utf-8")
        self.assertTrue(_has_pinned_requirement(requirements))
        with patch.object(Path, "read_text", side_effect=OSError):
            self.assertFalse(_has_pinned_requirement(requirements))


if __name__ == "__main__":
    unittest.main()
