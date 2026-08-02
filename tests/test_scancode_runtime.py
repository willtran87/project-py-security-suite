from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from py_security_suite.adapters.scancode import (
    ScanCodeAdapter,
    _copy_without_symlinks,
    _document,
    _integer,
    _license_results,
    _remove_staging_prefix,
    _scan_roots,
)
from py_security_suite.config import ToolConfig
from py_security_suite.execution import RawExecution
from py_security_suite.models import ToolStatus


def _execution(command: list[str], *, stdout: str = "") -> RawExecution:
    return RawExecution(
        command=command,
        exit_code=0,
        stdout=stdout,
        stderr="",
        duration_seconds=0.01,
    )


class ScanCodeRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.target = Path(self.enterContext(temporary)).resolve()

    def test_scan_roots_are_bounded_to_governance_and_vendored_inputs(self) -> None:
        (self.target / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        (self.target / "README.md").write_text("# Fixture\n", encoding="utf-8")
        (self.target / "requirements.in").write_text("package\n", encoding="utf-8")
        (self.target / "src").mkdir()
        (self.target / "src" / "ignored.py").write_text("pass\n", encoding="utf-8")
        (self.target / "vendor").mkdir()
        (self.target / "vendor" / "library.c").write_text("fixture\n", encoding="utf-8")
        (self.target / "build").mkdir()
        (self.target / "build" / "LICENSE").write_text("ignored\n", encoding="utf-8")

        roots = _scan_roots(self.target)

        self.assertEqual(
            roots, ["pyproject.toml", "README.md", "requirements.in", "vendor"]
        )

    def test_copy_helper_handles_file_directory_and_absent_symlinks(self) -> None:
        source = self.target / "source"
        source.mkdir()
        (source / "nested").mkdir()
        (source / "nested" / "file.txt").write_text("fixture", encoding="utf-8")
        destination = self.target / "destination"

        _copy_without_symlinks(source, destination)
        _copy_without_symlinks(source / "nested" / "file.txt", self.target / "one.txt")

        self.assertEqual(
            (destination / "nested" / "file.txt").read_text(encoding="utf-8"),
            "fixture",
        )
        self.assertEqual(
            (self.target / "one.txt").read_text(encoding="utf-8"), "fixture"
        )

    def test_license_helpers_cover_modern_legacy_and_invalid_shapes(self) -> None:
        result = {
            "license_detections": [
                {
                    "license_expression": "mit",
                    "matches": [{"start_line": 1}, "ignored"],
                },
                {"license_expression": "apache-2.0", "matches": "invalid"},
                "ignored",
            ],
            "licenses": [{"key": "unknown"}, "ignored"],
        }
        values = _license_results(result)
        self.assertEqual(len(values), 3)
        self.assertEqual(values[0]["license_expression"], "mit")
        self.assertEqual(_integer("4"), 4)
        self.assertIsNone(_integer("bad"))
        with self.assertRaisesRegex(TypeError, "must be an object"):
            _document("[]")

    def test_staging_prefix_is_removed_before_normalization(self) -> None:
        payload = json.dumps(
            {"files": [{"path": "inputs\\vendor\\library.c", "licenses": []}]}
        )
        document = json.loads(_remove_staging_prefix(payload, "inputs"))
        self.assertEqual(document["files"][0]["path"], "vendor/library.c")

    def test_run_stages_only_selected_inputs_and_completes(self) -> None:
        (self.target / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        adapter = ScanCodeAdapter(ToolConfig(executable="scancode"), 4096)
        payload = json.dumps(
            {
                "files": [
                    {
                        "path": "inputs/pyproject.toml",
                        "license_detections": [
                            {
                                "license_expression": "unknown-license-reference",
                                "matches": [{"start_line": 1}],
                            }
                        ],
                    }
                ]
            }
        )

        def executions(command: list[str], **_kwargs: object) -> RawExecution:
            if "--version" in command:
                return _execution(command, stdout="ScanCode 32.5\n")
            return _execution(command, stdout=payload)

        with (
            patch.object(
                adapter, "_prepare_executable", return_value=("scancode", None)
            ),
            patch.object(adapter, "_executable_changed_error", return_value=None),
            patch(
                "py_security_suite.adapters.scancode.run_command",
                side_effect=executions,
            ),
        ):
            result = adapter.run(self.target)

        self.assertEqual(result.tool_run.status, ToolStatus.COMPLETED)
        self.assertEqual(result.tool_run.version, "ScanCode 32.5")
        self.assertEqual(result.findings[0].locations[0].path, "pyproject.toml")
        self.assertEqual(result.diagnostic["staged_inputs"], ["pyproject.toml"])

    def test_run_skips_when_no_governance_inputs_exist(self) -> None:
        result = ScanCodeAdapter(ToolConfig(executable="scancode"), 4096).run(
            self.target
        )
        self.assertEqual(result.tool_run.status, ToolStatus.SKIPPED)
        self.assertFalse(result.tool_run.applicable)


if __name__ == "__main__":
    unittest.main()
