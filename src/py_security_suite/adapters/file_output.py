from __future__ import annotations

import json
import tempfile
from abc import abstractmethod
from pathlib import Path
from typing import Any

from ..execution import run_command
from ..models import ToolStatus
from .base import AdapterResult, ScannerAdapter


class JsonFileScannerAdapter(ScannerAdapter):
    """Scanner adapter for CLIs that can only emit JSON to a file."""

    output_filename = "results.json"

    def build_command(self, executable: str, target: Path) -> list[str]:
        raise NotImplementedError("this adapter requires a temporary output path")

    @abstractmethod
    def build_file_command(
        self, executable: str, target: Path, output: Path
    ) -> list[str]:
        raise NotImplementedError

    def run(self, target: Path) -> AdapterResult:
        reason = self.not_applicable_reason(  # pylint: disable=assignment-from-none
            target
        )
        if reason:
            return self._not_applicable(reason)
        prerequisite = self.prerequisite_error()  # pylint: disable=assignment-from-none
        executable, integrity_error = self._prepare_executable()
        if prerequisite or integrity_error or executable is None:
            return self._unavailable(
                prerequisite
                or integrity_error
                or f"executable not found: {self.config.executable}"
            )

        version = self._detect_version(executable, target)
        with tempfile.TemporaryDirectory(
            prefix=f"pysec-{self.name}-", ignore_cleanup_errors=True
        ) as temporary:
            output = Path(temporary) / self.output_filename
            command = self.build_file_command(executable, target, output)
            execution = run_command(
                command,
                cwd=target,
                timeout_seconds=self.config.timeout_seconds,
                max_output_bytes=self.max_output_bytes,
                environment=self.environment(),
            )
            changed_error = self._executable_changed_error()
            if changed_error:
                return self._failed(
                    execution, ToolStatus.FAILED, changed_error, version
                )
            if execution.timed_out:
                return self._failed(
                    execution,
                    ToolStatus.TIMED_OUT,
                    f"timed out after {self.config.timeout_seconds} seconds",
                    version,
                )
            if execution.exit_code not in self.accepted_exit_codes:
                return self._failed(
                    execution,
                    ToolStatus.FAILED,
                    f"unexpected exit code {execution.exit_code}",
                    version,
                )
            try:
                if not output.is_file() or output.is_symlink():
                    raise ValueError("scanner did not create its JSON output file")
                if output.stat().st_size > self.max_output_bytes:
                    raise ValueError(
                        "scanner JSON output exceeded the configured limit"
                    )
                payload = output.read_text(encoding="utf-8")
                findings = self.parse(payload, target)
                artifacts = self.derived_artifacts(payload, target)
            except (
                OSError,
                KeyError,
                TypeError,
                ValueError,
                json.JSONDecodeError,
            ) as exc:
                tool_run = self._tool_run(
                    execution,
                    ToolStatus.PARSE_ERROR,
                    error=f"could not parse {self.name} output: {exc}",
                    version=version,
                )
                return AdapterResult(
                    [], tool_run, self._diagnostic(tool_run, execution)
                )

        for finding in findings:
            for source in finding.sources:
                if source.tool == self.name and source.version == "unknown":
                    source.version = version
        tool_run = self._tool_run(
            execution,
            ToolStatus.COMPLETED,
            finding_count=len(findings),
            version=version,
        )
        return AdapterResult(
            findings,
            tool_run,
            self._diagnostic(tool_run, execution),
            artifacts,
        )

    def _not_applicable(self, reason: str) -> AdapterResult:
        from ..models import ToolRun  # local import avoids a broad public surface

        run = ToolRun(
            tool=self.name,
            status=ToolStatus.SKIPPED,
            command=[self.config.executable],
            duration_seconds=0.0,
            error=reason,
            applicable=False,
        )
        return AdapterResult([], run, self._diagnostic(run, None))

    def _unavailable(self, reason: str) -> AdapterResult:
        from ..models import ToolRun

        run = ToolRun(
            tool=self.name,
            status=ToolStatus.UNAVAILABLE,
            command=[self.config.executable],
            duration_seconds=0.0,
            error=reason,
        )
        return AdapterResult([], run, self._diagnostic(run, None))

    def _failed(
        self, execution: Any, status: ToolStatus, error: str, version: str
    ) -> AdapterResult:
        run = self._tool_run(execution, status, error=error, version=version)
        return AdapterResult([], run, self._diagnostic(run, execution))
