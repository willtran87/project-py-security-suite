from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import ToolConfig
from ..execution import (
    CommandEnvironment,
    RawExecution,
    resolve_executable,
    run_command,
    sanitize_diagnostic,
)
from ..models import Finding, ToolRun, ToolStatus


@dataclass(slots=True)
class AdapterResult:
    findings: list[Finding]
    tool_run: ToolRun
    diagnostic: dict[str, Any]
    artifacts: dict[str, Any] = field(default_factory=dict)


class ScannerAdapter(ABC):
    name: str
    accepted_exit_codes: frozenset[int] = frozenset({0})

    def __init__(self, config: ToolConfig, max_output_bytes: int) -> None:
        self.config = config
        self.max_output_bytes = max_output_bytes

    def prerequisite_error(self) -> str | None:
        return None

    def not_applicable_reason(self, target: Path) -> str | None:
        return None

    def environment(self) -> CommandEnvironment:
        return CommandEnvironment()

    @abstractmethod
    def build_command(self, executable: str, target: Path) -> list[str]:
        raise NotImplementedError

    @abstractmethod
    def parse(self, payload: str, target: Path) -> list[Finding]:
        raise NotImplementedError

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        return {}

    def run(self, target: Path) -> AdapterResult:
        not_applicable = self.not_applicable_reason(target)
        if not_applicable:
            tool_run = ToolRun(
                tool=self.name,
                status=ToolStatus.SKIPPED,
                command=[self.config.executable],
                duration_seconds=0.0,
                error=not_applicable,
                applicable=False,
            )
            return AdapterResult(
                findings=[],
                tool_run=tool_run,
                diagnostic=self._diagnostic(tool_run, None),
            )
        prerequisite = self.prerequisite_error()
        executable = resolve_executable(self.config.executable)
        if prerequisite or executable is None:
            error = prerequisite or f"executable not found: {self.config.executable}"
            tool_run = ToolRun(
                tool=self.name,
                status=ToolStatus.UNAVAILABLE,
                command=[self.config.executable],
                duration_seconds=0.0,
                error=error,
            )
            return AdapterResult(
                findings=[],
                tool_run=tool_run,
                diagnostic=self._diagnostic(tool_run, None),
            )

        command = self.build_command(executable, target)
        version = self._detect_version(executable, target)
        execution = run_command(
            command,
            cwd=target,
            timeout_seconds=self.config.timeout_seconds,
            max_output_bytes=self.max_output_bytes,
            environment=self.environment(),
        )
        if execution.timed_out:
            tool_run = self._tool_run(
                execution,
                ToolStatus.TIMED_OUT,
                error=f"timed out after {self.config.timeout_seconds} seconds",
                version=version,
            )
            return AdapterResult(
                findings=[],
                tool_run=tool_run,
                diagnostic=self._diagnostic(tool_run, execution),
            )
        if execution.exit_code not in self.accepted_exit_codes:
            tool_run = self._tool_run(
                execution,
                ToolStatus.FAILED,
                error=f"unexpected exit code {execution.exit_code}",
                version=version,
            )
            return AdapterResult(
                findings=[],
                tool_run=tool_run,
                diagnostic=self._diagnostic(tool_run, execution),
            )
        try:
            findings = self.parse(execution.stdout, target)
            artifacts = self.derived_artifacts(execution.stdout, target)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            tool_run = self._tool_run(
                execution,
                ToolStatus.PARSE_ERROR,
                error=f"could not parse {self.name} output: {exc}",
                version=version,
            )
            return AdapterResult(
                findings=[],
                tool_run=tool_run,
                diagnostic=self._diagnostic(tool_run, execution),
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
            findings=findings,
            tool_run=tool_run,
            diagnostic=self._diagnostic(tool_run, execution),
            artifacts=artifacts,
        )

    def _tool_run(
        self,
        execution: RawExecution,
        status: ToolStatus,
        *,
        error: str | None = None,
        finding_count: int = 0,
        version: str = "unknown",
    ) -> ToolRun:
        return ToolRun(
            tool=self.name,
            status=status,
            command=execution.command,
            duration_seconds=round(execution.duration_seconds, 3),
            version=version,
            exit_code=execution.exit_code,
            finding_count=finding_count,
            error=error,
            stdout_truncated=execution.stdout_truncated,
            stderr_truncated=execution.stderr_truncated,
        )

    def _detect_version(self, executable: str, target: Path) -> str:
        execution = run_command(
            [executable, "--version"],
            cwd=target,
            timeout_seconds=min(self.config.timeout_seconds, 10),
            max_output_bytes=2048,
            environment=self.environment(),
        )
        if execution.exit_code != 0 or execution.timed_out:
            return "unknown"
        value = execution.stdout.strip() or execution.stderr.strip()
        first_line = value.splitlines()[0] if value else ""
        return sanitize_diagnostic(first_line, maximum=200) or "unknown"

    @staticmethod
    def _diagnostic(
        tool_run: ToolRun, execution: RawExecution | None
    ) -> dict[str, Any]:
        stderr = execution.stderr if execution else ""
        return {
            "tool": tool_run.tool,
            "status": str(tool_run.status),
            "command": tool_run.command,
            "version": tool_run.version,
            "duration_seconds": tool_run.duration_seconds,
            "exit_code": tool_run.exit_code,
            "finding_count": tool_run.finding_count,
            "error": tool_run.error,
            "stderr_bytes": len(stderr.encode("utf-8")),
            "stderr_sha256": (
                hashlib.sha256(stderr.encode("utf-8")).hexdigest()
                if stderr
                else None
            ),
            "raw_output_retained": False,
            "applicable": tool_run.applicable,
        }
