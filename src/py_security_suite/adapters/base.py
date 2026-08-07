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
    sha256_file,
)
from ..models import Finding, ToolRun, ToolStatus


@dataclass(slots=True)
class AdapterResult:
    findings: list[Finding]
    tool_run: ToolRun
    diagnostic: dict[str, Any]
    artifacts: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class ScannerReadiness:
    """A bounded, non-executing scanner readiness assessment."""

    tool: str
    status: str
    reason: str | None = None
    executable: str | None = None
    executable_sha256: str | None = None
    executable_integrity_verified: bool | None = None


class ScannerAdapter(ABC):
    name: str
    accepted_exit_codes: frozenset[int] = frozenset({0})

    def __init__(self, config: ToolConfig, max_output_bytes: int) -> None:
        self.config = config
        self.max_output_bytes = max_output_bytes
        self._executable_path: Path | None = None
        self._executable_sha256: str | None = None
        self._executable_integrity_verified: bool | None = None
        self._executable_unchanged: bool | None = None

    def prerequisite_error(self) -> str | None:
        return None

    def not_applicable_reason(self, target: Path) -> str | None:
        return None

    def environment(self) -> CommandEnvironment:
        return CommandEnvironment()

    def version_command(self, executable: str) -> list[str]:
        return [executable, "--version"]

    @abstractmethod
    def build_command(self, executable: str, target: Path) -> list[str]:
        raise NotImplementedError

    @abstractmethod
    def parse(self, payload: str, target: Path) -> list[Finding]:
        raise NotImplementedError

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        return {}

    def result_payload(self, execution: RawExecution) -> str:
        """Return the scanner stream that contains its machine-readable result."""
        return execution.stdout

    def run(self, target: Path) -> AdapterResult:
        readiness = self.preflight(target)
        if readiness.status == "not_applicable":
            tool_run = ToolRun(
                tool=self.name,
                status=ToolStatus.SKIPPED,
                command=[self.config.executable],
                duration_seconds=0.0,
                error=readiness.reason,
                applicable=False,
            )
            return AdapterResult(
                findings=[],
                tool_run=tool_run,
                diagnostic=self._diagnostic(tool_run, None),
            )
        executable = readiness.executable
        if readiness.status != "ready" or executable is None:
            error = (
                readiness.reason or f"executable not found: {self.config.executable}"
            )
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
        changed_error = self._executable_changed_error()
        if changed_error:
            tool_run = self._tool_run(
                execution,
                ToolStatus.FAILED,
                error=changed_error,
                version=version,
            )
            return AdapterResult(
                findings=[],
                tool_run=tool_run,
                diagnostic=self._diagnostic(tool_run, execution),
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
            payload = self.result_payload(execution)
            findings = self.parse(payload, target)
            artifacts = self.derived_artifacts(payload, target)
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

    def preflight(self, target: Path) -> ScannerReadiness:
        """Validate applicability, offline assets, and executable integrity.

        The scanner is never executed and its version command is not invoked.
        """
        not_applicable = self.not_applicable_reason(  # pylint: disable=assignment-from-none
            target
        )
        if not_applicable:
            return ScannerReadiness(
                tool=self.name,
                status="not_applicable",
                reason=not_applicable,
            )
        prerequisite = self.prerequisite_error()  # pylint: disable=assignment-from-none
        if prerequisite:
            return ScannerReadiness(
                tool=self.name,
                status="unavailable",
                reason=prerequisite,
            )
        executable, integrity_error = self._prepare_executable()
        if integrity_error or executable is None:
            return ScannerReadiness(
                tool=self.name,
                status="unavailable",
                reason=(
                    integrity_error or f"executable not found: {self.config.executable}"
                ),
                executable_sha256=self._executable_sha256,
                executable_integrity_verified=self._executable_integrity_verified,
            )
        return ScannerReadiness(
            tool=self.name,
            status="ready",
            executable=executable,
            executable_sha256=self._executable_sha256,
            executable_integrity_verified=self._executable_integrity_verified,
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
            **self._integrity_fields(),
        )

    def _prepare_executable(self) -> tuple[str | None, str | None]:
        executable = resolve_executable(self.config.executable)
        if executable is None:
            return None, f"executable not found: {self.config.executable}"
        path = Path(executable).resolve()
        try:
            digest = sha256_file(path)
        except OSError:
            return None, "scanner executable could not be hashed"
        self._executable_path = path
        self._executable_sha256 = digest
        expected = self.config.executable_sha256
        self._executable_integrity_verified = digest == expected if expected else None
        self._executable_unchanged = None
        if expected and digest != expected:
            return (
                None,
                "scanner executable SHA-256 does not match the approved digest",
            )
        return str(path), None

    def _executable_changed_error(self) -> str | None:
        path = self._executable_path
        initial = self._executable_sha256
        if path is None or initial is None:
            return None
        try:
            current = sha256_file(path)
        except OSError:
            self._executable_unchanged = False
            return "scanner executable became unreadable during execution"
        self._executable_unchanged = current == initial
        if not self._executable_unchanged:
            return "scanner executable changed during execution"
        return None

    def _integrity_fields(self) -> dict[str, Any]:
        return {
            "executable_sha256": self._executable_sha256,
            "executable_integrity_verified": (self._executable_integrity_verified),
            "executable_unchanged": self._executable_unchanged,
        }

    def _detect_version(self, executable: str, target: Path) -> str:
        execution = run_command(
            self.version_command(executable),
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

    def _diagnostic(
        self, tool_run: ToolRun, execution: RawExecution | None
    ) -> dict[str, Any]:
        if tool_run.executable_sha256 is None:
            tool_run.executable_sha256 = self._executable_sha256
            tool_run.executable_integrity_verified = self._executable_integrity_verified
            tool_run.executable_unchanged = self._executable_unchanged
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
                hashlib.sha256(stderr.encode("utf-8")).hexdigest() if stderr else None
            ),
            "raw_output_retained": False,
            "applicable": tool_run.applicable,
            "executable_sha256": tool_run.executable_sha256,
            "executable_integrity_verified": (tool_run.executable_integrity_verified),
            "executable_unchanged": tool_run.executable_unchanged,
        }
