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
    governed_asset_sha256,
    python_runtime_closure_sha256,
    resolve_executable,
    run_command,
    sanitize_diagnostic,
    sealed_governed_assets,
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
    runtime_closure_sha256: str | None = None
    runtime_closure_integrity_verified: bool | None = None


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
        self._runtime_closure_sha256: str | None = None
        self._runtime_closure_integrity_verified: bool | None = None
        self._runtime_closure_unchanged: bool | None = None
        self._asset_digests: dict[str, str] = {}
        self._asset_unchanged: dict[str, bool] = {}
        self._asset_snapshot_verified: dict[str, bool] = {}

    def prerequisite_error(self) -> str | None:
        return None

    def not_applicable_reason(self, target: Path) -> str | None:
        return None

    def environment(self) -> CommandEnvironment:
        return CommandEnvironment()

    def execution_environment(self) -> CommandEnvironment:
        environment = self.environment()
        environment.extra.update(self.config.trust_environment)
        if self.config.trust_policy_sha256:
            environment.extra["PYSEC_TRUST_POLICY_SHA256"] = (
                self.config.trust_policy_sha256
            )
        if self.config.sandbox_executable:
            environment.sandbox_prefix = (
                self.config.sandbox_executable,
                *self.config.sandbox_arguments,
            )
            environment.sandbox_executable_sha256 = (
                self.config.sandbox_executable_sha256
            )
            environment.sandbox_runtime_closure_sha256 = (
                self.config.sandbox_runtime_closure_sha256
            )
        return environment

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

        assets = {
            label: path
            for label, path in (
                ("rules", self.config.rules_path),
                ("database", self.config.database_path),
            )
            if path is not None
        }
        try:
            with sealed_governed_assets(assets, self._asset_digests) as copies:
                originals = {
                    "rules": self.config.rules_path,
                    "database": self.config.database_path,
                }
                try:
                    if "rules" in copies:
                        self.config.rules_path = copies["rules"]
                    if "database" in copies:
                        self.config.database_path = copies["database"]
                    self._asset_snapshot_verified = dict.fromkeys(copies, True)
                    return self._run_ready(target, executable)
                finally:
                    self.config.rules_path = originals["rules"]
                    self.config.database_path = originals["database"]
        except (OSError, TypeError, ValueError) as exc:
            tool_run = ToolRun(
                tool=self.name,
                status=ToolStatus.UNAVAILABLE,
                command=[executable],
                duration_seconds=0.0,
                error=f"scanner assets could not be sealed: {exc}",
            )
            return AdapterResult(
                findings=[],
                tool_run=tool_run,
                diagnostic=self._diagnostic(tool_run, None),
            )

    def _run_ready(self, target: Path, executable: str) -> AdapterResult:
        command = self.build_command(executable, target)
        version = self._detect_version(executable, target)
        execution = run_command(
            command,
            cwd=target,
            timeout_seconds=self.config.timeout_seconds,
            max_output_bytes=self.max_output_bytes,
            environment=self.execution_environment(),
        )
        changed_error = self._executable_changed_error() or self._asset_changed_error()
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
        if execution.output_limit_exceeded:
            tool_run = self._tool_run(
                execution,
                ToolStatus.FAILED,
                error=(
                    "scanner output exceeded the configured byte limit and its "
                    "process tree was terminated"
                ),
                version=version,
            )
            return AdapterResult(
                findings=[],
                tool_run=tool_run,
                diagnostic=self._diagnostic(tool_run, execution),
            )
        if execution.scratch_limit_exceeded:
            tool_run = self._tool_run(
                execution,
                ToolStatus.FAILED,
                error=(
                    "scanner private scratch space exceeded the configured byte "
                    "limit and its process tree was terminated"
                ),
                version=version,
            )
            return AdapterResult(
                findings=[],
                tool_run=tool_run,
                diagnostic=self._diagnostic(tool_run, execution),
            )
        if execution.resident_memory_limit_exceeded:
            tool_run = self._tool_run(
                execution,
                ToolStatus.FAILED,
                error=(
                    "scanner process-tree resident memory exceeded the enforced "
                    "limit and its process tree was terminated"
                ),
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
        asset_error = self._prepare_assets()
        if asset_error:
            return ScannerReadiness(
                tool=self.name,
                status="unavailable",
                reason=asset_error,
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
                runtime_closure_sha256=self._runtime_closure_sha256,
                runtime_closure_integrity_verified=(
                    self._runtime_closure_integrity_verified
                ),
            )
        return ScannerReadiness(
            tool=self.name,
            status="ready",
            executable=executable,
            executable_sha256=self._executable_sha256,
            executable_integrity_verified=self._executable_integrity_verified,
            runtime_closure_sha256=self._runtime_closure_sha256,
            runtime_closure_integrity_verified=(
                self._runtime_closure_integrity_verified
            ),
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
        expected_runtime = self.config.runtime_closure_sha256
        if expected_runtime or self.config.require_runtime_closure:
            try:
                runtime_digest = python_runtime_closure_sha256(
                    executable,
                    include_environment=(
                        self.config.runtime_closure_scope == "environment"
                    ),
                    require_native_plugin_manifest=(
                        self.config.require_runtime_closure
                    ),
                )
            except (OSError, TypeError, ValueError) as exc:
                return (
                    None,
                    f"scanner runtime closure could not be hashed: {exc}",
                )
            if runtime_digest is None and expected_runtime:
                return (
                    None,
                    "scanner executable runtime closure could not be identified",
                )
            if runtime_digest is None:
                return str(path), None
            self._runtime_closure_sha256 = runtime_digest
            if self.config.require_runtime_closure and not expected_runtime:
                return (
                    None,
                    "production scanner requires an approved runtime_closure_sha256",
                )
            self._runtime_closure_integrity_verified = (
                runtime_digest == expected_runtime
            )
            if runtime_digest != expected_runtime:
                return (
                    None,
                    "scanner runtime closure does not match the approved digest",
                )
        return str(path), None

    def _prepare_assets(self) -> str | None:
        self._asset_digests = {}
        self._asset_unchanged = {}
        self._asset_snapshot_verified = {}
        for label, path, expected in (
            ("rules", self.config.rules_path, self.config.rules_sha256),
            ("database", self.config.database_path, self.config.database_sha256),
        ):
            if path is None:
                continue
            if self.config.require_asset_digests and not expected:
                return f"production scanner requires an approved {label}_sha256"
            if (
                self.config.require_asset_digests
                and not self.config.asset_digests_organization_approved
            ):
                return "production scanner asset digests lack organization approval"
            try:
                observed = governed_asset_sha256(path)
            except (OSError, TypeError, ValueError) as exc:
                return f"scanner {label} asset could not be hashed: {exc}"
            self._asset_digests[label] = observed
            if expected and observed != expected:
                return (
                    f"scanner {label} asset SHA-256 does not match the approved digest"
                )
        return None

    def _asset_changed_error(self) -> str | None:
        for label, initial in self._asset_digests.items():
            path = getattr(self.config, f"{label}_path")
            if path is None:
                continue
            try:
                current = governed_asset_sha256(path)
            except (OSError, TypeError, ValueError):
                self._asset_unchanged[label] = False
                return f"scanner {label} asset became unreadable during execution"
            self._asset_unchanged[label] = current == initial
            if current != initial:
                return f"scanner {label} asset changed during execution"
        return None

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
        if self._runtime_closure_sha256 is not None:
            if self.config.runtime_closure_scope == "environment":
                # The orchestrator performs one scan-wide post-run rehash so
                # dozens of Python entry points do not each hash the identical
                # interpreter environment independently.
                self._runtime_closure_unchanged = None
                return None
            try:
                current_runtime = python_runtime_closure_sha256(
                    str(path),
                    include_environment=(
                        self.config.runtime_closure_scope == "environment"
                    ),
                    require_native_plugin_manifest=(
                        self.config.require_runtime_closure
                    ),
                )
            except (OSError, TypeError, ValueError):
                self._runtime_closure_unchanged = False
                return "scanner runtime closure became unreadable during execution"
            self._runtime_closure_unchanged = (
                current_runtime == self._runtime_closure_sha256
            )
            if not self._runtime_closure_unchanged:
                return "scanner runtime closure changed during execution"
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
            environment=self.execution_environment(),
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
            "runtime_closure_sha256": self._runtime_closure_sha256,
            "runtime_closure_integrity_verified": (
                self._runtime_closure_integrity_verified
            ),
            "runtime_closure_unchanged": self._runtime_closure_unchanged,
            "asset_digests": dict(sorted(self._asset_digests.items())),
            "asset_unchanged": dict(sorted(self._asset_unchanged.items())),
            "asset_snapshot_verified": dict(
                sorted(self._asset_snapshot_verified.items())
            ),
            "resource_limits_enforced": (
                list(execution.resource_limits_enforced) if execution else []
            ),
            "resource_limit_errors": (
                list(execution.resource_limit_errors) if execution else []
            ),
            "resident_memory_limit_exceeded": (
                execution.resident_memory_limit_exceeded if execution else False
            ),
        }
