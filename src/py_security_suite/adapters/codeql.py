from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from pathlib import Path

from ..execution import (
    CommandEnvironment,
    RawExecution,
    resolve_executable,
    run_command,
    sanitize_diagnostic,
)
from ..models import Finding, ToolRun, ToolStatus
from .base import AdapterResult, ScannerAdapter
from .sarif import parse_sarif_findings


_MIRROR_SKIP_DIRECTORIES = {
    ".artifacts",
    ".codeql",
    ".git",
    ".hg",
    ".pysec-tools",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
}


class CodeQlAdapter(ScannerAdapter):
    """Run CodeQL through the pip-installable run-codeql orchestration wrapper."""

    name = "codeql"

    def not_applicable_reason(self, target: Path) -> str | None:
        if not any(target.rglob("*.py")):
            return "no Python source files were found"
        return None

    def prerequisite_error(self) -> str | None:
        codeql = self.config.auxiliary_executable or "codeql"
        if resolve_executable(codeql) is None:
            return (
                "a pre-staged CodeQL CLI is required on the configured path; "
                "run-codeql auto-download is prohibited"
            )
        home = self.config.database_path
        if home is None:
            return (
                "an isolated run-codeql home containing approved CodeQL query "
                "packs is required in database_path"
            )
        resolved_home = home.expanduser().resolve()
        pack = resolved_home / ".codeql" / "packages" / "codeql" / "python-queries"
        if not pack.is_dir():
            return f"approved CodeQL Python query pack is missing: {pack}"
        return None

    def environment(self) -> CommandEnvironment:
        home = self.config.database_path
        codeql = resolve_executable(self.config.auxiliary_executable or "codeql")
        extra: dict[str, str] = {
            "RCQL_DOWNLOAD_RETRY_ATTEMPTS": "1",
            "RCQL_DOWNLOAD_TIMEOUT_SECONDS": "1",
        }
        if home is not None:
            resolved = str(home.expanduser().resolve())
            extra["HOME"] = resolved
            extra["USERPROFILE"] = resolved
        if codeql is not None:
            existing = os.environ.get("PATH", "")
            extra["PATH"] = os.pathsep.join((str(Path(codeql).parent), existing))
        return CommandEnvironment(extra=extra)

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            executable,
            "--lang",
            "python",
            "--config",
            "",
            "--quiet",
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        return parse_sarif_findings(
            payload,
            target,
            tool_name=self.name,
            default_area="data-flow",
            default_impact=(
                "CodeQL identified a semantic or data-flow path that can expose "
                "the application to a security weakness."
            ),
            default_remediation=(
                "Review the CodeQL path and query guidance, enforce the trust "
                "boundary, and replace the dangerous operation or sanitize its input."
            ),
        )

    def _detect_version(self, executable: str, target: Path) -> str:
        codeql = resolve_executable(self.config.auxiliary_executable or "codeql")
        if codeql is None:
            return "run-codeql; CodeQL unknown"
        execution = run_command(
            [codeql, "version"],
            cwd=target,
            timeout_seconds=min(self.config.timeout_seconds, 10),
            max_output_bytes=2048,
            environment=self.environment(),
        )
        if execution.exit_code != 0 or execution.timed_out:
            return "run-codeql; CodeQL unknown"
        value = execution.stdout.strip() or execution.stderr.strip()
        first_line = value.splitlines()[0] if value else "unknown"
        return f"run-codeql; {sanitize_diagnostic(first_line, maximum=160)}"

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
            return AdapterResult([], tool_run, self._diagnostic(tool_run, None))
        prerequisite = self.prerequisite_error()
        executable = resolve_executable(self.config.executable)
        if prerequisite or executable is None:
            tool_run = ToolRun(
                tool=self.name,
                status=ToolStatus.UNAVAILABLE,
                command=[self.config.executable],
                duration_seconds=0.0,
                error=prerequisite or f"executable not found: {self.config.executable}",
            )
            return AdapterResult([], tool_run, self._diagnostic(tool_run, None))

        version = self._detect_version(executable, target)
        started = time.monotonic()
        with tempfile.TemporaryDirectory(
            prefix="pysec-run-codeql-", ignore_cleanup_errors=True
        ) as directory:
            mirror = Path(directory) / "target"
            _copy_target(target, mirror)
            command = self.build_command(executable, mirror)
            execution = run_command(
                command,
                cwd=mirror,
                timeout_seconds=self.config.timeout_seconds,
                max_output_bytes=self.max_output_bytes,
                environment=self.environment(),
            )
            if execution.timed_out or execution.exit_code not in {0, 1}:
                return self._failure(execution, version, started)
            sarif_files = sorted((mirror / ".codeql" / "reports").glob("python-*.sarif"))
            if len(sarif_files) != 1:
                tool_run = ToolRun(
                    tool=self.name,
                    status=ToolStatus.PARSE_ERROR,
                    command=command,
                    duration_seconds=round(time.monotonic() - started, 3),
                    version=version,
                    exit_code=execution.exit_code,
                    error=(
                        "run-codeql did not create exactly one Python SARIF report"
                    ),
                )
                return AdapterResult([], tool_run, self._diagnostic(tool_run, execution))
            data = sarif_files[0].read_bytes()
            if len(data) > self.max_output_bytes:
                tool_run = ToolRun(
                    tool=self.name,
                    status=ToolStatus.PARSE_ERROR,
                    command=command,
                    duration_seconds=round(time.monotonic() - started, 3),
                    version=version,
                    exit_code=execution.exit_code,
                    error="CodeQL SARIF exceeded execution.max_output_bytes",
                    stdout_truncated=True,
                )
                return AdapterResult([], tool_run, self._diagnostic(tool_run, execution))
            try:
                findings = self.parse(data.decode("utf-8"), mirror)
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                tool_run = ToolRun(
                    tool=self.name,
                    status=ToolStatus.PARSE_ERROR,
                    command=command,
                    duration_seconds=round(time.monotonic() - started, 3),
                    version=version,
                    exit_code=execution.exit_code,
                    error=f"could not parse CodeQL output: {exc}",
                )
                return AdapterResult([], tool_run, self._diagnostic(tool_run, execution))

        for finding in findings:
            for source in finding.sources:
                source.version = version
        tool_run = ToolRun(
            tool=self.name,
            status=ToolStatus.COMPLETED,
            command=command,
            duration_seconds=round(time.monotonic() - started, 3),
            version=version,
            exit_code=execution.exit_code,
            finding_count=len(findings),
        )
        diagnostic = self._diagnostic(tool_run, execution)
        diagnostic["runner"] = "run-codeql"
        diagnostic["target_mirrored"] = True
        diagnostic["repository_codeql_config_used"] = False
        diagnostic["auto_download_allowed"] = False
        return AdapterResult(findings, tool_run, diagnostic)

    def _failure(
        self, execution: RawExecution, version: str, started: float
    ) -> AdapterResult:
        status = ToolStatus.TIMED_OUT if execution.timed_out else ToolStatus.FAILED
        error = (
            f"run-codeql timed out after {self.config.timeout_seconds} seconds"
            if execution.timed_out
            else f"run-codeql failed with exit code {execution.exit_code}"
        )
        tool_run = ToolRun(
            tool=self.name,
            status=status,
            command=execution.command,
            duration_seconds=round(time.monotonic() - started, 3),
            version=version,
            exit_code=execution.exit_code,
            error=error,
            stdout_truncated=execution.stdout_truncated,
            stderr_truncated=execution.stderr_truncated,
        )
        return AdapterResult([], tool_run, self._diagnostic(tool_run, execution))


def _copy_target(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True)
    for root, directories, filenames in os.walk(source, followlinks=False):
        root_path = Path(root)
        relative_root = root_path.relative_to(source)
        kept: list[str] = []
        for directory in directories:
            path = root_path / directory
            if (
                path.is_symlink()
                or directory in _MIRROR_SKIP_DIRECTORIES
                or (
                    relative_root.as_posix() == ".github"
                    and directory == "codeql"
                )
            ):
                continue
            kept.append(directory)
        directories[:] = kept
        output_root = destination / relative_root
        output_root.mkdir(parents=True, exist_ok=True)
        for filename in filenames:
            source_file = root_path / filename
            if source_file.is_symlink():
                continue
            shutil.copy2(source_file, output_root / filename)
