from __future__ import annotations

import os
import math
import tempfile
import time
from dataclasses import asdict
from pathlib import Path
from collections.abc import Callable

from ..config import ToolConfig
from ..execution import (
    CommandEnvironment,
    RawExecution,
    resolve_executable,
    run_command,
    sanitize_diagnostic,
    sha256_file,
    sealed_governed_assets,
)
from ..path_safety import read_regular_file
from ..scan_control import stop_reason, ScanInterrupted
from ..models import Finding, ToolRun, ToolStatus
from .base import AdapterResult, ScannerAdapter
from .sarif import parse_sarif_findings
from .staging import maintained_files
from .coverage import reconcile_codeql_coverage
from .constant_sinks import annotate_constant_sinks
from .codeql_refinement import refine_native_results
from .codeql_queries import (
    locked_pack_paths,
    run_with_cache,
    supplemental_queries,
)

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

    def __init__(self, config: ToolConfig, max_output_bytes: int) -> None:
        super().__init__(config, max_output_bytes)
        self._retained_findings: list[Finding] = []
        self._deadline: float | None = None
        self._auxiliary_path: Path | None = None
        self._auxiliary_sha256: str | None = None
        self._auxiliary_integrity_verified: bool | None = None
        self._auxiliary_unchanged: bool | None = None

    def not_applicable_reason(self, target: Path) -> str | None:
        if not maintained_files(target, frozenset({".py"})):
            return "no Python source files were found"
        return None

    def prerequisite_error(self) -> str | None:
        codeql = self.config.auxiliary_executable or "codeql"
        resolved_codeql = resolve_executable(codeql)
        if resolved_codeql is None:
            return (
                "a pre-staged CodeQL CLI is required on the configured path; "
                "run-codeql auto-download is prohibited"
            )
        self._auxiliary_path = Path(resolved_codeql).resolve()
        try:
            self._auxiliary_sha256 = sha256_file(self._auxiliary_path)
        except OSError:
            return "the pre-staged CodeQL CLI could not be hashed"
        expected = self.config.auxiliary_executable_sha256
        self._auxiliary_integrity_verified = (
            self._auxiliary_sha256 == expected if expected else None
        )
        if expected and not self._auxiliary_integrity_verified:
            return "CodeQL CLI SHA-256 does not match the approved digest"
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
        if self.config.rules_path is not None:
            try:
                locked_pack_paths(self.config.rules_path, resolved_home)
            except (OSError, TypeError, ValueError):
                return "supplemental CodeQL query libraries are missing; stage the bundled query lock into database_path"
        return None

    def environment(self) -> CommandEnvironment:
        # Helpers enter PATH only through the supervisor's digest-checked API.
        helpers = (
            ((str(self._auxiliary_path), self._auxiliary_sha256),)
            if self._auxiliary_path is not None and self._auxiliary_sha256 is not None
            else ()
        )
        return CommandEnvironment(
            auxiliary_executables=helpers,
            extra={
                "RCQL_DOWNLOAD_RETRY_ATTEMPTS": "1",
                "RCQL_DOWNLOAD_TIMEOUT_SECONDS": "1",
            },
        )

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            executable,
            "--lang",
            "python",
            "--config=",
            "--quiet",
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        return parse_sarif_findings(
            payload,
            target,
            tool_name=self.name,
            generated_source_root=target,
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
        codeql = (
            str(self._auxiliary_path)
            if self._auxiliary_path is not None
            else resolve_executable(self.config.auxiliary_executable or "codeql")
        )
        if codeql is None:
            return "run-codeql; CodeQL unknown"
        execution = run_command(
            [codeql, "version"],
            cwd=target,
            timeout_seconds=min(self._remaining_seconds(), 10),
            max_output_bytes=2048,
            environment=self.environment(),
        )
        if execution.exit_code != 0 or execution.timed_out:
            return "run-codeql; CodeQL unknown"
        value = execution.stdout.strip() or execution.stderr.strip()
        first_line = value.splitlines()[0] if value else "unknown"
        return f"run-codeql; {sanitize_diagnostic(first_line, maximum=160)}"

    def _asset_check(self) -> None:
        self._remaining_seconds()

    def _remaining_seconds(self) -> int:
        if stop_reason():
            raise ScanInterrupted(stop_reason())
        remaining = (
            (self._deadline - time.monotonic())
            if self._deadline is not None
            else self.config.timeout_seconds
        )
        if remaining <= 0:
            raise TimeoutError("CodeQL scan deadline exhausted")
        return max(1, math.ceil(remaining))

    def run(self, target: Path) -> AdapterResult:
        started = time.monotonic()
        self._retained_findings = []
        self._deadline = started + self.config.timeout_seconds
        try:
            return self._run(target, started)
        except TimeoutError:
            run = ToolRun(
                tool=self.name,
                status=ToolStatus.TIMED_OUT,
                command=[self.config.executable],
                duration_seconds=round(time.monotonic() - started, 3),
                error="CodeQL scan deadline exhausted during preparation or execution",
                finding_count=len(self._retained_findings),
            )
            return AdapterResult(
                self._retained_findings,
                run,
                {**self._diagnostic(run, None), "failure_category": "wall-clock"},
            )
        finally:
            self._deadline = None
            self._retained_findings = []

    def _run(self, target: Path, started: float) -> AdapterResult:
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
        prerequisite = self.prerequisite_error() or self._prepare_assets()
        executable, integrity_error = self._prepare_executable()
        if prerequisite or integrity_error or executable is None:
            tool_run = ToolRun(
                tool=self.name,
                status=ToolStatus.UNAVAILABLE,
                command=[self.config.executable],
                duration_seconds=0.0,
                error=(
                    prerequisite
                    or integrity_error
                    or f"executable not found: {self.config.executable}"
                ),
            )
            return AdapterResult([], tool_run, self._diagnostic(tool_run, None))

        self._remaining_seconds()
        version = self._detect_version(executable, target)
        expected_files = tuple(
            path.relative_to(target).as_posix()
            for path in maintained_files(target, frozenset({".py"}))
        )
        supplemental_error = None
        native_refinement: dict[str, object] = {}
        assets = {
            label: path
            for label, path in (
                ("database", self.config.database_path),
                ("rules", self.config.rules_path),
            )
            if path is not None
        }
        with (
            tempfile.TemporaryDirectory(
                prefix="pysec-run-codeql-", ignore_cleanup_errors=True
            ) as directory,
            sealed_governed_assets(
                assets, self._asset_digests, check=self._remaining_seconds
            ) as copies,
        ):
            self._asset_snapshot_verified = dict.fromkeys(copies, True)
            mirror = Path(directory) / "target"
            _copy_target(target, mirror, check=self._remaining_seconds)
            command = self.build_command(executable, mirror)
            if self.config.database_path is not None:
                execution = run_with_cache(
                    command,
                    home=copies["database"],
                    target=mirror,
                    timeout_seconds=self._remaining_seconds(),
                    max_output_bytes=self.max_output_bytes,
                    environment=self.environment(),
                )
            else:
                execution = run_command(
                    command,
                    cwd=mirror,
                    timeout_seconds=self._remaining_seconds(),
                    max_output_bytes=self.max_output_bytes,
                    environment=self.environment(),
                )
            changed_error = self._executable_changed_error()
            auxiliary_changed_error = self._auxiliary_changed_error()
            if changed_error or auxiliary_changed_error:
                tool_run = ToolRun(
                    tool=self.name,
                    status=ToolStatus.FAILED,
                    command=command,
                    duration_seconds=round(time.monotonic() - started, 3),
                    version=version,
                    exit_code=execution.exit_code,
                    error=changed_error or auxiliary_changed_error,
                )
                return AdapterResult(
                    [], tool_run, self._diagnostic(tool_run, execution)
                )
            if (
                execution.timed_out
                or execution.stop_reason
                or execution.output_limit_exceeded
                or execution.scratch_limit_exceeded
                or execution.resident_memory_limit_exceeded
                or execution.exit_code not in {0, 1}
            ):
                return self._failure(execution, version, started)
            sarif_files = sorted(
                (mirror / ".codeql" / "reports").glob("python-*.sarif")
            )
            if len(sarif_files) != 1:
                tool_run = ToolRun(
                    tool=self.name,
                    status=ToolStatus.PARSE_ERROR,
                    command=command,
                    duration_seconds=round(time.monotonic() - started, 3),
                    version=version,
                    exit_code=execution.exit_code,
                    error=("run-codeql did not create exactly one Python SARIF report"),
                )
                return AdapterResult(
                    [], tool_run, self._diagnostic(tool_run, execution)
                )
            try:
                _, data = read_regular_file(
                    sarif_files[0],
                    "CodeQL SARIF",
                    maximum_bytes=self.max_output_bytes,
                    boundary=mirror,
                )
                self._remaining_seconds()
                findings = self.parse(data.decode("utf-8"), mirror)
                self._retained_findings = findings
                coverage = reconcile_codeql_coverage(
                    data.decode("utf-8"), mirror, expected_files
                )
            except (KeyError, OSError, TypeError, ValueError) as exc:
                if isinstance(exc, TimeoutError):
                    raise
                tool_run = ToolRun(
                    tool=self.name,
                    status=ToolStatus.PARSE_ERROR,
                    command=command,
                    duration_seconds=round(time.monotonic() - started, 3),
                    version=version,
                    exit_code=execution.exit_code,
                    error=f"could not parse CodeQL output: {exc}",
                )
                return AdapterResult(
                    [], tool_run, self._diagnostic(tool_run, execution)
                )

            if self.config.rules_path is not None:
                try:
                    extra = supplemental_queries(
                        cli=str(self._auxiliary_path),
                        target=mirror,
                        home=copies.get("database", mirror),
                        rules=copies["rules"],
                        already_sealed=True,
                        rules_digest=self._asset_digests["rules"],
                        environment=self.environment(),
                        timeout_seconds=self._remaining_seconds(),
                        max_output_bytes=self.max_output_bytes,
                    )
                    supplemental_error = (
                        self._asset_changed_error() or self._auxiliary_changed_error()
                    )
                    refined, extra, native_refinement = refine_native_results(
                        data.decode("utf-8"),
                        extra,
                        eligible=not supplemental_error
                        and coverage["state"] == "complete",
                        normalize=lambda payload: [
                            asdict(finding) for finding in self.parse(payload, mirror)
                        ],
                    )
                    # Commit only after both documents parse. On any failure the
                    # original native findings remain available to the caller.
                    refined_findings = self.parse(refined, mirror) + self.parse(
                        extra, mirror
                    )
                    findings = refined_findings
                except TimeoutError:
                    raise
                except (OSError, TypeError, ValueError):
                    supplemental_error = "supplemental CodeQL analysis incomplete; primary findings retained"

            findings, constant_reviews = annotate_constant_sinks(
                findings, mirror, check=self._remaining_seconds
            )

        for finding in findings:
            for source in finding.sources:
                source.version = version
        tool_run = ToolRun(
            tool=self.name,
            status=ToolStatus.FAILED
            if supplemental_error
            else ToolStatus.COMPLETED
            if coverage["state"] == "complete"
            else ToolStatus.PARSE_ERROR,
            command=command,
            duration_seconds=round(time.monotonic() - started, 3),
            version=version,
            exit_code=execution.exit_code,
            finding_count=len(findings),
            error=supplemental_error
            or (
                "CodeQL extraction coverage is incomplete or unknown; findings retained"
                if coverage["state"] != "complete"
                else None
            ),
        )
        diagnostic = self._diagnostic(tool_run, execution)
        diagnostic["runner"] = "run-codeql"
        diagnostic["analysis_coverage"] = coverage
        diagnostic["constant_sink_reviews"] = constant_reviews
        diagnostic["native_flow_refinement"] = native_refinement
        diagnostic["target_mirrored"] = True
        diagnostic["repository_codeql_config_used"] = False
        diagnostic["auto_download_allowed"] = False
        return AdapterResult(findings, tool_run, diagnostic)

    def _auxiliary_changed_error(self) -> str | None:
        path = self._auxiliary_path
        initial = self._auxiliary_sha256
        if path is None or initial is None:
            return None
        try:
            current = sha256_file(path)
        except OSError:
            self._auxiliary_unchanged = False
            return "CodeQL CLI became unreadable during execution"
        self._auxiliary_unchanged = current == initial
        if not self._auxiliary_unchanged:
            return "CodeQL CLI changed during execution"
        return None

    def _diagnostic(
        self, tool_run: ToolRun, execution: RawExecution | None
    ) -> dict[str, object]:
        tool_run.auxiliary_executable_sha256 = self._auxiliary_sha256
        tool_run.auxiliary_executable_integrity_verified = (
            self._auxiliary_integrity_verified
        )
        tool_run.auxiliary_executable_unchanged = self._auxiliary_unchanged
        diagnostic = super()._diagnostic(tool_run, execution)
        diagnostic["auxiliary_executable_sha256"] = self._auxiliary_sha256
        diagnostic["auxiliary_executable_integrity_verified"] = (
            self._auxiliary_integrity_verified
        )
        diagnostic["auxiliary_executable_unchanged"] = self._auxiliary_unchanged
        return diagnostic

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
        reason = (
            "wall-clock"
            if execution.timed_out
            else "memory"
            if execution.resident_memory_limit_exceeded
            else "output"
            if execution.output_limit_exceeded
            else "scratch"
            if execution.scratch_limit_exceeded
            else "native-quota"
            if execution.exit_code == 0xC0000044
            else "process-exit"
        )
        return AdapterResult(
            [],
            tool_run,
            {**self._diagnostic(tool_run, execution), "failure_category": reason},
        )


def _copy_target(
    source: Path, destination: Path, *, check: Callable[[], object] | None = None
) -> None:
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
                or (relative_root.as_posix() == ".github" and directory == "codeql")
            ):
                continue
            kept.append(directory)
        directories[:] = kept
        output_root = destination / relative_root
        output_root.mkdir(parents=True, exist_ok=True)
        for filename in filenames:
            if check:
                check()
            source_file = root_path / filename
            if source_file.is_symlink():
                continue
            _, payload = read_regular_file(
                source_file,
                "CodeQL source",
                maximum_bytes=64 * 1024**2,
                boundary=source,
            )
            (output_root / filename).write_bytes(payload)
