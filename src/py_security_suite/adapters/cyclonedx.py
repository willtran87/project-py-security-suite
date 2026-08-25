from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from ..config import ToolConfig
from ..execution import RawExecution, resolve_executable, run_command, sha256_file
from ..models import Finding, ToolRun, ToolStatus
from ..strict_json import loads as strict_json_loads
from .base import AdapterResult, ScannerAdapter


class CycloneDxAdapter(ScannerAdapter):
    name = "cyclonedx-py"

    def __init__(self, config: ToolConfig, max_output_bytes: int) -> None:
        super().__init__(config, max_output_bytes)
        self._auxiliary_path: Path | None = None
        self._auxiliary_sha256: str | None = None
        self._auxiliary_integrity_verified: bool | None = None
        self._auxiliary_unchanged: bool | None = None

    def not_applicable_reason(self, target: Path) -> str | None:
        if self._input(target) is None:
            return (
                "no supported locked dependency source was found "
                "(uv.lock, poetry.lock, Pipfile.lock, or pinned requirements file)"
            )
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        selected = self._input(target)
        if selected is None:
            raise ValueError("CycloneDX input selection was not available")
        kind, value = selected
        if kind == "uv":
            raise ValueError("uv.lock requires the guarded two-stage export path")
        command = [executable, kind]
        if kind in {"poetry", "pipenv"}:
            command.append(str(value))
        else:
            command.append(str(value))
        command.extend(
            [
                "--output-reproducible",
                "--output-format",
                "JSON",
                "--output-file",
                "-",
            ]
        )
        return command

    def run(self, target: Path) -> AdapterResult:
        selected = self._input(target)
        if selected is None or selected[0] != "uv":
            return super().run(target)
        return self._run_uv(target)

    def _run_uv(self, target: Path) -> AdapterResult:
        auxiliary_error = self._prepare_uv()
        executable, integrity_error = self._prepare_executable()
        if auxiliary_error or integrity_error or executable is None:
            error = (
                auxiliary_error
                or integrity_error
                or f"executable not found: {self.config.executable}"
            )
            run = ToolRun(
                tool=self.name,
                status=ToolStatus.UNAVAILABLE,
                command=[self.config.executable],
                duration_seconds=0.0,
                error=error,
            )
            return AdapterResult([], run, self._diagnostic(run, None))

        uv = self._auxiliary_path
        if uv is None:  # pragma: no cover - guarded by _prepare_uv
            raise RuntimeError("validated uv executable was not retained")
        version = self._detect_version(executable, target)
        with tempfile.TemporaryDirectory(
            prefix="pysec-cyclonedx-uv-", ignore_cleanup_errors=True
        ) as temporary:
            requirements = Path(temporary) / "requirements.txt"
            export_command = [
                str(uv),
                "export",
                "--format",
                "requirements.txt",
                "--frozen",
                "--offline",
                "--no-dev",
                "--no-emit-project",
                "--output-file",
                str(requirements),
            ]
            exported = run_command(
                export_command,
                cwd=target,
                timeout_seconds=self.config.timeout_seconds,
                max_output_bytes=self.max_output_bytes,
                environment=self.environment(),
            )
            changed_error = (
                self._executable_changed_error() or self._auxiliary_changed_error()
            )
            if changed_error:
                return self._failure(
                    exported, ToolStatus.FAILED, changed_error, version
                )
            if exported.timed_out:
                return self._failure(
                    exported,
                    ToolStatus.TIMED_OUT,
                    "uv lock export timed out",
                    version,
                )
            if exported.exit_code != 0:
                return self._failure(
                    exported,
                    ToolStatus.FAILED,
                    f"uv lock export failed with exit code {exported.exit_code}",
                    version,
                )
            if not requirements.is_file() or requirements.is_symlink():
                return self._failure(
                    exported,
                    ToolStatus.PARSE_ERROR,
                    "uv did not create a regular frozen requirements export",
                    version,
                )
            if requirements.stat().st_size > self.max_output_bytes:
                return self._failure(
                    exported,
                    ToolStatus.PARSE_ERROR,
                    "uv requirements export exceeded execution.max_output_bytes",
                    version,
                )

            command = self._requirements_command(executable, requirements)
            execution = run_command(
                command,
                cwd=target,
                timeout_seconds=self.config.timeout_seconds,
                max_output_bytes=self.max_output_bytes,
                environment=self.environment(),
            )
            changed_error = (
                self._executable_changed_error() or self._auxiliary_changed_error()
            )
            if changed_error:
                return self._failure(
                    execution, ToolStatus.FAILED, changed_error, version
                )
            if execution.timed_out:
                return self._failure(
                    execution,
                    ToolStatus.TIMED_OUT,
                    "CycloneDX generation timed out",
                    version,
                )
            if execution.exit_code not in self.accepted_exit_codes:
                return self._failure(
                    execution,
                    ToolStatus.FAILED,
                    f"CycloneDX generation failed with exit code {execution.exit_code}",
                    version,
                )
            try:
                findings = self.parse(execution.stdout, target)
                artifacts = self.derived_artifacts(execution.stdout, target)
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                return self._failure(
                    execution,
                    ToolStatus.PARSE_ERROR,
                    f"could not parse CycloneDX output: {exc}",
                    version,
                )

        run = self._tool_run(
            execution,
            ToolStatus.COMPLETED,
            finding_count=len(findings),
            version=version,
        )
        diagnostic = self._diagnostic(run, execution)
        diagnostic["dependency_source"] = "uv.lock"
        diagnostic["lock_export_frozen"] = True
        diagnostic["lock_export_offline"] = True
        diagnostic["export_exit_code"] = exported.exit_code
        return AdapterResult(findings, run, diagnostic, artifacts)

    @staticmethod
    def _requirements_command(executable: str, requirements: Path) -> list[str]:
        return [
            executable,
            "requirements",
            str(requirements),
            "--output-reproducible",
            "--output-format",
            "JSON",
            "--output-file",
            "-",
        ]

    def _prepare_uv(self) -> str | None:
        configured = self.config.auxiliary_executable or "uv"
        resolved = resolve_executable(configured)
        if resolved is None:
            return "uv.lock requires a pre-staged uv executable for frozen export"
        path = Path(resolved).resolve()
        try:
            digest = sha256_file(path)
        except OSError:
            return "the pre-staged uv executable could not be hashed"
        self._auxiliary_path = path
        self._auxiliary_sha256 = digest
        expected = self.config.auxiliary_executable_sha256
        self._auxiliary_integrity_verified = digest == expected if expected else None
        self._auxiliary_unchanged = None
        if expected and not self._auxiliary_integrity_verified:
            return "uv executable SHA-256 does not match the approved digest"
        return None

    def _auxiliary_changed_error(self) -> str | None:
        if self._auxiliary_path is None or self._auxiliary_sha256 is None:
            return None
        try:
            current = sha256_file(self._auxiliary_path)
        except OSError:
            self._auxiliary_unchanged = False
            return "uv executable became unreadable during SBOM generation"
        self._auxiliary_unchanged = current == self._auxiliary_sha256
        if not self._auxiliary_unchanged:
            return "uv executable changed during SBOM generation"
        return None

    def _tool_run(
        self,
        execution: RawExecution,
        status: ToolStatus,
        *,
        error: str | None = None,
        finding_count: int = 0,
        version: str = "unknown",
    ) -> ToolRun:
        run = super()._tool_run(
            execution,
            status,
            error=error,
            finding_count=finding_count,
            version=version,
        )
        run.auxiliary_executable_sha256 = self._auxiliary_sha256
        run.auxiliary_executable_integrity_verified = self._auxiliary_integrity_verified
        run.auxiliary_executable_unchanged = self._auxiliary_unchanged
        return run

    def _diagnostic(
        self, tool_run: ToolRun, execution: RawExecution | None
    ) -> dict[str, Any]:
        diagnostic = super()._diagnostic(tool_run, execution)
        diagnostic["auxiliary_executable_sha256"] = self._auxiliary_sha256
        diagnostic["auxiliary_executable_integrity_verified"] = (
            self._auxiliary_integrity_verified
        )
        diagnostic["auxiliary_executable_unchanged"] = self._auxiliary_unchanged
        return diagnostic

    def _failure(
        self,
        execution: RawExecution,
        status: ToolStatus,
        error: str,
        version: str,
    ) -> AdapterResult:
        run = self._tool_run(execution, status, error=error, version=version)
        return AdapterResult([], run, self._diagnostic(run, execution))

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = _document(payload)
        if document.get("bomFormat") != "CycloneDX":
            raise ValueError("output is not a CycloneDX BOM")
        components = document.get("components", [])
        if components is not None and not isinstance(components, list):
            raise TypeError("CycloneDX components must be a list")
        return []

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        return {"sbom.cdx.json": _document(payload)}

    @staticmethod
    def _input(target: Path) -> tuple[str, Path] | None:
        if (target / "uv.lock").is_file() and (target / "pyproject.toml").is_file():
            return "uv", target.resolve()
        if (target / "poetry.lock").is_file() and (target / "pyproject.toml").is_file():
            return "poetry", target.resolve()
        if (target / "Pipfile.lock").is_file():
            return "pipenv", target.resolve()
        preferred = (
            target / "requirements.txt",
            target / "requirements.lock",
            target / "requirements-dev.txt",
        )
        for path in preferred:
            if path.is_file() and _has_pinned_requirement(path):
                return "requirements", path.resolve()
        return None


def _document(payload: str) -> dict[str, Any]:
    value = strict_json_loads(payload)
    if not isinstance(value, dict):
        raise TypeError("CycloneDX output must be an object")
    return value


def _has_pinned_requirement(path: Path) -> bool:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    return any(
        "==" in line
        for line in lines
        if line.strip() and not line.lstrip().startswith(("#", "-", "git+"))
    )
