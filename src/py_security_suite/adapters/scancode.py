from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from ..execution import (
    CommandEnvironment,
    run_command,
    sanitize_diagnostic,
)
from ..models import (
    Citation,
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
    ToolRun,
    ToolStatus,
    finding_identity,
    normalize_repo_path,
)
from .base import AdapterResult, ScannerAdapter


class ScanCodeAdapter(ScannerAdapter):
    name = "scancode"

    def not_applicable_reason(self, target: Path) -> str | None:
        if not _scan_roots(target):
            return (
                "no package metadata, license/notice file, README, or "
                "vendored-source root was found"
            )
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            executable,
            "--license",
            "--package",
            "--processes",
            "1",
            "--timeout",
            str(min(self.config.timeout_seconds, 120)),
            "--only-findings",
            "--json-pp",
            "-",
            str(target.resolve()),
        ]

    def run(self, target: Path) -> AdapterResult:
        scan_roots = _scan_roots(target)
        if not scan_roots:
            run = ToolRun(
                tool=self.name,
                status=ToolStatus.SKIPPED,
                command=[self.config.executable],
                duration_seconds=0.0,
                error=self.not_applicable_reason(target),
                applicable=False,
            )
            return AdapterResult([], run, self._diagnostic(run, None))
        prerequisite = self.prerequisite_error()  # pylint: disable=assignment-from-none
        executable, integrity_error = self._prepare_executable()
        if prerequisite or integrity_error or executable is None:
            run = ToolRun(
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
            return AdapterResult([], run, self._diagnostic(run, None))

        with tempfile.TemporaryDirectory(prefix="pysec-scancode-") as directory:
            temporary_root = Path(directory)
            staging = temporary_root / "inputs"
            home = temporary_root / "home"
            staging.mkdir()
            home.mkdir()
            environment = CommandEnvironment(
                {
                    "HOME": str(home),
                    "USERPROFILE": str(home),
                    "XDG_CACHE_HOME": str(home / "cache"),
                }
            )
            version_execution = run_command(
                [executable, "--version"],
                cwd=staging,
                timeout_seconds=min(self.config.timeout_seconds, 10),
                max_output_bytes=2048,
                environment=environment,
            )
            version_value = (
                version_execution.stdout.strip() or version_execution.stderr.strip()
            )
            version = (
                sanitize_diagnostic(
                    version_value.splitlines()[0] if version_value else "",
                    maximum=200,
                )
                if (
                    version_execution.exit_code == 0 and not version_execution.timed_out
                )
                else "unknown"
            ) or "unknown"
            for relative in scan_roots:
                _copy_without_symlinks(target / relative, staging / relative)
            command = self.build_command(executable, staging)
            execution = run_command(
                command,
                cwd=staging,
                timeout_seconds=self.config.timeout_seconds,
                max_output_bytes=self.max_output_bytes,
                environment=environment,
            )
            changed_error = self._executable_changed_error()
            if changed_error:
                run = self._tool_run(
                    execution,
                    ToolStatus.FAILED,
                    error=changed_error,
                    version=version,
                )
                return AdapterResult([], run, self._diagnostic(run, execution))
            if execution.timed_out:
                run = self._tool_run(
                    execution,
                    ToolStatus.TIMED_OUT,
                    error=f"timed out after {self.config.timeout_seconds} seconds",
                    version=version,
                )
                return AdapterResult([], run, self._diagnostic(run, execution))
            if execution.exit_code not in self.accepted_exit_codes:
                run = self._tool_run(
                    execution,
                    ToolStatus.FAILED,
                    error=f"unexpected exit code {execution.exit_code}",
                    version=version,
                )
                return AdapterResult([], run, self._diagnostic(run, execution))
            try:
                payload = _remove_staging_prefix(execution.stdout, staging.name)
                findings = self.parse(payload, target)
                artifacts = self.derived_artifacts(payload, target)
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                run = self._tool_run(
                    execution,
                    ToolStatus.PARSE_ERROR,
                    error=f"could not parse {self.name} output: {exc}",
                    version=version,
                )
                return AdapterResult([], run, self._diagnostic(run, execution))

        for finding in findings:
            for source in finding.sources:
                if source.tool == self.name:
                    source.version = version
        run = self._tool_run(
            execution,
            ToolStatus.COMPLETED,
            finding_count=len(findings),
            version=version,
        )
        diagnostic = self._diagnostic(run, execution)
        diagnostic["staged_inputs"] = scan_roots
        return AdapterResult(findings, run, diagnostic, artifacts)

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = _document(payload)
        files = document.get("files") or []
        if not isinstance(files, list):
            raise TypeError("ScanCode files must be a list")
        findings: list[Finding] = []
        for file_result in files:
            if not isinstance(file_result, dict):
                continue
            path = normalize_repo_path(
                target, str(file_result.get("path") or "<unknown>")
            )
            for license_result in _license_results(file_result):
                expression = str(
                    license_result.get("license_expression")
                    or license_result.get("key")
                    or "unknown"
                )
                if "unknown" not in expression.casefold():
                    continue
                line = _integer(license_result.get("start_line"))
                rule_id = f"unknown-license/{expression}"
                finding_id, fingerprint = finding_identity(
                    tool=self.name,
                    rule_id=rule_id,
                    path=path,
                    start_line=line,
                )
                findings.append(
                    Finding(
                        finding_id=finding_id,
                        fingerprint=fingerprint,
                        title=f"Unknown license evidence: {expression}",
                        description=(
                            "ScanCode found license-like text that it could not "
                            "map to a recognized license expression."
                        ),
                        impact=(
                            "Unidentified licensing terms can create unreviewed "
                            "distribution or attribution obligations."
                        ),
                        remediation=(
                            "Review the cited text, determine the governing license, "
                            "and record an approved SPDX expression or remove the content."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        area="license-governance",
                        classifications=["LICENSE-UNKNOWN"],
                        locations=[
                            Location(
                                path=path,
                                start_line=line,
                                end_line=_integer(license_result.get("end_line"))
                                or line,
                            )
                        ],
                        sources=[
                            Source(
                                tool=self.name,
                                rule_id=rule_id,
                                message=f"Unknown license expression {expression}",
                                native_severity="unknown",
                            )
                        ],
                        citations=[
                            Citation(
                                kind="tool_rule",
                                identifier=rule_id,
                                title="ScanCode license detection",
                                uri=(
                                    "https://scancode-toolkit.readthedocs.io/en/"
                                    "stable/explanation/scancode-license-detection.html"
                                ),
                            )
                        ],
                    )
                )
        return findings

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        document = _document(payload)
        inventory: list[dict[str, Any]] = []
        for file_result in document.get("files") or []:
            if not isinstance(file_result, dict):
                continue
            licenses = sorted(
                {
                    str(item.get("license_expression") or item.get("key") or "unknown")
                    for item in _license_results(file_result)
                }
            )
            packages = [
                {
                    "type": package.get("type"),
                    "name": package.get("name"),
                    "version": package.get("version"),
                    "purl": package.get("purl"),
                }
                for package in file_result.get("packages") or []
                if isinstance(package, dict)
            ]
            if licenses or packages:
                inventory.append(
                    {
                        "path": normalize_repo_path(
                            target, str(file_result.get("path") or "<unknown>")
                        ),
                        "licenses": licenses,
                        "packages": packages,
                    }
                )
        return {
            "scancode-inventory.json": {
                "schema_version": "1.0",
                "files": inventory,
            }
        }


def _document(payload: str) -> dict[str, Any]:
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise TypeError("ScanCode output must be an object")
    return value


def _license_results(file_result: dict[str, Any]) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    detections = file_result.get("license_detections") or []
    if isinstance(detections, list):
        for detection in detections:
            if not isinstance(detection, dict):
                continue
            expression = detection.get("license_expression")
            matches = detection.get("matches") or [{}]
            if not isinstance(matches, list):
                matches = [{}]
            values.extend(
                {"license_expression": expression, **match}
                for match in matches
                if isinstance(match, dict)
            )
    legacy = file_result.get("licenses") or []
    if isinstance(legacy, list):
        values.extend(item for item in legacy if isinstance(item, dict))
    return values


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _scan_roots(target: Path) -> list[str]:
    excluded = {
        ".artifacts",
        ".docx-qa",
        ".git",
        ".hg",
        ".nox",
        ".pysec-tools",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "env",
        "node_modules",
        "venv",
        "~",
    }
    metadata_names = {
        "pdm.lock",
        "pipfile",
        "pipfile.lock",
        "poetry.lock",
        "pylock.toml",
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
        "uv.lock",
    }
    vendored_names = {"third-party", "third_party", "vendor", "vendored"}
    selected: set[str] = set()
    for root, directories, files in os.walk(target, followlinks=False):
        root_path = Path(root)
        kept: list[str] = []
        for directory in directories:
            path = root_path / directory
            if (
                path.is_symlink()
                or directory in excluded
                or directory.endswith((".egg-info", ".dist-info"))
            ):
                continue
            if root_path == target and directory.casefold() in vendored_names:
                selected.add(directory)
                continue
            kept.append(directory)
        directories[:] = kept
        for filename in files:
            path = root_path / filename
            if path.is_symlink():
                continue
            folded = filename.casefold()
            is_governance_file = (
                folded in metadata_names
                or folded.startswith(("license", "copying", "notice"))
                or (
                    folded.startswith("requirements")
                    and path.suffix.casefold() in {".in", ".txt"}
                )
                or (root_path == target and folded.startswith("readme"))
            )
            if is_governance_file:
                selected.add(path.relative_to(target).as_posix())
    return sorted(selected, key=str.casefold)


def _copy_without_symlinks(source: Path, destination: Path) -> None:
    if source.is_symlink():
        return
    if source.is_file():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        return
    for root, directories, files in os.walk(source, followlinks=False):
        root_path = Path(root)
        directories[:] = [
            directory
            for directory in directories
            if not (root_path / directory).is_symlink()
        ]
        relative_root = root_path.relative_to(source)
        destination_root = destination / relative_root
        destination_root.mkdir(parents=True, exist_ok=True)
        for filename in files:
            path = root_path / filename
            if not path.is_symlink():
                shutil.copy2(path, destination_root / filename)


def _remove_staging_prefix(payload: str, staging_name: str) -> str:
    document = _document(payload)
    prefix = f"{staging_name}/"
    for file_result in document.get("files") or []:
        if not isinstance(file_result, dict):
            continue
        path = str(file_result.get("path") or "")
        normalized = path.replace("\\", "/")
        if normalized.startswith(prefix):
            file_result["path"] = normalized[len(prefix) :]
    return json.dumps(document)
