from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from ..execution import CommandEnvironment
from ..models import (
    Citation,
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
    finding_identity,
    normalize_repo_path,
)
from ..strict_json import loads as strict_json_loads
from .base import ScannerAdapter
from .common import map_severity
from .staging import maintained_repository_files


class TrivyAdapter(ScannerAdapter):
    name = "trivy"

    def not_applicable_reason(self, target: Path) -> str | None:
        names = {
            "dockerfile",
            "containerfile",
            "license",
            "license.txt",
            "license.md",
            "poetry.lock",
            "pipfile.lock",
            "requirements.txt",
        }
        suffixes = {".tf", ".yaml", ".yml", ".json"}
        for path in maintained_repository_files(target):
            if path.name.casefold() in names or path.suffix.casefold() in suffixes:
                return None
        return "no supported deployment, dependency, or license files were found"

    def environment(self) -> CommandEnvironment:
        cache = self.config.database_path or (
            Path(tempfile.gettempdir()) / "pysec-trivy"
        )
        return CommandEnvironment(extra={"TRIVY_CACHE_DIR": str(cache.resolve())})

    def build_command(self, executable: str, target: Path) -> list[str]:
        cache = self.config.database_path or (
            Path(tempfile.gettempdir()) / "pysec-trivy"
        )
        return [
            executable,
            "fs",
            "--format",
            "json",
            "--scanners",
            "misconfig,license",
            "--offline-scan",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-check-update",
            "--skip-vex-repo-update",
            "--skip-version-check",
            "--disable-telemetry",
            "--cache-dir",
            str(cache.resolve()),
            "--skip-dirs",
            ".artifacts",
            "--skip-dirs",
            ".pysec-tools",
            str(target.resolve()),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = strict_json_loads(payload)
        if not isinstance(document, dict):
            raise TypeError("Trivy output must be an object")
        results = document.get("Results") or []
        if not isinstance(results, list):
            raise TypeError("Trivy Results must be a list")
        findings: list[Finding] = []
        for result in results:
            if not isinstance(result, dict):
                raise TypeError("Trivy result must be an object")
            result_target = normalize_repo_path(
                target, str(result.get("Target") or "<repository>")
            )
            findings.extend(_misconfigurations(result, result_target))
            findings.extend(_licenses(result, result_target, target))
        return findings


def _misconfigurations(result: dict[str, Any], path: str) -> list[Finding]:
    values = result.get("Misconfigurations") or []
    if not isinstance(values, list):
        return []
    findings: list[Finding] = []
    for item in values:
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("ID") or item.get("AVDID") or "TRIVY-MISCONFIG")
        title = str(item.get("Title") or item.get("Message") or rule_id)
        cause = item.get("CauseMetadata") or {}
        if not isinstance(cause, dict):
            cause = {}
        line = _integer(cause.get("StartLine"))
        finding_id, fingerprint = finding_identity(
            tool="trivy", rule_id=rule_id, path=path, start_line=line
        )
        primary_url = _safe_uri(item.get("PrimaryURL"))
        findings.append(
            Finding(
                finding_id=finding_id,
                fingerprint=fingerprint,
                title=title,
                description=str(
                    item.get("Description") or item.get("Message") or title
                ),
                impact=(
                    "The deployment or infrastructure configuration may expose "
                    "the application, credentials, data, or runtime privileges."
                ),
                remediation=str(
                    item.get("Resolution")
                    or "Apply the cited Trivy configuration guidance and rerun the scan."
                ),
                severity=map_severity(item.get("Severity")),
                confidence=Confidence.HIGH,
                area="deployment-configuration",
                classifications=[rule_id],
                locations=[
                    Location(
                        path=path,
                        start_line=line,
                        end_line=_integer(cause.get("EndLine")) or line,
                    )
                ],
                sources=[
                    Source(
                        tool="trivy",
                        rule_id=rule_id,
                        message=title,
                        native_severity=str(item.get("Severity") or "unknown"),
                    )
                ],
                citations=[
                    Citation(
                        kind="tool_rule",
                        identifier=rule_id,
                        title=title,
                        uri=primary_url,
                    )
                ],
            )
        )
    return findings


def _licenses(result: dict[str, Any], default_path: str, target: Path) -> list[Finding]:
    values = result.get("Licenses") or []
    if not isinstance(values, list):
        return []
    findings: list[Finding] = []
    for item in values:
        if not isinstance(item, dict):
            continue
        severity = map_severity(item.get("Severity"))
        if severity in {Severity.LOW, Severity.INFORMATIONAL}:
            continue
        name = str(item.get("Name") or "UNKNOWN")
        category = str(item.get("Category") or "unknown")
        package = str(item.get("PkgName") or "")
        path = normalize_repo_path(target, str(item.get("FilePath") or default_path))
        if path == "<outside-target>":
            path = default_path
        rule_id = f"license/{name}"
        finding_id, fingerprint = finding_identity(
            tool="trivy",
            rule_id=rule_id,
            path=path,
            package=package or None,
        )
        findings.append(
            Finding(
                finding_id=finding_id,
                fingerprint=fingerprint,
                title=f"{category.title()} license detected: {name}",
                description=(
                    f"Trivy classified license {name} as {category}"
                    + (f" for package {package}" if package else "")
                    + "."
                ),
                impact=(
                    "A forbidden, restricted, reciprocal, or unknown license can "
                    "create distribution and compliance obligations."
                ),
                remediation=(
                    "Validate the detected license against the organization's "
                    "approved-license policy and replace or formally approve it."
                ),
                severity=severity,
                confidence=Confidence.MEDIUM,
                area="license-governance",
                classifications=[f"LICENSE-{name}", category],
                locations=[Location(path=path, package=package or None)],
                sources=[
                    Source(
                        tool="trivy",
                        rule_id=rule_id,
                        message=f"{name} classified as {category}",
                        native_severity=str(item.get("Severity") or "unknown"),
                    )
                ],
                citations=[
                    Citation(
                        kind="license",
                        identifier=name,
                        title=f"License {name}",
                        uri=_safe_uri(item.get("Link")),
                    )
                ],
            )
        )
    return findings


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _safe_uri(value: Any) -> str | None:
    text = str(value or "")
    return text if text.startswith(("https://", "http://")) else None
