from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..execution import CommandEnvironment
from ..models import Citation, Confidence, Finding, Location, Severity, Source
from ..models import finding_identity, normalize_repo_path
from .base import ScannerAdapter
from .staging import maintained_repository_files


_IAC_NAMES = {
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "serverless.yml",
    "serverless.yaml",
    "template.yaml",
}
_IAC_SUFFIXES = {".tf", ".tf.json", ".bicep", ".yaml", ".yml"}


class CheckovAdapter(ScannerAdapter):
    name = "checkov"
    accepted_exit_codes = frozenset({0, 1})

    def not_applicable_reason(self, target: Path) -> str | None:
        for path in maintained_repository_files(target):
            lowered = path.name.casefold()
            if lowered in _IAC_NAMES or any(
                lowered.endswith(suffix) for suffix in _IAC_SUFFIXES
            ):
                return None
        return "no supported infrastructure-as-code or pipeline files were found"

    def environment(self) -> CommandEnvironment:
        return CommandEnvironment(
            extra={
                "BC_SOURCE": "py-security-suite",
                "ANSI_COLORS_DISABLED": "1",
                "CKV_SUPPRESS_GUIDE": "true",
                "DOWNLOAD_EXTERNAL_MODULES": "false",
            }
        )

    def version_command(self, executable: str) -> list[str]:
        return [*self._prefix(executable), "--version"]

    def _prefix(self, executable: str) -> list[str]:
        if Path(executable).stem.casefold().startswith("python"):
            return [
                executable,
                "-c",
                "from checkov.main import Checkov; raise SystemExit(Checkov().run())",
            ]
        return [executable]

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            *self._prefix(executable),
            "--directory",
            str(target.resolve()),
            "--output",
            "json",
            "--quiet",
            "--framework",
            "dockerfile",
            "github_actions",
            "terraform",
            "cloudformation",
            "kubernetes",
            "helm",
            "kustomize",
            "openapi",
            "bicep",
            "arm",
            "serverless",
            "--skip-download",
            "--download-external-modules",
            "false",
            "--skip-path",
            r"\.artifacts|\.git|\.pysec-tools|\.venv|build|dist|node_modules",
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = json.loads(payload or "{}")
        reports = document if isinstance(document, list) else [document]
        findings: list[Finding] = []
        for report in reports:
            if not isinstance(report, dict):
                raise TypeError("Checkov report must be an object")
            results = report.get("results", {})
            if not isinstance(results, dict):
                raise TypeError("Checkov results must be an object")
            failed = results.get("failed_checks", [])
            if not isinstance(failed, list):
                raise TypeError("Checkov failed_checks must be a list")
            findings.extend(_finding(check, target) for check in failed)
        return findings

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        return {"checkov-iac.json": json.loads(payload or "{}")}


def _finding(check: object, target: Path) -> Finding:
    if not isinstance(check, dict):
        raise TypeError("Checkov finding must be an object")
    rule_id = str(check.get("check_id") or "CKV_UNKNOWN")
    title = str(check.get("check_name") or rule_id)
    path = normalize_repo_path(target, str(check.get("file_path") or "<repository>"))
    check_result = check.get("check_result", {})
    if not isinstance(check_result, dict):
        check_result = {}
    line = _integer(check_result.get("start_line"))
    end_line = _integer(check_result.get("end_line")) or line
    severity = _severity(check.get("severity"))
    resource = str(check.get("resource") or "")
    finding_id, fingerprint = finding_identity(
        tool="checkov", rule_id=rule_id, path=path, start_line=line, advisory=resource
    )
    citation_uri = str(check.get("guideline") or "")
    if not citation_uri.startswith("https://"):
        citation_uri = "https://www.checkov.io/5.Policy%20Index/all.html"
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        title=f"IaC policy: {title}",
        description=f"{title}."
        + (f" Affected resource: {resource}." if resource else ""),
        impact="The infrastructure or pipeline configuration violates a recognized security policy and can create an insecure production deployment.",
        remediation="Apply the cited policy guidance to the declared resource, validate the generated plan where applicable, and rerun the isolated IaC profile.",
        severity=severity,
        confidence=Confidence.HIGH,
        area="infrastructure-as-code",
        domain="security",
        classifications=[rule_id],
        locations=[Location(path=path, start_line=line, end_line=end_line)],
        sources=[
            Source(
                tool="checkov",
                rule_id=rule_id,
                message=title,
                native_severity=str(check.get("severity") or "policy-failure"),
            )
        ],
        citations=[
            Citation(
                kind="tool_rule",
                identifier=rule_id,
                title=f"Checkov policy {rule_id}",
                uri=citation_uri,
            )
        ],
        evidence={"resource": resource, "framework": check.get("check_type")},
    )


def _severity(value: object) -> Severity:
    normalized = str(value or "").casefold()
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }.get(normalized, Severity.MEDIUM)


def _integer(value: object) -> int | None:
    try:
        return None if value is None else int(str(value))
    except (TypeError, ValueError):
        return None
