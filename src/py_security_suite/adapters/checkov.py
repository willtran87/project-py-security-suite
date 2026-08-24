from __future__ import annotations

import hashlib
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
from ..native_evidence import protect_native_report
from ..strict_json import canonical_bytes
from ..strict_json import loads as strict_json_loads
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
        reports = _reports(payload)
        findings: list[Finding] = []
        for report in reports:
            if not isinstance(report, dict):
                raise TypeError("Checkov report must be an object")
            results = report["results"]
            failed = results["failed_checks"]
            findings.extend(_finding(check, target) for check in failed)
        return findings

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        reports = _reports(payload)
        checks = {
            status: sum(len(report["results"][status]) for report in reports)
            for status in ("passed_checks", "failed_checks", "skipped_checks")
        }
        frameworks = sorted(
            {
                str(check.get("check_type") or "unknown")[:100]
                for report in reports
                for status in ("passed_checks", "failed_checks", "skipped_checks")
                for check in report["results"][status]
                if isinstance(check, dict)
            }
        )
        artifact: dict[str, Any] = {
            "schema_version": "1.0",
            "reports": len(reports),
            **checks,
            "total_checks": sum(checks.values()),
            "frameworks": frameworks,
            "native_report_records": sum(checks.values()),
            **protect_native_report(payload, adapter=self.name),
        }
        artifact["normalization_sha256"] = hashlib.sha256(
            canonical_bytes(artifact)
        ).hexdigest()
        return {"checkov-iac.json": artifact}


def _reports(payload: str) -> list[dict[str, Any]]:
    if not payload.strip():
        raise ValueError("Checkov emitted an empty report")
    document = strict_json_loads(payload)
    raw_reports = document if isinstance(document, list) else [document]
    if not raw_reports:
        raise ValueError("Checkov report list must not be empty")
    reports: list[dict[str, Any]] = []
    for report in raw_reports:
        if not isinstance(report, dict):
            raise TypeError("Checkov report must be an object")
        results = report.get("results")
        if not isinstance(results, dict):
            raise TypeError("Checkov results must be an object")
        for status in ("passed_checks", "failed_checks", "skipped_checks"):
            if not isinstance(results.get(status), list):
                raise TypeError(f"Checkov {status} must be a list")
        reports.append(report)
    return reports


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
