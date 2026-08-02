from __future__ import annotations

import json
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
from .base import ScannerAdapter
from .common import database_freshness_error, map_severity


class OsvScannerAdapter(ScannerAdapter):
    name = "osv-scanner"

    def prerequisite_error(self) -> str | None:
        database = self.config.database_path
        if database is None:
            return "an offline OSV database_path is required"
        resolved = database.expanduser().resolve()
        if not resolved.is_dir():
            return f"offline OSV database directory does not exist: {resolved}"
        return database_freshness_error(
            resolved, "all.zip", self.config.maximum_database_age_days
        )

    def environment(self) -> CommandEnvironment:
        database = self.config.database_path
        if database is None:
            raise ValueError("an offline OSV database_path is required")
        return CommandEnvironment(
            extra={
                "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(
                    database.expanduser().resolve()
                )
            }
        )

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            executable,
            "scan",
            "source",
            "--offline",
            "--offline-vulnerabilities",
            "--no-resolve",
            "--allow-no-lockfiles",
            "--format=json",
            "--recursive",
            "--experimental-exclude",
            ".artifacts",
            "--experimental-exclude",
            ".pysec-tools",
            str(target.resolve()),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = json.loads(payload)
        results = document.get("results") or []
        if not isinstance(results, list):
            raise TypeError("results must be a list")
        findings: list[Finding] = []
        for result in results:
            if not isinstance(result, dict):
                raise TypeError("OSV result must be an object")
            source = result.get("source") or {}
            source_path = source.get("path") if isinstance(source, dict) else None
            path = normalize_repo_path(target, str(source_path or "dependency"))
            packages = result.get("packages", [])
            if not isinstance(packages, list):
                continue
            for package_result in packages:
                findings.extend(self._package_findings(package_result, path))
        return findings

    def _package_findings(self, package_result: Any, path: str) -> list[Finding]:
        if not isinstance(package_result, dict):
            raise TypeError("OSV package result must be an object")
        package = package_result.get("package") or {}
        if not isinstance(package, dict):
            package = {}
        name = str(package.get("name") or "unknown-package")
        version = str(package.get("version") or "unknown")
        ecosystem = str(package.get("ecosystem") or "PyPI")
        vulnerabilities = package_result.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            return []
        findings: list[Finding] = []
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue
            advisory = str(vulnerability.get("id") or "OSV-UNKNOWN")
            summary = str(
                vulnerability.get("summary") or vulnerability.get("details") or advisory
            )
            native_severity = _native_severity(vulnerability)
            severity = map_severity(native_severity, default=Severity.HIGH)
            finding_id, fingerprint = finding_identity(
                tool=self.name,
                rule_id=advisory,
                path=path,
                package=f"{ecosystem}:{name}@{version}",
                advisory=advisory,
            )
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=f"{advisory} affects {name} {version}",
                    description=summary[:2000],
                    impact=(
                        "The locked dependency version matches a vulnerability in "
                        "the approved offline OSV database."
                    ),
                    remediation=(
                        "Review the bundled advisory and upgrade or replace the "
                        "dependency with an approved non-affected version."
                    ),
                    severity=severity,
                    confidence=Confidence.HIGH,
                    area="dependencies",
                    classifications=[advisory],
                    locations=[
                        Location(
                            path=path,
                            package=name,
                            version=version,
                            ecosystem=ecosystem,
                        )
                    ],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id=advisory,
                            message=summary[:500],
                            native_severity=native_severity,
                        )
                    ],
                    citations=[
                        Citation(
                            kind="advisory",
                            identifier=advisory,
                            title=summary[:200],
                            uri=f"https://osv.dev/vulnerability/{advisory}",
                        )
                    ],
                )
            )
        return findings


def _native_severity(vulnerability: dict[str, Any]) -> str:
    database_specific = vulnerability.get("database_specific")
    if isinstance(database_specific, dict) and database_specific.get("severity"):
        return str(database_specific["severity"])
    ecosystem_specific = vulnerability.get("ecosystem_specific")
    if isinstance(ecosystem_specific, dict) and ecosystem_specific.get("severity"):
        return str(ecosystem_specific["severity"])
    return "high"
