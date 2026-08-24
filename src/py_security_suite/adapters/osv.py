from __future__ import annotations

import hashlib
import re
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
from ..path_safety import read_regular_file
from ..strict_json import canonical_bytes
from ..strict_json import loads as strict_json_loads
from .base import ScannerAdapter
from .common import database_freshness_error, map_severity

_ADVISORY_IDENTIFIER = re.compile(r"^(?:CVE|GHSA|OSV|PYSEC)-[A-Z0-9._-]+$")


class OsvScannerAdapter(ScannerAdapter):
    name = "osv-scanner"
    # OSV-Scanner exits 1 when vulnerabilities are found. The JSON payload is
    # still a successful scan result and must be parsed instead of discarded.
    accepted_exit_codes = frozenset({0, 1})

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
        document = strict_json_loads(payload)
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

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        """Retain source records emitted by OSV instead of inferring scan scope."""
        document = strict_json_loads(payload)
        results = document.get("results") or []
        if not isinstance(results, list):
            raise TypeError("results must be a list")
        manifests: dict[str, dict[str, str]] = {}
        for result in results:
            if not isinstance(result, dict):
                raise TypeError("OSV result must be an object")
            source = result.get("source")
            source_path = source.get("path") if isinstance(source, dict) else None
            if not isinstance(source_path, str) or not source_path.strip():
                continue
            relative = normalize_repo_path(target, source_path)
            if relative in {".", "<outside-target>"}:
                continue
            try:
                _, raw = read_regular_file(
                    target / relative,
                    "OSV-reported dependency manifest",
                    maximum_bytes=256 * 1024 * 1024,
                    boundary=target,
                )
            except (OSError, ValueError):
                continue
            manifests[relative] = {
                "manifest": relative,
                "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            }
        receipt = {
            "schema_version": "1.0",
            "analysis": "osv-scanner-manifest-output-receipts",
            "tool": self.name,
            "raw_output_sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            "manifests": [manifests[path] for path in sorted(manifests)],
        }
        receipt["receipt_sha256"] = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
        return {"osv-manifest-receipts.json": receipt}

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
            aliases = _advisory_aliases(vulnerability, advisory)
            fixed_versions = _fixed_versions(vulnerability)
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
                    classifications=sorted({advisory, *aliases}),
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
                    ]
                    + [
                        Citation(
                            kind="advisory_alias",
                            identifier=alias,
                            title=f"{alias} (alias of {advisory})",
                            uri=f"https://osv.dev/vulnerability/{alias}",
                        )
                        for alias in aliases[:10]
                    ],
                    evidence={
                        "advisory_aliases": aliases,
                        "fixed_versions": fixed_versions,
                        "fixed_versions_by_tool": {
                            self.name: fixed_versions,
                        },
                    },
                )
            )
        return findings


def _advisory_aliases(vulnerability: dict[str, Any], primary: str) -> list[str]:
    raw = vulnerability.get("aliases")
    if not isinstance(raw, list):
        return []
    normalized_primary = primary.upper()
    return sorted(
        {
            value
            for item in raw[:100]
            if isinstance(item, str)
            and (value := item.strip().upper()) != normalized_primary
            and _ADVISORY_IDENTIFIER.fullmatch(value)
        }
    )[:50]


def _fixed_versions(vulnerability: dict[str, Any]) -> list[str]:
    affected = vulnerability.get("affected")
    if not isinstance(affected, list):
        return []
    versions: set[str] = set()
    for record in affected[:100]:
        if not isinstance(record, dict):
            continue
        ranges = record.get("ranges")
        if not isinstance(ranges, list):
            continue
        for version_range in ranges[:100]:
            if not isinstance(version_range, dict):
                continue
            range_type = str(version_range.get("type") or "").upper()
            if range_type not in {"ECOSYSTEM", "SEMVER"}:
                continue
            events = version_range.get("events")
            if not isinstance(events, list):
                continue
            for event in events[:500]:
                if not isinstance(event, dict):
                    continue
                value = event.get("fixed")
                if not isinstance(value, (str, int, float)):
                    continue
                normalized = " ".join(str(value).split())[:100]
                if normalized and not any(
                    ord(character) < 32 for character in normalized
                ):
                    versions.add(normalized)
    return sorted(versions)[:100]


def _native_severity(vulnerability: dict[str, Any]) -> str:
    database_specific = vulnerability.get("database_specific")
    if isinstance(database_specific, dict) and database_specific.get("severity"):
        return str(database_specific["severity"])
    ecosystem_specific = vulnerability.get("ecosystem_specific")
    if isinstance(ecosystem_specific, dict) and ecosystem_specific.get("severity"):
        return str(ecosystem_specific["severity"])
    return "high"
