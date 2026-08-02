from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ..execution import CommandEnvironment
from ..models import (
    Citation,
    Confidence,
    Finding,
    Location,
    Source,
    finding_identity,
    normalize_repo_path,
)
from .artifacts import (
    configured_path,
    distribution_files,
    extracted_distribution_tree,
)
from .base import AdapterResult, ScannerAdapter
from .common import database_freshness_error, map_severity


class GrypeAdapter(ScannerAdapter):
    name = "grype"
    _scan_root: Path | None = None

    def not_applicable_reason(self, target: Path) -> str | None:
        if not distribution_files(target, self.config):
            return "no built wheel or source distribution was found"
        return None

    def prerequisite_error(self) -> str | None:
        database = self.config.database_path
        if database is None:
            return "a staged offline Grype database directory is required"
        if not database.expanduser().resolve().is_dir():
            return f"Grype database directory does not exist: {database}"
        return database_freshness_error(
            database.expanduser().resolve(),
            "vulnerability.db",
            self.config.maximum_database_age_days,
        )

    def environment(self) -> CommandEnvironment:
        cache = self.config.database_path or (
            Path(tempfile.gettempdir()) / "pysec-grype"
        )
        return CommandEnvironment(
            extra={
                "GRYPE_DB_CACHE_DIR": str(cache.expanduser().resolve()),
                "GRYPE_DB_AUTO_UPDATE": "false",
                "GRYPE_CHECK_FOR_APP_UPDATE": "false",
                # Permit controlled transfer but fail closed on stale bundles.
                "GRYPE_DB_MAX_ALLOWED_BUILT_AGE": (
                    f"{self.config.maximum_database_age_days * 24:g}h"
                ),
            }
        )

    def build_command(self, executable: str, target: Path) -> list[str]:
        artifact_root = self._scan_root or configured_path(
            target, self.config.artifacts_path, "dist"
        )
        return [
            executable,
            f"dir:{artifact_root}",
            "--output",
            "json",
            "--quiet",
        ]

    def run(self, target: Path) -> AdapterResult:
        if not distribution_files(target, self.config):
            return super().run(target)
        with extracted_distribution_tree(target, self.config) as scan_root:
            self._scan_root = scan_root
            try:
                return super().run(target)
            finally:
                self._scan_root = None

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = json.loads(payload)
        matches = document.get("matches") or []
        if not isinstance(matches, list):
            raise TypeError("Grype matches must be a list")
        findings: list[Finding] = []
        for match in matches:
            if not isinstance(match, dict):
                continue
            vulnerability = match.get("vulnerability") or {}
            artifact = match.get("artifact") or {}
            if not isinstance(vulnerability, dict) or not isinstance(artifact, dict):
                continue
            advisory = str(vulnerability.get("id") or "GRYPE-UNKNOWN")
            package = str(artifact.get("name") or "unknown")
            version = str(artifact.get("version") or "unknown")
            locations = artifact.get("locations") or []
            raw_path = "<artifact>"
            if isinstance(locations, list) and locations:
                first = locations[0]
                if isinstance(first, dict):
                    raw_path = str(first.get("path") or raw_path)
            path = normalize_repo_path(target, raw_path)
            finding_id, fingerprint = finding_identity(
                tool=self.name,
                rule_id=advisory,
                path=path,
                package=package,
                advisory=advisory,
            )
            fix = vulnerability.get("fix") or {}
            versions = fix.get("versions") if isinstance(fix, dict) else []
            fixed = ", ".join(str(item) for item in versions or [])
            urls = vulnerability.get("urls") or []
            uri = next(
                (
                    str(value)
                    for value in urls
                    if str(value).startswith(("https://", "http://"))
                ),
                None,
            )
            description = str(
                vulnerability.get("description")
                or f"{advisory} affects {package} {version}."
            )
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=f"{advisory} affects artifact package {package}",
                    description=description,
                    impact=(
                        "The release artifact contains a component version associated "
                        "with a published vulnerability."
                    ),
                    remediation=(
                        f"Upgrade {package} to {fixed} and rebuild the artifact."
                        if fixed
                        else (
                            f"Review {advisory}, replace or mitigate {package}, and "
                            "rebuild the artifact."
                        )
                    ),
                    severity=map_severity(vulnerability.get("severity")),
                    confidence=Confidence.HIGH,
                    area="artifact-vulnerability",
                    classifications=[advisory],
                    locations=[
                        Location(
                            path=path,
                            package=package,
                            version=version,
                            ecosystem=str(artifact.get("type") or "unknown"),
                        )
                    ],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id=advisory,
                            message=description,
                            native_severity=str(
                                vulnerability.get("severity") or "unknown"
                            ),
                        )
                    ],
                    citations=[
                        Citation(
                            kind="advisory",
                            identifier=advisory,
                            title=advisory,
                            uri=uri,
                        )
                    ],
                    evidence={"fixed_versions": list(versions or [])},
                )
            )
        return findings
