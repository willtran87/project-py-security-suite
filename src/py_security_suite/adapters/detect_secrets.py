from __future__ import annotations

from pathlib import Path
from typing import Any

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


class DetectSecretsAdapter(ScannerAdapter):
    name = "detect-secrets"

    def build_command(self, executable: str, target: Path) -> list[str]:
        scan_roots = [
            str(entry.resolve())
            for entry in sorted(target.iterdir(), key=lambda path: path.name.lower())
            if entry.name
            not in {
                ".artifacts",
                ".git",
                ".hg",
                ".mypy_cache",
                ".nox",
                ".pysec-tools",
                ".pytest_cache",
                ".ruff_cache",
                ".svn",
                ".tox",
                ".venv",
                "__pycache__",
                "build",
                "dist",
                "env",
                "node_modules",
                "site",
                "venv",
            }
            and entry.name not in {"coverage.json", "coverage.xml", "junit.xml"}
            and not entry.name.endswith(".pysec-binding.json")
        ]
        return [
            executable,
            "--cores",
            "1",
            "scan",
            *(scan_roots or [str(target.resolve())]),
            "--all-files",
            "--no-verify",
            "--exclude-files",
            (
                r"(^|[\\/])\.(artifacts|mypy_cache|pysec-tools|"
                r"pytest_cache|ruff_cache)([\\/]|$)|"
                # This governed API-security corpus deliberately contains
                # synthetic credential shapes. Its schema and negative-control
                # tests validate those fixtures independently.
                r"(^|[\\/])security[\\/]api-surface-1[.]1[.]json$"
                r"|(^|[\\/])(coverage[.](json|xml)|junit[.]xml)"
                r"([.]pysec-binding[.]json)?$|(^|[\\/])site([\\/]|$)"
            ),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = strict_json_loads(payload)
        if not isinstance(document, dict):
            raise TypeError("detect-secrets output must be an object")
        results = document.get("results", {})
        if not isinstance(results, dict):
            raise TypeError("results must be an object")
        findings: list[Finding] = []
        for native_path, secrets in sorted(results.items()):
            if not isinstance(secrets, list):
                raise TypeError("secret results must be lists")
            path = normalize_repo_path(target, native_path)
            for secret in secrets:
                if not isinstance(secret, dict):
                    raise TypeError("secret result must be an object")
                detector = str(secret.get("type") or "Potential secret")
                line = _integer(secret.get("line_number"))
                rule_id = _rule_id(detector)
                finding_id, fingerprint = finding_identity(
                    tool=self.name,
                    rule_id=rule_id,
                    path=path,
                    start_line=line,
                )
                title = f"Potential secret detected: {detector}"
                findings.append(
                    Finding(
                        finding_id=finding_id,
                        fingerprint=fingerprint,
                        title=title,
                        description=(
                            "A local detect-secrets plugin identified a credential-like "
                            "value. The value is intentionally omitted from this report."
                        ),
                        impact=(
                            "Committed credentials can permit unauthorized access and "
                            "usually require rotation even after removal."
                        ),
                        remediation=(
                            "Validate the finding, revoke and rotate real credentials, "
                            "remove the value from source, and use an approved secret store."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        area="secrets",
                        classifications=["CWE-798"],
                        locations=[Location(path=path, start_line=line, end_line=line)],
                        sources=[
                            Source(
                                tool=self.name,
                                rule_id=rule_id,
                                message=title,
                                native_severity="potential-secret",
                            )
                        ],
                        citations=[
                            Citation(
                                kind="tool_rule",
                                identifier=rule_id,
                                title=detector,
                            ),
                            Citation(
                                kind="taxonomy",
                                identifier="CWE-798",
                                title="Use of Hard-coded Credentials",
                                uri=("https://cwe.mitre.org/data/definitions/798.html"),
                            ),
                        ],
                        evidence={"redacted": True},
                    )
                )
        return findings


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _rule_id(detector: str) -> str:
    normalized = "".join(
        character.lower() if character.isalnum() else "-" for character in detector
    ).strip("-")
    return f"detect-secrets.{normalized or 'unknown'}"
