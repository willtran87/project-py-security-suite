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
from .staging import maintained_files


class PysaAdapter(ScannerAdapter):
    name = "pysa"

    def not_applicable_reason(self, target: Path) -> str | None:
        if not maintained_files(target, frozenset({".py"})):
            return "no Python source files were found"
        if not (
            (target / ".pyre_configuration").is_file()
            or (target / ".pyre_configuration.local").is_file()
        ):
            return "no repository Pysa/Pyre configuration was found"
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [executable, "--noninteractive", "analyze"]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = strict_json_loads(payload)
        if isinstance(document, dict):
            results = document.get("errors") or document.get("results") or []
        else:
            results = document
        if not isinstance(results, list):
            raise TypeError("Pysa output must contain a list of issues")
        findings: list[Finding] = []
        for result in results:
            if not isinstance(result, dict):
                raise TypeError("Pysa result must be an object")
            rule_id = str(result.get("code") or "pysa.unknown")
            title = str(
                result.get("name")
                or result.get("concise_description")
                or f"Pysa issue {rule_id}"
            )
            description = str(
                result.get("description") or result.get("long_description") or title
            )
            path = normalize_repo_path(target, str(result.get("path") or "<unknown>"))
            line = _integer(result.get("line"))
            finding_id, fingerprint = finding_identity(
                tool=self.name,
                rule_id=rule_id,
                path=path,
                start_line=line,
            )
            severity, area, classifications = _classify(title, description)
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=title,
                    description=description[:2000],
                    impact=(
                        "Attacker-controlled data may reach a security-sensitive "
                        "operation across one or more Python call boundaries."
                    ),
                    remediation=(
                        "Validate the reported source-to-sink trace, constrain or "
                        "sanitize the input at the trust boundary, and update Pysa "
                        "models when framework behavior is not represented accurately."
                    ),
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    area=area,
                    classifications=classifications,
                    locations=[Location(path=path, start_line=line, end_line=line)],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id=rule_id,
                            message=description[:500],
                            native_severity="security",
                        )
                    ],
                    citations=[
                        Citation(
                            kind="tool_rule",
                            identifier=rule_id,
                            title=title,
                            uri="https://pyre-check.org/docs/pysa-basics/",
                        )
                    ],
                )
            )
        return findings


def _classify(title: str, description: str) -> tuple[Severity, str, list[str]]:
    value = f"{title} {description}".lower()
    if any(term in value for term in ("sql", "query injection")):
        return Severity.HIGH, "injection", ["CWE-89"]
    if any(term in value for term in ("shell", "command", "remote code")):
        return Severity.HIGH, "injection", ["CWE-78"]
    if "path" in value and "travers" in value:
        return Severity.HIGH, "filesystem", ["CWE-22"]
    if any(term in value for term in ("xss", "cross-site scripting")):
        return Severity.MEDIUM, "web-output", ["CWE-79"]
    if any(term in value for term in ("secret", "credential", "logging")):
        return Severity.HIGH, "data-exposure", ["CWE-532"]
    return Severity.HIGH, "data-flow", []


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
