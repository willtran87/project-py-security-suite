from __future__ import annotations

import os
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
from .common import map_severity, string_list
from .staging import maintained_files


class GuardDogAdapter(ScannerAdapter):
    name = "guarddog"
    accepted_exit_codes = frozenset({0, 1})

    def not_applicable_reason(self, target: Path) -> str | None:
        if os.name == "nt":
            return (
                "GuardDog does not support native Windows execution and this "
                "suite does not require Docker; run this profile on Linux or macOS"
            )
        if not maintained_files(target, frozenset({".py"})):
            return "no Python source or package content was found"
        return None

    def environment(self) -> CommandEnvironment:
        return CommandEnvironment(
            extra={
                "GUARDDOG_PARALLELISM": "1",
                "GUARDDOG_VERIFY_EXHAUSTIVE_DEPENDENCIES": "false",
            }
        )

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            executable,
            "--log-level",
            "ERROR",
            "pypi",
            "scan",
            "--output-format",
            "json",
            "--exit-non-zero-on-finding",
            str(target.resolve()),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = strict_json_loads(payload)
        if isinstance(document, list):
            documents = document
        elif isinstance(document, dict):
            documents = [document]
        else:
            raise TypeError("GuardDog output must be an object or list")
        findings: list[Finding] = []
        for item in documents:
            if not isinstance(item, dict):
                continue
            risks = item.get("risks") or []
            if not isinstance(risks, list):
                raise TypeError("GuardDog risks must be a list")
            findings.extend(
                _risk_finding(risk, target) for risk in risks if isinstance(risk, dict)
            )
        return findings


def _risk_finding(risk: dict[str, Any], target: Path) -> Finding:
    rule_id = str(risk.get("threat_rule") or risk.get("name") or "guarddog.unknown")
    message = str(risk.get("threat_description") or risk.get("description") or rule_id)
    raw_path, line = _location(
        str(risk.get("file_path") or risk.get("threat_location") or "")
    )
    path = normalize_repo_path(target, raw_path or "<repository>")
    finding_id, fingerprint = finding_identity(
        tool="guarddog",
        rule_id=rule_id,
        path=path,
        start_line=line,
    )
    tactics = string_list(risk.get("mitre_tactics"))
    severity = map_severity(risk.get("severity"), default=Severity.HIGH)
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        title=f"Suspicious package behavior: {rule_id}",
        description=message[:2000],
        impact=(
            "The package contains behavior associated with malicious installation, "
            "execution, persistence, obfuscation, or data exfiltration."
        ),
        remediation=(
            "Quarantine the package or source artifact, inspect its provenance and "
            "matched behavior, and do not approve it for the enterprise wheelhouse "
            "until the finding is resolved."
        ),
        severity=severity,
        confidence=Confidence.MEDIUM,
        area="package-integrity",
        classifications=[f"MITRE-{value}" for value in tactics],
        locations=[Location(path=path, start_line=line, end_line=line)],
        sources=[
            Source(
                tool="guarddog",
                rule_id=rule_id,
                message=message[:500],
                native_severity=str(risk.get("severity") or "unknown"),
            )
        ],
        citations=[
            Citation(
                kind="tool_rule",
                identifier=rule_id,
                title=rule_id,
                uri=("https://github.com/DataDog/guarddog/tree/main/guarddog/analyzer"),
            )
        ],
        evidence={"code_retained": False},
    )


def _location(value: str) -> tuple[str, int | None]:
    path, separator, line = value.rpartition(":")
    if separator:
        try:
            return path, int(line)
        except ValueError:
            pass
    return value, None
