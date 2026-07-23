from __future__ import annotations

import json
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
from .base import ScannerAdapter


class RuffAdapter(ScannerAdapter):
    name = "ruff"
    accepted_exit_codes = frozenset({0, 1})

    def not_applicable_reason(self, target: Path) -> str | None:
        if not any(target.rglob("*.py")):
            return "no Python source files were found"
        return None

    def environment(self) -> CommandEnvironment:
        return CommandEnvironment(
            extra={
                "RUFF_NO_CACHE": "1",
                "RUFF_CACHE_DIR": str(Path(tempfile.gettempdir()) / "pysec-ruff"),
            }
        )

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            executable,
            "check",
            "--isolated",
            "--no-cache",
            "--output-format",
            "json",
            "--select",
            "S",
            "--exclude",
            ".artifacts",
            "--exclude",
            ".pysec-tools",
            "--exclude",
            ".ruff_cache",
            "--exclude",
            "build",
            "--exclude",
            "dist",
            "--exclude",
            "node_modules",
            "--exclude",
            "venv",
            str(target.resolve()),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = json.loads(payload)
        if not isinstance(document, list):
            raise TypeError("Ruff output must be a list")
        findings: list[Finding] = []
        for result in document:
            if not isinstance(result, dict):
                raise TypeError("Ruff result must be an object")
            rule_id = str(result.get("code") or "S000")
            message = str(result.get("message") or rule_id)
            location = result.get("location") or {}
            end = result.get("end_location") or {}
            path = normalize_repo_path(
                target, str(result.get("filename") or "<unknown>")
            )
            line = _integer(location.get("row")) if isinstance(location, dict) else None
            end_line = _integer(end.get("row")) if isinstance(end, dict) else line
            finding_id, fingerprint = finding_identity(
                tool=self.name,
                rule_id=rule_id,
                path=path,
                start_line=line,
            )
            severity, area, classifications = _rule_metadata(rule_id)
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=message,
                    description=message,
                    impact=(
                        "The flagged Python construct can weaken validation, expose "
                        "credentials, or cross a dangerous execution boundary."
                    ),
                    remediation=(
                        "Review the Ruff security rule and replace the construct "
                        "with a safer API or explicit validated behavior."
                    ),
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    area=area,
                    classifications=classifications,
                    locations=[
                        Location(path=path, start_line=line, end_line=end_line)
                    ],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id=rule_id,
                            message=message,
                            native_severity="warning",
                        )
                    ],
                    citations=[
                        Citation(
                            kind="tool_rule",
                            identifier=rule_id,
                            title=message,
                            uri=_safe_uri(result.get("url")),
                        )
                    ],
                )
            )
        return findings


def _rule_metadata(rule_id: str) -> tuple[Severity, str, list[str]]:
    metadata = {
        "S101": (Severity.LOW, "validation", ["CWE-617"]),
        "S102": (Severity.HIGH, "injection", ["CWE-95"]),
        "S105": (Severity.MEDIUM, "secrets", ["CWE-798"]),
        "S106": (Severity.MEDIUM, "secrets", ["CWE-798"]),
        "S107": (Severity.MEDIUM, "secrets", ["CWE-798"]),
        "S301": (Severity.HIGH, "unsafe-deserialization", ["CWE-502"]),
        "S302": (Severity.HIGH, "unsafe-deserialization", ["CWE-502"]),
        "S307": (Severity.HIGH, "injection", ["CWE-95"]),
        "S324": (Severity.MEDIUM, "cryptography", ["CWE-327"]),
        "S506": (Severity.HIGH, "unsafe-deserialization", ["CWE-502"]),
        "S602": (Severity.HIGH, "process-execution", ["CWE-78"]),
        "S603": (Severity.MEDIUM, "process-execution", ["CWE-78"]),
        "S608": (Severity.MEDIUM, "injection", ["CWE-89"]),
        "S609": (Severity.HIGH, "process-execution", ["CWE-78"]),
    }
    return metadata.get(
        rule_id, (Severity.MEDIUM, "python-code", [])
    )


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _safe_uri(value: Any) -> str | None:
    text = str(value or "")
    return text if text.startswith(("https://", "http://")) else None
