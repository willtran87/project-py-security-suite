from __future__ import annotations

import re
from pathlib import Path

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
from .staging import maintained_files

_RESULT = re.compile(
    r"^(?P<path>.+):(?P<line>\d+): (?P<message>.+) "
    r"\((?P<confidence>\d+)% confidence\)$"
)


class VultureAdapter(ScannerAdapter):
    name = "vulture"
    accepted_exit_codes = frozenset({0, 1})

    def not_applicable_reason(self, target: Path) -> str | None:
        if not maintained_files(target, frozenset({".py"})):
            return "no Python source files were found"
        return None

    def prerequisite_error(self) -> str | None:
        rules = self.config.rules_path
        if rules is None or not rules.expanduser().resolve().is_file():
            return "the suite-controlled Vulture configuration file is required"
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        rules = self.config.rules_path
        if rules is None:
            raise ValueError("Vulture rules path was not configured")
        return [
            executable,
            "--config",
            str(rules.expanduser().resolve()),
            "--min-confidence",
            "100",
            "--exclude",
            ".artifacts,.pysec-tools,.venv,build,dist,node_modules",
            str(target.resolve()),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        for raw_line in payload.splitlines():
            if not raw_line.strip():
                continue
            match = _RESULT.match(raw_line.strip())
            if match is None:
                raise ValueError(f"unexpected Vulture output line: {raw_line[:120]}")
            message = match.group("message")
            path = normalize_repo_path(target, match.group("path"))
            line = int(match.group("line"))
            rule_id = _rule_id(message)
            finding_id, fingerprint = finding_identity(
                tool=self.name,
                rule_id=rule_id,
                path=path,
                start_line=line,
            )
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=f"Dead code: {message}",
                    description=message,
                    impact=(
                        "Unreachable or certainly unused code expands review and "
                        "maintenance surface and can preserve obsolete security logic."
                    ),
                    remediation=(
                        "Confirm the code is not reached through framework conventions, "
                        "then remove it or add a narrowly reviewed Vulture allowlist."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    area="dead-code",
                    domain="quality",
                    classifications=[f"VULTURE-{rule_id.upper()}"],
                    locations=[Location(path=path, start_line=line, end_line=line)],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id=rule_id,
                            message=message,
                            native_severity="100-percent-confidence",
                        )
                    ],
                    citations=[
                        Citation(
                            kind="tool_rule",
                            identifier=rule_id,
                            title="Vulture dead-code analysis",
                            uri="https://github.com/jendrikseipp/vulture",
                        )
                    ],
                    evidence={"confidence_percent": int(match.group("confidence"))},
                )
            )
        return findings


def _rule_id(message: str) -> str:
    match = re.match(r"unused ([A-Za-z_-]+)", message.casefold())
    if match:
        return f"unused-{match.group(1)}"
    if message.casefold().startswith("unreachable"):
        return "unreachable-code"
    return "dead-code"
