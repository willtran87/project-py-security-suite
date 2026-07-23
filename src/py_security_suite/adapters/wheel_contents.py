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
from .artifacts import wheel_files
from .base import ScannerAdapter


_ISSUE = re.compile(r"^(?P<path>.+?):\s+(?P<rule>W\d{3}):\s+(?P<message>.+)$")


class CheckWheelContentsAdapter(ScannerAdapter):
    name = "check-wheel-contents"
    accepted_exit_codes = frozenset({0, 1})

    def not_applicable_reason(self, target: Path) -> str | None:
        if not wheel_files(target, self.config):
            return "no built wheel was found"
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            executable,
            "--no-config",
            *(str(path) for path in wheel_files(target, self.config)),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        for line in payload.splitlines():
            match = _ISSUE.match(line.strip())
            if match is None:
                continue
            rule_id = match.group("rule")
            message = match.group("message")
            path = normalize_repo_path(target, match.group("path"))
            finding_id, fingerprint = finding_identity(
                tool=self.name, rule_id=rule_id, path=path
            )
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=f"Wheel content problem: {message}",
                    description=(
                        "check-wheel-contents identified an unexpected, missing, "
                        "duplicated, or otherwise incorrect wheel member."
                    ),
                    impact=(
                        "A malformed or over-inclusive release wheel can ship unintended "
                        "code, data, tests, bytecode, or packaging metadata."
                    ),
                    remediation=(
                        "Correct the build configuration, rebuild the wheel from a clean "
                        "tree, and repeat the artifact scan."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    area="artifact-integrity",
                    classifications=[rule_id],
                    locations=[Location(path=path)],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id=rule_id,
                            message=message,
                            native_severity="error",
                        )
                    ],
                    citations=[
                        Citation(
                            kind="tool_rule",
                            identifier=rule_id,
                            title=message,
                            uri=(
                                "https://github.com/jwodder/check-wheel-contents"
                                f"#{rule_id.lower()}"
                            ),
                        )
                    ],
                )
            )
        return findings

