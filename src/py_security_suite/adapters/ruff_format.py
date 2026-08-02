from __future__ import annotations

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
from .ruff import RuffAdapter


class RuffFormatAdapter(RuffAdapter):
    name = "ruff-format"

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            executable,
            "format",
            "--check",
            "--no-cache",
            "--isolated",
            "--exclude",
            ".artifacts",
            "--exclude",
            ".pysec-tools",
            "--exclude",
            ".venv",
            "--exclude",
            "build",
            "--exclude",
            "dist",
            "--exclude",
            "node_modules",
            str(target.resolve()),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        for raw_line in payload.splitlines():
            line = raw_line.strip()
            if not line.startswith("Would reformat: "):
                continue
            path = normalize_repo_path(target, line.removeprefix("Would reformat: "))
            finding_id, fingerprint = finding_identity(
                tool=self.name,
                rule_id="format-drift",
                path=path,
            )
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=f"Python formatting drift: {path}",
                    description="Ruff would reformat this Python file.",
                    impact=(
                        "Formatting drift creates review noise, hides meaningful "
                        "changes, and makes automated maintenance less predictable."
                    ),
                    remediation=(
                        "Run the approved Ruff formatter, review the resulting diff, "
                        "and commit the formatting-only change."
                    ),
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                    area="formatting",
                    domain="quality",
                    classifications=["RUFF-FORMAT"],
                    locations=[Location(path=path)],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id="format-drift",
                            message="file would be reformatted",
                            native_severity="change-required",
                        )
                    ],
                    citations=[
                        Citation(
                            kind="tool_rule",
                            identifier="format-drift",
                            title="Ruff formatter",
                            uri="https://docs.astral.sh/ruff/formatter/",
                        )
                    ],
                )
            )
        return findings
