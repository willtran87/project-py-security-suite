from __future__ import annotations

from pathlib import Path

from ..models import Finding, Severity
from .ruff import RuffAdapter


class RuffQualityAdapter(RuffAdapter):
    """Use Ruff's stable correctness-oriented rules without duplicating SAST."""

    name = "ruff-quality"

    def build_command(self, executable: str, target: Path) -> list[str]:
        command = super().build_command(executable, target)
        command[command.index("S")] = "E9,F,B,C90,PERF,RUF,UP"
        command[2:2] = [
            "--config",
            "lint.mccabe.max-complexity=20",
            "--ignore",
            # Preserve suppressions owned by the separate security rule pass.
            "RUF100",
        ]
        return command

    def parse(self, payload: str, target: Path) -> list[Finding]:
        findings = super().parse(payload, target)
        for finding in findings:
            rule_id = finding.sources[0].rule_id
            finding.domain = "quality"
            finding.area = _area(rule_id)
            finding.severity = _severity(rule_id)
            finding.classifications = [_classification(rule_id)]
            finding.impact = (
                "The flagged construct increases defect probability, obscures "
                "control flow, or makes security-sensitive code harder to review."
            )
            finding.remediation = (
                "Apply the cited Ruff rule, preserve behavior with tests, and "
                "rerun the repository quality profile."
            )
        return findings


def _area(rule_id: str) -> str:
    if rule_id.startswith("C90"):
        return "complexity"
    if rule_id.startswith("PERF"):
        return "performance"
    if rule_id.startswith("UP"):
        return "compatibility"
    return "code-correctness"


def _severity(rule_id: str) -> Severity:
    if rule_id.startswith(("E9", "F", "B", "RUF")):
        return Severity.MEDIUM
    return Severity.LOW


def _classification(rule_id: str) -> str:
    prefixes = {
        "E": "PYCODESTYLE",
        "F": "PYFLAKES",
        "B": "BUGBEAR",
        "C": "MCCABE",
        "PERF": "PERFLINT",
        "RUF": "RUFF",
        "UP": "PYUPGRADE",
    }
    prefix = next(
        (value for key, value in prefixes.items() if rule_id.startswith(key)),
        "RUFF",
    )
    return f"{prefix}-{rule_id}"
