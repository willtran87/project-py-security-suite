from __future__ import annotations

import json
from pathlib import Path

from ..models import Citation, Confidence, Finding, Location, Severity, Source
from ..models import finding_identity
from .artifacts import configured_path
from .base import ScannerAdapter


class ScorecardAdapter(ScannerAdapter):
    """Ingest connected-lane OpenSSF Scorecard JSON without network access."""

    name = "scorecard"

    def not_applicable_reason(self, target: Path) -> str | None:
        path = configured_path(target, self.config.artifacts_path, "scorecard.json")
        return (
            None
            if path.is_file()
            else "no pre-generated OpenSSF Scorecard JSON evidence was found"
        )

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            executable,
            "scorecard",
            str(configured_path(target, self.config.artifacts_path, "scorecard.json")),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = json.loads(payload)
        if not isinstance(document, dict) or document.get("kind") != "scorecard":
            raise TypeError("validated Scorecard evidence must be an object")
        checks = document.get("checks", [])
        if not isinstance(checks, list):
            raise TypeError("Scorecard checks must be a list")
        findings: list[Finding] = []
        for check in checks:
            if not isinstance(check, dict):
                raise TypeError("Scorecard check must be an object")
            score = _number(check.get("score"))
            if score >= 10:
                continue
            name = str(check.get("name") or "Unknown")
            reason = str(
                check.get("reason") or "Scorecard check did not receive full credit"
            )
            rule_id = f"SCORECARD-{name.upper().replace('_', '-').replace(' ', '-')}"
            finding_id, fingerprint = finding_identity(
                tool=self.name, rule_id=rule_id, path="<repository>"
            )
            documentation = check.get("documentation", {})
            uri = (
                str(
                    documentation.get("url")
                    or "https://github.com/ossf/scorecard/blob/main/docs/checks.md"
                )
                if isinstance(documentation, dict)
                else "https://github.com/ossf/scorecard/blob/main/docs/checks.md"
            )
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=f"Repository governance: {name} scored {score:g}/10",
                    description=reason,
                    impact="The repository control is weaker than the OpenSSF security-health benchmark, reducing confidence in review, release, or dependency governance.",
                    remediation=f"Review the {name} check evidence and implement the cited repository control; regenerate Scorecard evidence in the connected governance lane.",
                    severity=_severity(score),
                    confidence=Confidence.HIGH,
                    area="repository-governance",
                    domain="governance",
                    classifications=[rule_id],
                    locations=[Location(path="<repository>")],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id=name,
                            message=reason,
                            native_severity=f"score-{score:g}",
                        )
                    ],
                    citations=[
                        Citation(
                            kind="tool_rule",
                            identifier=name,
                            title=f"OpenSSF Scorecard {name}",
                            uri=uri,
                        )
                    ],
                    evidence={"score": score, "details": check.get("details", [])},
                )
            )
        return findings


def _number(value: object) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError) as exc:
        raise TypeError(f"invalid Scorecard score: {value!r}") from exc


def _severity(score: float) -> Severity:
    if score < 4:
        return Severity.HIGH
    if score < 7:
        return Severity.MEDIUM
    return Severity.LOW
