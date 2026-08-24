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
from ..strict_json import loads as strict_json_loads
from .base import ScannerAdapter


class ActionlintAdapter(ScannerAdapter):
    name = "actionlint"
    accepted_exit_codes = frozenset({0, 1})

    def _workflows(self, target: Path) -> list[Path]:
        directory = target / ".github" / "workflows"
        if not directory.is_dir():
            return []
        return sorted(
            path
            for path in directory.iterdir()
            if path.is_file() and path.suffix.casefold() in {".yml", ".yaml"}
        )

    def not_applicable_reason(self, target: Path) -> str | None:
        if not self._workflows(target):
            return "no GitHub Actions workflow files were found"
        return None

    def prerequisite_error(self) -> str | None:
        rules = self.config.rules_path
        if rules is None or not rules.expanduser().resolve().is_file():
            return "the suite-controlled actionlint configuration file is required"
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        rules = self.config.rules_path
        if rules is None:
            raise ValueError("actionlint rules path was not configured")
        return [
            executable,
            "-no-color",
            "-format",
            "{{json .}}",
            "-config-file",
            str(rules.expanduser().resolve()),
            "-shellcheck",
            "",
            "-pyflakes",
            "",
            *(str(path.resolve()) for path in self._workflows(target)),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        results = strict_json_loads(payload or "[]")
        if not isinstance(results, list):
            raise TypeError("actionlint output must be a JSON list")
        findings: list[Finding] = []
        for result in results:
            if not isinstance(result, dict):
                raise TypeError("actionlint finding must be an object")
            rule_id = str(result.get("kind") or "workflow")
            message = str(result.get("message") or rule_id)
            path = normalize_repo_path(
                target, str(result.get("filepath") or "<repository>")
            )
            line = _integer(result.get("line"))
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
                    title=f"Workflow validation: {message}",
                    description=message,
                    impact=(
                        "An invalid or ambiguous workflow can bypass intended checks, "
                        "break release controls, or behave differently than reviewers expect."
                    ),
                    remediation=(
                        "Correct the workflow at the cited location and rerun actionlint "
                        "before merging the workflow change."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    area="ci-cd-correctness",
                    domain="quality",
                    classifications=[f"ACTIONLINT-{rule_id.upper()}"],
                    locations=[Location(path=path, start_line=line, end_line=line)],
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
                            title="actionlint checks",
                            uri=(
                                "https://github.com/rhysd/actionlint/"
                                "blob/main/docs/checks.md"
                            ),
                        )
                    ],
                )
            )
        return findings


def _integer(value: object) -> int | None:
    try:
        return int(str(value)) if value is not None else None
    except (TypeError, ValueError):
        return None
