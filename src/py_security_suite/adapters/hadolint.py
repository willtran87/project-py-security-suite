from __future__ import annotations

import json
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
from .common import map_severity
from .staging import maintained_repository_files


class HadolintAdapter(ScannerAdapter):
    name = "hadolint"
    accepted_exit_codes = frozenset({0, 1})

    def _dockerfiles(self, target: Path) -> list[Path]:
        return sorted(
            path
            for path in maintained_repository_files(target)
            if path.name == "Dockerfile" or path.suffix.casefold() == ".dockerfile"
        )

    def not_applicable_reason(self, target: Path) -> str | None:
        if not self._dockerfiles(target):
            return "no Dockerfiles were found"
        return None

    def prerequisite_error(self) -> str | None:
        rules = self.config.rules_path
        if rules is None or not rules.expanduser().resolve().is_file():
            return "the suite-controlled Hadolint configuration file is required"
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        rules = self.config.rules_path
        if rules is None:
            raise ValueError("Hadolint rules path was not configured")
        return [
            executable,
            "--config",
            str(rules.expanduser().resolve()),
            "--format",
            "json",
            *(str(path.resolve()) for path in self._dockerfiles(target)),
        ]

    def version_command(self, executable: str) -> list[str]:
        rules = self.config.rules_path
        if rules is None:
            return super().version_command(executable)
        return [
            executable,
            "--config",
            str(rules.expanduser().resolve()),
            "--version",
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        results = json.loads(payload or "[]")
        if not isinstance(results, list):
            raise TypeError("Hadolint output must be a JSON list")
        findings: list[Finding] = []
        for result in results:
            if not isinstance(result, dict):
                raise TypeError("Hadolint finding must be an object")
            rule_id = str(result.get("code") or "dockerfile")
            message = str(result.get("message") or rule_id)
            path = normalize_repo_path(
                target, str(result.get("file") or "<repository>")
            )
            line = _integer(result.get("line"))
            native_severity = str(result.get("level") or "warning")
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
                    title=f"Dockerfile hardening: {message}",
                    description=message,
                    impact=(
                        "The container build may be less reproducible, run with excess "
                        "privilege, or introduce avoidable supply-chain and runtime risk."
                    ),
                    remediation=(
                        "Apply the cited Hadolint rule, rebuild the image from pinned "
                        "inputs, and validate its effective runtime permissions."
                    ),
                    severity=map_severity(
                        native_severity, default=Severity.INFORMATIONAL
                    ),
                    confidence=Confidence.HIGH,
                    area="container-hardening",
                    classifications=[f"HADOLINT-{rule_id}"],
                    locations=[Location(path=path, start_line=line, end_line=line)],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id=rule_id,
                            message=message,
                            native_severity=native_severity,
                        )
                    ],
                    citations=[
                        Citation(
                            kind="tool_rule",
                            identifier=rule_id,
                            title=f"Hadolint {rule_id}",
                            uri=f"https://github.com/hadolint/hadolint/wiki/{rule_id}",
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
