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
from .artifacts import artifact_identity_evidence, distribution_files
from .base import ScannerAdapter


_TWINE_ISSUE = re.compile(
    r"^(?P<level>ERROR|WARNING)\s+(?P<message>.+)$",
    re.IGNORECASE,
)
_CHECKING = re.compile(
    r"^Checking\s+(?P<path>.+?):\s*(?P<status>PASSED|FAILED|WARNING)",
    re.IGNORECASE,
)


class TwineAdapter(ScannerAdapter):
    name = "twine"
    accepted_exit_codes = frozenset({0, 1})

    def not_applicable_reason(self, target: Path) -> str | None:
        if not distribution_files(target, self.config):
            return "no built wheel or source distribution was found"
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            executable,
            "check",
            "--strict",
            *(str(path) for path in distribution_files(target, self.config)),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        identities = {
            normalize_repo_path(target, artifact): artifact_identity_evidence(
                target, artifact
            )
            for artifact in distribution_files(target, self.config)
        }
        current_path = "<distribution>"
        for line in payload.splitlines():
            stripped = line.strip()
            checking = _CHECKING.match(stripped)
            if checking is not None:
                current_path = checking.group("path")
                continue
            match = _TWINE_ISSUE.match(stripped)
            if match is None:
                continue
            level = match.group("level").upper()
            message = match.group("message")
            path = normalize_repo_path(target, current_path)
            rule_id = f"twine-{level.casefold()}"
            finding_id, fingerprint = finding_identity(
                tool=self.name, rule_id=rule_id, path=path
            )
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=f"Distribution metadata {level.casefold()}: {message}",
                    description=(
                        "Twine could not validate the distribution metadata and "
                        "long-description rendering without a warning or error."
                    ),
                    impact=(
                        "Invalid or misleading package metadata can block publication "
                        "and make release provenance and ownership harder to assess."
                    ),
                    remediation=(
                        "Correct the package metadata, rebuild from a clean tree, and "
                        "rerun `twine check --strict`."
                    ),
                    severity=(Severity.MEDIUM if level == "ERROR" else Severity.LOW),
                    confidence=Confidence.HIGH,
                    area="artifact-metadata",
                    classifications=["PYPA-PACKAGE-METADATA"],
                    locations=[Location(path=path)],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id=rule_id,
                            message=message,
                            native_severity=level.casefold(),
                        )
                    ],
                    citations=[
                        Citation(
                            kind="tool_rule",
                            identifier=rule_id,
                            title="Twine distribution checks",
                            uri="https://twine.readthedocs.io/en/stable/#twine-check",
                        )
                    ],
                    evidence=identities.get(path, {}),
                )
            )
        return findings
