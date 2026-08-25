from __future__ import annotations

import tempfile
import uuid
from pathlib import Path
from typing import Any

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
from .base import AdapterResult, ScannerAdapter


class GitleaksAdapter(ScannerAdapter):
    name = "gitleaks"
    accepted_exit_codes = frozenset({0, 1})

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._report_path: Path | None = None
        self._mode = "dir"

    def not_applicable_reason(self, target: Path) -> str | None:
        if not any(path.is_file() for path in target.iterdir()):
            return "the target contains no files to inspect for secret history"
        return None

    def prerequisite_error(self) -> str | None:
        config = self.config.rules_path
        if config is not None and not config.expanduser().resolve().is_file():
            return f"Gitleaks configuration does not exist: {config}"
        return None

    def run(self, target: Path) -> AdapterResult:
        try:
            return super().run(target)
        finally:
            if self._report_path is not None:
                self._report_path.unlink(missing_ok=True)

    def build_command(self, executable: str, target: Path) -> list[str]:
        self._report_path = (
            Path(tempfile.gettempdir()) / f"pysec-gitleaks-{uuid.uuid4().hex}.json"
        )
        self._mode = "git" if (target / ".git").is_dir() else "dir"
        command = [
            executable,
            self._mode,
            "--no-banner",
            "--log-level",
            "error",
            "--redact=100",
            "--report-format",
            "json",
            "--report-path",
            str(self._report_path),
            str(target.resolve()),
        ]
        if self.config.rules_path is not None:
            command[2:2] = [
                "--config",
                str(self.config.rules_path.expanduser().resolve()),
            ]
        return command

    def parse(self, payload: str, target: Path) -> list[Finding]:
        if self._report_path is None:
            raise ValueError("Gitleaks report path was not initialized")
        try:
            if not self._report_path.is_file():
                return []
            document = strict_json_loads(self._report_path.read_text(encoding="utf-8"))
        finally:
            self._report_path.unlink(missing_ok=True)
        if not isinstance(document, list):
            raise TypeError("Gitleaks output must be a list")
        findings: list[Finding] = []
        for result in document:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("RuleID") or "gitleaks.unknown")
            description = str(result.get("Description") or rule_id)
            path = normalize_repo_path(target, str(result.get("File") or "<unknown>"))
            line = _integer(result.get("StartLine"))
            commit = str(result.get("Commit") or "")
            finding_id, fingerprint = finding_identity(
                tool=self.name,
                rule_id=rule_id,
                path=path,
                start_line=line,
                advisory=commit or None,
            )
            historical = self._mode == "git"
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=(
                        "Credential candidate in repository history: "
                        if historical
                        else "Credential candidate in current tree: "
                    )
                    + description,
                    description=(
                        "Gitleaks identified a credential-shaped value. The value "
                        "was fully redacted before the suite parsed the result."
                    ),
                    impact=(
                        "A credential in the current tree or Git history may be "
                        "recoverable and usable by an unauthorized party."
                    ),
                    remediation=(
                        "Confirm the candidate without copying it into tickets, revoke "
                        "and rotate real credentials, remove them from history where "
                        "required, and add a narrowly governed allowlist for test data."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    area="secrets-history",
                    classifications=["CWE-798"],
                    locations=[Location(path=path, start_line=line, end_line=line)],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id=rule_id,
                            message=description,
                            native_severity="secret",
                        )
                    ],
                    citations=[
                        Citation(
                            kind="tool_rule",
                            identifier=rule_id,
                            title=description,
                            uri="https://github.com/gitleaks/gitleaks",
                        )
                    ],
                    evidence={
                        "redacted": True,
                        "scan_mode": self._mode,
                        "commit": commit[:64] if commit else None,
                    },
                )
            )
        return findings


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
