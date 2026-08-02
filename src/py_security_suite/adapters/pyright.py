from __future__ import annotations

import json
from pathlib import Path

from ..models import Citation, Confidence, Finding, Location, Severity, Source
from ..models import finding_identity, normalize_repo_path
from .base import ScannerAdapter
from .common import map_severity
from .staging import maintained_files


class PyrightAdapter(ScannerAdapter):
    name = "pyright"
    accepted_exit_codes = frozenset({0, 1})

    def not_applicable_reason(self, target: Path) -> str | None:
        return (
            None
            if maintained_files(target, frozenset({".py"}))
            else "no Python source files were found"
        )

    def prerequisite_error(self) -> str | None:
        cli = self.config.database_path
        if cli is None or not cli.expanduser().resolve().is_file():
            return "the staged Pyright CLI JavaScript entry point is required in database_path"
        rules = self.config.rules_path
        if rules is None or not rules.expanduser().resolve().is_file():
            return "the approved Pyright configuration is required in rules_path"
        return None

    def version_command(self, executable: str) -> list[str]:
        cli = self.config.database_path
        if cli is None:
            raise ValueError("Pyright CLI path was not configured")
        return [executable, str(cli.expanduser().resolve()), "--version"]

    def build_command(self, executable: str, target: Path) -> list[str]:
        cli = self.config.database_path
        if cli is None:
            raise ValueError("Pyright CLI path was not configured")
        rules = self.config.rules_path
        if rules is None:
            raise ValueError("Pyright configuration was not configured")
        command = [
            executable,
            str(cli.expanduser().resolve()),
            "--outputjson",
            "--project",
            str(rules.expanduser().resolve()),
        ]
        source_root = target / "src"
        command.append(str((source_root if source_root.is_dir() else target).resolve()))
        return command

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = json.loads(payload)
        if not isinstance(document, dict):
            raise TypeError("Pyright output must be an object")
        diagnostics = document.get("generalDiagnostics", [])
        if not isinstance(diagnostics, list):
            raise TypeError("Pyright generalDiagnostics must be a list")
        findings: list[Finding] = []
        for diagnostic in diagnostics:
            if not isinstance(diagnostic, dict):
                raise TypeError("Pyright diagnostic must be an object")
            range_value = diagnostic.get("range", {})
            start = (
                range_value.get("start", {}) if isinstance(range_value, dict) else {}
            )
            end = range_value.get("end", {}) if isinstance(range_value, dict) else {}
            rule_id = str(diagnostic.get("rule") or "type-checking")
            message = str(diagnostic.get("message") or rule_id)
            path = normalize_repo_path(
                target, str(diagnostic.get("file") or "<repository>")
            )
            line = _one_based(start.get("line") if isinstance(start, dict) else None)
            end_line = (
                _one_based(end.get("line") if isinstance(end, dict) else None) or line
            )
            native_severity = str(diagnostic.get("severity") or "error")
            finding_id, fingerprint = finding_identity(
                tool=self.name, rule_id=rule_id, path=path, start_line=line
            )
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=f"Pyright type analysis: {_summary(message)}",
                    description=message,
                    impact="The incompatible or ambiguous type relationship can conceal invalid state and error paths in production code.",
                    remediation="Correct the implementation or declared contract, add a narrowly justified suppression only when necessary, and rerun both Pyright and mypy.",
                    severity=_severity(native_severity),
                    confidence=Confidence.HIGH,
                    area="type-safety",
                    domain="quality",
                    classifications=[f"PYRIGHT-{rule_id.upper()}"],
                    locations=[Location(path=path, start_line=line, end_line=end_line)],
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
                            title=f"Pyright diagnostic {rule_id}",
                            uri="https://github.com/microsoft/pyright/blob/main/docs/configuration.md#diagnostic-settings-defaults",
                        )
                    ],
                )
            )
        return findings


def _one_based(value: object) -> int | None:
    try:
        return None if value is None else int(str(value)) + 1
    except (TypeError, ValueError):
        return None


def _severity(value: str) -> Severity:
    return {
        "error": Severity.MEDIUM,
        "warning": Severity.LOW,
        "information": Severity.INFORMATIONAL,
    }.get(value.casefold(), map_severity(value, default=Severity.MEDIUM))


def _summary(message: str) -> str:
    first_line = message.splitlines()[0].strip()
    return first_line if len(first_line) <= 140 else f"{first_line[:137]}..."
