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
from .staging import maintained_files


class MypyAdapter(ScannerAdapter):
    name = "mypy"
    accepted_exit_codes = frozenset({0, 1})

    def not_applicable_reason(self, target: Path) -> str | None:
        if not maintained_files(target, frozenset({".py"})):
            return "no Python source files were found"
        return None

    def prerequisite_error(self) -> str | None:
        rules = self.config.rules_path
        if rules is None or not rules.expanduser().resolve().is_file():
            return "the suite-controlled mypy configuration file is required"
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        rules = self.config.rules_path
        if rules is None:
            raise ValueError("mypy rules path was not configured")
        return [
            executable,
            "--output",
            "json",
            "--config-file",
            str(rules.expanduser().resolve()),
            "--no-incremental",
            "--no-site-packages",
            "--ignore-missing-imports",
            "--follow-imports=normal",
            "--show-error-codes",
            "--show-column-numbers",
            "--no-error-summary",
            "--no-pretty",
            "--no-color-output",
            "--exclude",
            r"(^|[\\/])(\.artifacts|\.pysec-tools|\.venv|build|dist|node_modules)([\\/]|$)",
            str(target.resolve()),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        for line in payload.splitlines():
            if not line.strip():
                continue
            result = strict_json_loads(line)
            if not isinstance(result, dict):
                raise TypeError("mypy JSON line must be an object")
            rule_id = str(result.get("code") or "type-checking")
            message = str(result.get("message") or rule_id)
            path = normalize_repo_path(
                target, str(result.get("file") or "<repository>")
            )
            start_line = _integer(result.get("line"))
            end_line = _integer(result.get("end_line")) or start_line
            finding_id, fingerprint = finding_identity(
                tool=self.name,
                rule_id=rule_id,
                path=path,
                start_line=start_line,
            )
            native_severity = str(result.get("severity") or "error")
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=f"Type checking: {message}",
                    description=message,
                    impact=(
                        "The incompatible or ambiguous type relationship can hide "
                        "incorrect state transitions and error paths during review."
                    ),
                    remediation=(
                        "Correct the annotated contract or implementation, avoid an "
                        "unscoped ignore, and rerun mypy with the suite configuration."
                    ),
                    severity=(
                        Severity.MEDIUM if native_severity == "error" else Severity.LOW
                    ),
                    confidence=Confidence.HIGH,
                    area="type-safety",
                    domain="quality",
                    classifications=[f"MYPY-{rule_id.upper()}"],
                    locations=[
                        Location(
                            path=path,
                            start_line=start_line,
                            end_line=end_line,
                        )
                    ],
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
                            title=f"mypy error code {rule_id}",
                            uri=(
                                "https://mypy.readthedocs.io/en/stable/"
                                "error_code_list.html"
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
