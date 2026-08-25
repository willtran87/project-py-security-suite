from __future__ import annotations

import re
from pathlib import Path

from ..execution import CommandEnvironment, RawExecution
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
from .staging import maintained_files

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_VIOLATION = re.compile(
    r"^(?:\[[A-Z]+\]\s*)?(?P<path>.+?)"
    r"(?:\[L(?P<bracket_line>\d+)\]|:(?P<colon_line>\d+)):"
    r"\s*(?P<message>.+)$"
)


class TachAdapter(ScannerAdapter):
    """Enforce repository-owned Python module architecture contracts."""

    name = "tach"
    accepted_exit_codes = frozenset({0, 1})

    def not_applicable_reason(self, target: Path) -> str | None:
        if not maintained_files(target, frozenset({".py"})):
            return "no Python source files were found"
        if not (target / "tach.toml").is_file():
            return "no repository Tach architecture contract was found (tach.toml)"
        return None

    def environment(self) -> CommandEnvironment:
        return CommandEnvironment(extra={"NO_COLOR": "1"})

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            executable,
            "check",
            "--exclude",
            ".artifacts,.pysec-tools,.venv,build,dist,node_modules",
        ]

    def result_payload(self, execution: RawExecution) -> str:
        """Tach 0.35 writes contract violations to stderr."""
        return "\n".join(
            value for value in (execution.stdout, execution.stderr) if value
        )

    def parse(self, payload: str, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        unexpected_locations: list[str] = []
        for raw_line in payload.splitlines():
            line = _ANSI.sub("", raw_line).strip()
            if not line:
                continue
            if "\x00" in line:
                raise ValueError("Tach output contains a NUL byte")
            match = _VIOLATION.match(line)
            if match is None:
                if "[L" in line or line.startswith("[FAIL]"):
                    unexpected_locations.append(line)
                continue
            path = normalize_repo_path(target, match.group("path"))
            start_line = int(match.group("bracket_line") or match.group("colon_line"))
            message = match.group("message").strip()
            rule_id = _rule_id(message)
            finding_id, fingerprint = finding_identity(
                tool=self.name,
                rule_id=rule_id,
                path=path,
                start_line=start_line,
            )
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=f"Architecture contract violation: {_title(message)}",
                    description=message,
                    impact=(
                        "The import breaks an explicit module boundary, public API, "
                        "or dependency direction and increases coupling and change "
                        "risk across the repository."
                    ),
                    remediation=(
                        "Move the dependency behind the permitted public interface, "
                        "reverse or remove the coupling, or update tach.toml only "
                        "after an intentional architecture review."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    area="architecture",
                    domain="quality",
                    classifications=[f"TACH-{rule_id.upper()}"],
                    locations=[
                        Location(
                            path=path,
                            start_line=start_line,
                            end_line=start_line,
                        )
                    ],
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
                            title="Tach architecture checks",
                            uri="https://docs.gauge.sh/usage/commands/#tach-check",
                        )
                    ],
                )
            )
        if unexpected_locations:
            raise ValueError(
                f"unexpected Tach location output: {unexpected_locations[0][:160]}"
            )
        return findings


def _rule_id(message: str) -> str:
    lowered = message.casefold()
    if "public interface" in lowered or "not public" in lowered:
        return "public-interface"
    if "cycle" in lowered or "cyclic" in lowered:
        return "dependency-cycle"
    if "unused" in lowered and "depend" in lowered:
        return "unused-dependency"
    if "cannot depend" in lowered or "cannot import" in lowered:
        return "forbidden-dependency"
    return "architecture-contract"


def _title(message: str) -> str:
    return message if len(message) <= 120 else message[:117] + "..."
