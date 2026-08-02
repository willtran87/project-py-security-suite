from __future__ import annotations

import json
from pathlib import Path

from ..models import Citation, Confidence, Finding, Location, Severity, Source
from ..models import finding_identity, normalize_repo_path
from .base import ScannerAdapter
from .common import map_severity
from .staging import maintained_repository_files


class ShellCheckAdapter(ScannerAdapter):
    name = "shellcheck"
    accepted_exit_codes = frozenset({0, 1})

    def _scripts(self, target: Path) -> list[Path]:
        scripts: list[Path] = []
        for path in maintained_repository_files(target):
            if path.suffix.casefold() in {".sh", ".bash", ".dash", ".ksh"}:
                scripts.append(path.resolve())
                continue
            if path.suffix:
                continue
            try:
                first_line = (
                    path.open("rb").readline(256).decode("utf-8", errors="ignore")
                )
            except OSError:
                continue
            if first_line.startswith("#!") and any(
                shell in first_line for shell in ("/sh", "/bash", "/dash", "/ksh")
            ):
                scripts.append(path.resolve())
        return sorted(scripts)

    def not_applicable_reason(self, target: Path) -> str | None:
        return (
            None if self._scripts(target) else "no supported shell scripts were found"
        )

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            executable,
            "--format=json1",
            "--severity=style",
            *(str(path) for path in self._scripts(target)),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        results = json.loads(payload or "[]")
        if not isinstance(results, list):
            raise TypeError("ShellCheck output must be a list")
        findings: list[Finding] = []
        for result in results:
            if not isinstance(result, dict):
                raise TypeError("ShellCheck finding must be an object")
            code = str(result.get("code") or "unknown")
            rule_id = f"SC{code}" if not code.upper().startswith("SC") else code.upper()
            message = str(result.get("message") or rule_id)
            path = normalize_repo_path(
                target, str(result.get("file") or "<repository>")
            )
            line = _integer(result.get("line"))
            end_line = _integer(result.get("endLine")) or line
            level = str(result.get("level") or "warning")
            finding_id, fingerprint = finding_identity(
                tool=self.name, rule_id=rule_id, path=path, start_line=line
            )
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=f"Shell safety: {message}",
                    description=message,
                    impact="The shell construct can produce unsafe expansion, injection, data loss, or behavior that differs across environments.",
                    remediation="Apply ShellCheck's rule guidance at the cited location, preserve argument boundaries, and test the script with representative hostile input.",
                    severity=map_severity(level, default=Severity.MEDIUM),
                    confidence=Confidence.HIGH,
                    area="shell-safety",
                    domain="security",
                    classifications=[rule_id],
                    locations=[Location(path=path, start_line=line, end_line=end_line)],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id=rule_id,
                            message=message,
                            native_severity=level,
                        )
                    ],
                    citations=[
                        Citation(
                            kind="tool_rule",
                            identifier=rule_id,
                            title=f"ShellCheck {rule_id}",
                            uri=f"https://www.shellcheck.net/wiki/{rule_id}",
                        )
                    ],
                )
            )
        return findings


def _integer(value: object) -> int | None:
    try:
        return None if value is None else int(str(value))
    except (TypeError, ValueError):
        return None
