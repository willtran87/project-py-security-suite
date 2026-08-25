from __future__ import annotations

from pathlib import Path
from typing import Any

from ..config import ToolConfig
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
from .staging import maintained_files, mirrored_source_tree


class PylintAdapter(ScannerAdapter):
    name = "pylint"
    accepted_exit_codes = frozenset(range(32))

    def __init__(self, config: ToolConfig, max_output_bytes: int) -> None:
        super().__init__(config, max_output_bytes)
        self._scan_root: Path | None = None

    def not_applicable_reason(self, target: Path) -> str | None:
        if not maintained_files(target, frozenset({".py"})):
            return "no Python source files were found"
        return None

    def prerequisite_error(self) -> str | None:
        rules = self.config.rules_path
        if rules is None or not rules.expanduser().resolve().is_file():
            return "the suite-controlled Pylint configuration file is required"
        return None

    def run(self, target: Path) -> AdapterResult:
        with mirrored_source_tree(target) as mirror:
            self._scan_root = mirror
            try:
                return super().run(target)
            finally:
                self._scan_root = None

    def build_command(self, executable: str, target: Path) -> list[str]:
        rules = self.config.rules_path
        if rules is None:
            raise ValueError("Pylint rules path was not configured")
        return [
            executable,
            "--rcfile",
            str(rules.expanduser().resolve()),
            "--output-format=json2",
            "--reports=no",
            "--score=yes",
            "--persistent=no",
            "--jobs=1",
            "--recursive=y",
            str(self._scan_root or target.resolve()),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = strict_json_loads(payload)
        if not isinstance(document, dict) or not isinstance(
            document.get("messages"), list
        ):
            raise TypeError("Pylint json2 output must contain a messages list")
        findings: list[Finding] = []
        for result in document["messages"]:
            if not isinstance(result, dict):
                raise TypeError("Pylint message must be an object")
            rule_id = str(
                result.get("messageId") or result.get("message-id") or "unknown"
            )
            symbol = str(result.get("symbol") or rule_id)
            message = str(result.get("message") or symbol)
            native_type = str(result.get("type") or "warning").casefold()
            path = self._normalize_path(target, result)
            line = _integer(result.get("line"))
            end_line = _integer(result.get("endLine")) or line
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
                    title=f"Pylint: {message}",
                    description=message,
                    impact=(
                        "The inferred defect or design smell increases failure risk, "
                        "obscures behavior, or makes security-sensitive code harder "
                        "to change safely."
                    ),
                    remediation=(
                        "Apply the cited Pylint guidance, preserve intended behavior "
                        "with tests, and use a narrow documented suppression only when "
                        "the construct is intentional."
                    ),
                    severity=_severity(native_type),
                    confidence=Confidence.HIGH,
                    area=_area(symbol),
                    domain="quality",
                    classifications=[f"PYLINT-{rule_id.upper()}"],
                    locations=[Location(path=path, start_line=line, end_line=end_line)],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id=rule_id,
                            message=message,
                            native_severity=native_type,
                        )
                    ],
                    citations=[
                        Citation(
                            kind="tool_rule",
                            identifier=rule_id,
                            title=f"Pylint {symbol}",
                            uri=(
                                "https://pylint.readthedocs.io/en/latest/"
                                f"user_guide/messages/{native_type}/{symbol}.html"
                            ),
                        )
                    ],
                )
            )
        return findings

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        document = strict_json_loads(payload)
        return {
            "pylint-summary.json": {
                "schema_version": "1.0",
                "score": document.get("score"),
                "statistics": document.get("statistics", {}),
                "message_count": len(document.get("messages", [])),
            }
        }

    def _normalize_path(self, target: Path, result: dict[str, Any]) -> str:
        value = str(result.get("absolutePath") or result.get("path") or "")
        candidate = Path(value)
        scan_root = self._scan_root
        if scan_root is not None:
            try:
                return candidate.resolve().relative_to(scan_root.resolve()).as_posix()
            except (OSError, ValueError):
                pass
        return normalize_repo_path(target, value or "<repository>")


def _integer(value: object) -> int | None:
    try:
        return int(str(value)) if value is not None else None
    except (TypeError, ValueError):
        return None


def _severity(native_type: str) -> Severity:
    if native_type in {"fatal", "error"}:
        return Severity.MEDIUM
    if native_type == "warning":
        return Severity.LOW
    return Severity.INFORMATIONAL


def _area(symbol: str) -> str:
    if "exception" in symbol or symbol.startswith(("raise", "broad-")):
        return "exception-handling"
    if symbol.startswith("logging"):
        return "logging"
    if any(token in symbol for token in ("argument", "parameter", "return")):
        return "api-contract"
    if symbol.startswith("too-many") or "nested" in symbol:
        return "design-complexity"
    return "code-correctness"
