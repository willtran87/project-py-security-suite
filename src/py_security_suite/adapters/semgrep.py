from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from ..execution import CommandEnvironment
from ..models import (
    Citation,
    Finding,
    Location,
    Source,
    finding_identity,
    normalize_repo_path,
)
from .base import ScannerAdapter
from .common import map_confidence, map_severity, string_list


class SemgrepAdapter(ScannerAdapter):
    name = "semgrep"

    def environment(self) -> CommandEnvironment:
        temporary_root = Path(tempfile.gettempdir()) / "pysec-semgrep"
        home = temporary_root / "home"
        return CommandEnvironment(
            extra={
                "HOME": str(home),
                "USERPROFILE": str(home),
                "XDG_CACHE_HOME": str(temporary_root / "cache"),
            }
        )

    def prerequisite_error(self) -> str | None:
        rules = self.config.rules_path
        if rules is None:
            return "a local Semgrep rules_path is required"
        if not rules.expanduser().resolve().exists():
            return f"local Semgrep rules do not exist: {rules}"
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        rules_path = self.config.rules_path
        if rules_path is None:
            raise ValueError("a local Semgrep rules_path is required")
        return [
            executable,
            "scan",
            "--config",
            str(rules_path.expanduser().resolve()),
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--strict",
            "--exclude",
            ".artifacts",
            "--exclude",
            ".pysec-tools",
            "--exclude",
            ".ruff_cache",
            "--exclude",
            "build",
            "--exclude",
            "dist",
            "--exclude",
            "node_modules",
            "--exclude",
            "venv",
            ".",
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = json.loads(payload)
        results = document.get("results", [])
        if not isinstance(results, list):
            raise TypeError("results must be a list")
        findings: list[Finding] = []
        for result in results:
            if not isinstance(result, dict):
                raise TypeError("Semgrep result must be an object")
            extra = result.get("extra") or {}
            if not isinstance(extra, dict):
                raise TypeError("Semgrep extra must be an object")
            metadata = extra.get("metadata") or {}
            if not isinstance(metadata, dict):
                metadata = {}
            path = normalize_repo_path(target, str(result.get("path", "")))
            start = result.get("start") or {}
            end = result.get("end") or {}
            line = _line(start)
            rule_id = str(result.get("check_id") or "semgrep.unknown")
            title = str(extra.get("message") or rule_id)
            finding_id, fingerprint = finding_identity(
                tool=self.name,
                rule_id=rule_id,
                path=path,
                start_line=line,
            )
            classifications = _classifications(metadata)
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=title,
                    description=title,
                    impact=str(
                        metadata.get("impact")
                        or "The matched pattern may expose the application to a security weakness."
                    ),
                    remediation=str(
                        metadata.get("fix")
                        or metadata.get("remediation")
                        or "Review the local Semgrep rule guidance and use the safer pattern."
                    ),
                    severity=map_severity(extra.get("severity")),
                    confidence=map_confidence(metadata.get("confidence")),
                    area=str(metadata.get("category") or "python-code"),
                    classifications=classifications,
                    locations=[
                        Location(
                            path=path,
                            start_line=line,
                            end_line=_line(end) or line,
                        )
                    ],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id=rule_id,
                            message=title,
                            native_severity=str(extra.get("severity") or "unknown"),
                        )
                    ],
                    citations=[
                        Citation(
                            kind="tool_rule",
                            identifier=rule_id,
                            title=rule_id,
                            uri=_safe_uri(metadata.get("source")),
                        )
                    ],
                )
            )
        return findings


def _line(value: Any) -> int | None:
    if not isinstance(value, dict):
        return None
    try:
        return int(value["line"]) if value.get("line") is not None else None
    except (TypeError, ValueError):
        return None


def _classifications(metadata: dict[str, Any]) -> list[str]:
    values = string_list(metadata.get("cwe")) + string_list(metadata.get("owasp"))
    return list(dict.fromkeys(values))


def _safe_uri(value: Any) -> str | None:
    text = str(value or "")
    return text if text.startswith(("https://", "http://")) else None
