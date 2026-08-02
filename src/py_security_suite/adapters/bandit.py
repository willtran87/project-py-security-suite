from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import (
    Citation,
    Finding,
    Location,
    Source,
    finding_identity,
    normalize_repo_path,
)
from .base import ScannerAdapter
from .common import map_confidence, map_severity


class BanditAdapter(ScannerAdapter):
    name = "bandit"
    accepted_exit_codes = frozenset({0, 1})

    def build_command(self, executable: str, target: Path) -> list[str]:
        excluded_paths = ",".join(
            str((target / directory).resolve())
            for directory in (
                ".artifacts",
                ".git",
                ".hg",
                ".nox",
                ".pysec-tools",
                ".svn",
                ".tox",
                ".venv",
                "__pycache__",
                "build",
                "dist",
                "env",
                "node_modules",
                "venv",
            )
        )
        return [
            executable,
            "-r",
            str(target.resolve()),
            "-x",
            excluded_paths,
            "-f",
            "json",
            "-q",
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = json.loads(payload)
        results = document.get("results", [])
        if not isinstance(results, list):
            raise TypeError("results must be a list")
        findings: list[Finding] = []
        for result in results:
            if not isinstance(result, dict):
                raise TypeError("Bandit result must be an object")
            path = normalize_repo_path(target, str(result.get("filename", "")))
            line = _integer(result.get("line_number"))
            rule_id = str(result.get("test_id") or "bandit.unknown")
            title = str(result.get("issue_text") or result.get("test_name") or rule_id)
            finding_id, fingerprint = finding_identity(
                tool=self.name,
                rule_id=rule_id,
                path=path,
                start_line=line,
            )
            classifications = _bandit_classifications(result)
            impact, remediation = _guidance_for(rule_id)
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=title,
                    description=title,
                    impact=impact,
                    remediation=remediation,
                    severity=map_severity(result.get("issue_severity")),
                    confidence=map_confidence(result.get("issue_confidence")),
                    area=_area_for(rule_id, classifications, title),
                    classifications=classifications,
                    locations=[
                        Location(
                            path=path,
                            start_line=line,
                            end_line=_integer(result.get("end_line_number")) or line,
                        )
                    ],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id=rule_id,
                            message=title,
                            native_severity=str(
                                result.get("issue_severity") or "unknown"
                            ),
                        )
                    ],
                    citations=[
                        Citation(
                            kind="tool_rule",
                            identifier=rule_id,
                            title=str(result.get("test_name") or rule_id),
                            uri=_safe_uri(result.get("more_info")),
                        )
                    ],
                )
            )
        return findings


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _safe_uri(value: Any) -> str | None:
    text = str(value or "")
    return text if text.startswith(("https://", "http://")) else None


def _bandit_classifications(result: dict[str, Any]) -> list[str]:
    issue_cwe = result.get("issue_cwe")
    if isinstance(issue_cwe, dict) and issue_cwe.get("id"):
        return [f"CWE-{issue_cwe['id']}"]
    return []


def _area_for(rule_id: str, classifications: list[str], title: str) -> str:
    rule_areas = {
        "B101": "validation",
        "B105": "secrets",
        "B108": "filesystem",
        "B404": "process-execution",
        "B603": "process-execution",
    }
    if rule_id in rule_areas:
        return rule_areas[rule_id]
    combined = " ".join([*classifications, title]).lower()
    if any(value in combined for value in ("command", "sql", "injection", "cwe-78")):
        return "injection"
    if any(value in combined for value in ("crypto", "hash", "tls", "ssl")):
        return "cryptography"
    if any(value in combined for value in ("deserialize", "pickle", "yaml")):
        return "unsafe-deserialization"
    return "python-code"


def _guidance_for(rule_id: str) -> tuple[str, str]:
    guidance = {
        "B101": (
            "Assertions can be removed when Python runs with optimization, so "
            "security or input validation implemented with assert may disappear.",
            "Replace security-relevant assertions with explicit conditional checks "
            "that raise a specific exception in every runtime mode.",
        ),
        "B105": (
            "A string that resembles a password or credential may expose reusable "
            "access if it is real and committed.",
            "Confirm whether the value is a real credential. If it is, revoke and "
            "rotate it, remove it from history, and load it from an approved secret "
            "store. Mark demonstrably synthetic fixtures with an approved suppression.",
        ),
        "B108": (
            "Predictable shared temporary paths can be pre-created or redirected by "
            "another local process, leading to overwrite or disclosure.",
            "Use tempfile APIs or a private, permission-restricted runtime directory. "
            "If the fixed path is an intentional container tmpfs, document that trust "
            "boundary and suppress this rule locally.",
        ),
        "B404": (
            "Process-launching APIs cross a command-execution boundary and can become "
            "unsafe when executable names or arguments are influenced by untrusted input.",
            "Keep executable paths and argument structure trusted, pass an argument "
            "vector, avoid a shell, and enforce an allowlist at the caller boundary.",
        ),
        "B603": (
            "Even without a shell, untrusted executable paths or arguments can invoke "
            "unexpected programs or unsafe command behavior.",
            "Use a fixed executable resolved from approved configuration, validate "
            "arguments, avoid user-controlled environment variables, and retain "
            "shell=False.",
        ),
    }
    return guidance.get(
        rule_id,
        (
            "The flagged Python construct may create an exploitable security weakness.",
            "Review the cited Bandit rule and replace the construct with a safer API "
            "or validated input handling.",
        ),
    )
