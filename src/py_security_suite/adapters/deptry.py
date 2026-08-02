from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Citation, Confidence, Finding, Location, Severity, Source
from ..models import finding_identity, normalize_repo_path
from .file_output import JsonFileScannerAdapter
from .staging import maintained_files


class DeptryAdapter(JsonFileScannerAdapter):
    name = "deptry"
    accepted_exit_codes = frozenset({0, 1})

    def not_applicable_reason(self, target: Path) -> str | None:
        dependency_files = (
            target / "pyproject.toml",
            target / "requirements.txt",
            target / "Pipfile",
            target / "poetry.lock",
            target / "uv.lock",
        )
        if not any(path.is_file() for path in dependency_files):
            return "no supported Python dependency declaration was found"
        if not maintained_files(target, frozenset({".py"})):
            return "no Python source files were found"
        return None

    def build_file_command(
        self, executable: str, target: Path, output: Path
    ) -> list[str]:
        source_root = target / "src"
        scan_root = source_root if source_root.is_dir() else target
        return [
            executable,
            str(scan_root.resolve()),
            "--config",
            str((target / "pyproject.toml").resolve()),
            "--no-ansi",
            "--ignore-notebooks",
            "--extend-exclude",
            r".*[\\/](\.artifacts|\.pysec-tools|build|dist|node_modules|tests)([\\/]|$)",
            "--json-output",
            str(output),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        results = json.loads(payload or "[]")
        if not isinstance(results, list):
            raise TypeError("deptry output must be a JSON list")
        findings: list[Finding] = []
        for result in results:
            if not isinstance(result, dict):
                raise TypeError("deptry finding must be an object")
            error = result.get("error")
            location = result.get("location")
            if not isinstance(error, dict) or not isinstance(location, dict):
                raise TypeError("deptry finding requires error and location objects")
            rule_id = str(error.get("code") or "DEP000")
            message = str(error.get("message") or rule_id)
            module = str(result.get("module") or "unknown dependency")
            path = normalize_repo_path(
                target, str(location.get("file") or "pyproject.toml")
            )
            line = _integer(location.get("line"))
            column = _integer(location.get("column"))
            finding_id, fingerprint = finding_identity(
                tool=self.name,
                rule_id=rule_id,
                path=path,
                start_line=line,
                package=module,
            )
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=f"Dependency declaration: {message}",
                    description=message,
                    impact=_impact(rule_id),
                    remediation=_remediation(rule_id, module),
                    severity=_severity(rule_id),
                    confidence=Confidence.HIGH,
                    area="dependency-hygiene",
                    domain="supply-chain",
                    classifications=[f"DEPTRY-{rule_id}"],
                    locations=[Location(path=path, start_line=line)],
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
                            title=f"deptry {rule_id}",
                            uri=f"https://deptry.com/rules-violations/#{rule_id.lower()}",
                        )
                    ],
                    evidence={"module": module, "column": column},
                )
            )
        return findings

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        return {
            "deptry-dependencies.json": {
                "schema_version": "1.0",
                "findings": json.loads(payload or "[]"),
            }
        }


def _integer(value: object) -> int | None:
    try:
        return None if value is None else int(str(value))
    except (TypeError, ValueError):
        return None


def _severity(rule_id: str) -> Severity:
    return (
        Severity.MEDIUM if rule_id in {"DEP001", "DEP003", "DEP004"} else Severity.LOW
    )


def _impact(rule_id: str) -> str:
    if rule_id == "DEP001":
        return "An undeclared runtime dependency can make clean, reproducible, or isolated deployments fail."
    if rule_id == "DEP003":
        return "Depending on a transitive package hides the runtime contract and can break when the direct dependency changes."
    if rule_id == "DEP004":
        return "A runtime import declared only for development can be absent from the production environment."
    return "Stale dependency declarations increase attack surface, maintenance cost, and software-composition noise."


def _remediation(rule_id: str, module: str) -> str:
    if rule_id in {"DEP001", "DEP003"}:
        return f"Declare the distribution providing {module!r} as a direct production dependency and refresh the approved lock file."
    if rule_id == "DEP004":
        return (
            f"Move {module!r} to production dependencies or remove the runtime import."
        )
    return f"Remove {module!r} from the applicable dependency group after confirming it is not required by runtime or packaging workflows."
