from __future__ import annotations

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
from .base import ScannerAdapter


class ReuseAdapter(ScannerAdapter):
    name = "reuse"
    accepted_exit_codes = frozenset({0, 1})

    def not_applicable_reason(self, target: Path) -> str | None:
        markers = (
            target / "REUSE.toml",
            target / ".reuse" / "dep5",
            target / "LICENSES",
        )
        if not any(path.exists() for path in markers):
            return "no REUSE.toml, .reuse/dep5, or LICENSES opt-in marker was found"
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [executable, "lint", "--json"]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = strict_json_loads(payload)
        if not isinstance(document, dict):
            raise TypeError("REUSE JSON output must be an object")
        findings: list[Finding] = []
        for rule_id, item in _issues(document):
            path = normalize_repo_path(target, str(item.get("path") or "<repository>"))
            message = str(item.get("message") or _rule_title(rule_id))
            finding_id, fingerprint = finding_identity(
                tool=self.name,
                rule_id=rule_id,
                path=path,
            )
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=f"License metadata: {_rule_title(rule_id)}",
                    description=message,
                    impact=(
                        "Incomplete or invalid file-level license metadata prevents "
                        "reliable automated compliance review and can create legal "
                        "or redistribution uncertainty."
                    ),
                    remediation=(
                        "Add or correct the SPDX license and copyright metadata using "
                        "REUSE.toml, file headers, or adjacent .license files, then "
                        "rerun REUSE lint."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    area="license-compliance",
                    domain="governance",
                    classifications=[f"REUSE-{rule_id.upper()}"],
                    locations=[Location(path=path)],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id=rule_id,
                            message=message,
                            native_severity="non-compliant",
                        )
                    ],
                    citations=[
                        Citation(
                            kind="standard",
                            identifier=rule_id,
                            title="REUSE specification compliance",
                            uri=(
                                "https://reuse.readthedocs.io/en/stable/man/"
                                "reuse-lint.html"
                            ),
                        )
                    ],
                )
            )
        return findings

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        return {"reuse-compliance.json": strict_json_loads(payload)}


def _issues(document: dict[str, Any]) -> list[tuple[str, dict[str, str]]]:
    issues: list[tuple[str, dict[str, str]]] = []
    raw_non_compliant = document.get("non_compliant", {})
    non_compliant = raw_non_compliant if isinstance(raw_non_compliant, dict) else {}
    keys = {
        "bad_licenses": "bad-license",
        "deprecated_licenses": "deprecated-license",
        "licenses_without_extension": "license-without-extension",
        "missing_licenses": "missing-license",
        "unused_licenses": "unused-license",
        "read_errors": "read-error",
        "invalid_spdx_expressions": "invalid-spdx-expression",
        "missing_copyright_info": "missing-copyright",
        "missing_licensing_info": "missing-license-metadata",
    }
    for key, rule_id in keys.items():
        value = non_compliant.get(key, [])
        if isinstance(value, dict):
            value = [
                {"path": str(path), "message": str(message)}
                for path, message in value.items()
            ]
        if not isinstance(value, list):
            continue
        for entry in value:
            if isinstance(entry, dict):
                issues.append(
                    (
                        rule_id,
                        {
                            "path": str(
                                entry.get("path")
                                or entry.get("file")
                                or entry.get("name")
                                or "<repository>"
                            ),
                            "message": str(entry.get("message") or entry),
                        },
                    )
                )
            else:
                issues.append((rule_id, {"path": str(entry), "message": str(entry)}))
    return issues


def _rule_title(rule_id: str) -> str:
    return rule_id.replace("-", " ")
