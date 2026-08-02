from __future__ import annotations

import json
from pathlib import Path

from ..execution import CommandEnvironment
from ..models import Citation, Confidence, Finding, Location, Severity, Source
from ..models import finding_identity, normalize_repo_path
from .base import ScannerAdapter
from .common import map_severity
from .staging import maintained_files


class PSScriptAnalyzerAdapter(ScannerAdapter):
    name = "psscriptanalyzer"

    def _scripts(self, target: Path) -> list[Path]:
        return maintained_files(target, frozenset({".ps1", ".psm1", ".psd1"}))

    def not_applicable_reason(self, target: Path) -> str | None:
        return (
            None if self._scripts(target) else "no PowerShell source files were found"
        )

    def prerequisite_error(self) -> str | None:
        if (
            self.config.rules_path is None
            or not self.config.rules_path.resolve().is_file()
        ):
            return "the suite-controlled PSScriptAnalyzer settings file is required"
        if (
            self.config.database_path is None
            or not self.config.database_path.resolve().is_dir()
        ):
            return "a staged PSScriptAnalyzer module directory is required in database_path"
        return None

    def environment(self) -> CommandEnvironment:
        module_root = self.config.database_path
        return (
            CommandEnvironment(extra={"PSModulePath": str(module_root.resolve())})
            if module_root
            else CommandEnvironment()
        )

    def version_command(self, executable: str) -> list[str]:
        script = "Import-Module PSScriptAnalyzer -ErrorAction Stop; (Get-Module PSScriptAnalyzer).Version.ToString()"
        return [
            executable,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ]

    def build_command(self, executable: str, target: Path) -> list[str]:
        settings = self.config.rules_path
        if settings is None:
            raise ValueError("PSScriptAnalyzer settings path was not configured")
        paths = ",".join(f"'{_quote(path)}'" for path in self._scripts(target))
        script = (
            "$ErrorActionPreference='Stop'; Import-Module PSScriptAnalyzer -ErrorAction Stop; "
            f"$paths=@({paths}); $items=@($paths | ForEach-Object {{ "
            f"Invoke-ScriptAnalyzer -Path $_ -Settings '{_quote(settings.resolve())}' }}); "
            "$normalized=@($items | ForEach-Object { [ordered]@{RuleName=$_.RuleName; "
            "Severity=$_.Severity.ToString(); ScriptName=$_.ScriptName; ScriptPath=$_.ScriptPath; "
            "Line=$_.Line; Column=$_.Column; EndLine=$_.EndLine; EndColumn=$_.EndColumn; "
            "Message=$_.Message} }); ConvertTo-Json -InputObject $normalized -Depth 5 -Compress"
        )
        return [
            executable,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        results = json.loads(payload or "[]")
        if not isinstance(results, list):
            raise TypeError("PSScriptAnalyzer output must be a list")
        findings: list[Finding] = []
        for result in results:
            if not isinstance(result, dict):
                raise TypeError("PSScriptAnalyzer finding must be an object")
            rule_id = str(result.get("RuleName") or "PowerShellRule")
            message = str(result.get("Message") or rule_id)
            path = normalize_repo_path(
                target,
                str(
                    result.get("ScriptPath")
                    or result.get("ScriptName")
                    or "<repository>"
                ),
            )
            line = _integer(result.get("Line"))
            end_line = _integer(result.get("EndLine")) or line
            native_severity = str(result.get("Severity") or "Warning")
            finding_id, fingerprint = finding_identity(
                tool=self.name, rule_id=rule_id, path=path, start_line=line
            )
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=f"PowerShell analysis: {message}",
                    description=message,
                    impact="The PowerShell construct can weaken automation reliability, security boundaries, or compatibility on enterprise runners.",
                    remediation="Apply the cited PSScriptAnalyzer rule, keep any suppression narrowly scoped and justified, and rerun the isolated scan.",
                    severity=_severity(rule_id, native_severity),
                    confidence=Confidence.HIGH,
                    area="powershell-safety",
                    domain="security",
                    classifications=[f"PSSA-{rule_id.upper()}"],
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
                            title=f"PSScriptAnalyzer {rule_id}",
                            uri=f"https://learn.microsoft.com/en-us/powershell/utility-modules/psscriptanalyzer/rules/{rule_id.lower()}",
                        )
                    ],
                )
            )
        return findings


def _quote(value: Path) -> str:
    return str(value).replace("'", "''")


def _integer(value: object) -> int | None:
    try:
        return None if value is None else int(str(value))
    except (TypeError, ValueError):
        return None


def _severity(rule_id: str, native: str) -> Severity:
    if rule_id in {"PSAvoidUsingWriteHost", "PSAvoidTrailingWhitespace"}:
        return Severity.INFORMATIONAL
    if rule_id == "PSReviewUnusedParameter":
        return Severity.LOW
    return map_severity(native, default=Severity.MEDIUM)
