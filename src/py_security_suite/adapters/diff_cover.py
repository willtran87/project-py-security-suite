from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Citation, Confidence, Finding, Location, Severity, Source
from ..models import finding_identity, normalize_repo_path
from .artifacts import configured_path
from .file_output import JsonFileScannerAdapter


class DiffCoverAdapter(JsonFileScannerAdapter):
    name = "diff-cover"
    accepted_exit_codes = frozenset({0, 1})
    maximum_file_findings = 20

    def not_applicable_reason(self, target: Path) -> str | None:
        report = configured_path(target, self.config.artifacts_path, "coverage.xml")
        if not report.is_file():
            return "no pre-generated coverage.xml evidence was found"
        if not (target / ".git").exists():
            return "Git history is required for changed-line coverage"
        return None

    def build_file_command(
        self, executable: str, target: Path, output: Path
    ) -> list[str]:
        command = [
            executable,
            str(configured_path(target, self.config.artifacts_path, "coverage.xml")),
            "--format",
            f"json:{output}",
            "--fail-under",
            "0",
            "--quiet",
        ]
        if self.config.compare_branch:
            command.extend(["--compare-branch", self.config.compare_branch])
        return command

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = json.loads(payload)
        if not isinstance(document, dict):
            raise TypeError("diff-cover output must be an object")
        threshold = self.config.minimum_coverage_percent
        total = _number(document.get("total_percent_covered"))
        findings: list[Finding] = []
        if total < threshold and _integer(document.get("num_changed_lines")) > 0:
            findings.append(
                _finding(
                    target,
                    "<repository>",
                    None,
                    total,
                    threshold,
                    _integer(document.get("total_num_violations")),
                    "repository",
                )
            )
        stats = document.get("src_stats", {})
        if not isinstance(stats, dict):
            raise TypeError("diff-cover src_stats must be an object")
        candidates: list[tuple[float, str, dict[str, Any]]] = []
        for raw_path, raw_stat in stats.items():
            if not isinstance(raw_stat, dict):
                raise TypeError("diff-cover file statistics must be objects")
            missing = raw_stat.get("violation_lines") or []
            if not isinstance(missing, list):
                raise TypeError("diff-cover violation_lines must be a list")
            percent = _number(raw_stat.get("percent_covered"))
            if missing and percent < threshold:
                candidates.append((percent, str(raw_path), raw_stat))
        for percent, raw_path, stat in sorted(candidates)[: self.maximum_file_findings]:
            missing = [_integer(value) for value in stat.get("violation_lines", [])]
            findings.append(
                _finding(
                    target,
                    raw_path,
                    missing[0] if missing else None,
                    percent,
                    threshold,
                    len(missing),
                    "file",
                )
            )
        return findings

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        document = json.loads(payload)
        document["schema_version"] = "1.0"
        document["minimum_percent"] = self.config.minimum_coverage_percent
        return {"diff-coverage.json": document}


def _finding(
    target: Path,
    raw_path: str,
    line: int | None,
    percent: float,
    threshold: float,
    missing: int,
    scope: str,
) -> Finding:
    path = normalize_repo_path(target, raw_path)
    rule_id = f"{scope}-changed-lines-below-threshold"
    finding_id, fingerprint = finding_identity(
        tool="diff-cover", rule_id=rule_id, path=path, start_line=line
    )
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        title=f"Changed-line coverage below {threshold:g}%: {path}",
        description=f"Changed executable lines have {percent:.2f}% coverage with {missing} uncovered line(s).",
        impact="New or modified behavior lacks focused executable evidence, increasing the chance of an unreviewed regression in the exact code being shipped.",
        remediation="Add tests for the cited changed lines, regenerate Cobertura coverage XML in the disposable test lane, and rerun the repository scan.",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        area="changed-line-coverage",
        domain="testing",
        classifications=["DIFF-COVERAGE-BELOW-THRESHOLD"],
        locations=[Location(path=path, start_line=line)],
        sources=[
            Source(
                tool="diff-cover",
                rule_id=rule_id,
                message=f"coverage={percent:.2f}; threshold={threshold:g}",
                native_severity="threshold-failure",
            )
        ],
        citations=[
            Citation(
                kind="tool_rule",
                identifier="diff-coverage",
                title="diff-cover changed-line coverage",
                uri="https://github.com/Bachmann1234/diff-cover",
            )
        ],
        evidence={
            "percent_covered": percent,
            "minimum_percent": threshold,
            "uncovered_changed_lines": missing,
        },
    )


def _integer(value: object) -> int:
    try:
        return int(str(value or 0))
    except (TypeError, ValueError) as exc:
        raise TypeError(f"invalid diff-cover integer: {value!r}") from exc


def _number(value: object) -> float:
    try:
        return float(str(value or 0.0))
    except (TypeError, ValueError) as exc:
        raise TypeError(f"invalid diff-cover number: {value!r}") from exc
