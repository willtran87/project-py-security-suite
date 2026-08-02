from __future__ import annotations

import json
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
from .artifacts import configured_path
from .base import ScannerAdapter
from .staging import maintained_files


class CoverageAdapter(ScannerAdapter):
    name = "coverage"
    default_report = "coverage.json"
    maximum_hotspot_findings = 10

    def not_applicable_reason(self, target: Path) -> str | None:
        if not _report_path(target, self.config, self.default_report).is_file():
            return "no pre-generated coverage.json evidence was found"
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            executable,
            "coverage",
            str(_report_path(target, self.config, self.default_report)),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = _document(payload, "coverage")
        threshold = self.config.minimum_coverage_percent
        findings: list[Finding] = []
        totals = document.get("totals")
        if not isinstance(totals, dict):
            raise TypeError("coverage evidence requires a totals object")
        if _number(totals.get("percent_covered")) < threshold:
            findings.append(
                _coverage_finding(
                    target=target,
                    path="<repository>",
                    summary=totals,
                    missing_lines=[],
                    threshold=threshold,
                    scope="repository",
                )
            )
        hotspots: list[tuple[float, int, dict[str, Any], dict[str, Any]]] = []
        for file_result in document["files"]:
            if not isinstance(file_result, dict):
                raise TypeError("coverage file result must be an object")
            summary = file_result.get("summary")
            if not isinstance(summary, dict):
                raise TypeError("coverage file summary must be an object")
            statements = _integer(summary.get("num_statements"))
            percent = _number(summary.get("percent_covered"))
            if statements == 0 or percent >= threshold:
                continue
            missing_lines = file_result.get("missing_lines") or []
            if not isinstance(missing_lines, list):
                raise TypeError("coverage missing_lines must be a list")
            hotspots.append((percent, -statements, file_result, summary))
        ordered_hotspots = sorted(
            hotspots,
            key=lambda value: (
                value[0],
                value[1],
                str(value[2].get("path") or ""),
            ),
        )
        for _, _, file_result, summary in ordered_hotspots[
            : self.maximum_hotspot_findings
        ]:
            raw_missing_lines = file_result.get("missing_lines") or []
            missing_lines = [_integer(value) for value in raw_missing_lines]
            findings.append(
                _coverage_finding(
                    target=target,
                    path=str(file_result.get("path") or ""),
                    summary=summary,
                    missing_lines=missing_lines,
                    threshold=threshold,
                    scope="file",
                )
            )
        return findings

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        document = _document(payload, "coverage")
        document["finding_hotspot_limit"] = self.maximum_hotspot_findings
        return {"coverage-summary.json": document}


class JUnitAdapter(ScannerAdapter):
    name = "junit"
    default_report = "junit.xml"
    evidence_label = "Test"
    summary_artifact = "junit-summary.json"
    finding_area = "test-failure"
    classification_prefix = "JUNIT"
    reference = "https://github.com/testmoapp/junitxml"

    def not_applicable_reason(self, target: Path) -> str | None:
        path = _report_path(target, self.config, self.default_report)
        if path.is_file():
            return None
        if path.is_dir() and any(path.rglob("*.xml")):
            return None
        return f"no pre-generated {self.evidence_label} JUnit XML evidence was found"

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            executable,
            "junit",
            str(_report_path(target, self.config, self.default_report)),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = _document(payload, "junit")
        failures = document.get("failures")
        if not isinstance(failures, list):
            raise TypeError("JUnit evidence requires a failures list")
        findings: list[Finding] = []
        for failure in failures:
            if not isinstance(failure, dict):
                raise TypeError("JUnit failure must be an object")
            result_type = str(failure.get("result") or "failure")
            test_name = str(failure.get("name") or "unnamed test")
            classname = str(failure.get("classname") or "")
            path = normalize_repo_path(
                target, str(failure.get("file") or "<test-suite>")
            )
            line = _optional_integer(failure.get("line"))
            rule_id = f"test-{result_type}"
            finding_id, fingerprint = finding_identity(
                tool=self.name,
                rule_id=rule_id,
                path=path,
                start_line=line,
                advisory=f"{classname}.{test_name}",
            )
            message = str(failure.get("message") or result_type)
            findings.append(
                Finding(
                    finding_id=finding_id,
                    fingerprint=fingerprint,
                    title=f"{self.evidence_label} {result_type}: {test_name}",
                    description=(
                        f"{classname + '.' if classname else ''}{test_name}: {message}"
                    ),
                    impact=(
                        "A failing automated test invalidates the behavioral evidence "
                        "needed to approve this repository state."
                    ),
                    remediation=(
                        "Reproduce the failure in the disposable test lane, correct "
                        "the implementation or test expectation, regenerate the JUnit "
                        "report, and rerun the repository scan."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    area=self.finding_area,
                    domain="testing",
                    classifications=[
                        f"{self.classification_prefix}-{result_type.upper()}"
                    ],
                    locations=[Location(path=path, start_line=line)],
                    sources=[
                        Source(
                            tool=self.name,
                            rule_id=rule_id,
                            message=message,
                            native_severity=result_type,
                        )
                    ],
                    citations=[
                        Citation(
                            kind="standard",
                            identifier=self.classification_prefix.casefold(),
                            title=f"{self.evidence_label} evidence",
                            uri=self.reference,
                        )
                    ],
                    evidence={
                        "test_class": classname,
                        "duration_seconds": failure.get("time", 0),
                    },
                )
            )
        return findings

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        return {self.summary_artifact: _document(payload, "junit")}


class HypothesisAdapter(JUnitAdapter):
    """Ingest property-based pytest/Hypothesis results from a sandboxed lane."""

    name = "hypothesis"
    default_report = "hypothesis-junit.xml"
    evidence_label = "Property test"
    summary_artifact = "hypothesis-summary.json"
    finding_area = "property-based-testing"
    classification_prefix = "HYPOTHESIS"
    reference = "https://hypothesis.readthedocs.io/en/latest/"

    def not_applicable_reason(self, target: Path) -> str | None:
        path = _report_path(target, self.config, self.default_report)
        if path.is_file() or (path.is_dir() and any(path.rglob("*.xml"))):
            return None
        if maintained_files(target, frozenset({".py"})):
            # Property testing is a production expectation for Python projects.
            # Returning applicable makes missing evidence fail closed.
            return None
        return "no Python source requires property-test evidence"


class SchemathesisAdapter(JUnitAdapter):
    """Ingest schema-driven API test results without executing the target."""

    name = "schemathesis"
    default_report = "schemathesis-junit.xml"
    evidence_label = "API schema test"
    summary_artifact = "schemathesis-summary.json"
    finding_area = "api-schema-testing"
    classification_prefix = "SCHEMATHESIS"
    reference = "https://schemathesis.readthedocs.io/en/stable/"

    def not_applicable_reason(self, target: Path) -> str | None:
        path = _report_path(target, self.config, self.default_report)
        if path.is_file() or (path.is_dir() and any(path.rglob("*.xml"))):
            return None
        schema_names = {
            "openapi.json",
            "openapi.yaml",
            "openapi.yml",
            "swagger.json",
            "swagger.yaml",
            "swagger.yml",
        }
        if any(
            candidate.name.casefold() in schema_names
            for candidate in target.rglob("*")
            if candidate.is_file()
        ):
            return None
        return "no OpenAPI schema or pre-generated Schemathesis evidence was found"


def _report_path(target: Path, config: Any, default: str) -> Path:
    return configured_path(target, config.artifacts_path, default)


def _coverage_finding(
    *,
    target: Path,
    path: str,
    summary: dict[str, Any],
    missing_lines: list[int],
    threshold: float,
    scope: str,
) -> Finding:
    normalized_path = normalize_repo_path(target, path)
    statements = _integer(summary.get("num_statements"))
    percent = _number(summary.get("percent_covered"))
    first_missing = missing_lines[0] if missing_lines else None
    rule_id = f"{scope}-below-threshold"
    finding_id, fingerprint = finding_identity(
        tool="coverage",
        rule_id=rule_id,
        path=normalized_path,
    )
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        title=f"Coverage below {threshold:g}%: {normalized_path}",
        description=(
            f"The pre-generated coverage report records {percent:.2f}% coverage "
            f"across {statements} executable statements."
        ),
        impact=(
            "Untested paths can conceal regressions and leave security decisions "
            "without executable evidence."
        ),
        remediation=(
            "Add focused tests for the listed missing lines and branches in the "
            "disposable test lane, regenerate coverage.json with branch coverage "
            "enabled, and rerun the repository scan."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        area="test-coverage",
        domain="testing",
        classifications=[f"COVERAGE-{scope.upper()}-BELOW-THRESHOLD"],
        locations=[Location(path=normalized_path, start_line=first_missing)],
        sources=[
            Source(
                tool="coverage",
                rule_id=rule_id,
                message=f"coverage={percent:.2f}; threshold={threshold:g}",
                native_severity="threshold-failure",
            )
        ],
        citations=[
            Citation(
                kind="tool_rule",
                identifier=rule_id,
                title="Coverage.py JSON reporting",
                uri=(
                    "https://coverage.readthedocs.io/en/latest/"
                    "commands/cmd_reporting.html"
                ),
            )
        ],
        evidence={
            "percent_covered": percent,
            "minimum_percent": threshold,
            "missing_lines": len(missing_lines)
            if missing_lines
            else _integer(summary.get("missing_lines")),
            "missing_branches": _integer(summary.get("missing_branches")),
        },
    )


def _document(payload: str, kind: str) -> dict[str, Any]:
    document = json.loads(payload)
    if not isinstance(document, dict) or document.get("kind") != kind:
        raise TypeError(f"validated {kind} evidence must be an object")
    return document


def _integer(value: object) -> int:
    try:
        return int(str(value or 0))
    except (TypeError, ValueError) as exc:
        raise TypeError(f"expected integer evidence, received {value!r}") from exc


def _optional_integer(value: object) -> int | None:
    return None if value in (None, "") else _integer(value)


def _number(value: object) -> float:
    try:
        return float(str(value or 0.0))
    except (TypeError, ValueError) as exc:
        raise TypeError(f"expected numeric evidence, received {value!r}") from exc
