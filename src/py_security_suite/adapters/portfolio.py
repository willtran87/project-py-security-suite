from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..execution import CommandEnvironment
from ..strict_json import canonical_bytes
from ..native_evidence import protect_native_report
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
from .file_output import JsonFileScannerAdapter
from .sarif import parse_sarif_findings
from .staging import maintained_repository_files


_IAC_SUFFIXES = {".tf", ".tf.json", ".yaml", ".yml", ".json"}


def _has_file(target: Path, suffixes: set[str]) -> bool:
    return any(
        any(path.name.casefold().endswith(suffix) for suffix in suffixes)
        for path in maintained_repository_files(target)
    )


class ConftestAdapter(ScannerAdapter):
    """Apply repository or organization OPA/Rego policy without remote pulls."""

    name = "conftest"
    accepted_exit_codes = frozenset({0, 1})

    def not_applicable_reason(self, target: Path) -> str | None:
        policy = self.config.rules_path
        if policy is None or not policy.is_dir():
            return "no approved local Conftest policy directory was configured"
        if not _has_file(target, _IAC_SUFFIXES | {".toml"}):
            return "no supported structured configuration files were found"
        return None

    def environment(self) -> CommandEnvironment:
        return CommandEnvironment(extra={"NO_COLOR": "1"})

    def build_command(self, executable: str, target: Path) -> list[str]:
        if self.config.rules_path is None:
            raise ValueError("Conftest requires a local policy directory")
        return [
            executable,
            "test",
            str(target.resolve()),
            "--policy",
            str(self.config.rules_path.resolve()),
            "--output",
            "sarif",
            "--no-fail",
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        return parse_sarif_findings(
            payload,
            target,
            tool_name=self.name,
            default_area="organization-policy",
            default_impact="The repository violates an approved organization policy and may not meet its deployment or governance boundary.",
            default_remediation="Apply the cited Rego policy requirement or obtain a reviewed policy exception, then rerun Conftest offline.",
        )


class KicsAdapter(JsonFileScannerAdapter):
    """Run Checkmarx KICS with a locally staged query library."""

    name = "kics"
    accepted_exit_codes = frozenset({0, 20, 30, 40, 50})
    output_filename = "results.json"

    def not_applicable_reason(self, target: Path) -> str | None:
        queries = self.config.rules_path
        if queries is None or not queries.is_dir():
            return "no approved local KICS query library was configured"
        if not _has_file(target, _IAC_SUFFIXES | {"dockerfile"}):
            return "no supported infrastructure-as-code files were found"
        return None

    def build_file_command(
        self, executable: str, target: Path, output: Path
    ) -> list[str]:
        if self.config.rules_path is None:
            raise ValueError("KICS requires a local query library")
        return [
            executable,
            "scan",
            "--path",
            str(target.resolve()),
            "--queries-path",
            str(self.config.rules_path.resolve()),
            "--output-path",
            str(output.parent),
            "--output-name",
            output.stem,
            "--report-formats",
            "json",
            "--disable-secrets",
            "--no-color",
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = json.loads(payload)
        if not isinstance(document, dict) or not isinstance(
            document.get("queries", []), list
        ):
            raise TypeError("KICS output must contain a queries list")
        findings: list[Finding] = []
        for query in document.get("queries", []):
            if not isinstance(query, dict) or not isinstance(
                query.get("files", []), list
            ):
                raise TypeError("KICS query entries must contain a files list")
            findings.extend(
                _kics_finding(query, occurrence, target)
                for occurrence in query.get("files", [])
            )
        return findings

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        return {"kics-iac.json": json.loads(payload)}


class PipdeptreeAdapter(ScannerAdapter):
    """Summarize an explicitly approved Python runtime environment."""

    name = "pipdeptree"

    def not_applicable_reason(self, target: Path) -> str | None:
        if not self.config.auxiliary_executable:
            return "no approved target Python environment was configured"
        if not (target / "pyproject.toml").is_file():
            return "no pyproject.toml dependency declaration was found"
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [
            executable,
            "--python",
            self.config.auxiliary_executable,
            "--summary",
            "--output",
            "json",
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = json.loads(payload)
        if not isinstance(document, dict):
            raise TypeError("pipdeptree summary must be an object")
        findings: list[Finding] = []
        counts = {
            "missing-dependencies": _integer(document.get("missing_dependencies")),
            "cyclic-dependencies": _integer(document.get("cyclic_dependencies")),
        }
        conflicts = document.get("conflicting_dependencies", {})
        if isinstance(conflicts, dict):
            counts["conflicting-dependencies"] = _integer(conflicts.get("edges"))
        for rule_id, count in counts.items():
            if count:
                findings.append(
                    _repository_finding(
                        tool=self.name,
                        rule_id=rule_id,
                        title=f"Python environment has {count} {rule_id.replace('-', ' ')}",
                        description=f"pipdeptree reported {count} {rule_id.replace('-', ' ')} in the approved target environment.",
                        severity=Severity.MEDIUM,
                        area="dependency-health",
                        domain="supply-chain",
                        citation="https://pipdeptree.readthedocs.io/en/latest/reference/cli.html",
                    )
                )
        return findings

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        document = json.loads(payload)
        if not isinstance(document, dict):
            raise TypeError("pipdeptree summary must be an object")
        conflicts = document.get("conflicting_dependencies")
        if not isinstance(conflicts, dict):
            raise TypeError("pipdeptree conflicting_dependencies must be an object")
        artifact: dict[str, Any] = {
            "schema_version": "1.0",
            "total_packages": _bounded_count(document, "total_packages"),
            "direct_dependencies": _bounded_count(document, "direct_dependencies"),
            "transitive_dependencies": _bounded_count(
                document, "transitive_dependencies"
            ),
            "max_depth": _bounded_count(document, "max_depth"),
            "missing_dependencies": _bounded_count(document, "missing_dependencies"),
            "cyclic_dependencies": _bounded_count(document, "cyclic_dependencies"),
            "conflicting_dependencies": {
                "packages": _bounded_count(conflicts, "packages"),
                "edges": _bounded_count(conflicts, "edges"),
            },
            "native_report_records": _bounded_count(document, "total_packages"),
            **protect_native_report(payload, adapter=self.name),
        }
        artifact["normalization_sha256"] = hashlib.sha256(
            canonical_bytes(artifact)
        ).hexdigest()
        return {"pipdeptree-summary.json": artifact}


class GitSizerAdapter(ScannerAdapter):
    name = "git-sizer"

    def not_applicable_reason(self, target: Path) -> str | None:
        return (
            None if (target / ".git").is_dir() else "target is not a full Git checkout"
        )

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [executable, "--json", "--json-version", "2"]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = json.loads(payload)
        if not isinstance(document, dict):
            raise TypeError("git-sizer JSON must be an object")
        findings: list[Finding] = []
        for path, metric in _concern_metrics(document):
            concern = _number(
                metric.get("levelOfConcern", metric.get("level_of_concern"))
            )
            if concern < 1:
                continue
            label = str(metric.get("description") or path.rsplit(".", 1)[-1])
            findings.append(
                _repository_finding(
                    tool=self.name,
                    rule_id=path.replace(".", "-")[:120],
                    title=f"Git repository size concern: {label}",
                    description=f"git-sizer assigned concern level {concern} to {label}; measured value: {metric.get('value', 'unknown')}.",
                    severity=Severity.MEDIUM if concern >= 2 else Severity.LOW,
                    area="repository-health",
                    domain="quality",
                    citation="https://github.com/github/git-sizer",
                )
            )
        return findings

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        document = json.loads(payload)
        if not isinstance(document, dict):
            raise TypeError("git-sizer JSON must be an object")
        metrics = [
            {
                "path": path[:500],
                "description": str(
                    metric.get("description") or path.rsplit(".", 1)[-1]
                )[:500],
                "value": str(metric.get("value", "unknown"))[:500],
                "level_of_concern": _number(
                    metric.get("levelOfConcern", metric.get("level_of_concern"))
                ),
            }
            for path, metric in _concern_metrics(document)
        ]
        metrics.sort(key=lambda item: str(item["path"]))
        artifact: dict[str, Any] = {
            "schema_version": "1.0",
            "metrics": metrics,
            "concerning_metrics": sum(
                _number(item["level_of_concern"]) >= 1 for item in metrics
            ),
            "native_report_records": len(metrics),
            **protect_native_report(payload, adapter=self.name),
        }
        artifact["normalization_sha256"] = hashlib.sha256(
            canonical_bytes(artifact)
        ).hexdigest()
        return {"git-sizer.json": artifact}


class ValidatePyprojectAdapter(ScannerAdapter):
    name = "validate-pyproject"
    accepted_exit_codes = frozenset({0, 1})

    def not_applicable_reason(self, target: Path) -> str | None:
        return (
            None
            if (target / "pyproject.toml").is_file()
            else "no pyproject.toml was found"
        )

    def environment(self) -> CommandEnvironment:
        return CommandEnvironment(extra={"VALIDATE_PYPROJECT_NO_NETWORK": "1"})

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [executable, "--dump-json", str((target / "pyproject.toml").resolve())]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        if payload.lstrip().startswith("{"):
            document = json.loads(payload)
            if not isinstance(document, dict):
                raise TypeError("validated pyproject document must be an object")
            return []
        message = " ".join(payload.split()) or "pyproject.toml failed schema validation"
        return [
            _repository_finding(
                tool=self.name,
                rule_id="invalid-pyproject",
                title="pyproject.toml is not standards-valid",
                description=message,
                severity=Severity.MEDIUM,
                area="packaging-metadata",
                domain="quality",
                citation="https://validate-pyproject.readthedocs.io/en/latest/readme.html",
                path="pyproject.toml",
            )
        ]


class ValeAdapter(ScannerAdapter):
    name = "vale"
    accepted_exit_codes = frozenset({0, 1})

    def not_applicable_reason(self, target: Path) -> str | None:
        config = self.config.rules_path
        if config is None or not config.is_file():
            return "no approved local Vale configuration was configured"
        if not _has_file(target, {".md", ".rst"}):
            return "no supported documentation files were found"
        return None

    def build_command(self, executable: str, target: Path) -> list[str]:
        if self.config.rules_path is None:
            raise ValueError("Vale requires a local configuration")
        return [
            executable,
            "--config",
            str(self.config.rules_path.resolve()),
            "--output",
            "JSON",
            str(target.resolve()),
        ]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = json.loads(payload or "{}")
        if not isinstance(document, dict):
            raise TypeError("Vale output must be an object")
        findings: list[Finding] = []
        for filename, alerts in document.items():
            if not isinstance(alerts, list):
                raise TypeError("Vale file alerts must be a list")
            for alert in alerts:
                if not isinstance(alert, dict):
                    raise TypeError("Vale alert must be an object")
                rule_id = str(alert.get("Check") or "Vale.Style")
                path = normalize_repo_path(target, str(filename))
                line = _integer(alert.get("Line")) or None
                findings.append(
                    _finding(
                        tool=self.name,
                        rule_id=rule_id,
                        title=f"Documentation: {rule_id}",
                        description=str(alert.get("Message") or rule_id),
                        severity={
                            "error": Severity.MEDIUM,
                            "warning": Severity.LOW,
                        }.get(
                            str(alert.get("Severity") or "").casefold(),
                            Severity.INFORMATIONAL,
                        ),
                        area="documentation-quality",
                        domain="quality",
                        citation=str(alert.get("Link") or "https://vale.sh/docs/cli"),
                        path=path,
                        line=line,
                    )
                )
        return findings


class KubeLinterAdapter(ScannerAdapter):
    name = "kube-linter"
    accepted_exit_codes = frozenset({0, 1})

    def not_applicable_reason(self, target: Path) -> str | None:
        if (target / "Chart.yaml").is_file() or _has_kubernetes_manifest(target):
            return None
        return "no Kubernetes YAML or Helm chart was found"

    def build_command(self, executable: str, target: Path) -> list[str]:
        return [executable, "lint", str(target.resolve()), "--format", "json"]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = json.loads(payload or "{}")
        reports = (
            document.get("Reports", document.get("reports", []))
            if isinstance(document, dict)
            else []
        )
        if not isinstance(reports, list):
            raise TypeError("KubeLinter output must contain a reports list")
        findings: list[Finding] = []
        for report in reports:
            if not isinstance(report, dict):
                raise TypeError("KubeLinter report must be an object")
            diagnostic = report.get("Diagnostic", report.get("diagnostic", {}))
            obj = report.get("Object", report.get("object", {}))
            diagnostic = diagnostic if isinstance(diagnostic, dict) else {}
            obj = obj if isinstance(obj, dict) else {}
            metadata = obj.get("Metadata", obj.get("metadata", {}))
            metadata = metadata if isinstance(metadata, dict) else {}
            rule_id = str(
                report.get("Check") or report.get("check") or "kubernetes-policy"
            )
            path = normalize_repo_path(
                target,
                str(
                    metadata.get("FilePath")
                    or metadata.get("filePath")
                    or "<repository>"
                ),
            )
            findings.append(
                _finding(
                    tool=self.name,
                    rule_id=rule_id,
                    title=f"Kubernetes policy: {rule_id}",
                    description=str(
                        diagnostic.get("Message")
                        or diagnostic.get("message")
                        or rule_id
                    ),
                    severity=Severity.MEDIUM,
                    area="kubernetes-security",
                    domain="security",
                    citation="https://docs.kubelinter.io/",
                    path=path,
                    line=_integer(metadata.get("Line")) or None,
                )
            )
        return findings


def _kics_finding(query: dict[str, Any], occurrence: object, target: Path) -> Finding:
    if not isinstance(occurrence, dict):
        raise TypeError("KICS file occurrence must be an object")
    rule_id = str(query.get("query_id") or "KICS-UNKNOWN")
    title = str(query.get("query_name") or rule_id)
    path = normalize_repo_path(
        target, str(occurrence.get("file_name") or "<repository>")
    )
    line = _integer(occurrence.get("line")) or None
    cwe = str(query.get("cwe") or "").removeprefix("CWE-")
    classifications = [rule_id]
    if cwe.isdigit():
        classifications.append(f"CWE-{cwe}")
    severity = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFORMATIONAL,
    }.get(str(query.get("severity") or "").casefold(), Severity.MEDIUM)
    description = str(query.get("description") or title)
    expected = str(occurrence.get("expected_value") or "")
    actual = str(occurrence.get("actual_value") or "")
    if expected or actual:
        description += f" Expected: {expected or 'policy-compliant value'}. Actual: {actual or 'missing value'}."
    finding = _finding(
        tool="kics",
        rule_id=rule_id,
        title=f"IaC policy: {title}",
        description=description,
        severity=severity,
        area="infrastructure-as-code",
        domain="security",
        citation=str(query.get("query_uri") or "https://docs.kics.io/latest/queries/"),
        path=path,
        line=line,
    )
    finding.classifications = classifications
    finding.evidence = {
        "platform": query.get("platform"),
        "category": query.get("category"),
        "issue_type": occurrence.get("issue_type"),
        "resource_type": occurrence.get("resource_type"),
        "risk_score": query.get("risk_score"),
    }
    return finding


def _finding(
    *,
    tool: str,
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    area: str,
    domain: str,
    citation: str,
    path: str,
    line: int | None,
) -> Finding:
    finding_id, fingerprint = finding_identity(
        tool=tool, rule_id=rule_id, path=path, start_line=line
    )
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        title=title,
        description=description,
        impact="The reported condition reduces security, correctness, maintainability, or production-readiness confidence for this repository.",
        remediation="Review the cited rule and local evidence, correct the underlying configuration or structure, add a regression check, and rerun the applicable profile.",
        severity=severity,
        confidence=Confidence.HIGH,
        area=area,
        domain=domain,
        classifications=[rule_id],
        locations=[Location(path=path, start_line=line)],
        sources=[
            Source(
                tool=tool,
                rule_id=rule_id,
                message=description,
                native_severity=severity.value,
            )
        ],
        citations=[
            Citation(
                kind="tool_rule",
                identifier=rule_id,
                title=title,
                uri=citation if citation.startswith("https://") else None,
            )
        ],
    )


def _repository_finding(
    *,
    tool: str,
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    area: str,
    domain: str,
    citation: str,
    path: str = "<repository>",
) -> Finding:
    return _finding(
        tool=tool,
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        area=area,
        domain=domain,
        citation=citation,
        path=path,
        line=None,
    )


def _concern_metrics(
    value: object, prefix: str = ""
) -> list[tuple[str, dict[str, Any]]]:
    metrics: list[tuple[str, dict[str, Any]]] = []
    if isinstance(value, dict):
        if "levelOfConcern" in value or "level_of_concern" in value:
            metrics.append((prefix or "repository", value))
        else:
            for key, child in value.items():
                metrics.extend(_concern_metrics(child, f"{prefix}.{key}".strip(".")))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            metrics.extend(_concern_metrics(child, f"{prefix}.{index}".strip(".")))
    return metrics


def _integer(value: object) -> int:
    try:
        return int(str(value or 0))
    except (TypeError, ValueError):
        return 0


def _bounded_count(value: dict[str, Any], name: str) -> int:
    raw = value.get(name)
    if isinstance(raw, bool) or not isinstance(raw, int) or not 0 <= raw <= 10_000_000:
        raise ValueError(f"{name} must be an integer between 0 and 10000000")
    return raw


def _number(value: object) -> float:
    try:
        return float(str(value or 0))
    except (TypeError, ValueError):
        return 0.0


def _has_kubernetes_manifest(target: Path) -> bool:
    for path in maintained_repository_files(target):
        if path.suffix.casefold() not in {".yaml", ".yml"}:
            continue
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                prefix = handle.read(64 * 1024)
        except OSError:
            continue
        if "apiVersion:" in prefix and "kind:" in prefix:
            return True
    return False
