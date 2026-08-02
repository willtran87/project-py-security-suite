from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

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


class AssuranceEvidenceAdapter(ScannerAdapter):
    """Ingest bounded output from a separately sandboxed assurance lane."""

    evidence_kind: ClassVar[str]
    default_report: ClassVar[str]
    default_domain: ClassVar[str] = "testing"
    default_area: ClassVar[str] = "dynamic-assurance"
    reference: ClassVar[str]

    def not_applicable_reason(self, target: Path) -> str | None:
        path = configured_path(target, self.config.artifacts_path, self.default_report)
        return (
            None
            if path.is_file()
            else f"no pre-generated {self.evidence_kind} evidence was found"
        )

    def build_command(self, executable: str, target: Path) -> list[str]:
        path = configured_path(target, self.config.artifacts_path, self.default_report)
        return [executable, "assurance", self.evidence_kind, str(path)]

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = json.loads(payload)
        if not isinstance(document, dict) or document.get("kind") != self.evidence_kind:
            raise TypeError(
                f"validated {self.evidence_kind} evidence must be an object"
            )
        raw_findings = document.get("findings", [])
        if not isinstance(raw_findings, list):
            raise TypeError("assurance evidence findings must be a list")
        return [self._finding(value, target) for value in raw_findings]

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        return {f"{self.evidence_kind}-summary.json": json.loads(payload)}

    def _finding(self, value: object, target: Path) -> Finding:
        if not isinstance(value, dict):
            raise TypeError("assurance evidence finding must be an object")
        rule_id = str(value.get("rule_id") or f"{self.evidence_kind}-finding")
        title = str(value.get("title") or rule_id)
        description = str(value.get("message") or value.get("description") or title)
        path = normalize_repo_path(target, str(value.get("path") or "<repository>"))
        line = _optional_integer(value.get("line"))
        severity = _severity(value.get("severity"))
        finding_id, fingerprint = finding_identity(
            tool=self.name,
            rule_id=rule_id,
            path=path,
            start_line=line,
            advisory=str(value.get("fingerprint") or ""),
        )
        classification = str(value.get("classification") or rule_id)
        citation = str(value.get("citation") or self.reference)
        return Finding(
            finding_id=finding_id,
            fingerprint=fingerprint,
            title=title,
            description=description,
            impact=str(
                value.get("impact")
                or "The companion assurance lane exposed behavior or release evidence that needs review before production promotion."
            ),
            remediation=str(
                value.get("remediation")
                or "Reproduce the result in the isolated companion lane, correct the cause, add a durable regression check, regenerate the evidence, and rerun the repository gate."
            ),
            severity=severity,
            confidence=Confidence.HIGH,
            area=str(value.get("area") or self.default_area),
            domain=str(value.get("domain") or self.default_domain),
            classifications=[classification],
            locations=[Location(path=path, start_line=line)],
            sources=[
                Source(
                    tool=self.name,
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
                    uri=citation if citation.startswith("https://") else self.reference,
                )
            ],
            evidence=value.get("evidence", {})
            if isinstance(value.get("evidence"), dict)
            else {},
        )


class CrossHairAdapter(AssuranceEvidenceAdapter):
    name = "crosshair"
    evidence_kind = "crosshair"
    default_report = "crosshair.json"
    default_area = "symbolic-execution"
    reference = "https://crosshair.readthedocs.io/en/latest/contracts.html"


class AtherisAdapter(AssuranceEvidenceAdapter):
    name = "atheris"
    evidence_kind = "atheris"
    default_report = "atheris.json"
    default_area = "fuzz-testing"
    reference = "https://github.com/google/atheris"


class MutmutAdapter(AssuranceEvidenceAdapter):
    name = "mutmut"
    evidence_kind = "mutmut"
    default_report = "mutmut.json"
    default_area = "mutation-testing"
    reference = "https://mutmut.readthedocs.io/"


class CheckManifestAdapter(AssuranceEvidenceAdapter):
    name = "check-manifest"
    evidence_kind = "check-manifest"
    default_report = "check-manifest.json"
    default_domain = "supply-chain"
    default_area = "source-distribution-completeness"
    reference = "https://github.com/mgedmin/check-manifest"


class ClamAvAdapter(AssuranceEvidenceAdapter):
    name = "clamav"
    evidence_kind = "clamav"
    default_report = "clamav.json"
    default_domain = "security"
    default_area = "malware-scanning"
    reference = "https://docs.clamav.net/manual/Usage/Scanning.html"


class GitHubAttestationAdapter(AssuranceEvidenceAdapter):
    name = "github-attestation"
    evidence_kind = "github-attestation"
    default_report = "github-attestation.json"
    default_domain = "supply-chain"
    default_area = "artifact-provenance"
    reference = "https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline"


class ZapAdapter(AssuranceEvidenceAdapter):
    name = "zap"
    evidence_kind = "zap"
    default_report = "zap.json"
    default_domain = "security"
    default_area = "dynamic-application-security-testing"
    reference = "https://www.zaproxy.org/docs/automate/automation-framework/"


class PyTmAdapter(AssuranceEvidenceAdapter):
    name = "pytm"
    evidence_kind = "pytm"
    default_report = "pytm.json"
    default_domain = "security"
    default_area = "threat-modeling"
    reference = "https://owasp.org/www-project-pytm/"


class InTotoAdapter(AssuranceEvidenceAdapter):
    name = "in-toto"
    evidence_kind = "in-toto"
    default_report = "in-toto.json"
    default_domain = "supply-chain"
    default_area = "build-provenance"
    reference = "https://in-toto.io/docs/getting-started/"


class ReproducibleBuildAdapter(AssuranceEvidenceAdapter):
    name = "reproducible-build"
    evidence_kind = "reproducible-build"
    default_report = "reproducible-build.json"
    default_domain = "supply-chain"
    default_area = "build-reproducibility"
    reference = "https://reproducible-builds.org/tools/"


class OciImageAdapter(AssuranceEvidenceAdapter):
    name = "oci-image"
    evidence_kind = "oci-image"
    default_report = "oci-image.json"
    default_domain = "supply-chain"
    default_area = "container-image-security"
    reference = "https://opencontainers.org/"


class YaraAdapter(AssuranceEvidenceAdapter):
    name = "yara"
    evidence_kind = "yara"
    default_report = "yara.json"
    default_domain = "security"
    default_area = "malware-scanning"
    reference = "https://yara.readthedocs.io/en/stable/"


def _optional_integer(value: object) -> int | None:
    try:
        return None if value in (None, "") else int(str(value))
    except (TypeError, ValueError):
        return None


def _severity(value: object) -> Severity:
    normalized = str(value or "medium").casefold()
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "informational": Severity.INFORMATIONAL,
        "info": Severity.INFORMATIONAL,
    }.get(normalized, Severity.MEDIUM)
