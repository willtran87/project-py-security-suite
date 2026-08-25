from __future__ import annotations

import re
from pathlib import Path
from typing import Any, ClassVar

from ..execution import sha256_file
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
from ..repository_surfaces import classify_repository_surfaces
from ..surface_proof import verify_surface_proof
from .artifacts import configured_path
from .base import ScannerAdapter
from .staging import maintained_repository_files


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
        command = [
            executable,
            "assurance",
            self.evidence_kind,
            str(path),
            "--maximum-age-days",
            str(self.config.maximum_evidence_age_days),
            "--minimum-coverage-percent",
            str(self.config.minimum_coverage_percent),
        ]
        if self.config.require_evidence_contract_v2:
            command.append("--require-contract-v2")
        if self.config.public_key_path is not None:
            command.extend(
                [
                    "--public-key",
                    str(self.config.public_key_path.expanduser().resolve()),
                ]
            )
        if self.config.public_keyring_path is not None:
            command.extend(
                [
                    "--public-keyring",
                    str(self.config.public_keyring_path.expanduser().resolve()),
                ]
            )
        if self.config.require_signed_evidence:
            command.append("--require-signature")
        if self.config.expected_run_id:
            command.extend(["--expected-run-id", self.config.expected_run_id])
        if self.config.expected_environment_sha256:
            command.extend(
                [
                    "--expected-environment-sha256",
                    self.config.expected_environment_sha256,
                ]
            )
        if self.config.expected_context_path is not None:
            command.extend(
                [
                    "--expected-context",
                    str(self.config.expected_context_path.expanduser().resolve()),
                ]
            )
        if self.config.replay_ledger_path is not None:
            command.extend(
                [
                    "--consume-replay-ledger",
                    str(self.config.replay_ledger_path.expanduser().resolve()),
                ]
            )
        if self.config.replay_service_url:
            command.extend(
                [
                    "--consume-replay-service",
                    self.config.replay_service_url,
                    "--replay-service-token-env",
                    self.config.replay_service_token_env,
                ]
            )
            if self.config.replay_service_ca_path is not None:
                command.extend(
                    [
                        "--replay-service-ca",
                        str(self.config.replay_service_ca_path.expanduser().resolve()),
                    ]
                )
            for option, replay_path in (
                (
                    "--replay-service-receipt-key",
                    self.config.replay_service_receipt_key_path,
                ),
                (
                    "--replay-service-client-cert",
                    self.config.replay_service_client_cert_path,
                ),
                (
                    "--replay-service-client-key",
                    self.config.replay_service_client_key_path,
                ),
            ):
                if replay_path is not None:
                    command.extend([option, str(replay_path.expanduser().resolve())])
        for builder_id in self.config.allowed_builder_ids:
            command.extend(["--allowed-builder-id", builder_id])
        if self.config.expected_build_type:
            command.extend(["--expected-build-type", self.config.expected_build_type])
        if self.config.expected_source_repository:
            command.extend(
                ["--expected-source-repository", self.config.expected_source_repository]
            )
        if self.config.assurance_profile_path is not None:
            command.extend(
                [
                    "--assurance-profile",
                    str(self.config.assurance_profile_path.expanduser().resolve()),
                ]
            )
        if self.config.require_assurance_profile:
            command.append("--require-assurance-profile")
        return command

    def prerequisite_error(self) -> str | None:
        profile = self.config.assurance_profile_path
        if self.config.require_assurance_profile and profile is None:
            return (
                "trusted assurance evidence requires a checkpointed assurance profile"
            )
        if profile is not None:
            resolved_profile = profile.expanduser().resolve()
            if resolved_profile.is_symlink() or not resolved_profile.is_file():
                return "assurance profile is not a regular file"
            try:
                observed_profile = sha256_file(resolved_profile)
            except OSError:
                return "assurance profile could not be hashed"
            if observed_profile != self.config.assurance_profile_sha256:
                return "assurance profile SHA-256 is not approved"
        if self.config.require_evidence_contract_v2:
            context = self.config.expected_context_path
            if context is None:
                return "companion assurance v2 requires expected_context_path"
            resolved_context = context.expanduser().resolve()
            if resolved_context.is_symlink() or not resolved_context.is_file():
                return "expected_context_path is not a regular file"
        service_ca = self.config.replay_service_ca_path
        if service_ca is not None:
            if service_ca.expanduser().is_symlink():
                return "replay service CA is not a regular file"
            resolved_ca = service_ca.expanduser().resolve()
            if resolved_ca.is_symlink() or not resolved_ca.is_file():
                return "replay service CA is not a regular file"
            try:
                observed_ca = sha256_file(resolved_ca)
            except OSError:
                return "replay service CA could not be hashed"
            if observed_ca != self.config.replay_service_ca_sha256:
                return "replay service CA SHA-256 is not approved"
        for label, path, expected in (
            (
                "receipt key",
                self.config.replay_service_receipt_key_path,
                self.config.replay_service_receipt_key_sha256,
            ),
            (
                "client certificate",
                self.config.replay_service_client_cert_path,
                self.config.replay_service_client_cert_sha256,
            ),
            (
                "client key",
                self.config.replay_service_client_key_path,
                self.config.replay_service_client_key_sha256,
            ),
        ):
            if path is None:
                continue
            resolved_replay_file = path.expanduser().resolve()
            if resolved_replay_file.is_symlink() or not resolved_replay_file.is_file():
                return f"replay service {label} is not a regular file"
            try:
                observed_replay_digest = sha256_file(resolved_replay_file)
            except OSError:
                return f"replay service {label} could not be hashed"
            if observed_replay_digest != expected:
                return f"replay service {label} SHA-256 is not approved"
        if not self.config.require_signed_evidence:
            return None
        public_key = self.config.public_key_path or self.config.public_keyring_path
        if public_key is None:
            return "signed companion evidence requires a public key or keyring"
        resolved = public_key.expanduser().resolve()
        if resolved.is_symlink() or not resolved.is_file():
            return "signed companion evidence public_key_path is not a regular file"
        expected_digest = (
            self.config.public_key_sha256
            if self.config.public_key_path is not None
            else self.config.public_keyring_sha256
        )
        if not expected_digest:
            return "signed companion evidence requires an approved trust digest"
        try:
            observed = sha256_file(resolved)
        except OSError:
            return "signed companion evidence public key could not be hashed"
        if observed != expected_digest:
            return "signed companion evidence trust SHA-256 is not approved"
        return None

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = strict_json_loads(payload)
        if not isinstance(document, dict) or document.get("kind") != self.evidence_kind:
            raise TypeError(
                f"validated {self.evidence_kind} evidence must be an object"
            )
        raw_findings = document.get("findings", [])
        if not isinstance(raw_findings, list):
            raise TypeError("assurance evidence findings must be a list")
        binding = document.get("evidence_binding")
        source_sha256 = document.get("source_sha256")
        if (
            not isinstance(binding, dict)
            or binding.get("verified") is not True
            or not isinstance(source_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", source_sha256) is None
        ):
            raise TypeError("assurance evidence must have a verified source binding")
        if (
            self.config.require_evidence_contract_v2
            and document.get("schema_version") != "2.0"
        ):
            raise TypeError("assurance evidence must use contract version 2.0")
        if (
            self.config.require_signed_evidence
            and binding.get("authenticated") is not True
        ):
            raise TypeError("assurance evidence must have an authenticated binding")
        context = {
            "contract_version": str(document.get("schema_version") or ""),
            "producer": str(document.get("producer") or "unknown"),
            "producer_version": str(document.get("producer_version") or ""),
            "revision": str(document.get("revision") or ""),
            "generated_at": str(document.get("generated_at") or ""),
            "expires_at": str(document.get("expires_at") or ""),
            "run_id": str(document.get("run_id") or ""),
            "source_sha256": source_sha256,
            "evidence_sha256": str(binding.get("evidence_sha256") or ""),
            "binding_verified": True,
            "binding_authenticated": binding.get("authenticated") is True,
            "execution": document.get("execution", {}),
            "target_context": document.get("context", {}),
            "assurance_profile": document.get("assurance_profile", {}),
        }
        return [self._finding(value, target, context) for value in raw_findings]

    def derived_artifacts(self, payload: str, target: Path) -> dict[str, Any]:
        return {f"{self.evidence_kind}-summary.json": strict_json_loads(payload)}

    def _finding(
        self, value: object, target: Path, context: dict[str, object]
    ) -> Finding:
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
        finding_evidence = (
            dict(value.get("evidence", {}))
            if isinstance(value.get("evidence"), dict)
            else {}
        )
        finding_evidence["assurance_context"] = context
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
            evidence=finding_evidence,
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

    def not_applicable_reason(self, target: Path) -> str | None:
        return _web_evidence_applicability(self, target)


class NucleiAdapter(AssuranceEvidenceAdapter):
    name = "nuclei"
    evidence_kind = "nuclei"
    default_report = "nuclei.json"
    default_domain = "security"
    default_area = "independent-dynamic-application-security-testing"
    reference = "https://docs.projectdiscovery.io/templates/reference/template-signing"

    def not_applicable_reason(self, target: Path) -> str | None:
        return _web_evidence_applicability(self, target)


class OastAdapter(AssuranceEvidenceAdapter):
    name = "oast"
    evidence_kind = "oast"
    default_report = "oast.json"
    default_domain = "security"
    default_area = "out-of-band-application-security-testing"
    reference = "https://docs.projectdiscovery.io/templates/reference/oob-testing"

    def not_applicable_reason(self, target: Path) -> str | None:
        return _web_evidence_applicability(self, target)


class RestlerAdapter(AssuranceEvidenceAdapter):
    name = "restler"
    evidence_kind = "restler"
    default_report = "restler.json"
    default_domain = "security"
    default_area = "stateful-rest-api-security-testing"
    reference = "https://github.com/microsoft/restler-fuzzer"

    def not_applicable_reason(self, target: Path) -> str | None:
        return _web_evidence_applicability(self, target)


class ProtocolSecurityAdapter(AssuranceEvidenceAdapter):
    name = "protocol-security"
    evidence_kind = "protocol-security"
    default_report = "protocol-security.json"
    default_domain = "security"
    default_area = "non-http-protocol-security-testing"
    reference = "https://grpc.io/docs/guides/auth/"

    def not_applicable_reason(self, target: Path) -> str | None:
        configured = configured_path(
            target, self.config.artifacts_path, self.default_report
        )
        contracts = (
            target / "security" / "protocol-contract.json",
            target / "protocol-contract.json",
        )
        if configured.is_file() or any(path.is_file() for path in contracts):
            return None
        if any(
            path.suffix.casefold() == ".proto"
            for path in maintained_repository_files(target)
        ):
            return None
        return "no protocol contract, protobuf service, or pre-generated protocol evidence was found"


class FuzzIntrospectorAdapter(AssuranceEvidenceAdapter):
    name = "fuzz-introspector"
    evidence_kind = "fuzz-introspector"
    default_report = "fuzz-introspector.json"
    default_domain = "testing"
    default_area = "fuzz-harness-quality"
    reference = "https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/"

    def not_applicable_reason(self, target: Path) -> str | None:
        configured = configured_path(
            target, self.config.artifacts_path, self.default_report
        )
        if configured.is_file() or (target / ".clusterfuzzlite").is_dir():
            return None
        if (target / "security" / "fuzz-targets.json").is_file():
            return None
        return "no fuzz target declaration or pre-generated Fuzz Introspector evidence was found"


class IastAdapter(AssuranceEvidenceAdapter):
    name = "iast"
    evidence_kind = "iast"
    default_report = "iast.json"
    default_domain = "security"
    default_area = "interactive-application-security-testing"
    reference = "https://docs.datadoghq.com/security/code_security/iast/"

    def not_applicable_reason(self, target: Path) -> str | None:
        return _web_evidence_applicability(self, target)


class BrowserSecurityAdapter(AssuranceEvidenceAdapter):
    name = "browser-security"
    evidence_kind = "browser-security"
    default_report = "browser-security.json"
    default_domain = "security"
    default_area = "authenticated-browser-security-testing"
    reference = "https://www.zaproxy.org/docs/desktop/addons/client-side-integration/"

    def not_applicable_reason(self, target: Path) -> str | None:
        return _web_evidence_applicability(self, target)


class AuthorizationSecurityAdapter(AssuranceEvidenceAdapter):
    name = "authorization-security"
    evidence_kind = "authorization-security"
    default_report = "authorization-security.json"
    default_domain = "security"
    default_area = "multi-role-authorization-security-testing"
    reference = "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"

    def not_applicable_reason(self, target: Path) -> str | None:
        configured = configured_path(
            target, self.config.artifacts_path, self.default_report
        )
        contracts = (
            target / "security" / "authorization-contract.json",
            target / "authorization-contract.json",
        )
        if (
            configured.is_file()
            or any(path.is_file() for path in contracts)
            or "authorization" in classify_repository_surfaces(target)
        ):
            return None
        return "no authorization contract or pre-generated authorization evidence was found"


class SurfaceInventoryAdapter(AssuranceEvidenceAdapter):
    name = "surface-inventory"
    evidence_kind = "surface-inventory"
    default_report = "surface-inventory.json"
    default_domain = "security"
    default_area = "api-and-service-surface-inventory"
    reference = "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"

    def not_applicable_reason(self, target: Path) -> str | None:
        configured = configured_path(
            target, self.config.artifacts_path, self.default_report
        )
        if configured.is_file() or "service" in classify_repository_surfaces(target):
            return None
        return (
            "no service surface or pre-generated surface inventory evidence was found"
        )

    def parse(self, payload: str, target: Path) -> list[Finding]:
        document = strict_json_loads(payload)
        if self.config.require_assurance_profile:
            execution = (
                document.get("execution") if isinstance(document, dict) else None
            )
            verify_surface_proof(execution)
        return super().parse(payload, target)


class EventSecurityAdapter(AssuranceEvidenceAdapter):
    name = "event-security"
    evidence_kind = "event-security"
    default_report = "event-security.json"
    default_domain = "security"
    default_area = "event-driven-security-testing"
    reference = (
        "https://owasp.org/www-project-application-security-verification-standard/"
    )

    def not_applicable_reason(self, target: Path) -> str | None:
        return _classified_evidence_applicability(self, target, "event")


class DatabaseSecurityAdapter(AssuranceEvidenceAdapter):
    name = "database-security"
    evidence_kind = "database-security"
    default_report = "database-security.json"
    default_domain = "security"
    default_area = "database-behavior-security-testing"
    reference = (
        "https://owasp.org/www-project-application-security-verification-standard/"
    )

    def not_applicable_reason(self, target: Path) -> str | None:
        return _classified_evidence_applicability(self, target, "database")


class RulesetRegressionAdapter(AssuranceEvidenceAdapter):
    name = "ruleset-regression"
    evidence_kind = "ruleset-regression"
    default_report = "ruleset-regression.json"
    default_domain = "testing"
    default_area = "semantic-scanner-ruleset-regression"
    reference = "https://csrc.nist.gov/projects/ssdf"

    def not_applicable_reason(self, target: Path) -> str | None:
        configured = configured_path(
            target, self.config.artifacts_path, self.default_report
        )
        if configured.is_file() or any(
            path.suffix.casefold()
            in {
                ".c",
                ".cc",
                ".cpp",
                ".cs",
                ".go",
                ".java",
                ".js",
                ".kt",
                ".php",
                ".py",
                ".rb",
                ".rs",
                ".swift",
                ".ts",
                ".tsx",
            }
            for path in maintained_repository_files(target)
        ):
            return None
        return "no analyzable source or pre-generated ruleset regression evidence was found"


class AiSecurityAdapter(AssuranceEvidenceAdapter):
    name = "ai-security"
    evidence_kind = "ai-security"
    default_report = "ai-security.json"
    default_domain = "security"
    default_area = "ai-and-agent-security-testing"
    reference = (
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
    )

    def not_applicable_reason(self, target: Path) -> str | None:
        return _classified_evidence_applicability(self, target, "ai")


class ClusterFuzzLiteAdapter(AssuranceEvidenceAdapter):
    name = "clusterfuzzlite"
    evidence_kind = "clusterfuzzlite"
    default_report = "clusterfuzzlite.json"
    default_area = "continuous-fuzz-testing"
    reference = "https://google.github.io/clusterfuzzlite/"

    def not_applicable_reason(self, target: Path) -> str | None:
        configured = configured_path(
            target, self.config.artifacts_path, self.default_report
        )
        if configured.is_file() or (target / ".clusterfuzzlite").is_dir():
            return None
        return "no ClusterFuzzLite configuration or pre-generated evidence was found"


class FalcoAdapter(AssuranceEvidenceAdapter):
    name = "falco"
    evidence_kind = "falco"
    default_report = "falco.json"
    default_domain = "security"
    default_area = "runtime-threat-detection"
    reference = "https://falco.org/docs/"

    def not_applicable_reason(self, target: Path) -> str | None:
        return _runtime_evidence_applicability(self, target, "Falco")


class KubescapeAdapter(AssuranceEvidenceAdapter):
    name = "kubescape"
    evidence_kind = "kubescape"
    default_report = "kubescape.json"
    default_domain = "security"
    default_area = "deployed-kubernetes-security"
    reference = "https://kubescape.io/docs/scanning/"

    def not_applicable_reason(self, target: Path) -> str | None:
        configured = configured_path(
            target, self.config.artifacts_path, self.default_report
        )
        if configured.is_file() or _has_kubernetes_shape(target):
            return None
        return "no Kubernetes deployment or pre-generated Kubescape evidence was found"


class ProwlerAdapter(AssuranceEvidenceAdapter):
    name = "prowler"
    evidence_kind = "prowler"
    default_report = "prowler.json"
    default_domain = "security"
    default_area = "deployed-cloud-posture-and-drift"
    reference = "https://docs.prowler.com/introduction"

    def not_applicable_reason(self, target: Path) -> str | None:
        configured = configured_path(
            target, self.config.artifacts_path, self.default_report
        )
        if configured.is_file() or _has_cloud_shape(target):
            return None
        return "no cloud deployment shape or pre-generated Prowler evidence was found"


class CloudAttackPathAdapter(AssuranceEvidenceAdapter):
    name = "cloud-attack-path"
    evidence_kind = "cloud-attack-path"
    default_report = "cloud-attack-path.json"
    default_domain = "security"
    default_area = "cloud-identity-and-network-attack-paths"
    reference = "https://github.com/lyft/cartography"

    def not_applicable_reason(self, target: Path) -> str | None:
        configured = configured_path(
            target, self.config.artifacts_path, self.default_report
        )
        if configured.is_file() or _has_cloud_shape(target):
            return None
        return "no cloud deployment shape or pre-generated cloud attack-path evidence was found"


class RaspAdapter(AssuranceEvidenceAdapter):
    name = "rasp"
    evidence_kind = "rasp"
    default_report = "rasp.json"
    default_domain = "security"
    default_area = "runtime-application-self-protection"
    reference = "https://coraza.io/docs/"

    def not_applicable_reason(self, target: Path) -> str | None:
        return _web_evidence_applicability(self, target)


class NativeSanitizersAdapter(AssuranceEvidenceAdapter):
    name = "native-sanitizers"
    evidence_kind = "native-sanitizers"
    default_report = "native-sanitizers.json"
    default_domain = "security"
    default_area = "native-memory-and-undefined-behavior-testing"
    reference = "https://clang.llvm.org/docs/AddressSanitizer.html"

    def not_applicable_reason(self, target: Path) -> str | None:
        configured = configured_path(
            target, self.config.artifacts_path, self.default_report
        )
        if configured.is_file() or _has_native_source(target):
            return None
        return "no native source or pre-generated sanitizer evidence was found"


class MobSfAdapter(AssuranceEvidenceAdapter):
    name = "mobsf"
    evidence_kind = "mobsf"
    default_report = "mobsf.json"
    default_domain = "security"
    default_area = "mobile-application-security-testing"
    reference = "https://mobsf.github.io/docs/"

    def not_applicable_reason(self, target: Path) -> str | None:
        configured = configured_path(
            target, self.config.artifacts_path, self.default_report
        )
        if configured.is_file() or _has_mobile_shape(target):
            return None
        return "no mobile application shape or pre-generated MobSF evidence was found"


class TlsScanAdapter(AssuranceEvidenceAdapter):
    name = "tls-scan"
    evidence_kind = "tls-scan"
    default_report = "tls-scan.json"
    default_domain = "security"
    default_area = "deployed-transport-security-testing"
    reference = "https://nabla-c0d3.github.io/sslyze/documentation/"

    def not_applicable_reason(self, target: Path) -> str | None:
        return _web_evidence_applicability(self, target)


class PolyglotAdapter(AssuranceEvidenceAdapter):
    name = "polyglot"
    evidence_kind = "polyglot"
    default_report = "polyglot.json"
    default_domain = "security"
    default_area = "polyglot-semantic-security-analysis"
    reference = "https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/"

    def not_applicable_reason(self, target: Path) -> str | None:
        configured = configured_path(
            target, self.config.artifacts_path, self.default_report
        )
        if configured.is_file() or _has_non_python_source(target):
            return None
        return "no supported non-Python source or pre-generated polyglot evidence was found"


class SecretVerificationAdapter(AssuranceEvidenceAdapter):
    name = "secret-verification"
    evidence_kind = "secret-verification"
    default_report = "secret-verification.json"
    default_domain = "security"
    default_area = "connected-secret-status-verification"
    reference = "https://github.com/trufflesecurity/trufflehog"

    def not_applicable_reason(self, target: Path) -> str | None:
        configured = configured_path(
            target, self.config.artifacts_path, self.default_report
        )
        if (
            configured.is_file()
            or (target / "security" / "secret-verification-policy.json").is_file()
        ):
            return None
        return "no connected secret-verification policy or pre-generated evidence was found"


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


def _web_evidence_applicability(
    adapter: AssuranceEvidenceAdapter, target: Path
) -> str | None:
    configured = configured_path(
        target, adapter.config.artifacts_path, adapter.default_report
    )
    if configured.is_file() or _has_web_surface(target):
        return None
    return (
        f"no web application surface or pre-generated {adapter.evidence_kind} "
        "evidence was found"
    )


def _classified_evidence_applicability(
    adapter: AssuranceEvidenceAdapter, target: Path, surface: str
) -> str | None:
    configured = configured_path(
        target, adapter.config.artifacts_path, adapter.default_report
    )
    if configured.is_file() or surface in classify_repository_surfaces(target):
        return None
    return (
        f"no {surface} runtime surface or pre-generated {adapter.evidence_kind} "
        "evidence was found"
    )


def _runtime_evidence_applicability(
    adapter: AssuranceEvidenceAdapter, target: Path, label: str
) -> str | None:
    configured = configured_path(
        target, adapter.config.artifacts_path, adapter.default_report
    )
    if configured.is_file() or _has_container_shape(target):
        return None
    return f"no container deployment or pre-generated {label} evidence was found"


def _has_web_surface(target: Path) -> bool:
    return "web" in classify_repository_surfaces(target)


def _has_container_shape(target: Path) -> bool:
    return "container" in classify_repository_surfaces(target)


def _has_kubernetes_shape(target: Path) -> bool:
    return any(
        path.name.casefold() == "chart.yaml" or _looks_like_kubernetes_manifest(path)
        for path in maintained_repository_files(target)
    )


def _looks_like_kubernetes_manifest(path: Path) -> bool:
    if path.suffix.casefold() not in {".yaml", ".yml"}:
        return False
    try:
        if path.stat().st_size > 4 * 1024 * 1024:
            return False
        prefix = path.read_text(encoding="utf-8", errors="replace")[: 128 * 1024]
    except OSError:
        return False
    return "apiVersion:" in prefix and "kind:" in prefix


def _has_cloud_shape(target: Path) -> bool:
    return "cloud" in classify_repository_surfaces(target)


def _has_native_source(target: Path) -> bool:
    return any(
        path.suffix.casefold() in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".rs"}
        for path in maintained_repository_files(target)
    )


def _has_mobile_shape(target: Path) -> bool:
    return "mobile" in classify_repository_surfaces(target)


def _has_non_python_source(target: Path) -> bool:
    return "polyglot" in classify_repository_surfaces(target)
