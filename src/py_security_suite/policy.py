from __future__ import annotations

from dataclasses import dataclass

from .config import SuiteConfig
from .models import Finding, FindingStatus, Inventory, Outcome, ToolRun, ToolStatus
from .risk_acceptance import apply_risk_acceptances


_PRODUCTION_EVIDENCE = (
    "hypothesis",
    "crosshair",
    "atheris",
    "mutmut",
    "pytm",
    "scorecard",
)
_CONDITIONAL_PRODUCTION_EVIDENCE = (
    "surface-inventory",
    "event-security",
    "database-security",
    "ai-security",
    "ruleset-regression",
    "schemathesis",
    "clusterfuzzlite",
    "zap",
    "nuclei",
    "oast",
    "restler",
    "protocol-security",
    "fuzz-introspector",
    "browser-security",
    "authorization-security",
    "iast",
    "falco",
    "kubescape",
    "prowler",
    "cloud-attack-path",
    "rasp",
    "native-sanitizers",
    "mobsf",
    "tls-scan",
    "polyglot",
    "secret-verification",
)
_RELEASE_EVIDENCE = (
    "check-manifest",
    "clamav",
    "github-attestation",
    "in-toto",
    "oci-image",
    "reproducible-build",
    "yara",
    "pypi-attestations",
)


@dataclass(slots=True)
class PolicyDecision:
    outcome: Outcome
    reasons: list[str]


def evaluate_policy(
    *,
    config: SuiteConfig,
    findings: list[Finding],
    tool_runs: list[ToolRun],
    network_isolation_attested: bool,
    inventory: Inventory | None = None,
    context_errors: list[str] | None = None,
) -> PolicyDecision:
    reasons: list[str] = list(context_errors or [])
    by_tool = {run.tool: run for run in tool_runs}
    reasons.extend(
        apply_risk_acceptances(
            findings,
            config.policy.risk_acceptance_path,
            config.policy.risk_acceptance_sha256,
        )
    )

    if config.isolation.require_attestation and not network_isolation_attested:
        reasons.append(
            "required external network-isolation attestation was not provided"
        )
    if (
        config.isolation.enforcement_mode == "sandbox-launcher"
        and not config.isolation.sandbox_organization_approved
    ):
        reasons.append("sandbox launcher is not bound by the organization policy")

    if (
        inventory is not None
        and inventory.source_sha256
        and not inventory.source_integrity_verified
    ):
        reasons.append(
            "target content changed during scanner execution; discard the "
            "result and investigate scanner or concurrent-process writes"
        )

    explicitly_required = set(config.policy.required_scanners)
    for tool in config.required_tools:
        run = by_tool.get(tool)
        if run is None:
            reasons.append(
                f"required scanner {tool} did not produce a tool-health record"
            )
        elif not run.applicable:
            if tool in explicitly_required:
                reasons.append(
                    f"explicitly required scanner {tool} was classified not applicable: "
                    f"{run.error or 'no applicability evidence was retained'}"
                )
            continue
        elif run.status is not ToolStatus.COMPLETED:
            reasons.append(f"required scanner {tool} status is {run.status}")

    if config.profile in {"production", "release"} and inventory is not None:
        reasons.extend(_production_integrity_reasons(config, by_tool))
        reasons.extend(_production_context_reasons(config, by_tool, inventory))
        reasons.extend(_required_evidence_reasons(config.profile, by_tool))

    active_findings = [
        finding
        for finding in findings
        if finding.status is not FindingStatus.SUPPRESSED
    ]
    blocked = 0
    for finding in active_findings:
        intelligence = finding.evidence.get("risk_intelligence", {})
        known_exploited = bool(
            isinstance(intelligence, dict) and intelligence.get("known_exploited")
        )
        release_provenance = config.profile == "release" and finding.area in {
            "artifact-provenance",
            "build-provenance",
        }
        finding.blocking = (
            finding.severity in config.policy.block_severities
            or known_exploited
            or release_provenance
        )
        if finding.blocking:
            blocked += 1

    if reasons:
        return PolicyDecision(Outcome.INCOMPLETE, reasons)
    if blocked:
        severities = ", ".join(
            severity.value for severity in config.policy.block_severities
        )
        known_exploited_count = sum(
            bool(
                isinstance(finding.evidence.get("risk_intelligence"), dict)
                and finding.evidence["risk_intelligence"].get("known_exploited")
            )
            for finding in active_findings
        )
        return PolicyDecision(
            Outcome.FAIL,
            [
                f"{blocked} finding(s) meet blocking criteria: severities "
                f"{severities}; known-exploited findings {known_exploited_count}"
            ],
        )
    if active_findings:
        return PolicyDecision(
            Outcome.WARN,
            [f"{len(active_findings)} non-blocking finding(s) require review"],
        )
    accepted = len(findings) - len(active_findings)
    return PolicyDecision(
        Outcome.PASS,
        [
            "all applicable required scanners completed with no active findings"
            + (f"; {accepted} governed acceptance(s) applied" if accepted else "")
        ],
    )


def exit_code(outcome: Outcome) -> int:
    return {
        Outcome.PASS: 0,
        Outcome.WARN: 0,
        Outcome.FAIL: 1,
        Outcome.INCOMPLETE: 2,
    }[outcome]


def _production_integrity_reasons(
    config: SuiteConfig,
    by_tool: dict[str, ToolRun],
) -> list[str]:
    reasons: list[str] = []
    for tool in config.required_tools:
        run = by_tool.get(tool)
        if run is None or not run.applicable:
            continue
        if (
            not config.tools[tool].executable_sha256
            or not config.tools[tool].executable_organization_approved
        ):
            reasons.append(
                "production scan requires an organization-approved "
                f"executable_sha256 for {tool}"
            )
        elif (
            run.executable_integrity_verified is not True
            or run.executable_unchanged is not True
        ):
            reasons.append(
                f"production scan could not verify the approved executable "
                f"digest and post-execution integrity for {tool}"
            )
        if config.tools[tool].runtime_closure_sha256 and not (
            config.tools[tool].runtime_closure_organization_approved
        ):
            reasons.append(
                "production scan requires the configured runtime_closure_sha256 "
                f"to be organization-approved for {tool}"
            )
        if str(run.version or "unknown").casefold() == "unknown":
            reasons.append(
                f"production scan could not establish the version of required scanner {tool}"
            )
        if config.tools[tool].require_assurance_profile and (
            config.tools[tool].assurance_profile_path is None
            or not config.tools[tool].assurance_profile_sha256
        ):
            reasons.append(
                f"production assurance evidence from {tool} lacks a checkpointed assurance profile"
            )
    for tool in config.required_tools:
        run = by_tool.get(tool)
        if run is None or not run.applicable:
            continue
        tool_config = config.tools[tool]
        uses_auxiliary = bool(tool_config.auxiliary_executable) or (
            run.auxiliary_executable_sha256 is not None
        )
        if not uses_auxiliary:
            continue
        if (
            not tool_config.auxiliary_executable_sha256
            or not tool_config.auxiliary_executable_organization_approved
        ):
            reasons.append(
                "production scan requires an organization-approved "
                f"auxiliary_executable_sha256 for {tool}"
            )
        elif (
            run.auxiliary_executable_integrity_verified is not True
            or run.auxiliary_executable_unchanged is not True
        ):
            reasons.append(
                f"production scan could not verify the approved {tool} auxiliary "
                "executable digest and post-execution integrity"
            )
    return reasons


def _production_context_reasons(
    config: SuiteConfig,
    by_tool: dict[str, ToolRun],
    inventory: Inventory,
) -> list[str]:
    reasons: list[str] = []
    if not inventory.vcs_history_available:
        reasons.append(
            "production scan requires a full VCS checkout so secret history "
            "and source provenance can be evaluated"
        )
    if inventory.declared_dependencies and not inventory.lock_files:
        reasons.append(
            "production scan found declared dependencies without a recognized lock file"
        )
    pysa = by_tool.get("pysa")
    if inventory.python_files and pysa is not None and not pysa.applicable:
        reasons.append(
            "production scan requires configured deep Python data-flow "
            "analysis; Pysa was not applicable"
        )
    if inventory.declared_dependencies:
        for tool in ("cyclonedx-py", "guarddog"):
            run = by_tool.get(tool)
            if run is not None and not run.applicable:
                reasons.append(
                    f"production dependency assurance requires {tool} to be applicable"
                )
    if config.profile == "release" and not inventory.distribution_files:
        reasons.append(
            "release scan requires at least one built wheel or source distribution"
        )
    return reasons


def _required_evidence_reasons(profile: str, by_tool: dict[str, ToolRun]) -> list[str]:
    required: tuple[str, ...] = _PRODUCTION_EVIDENCE
    if profile == "release":
        required = (*required, *_RELEASE_EVIDENCE)
    reasons: list[str] = []
    for tool in required:
        run = by_tool.get(tool)
        if run is None or not run.applicable or run.status is not ToolStatus.COMPLETED:
            reasons.append(
                f"{profile} assurance requires completed, revision-bound {tool} evidence"
            )
    for tool in _CONDITIONAL_PRODUCTION_EVIDENCE:
        run = by_tool.get(tool)
        if run is None:
            reasons.append(
                f"{profile} assurance could not establish {tool} applicability"
            )
        elif run.applicable and run.status is not ToolStatus.COMPLETED:
            reasons.append(
                f"{profile} assurance requires completed, revision-bound {tool} "
                "evidence for this repository shape"
            )
    return reasons
