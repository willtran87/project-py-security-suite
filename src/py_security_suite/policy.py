from __future__ import annotations

from dataclasses import dataclass

from .config import SuiteConfig
from .models import Finding, Inventory, Outcome, ToolRun, ToolStatus


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
) -> PolicyDecision:
    reasons: list[str] = []
    by_tool = {run.tool: run for run in tool_runs}

    if config.isolation.require_attestation and not network_isolation_attested:
        reasons.append(
            "required external network-isolation attestation was not provided"
        )

    for tool in config.required_tools:
        run = by_tool.get(tool)
        if run is None:
            reasons.append(f"required scanner {tool} did not produce a tool-health record")
        elif not run.applicable:
            continue
        elif run.status is not ToolStatus.COMPLETED:
            reasons.append(f"required scanner {tool} status is {run.status}")

    if config.profile in {"production", "release"} and inventory is not None:
        if not inventory.vcs_history_available:
            reasons.append(
                "production scan requires a full VCS checkout so secret history "
                "and source provenance can be evaluated"
            )
        if inventory.declared_dependencies and not inventory.lock_files:
            reasons.append(
                "production scan found declared dependencies without a recognized "
                "lock file"
            )
        pysa = by_tool.get("pysa")
        if (
            inventory.python_files
            and pysa is not None
            and not pysa.applicable
        ):
            reasons.append(
                "production scan requires configured deep Python data-flow "
                "analysis; Pysa was not applicable"
            )
        if inventory.declared_dependencies:
            for tool in ("cyclonedx-py", "guarddog"):
                run = by_tool.get(tool)
                if run is not None and not run.applicable:
                    reasons.append(
                        f"production dependency assurance requires {tool} to be "
                        "applicable"
                    )
        if config.profile == "release" and not inventory.distribution_files:
            reasons.append(
                "release scan requires at least one built wheel or source distribution"
            )

    if reasons:
        return PolicyDecision(Outcome.INCOMPLETE, reasons)

    blocked = 0
    for finding in findings:
        finding.blocking = finding.severity in config.policy.block_severities
        if finding.blocking:
            blocked += 1
    if blocked:
        severities = ", ".join(
            severity.value for severity in config.policy.block_severities
        )
        return PolicyDecision(
            Outcome.FAIL,
            [f"{blocked} finding(s) meet blocking severities: {severities}"],
        )
    if findings:
        return PolicyDecision(
            Outcome.WARN,
            [f"{len(findings)} non-blocking finding(s) require review"],
        )
    return PolicyDecision(
        Outcome.PASS,
        ["all applicable required scanners completed with no findings"],
    )


def exit_code(outcome: Outcome) -> int:
    return {
        Outcome.PASS: 0,
        Outcome.WARN: 0,
        Outcome.FAIL: 1,
        Outcome.INCOMPLETE: 2,
    }[outcome]
