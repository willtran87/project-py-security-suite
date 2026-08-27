from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .models import Finding
from .path_safety import read_regular_file, resolve_unlinked_path
from .strict_json import canonical_bytes, loads as strict_loads


_POLICY_PATH = "security/llm-adversarial-policy.json"
_MAX_POLICY_BYTES = 2 * 1024 * 1024
_MAX_CAMPAIGNS = 1_000
_MAX_CONTEXT_FILES = 500
_MAX_CONTEXT_BYTES = 64 * 1024 * 1024
_ALLOWED_TOOLS = frozenset(
    {
        "atheris",
        "authorization-security",
        "codeql",
        "crosshair",
        "hypothesis",
        "mutmut",
        "playwright",
        "pysa",
        "restler",
        "schemathesis",
        "semgrep",
    }
)
_DEFAULT_TOOLS = (
    "authorization-security",
    "crosshair",
    "hypothesis",
    "mutmut",
    "schemathesis",
    "semgrep",
)
_PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
_REQUIRED_EVIDENCE_CONTROLS = frozenset(
    {
        "schema-constrained-proposal",
        "prompt-injection-resistance",
        "disposable-worktree",
        "network-deny",
        "command-allowlist",
        "deterministic-oracle",
        "negative-control",
        "mutation-validation",
        "source-bound-evidence",
    }
)


def build_llm_adversarial_plan(
    target: Path,
    findings: list[Finding],
    artifacts: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    """Build a bounded LLM handoff without executing a model or target code."""

    target = target.resolve()
    policy, policy_error = _load_policy(target)
    context_candidates: list[dict[str, Any]] = []
    campaign_candidates: list[dict[str, Any]] = []
    _finding_candidates(findings, context_candidates, campaign_candidates)
    _application_candidates(artifacts, context_candidates, campaign_candidates)
    _domain_candidates(artifacts, context_candidates, campaign_candidates)
    _architecture_candidates(artifacts, context_candidates, campaign_candidates)
    _quality_candidates(artifacts, context_candidates, campaign_candidates)

    context, context_errors, context_truncated = _context_manifest(
        target,
        context_candidates,
        maximum_files=int(policy["maximum_context_files"]),
        maximum_bytes=int(policy["maximum_context_bytes"]),
    )
    context_ids = {item["id"] for item in context}
    campaigns = _campaigns(
        campaign_candidates,
        context_ids=context_ids,
        maximum=int(policy["maximum_campaigns"]),
        allowed_tools=tuple(str(item) for item in policy["allowed_tools"]),
        maximum_iterations=int(policy["maximum_iterations"]),
        generated_test_root=str(policy["allowed_test_roots"][0]),
    )
    campaign_truncated = len(campaign_candidates) > len(campaigns)
    source_inventory = artifacts.get("source-inventory.json")
    source_sha256 = (
        str(source_inventory.get("source_sha256") or "")
        if isinstance(source_inventory, dict)
        else ""
    )
    evidence = _evidence_accounting(
        artifacts.get("llm-adversarial-summary.json"),
        source_sha256=source_sha256,
        campaign_ids={item["id"] for item in campaigns},
    )
    for campaign in campaigns:
        campaign["evidence_status"] = evidence["campaign_status"].get(
            campaign["id"], "not-run"
        )
    tasks = _execution_tasks(campaigns, policy)
    errors = ([policy_error] if policy_error else []) + context_errors
    complete = not errors and not context_truncated and not campaign_truncated
    planning_enabled = bool(policy["enabled"])
    execution_ready = (
        planning_enabled
        and bool(policy["present"])
        and complete
        and bool(campaigns)
        and policy["network_policy"] == "deny"
        and policy["write_scope"] == "generated-tests-only"
        and policy["require_human_approval_before_execution"] is True
        and policy["require_negative_control"] is True
        and policy["require_mutation_validation"] is True
    )
    source_bound = bool(re.fullmatch(r"[0-9a-f]{64}", source_sha256))
    if not source_bound:
        errors.append("source inventory does not contain a valid source digest")
        complete = False
        execution_ready = False
    counts = {
        status: sum(item["evidence_status"] == status for item in campaigns)
        for status in (
            "not-run",
            "inconclusive",
            "exercised-no-confirmed-defect",
            "confirmed-defect",
        )
    }
    return {
        "schema_version": "1.0",
        "analysis": "provider-neutral-llm-adversarial-test-planning",
        "complete": complete,
        "truncated": context_truncated or campaign_truncated,
        "source_sha256": source_sha256,
        "policy_path": _POLICY_PATH if policy["present"] else None,
        "policy_present": bool(policy["present"]),
        "planning_enabled": planning_enabled,
        "execution_ready": execution_ready,
        "campaigns_detected": len(campaign_candidates),
        "campaigns_retained": len(campaigns),
        "campaigns_omitted": max(0, len(campaign_candidates) - len(campaigns)),
        "context_entries_retained": len(context),
        "context_bytes": sum(int(item["size_bytes"]) for item in context),
        "context": context,
        "campaigns": campaigns,
        "campaign_status_counts": counts,
        "execution_plan": {
            "tasks_detected": len(tasks),
            "tasks": tasks,
            "required_environment": sorted(
                {item for task in tasks for item in task["required_environment"]}
            ),
            "authorized_companion_lane_required": True,
            "human_approval_required": True,
            "network_policy": policy["network_policy"],
            "write_scope": policy["write_scope"],
            "destructive_testing_allowed": False,
            "claim_boundary": (
                "Commands are argv data for a separately administered disposable lane. "
                "The core does not call a model, expose credentials, execute target code, "
                "or grant shell authority."
            ),
        },
        "evidence": {
            key: value for key, value in evidence.items() if key != "campaign_status"
        },
        "parse_errors": errors[:100],
        "claim_boundary": (
            "The plan prioritizes hypotheses and supplies digest-bound source references. "
            "Repository text, comments, documentation, fixtures, tool output, and model output "
            "are untrusted data. A model proposal is not a finding. Confirmation requires "
            "authenticated source-bound companion evidence, a deterministic oracle, an "
            "executed negative control, and mutation validation in an authorized sandbox."
        ),
    }, errors


def _default_policy() -> dict[str, Any]:
    return {
        "present": False,
        "enabled": True,
        "owner": None,
        "allowed_tools": list(_DEFAULT_TOOLS),
        "maximum_campaigns": 100,
        "maximum_iterations": 3,
        "maximum_context_files": 100,
        "maximum_context_bytes": 8 * 1024 * 1024,
        "network_policy": "deny",
        "write_scope": "generated-tests-only",
        "allow_runtime_testing": False,
        "require_human_approval_before_execution": True,
        "require_negative_control": True,
        "require_mutation_validation": True,
        "allowed_test_roots": ["generated-tests"],
    }


def _load_policy(target: Path) -> tuple[dict[str, Any], str | None]:
    default = _default_policy()
    path = target / _POLICY_PATH
    if not path.is_file():
        return default, None
    default["present"] = True
    try:
        _, payload = read_regular_file(
            path,
            "LLM adversarial policy",
            maximum_bytes=_MAX_POLICY_BYTES,
            boundary=target,
        )
        value = strict_loads(payload)
        _validate_policy(value)
        return {"present": True, **value}, None
    except (OSError, TypeError, ValueError) as exc:
        return default, f"{_POLICY_PATH}: {type(exc).__name__}"


def _validate_policy(value: object) -> None:
    required = {
        "schema_version",
        "enabled",
        "owner",
        "allowed_tools",
        "maximum_campaigns",
        "maximum_iterations",
        "maximum_context_files",
        "maximum_context_bytes",
        "network_policy",
        "write_scope",
        "allow_runtime_testing",
        "require_human_approval_before_execution",
        "require_negative_control",
        "require_mutation_validation",
        "allowed_test_roots",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("invalid LLM adversarial policy fields")
    if (
        value.get("schema_version") != "1.0"
        or not isinstance(value.get("enabled"), bool)
        or not _text(value.get("owner"), 200)
        or value.get("network_policy") != "deny"
        or value.get("write_scope") != "generated-tests-only"
        or value.get("allow_runtime_testing") is not False
        or value.get("require_human_approval_before_execution") is not True
        or value.get("require_negative_control") is not True
        or value.get("require_mutation_validation") is not True
    ):
        raise ValueError("unsafe LLM adversarial policy")
    allowed_tools = value.get("allowed_tools")
    if (
        not isinstance(allowed_tools, list)
        or not allowed_tools
        or len(allowed_tools) > len(_ALLOWED_TOOLS)
        or len(set(allowed_tools)) != len(allowed_tools)
        or not set(allowed_tools).issubset(_ALLOWED_TOOLS)
    ):
        raise ValueError("invalid LLM adversarial tool allowlist")
    for field, minimum, maximum in (
        ("maximum_campaigns", 1, _MAX_CAMPAIGNS),
        ("maximum_iterations", 1, 10),
        ("maximum_context_files", 1, _MAX_CONTEXT_FILES),
        ("maximum_context_bytes", 1024, _MAX_CONTEXT_BYTES),
    ):
        item = value.get(field)
        if (
            not isinstance(item, int)
            or isinstance(item, bool)
            or not minimum <= item <= maximum
        ):
            raise ValueError(f"invalid LLM adversarial policy limit: {field}")
    roots = value.get("allowed_test_roots")
    if roots != ["generated-tests"] or not all(
        _safe_relative_root(item) for item in roots
    ):
        raise ValueError("invalid generated-test roots")


def _finding_candidates(
    findings: list[Finding],
    context: list[dict[str, Any]],
    campaigns: list[dict[str, Any]],
) -> None:
    severity_priority = {
        "critical": "P0",
        "high": "P0",
        "medium": "P1",
        "low": "P2",
        "informational": "P3",
        "unknown": "P3",
    }
    for finding in findings[:10_000]:
        location = finding.locations[0] if finding.locations else None
        path = str(location.path) if location is not None else "<repository>"
        line = int(location.start_line) if location and location.start_line else None
        context_id = _identity("finding", finding.finding_id)
        context.append(
            {
                "id": context_id,
                "kind": "finding",
                "path": path,
                "start_line": line,
                "end_line": int(location.end_line)
                if location and location.end_line
                else line,
                "symbol": None,
                "rationale": finding.title[:1_000],
                "source_artifacts": ["findings.json"],
                "rank": _PRIORITY_ORDER[severity_priority[finding.severity.value]],
            }
        )
        campaigns.append(
            {
                "seed": f"finding:{finding.finding_id}",
                "attack_class": "finding-reproduction",
                "priority": severity_priority[finding.severity.value],
                "objective": f"Reproduce or falsify: {finding.title}",
                "hypothesis": finding.description[:2_000],
                "context_ids": [context_id],
                "oracle": "security-invariant",
                "recommended_tools": ["semgrep", "hypothesis", "mutmut"],
            }
        )


def _application_candidates(
    artifacts: dict[str, Any],
    context: list[dict[str, Any]],
    campaigns: list[dict[str, Any]],
) -> None:
    document = artifacts.get("application-contract-analysis.json")
    if not isinstance(document, dict):
        return
    scenarios = document.get("generated_test_scenarios")
    if not isinstance(scenarios, list):
        return
    for scenario in scenarios[:10_000]:
        if not isinstance(scenario, dict):
            continue
        scenario_id = str(scenario.get("id") or "")
        if not scenario_id:
            continue
        context_id = _identity("api", scenario_id)
        context.append(
            {
                "id": context_id,
                "kind": "application-contract",
                "path": "<repository>",
                "start_line": None,
                "end_line": None,
                "symbol": f"{scenario.get('method', '')} {scenario.get('path', '')}".strip(),
                "rationale": str(scenario.get("rationale") or "")[:1_000],
                "source_artifacts": ["application-contract-analysis.json"],
                "rank": _PRIORITY_ORDER.get(str(scenario.get("priority")), 3),
            }
        )
        kind = str(scenario.get("kind") or "")
        tools = (
            ["authorization-security"]
            if kind
            in {
                "authenticated-allow",
                "anonymous-deny",
                "cross-tenant-deny",
                "replay-safety",
            }
            else ["hypothesis", "schemathesis"]
        )
        execution = scenario.get("execution")
        oracle = (
            str(execution.get("oracle") or "security-invariant")
            if isinstance(execution, dict)
            else "security-invariant"
        )
        campaigns.append(
            {
                "seed": f"api:{scenario_id}",
                "attack_class": "api-abuse",
                "priority": str(scenario.get("priority") or "P2"),
                "objective": str(scenario.get("rationale") or scenario_id)[:1_000],
                "hypothesis": f"The {kind} oracle may fail for {scenario.get('method')} {scenario.get('path')}.",
                "context_ids": [context_id],
                "oracle": oracle,
                "recommended_tools": tools,
            }
        )


def _domain_candidates(
    artifacts: dict[str, Any],
    context: list[dict[str, Any]],
    campaigns: list[dict[str, Any]],
) -> None:
    document = artifacts.get("domain-assurance.json")
    if not isinstance(document, dict):
        return
    domains = document.get("domains")
    if not isinstance(domains, list):
        return
    for domain in domains:
        if not isinstance(domain, dict) or domain.get("applicable") is not True:
            continue
        if domain.get("status") == "covered":
            continue
        name = str(domain.get("name") or "unknown")
        context_id = _identity("domain", name)
        context.append(
            {
                "id": context_id,
                "kind": "domain-gap",
                "path": (
                    str(document.get("policy_path"))
                    if document.get("policy_present") is True
                    else "<repository>"
                ),
                "start_line": None,
                "end_line": None,
                "symbol": name,
                "rationale": str(domain.get("recommendation") or "")[:1_000],
                "source_artifacts": ["domain-assurance.json"],
                "rank": 1,
            }
        )
        campaigns.append(
            {
                "seed": f"domain:{name}",
                "attack_class": "domain-invariant",
                "priority": "P1",
                "objective": f"Design an adversarial test for the uncovered {name} assurance domain.",
                "hypothesis": str(
                    domain.get("recommendation")
                    or "Unmodeled domain behavior may fail open."
                )[:2_000],
                "context_ids": [context_id],
                "oracle": "domain-invariant",
                "recommended_tools": ["hypothesis", "crosshair", "mutmut"],
            }
        )


def _architecture_candidates(
    artifacts: dict[str, Any],
    context: list[dict[str, Any]],
    campaigns: list[dict[str, Any]],
) -> None:
    document = artifacts.get("static-architecture.json")
    targets = (
        document.get("ranked_refactoring_targets")
        if isinstance(document, dict)
        else None
    )
    if not isinstance(targets, list):
        return
    for target_item in targets[:1_000]:
        if not isinstance(target_item, dict):
            continue
        subject = str(target_item.get("subject") or "architecture-target")
        modules = target_item.get("modules")
        path = (
            str(modules[0]) if isinstance(modules, list) and modules else "<repository>"
        )
        context_id = _identity("architecture", f"{target_item.get('kind')}:{subject}")
        priority = str(target_item.get("priority") or "P2")
        context.append(
            {
                "id": context_id,
                "kind": "architecture-target",
                "path": path,
                "start_line": None,
                "end_line": None,
                "symbol": subject[:500],
                "rationale": str(target_item.get("reason") or "")[:1_000],
                "source_artifacts": ["static-architecture.json"],
                "rank": _PRIORITY_ORDER.get(priority, 3),
            }
        )
        campaigns.append(
            {
                "seed": f"architecture:{context_id}",
                "attack_class": "architecture-challenge",
                "priority": priority if priority in _PRIORITY_ORDER else "P2",
                "objective": f"Test whether architecture target {subject} creates a security or correctness failure.",
                "hypothesis": str(
                    target_item.get("reason")
                    or "Architectural coupling may amplify failure."
                )[:2_000],
                "context_ids": [context_id],
                "oracle": "architecture-invariant",
                "recommended_tools": ["semgrep", "codeql", "mutmut"],
            }
        )


def _quality_candidates(
    artifacts: dict[str, Any],
    context: list[dict[str, Any]],
    campaigns: list[dict[str, Any]],
) -> None:
    document = artifacts.get("code-health.json")
    clusters = (
        document.get("root_cause_clusters") if isinstance(document, dict) else None
    )
    if not isinstance(clusters, list):
        return
    for cluster in clusters[:1_000]:
        if not isinstance(cluster, dict):
            continue
        path = str(cluster.get("path") or "<repository>")
        symbol = str(cluster.get("symbol") or "")
        seed = f"quality:{path}:{symbol}:{cluster.get('family')}"
        context_id = _identity("quality", seed)
        priority = str(cluster.get("priority") or "P2")
        context.append(
            {
                "id": context_id,
                "kind": "quality-cluster",
                "path": path,
                "start_line": _optional_positive_integer(cluster.get("first_line")),
                "end_line": _optional_positive_integer(cluster.get("last_line")),
                "symbol": symbol[:500] or None,
                "rationale": str(cluster.get("remediation") or "")[:1_000],
                "source_artifacts": ["code-health.json"],
                "rank": _PRIORITY_ORDER.get(priority, 3),
            }
        )
        campaigns.append(
            {
                "seed": seed,
                "attack_class": "quality-invariant",
                "priority": priority if priority in _PRIORITY_ORDER else "P2",
                "objective": f"Expose an observable failure behind the {cluster.get('family')} cluster in {symbol or path}.",
                "hypothesis": "Correlated code-health symptoms may share a behavioral root cause.",
                "context_ids": [context_id],
                "oracle": "behavioral-invariant",
                "recommended_tools": ["hypothesis", "crosshair", "mutmut"],
            }
        )


def _context_manifest(
    target: Path,
    candidates: list[dict[str, Any]],
    *,
    maximum_files: int,
    maximum_bytes: int,
) -> tuple[list[dict[str, Any]], list[str], bool]:
    result: list[dict[str, Any]] = []
    errors: list[str] = []
    seen: set[str] = set()
    bytes_used = 0
    truncated = False
    for candidate in sorted(candidates, key=lambda item: (item["rank"], item["id"])):
        if candidate["id"] in seen:
            continue
        if len(result) >= maximum_files:
            truncated = True
            break
        seen.add(candidate["id"])
        path = str(candidate["path"])
        size = 0
        digest: str | None = None
        if path != "<repository>":
            relative = path.partition("#")[0].partition(":")[0]
            try:
                resolved = resolve_unlinked_path(
                    target / relative, "LLM context source", boundary=target
                )
                if resolved.is_file():
                    size = resolved.stat().st_size
                    if bytes_used + size > maximum_bytes:
                        truncated = True
                        continue
                    _, payload = read_regular_file(
                        resolved,
                        "LLM context source",
                        maximum_bytes=maximum_bytes,
                        boundary=target,
                    )
                    digest = hashlib.sha256(payload).hexdigest()
                    bytes_used += size
                else:
                    errors.append(f"{relative}: FileNotFoundError")
            except (OSError, ValueError) as exc:
                errors.append(f"{relative}: {type(exc).__name__}")
        result.append(
            {key: value for key, value in candidate.items() if key != "rank"}
            | {
                "size_bytes": size,
                "sha256": digest,
                "content_trust": "untrusted-repository-data",
                "content_included": False,
            }
        )
    return result, errors[:100], truncated


def _campaigns(
    candidates: list[dict[str, Any]],
    *,
    context_ids: set[str],
    maximum: int,
    allowed_tools: tuple[str, ...],
    maximum_iterations: int,
    generated_test_root: str,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    allowed = set(allowed_tools)
    ordered = sorted(
        candidates,
        key=lambda item: (
            _PRIORITY_ORDER.get(str(item["priority"]), 3),
            str(item["seed"]),
        ),
    )
    for candidate in ordered:
        campaign_id = _identity("campaign", str(candidate["seed"]))
        if campaign_id in seen:
            continue
        references = [item for item in candidate["context_ids"] if item in context_ids]
        if not references:
            continue
        tools = [item for item in candidate["recommended_tools"] if item in allowed]
        if not tools:
            tools = [allowed_tools[0]]
        seen.add(campaign_id)
        result.append(
            {
                "id": campaign_id,
                "attack_class": candidate["attack_class"],
                "priority": candidate["priority"],
                "objective": candidate["objective"],
                "hypothesis": candidate["hypothesis"],
                "context_ids": references,
                "allowed_tools": tools,
                "oracle": {
                    "kind": candidate["oracle"],
                    "expected": "The declared security or behavioral invariant holds.",
                    "deterministic": True,
                    "llm_judge_sufficient": False,
                },
                "negative_control_required": True,
                "mutation_validation_required": True,
                "maximum_iterations": maximum_iterations,
                "generated_test_root": generated_test_root,
                "evidence_status": "not-run",
            }
        )
        if len(result) >= maximum:
            break
    return result


def _execution_tasks(
    campaigns: list[dict[str, Any]], policy: dict[str, Any]
) -> list[dict[str, Any]]:
    if not policy["enabled"]:
        return []
    result: list[dict[str, Any]] = []
    for campaign in campaigns:
        result.append(
            {
                "task_id": f"{campaign['id']}:llm-adversarial",
                "campaign_id": campaign["id"],
                "consumer": "llm-adversarial",
                "protocol": "llm-adversarial-proposal-v1",
                "command": [
                    "python",
                    "-m",
                    "companion.llm_adversarial",
                    "validate",
                    "--plan",
                    "${PYSEC_LLM_ADVERSARIAL_PLAN}",
                    "--proposal",
                    "${PYSEC_LLM_ADVERSARIAL_PROPOSAL}",
                    "--campaign",
                    campaign["id"],
                    "--source-root",
                    "${PYSEC_SOURCE_ROOT}",
                    "--workspace",
                    "${PYSEC_DISPOSABLE_WORKTREE}",
                    "--output",
                    "${PYSEC_LLM_VALIDATED_PROPOSAL}",
                ],
                "required_environment": [
                    "PYSEC_DISPOSABLE_WORKTREE",
                    "PYSEC_LLM_ADVERSARIAL_PLAN",
                    "PYSEC_LLM_ADVERSARIAL_PROPOSAL",
                    "PYSEC_LLM_EXECUTION_APPROVAL",
                    "PYSEC_LLM_VALIDATED_PROPOSAL",
                    "PYSEC_SOURCE_ROOT",
                ],
                "allowed_tools": campaign["allowed_tools"],
                "maximum_iterations": campaign["maximum_iterations"],
                "network_policy": "deny",
                "write_scope": "generated-tests-only",
                "expected_evidence": "llm-adversarial.json",
                "source_bound_evidence_required": True,
            }
        )
    return result


def _evidence_accounting(
    value: object,
    *,
    source_sha256: str,
    campaign_ids: set[str],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "present": False,
        "source_bound": False,
        "execution_complete": False,
        "campaigns_exercised": 0,
        "confirmed_defects": 0,
        "campaign_status": {},
    }
    if not isinstance(value, dict) or value.get("kind") != "llm-adversarial":
        return result
    result["present"] = True
    binding = value.get("evidence_binding")
    source_bound = (
        bool(source_sha256)
        and value.get("source_sha256") == source_sha256
        and isinstance(binding, dict)
        and binding.get("verified") is True
        and binding.get("authenticated") is True
    )
    result["source_bound"] = source_bound
    execution = value.get("execution")
    features = execution.get("features") if isinstance(execution, dict) else None
    observed_features = set(features) if isinstance(features, list) else set()
    complete = (
        source_bound
        and isinstance(execution, dict)
        and execution.get("status") == "completed"
        and _REQUIRED_EVIDENCE_CONTROLS.issubset(observed_features)
    )
    result["execution_complete"] = complete
    if not complete or not isinstance(execution, dict):
        return result
    proof = execution.get("control_proof")
    ledger = proof.get("case_ledger") if isinstance(proof, dict) else None
    observed: dict[str, list[bool]] = {}
    failed_cases: dict[str, str] = {}
    observed_controls: set[str] = set()
    if isinstance(ledger, list):
        for item in ledger[:10_000]:
            if not isinstance(item, dict):
                continue
            campaign_id = str(item.get("target_id") or "")
            if campaign_id not in campaign_ids:
                continue
            matched = str(item.get("expected")) == str(item.get("observed"))
            observed.setdefault(campaign_id, []).append(matched)
            control = str(item.get("control") or "")
            if control:
                observed_controls.add(control)
            case_id = str(item.get("id") or "")
            if case_id and not matched:
                failed_cases[case_id] = campaign_id
    if not _REQUIRED_EVIDENCE_CONTROLS.issubset(observed_controls):
        result["execution_complete"] = False
        return result
    confirmed: set[str] = set()
    findings = value.get("findings")
    if isinstance(findings, list):
        for item in findings[:10_000]:
            if not isinstance(item, dict):
                continue
            evidence = item.get("evidence")
            campaign_id = (
                str(evidence.get("campaign_id") or evidence.get("target_id") or "")
                if isinstance(evidence, dict)
                else ""
            )
            case_id = (
                str(evidence.get("case_id") or "") if isinstance(evidence, dict) else ""
            )
            if campaign_id in campaign_ids and failed_cases.get(case_id) == campaign_id:
                confirmed.add(campaign_id)
    statuses: dict[str, str] = {}
    for campaign_id, matches in observed.items():
        if campaign_id in confirmed:
            statuses[campaign_id] = "confirmed-defect"
        elif matches and all(matches):
            statuses[campaign_id] = "exercised-no-confirmed-defect"
        else:
            statuses[campaign_id] = "inconclusive"
    result["campaign_status"] = statuses
    result["campaigns_exercised"] = len(observed)
    result["confirmed_defects"] = sum(
        status == "confirmed-defect" for status in statuses.values()
    )
    return result


def _identity(kind: str, value: str) -> str:
    digest = hashlib.sha256(f"{kind}\0{value}".encode()).hexdigest()[:20]
    return f"llm-{kind}-{digest}"


def _optional_positive_integer(value: object) -> int | None:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value > 0
        else None
    )


def _text(value: object, maximum: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum


def _safe_relative_root(value: object) -> bool:
    if not _text(value, 200):
        return False
    path = Path(str(value))
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and str(value) not in {".", ""}
    )


def plan_sha256(value: dict[str, Any]) -> str:
    """Return the canonical plan digest used by companion proposals."""

    return hashlib.sha256(canonical_bytes(value)).hexdigest()
