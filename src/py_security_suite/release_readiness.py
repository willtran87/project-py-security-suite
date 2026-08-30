from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta

from pathlib import Path
from typing import Any

from .artifact_validation import validate_governed_artifacts
from .benchmark_signing import verify_portable_signing_provider_conformance
from .execution import sha256_file
from .passport import verify_report
from .path_safety import resolve_regular_file
from .strict_json import loads as strict_json_loads
from .trusted_observation import governed_now

_MAX_JSON_BYTES = 128 * 1024 * 1024
_GOVERNED_EFFECTIVENESS_MINIMUMS = {
    "labels": 500,
    "positive_labels": 200,
    "negative_labels": 200,
    "tools": 3,
    "labels_per_tool": 50,
}
_CONTROL_REMEDIATION = {
    "scan-policy": (
        "release-engineering",
        "cross-functional",
        "Resolve every underlying failed control and rerun the exact release candidate.",
        ["pysec release-check REPORT --format json --output release-readiness.json"],
    ),
    "assurance-claims": (
        "application-security",
        "cross-functional",
        "Satisfy every named assurance claim with checksum-bound evidence.",
        [],
    ),
    "external-isolation": (
        "platform-security",
        "organization-security",
        "Issue signed isolation evidence for the exact runner, source digest, and policy window.",
        ["pysec evidence-draft REPORT --output governance-evidence-draft.json"],
    ),
    "scanner-trust": (
        "security-tooling",
        "organization-security",
        "Verify publisher provenance and approve every exact scanner entry-point digest in organization policy.",
        ["pysec evidence-draft REPORT --output governance-evidence-draft.json"],
    ),
    "intelligence-approval": (
        "vulnerability-management",
        "organization-security",
        "Approve the exact consumed intelligence snapshot set and bind its digest in organization policy.",
        ["pysec evidence-draft REPORT --output governance-evidence-draft.json"],
    ),
    "detection-effectiveness": (
        "application-security",
        "repository",
        "Run a digest-bound labeled corpus with the required minimum sample size and resolve misses.",
        ["pysec benchmark REPORT --corpus CORPUS --corpus-sha256 SHA256"],
    ),
    "runtime-trace-correlation": (
        "application-security",
        "platform-security",
        "Provide signed, time-bounded traces bound to this deployment and static boundary graph.",
        [],
    ),
    "signed-release-passport": (
        "release-approver",
        "release-approver",
        "Verify and approve a signed Passport bound to this exact report and artifact payload.",
        ["pysec verify PASSPORT --report REPORT --artifact-root PAYLOAD"],
    ),
    "change-validation-alignment": (
        "quality-engineering",
        "repository",
        "Restore retained diff-coverage assessment scope, resolve every changed-file focused-test and changed-line coverage mismatch, then regenerate the sealed report.",
        [],
    ),
    "signing-provider-conformance": (
        "platform-security",
        "organization-security",
        "Provide fresh, portable conformance receipts for every required external signing provider and key version.",
        [
            "pysec benchmark-provider-check --profile PROFILE --profile-sha256 SHA256 --output RECEIPT.json"
        ],
    ),
}


def assess_release_readiness(
    report: Path,
    *,
    effectiveness_evaluation: Path | None = None,
    effectiveness_sha256: str = "",
    minimum_effectiveness_labels: int = 0,
    minimum_effectiveness_positive_labels: int = 0,
    minimum_effectiveness_negative_labels: int = 0,
    minimum_effectiveness_tools: int = 0,
    minimum_effectiveness_labels_per_tool: int = 0,
    required_effectiveness_tools: tuple[str, ...] = (),
    passport_verification: Path | None = None,
    passport_verification_sha256: str = "",
    require_passport: bool = False,
    provider_conformance: tuple[Path, ...] = (),
    provider_conformance_sha256: tuple[str, ...] = (),
    required_provider_ids: tuple[str, ...] = (),
    maximum_provider_conformance_age_hours: int = 168,
    require_provider_conformance: bool = False,
) -> dict[str, Any]:
    """Build one fail-closed release decision from verified evidence."""
    for value, label in (
        (minimum_effectiveness_labels, "labels"),
        (minimum_effectiveness_positive_labels, "positive labels"),
        (minimum_effectiveness_negative_labels, "negative labels"),
        (minimum_effectiveness_tools, "tools"),
        (minimum_effectiveness_labels_per_tool, "labels per required tool"),
    ):
        if value < 0 or value > 10_000:
            raise ValueError(
                f"minimum effectiveness {label} must be between 0 and 10000"
            )
    _paired(
        effectiveness_evaluation,
        effectiveness_sha256,
        "effectiveness evaluation",
    )
    _paired(
        passport_verification,
        passport_verification_sha256,
        "passport verification",
    )
    if len(provider_conformance) != len(provider_conformance_sha256):
        raise ValueError(
            "provider conformance paths and SHA-256 values must have equal counts"
        )
    if not 1 <= maximum_provider_conformance_age_hours <= 24 * 90:
        raise ValueError(
            "maximum provider conformance age must be between 1 and 2160 hours"
        )
    if any(not value for value in required_provider_ids) or len(
        set(required_provider_ids)
    ) != len(required_provider_ids):
        raise ValueError("required provider IDs must be non-empty and unique")
    verification = verify_report(report)
    root = report.expanduser().resolve()
    manifest = _read_object(root / "scan-manifest.json")
    governed_effectiveness_required = manifest.get("profile") in {
        "production",
        "release",
    }
    if governed_effectiveness_required:
        minimum_effectiveness_labels = max(
            minimum_effectiveness_labels,
            _GOVERNED_EFFECTIVENESS_MINIMUMS["labels"],
        )
        minimum_effectiveness_positive_labels = max(
            minimum_effectiveness_positive_labels,
            _GOVERNED_EFFECTIVENESS_MINIMUMS["positive_labels"],
        )
        minimum_effectiveness_negative_labels = max(
            minimum_effectiveness_negative_labels,
            _GOVERNED_EFFECTIVENESS_MINIMUMS["negative_labels"],
        )
        minimum_effectiveness_tools = max(
            minimum_effectiveness_tools,
            _GOVERNED_EFFECTIVENESS_MINIMUMS["tools"],
        )
        minimum_effectiveness_labels_per_tool = max(
            minimum_effectiveness_labels_per_tool,
            _GOVERNED_EFFECTIVENESS_MINIMUMS["labels_per_tool"],
        )
        run_names = {
            str(run.get("tool") or "")
            for run in (manifest.get("tools") or manifest.get("tool_runs") or [])
            if isinstance(run, dict)
        }
        required_effectiveness_tools = tuple(
            sorted(
                set(required_effectiveness_tools)
                | ({"bandit", "codeql", "semgrep"} & run_names)
            )
        )
    findings_document = _read_object(root / "findings.json")
    claims = _read_object(root / "assurance-claims.json")
    portfolio = _read_object(root / "portfolio-health.json")
    isolation = _optional_object(root / "isolation-attestation.json")
    intelligence = _optional_object(root / "risk-intelligence.json")
    intelligence_approval = _optional_object(root / "intelligence-approval.json")
    trust = _entrypoint_trust(manifest)
    closure = _optional_object(root / "closure-plan.json")
    diff_coverage = _optional_object(root / "diff-coverage.json")
    runtime_trace = _optional_object(root / "runtime-trace-correlation.json")
    if runtime_trace:
        validate_governed_artifacts({"runtime-trace-correlation.json": runtime_trace})

    findings = findings_document.get("findings")
    if not isinstance(findings, list):
        raise TypeError("verified report findings must be an array")
    blocking_findings = sum(
        isinstance(finding, dict)
        and finding.get("blocking") is True
        and finding.get("status") != "suppressed"
        for finding in findings
    )
    claim_values = claims.get("claims")
    if not isinstance(claim_values, list):
        raise TypeError("verified assurance claims must be an array")
    unsatisfied_claims = [
        str(claim.get("control") or "unknown")
        for claim in claim_values
        if isinstance(claim, dict) and claim.get("result") != "satisfied"
    ]
    overall = portfolio.get("overall")
    execution_gaps = (
        int(overall.get("domains_with_execution_gaps") or 0)
        if isinstance(overall, dict)
        else 1
    )
    controls = _report_controls(
        manifest=manifest,
        blocking_findings=blocking_findings,
        unsatisfied_claims=unsatisfied_claims,
        execution_gaps=execution_gaps,
        isolation=isolation,
        trust=trust,
    )
    controls.append(_intelligence_control(intelligence, intelligence_approval))
    controls.append(_change_validation_control(closure, diff_coverage))
    if governed_effectiveness_required:
        runtime_valid = bool(
            isinstance(runtime_trace, dict)
            and runtime_trace.get("complete") is True
            and runtime_trace.get("authority_receipt")
            and int(runtime_trace.get("trace_count") or 0) > 0
            and runtime_trace.get("coverage_percent") == 100.0
            and runtime_trace.get("coverage_observed")
            == runtime_trace.get("coverage_required")
        )
        controls.append(
            _control(
                "runtime-trace-correlation",
                runtime_valid,
                (
                    "Signed deployment-bound runtime trace evidence is complete."
                    if runtime_valid
                    else "Signed deployment-bound runtime trace evidence is required."
                ),
                ["runtime-trace-correlation.json"],
            )
        )
    evaluation_control = _effectiveness_control(
        effectiveness_evaluation,
        effectiveness_sha256,
        minimum_effectiveness_labels,
        minimum_effectiveness_positive_labels,
        minimum_effectiveness_negative_labels,
        minimum_effectiveness_tools,
        minimum_effectiveness_labels_per_tool,
        required_effectiveness_tools,
        verification,
        governed_effectiveness_required,
    )
    if evaluation_control is not None:
        controls.append(evaluation_control)
    passport_control = _passport_control(
        passport_verification,
        passport_verification_sha256,
        require_passport or manifest.get("profile") == "release",
        verification,
    )
    if passport_control is not None:
        controls.append(passport_control)
    provider_control = _provider_conformance_control(
        provider_conformance,
        provider_conformance_sha256,
        required_provider_ids,
        maximum_provider_conformance_age_hours,
        require_provider_conformance,
    )
    if provider_control is not None:
        controls.append(provider_control)

    return _decision(
        controls=controls,
        verification=verification,
        blocking_findings=blocking_findings,
        findings=findings,
        trust=trust,
        closure=closure,
    )


def _provider_conformance_control(
    paths: tuple[Path, ...],
    digests: tuple[str, ...],
    required_provider_ids: tuple[str, ...],
    maximum_age_hours: int,
    required: bool,
) -> dict[str, Any] | None:
    if not paths and not required_provider_ids and not required:
        return None
    verified: dict[str, dict[str, Any]] = {}
    evidence: list[str] = []
    now = governed_now()
    hardened = (
        os.environ.get("PYSEC_REQUIRE_HARDENED_RELEASE_EVIDENCE", "").strip() == "1"
    )
    stale: list[str] = []
    for path, digest in zip(paths, digests, strict=True):
        document = _digest_bound_object(path, digest, "provider conformance receipt")
        result = verify_portable_signing_provider_conformance(document)
        provider_id = str(result["provider_id"])
        if provider_id in verified:
            raise ValueError(f"duplicate provider conformance receipt: {provider_id}")
        observed = result["observed_at"]
        if not isinstance(observed, datetime):
            raise ValueError("provider conformance observation time is invalid")
        if observed > now or now - observed > timedelta(hours=maximum_age_hours):
            stale.append(provider_id)
        if hardened and not result["time_context_sha256"]:
            stale.append(f"{provider_id}:trusted-time")
        verified[provider_id] = result
        evidence.append(f"{path}#provider_id={provider_id}")
    missing = sorted(set(required_provider_ids) - set(verified))
    passed = bool(verified) and not missing and not stale
    details: list[str] = []
    if missing:
        details.append("missing " + ", ".join(missing))
    if stale:
        details.append("stale or untrusted-time " + ", ".join(sorted(stale)))
    if not verified:
        details.append("no portable conformance receipt supplied")
    return _control(
        "signing-provider-conformance",
        passed,
        (
            f"{len(verified)} fresh provider conformance receipt(s) verified."
            if passed
            else "Provider conformance failed: " + "; ".join(details)
        ),
        evidence or ["benchmark-signing-provider-conformance-1.1"],
    )


def _report_controls(
    *,
    manifest: dict[str, Any],
    blocking_findings: int,
    unsatisfied_claims: list[str],
    execution_gaps: int,
    isolation: dict[str, Any],
    trust: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        _control(
            "report-integrity",
            True,
            "The checksum seal and semantic report contract verified.",
            ["checksums.sha256", "scan-manifest.json"],
        ),
        _control(
            "scan-policy",
            manifest.get("outcome") == "pass",
            f"Scan outcome is {manifest.get('outcome', 'unknown')}.",
            ["scan-manifest.json#outcome"],
        ),
        _control(
            "blocking-findings",
            blocking_findings == 0,
            f"{blocking_findings} active blocking finding(s).",
            ["findings.json"],
        ),
        _control(
            "assurance-claims",
            not unsatisfied_claims,
            (
                "All assurance claims are satisfied."
                if not unsatisfied_claims
                else "Unsatisfied claims: " + ", ".join(unsatisfied_claims)
            ),
            ["assurance-claims.json"],
        ),
        _control(
            "operational-coverage",
            execution_gaps == 0,
            f"{execution_gaps} operational domain(s) have execution gaps.",
            ["portfolio-health.json"],
        ),
        _control(
            "external-isolation",
            (
                manifest.get("network_isolation_attested") is True
                and isolation.get("validated") is True
                and isolation.get("organization_approved") is True
            ),
            (
                "Externally enforced isolation evidence is present and validated."
                if isolation.get("validated") is True
                and isolation.get("organization_approved") is True
                else "Validated external isolation evidence is absent."
            ),
            [
                "scan-manifest.json#network_isolation_attested",
                "isolation-attestation.json",
            ],
        ),
        _control(
            "scanner-trust",
            not trust["gaps"],
            (
                f"All {trust['entrypoints']} scanner entry points are approved and unchanged."
                if not trust["gaps"]
                else f"{len(trust['gaps'])} scanner entry-point trust gap(s) remain."
            ),
            ["scan-manifest.json#tools", "scanner-trust.json"],
        ),
    ]


def _intelligence_control(
    intelligence: dict[str, Any], approval: dict[str, Any]
) -> dict[str, Any]:
    configured = intelligence.get("configured") is True
    approved = (
        approval.get("validated") is True
        and approval.get("organization_approved") is True
    )
    detail = (
        "Consumed intelligence snapshots have governed approval."
        if configured and approved
        else "No intelligence snapshots were consumed."
        if not configured
        else "Governed approval for consumed intelligence is absent."
    )
    return _control(
        "intelligence-approval",
        not configured or approved,
        detail,
        ["risk-intelligence.json", "intelligence-approval.json"],
    )


def _change_validation_control(
    closure: dict[str, Any], diff_coverage: dict[str, Any]
) -> dict[str, Any]:
    summary = closure.get("summary")
    if closure.get("schema_version") != "1.2" or not isinstance(summary, dict):
        return _control(
            "change-validation-alignment",
            False,
            "Current closure-plan validation alignment evidence is absent.",
            ["closure-plan.json#summary.validation_alignment_items"],
        )
    stats = diff_coverage.get("src_stats")
    changed_lines = diff_coverage.get("num_changed_lines")
    if (
        diff_coverage.get("schema_version") != "1.0"
        or not isinstance(stats, dict)
        or not isinstance(diff_coverage.get("diff_name"), str)
        or not str(diff_coverage["diff_name"]).strip()
        or not isinstance(changed_lines, int)
        or isinstance(changed_lines, bool)
        or changed_lines < 0
    ):
        return _control(
            "change-validation-alignment",
            False,
            "Retained diff-coverage change-assessment scope is absent; zero validation gaps cannot prove alignment.",
            [
                "closure-plan.json#summary.validation_alignment_items",
                "diff-coverage.json",
            ],
        )
    gaps = int(summary.get("validation_alignment_items") or 0)
    return _control(
        "change-validation-alignment",
        gaps == 0,
        (
            "No changed-file focused-test or changed-line coverage mismatch remains."
            if gaps == 0
            else f"{gaps} changed-file validation alignment gap(s) remain."
        ),
        [
            "closure-plan.json#summary.validation_alignment_items",
            "diff-coverage.json",
        ],
    )


def _decision(
    *,
    controls: list[dict[str, Any]],
    verification: dict[str, Any],
    blocking_findings: int,
    findings: list[Any],
    trust: dict[str, Any],
    closure: dict[str, Any],
) -> dict[str, Any]:
    blockers = [control["id"] for control in controls if control["status"] == "fail"]
    root_blockers = [blocker for blocker in blockers if blocker != "scan-policy"]
    if not root_blockers and "scan-policy" in blockers:
        root_blockers = ["scan-policy"]
    derived_blockers = (
        ["scan-policy"]
        if "scan-policy" in blockers and "scan-policy" not in root_blockers
        else []
    )
    blocker_graph = [
        {"blocker": "scan-policy", "derived_from": blocker}
        for blocker in root_blockers
        if derived_blockers
    ]
    remediation = _remediation(root_blockers, findings, closure)
    authority_counts: dict[str, int] = {}
    for action in remediation:
        authority = str(action["authority"])
        authority_counts[authority] = authority_counts.get(authority, 0) + 1
    validation_groups = sum(
        action.get("blocker") == "change-validation-alignment" for action in remediation
    )
    closure_summary = closure.get("summary")
    validation_subjects = (
        int(closure_summary.get("validation_alignment_items") or 0)
        if isinstance(closure_summary, dict)
        else 0
    )
    return {
        "schema_version": "1.3",
        "decision": "approved" if not blockers else "not_approved",
        "scope": (
            "Fail-closed aggregation of verified release evidence; approval does "
            "not replace organization authorization or deployment admission policy."
        ),
        "report": {
            "scan_id": verification["scan_id"],
            "checksums_sha256": verification["checksums_sha256"],
            "files_verified": verification["file_count"],
        },
        "summary": {
            "controls": len(controls),
            "passed": len(controls) - len(blockers),
            "failed": len(blockers),
            "root_failed": len(root_blockers),
            "derived_failed": len(derived_blockers),
            "blocking_findings": blocking_findings,
            "scanner_entrypoints": trust["entrypoints"],
            "scanner_trust_gaps": len(trust["gaps"]),
            "remediation_actions": len(remediation),
            "validation_remediation_groups": validation_groups,
            "validation_remediation_subjects": validation_subjects,
            "actions_by_authority": dict(sorted(authority_counts.items())),
        },
        "blockers": blockers,
        "root_blockers": root_blockers,
        "derived_blockers": derived_blockers,
        "blocker_graph": blocker_graph,
        "controls": controls,
        "remediation": remediation,
    }


def _remediation(
    blockers: list[str], findings: list[Any], closure: dict[str, Any]
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    if "blocking-findings" in blockers:
        for finding in findings:
            if (
                not isinstance(finding, dict)
                or finding.get("blocking") is not True
                or finding.get("status") == "suppressed"
            ):
                continue
            evidence = finding.get("evidence")
            evidence = evidence if isinstance(evidence, dict) else {}
            fusion = evidence.get("fusion")
            fusion = fusion if isinstance(fusion, dict) else {}
            advisory = fusion.get("advisory_context")
            advisory = advisory if isinstance(advisory, dict) else {}
            remediation = advisory.get("remediation_context")
            remediation = remediation if isinstance(remediation, dict) else {}
            cluster_id = str(advisory.get("cluster_id") or "")
            if cluster_id and remediation:
                raw_owners = remediation.get("owners")
                finding_owners = evidence.get("owners")
                owner = (
                    str(raw_owners[0])
                    if isinstance(raw_owners, list) and raw_owners
                    else str(finding_owners[0])
                    if isinstance(finding_owners, list) and finding_owners
                    else "repository-owner"
                )
                raw_priority = str(remediation.get("priority") or "P2")
                priority = (
                    raw_priority
                    if raw_priority in {"P0", "P1", "P2", "P3", "P4"}
                    else "P2"
                )
                cluster_findings = advisory.get("finding_ids")
                cluster_findings = (
                    [str(item) for item in cluster_findings[:90] if item]
                    if isinstance(cluster_findings, list)
                    else [str(finding.get("finding_id") or "findings.json")]
                )
                usage = advisory.get("dependency_usage")
                usage = usage if isinstance(usage, dict) else {}
                import_paths = usage.get("import_paths")
                import_paths = (
                    [str(item) for item in import_paths[:5] if item]
                    if isinstance(import_paths, list)
                    else []
                )
                tests = remediation.get("recommended_test_files")
                tests = (
                    [str(item) for item in tests[:4] if item]
                    if isinstance(tests, list)
                    else []
                )
                test_execution_sources = usage.get("test_execution_sources")
                test_execution_sources = (
                    [str(item) for item in test_execution_sources[:3] if item]
                    if isinstance(test_execution_sources, list)
                    else []
                )
                dependency_evidence = usage.get("evidence_artifacts")
                dependency_evidence = (
                    [
                        str(item)
                        for item in dependency_evidence[:10]
                        if item in {"sbom.cdx.json", "pipdeptree-summary.json"}
                    ]
                    if isinstance(dependency_evidence, list)
                    else []
                )
                actions.append(
                    {
                        "id": f"advisory:{cluster_id}",
                        "blocker": "blocking-findings",
                        "priority": priority,
                        "owner": owner,
                        "authority": "repository",
                        "automatable": False,
                        "action": str(
                            remediation.get("recommended_action")
                            or finding.get("remediation")
                            or "Resolve the blocking advisory and regenerate the report."
                        ),
                        "evidence": list(
                            dict.fromkeys(
                                [
                                    *cluster_findings,
                                    "evidence-fusion.json",
                                    *import_paths,
                                    *tests,
                                    *test_execution_sources,
                                    *dependency_evidence,
                                ]
                            )
                        )[:100],
                        "commands": [],
                    }
                )
                continue
            owners = evidence.get("owners") if isinstance(evidence, dict) else []
            owner = (
                str(owners[0])
                if isinstance(owners, list) and owners
                else "repository-owner"
            )
            classifications = finding.get("classifications")
            signing = isinstance(classifications, list) and any(
                value in {"COSIGN-BUNDLE-MISSING", "SLSA-PROVENANCE"}
                for value in classifications
            )
            actions.append(
                {
                    "id": f"finding:{finding.get('finding_id', 'unknown')}",
                    "blocker": "blocking-findings",
                    "priority": "P1" if signing else "P2",
                    "owner": owner,
                    "authority": "controlled-signing" if signing else "repository",
                    "automatable": False,
                    "action": str(
                        finding.get("remediation")
                        or "Resolve the blocking finding and regenerate the report."
                    ),
                    "evidence": [
                        str(finding.get("finding_id") or "findings.json"),
                        *(
                            [str(evidence["artifact_path"])]
                            if isinstance(evidence, dict)
                            and evidence.get("artifact_path")
                            else []
                        ),
                    ],
                    "commands": (
                        [
                            "pysec sign-artifacts ARTIFACTS --output PROVENANCE --signing-key KEY --cosign-sha256 SHA256"
                        ]
                        if signing
                        else []
                    ),
                }
            )
    validation_actions = _change_validation_actions(blockers, closure)
    actions.extend(validation_actions)
    for blocker in blockers:
        if (
            blocker == "blocking-findings"
            or (blocker == "scan-policy" and len(blockers) > 1)
            or (blocker == "change-validation-alignment" and validation_actions)
        ):
            continue
        owner, authority, action, commands = _CONTROL_REMEDIATION.get(
            blocker,
            (
                "release-engineering",
                "cross-functional",
                "Resolve the failed release control and regenerate its evidence.",
                [],
            ),
        )
        actions.append(
            {
                "id": f"control:{blocker}",
                "blocker": blocker,
                "priority": "P1",
                "owner": owner,
                "authority": authority,
                "automatable": authority == "repository",
                "action": action,
                "evidence": [blocker],
                "commands": commands,
            }
        )
    consolidated = _consolidate_finding_remediation(actions)
    return sorted(consolidated, key=lambda item: (item["priority"], item["id"]))


def _change_validation_actions(
    blockers: list[str], closure: dict[str, Any]
) -> list[dict[str, Any]]:
    if "change-validation-alignment" not in blockers:
        return []
    items = closure.get("items")
    if not isinstance(items, list):
        return []
    actions: list[dict[str, Any]] = []
    for item in items[:10_000]:
        if not isinstance(item, dict):
            continue
        details = item.get("details")
        if not isinstance(details, dict) or not details.get("validation_alignment"):
            continue
        refs = _release_validation_evidence(item, details)
        closure_id = str(item.get("id") or "unknown")
        actions.append(
            {
                "id": f"validation:{closure_id}",
                "blocker": "change-validation-alignment",
                "priority": (
                    str(item.get("priority"))
                    if item.get("priority") in {"P0", "P1", "P2", "P3", "P4"}
                    else "P2"
                ),
                "owner": str(item.get("owner") or "quality-engineering")[:256],
                "authority": "repository",
                "automatable": False,
                "action": str(
                    item.get("action")
                    or "Resolve the validation mismatch and regenerate the report."
                )[:2000],
                "evidence": [f"closure-plan.json#{closure_id}", *refs],
                "commands": [],
            }
        )
    return actions


def _release_validation_evidence(
    item: dict[str, Any], details: dict[str, Any]
) -> list[str]:
    """Keep readiness actions concise while the closure plan retains full detail."""
    raw_refs = item.get("evidence_refs")
    refs = (
        [str(value)[:2000] for value in raw_refs if value]
        if isinstance(raw_refs, list)
        else []
    )
    artifacts = [
        value
        for value in refs
        if value.endswith((".json", ".xml")) or ".json#" in value
    ][:6]
    source_paths = [
        value
        for value in refs
        if value.startswith(("src/", "src\\")) and value.endswith(".py")
    ][:3]
    tests = details.get("recommended_test_files")
    test_paths = (
        [str(value)[:2000] for value in tests[:5] if value]
        if isinstance(tests, list)
        else []
    )
    related = item.get("related_findings")
    finding_ids = (
        [str(value)[:2000] for value in related[:5] if value]
        if isinstance(related, list)
        else []
    )
    return list(dict.fromkeys([*artifacts, *source_paths, *test_paths, *finding_ids]))[
        :20
    ]


def _consolidate_finding_remediation(
    actions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Collapse equivalent finding work while retaining every evidence subject."""
    controls: list[dict[str, Any]] = []
    advisory_actions: dict[str, dict[str, Any]] = {}
    validation_groups: dict[tuple[object, ...], list[dict[str, Any]]] = {}
    groups: dict[tuple[object, ...], list[dict[str, Any]]] = {}
    for action in actions:
        action_id = str(action.get("id") or "")
        if action_id.startswith("advisory:"):
            current = advisory_actions.get(action_id)
            if current is None:
                advisory_actions[action_id] = action
            else:
                current["evidence"] = sorted(
                    {
                        str(subject)
                        for item in (current, action)
                        for subject in item.get("evidence", [])
                        if subject
                    }
                )[:100]
            continue
        if action_id.startswith("validation:"):
            validation_key = (
                action.get("blocker"),
                action.get("priority"),
                action.get("owner"),
                action.get("authority"),
                action.get("automatable"),
                action.get("action"),
                tuple(action.get("commands") or ()),
            )
            validation_groups.setdefault(validation_key, []).append(action)
            continue
        if not action_id.startswith("finding:"):
            controls.append(action)
            continue
        finding_key = (
            action.get("blocker"),
            action.get("priority"),
            action.get("owner"),
            action.get("authority"),
            action.get("automatable"),
            action.get("action"),
            tuple(action.get("commands") or ()),
        )
        groups.setdefault(finding_key, []).append(action)

    for grouped in groups.values():
        if len(grouped) == 1:
            controls.append(grouped[0])
            continue
        ordered = sorted(grouped, key=lambda value: str(value["id"]))
        finding_ids = [str(value["id"]).removeprefix("finding:") for value in ordered]
        value = dict(ordered[0])
        value["id"] = "findings:" + "+".join(finding_ids)
        value["evidence"] = sorted(
            {
                str(subject)
                for item in ordered
                for subject in item.get("evidence", [])
                if subject
            }
        )
        controls.append(value)
    controls.extend(
        advisory_actions[advisory_key] for advisory_key in sorted(advisory_actions)
    )
    for validation_group_key in sorted(validation_groups, key=str):
        grouped = validation_groups[validation_group_key]
        if len(grouped) == 1:
            controls.append(grouped[0])
            continue
        ordered = sorted(grouped, key=lambda value: str(value["id"]))
        subject_ids = [str(value["id"]) for value in ordered]
        digest = hashlib.sha256("\n".join(subject_ids).encode("utf-8")).hexdigest()
        value = dict(ordered[0])
        value["id"] = f"validation-group:{digest[:12].upper()}"
        value["action"] = (
            f"Resolve {len(ordered)} validation work items with the same owner, "
            f"priority, and evidence condition. {value['action']}"
        )[:2000]
        value["evidence"] = _validation_group_evidence(ordered)
        controls.append(value)
    return controls


def _validation_group_evidence(grouped: list[dict[str, Any]]) -> list[str]:
    values = [
        str(subject)
        for item in grouped
        for subject in item.get("evidence", [])
        if subject
    ]
    closure_refs = sorted(
        {value for value in values if value.startswith("closure-plan.json#")}
    )
    source_refs = sorted(
        {
            value
            for value in values
            if value.startswith(("src/", "src\\")) and value.endswith(".py")
        }
    )
    artifact_refs = sorted(
        {
            value
            for value in values
            if value.endswith((".json", ".xml"))
            and not value.startswith("closure-plan.json#")
        }
    )
    test_refs = sorted(
        {
            value
            for value in values
            if value.startswith(("tests/", "tests\\")) and value.endswith(".py")
        }
    )
    return list(
        dict.fromkeys([*closure_refs, *source_refs, *artifact_refs, *test_refs])
    )[:100]


def _effectiveness_control(
    path: Path | None,
    expected_digest: str,
    minimum_labels: int,
    minimum_positive_labels: int,
    minimum_negative_labels: int,
    minimum_tools: int,
    minimum_labels_per_tool: int,
    required_tools: tuple[str, ...],
    report_verification: dict[str, Any],
    require_governed_authority: bool,
) -> dict[str, Any] | None:
    normalized_required_tools = tuple(
        sorted({tool.strip() for tool in required_tools if tool.strip()})
    )
    required = any(
        value > 0
        for value in (
            minimum_labels,
            minimum_positive_labels,
            minimum_negative_labels,
            minimum_tools,
            minimum_labels_per_tool,
        )
    ) or bool(normalized_required_tools)
    if path is None:
        return (
            _control(
                "detection-effectiveness",
                False,
                "A digest-bound effectiveness evaluation is required.",
                ["effectiveness-evaluation.json"],
            )
            if required
            else None
        )
    evaluation = _digest_bound_object(path, expected_digest, "effectiveness evaluation")
    report = evaluation.get("report")
    corpus = evaluation.get("corpus")
    labels = int(corpus.get("labels") or 0) if isinstance(corpus, dict) else 0
    label_outcomes = evaluation.get("label_outcomes")
    outcomes = (
        [item for item in label_outcomes if isinstance(item, dict)]
        if isinstance(label_outcomes, list)
        else []
    )
    aggregate = evaluation.get("coverage_summary")
    aggregate_present = isinstance(aggregate, dict)
    tool_expectations: dict[str, set[str]]
    if isinstance(aggregate, dict):
        positive_labels = int(aggregate.get("positive_labels") or 0)
        negative_labels = int(aggregate.get("negative_labels") or 0)
        raw_tool_counts = aggregate.get("tool_counts")
        raw_tool_expectations = aggregate.get("tool_expectations")
        tool_counts = (
            {
                str(tool): int(count)
                for tool, count in raw_tool_counts.items()
                if isinstance(tool, str)
                and isinstance(count, int)
                and not isinstance(count, bool)
                and count >= 0
            }
            if isinstance(raw_tool_counts, dict)
            else {}
        )
        tool_expectations = (
            {
                str(tool): {str(value) for value in expectations}
                for tool, expectations in raw_tool_expectations.items()
                if isinstance(tool, str) and isinstance(expectations, list)
            }
            if isinstance(raw_tool_expectations, dict)
            else {}
        )
    else:
        positive_labels = sum(item.get("expected") == "finding" for item in outcomes)
        negative_labels = sum(item.get("expected") == "clean" for item in outcomes)
        tool_counts = {}
        tool_expectations = {}
        for item in outcomes:
            match = item.get("match")
            if not isinstance(match, dict) or not match.get("tool"):
                continue
            tool = str(match["tool"])
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
            tool_expectations.setdefault(tool, set()).add(str(item.get("expected")))
    covered_tools = {
        tool for tool, count in tool_counts.items() if count >= minimum_labels_per_tool
    }
    missing_required_tools = sorted(
        set(normalized_required_tools).difference(covered_tools)
    )
    all_matched_tools = set(tool_counts)
    corpus_authority = corpus.get("authority") if isinstance(corpus, dict) else None
    declared_diversity = corpus.get("diversity") if isinstance(corpus, dict) else None
    strata_names = (
        "cwe",
        "language",
        "parser_variant",
        "boundary_type",
        "severity",
        "mutation_operator",
    )
    observed_diversity = {
        name: len(
            {
                str(item.get("strata", {}).get(name) or "")
                for item in outcomes
                if isinstance(item.get("strata"), dict)
                and item["strata"].get(name)
                and not (
                    name == "mutation_operator" and item["strata"].get(name) == "none"
                )
            }
        )
        for name in strata_names
    }
    if (
        evaluation.get("schema_version") == "2.0"
        and aggregate_present
        and isinstance(declared_diversity, dict)
        and not outcomes
    ):
        observed_diversity = {
            name: int(declared_diversity.get(name) or 0) for name in strata_names
        }
    minimum_diversity = {
        "cwe": 5,
        "language": 2,
        "parser_variant": 2,
        "boundary_type": 3,
        "severity": 3,
        "mutation_operator": 2,
    }
    diversity_passed = all(
        observed_diversity[name] >= minimum
        for name, minimum in minimum_diversity.items()
    )
    tools_have_positive_and_negative = all(
        tool_expectations.get(tool, set()) >= {"finding", "clean"}
        for tool in normalized_required_tools
    )
    confusion = evaluation.get("confusion_matrix")
    confusion_total = (
        sum(
            int(confusion.get(name) or 0)
            for name in (
                "true_positive",
                "true_negative",
                "false_positive",
                "false_negative",
            )
        )
        if isinstance(confusion, dict)
        else labels
    )
    aggregate_consistent = not aggregate_present or (
        positive_labels + negative_labels == labels
        and confusion_total == labels
        and all(count <= labels for count in tool_counts.values())
        and all(
            expectations and expectations <= {"finding", "clean"}
            for expectations in tool_expectations.values()
        )
    )
    governed = bool(
        evaluation.get("schema_version") == "2.0"
        and aggregate_present
        and isinstance(corpus_authority, dict)
        and corpus_authority.get("validated") is True
        and corpus_authority.get("organization_approved") is True
        and isinstance(evaluation.get("time_authority"), dict)
        and evaluation["time_authority"].get("validated") is True
        and evaluation.get("replay_protected") is True
        and declared_diversity == observed_diversity
        and diversity_passed
        and tools_have_positive_and_negative
        and aggregate_consistent
    )
    passed = (
        evaluation.get("schema_version") in {"1.0", "2.0"}
        and evaluation.get("verdict") == "pass"
        and isinstance(report, dict)
        and report.get("checksums_sha256") == report_verification["checksums_sha256"]
        and labels >= minimum_labels
        and positive_labels >= minimum_positive_labels
        and negative_labels >= minimum_negative_labels
        and len(covered_tools) >= minimum_tools
        and not missing_required_tools
        and aggregate_consistent
        and (governed or not require_governed_authority)
    )
    return _control(
        "detection-effectiveness",
        passed,
        (
            f"Effectiveness verdict is {evaluation.get('verdict', 'unknown')} across "
            f"{labels} labels ({positive_labels} positive, {negative_labels} negative) "
            f"and {len(all_matched_tools)} matched tools; minimums {minimum_labels} total, "
            f"{minimum_positive_labels} positive, {minimum_negative_labels} negative, "
            f"{minimum_tools} tools with {minimum_labels_per_tool} labels each. "
            f"Required tools: {list(normalized_required_tools)}; missing: "
            f"{missing_required_tools}. Governed corpus required: "
            f"{require_governed_authority}; validated: {governed}; diversity: "
            f"{observed_diversity}."
        ),
        [str(path)],
    )


def _passport_control(
    path: Path | None,
    expected_digest: str,
    required: bool,
    report_verification: dict[str, Any],
) -> dict[str, Any] | None:
    if path is None:
        return (
            _control(
                "signed-release-passport",
                False,
                "An authentic approved passport verification is required.",
                ["passport-verification.json"],
            )
            if required
            else None
        )
    verification = _digest_bound_object(path, expected_digest, "passport verification")
    report = verification.get("report")
    bound = (
        isinstance(report, dict)
        and report.get("checksums_sha256") == report_verification["checksums_sha256"]
    )
    passed = (
        verification.get("release_decision") == "approved"
        and verification.get("authentic") is True
        and bound
    )
    return _control(
        "signed-release-passport",
        passed,
        (
            "Passport authenticity, report binding, artifacts, and release policy are approved."
            if passed
            else "Passport verification is not authentic, approved, and bound to this report."
        ),
        [str(path)],
    )


def _entrypoint_trust(manifest: dict[str, Any]) -> dict[str, Any]:
    tools = manifest.get("tools")
    if not isinstance(tools, list):
        raise TypeError("verified scan manifest tools must be an array")
    gaps: list[str] = []
    entrypoints = 0
    for run in tools:
        if not isinstance(run, dict) or run.get("applicable") is False:
            continue
        tool = str(run.get("tool") or "unknown")
        entrypoints += 1
        if not (
            run.get("executable_sha256")
            and run.get("executable_integrity_verified") is True
            and run.get("executable_organization_approved") is True
            and run.get("executable_unchanged") is True
        ):
            gaps.append(f"{tool}:primary")

        auxiliary_required = tool == "codeql" or bool(
            run.get("auxiliary_executable_sha256")
        )
        if auxiliary_required:
            entrypoints += 1
            if not (
                run.get("auxiliary_executable_sha256")
                and run.get("auxiliary_executable_integrity_verified") is True
                and run.get("auxiliary_executable_organization_approved") is True
                and run.get("auxiliary_executable_unchanged") is True
            ):
                gaps.append(f"{tool}:auxiliary")
    return {"entrypoints": entrypoints, "gaps": gaps}


def _control(
    identifier: str, passed: bool, detail: str, evidence: list[str]
) -> dict[str, Any]:
    return {
        "id": identifier,
        "status": "pass" if passed else "fail",
        "detail": detail,
        "evidence": evidence,
    }


def _paired(path: Path | None, digest: str, label: str) -> None:
    if bool(path) != bool(digest):
        raise ValueError(f"{label} path and SHA-256 must be supplied together")


def _digest_bound_object(
    path: Path, expected_digest: str, label: str
) -> dict[str, Any]:
    source = resolve_regular_file(path, label)
    if sha256_file(source) != expected_digest.casefold():
        raise ValueError(f"{label} does not match the approved SHA-256")
    return _read_object(source)


def _optional_object(path: Path) -> dict[str, Any]:
    return _read_object(path) if path.is_file() else {}


def _read_object(path: Path) -> dict[str, Any]:
    source = resolve_regular_file(path, "JSON evidence")
    if source.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError(f"JSON evidence exceeds {_MAX_JSON_BYTES} bytes")
    document = strict_json_loads(source.read_bytes())
    if not isinstance(document, dict):
        raise TypeError("JSON evidence root must be an object")
    return document
