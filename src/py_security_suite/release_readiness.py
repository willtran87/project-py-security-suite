from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .execution import sha256_file
from .passport import verify_report
from .path_safety import resolve_regular_file

_MAX_JSON_BYTES = 128 * 1024 * 1024
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
    "signed-release-passport": (
        "release-approver",
        "release-approver",
        "Verify and approve a signed Passport bound to this exact report and artifact payload.",
        ["pysec verify PASSPORT --report REPORT --artifact-root PAYLOAD"],
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
    verification = verify_report(report)
    root = report.expanduser().resolve()
    manifest = _read_object(root / "scan-manifest.json")
    findings_document = _read_object(root / "findings.json")
    claims = _read_object(root / "assurance-claims.json")
    portfolio = _read_object(root / "portfolio-health.json")
    isolation = _optional_object(root / "isolation-attestation.json")
    intelligence = _optional_object(root / "risk-intelligence.json")
    intelligence_approval = _optional_object(root / "intelligence-approval.json")
    trust = _entrypoint_trust(manifest)

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

    return _decision(
        controls=controls,
        verification=verification,
        blocking_findings=blocking_findings,
        findings=findings,
        trust=trust,
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


def _decision(
    *,
    controls: list[dict[str, Any]],
    verification: dict[str, Any],
    blocking_findings: int,
    findings: list[Any],
    trust: dict[str, Any],
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
    remediation = _remediation(root_blockers, findings)
    authority_counts: dict[str, int] = {}
    for action in remediation:
        authority = str(action["authority"])
        authority_counts[authority] = authority_counts.get(authority, 0) + 1
    return {
        "schema_version": "1.2",
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
            "actions_by_authority": dict(sorted(authority_counts.items())),
        },
        "blockers": blockers,
        "root_blockers": root_blockers,
        "derived_blockers": derived_blockers,
        "blocker_graph": blocker_graph,
        "controls": controls,
        "remediation": remediation,
    }


def _remediation(blockers: list[str], findings: list[Any]) -> list[dict[str, Any]]:
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
    for blocker in blockers:
        if blocker == "blocking-findings" or (
            blocker == "scan-policy" and len(blockers) > 1
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


def _consolidate_finding_remediation(
    actions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Collapse equivalent finding work while retaining every evidence subject."""
    controls: list[dict[str, Any]] = []
    advisory_actions: dict[str, dict[str, Any]] = {}
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
        if not action_id.startswith("finding:"):
            controls.append(action)
            continue
        key = (
            action.get("blocker"),
            action.get("priority"),
            action.get("owner"),
            action.get("authority"),
            action.get("automatable"),
            action.get("action"),
            tuple(action.get("commands") or ()),
        )
        groups.setdefault(key, []).append(action)

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
    controls.extend(advisory_actions[key] for key in sorted(advisory_actions))
    return controls


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
    positive_labels = sum(item.get("expected") == "finding" for item in outcomes)
    negative_labels = sum(item.get("expected") == "clean" for item in outcomes)
    tool_counts: dict[str, int] = {}
    for item in outcomes:
        match = item.get("match")
        if not isinstance(match, dict) or not match.get("tool"):
            continue
        tool = str(match["tool"])
        tool_counts[tool] = tool_counts.get(tool, 0) + 1
    covered_tools = {
        tool for tool, count in tool_counts.items() if count >= minimum_labels_per_tool
    }
    missing_required_tools = sorted(
        set(normalized_required_tools).difference(covered_tools)
    )
    all_matched_tools = {
        str(match.get("tool"))
        for item in outcomes
        if isinstance((match := item.get("match")), dict) and match.get("tool")
    }
    passed = (
        evaluation.get("schema_version") == "1.0"
        and evaluation.get("verdict") == "pass"
        and isinstance(report, dict)
        and report.get("checksums_sha256") == report_verification["checksums_sha256"]
        and labels >= minimum_labels
        and positive_labels >= minimum_positive_labels
        and negative_labels >= minimum_negative_labels
        and len(covered_tools) >= minimum_tools
        and not missing_required_tools
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
            f"{missing_required_tools}."
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
    document = json.loads(source.read_bytes())
    if not isinstance(document, dict):
        raise TypeError("JSON evidence root must be an object")
    return document
