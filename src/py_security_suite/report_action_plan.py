"""Markdown remediation action plan (action-plan.md) rendering."""

from __future__ import annotations

from collections import Counter
from urllib.parse import quote

from .report_markdown import _markdown_code
from .models import Finding, ScanManifest, ToolRun
from .report_common import (
    _applicable_scanner_gaps,
    _artifact_identity,
    _coverage_action,
    _entrypoint_integrity_counts,
    _entrypoint_integrity_states,
    _finding_owners,
    _finding_priority,
    _finding_sort_key,
    _location_text,
    _markdown_citation,
    _markdown_classification,
    _markdown_table,
    _markdown_tool_reference,
    _next_action_for_manifest,
    _not_applicable_scanners,
    _owner_values,
    _policy_disposition,
)


__all__ = [
    "_render_entrypoint_trust_actions",
    "render_action_plan",
]


def render_action_plan(manifest: ScanManifest, findings: list[Finding]) -> str:
    coverage_gaps = _applicable_scanner_gaps(manifest.tools)
    not_applicable = _not_applicable_scanners(manifest.tools)
    blocking = sum(1 for finding in findings if finding.blocking)
    entrypoints, approved_entrypoints, unchanged_entrypoints = (
        _entrypoint_integrity_counts(manifest.tools)
    )
    trust_gaps, approval_gaps, postcheck_gaps = _entrypoint_integrity_gap_counts(
        manifest.tools
    )
    approval_gap_label = "gap" if approval_gaps == 1 else "gaps"
    postcheck_gap_label = "gap" if postcheck_gaps == 1 else "gaps"
    approval_candidates, unique_candidate_digests = (
        _entrypoint_approval_candidate_counts(manifest.tools)
    )
    candidate_binding_label = "binding" if approval_candidates == 1 else "bindings"
    candidate_digest_label = "digest" if unique_candidate_digests == 1 else "digests"
    assigned_findings = sum(bool(_owner_values(finding)) for finding in findings)
    owner_queues = {owner for finding in findings for owner in _owner_values(finding)}
    unassigned_findings = len(findings) - assigned_findings
    lines = [
        "# Security action plan",
        "",
        f"- **Scan:** `{_markdown_code(manifest.scan_id)}`",
        f"- **Outcome:** `{_markdown_code(manifest.outcome.value)}`",
        f"- **Profile:** `{_markdown_code(manifest.profile)}`",
        f"- **Scan-policy disposition:** {_policy_disposition(manifest.outcome)}",
        f"- **Blocking findings:** {blocking}",
        f"- **Applicable scanner execution gaps:** {len(coverage_gaps)}",
        f"- **Conditional controls not applicable:** {len(not_applicable)}",
        f"- **Scanner entry points approved and unchanged:** "
        f"{approved_entrypoints}/{entrypoints}",
        f"- **Scanner entry points unchanged after execution:** "
        f"{unchanged_entrypoints}/{entrypoints}",
        f"- **Scanner trust actions:** {trust_gaps} affected entry points "
        f"({approval_gaps} approval {approval_gap_label}; "
        f"{postcheck_gaps} post-execution {postcheck_gap_label})",
        f"- **Approval review workload:** {approval_candidates} candidate "
        f"{candidate_binding_label} across {unique_candidate_digests} unique "
        f"executable {candidate_digest_label}",
        f"- **Finding ownership:** {assigned_findings}/{len(findings)} findings "
        f"assigned across {len(owner_queues)} named owner queues; "
        f"{unassigned_findings} unassigned",
        f"- **Immediate next step:** {_next_action_for_manifest(manifest)}",
        "",
        "## Finding actions",
        "",
        "| Risk | Lifecycle | Finding | Domain / area | Location | Evidence | Owner | Action |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for finding in sorted(findings, key=_finding_sort_key):
        sources = (
            ", ".join(f"{source.tool}/{source.rule_id}" for source in finding.sources)
            or "unattributed"
        )
        reference = (
            _markdown_citation(finding.citations[0]) if finding.citations else "-"
        )
        classifications = (
            ", ".join(
                _markdown_classification(value) for value in finding.classifications
            )
            or "-"
        )
        lines.append(
            f"| {_finding_priority(finding)} / "
            f"{_markdown_table(finding.severity.value)} | "
            f"{_markdown_table(finding.status.value)} | "
            f"[`{_markdown_code(finding.finding_id)}` "
            f"{_markdown_table(finding.title)}]"
            f"(index.html#{quote(finding.finding_id, safe='')}) | "
            f"{_markdown_table(finding.domain)} / "
            f"{_markdown_table(finding.area)} | "
            f"`{_markdown_code(_location_text(finding))}` | "
            f"Source: {_markdown_table(sources)}; "
            f"Class: {classifications}; Reference: {reference} | "
            f"{_finding_owners(finding)} | "
            f"{_markdown_table(finding.remediation)} |"
        )
    if not findings:
        lines.append("| - | - | - | No normalized findings | - | - | - | No action |")

    lines.extend(_render_owner_work_queues(findings))
    lines.extend(_render_action_plan_artifact_identities(findings))
    lines.extend(_render_entrypoint_trust_actions(manifest.tools))
    lines.extend(
        [
            "",
            "## Coverage actions",
            "",
            "| Tool | Applicability | Status | Reason | Action | Reference |",
            "|---|---|---|---|---|---|",
        ]
    )
    lines.extend(
        (
            f"| {_markdown_table(run.tool)} | "
            f"{'applicable' if run.applicable else 'not applicable'} | "
            f"{_markdown_table(run.status.value)} | "
            f"{_markdown_table(run.error or 'No diagnostic supplied')} | "
            f"{_markdown_table(_coverage_action(run, manifest))} | "
            f"{_markdown_tool_reference(run.tool)} |"
        )
        for run in coverage_gaps
    )
    if not coverage_gaps:
        lines.append(
            "| All applicable tools | applicable | completed | - | No action | - |"
        )
    if not_applicable:
        lines.extend(
            [
                "",
                f"<details><summary>{len(not_applicable)} not-applicable controls "
                "(informational)</summary>",
                "",
                "| Tool | Reason | Re-enable condition | Reference |",
                "|---|---|---|---|",
            ]
        )
        lines.extend(
            (
                f"| {_markdown_table(run.tool)} | "
                f"{_markdown_table(run.error or 'No diagnostic supplied')} | "
                f"{_markdown_table(_coverage_action(run, manifest))} | "
                f"{_markdown_tool_reference(run.tool)} |"
            )
            for run in not_applicable
        )
        lines.extend(["", "</details>"])
    lines.extend(
        [
            "",
            "## Policy and release-evidence actions",
            "",
            "| Requirement | Required action |",
            "|---|---|",
        ]
    )
    lines.extend(
        (f"| {_markdown_table(reason)} | {_markdown_table(_policy_action(reason))} |")
        for reason in manifest.policy_reasons
    )
    if not manifest.policy_reasons:
        lines.append("| All configured policy requirements | No action |")
    lines.extend(
        [
            "",
            "## Disposition record",
            "",
            "For each finding, record an owner and one disposition: fixed, accepted "
            + "risk, false positive, or approved suppression. Preserve the finding ID "
            + "and cited scanner rule in the review record, then rerun the suite.",
            "",
        ]
    )
    return "\n".join(lines)


def _render_owner_work_queues(findings: list[Finding]) -> list[str]:
    if not findings:
        return []
    queues: dict[str, list[Finding]] = {}
    for finding in findings:
        owners = list(dict.fromkeys(_owner_values(finding))) or ["Unassigned"]
        for owner in owners:
            queues.setdefault(owner, []).append(finding)
    queue_guidance = " ".join(
        (
            "A finding with multiple owners appears in each applicable queue;",
            "totals therefore represent routing workload, not unique finding count.",
        )
    )
    lines = [
        "",
        "### Ownership work queues",
        "",
        queue_guidance,
        "",
        "| Owner | P0 | P1 | P2 | P3 | P4 | Blocking | Total |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for owner, owned_findings in sorted(queues.items()):
        priorities = Counter(_finding_priority(finding) for finding in owned_findings)
        owner_label = (
            "**Unassigned**" if owner == "Unassigned" else f"`{_markdown_code(owner)}`"
        )
        lines.append(
            f"| {owner_label} | {priorities['P0']} | {priorities['P1']} | "
            f"{priorities['P2']} | {priorities['P3']} | {priorities['P4']} | "
            f"{sum(finding.blocking for finding in owned_findings)} | "
            f"{len(owned_findings)} |"
        )
    return lines


def _render_action_plan_artifact_identities(findings: list[Finding]) -> list[str]:
    identities = [
        (finding, identity)
        for finding in sorted(findings, key=_finding_sort_key)
        if (identity := _artifact_identity(finding)) is not None
    ]
    if not identities:
        return []
    identity_guidance = " ".join(
        (
            "Use these immutable identities when locating, signing, quarantining,",
            "or approving an affected distribution.",
        )
    )
    lines = [
        "",
        "### Release artifact bindings",
        "",
        identity_guidance,
        "",
        "| Finding | Artifact | SHA-256 | Size |",
        "|---|---|---|---:|",
    ]
    for finding, (path, digest, size) in identities:
        rendered_size = f"{size} bytes" if size is not None else "not supplied"
        lines.append(
            f"| [`{_markdown_code(finding.finding_id)}`]"
            f"(index.html#{quote(finding.finding_id, safe='')}) | "
            f"`{_markdown_code(path)}` | `sha256:{digest}` | {rendered_size} |"
        )
    return lines


def _render_entrypoint_trust_actions(tools: list[ToolRun]) -> list[str]:
    states = _entrypoint_integrity_states(tools)
    gaps = sorted(
        (state for state in states if state[3] is not True or state[4] is not True),
        key=_entrypoint_trust_sort_key,
    )
    trust_guidance = " ".join(
        (
            "Address changed or unverifiable entry points before approval gaps.",
            "Digest approval candidates below are observations, not provenance decisions.",
        )
    )
    lines = [
        "",
        "## Scanner entry-point trust actions",
        "",
        trust_guidance,
        "",
        "| Priority | Entry point | Digest | Trust state | Required action |",
        "|---|---|---|---|---|",
    ]
    for tool, role, digest, approved, unchanged in gaps:
        priority = (
            "P0" if unchanged is False else "P1" if unchanged is not True else "P2"
        )
        actions: list[str] = []
        if unchanged is False:
            actions.append("Quarantine the changed toolchain and reinstall it.")
        elif unchanged is not True:
            actions.append("Restore post-execution digest verification.")
        if approved is not True:
            actions.append(
                "After integrity is restored, independently verify provenance and "
                "approve the exact digest."
                if unchanged is not True
                else "Independently verify provenance and approve the exact digest."
            )
        postcheck = (
            "unchanged"
            if unchanged is True
            else "changed"
            if unchanged is False
            else "unavailable"
        )
        lines.append(
            f"| {priority} | {_markdown_table(tool)} ({role}) | "
            f"`sha256:{_markdown_code(digest[:12])}...` | "
            f"{'approved' if approved is True else 'not approved'}; "
            f"post-check {postcheck} | {_markdown_table(' '.join(actions))} |"
        )
    if not states:
        lines.append(
            "| P0 | No observed entry points | - | unavailable | Configure scanner "
            "entry points and approved digests, then rerun. |"
        )
    elif not gaps:
        lines.append(
            "| - | All observed entry points | - | approved; post-check unchanged | "
            "No action |"
        )
    versions = {
        (run.tool, role): run.version
        for run in tools
        for role, digest in (
            ("primary", run.executable_sha256),
            ("helper", run.auxiliary_executable_sha256),
        )
        if digest is not None
    }
    lines.extend(_render_entrypoint_approval_candidates(gaps, versions))
    return lines


def _entrypoint_trust_sort_key(
    state: tuple[str, str, str, bool | None, bool | None],
) -> tuple[int, str, str]:
    tool, role, _, _, unchanged = state
    priority = 0 if unchanged is False else 1 if unchanged is not True else 2
    return priority, tool, role


def _render_entrypoint_approval_candidates(
    gaps: list[tuple[str, str, str, bool | None, bool | None]],
    versions: dict[tuple[str, str], str],
) -> list[str]:
    candidates = sorted(
        (state for state in gaps if state[3] is not True and state[4] is True),
        key=lambda state: (state[0], state[1]),
    )
    if not candidates:
        return []
    grouped_by_tool: dict[str, list[tuple[str, str]]] = {}
    grouped_by_digest: dict[str, list[tuple[str, str, str]]] = {}
    for tool, role, digest, _, _ in candidates:
        grouped_by_tool.setdefault(tool, []).append((role, digest))
        grouped_by_digest.setdefault(digest, []).append(
            (tool, role, versions.get((tool, role), "unknown"))
        )
    digest_label = "digest" if len(grouped_by_digest) == 1 else "digests"
    provenance_warning = " ".join(
        (
            "> Do not apply these observed digests as approvals until an independent",
            "provenance review confirms each executable's source, version, and custody.",
        )
    )
    lines = [
        "",
        f"<details><summary>{len(candidates)} copy-ready digest approval "
        "candidates (provenance review required)</summary>",
        "",
        provenance_warning,
        "",
        "### Provenance review batches",
        "",
        f"{len(candidates)} candidate policy bindings map to "
        f"{len(grouped_by_digest)} unique executable {digest_label}. Review provenance "
        "once per digest, then record every affected binding.",
        "",
        "| Exact digest | Observed version | Candidate policy bindings |",
        "|---|---|---|",
    ]
    for digest, bindings in sorted(grouped_by_digest.items()):
        rendered_versions = ", ".join(
            f"`{_markdown_code(version)}`"
            for version in sorted({version for _, _, version in bindings})
        )
        rendered_bindings = ", ".join(
            f"`{_markdown_code(tool)} ({role})`" for tool, role, _ in sorted(bindings)
        )
        lines.append(
            f"| `sha256:{digest}` | {rendered_versions} | {rendered_bindings} |"
        )
    lines.extend(
        [
            "",
            "### Copy-ready policy bindings",
            "",
            "```toml",
        ]
    )
    for tool, entries in grouped_by_tool.items():
        lines.append(f"[tools.{tool}]")
        for role, digest in entries:
            field = (
                "auxiliary_executable_sha256"
                if role == "helper"
                else "executable_sha256"
            )
            lines.append(f'{field} = "{digest}"')
        lines.append("")
    lines.extend(["```", "", "</details>"])
    return lines


def _entrypoint_integrity_gap_counts(tools: list[ToolRun]) -> tuple[int, int, int]:
    states = _entrypoint_integrity_states(tools)
    return (
        sum(
            approved is not True or unchanged is not True
            for _, _, _, approved, unchanged in states
        ),
        sum(approved is not True for _, _, _, approved, _ in states),
        sum(unchanged is not True for _, _, _, _, unchanged in states),
    )


def _entrypoint_approval_candidate_counts(tools: list[ToolRun]) -> tuple[int, int]:
    candidates = [
        digest
        for _, _, digest, approved, unchanged in _entrypoint_integrity_states(tools)
        if approved is not True and unchanged is True
    ]
    return len(candidates), len(set(candidates))


def _policy_action(reason: str) -> str:
    lowered = reason.casefold()
    if "network-isolation attestation" in lowered:
        return (
            "Run inside an independently enforced egress-denied boundary and pass "
            "--network-isolated only after the runner verifies that control."
        )
    if "full vcs checkout" in lowered:
        return (
            "Use a full immutable clone with history instead of an exported source "
            "directory, then rerun."
        )
    if "lock file" in lowered:
        return (
            "Generate and approve a reproducible lock file, preferably with artifact "
            "hashes, and rerun dependency and SBOM checks."
        )
    if "built wheel or source distribution" in lowered:
        return (
            "Build the immutable release distributions in the approved build lane, "
            "stage them under the configured artifacts path, and rerun."
        )
    if "data-flow" in lowered or "pysa" in lowered:
        return (
            "Add a reviewed Pyre/Pysa configuration and models, stage the approved "
            "scanner, and rerun."
        )
    if "scanner" in lowered:
        return (
            "Restore the named required scanner and its approved offline assets, "
            "then rerun."
        )
    return "Satisfy the stated policy requirement, attach evidence, and rerun."
