from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .execution import resolve_executable, run_command
from .models import Finding, FindingStatus
from .path_safety import resolve_regular_file

_MAX_BASELINE_BYTES = 64 * 1024 * 1024
_MAX_BASELINE_FINDINGS = 100_000
_MAX_CODEOWNERS_BYTES = 1024 * 1024
_MAX_CODEOWNERS_RULES = 10_000


@dataclass(slots=True)
class DeltaResult:
    errors: list[str] = field(default_factory=list)
    artifact: dict[str, Any] = field(default_factory=dict)


def apply_finding_delta(
    findings: list[Finding],
    *,
    target: Path,
    baseline_path: Path | None,
    baseline_sha256: str,
    current_profile: str = "",
    current_tools: tuple[str, ...] = (),
    current_source_sha256: str = "",
    current_vcs_revision: str = "",
) -> DeltaResult:
    ownership = _apply_ownership(findings, target)

    if baseline_path is None:
        return DeltaResult(
            artifact={
                "schema_version": "1.0",
                "configured": False,
                "counts": {
                    "new": len(findings),
                    "existing": 0,
                    "regression": 0,
                    "resolved": 0,
                },
                "resolved": [],
                "ownership_rules": len(ownership),
            }
        )
    try:
        previous, metadata = _load_baseline(
            baseline_path, baseline_sha256, expected_target=target.name
        )
    except (OSError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        return DeltaResult(
            errors=[f"finding baseline is invalid: {exc}"],
            artifact={
                "schema_version": "1.0",
                "configured": True,
                "errors": [str(exc)],
            },
        )

    comparable, reasons, comparison = _comparison_context(
        target=target,
        metadata=metadata,
        current_profile=current_profile,
        current_tools=current_tools,
        current_source_sha256=current_source_sha256,
        current_vcs_revision=current_vcs_revision,
    )
    if not comparable:
        return _incomparable_result(
            findings,
            reasons=reasons,
            comparison=comparison,
            metadata=metadata,
            ownership_rules=len(ownership),
        )
    return _classify_comparable_findings(
        findings,
        previous=previous,
        comparison=comparison,
        metadata=metadata,
        ownership_rules=len(ownership),
    )


def _apply_ownership(
    findings: list[Finding], target: Path
) -> list[tuple[str, list[str]]]:
    ownership = _load_codeowners(target)
    for finding in findings:
        owners = _owners_for_finding(finding, ownership)
        if owners:
            finding.evidence = {**finding.evidence, "owners": owners}
    return ownership


def _comparison_context(
    *,
    target: Path,
    metadata: dict[str, Any],
    current_profile: str,
    current_tools: tuple[str, ...],
    current_source_sha256: str,
    current_vcs_revision: str,
) -> tuple[bool, list[str], dict[str, Any]]:
    comparable, reasons = _baseline_compatibility(
        metadata, current_profile=current_profile, current_tools=current_tools
    )
    ancestry_verified = False
    if current_profile in {"production", "release"} or current_vcs_revision:
        ancestry_verified, reason = _verify_local_ancestry(
            target,
            baseline_revision=str(metadata.get("vcs_revision") or ""),
            current_revision=current_vcs_revision,
        )
        if reason:
            reasons.append(reason)
            comparable = False
    comparison = {
        "comparable": comparable,
        "reasons": reasons,
        "profile": {"baseline": metadata["profile"], "current": current_profile},
        "selected_tools": {
            "baseline": metadata["selected_tools"],
            "current": sorted(current_tools),
        },
        "source": {
            "baseline_sha256": metadata["source_sha256"],
            "current_sha256": current_source_sha256,
            "same_snapshot": bool(current_source_sha256)
            and metadata["source_sha256"] == current_source_sha256,
            "baseline_revision": metadata["vcs_revision"],
            "current_revision": current_vcs_revision,
            "ancestry_verified": ancestry_verified,
            "ancestry_authority": "local-git" if ancestry_verified else "unverified",
        },
    }
    return comparable, reasons, comparison


def _incomparable_result(
    findings: list[Finding],
    *,
    reasons: list[str],
    comparison: dict[str, Any],
    metadata: dict[str, Any],
    ownership_rules: int,
) -> DeltaResult:
    for finding in findings:
        finding.status = FindingStatus.UNCLASSIFIED
        finding.evidence = {
            **finding.evidence,
            "baseline": {"comparable": False, "reasons": reasons},
        }
    return DeltaResult(
        errors=[f"finding baseline is not comparable: {'; '.join(reasons)}"],
        artifact={
            "schema_version": "1.1",
            "configured": True,
            "comparison": comparison,
            "baseline": metadata,
            "counts": {
                "unclassified": len(findings),
                "new": 0,
                "existing": 0,
                "regression": 0,
                "resolved": 0,
            },
            "match_strategies": {"exact": 0, "semantic": 0},
            "resolved": [],
            "ownership_rules": ownership_rules,
        },
    )


def _classify_comparable_findings(
    findings: list[Finding],
    *,
    previous: list[dict[str, Any]],
    comparison: dict[str, Any],
    metadata: dict[str, Any],
    ownership_rules: int,
) -> DeltaResult:
    exact = {
        str(value.get("fingerprint")): value
        for value in previous
        if value.get("fingerprint")
    }
    fuzzy: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for value in previous:
        fuzzy.setdefault(_record_key(value), []).append(value)
    matched: set[str] = set()
    strategies = {"exact": 0, "semantic": 0}
    for finding in findings:
        _classify_finding(
            finding, exact=exact, fuzzy=fuzzy, matched=matched, strategies=strategies
        )
    resolved = [
        _resolved_record(value)
        for value in previous
        if str(value.get("fingerprint") or "") not in matched
        and str(value.get("status") or "") != FindingStatus.SUPPRESSED.value
    ]
    counts = {
        status.value: sum(finding.status is status for finding in findings)
        for status in (
            FindingStatus.NEW,
            FindingStatus.EXISTING,
            FindingStatus.REGRESSION,
        )
    }
    counts[FindingStatus.RESOLVED.value] = len(resolved)
    return DeltaResult(
        artifact={
            "schema_version": "1.1",
            "configured": True,
            "comparison": comparison,
            "baseline": metadata,
            "counts": counts,
            "match_strategies": strategies,
            "resolved": resolved,
            "ownership_rules": ownership_rules,
        }
    )


def _classify_finding(
    finding: Finding,
    *,
    exact: dict[str, dict[str, Any]],
    fuzzy: dict[tuple[str, str, str, str], list[dict[str, Any]]],
    matched: set[str],
    strategies: dict[str, int],
) -> None:
    prior = exact.get(finding.fingerprint)
    strategy = "exact"
    if prior is None:
        unmatched = [
            value
            for value in fuzzy.get(_finding_key(finding), [])
            if str(value.get("fingerprint") or "") not in matched
        ]
        if len(unmatched) == 1:
            prior, strategy = unmatched[0], "semantic"
    if prior is None:
        finding.status = FindingStatus.NEW
        return
    prior_fingerprint = str(prior.get("fingerprint") or "")
    matched.add(prior_fingerprint)
    previous_status = str(prior.get("status") or "new")
    finding.status = (
        FindingStatus.REGRESSION
        if previous_status == FindingStatus.RESOLVED.value
        else FindingStatus.EXISTING
    )
    finding.evidence = {
        **finding.evidence,
        "baseline": {
            "match_strategy": strategy,
            "previous_finding_id": str(prior.get("finding_id") or ""),
            "previous_fingerprint": prior_fingerprint,
            "previous_status": previous_status,
        },
    }
    strategies[strategy] += 1


def _load_baseline(
    path: Path, approved: str, *, expected_target: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    resolved = resolve_regular_file(path, "baseline")
    data = resolved.read_bytes()
    if len(data) > _MAX_BASELINE_BYTES:
        raise ValueError("baseline exceeds 64 MiB")
    digest = hashlib.sha256(data).hexdigest()
    if not approved:
        raise ValueError("an approved baseline SHA-256 digest is required")
    if digest != approved:
        raise ValueError(f"SHA-256 {digest} does not match approved digest")
    document = json.loads(data.decode("utf-8"))
    if not isinstance(document, dict) or document.get("schema_version") != "1.0":
        raise TypeError("baseline must be a findings.json schema_version 1.0 object")
    baseline_target = str(document.get("target") or "")
    if not baseline_target:
        raise ValueError("baseline findings report does not bind a target identity")
    if baseline_target != expected_target:
        raise ValueError(
            f"baseline target {baseline_target!r} does not match {expected_target!r}"
        )
    values = document.get("findings")
    if not isinstance(values, list):
        raise TypeError("baseline requires a findings list")
    if len(values) > _MAX_BASELINE_FINDINGS:
        raise ValueError("baseline contains too many findings")
    if not all(isinstance(value, dict) for value in values):
        raise TypeError("baseline findings must be objects")
    return values, {
        "path": str(resolved),
        "sha256": digest,
        "scan_id": str(document.get("scan_id") or ""),
        "outcome": str(document.get("outcome") or ""),
        "target": baseline_target,
        "profile": str(document.get("profile") or ""),
        "source_sha256": str(document.get("source_sha256") or ""),
        "vcs_revision": str(document.get("vcs_revision") or ""),
        "selected_tools": sorted(
            str(value)
            for value in document.get("selected_tools", [])
            if isinstance(value, str) and value
        )
        if isinstance(document.get("selected_tools"), list)
        else [],
        "finding_count": len(values),
    }


def _verify_local_ancestry(
    target: Path, *, baseline_revision: str, current_revision: str
) -> tuple[bool, str]:
    """Verify that the baseline commit is an ancestor using only local history."""
    if not current_revision:
        return False, "current VCS revision is unavailable"
    if not baseline_revision:
        return False, "baseline does not bind a VCS revision"
    executable = resolve_executable("git")
    if executable is None:
        return False, "git is unavailable for local baseline ancestry verification"
    result = run_command(
        [
            executable,
            "-c",
            f"safe.directory={target.resolve()}",
            "merge-base",
            "--is-ancestor",
            baseline_revision,
            current_revision,
        ],
        cwd=target,
        timeout_seconds=10,
        max_output_bytes=4096,
    )
    if not result.timed_out and result.exit_code == 0:
        return True, ""
    if not result.timed_out and result.exit_code == 1:
        return False, "baseline VCS revision is not an ancestor of the current revision"
    return False, "local baseline ancestry could not be verified"


def _baseline_compatibility(
    metadata: dict[str, Any],
    *,
    current_profile: str,
    current_tools: tuple[str, ...],
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    baseline_profile = str(metadata.get("profile") or "")
    baseline_tools = metadata.get("selected_tools")
    if current_profile and baseline_profile != current_profile:
        reasons.append(
            f"profile {baseline_profile or 'unknown'} does not match {current_profile}"
        )
    if current_tools:
        if not isinstance(baseline_tools, list) or not baseline_tools:
            reasons.append("baseline does not declare its selected tool set")
        elif set(str(value) for value in baseline_tools) != set(current_tools):
            reasons.append("baseline selected tool set does not match the current scan")
    return not reasons, reasons


def _finding_key(finding: Finding) -> tuple[str, str, str, str]:
    source = finding.sources[0] if finding.sources else None
    location = finding.locations[0] if finding.locations else None
    return (
        source.tool if source else "",
        source.rule_id if source else "",
        location.path if location else "",
        finding.title.casefold(),
    )


def _record_key(value: dict[str, Any]) -> tuple[str, str, str, str]:
    sources = value.get("sources", [])
    locations = value.get("locations", [])
    source = sources[0] if isinstance(sources, list) and sources else {}
    location = locations[0] if isinstance(locations, list) and locations else {}
    return (
        str(source.get("tool") or "") if isinstance(source, dict) else "",
        str(source.get("rule_id") or "") if isinstance(source, dict) else "",
        str(location.get("path") or "") if isinstance(location, dict) else "",
        str(value.get("title") or "").casefold(),
    )


def _resolved_record(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_id": str(value.get("finding_id") or ""),
        "fingerprint": str(value.get("fingerprint") or ""),
        "title": str(value.get("title") or "")[:500],
        "severity": str(value.get("severity") or "unknown"),
        "domain": str(value.get("domain") or "")[:100],
        "area": str(value.get("area") or "")[:100],
        "status": FindingStatus.RESOLVED.value,
        "sources": value.get("sources", [])[:10]
        if isinstance(value.get("sources"), list)
        else [],
        "locations": value.get("locations", [])[:10]
        if isinstance(value.get("locations"), list)
        else [],
    }


def _load_codeowners(target: Path) -> list[tuple[str, list[str]]]:
    candidates = (
        target / ".github" / "CODEOWNERS",
        target / "CODEOWNERS",
        target / "docs" / "CODEOWNERS",
    )
    path = next(
        (value for value in candidates if value.is_file() and not value.is_symlink()),
        None,
    )
    if path is None or path.stat().st_size > _MAX_CODEOWNERS_BYTES:
        return []
    rules: list[tuple[str, list[str]]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        pattern = parts[0].lstrip("/")
        owners = [value for value in parts[1:] if value.startswith(("@", "mailto:"))]
        if pattern and owners:
            rules.append((pattern, owners[:20]))
        if len(rules) >= _MAX_CODEOWNERS_RULES:
            break
    return rules


def _owners_for_finding(
    finding: Finding, rules: list[tuple[str, list[str]]]
) -> list[str]:
    if not finding.locations:
        return []
    path = finding.locations[0].path.replace("\\", "/").lstrip("/")
    if not path or path.startswith("<"):
        return []
    owners: list[str] = []
    for pattern, candidates in rules:
        normalized = pattern.rstrip("/")
        matched = fnmatch.fnmatchcase(path, normalized)
        if not matched and "/" not in normalized:
            matched = any(
                fnmatch.fnmatchcase(part, normalized) for part in path.split("/")
            )
        if not matched and pattern.endswith("/"):
            matched = path.startswith(normalized + "/")
        if matched:
            owners = candidates
    return owners
