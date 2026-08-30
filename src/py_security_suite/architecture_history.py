from __future__ import annotations

from collections import Counter
from itertools import combinations
from pathlib import Path
from typing import Any

from .execution import CommandEnvironment, resolve_executable, run_command
from .models import (
    Citation,
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
    finding_identity,
)


_SOURCE_SUFFIXES = frozenset(
    {
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
)
_SKIP_PARTS = frozenset(
    {
        ".artifacts",
        ".git",
        ".pysec-tools",
        ".venv",
        "build",
        "dist",
        "node_modules",
        "tests",
    }
)
_MAX_COMMITS = 500
_MAX_FILES_PER_COMMIT = 500
_MAX_PAIR_FILES_PER_COMMIT = 100
_MAX_PAIRS = 50


def architecture_history(
    target: Path, findings: list[Finding]
) -> tuple[list[Finding], dict[str, Any]]:
    """Mine bounded Git co-change evidence without treating correlation as causation."""

    git = resolve_executable("git")
    if git is None or not (target / ".git").is_dir():
        return [], _artifact(False, "verified Git history is unavailable", [], [], 0)
    execution = run_command(
        [
            git,
            "-c",
            f"safe.directory={target.resolve()}",
            "-C",
            str(target.resolve()),
            "log",
            f"--max-count={_MAX_COMMITS}",
            "--format=commit:%H",
            "--name-only",
            "--no-renames",
            "--no-decorate",
        ],
        cwd=target,
        timeout_seconds=120,
        max_output_bytes=32 * 1024 * 1024,
        environment=CommandEnvironment(extra={"GIT_OPTIONAL_LOCKS": "0"}),
    )
    if (
        execution.exit_code != 0
        or execution.timed_out
        or execution.output_limit_exceeded
    ):
        return [], _artifact(False, "bounded Git history query failed", [], [], 0)
    commits, file_truncated_commits = _parse_commits(execution.stdout, target)
    counts: Counter[str] = Counter()
    pair_counts: Counter[tuple[str, str]] = Counter()
    pair_analysis_omitted_commits = 0
    for files in commits:
        counts.update(files)
        if len(files) > _MAX_PAIR_FILES_PER_COMMIT:
            pair_analysis_omitted_commits += 1
        else:
            pair_counts.update(combinations(files, 2))
    coupled: list[dict[str, Any]] = []
    for (left, right), shared in pair_counts.items():
        denominator = min(counts[left], counts[right])
        ratio = shared / denominator if denominator else 0.0
        if shared < 8 or ratio < 0.8:
            continue
        coupled.append(
            {
                "left": left,
                "right": right,
                "shared_commits": shared,
                "left_commits": counts[left],
                "right_commits": counts[right],
                "coupling_ratio": round(ratio, 4),
                "overlaps_architecture_contract_violation": _architecture_overlap(
                    left, right, findings
                ),
            }
        )
    coupled.sort(
        key=lambda item: (
            -float(item["coupling_ratio"]),
            -int(item["shared_commits"]),
            str(item["left"]),
            str(item["right"]),
        )
    )
    couplings_detected = len(coupled)
    coupled = coupled[:_MAX_PAIRS]
    detected_hotspots = [
        {
            "path": path,
            "commits": count,
            "related_findings": _finding_count(path, findings),
        }
        for path, count in counts.most_common()
        if count >= 10 and _finding_count(path, findings)
    ]
    hotspots_detected = len(detected_hotspots)
    hotspots = detected_hotspots[:50]
    normalized_findings = [_coupling_finding(item) for item in coupled]
    normalized_findings.extend(_hotspot_finding(item) for item in hotspots)
    return normalized_findings, _artifact(
        not file_truncated_commits and not pair_analysis_omitted_commits,
        _history_limitation(file_truncated_commits, pair_analysis_omitted_commits),
        coupled,
        hotspots,
        len(commits),
        couplings_detected=couplings_detected,
        hotspots_detected=hotspots_detected,
        file_truncated_commits=file_truncated_commits,
        pair_analysis_omitted_commits=pair_analysis_omitted_commits,
    )


def _parse_commits(payload: str, target: Path) -> tuple[list[list[str]], int]:
    current: set[str] = set()
    commits: list[list[str]] = []
    current_truncated = False
    truncated_commits = 0
    resolved_target = target.resolve()
    for raw in payload.splitlines():
        line = raw.strip().replace("\\", "/")
        if line.startswith("commit:"):
            if current:
                commits.append(sorted(current))
                truncated_commits += int(current_truncated)
            current = set()
            current_truncated = False
            continue
        candidate = Path(line)
        if (
            not line
            or candidate.is_absolute()
            or ".." in candidate.parts
            or candidate.suffix.casefold() not in _SOURCE_SUFFIXES
        ):
            continue
        if any(part in _SKIP_PARTS for part in candidate.parts):
            continue
        try:
            resolved = (resolved_target / candidate).resolve()
            resolved.relative_to(resolved_target)
        except (OSError, ValueError):
            continue
        if not resolved.is_file():
            continue
        if len(current) < _MAX_FILES_PER_COMMIT:
            current.add(candidate.as_posix())
        elif candidate.as_posix() not in current:
            current_truncated = True
    if current:
        commits.append(sorted(current))
        truncated_commits += int(current_truncated)
    return commits[:_MAX_COMMITS], truncated_commits


def _history_limitation(file_truncated: int, pair_omitted: int) -> str | None:
    limitations: list[str] = []
    if file_truncated:
        limitations.append(
            f"{file_truncated} commit(s) exceeded the {_MAX_FILES_PER_COMMIT}-file history limit"
        )
    if pair_omitted:
        limitations.append(
            f"{pair_omitted} commit(s) exceeded the {_MAX_PAIR_FILES_PER_COMMIT}-file pair-analysis limit"
        )
    return "; ".join(limitations) or None


def _architecture_overlap(left: str, right: str, findings: list[Finding]) -> bool:
    for finding in findings:
        if not any(source.tool == "tach" for source in finding.sources):
            continue
        paths = {location.path for location in finding.locations}
        if left in paths or right in paths:
            return True
    return False


def _finding_count(path: str, findings: list[Finding]) -> int:
    return sum(
        path in {location.path for location in finding.locations}
        for finding in findings
    )


def _coupling_finding(item: dict[str, Any]) -> Finding:
    left, right = str(item["left"]), str(item["right"])
    rule_id = "ARCH-TEMPORAL-COUPLING"
    finding_id, fingerprint = finding_identity(
        tool="architecture-history", rule_id=rule_id, path=left, advisory=right
    )
    description = (
        f"{left} and {right} changed together in {item['shared_commits']} commits; "
        f"the bounded coupling ratio is {item['coupling_ratio']:.2f}."
    )
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        title="Persistent temporal coupling between source files",
        description=description,
        impact=(
            "Files that repeatedly require coordinated changes may hide an undeclared "
            "interface, duplicated responsibility, or a module boundary in the wrong place."
        ),
        remediation=(
            "Review the shared responsibility and change reasons; introduce a stable interface, "
            "move the behavior into one owner, or document why coordinated evolution is intentional."
        ),
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        area="architecture",
        domain="quality",
        classifications=[rule_id],
        locations=[Location(path=left), Location(path=right)],
        sources=[
            Source(
                tool="architecture-history",
                rule_id=rule_id,
                message=description,
                native_severity="review",
            )
        ],
        citations=[
            Citation(
                kind="tool_rule",
                identifier=rule_id,
                title="Temporal coupling analysis",
                uri="https://github.com/ishepard/pydriller",
            )
        ],
        evidence={"architecture_history": item},
    )


def _hotspot_finding(item: dict[str, Any]) -> Finding:
    path = str(item["path"])
    rule_id = "ARCH-CHANGE-RISK-HOTSPOT"
    finding_id, fingerprint = finding_identity(
        tool="architecture-history", rule_id=rule_id, path=path
    )
    description = (
        f"{path} changed in {item['commits']} of the retained commits and currently "
        f"has {item['related_findings']} normalized finding(s)."
    )
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        title="Frequently changed source retains active analysis findings",
        description=description,
        impact="Defects and architectural weaknesses concentrate where change frequency and unresolved analysis findings overlap.",
        remediation="Reduce the module's responsibilities, strengthen its tests and contracts, and resolve the overlapping findings before further expansion.",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        area="change-risk",
        domain="quality",
        classifications=[rule_id],
        locations=[Location(path=path)],
        sources=[
            Source(
                tool="architecture-history",
                rule_id=rule_id,
                message=description,
                native_severity="hotspot",
            )
        ],
        citations=[
            Citation(
                kind="tool_rule",
                identifier=rule_id,
                title="Repository mining",
                uri="https://github.com/ishepard/pydriller",
            )
        ],
        evidence={"architecture_history": item},
    )


def _artifact(
    complete: bool,
    limitation: str | None,
    coupled: list[dict[str, Any]],
    hotspots: list[dict[str, Any]],
    commits: int,
    *,
    couplings_detected: int = 0,
    hotspots_detected: int = 0,
    file_truncated_commits: int = 0,
    pair_analysis_omitted_commits: int = 0,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "analysis": "bounded-git-temporal-coupling-and-change-risk",
        "complete": complete,
        "commits_analyzed": commits,
        "history_limit": _MAX_COMMITS,
        "file_truncated_commits": file_truncated_commits,
        "pair_analysis_omitted_commits": pair_analysis_omitted_commits,
        "couplings_detected": couplings_detected,
        "hotspots_detected": hotspots_detected,
        "output_truncated": couplings_detected > _MAX_PAIRS or hotspots_detected > 50,
        "temporal_couplings": coupled,
        "change_risk_hotspots": hotspots,
        "limitations": [
            "Co-change is correlation and does not by itself prove an architectural defect.",
            *([limitation] if limitation else []),
        ],
    }
