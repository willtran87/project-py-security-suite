from __future__ import annotations

import os
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..execution import RawExecution
from ..models import (
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
    finding_identity,
)
from ..trusted_observation import governed_now


def map_severity(value: Any, *, default: Severity = Severity.UNKNOWN) -> Severity:
    normalized = str(value or "").strip().lower()
    mapping = {
        "critical": Severity.CRITICAL,
        "error": Severity.HIGH,
        "high": Severity.HIGH,
        "warning": Severity.MEDIUM,
        "warn": Severity.MEDIUM,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFORMATIONAL,
        "information": Severity.INFORMATIONAL,
        "informational": Severity.INFORMATIONAL,
        "unknown": Severity.UNKNOWN,
    }
    return mapping.get(normalized, default)


def database_freshness_error(
    root: Path, filename: str, maximum_age_days: float
) -> str | None:
    """Validate a staged database marker's age without consulting a network."""
    candidates = sorted(
        path
        for path in root.rglob(filename)
        if path.is_file() and not path.is_symlink()
    )
    if not candidates:
        return f"offline database freshness marker {filename!r} was not found"
    newest = max(candidates, key=lambda path: path.stat().st_mtime)
    modified = datetime.fromtimestamp(newest.stat().st_mtime, tz=UTC)
    age_days = (governed_now() - modified).total_seconds() / 86400
    if age_days > maximum_age_days:
        return (
            f"offline database is {age_days:.1f} days old; "
            f"maximum allowed age is {maximum_age_days:g} days"
        )
    return None


def map_confidence(value: Any) -> Confidence:
    normalized = str(value or "").strip().lower()
    mapping = {
        "high": Confidence.HIGH,
        "medium": Confidence.MEDIUM,
        "low": Confidence.LOW,
    }
    return mapping.get(normalized, Confidence.UNKNOWN)


def string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable) and not isinstance(value, (bytes, dict)):
        return [str(item) for item in value]
    return [str(value)]


def failure_exit_payload(name: str, execution: RawExecution, payload: str) -> str:
    """Reject an accepted nonzero exit that produced no machine-readable output.

    Scanners that use exit 1 to mean "findings reported" must also emit those
    findings. An empty stream on a nonzero exit means the scanner failed before
    reporting, so it must never be parsed as a clean result.
    """
    if execution.exit_code not in (0, None) and not payload.strip():
        raise ValueError(
            f"{name} exited {execution.exit_code} without producing "
            "machine-readable output"
        )
    return payload


def require_results_for_failure_exit(
    name: str, exit_code: int | None, result_count: int
) -> None:
    """Reject a findings exit code whose output reported no results."""
    if exit_code not in (0, None) and result_count == 0:
        raise ValueError(
            f"{name} exited {exit_code} but its output reported no results"
        )


SECRET_SCAN_APPLICABILITY_ENTRY_LIMIT = 100_000


def contains_regular_file(
    root: Path, *, entry_limit: int = SECRET_SCAN_APPLICABILITY_ENTRY_LIMIT
) -> bool:
    """Return whether a bounded walk of ``root`` finds any regular file.

    Exhausting the bound without a decision is treated as applicable so that a
    secret scanner still runs (fail closed) on very large trees.
    """
    pending = [root]
    seen = 0
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    seen += 1
                    if seen > entry_limit:
                        return True
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_file(follow_symlinks=False):
                            return True
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(Path(entry.path))
                    except OSError:
                        return True
        except OSError:
            return True
    return False


NATIVE_SUPPRESSION_FILE_LIMIT = 200_000
NATIVE_SUPPRESSION_BYTE_LIMIT = 4 * 1024**3


def native_suppression_markers(
    root: Path,
    marker: bytes,
    *,
    excluded: Iterable[re.Pattern[str]] = (),
    file_limit: int = NATIVE_SUPPRESSION_FILE_LIMIT,
    byte_limit: int = NATIVE_SUPPRESSION_BYTE_LIMIT,
) -> list[tuple[Path, int]]:
    """Locate in-source scanner suppression markers within a bounded walk.

    Scanners that cannot be told to ignore their inline suppression comments
    have those comments counted by the suite instead. The walk fails closed by
    raising ``ValueError`` when its file or byte budget is exhausted, because an
    unexamined file could hide a suppressed credential.
    """
    patterns = tuple(excluded)
    marker_folded = marker.lower()
    found: list[tuple[Path, int]] = []
    files = 0
    consumed = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError as exc:
            raise ValueError(
                f"could not inspect {directory} for native suppressions: {exc}"
            ) from exc
        for entry in entries:
            if any(pattern.search(entry.path) for pattern in patterns):
                continue
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                if entry.name == ".git":
                    continue
                pending.append(Path(entry.path))
                continue
            if not entry.is_file(follow_symlinks=False):
                continue
            files += 1
            if files > file_limit:
                raise ValueError(
                    "native suppression inspection exceeded its file budget"
                )
            try:
                with open(entry.path, "rb") as handle:
                    for line_number, line in enumerate(handle, start=1):
                        consumed += len(line)
                        if consumed > byte_limit:
                            raise ValueError(
                                "native suppression inspection exceeded its byte budget"
                            )
                        if marker_folded in line.lower():
                            found.append((Path(entry.path), line_number))
            except OSError as exc:
                raise ValueError(
                    f"could not inspect {entry.path} for native suppressions: {exc}"
                ) from exc
    return found


def native_suppression_finding(
    tool: str, *, rule_id: str, path: str, line: int, mechanism: str, area: str
) -> Finding:
    """Build an unaccepted finding for a target-controlled scanner suppression."""
    finding_id, fingerprint = finding_identity(
        tool=tool, rule_id=rule_id, path=path, start_line=line
    )
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        title=f"Scanner-native secret suppression in target: {mechanism}",
        description=(
            f"The scanned repository supplies a {mechanism} that {tool} always "
            "honours. Any candidate it hides was not reported, so the suppression "
            "itself is reported as an unaccepted finding."
        ),
        impact=(
            "A repository-controlled suppression can hide a real credential from "
            "the secret scan without suite-governed risk acceptance."
        ),
        remediation=(
            "Remove the native suppression and govern any confirmed test "
            "credential through the suite risk-acceptance process instead."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        area=area,
        classifications=["CWE-798"],
        locations=[Location(path=path, start_line=line, end_line=line)],
        sources=[
            Source(
                tool=tool,
                rule_id=rule_id,
                message=f"target-controlled {mechanism}",
                native_severity="suppression",
            )
        ],
        evidence={"redacted": True, "native_suppression": mechanism},
    )
