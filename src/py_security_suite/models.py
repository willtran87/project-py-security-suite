from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, cast


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class FindingStatus(StrEnum):
    UNCLASSIFIED = "unclassified"
    NEW = "new"
    EXISTING = "existing"
    RESOLVED = "resolved"
    REGRESSION = "regression"
    SUPPRESSED = "suppressed"


class ToolStatus(StrEnum):
    COMPLETED = "completed"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    PARSE_ERROR = "parse_error"
    SKIPPED = "skipped"


class Outcome(StrEnum):
    PASS = "pass"  # noqa: S105  # nosec B105 - policy outcome, not a credential
    WARN = "warn"
    FAIL = "fail"
    INCOMPLETE = "incomplete"


@dataclass(slots=True)
class Location:
    path: str
    start_line: int | None = None
    end_line: int | None = None
    package: str | None = None
    version: str | None = None
    ecosystem: str | None = None
    snippet: str | None = None
    snippet_start_line: int | None = None
    snippet_redacted: bool = False


@dataclass(slots=True)
class Source:
    tool: str
    rule_id: str
    message: str
    version: str = "unknown"
    native_severity: str = "unknown"


@dataclass(slots=True)
class Citation:
    kind: str
    identifier: str
    title: str
    uri: str | None = None


@dataclass(slots=True)
class Finding:
    finding_id: str
    fingerprint: str
    title: str
    description: str
    impact: str
    remediation: str
    severity: Severity
    confidence: Confidence
    area: str
    domain: str = "security"
    status: FindingStatus = FindingStatus.NEW
    classifications: list[str] = field(default_factory=list)
    locations: list[Location] = field(default_factory=list)
    sources: list[Source] = field(default_factory=list)
    citations: list[Citation] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    blocking: bool = False


@dataclass(slots=True)
class ToolRun:
    tool: str
    status: ToolStatus
    command: list[str]
    duration_seconds: float
    version: str = "unknown"
    exit_code: int | None = None
    finding_count: int = 0
    error: str | None = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    applicable: bool = True
    executable_sha256: str | None = None
    executable_integrity_verified: bool | None = None
    executable_organization_approved: bool = False
    executable_unchanged: bool | None = None
    auxiliary_executable_sha256: str | None = None
    auxiliary_executable_integrity_verified: bool | None = None
    auxiliary_executable_organization_approved: bool = False
    auxiliary_executable_unchanged: bool | None = None


@dataclass(slots=True)
class Inventory:
    python_files: int
    dependency_files: list[str]
    total_files: int
    skipped_symlinks: int
    declared_dependencies: bool = False
    lock_files: list[str] = field(default_factory=list)
    vcs_history_available: bool = False
    vcs_revision: str = ""
    vcs_revision_verified: bool = False
    distribution_files: list[str] = field(default_factory=list)
    source_sha256: str = ""
    source_sha256_after: str = ""
    source_integrity_verified: bool = False
    hashed_files: int = 0
    hashed_bytes: int = 0
    hashed_files_after: int = 0
    hashed_bytes_after: int = 0


@dataclass(slots=True)
class ScanManifest:
    schema_version: str
    suite_version: str
    scan_id: str
    target: str
    profile: str
    outcome: Outcome
    started_at: str
    finished_at: str
    duration_seconds: float
    network_policy: str
    network_isolation_attested: bool
    execute_target_code: bool
    inventory: Inventory
    tools: list[ToolRun]
    finding_counts: dict[str, int]
    policy_reasons: list[str]
    diagnostic_without_isolation: bool = False
    artifacts: dict[str, str] = field(default_factory=dict)
    configuration_sha256: str = ""
    risk_acceptance_sha256: str = ""
    intelligence: dict[str, Any] = field(default_factory=dict)
    baseline: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ScanResult:
    outcome: Outcome
    findings: list[Finding]
    tool_runs: list[ToolRun]
    manifest: ScanManifest


def utc_now() -> datetime:
    return datetime.now(UTC)


def isoformat(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize_repo_path(target: Path, path: str | Path) -> str:
    candidate = Path(path)
    if not candidate.is_absolute() and ".." in candidate.parts:
        return "<outside-target>"
    try:
        resolved_target = target.resolve()
        resolved_candidate = (
            candidate.resolve()
            if candidate.is_absolute()
            else (resolved_target / candidate).resolve()
        )
        candidate = resolved_candidate.relative_to(resolved_target)
    except (OSError, ValueError):
        return "<outside-target>"
    normalized = candidate.as_posix()
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized or "."


def finding_identity(
    *,
    tool: str,
    rule_id: str,
    path: str,
    start_line: int | None = None,
    package: str | None = None,
    advisory: str | None = None,
) -> tuple[str, str]:
    """Return a stable ID and fingerprint without incorporating secret values."""
    material = {
        "tool": tool,
        "rule_id": rule_id,
        "path": path,
        "start_line": start_line,
        "package": package,
        "advisory": advisory,
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"PYSEC-{digest[:12].upper()}", f"sha256:{digest}"


def json_ready(value: Any) -> Any:
    if isinstance(value, StrEnum):
        return str(value)
    if isinstance(value, Path):
        return value.as_posix()
    if is_dataclass(value) and not isinstance(value, type):
        return {key: json_ready(item) for key, item in asdict(cast(Any, value)).items()}
    if isinstance(value, dict):
        return {str(key): json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_ready(item) for item in value]
    return value
