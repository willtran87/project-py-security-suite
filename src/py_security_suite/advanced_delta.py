from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .execution import sha256_file
from .path_safety import resolve_regular_file


_MAX_BYTES = 128 * 1024 * 1024
_MAX_CHANGES = 500
_PRIVACY_RANK = {
    "protected-static-route": 0,
    "mandatory-control-not-established": 1,
    "control-bypass-review": 2,
    "protection-gap": 3,
    "redaction-order-risk": 4,
}
_CONTROL_RANK = {"mandatory": 0, "not-on-retained-route": 1, "bypass-capable": 2}
_TIER_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def compare_advanced_analysis(
    baseline: Path,
    current: Path,
    *,
    baseline_sha256: str,
    current_sha256: str,
) -> dict[str, Any]:
    """Compare digest-bound cross-evidence analyses as release attack surfaces."""
    before = _load(baseline, baseline_sha256, "baseline advanced analysis")
    after = _load(current, current_sha256, "current advanced analysis")
    controls = _transitions(
        _control_index(before),
        _control_index(after),
        field="topology_status",
        rank=_CONTROL_RANK,
    )
    privacy = _transitions(
        _index(before, "telemetry_privacy_topology", _privacy_key),
        _index(after, "telemetry_privacy_topology", _privacy_key),
        field="review_status",
        rank=_PRIVACY_RANK,
    )
    dependencies = _transitions(
        _index(before, "dependency_trust_routes", _dependency_key),
        _index(after, "dependency_trust_routes", _dependency_key),
        field="review_tier",
        rank=_TIER_RANK,
    )
    new_taint = _added(
        _index(before, "taint_paths", _taint_key),
        _index(after, "taint_paths", _taint_key),
    )
    new_entries = [
        item
        for item in _added(_published_entries(before), _published_entries(after))
        if item.get("parity_status") != "modeled-entry-point"
    ]
    new_record_gaps = _added(_record_gaps(before), _record_gaps(after))
    regressions = [
        *controls["regressions"],
        *privacy["regressions"],
        *dependencies["regressions"],
        *new_taint,
        *new_entries,
        *new_record_gaps,
    ]
    return {
        "schema_version": "1.0",
        "schema_id": "urn:project-py-security-suite:advanced-analysis-delta:1.0",
        "authoritative": False,
        "verdict": "regression" if regressions else "pass",
        "scope": (
            "Digest-bound attack-surface comparison. A passing delta does not prove "
            "runtime safety, exploitability absence, or control effectiveness."
        ),
        "baseline": _identity(before, baseline, baseline_sha256),
        "current": _identity(after, current, current_sha256),
        "summary": {
            "regressions": len(regressions),
            "control_regressions": len(controls["regressions"]),
            "privacy_regressions": len(privacy["regressions"]),
            "dependency_trust_regressions": len(dependencies["regressions"]),
            "new_scanner_confirmed_taint_paths": len(new_taint),
            "new_unmodeled_published_entry_points": len(new_entries),
            "new_wheel_record_gaps": len(new_record_gaps),
            "control_improvements": len(controls["improvements"]),
            "privacy_improvements": len(privacy["improvements"]),
            "dependency_trust_improvements": len(dependencies["improvements"]),
        },
        "changes": {
            "control_regressions": controls["regressions"][:_MAX_CHANGES],
            "privacy_regressions": privacy["regressions"][:_MAX_CHANGES],
            "dependency_trust_regressions": dependencies["regressions"][:_MAX_CHANGES],
            "new_scanner_confirmed_taint_paths": new_taint[:_MAX_CHANGES],
            "new_unmodeled_published_entry_points": new_entries[:_MAX_CHANGES],
            "new_wheel_record_gaps": new_record_gaps[:_MAX_CHANGES],
            "control_improvements": controls["improvements"][:_MAX_CHANGES],
            "privacy_improvements": privacy["improvements"][:_MAX_CHANGES],
            "dependency_trust_improvements": dependencies["improvements"][
                :_MAX_CHANGES
            ],
        },
        "omitted": {
            "regressions": max(0, len(regressions) - _MAX_CHANGES),
            "change_limit": _MAX_CHANGES,
        },
    }


def render_advanced_delta_markdown(delta: dict[str, Any]) -> str:
    summary = _object(delta.get("summary"))
    changes = _object(delta.get("changes"))
    lines = [
        "# Cross-evidence attack-surface delta",
        "",
        "> Digest-bound comparison; absence of a regression is not proof of safety.",
        "",
        f"- **Verdict:** `{_md(delta.get('verdict'))}`",
        f"- **Regressions:** {int(summary.get('regressions') or 0)}",
        f"- **Control topology regressions:** {int(summary.get('control_regressions') or 0)}",
        f"- **Telemetry privacy regressions:** {int(summary.get('privacy_regressions') or 0)}",
        f"- **Dependency trust regressions:** {int(summary.get('dependency_trust_regressions') or 0)}",
        f"- **New confirmed taint paths:** {int(summary.get('new_scanner_confirmed_taint_paths') or 0)}",
        f"- **New unmodeled artifact entry points:** {int(summary.get('new_unmodeled_published_entry_points') or 0)}",
        f"- **New wheel RECORD gaps:** {int(summary.get('new_wheel_record_gaps') or 0)}",
        "",
        "## Actionable regressions",
        "",
        "| Kind | Subject | Transition / evidence |",
        "|---|---|---|",
    ]
    rows: list[str] = []
    for key, label in (
        ("control_regressions", "control"),
        ("privacy_regressions", "privacy"),
        ("dependency_trust_regressions", "dependency"),
    ):
        rows.extend(
            f"| `{label}` | `{_md(item.get('key'))}` | "
            f"`{_md(item.get('before'))}` → `{_md(item.get('after'))}` |"
            for item in _objects(changes.get(key), _MAX_CHANGES)
        )
    for key, label in (
        ("new_scanner_confirmed_taint_paths", "taint path"),
        ("new_unmodeled_published_entry_points", "artifact entry"),
        ("new_wheel_record_gaps", "wheel RECORD"),
    ):
        for item in _objects(changes.get(key), _MAX_CHANGES):
            subject = (
                item.get("path")
                or item.get("target")
                or item.get("name")
                or item.get("kind")
                or "unknown"
            )
            rows.append(f"| `{label}` | `{_md(subject)}` | newly retained |")
    lines.extend(rows or ["| none | — | No retained regression |"])
    return "\n".join(lines) + "\n"


def _load(path: Path, expected_sha256: str, label: str) -> dict[str, Any]:
    source = resolve_regular_file(path, label)
    if source.stat().st_size > _MAX_BYTES:
        raise ValueError(f"{label} exceeds {_MAX_BYTES} bytes")
    if not expected_sha256 or sha256_file(source) != expected_sha256.casefold():
        raise ValueError(f"{label} does not match the approved SHA-256")
    value = json.loads(source.read_bytes())
    if not isinstance(value, dict):
        raise TypeError(f"{label} root must be an object")
    if (
        value.get("schema_version") != "1.0"
        or value.get("schema_id")
        != "urn:project-py-security-suite:advanced-analysis:1.0"
    ):
        raise ValueError(f"{label} uses an unsupported schema")
    return value


def _identity(value: dict[str, Any], path: Path, digest: str) -> dict[str, Any]:
    identity = _object(value.get("analysis_identity"))
    return {
        "path": str(path.expanduser().resolve()),
        "sha256": digest.casefold(),
        "source_sha256": str(identity.get("source_sha256") or ""),
        "graph_source_sha256": str(identity.get("graph_source_sha256") or ""),
        "artifact_sha256": _strings(identity.get("artifact_sha256"), 500),
    }


def _index(
    value: dict[str, Any], section: str, key_fn: Any
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in _objects(value.get(section), 10_000):
        key = str(key_fn(item) or "")
        if key:
            result[key] = item
    return result


def _transitions(
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
    *,
    field: str,
    rank: dict[str, int],
) -> dict[str, list[dict[str, Any]]]:
    regressions: list[dict[str, Any]] = []
    improvements: list[dict[str, Any]] = []
    for key in sorted(set(before) & set(after)):
        old = str(before[key].get(field) or "")
        new = str(after[key].get(field) or "")
        if old == new or old not in rank or new not in rank:
            continue
        record = {"key": key, "before": old, "after": new, "current": after[key]}
        (regressions if rank[new] > rank[old] else improvements).append(record)
    return {"regressions": regressions, "improvements": improvements}


def _added(
    before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    return [after[key] for key in sorted(set(after) - set(before))]


def _published_entries(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for artifact in _objects(value.get("artifact_route_parity"), 10_000):
        artifact_name = str(artifact.get("artifact") or "")
        for item in _objects(artifact.get("published_entry_points"), 10_000):
            key = "|".join(
                (
                    Path(artifact_name).name,
                    str(item.get("group") or ""),
                    str(item.get("name") or ""),
                    str(item.get("target") or ""),
                )
            )
            result[key] = item
    return result


def _control_index(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in _objects(value.get("control_topology"), 10_000):
        path = str(item.get("path") or "")
        status = str(item.get("topology_status") or "")
        if not path or status not in _CONTROL_RANK:
            continue
        existing = result.get(path)
        existing_rank = (
            _CONTROL_RANK.get(str(existing.get("topology_status") or ""), -1)
            if existing is not None
            else -1
        )
        if _CONTROL_RANK[status] > existing_rank:
            result[path] = item
    return result


def _record_gaps(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for artifact in _objects(value.get("artifact_route_parity"), 10_000):
        name = Path(str(artifact.get("artifact") or "")).name
        for item in _objects(artifact.get("record_gaps"), 10_000):
            key = f"{name}|{item.get('kind')}|{item.get('path') or item.get('detail') or ''}"
            result[key] = item
    return result


def _privacy_key(item: dict[str, Any]) -> str:
    return "|".join(
        (
            str(item.get("path") or ""),
            str(item.get("sink_family") or ""),
            str(item.get("trust_boundary") or ""),
        )
    )


def _dependency_key(item: dict[str, Any]) -> str:
    return "|".join(
        (
            str(item.get("package") or ""),
            str(item.get("primary_identifier") or ""),
            str(item.get("path") or ""),
        )
    )


def _taint_key(item: dict[str, Any]) -> str:
    source = _object(item.get("source"))
    sink = _object(item.get("sink"))
    return "|".join(
        (
            str(item.get("tool") or ""),
            str(item.get("finding_id") or ""),
            str(source.get("path") or ""),
            str(source.get("line") or ""),
            str(sink.get("path") or ""),
            str(sink.get("line") or ""),
        )
    )


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _objects(value: Any, maximum: int) -> list[dict[str, Any]]:
    return (
        [item for item in value[:maximum] if isinstance(item, dict)]
        if isinstance(value, list)
        else []
    )


def _strings(value: Any, maximum: int) -> list[str]:
    return (
        [str(item) for item in value[:maximum] if isinstance(item, str)]
        if isinstance(value, list)
        else []
    )


def _md(value: Any) -> str:
    return str(value or "").replace("`", "'").replace("|", "\\|")[:1000]
