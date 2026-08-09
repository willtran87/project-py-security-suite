from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from .execution import sha256_file
from .path_safety import resolve_regular_file

_MAX_INPUTS = 100
_MAX_BYTES = 128 * 1024 * 1024
_MAX_FILES = 20_000
_MAX_LINES = 10_000_000


def merge_coverage_scenarios(
    scenarios: tuple[tuple[str, Path, str], ...],
) -> dict[str, Any]:
    """Merge independently digest-bound coverage.py JSON scenarios offline."""
    if not scenarios or len(scenarios) > _MAX_INPUTS:
        raise ValueError("coverage merge requires 1-100 scenarios")
    names: set[str] = set()
    merged: dict[str, set[int]] = {}
    inputs: list[dict[str, Any]] = []
    for name, path, expected in scenarios:
        if not name or name in names:
            raise ValueError("coverage scenario names must be non-empty and unique")
        names.add(name)
        source = resolve_regular_file(path, f"coverage scenario {name}")
        if source.stat().st_size > _MAX_BYTES:
            raise ValueError(f"coverage scenario {name} exceeds 128 MiB")
        digest = _digest(expected)
        if sha256_file(source) != digest:
            raise ValueError(f"coverage scenario {name} does not match its SHA-256")
        document = json.loads(source.read_bytes())
        files = document.get("files") if isinstance(document, dict) else None
        if not isinstance(files, dict) or len(files) > _MAX_FILES:
            raise TypeError(f"coverage scenario {name} requires a bounded files object")
        scenario_lines = 0
        for raw_path, raw in files.items():
            relative = _path(str(raw_path))
            if not isinstance(raw, dict) or not isinstance(
                raw.get("executed_lines"), list
            ):
                raise TypeError(
                    f"coverage scenario {name} file entries require executed_lines"
                )
            values = raw["executed_lines"]
            if any(
                not isinstance(line, int) or isinstance(line, bool) or line < 1
                for line in values
            ):
                raise ValueError(f"coverage scenario {name} contains an invalid line")
            merged.setdefault(relative, set()).update(values)
            scenario_lines += len(values)
            if scenario_lines > _MAX_LINES:
                raise ValueError(f"coverage scenario {name} exceeds the line limit")
        inputs.append(
            {
                "name": name,
                "path": str(source),
                "sha256": digest,
                "files": len(files),
                "executed_lines": scenario_lines,
            }
        )
    total_lines = sum(len(values) for values in merged.values())
    if len(merged) > _MAX_FILES or total_lines > _MAX_LINES:
        raise ValueError("merged coverage exceeds bounded file or line limits")
    result_files = {
        path: {
            "executed_lines": sorted(lines),
            "summary": {"covered_lines": len(lines)},
        }
        for path, lines in sorted(merged.items())
    }
    identity = hashlib.sha256(
        json.dumps(
            {path: value["executed_lines"] for path, value in result_files.items()},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return {
        "meta": {
            "format": 3,
            "version": "pysec-coverage-merge-1.0",
            "show_contexts": False,
        },
        "files": result_files,
        "pysec_merge": {
            "schema_version": "1.0",
            "target_code_executed": False,
            "scenario_count": len(inputs),
            "scenarios": sorted(inputs, key=lambda value: str(value["name"])),
            "files": len(result_files),
            "executed_lines": total_lines,
            "merged_sha256": identity,
        },
    }


def _path(value: str) -> str:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or path.is_absolute()
        or ".." in path.parts
        or ":" in path.parts[0]
    ):
        raise ValueError(f"coverage source path must be safe and relative: {value}")
    return path.as_posix()


def _digest(value: str) -> str:
    normalized = value.strip().casefold()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError("coverage scenario SHA-256 must be a lowercase digest")
    return normalized
