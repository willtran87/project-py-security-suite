"""Retain every attempt when checking native Semgrep repeatability."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Any

from py_security_suite.adapters.coverage import reconcile_coverage
from py_security_suite.adapters.semgrep import SemgrepAdapter
from py_security_suite.config import ToolConfig
from py_security_suite.path_safety import (
    is_link_like,
    read_regular_file,
    resolve_regular_directory,
)


def source_identity(source: Path) -> tuple[tuple[str, ...], str]:
    """Bind bounded regular Python files to their names and exact bytes."""
    records = []
    total = 0
    resolve_regular_directory(source, "repeatability input")
    for entry, path in enumerate(source.rglob("*"), start=1):
        if entry > 100000:
            raise ValueError("repeatability input entry limit exceeded")
        if is_link_like(path):
            raise ValueError("repeatability input contains a link")
        if path.suffix != ".py" or path.is_dir():
            continue
        if len(records) >= 10000:
            raise ValueError("repeatability input file limit exceeded")
        _, data = read_regular_file(
            path, "repeatability input", maximum_bytes=1024**2, boundary=source
        )
        total += len(data)
        if total > 64 * 1024**2:
            raise ValueError("repeatability input byte limit exceeded")
        records.append(
            (path.relative_to(source).as_posix(), hashlib.sha256(data).hexdigest())
        )
    if not records:
        raise ValueError("repeatability input has no Python files")
    records.sort()
    return tuple(name for name, _ in records), hashlib.sha256(
        json.dumps(records, separators=(",", ":")).encode()
    ).hexdigest()


def repeated_semgrep(
    execute: Callable[[], dict[str, Any]],
    source: Path,
    repetitions: int,
    *,
    checkpoint: Callable[[str, dict[str, Any]], None] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run a fixed count, never retry until green or omit failed attempts."""
    if type(repetitions) is not int or not 1 <= repetitions <= 5:
        raise ValueError("Semgrep repetitions must be between one and five")
    attempts: list[dict[str, Any]] = []
    first: dict[str, Any] = {}
    initial_identity = None
    for index in range(repetitions):
        started = time.monotonic()
        attempt: dict[str, Any] = {"attempt": index + 1, "complete": False}
        if checkpoint:
            checkpoint("started", dict(attempt))
        try:
            expected, before = source_identity(source)
            if initial_identity is None:
                initial_identity = before
            attempt["source_sha256_before"] = before
            attempt["source_files"] = len(expected)
            document = execute()
            _, after = source_identity(source)
            attempt["source_sha256_after"] = after
            attempt["unchanged_source"] = before == after == initial_identity
            if not isinstance(document, dict):
                raise TypeError("native output must be an object")
            payload = json.dumps(document)
            coverage = reconcile_coverage(payload, source, expected, semgrep=True)
            findings = SemgrepAdapter(ToolConfig(), 8 * 1024**2).parse(payload, source)
            serialized = sorted(
                json.dumps(asdict(finding), sort_keys=True) for finding in findings
            )
            version = document.get("version")
            if not isinstance(version, str) or not version:
                raise ValueError("missing native version")
            if index == 0:
                first = document
            attempt.update(
                version=version,
                coverage=coverage,
                finding_count=len(findings),
                findings_sha256=hashlib.sha256(
                    json.dumps(serialized).encode()
                ).hexdigest(),
                complete=coverage["state"] == "complete"
                and attempt["unchanged_source"],
            )
        except (
            OSError,
            RuntimeError,
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
        ) as exc:
            # Native output may contain source contents. Keep only the category.
            attempt["error_category"] = type(exc).__name__
        attempt["duration_seconds"] = round(time.monotonic() - started, 3)
        attempts.append(attempt)
        if checkpoint:
            checkpoint("finished", dict(attempt))
    signatures = {
        (attempt.get("version"), attempt.get("findings_sha256")) for attempt in attempts
    }
    stable = len(signatures) == 1 and all(
        attempt.get("findings_sha256") for attempt in attempts
    )
    return first, {
        "scope": "fixed-count native regression repetitions; not production reliability proof",
        "repetitions": repetitions,
        "attempts": attempts,
        "stable_findings": stable,
        "passed": stable and all(attempt["complete"] for attempt in attempts),
    }
