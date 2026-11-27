"""Count native analysis failures without retaining source or error contents."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import unquote, urlsplit

from ..strict_json import loads
from .sarif import load_sarif_document


def reconcile_codeql_coverage(
    payload: str, target: Path, expected: tuple[str, ...]
) -> dict[str, object]:
    """Use extraction diagnostics, never the subset of files with security alerts."""
    document = load_sarif_document(payload)
    scanned: list[str] = []
    errors: list[bool] = []
    known = False
    try:
        runs = document["runs"]
        if not isinstance(runs, list) or not runs:
            raise ValueError("missing runs")
        for run in runs:
            bases = run.get("originalUriBaseIds", {})
            if "%SRCROOT%" in bases and bases["%SRCROOT%"] != {
                "uri": target.resolve().as_uri().rstrip("/") + "/"
            }:
                raise ValueError(
                    "source root definition differs from the extraction target"
                )
            invocations = run["invocations"]
            if not isinstance(invocations, list) or not invocations:
                raise ValueError("missing invocation metadata")
            for invocation in invocations:
                if invocation.get("executionSuccessful") is not True:
                    errors.append(True)
                notifications = invocation["toolExecutionNotifications"]
                if not isinstance(notifications, list):
                    raise ValueError("invalid diagnostics")
                for notification in notifications:
                    identifier = notification.get("descriptor", {}).get("id")
                    if identifier == "py/diagnostics/successfully-extracted-files":
                        locations = notification["locations"]
                        if not isinstance(locations, list) or not locations:
                            raise ValueError("missing extracted file location")
                        for location in locations:
                            artifact = location["physicalLocation"]["artifactLocation"]
                            uri = artifact["uri"]
                            # Pinned CodeQL emits source-relative URIs. Unsupported
                            # bases fail closed rather than silently changing roots.
                            if artifact.get(
                                "uriBaseId"
                            ) != "%SRCROOT%" or not isinstance(uri, str):
                                raise ValueError("unsupported extracted file URI")
                            parsed = urlsplit(uri)
                            if (
                                parsed.scheme
                                or parsed.netloc
                                or parsed.query
                                or parsed.fragment
                            ):
                                raise ValueError("non-relative extracted file URI")
                            scanned.append(unquote(uri))
                        known = True
                    elif notification.get("level", "warning") not in {"none", "note"}:
                        errors.append(True)
        normalized = (
            {"errors": errors, "paths": {"scanned": scanned}}
            if known
            else {"errors": errors}
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        normalized = {"errors": errors}
    result = reconcile_coverage(json.dumps(normalized), target, expected, semgrep=True)
    result["basis"] = "CodeQL extraction diagnostics and pre-scan Python inventory"
    return result


def native_coverage(payload: str, *, semgrep: bool = False) -> dict[str, int]:
    document = loads(payload)
    if not isinstance(document, dict):
        raise TypeError("scanner coverage must be an object")
    errors = document.get("errors", [])
    if not isinstance(errors, list):
        raise TypeError("scanner errors must be a list")
    skipped = []
    timeouts = []
    if semgrep:
        paths = document.get("paths", {})
        if not isinstance(paths, dict):
            raise TypeError("scanner paths must be an object")
        skipped = paths.get("skipped", [])
        if not isinstance(skipped, list):
            raise TypeError("scanner skipped paths must be a list")
        # Semgrep can exit successfully with no top-level errors while its
        # dataflow solver reports failures only in profiling metadata. These
        # are incomplete analyses even when every file appears in `scanned`.
        timing = document.get("time", {})
        if not isinstance(timing, dict):
            raise TypeError("scanner timing metadata must be an object")
        timeouts = timing.get("fixpoint_timeouts", [])
        if not isinstance(timeouts, list):
            raise TypeError("scanner fixpoint timeouts must be a list")
    return {"native_errors": len(errors) + len(timeouts), "skipped_files": len(skipped)}


def reconcile_coverage(
    payload: str, target: Path, expected: tuple[str, ...], *, semgrep: bool
) -> dict[str, object]:
    """Reconcile Python inputs against the engine inventory without disclosing paths."""
    document = loads(payload)
    native = (
        document.get("paths", {}).get("scanned") if semgrep else document.get("metrics")
    )
    paths = (
        native
        if semgrep
        else [key for key in native if key != "_totals"]
        if isinstance(native, dict)
        else None
    )
    known = isinstance(paths, list) and all(isinstance(path, str) for path in paths)
    observed: set[str] = set()
    invalid = 0
    if known and isinstance(paths, list):
        for value in paths:
            path = Path(value)
            absolute = path if path.is_absolute() else target / path
            try:
                normalized = absolute.resolve().relative_to(target.resolve()).as_posix()
            except (OSError, ValueError):
                invalid += 1
                continue
            if path.suffix.casefold() == ".py":
                observed.add(normalized)
    expected_set = set(expected)
    counts = native_coverage(payload, semgrep=semgrep)
    missing = expected_set - observed
    unexpected = observed - expected_set
    metadata_complete = "errors" in document and known
    state = (
        "unknown"
        if not metadata_complete
        else "partial"
        if any(counts.values()) or missing or unexpected or invalid
        else "complete"
    )
    return {
        **counts,
        "state": state,
        "scope": "maintained Python files",
        "expected_files": len(expected_set),
        "analyzed_files": len(observed) if known else None,
        "missing_files": len(missing) if known else None,
        "unexpected_files": len(unexpected) if known else None,
        "invalid_paths": invalid,
        "inventory_sha256": hashlib.sha256(
            "\n".join(sorted(expected_set)).encode()
        ).hexdigest(),
    }
