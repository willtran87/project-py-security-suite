"""Private, versioned report inputs for recovery after presentation failures."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import types
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, fields, is_dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, cast, get_args, get_origin, get_type_hints

from .models import Finding, ScanManifest
from .json_stream import iter_model_json
from .report_cleanup import cleanup_directory
from .path_safety import read_regular_file, resolve_regular_directory
from .source_context import redact_sensitive_snippets
from .strict_json import loads
from .version import __version__

_MAX_BYTES = 128 * 1024 * 1024


@dataclass
class ReportInputs:
    findings: list[Finding]
    manifest: ScanManifest
    diagnostics: dict[str, dict[str, Any]]
    include_evidence: bool
    derived_artifacts: dict[str, Any] | None

    def __post_init__(self) -> None:
        if any(
            re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", name) is None
            for name in self.diagnostics
        ):
            raise ValueError("unsafe diagnostic tool name in report inputs")


def _encode(document: object) -> bytes:
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _load(payload: bytes) -> Any:
    return loads(payload, maximum_nodes=5_000_000, maximum_string_length=16 * 1024**2)


@contextmanager
def preserve_report_inputs(
    output: Path, inputs: ReportInputs, harden: Callable[[Path], None]
) -> Iterator[None]:
    """Checkpoint before rendering; retain on failure, remove after publication."""
    redact_sensitive_snippets(inputs.findings)
    saved = inputs if inputs.include_evidence else replace(inputs, diagnostics={})
    recovery = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.recovery-", dir=output.parent)
    )
    try:
        harden(recovery)  # Restrict directory access before writing any evidence.
        with (recovery / "inputs.json").open("xb") as handle:
            harden(recovery)  # Also restrict the new file's explicit Windows ACL.
            total = 0
            digest = hashlib.sha256()

            def write(chunk: bytes) -> None:
                nonlocal total
                total += len(chunk)
                if total > _MAX_BYTES:
                    raise ValueError(
                        "report recovery inputs exceed the 128 MiB checkpoint limit"
                    )
                handle.write(chunk)

            write(b'{"inputs":')
            for chunk in iter_model_json(saved):
                digest.update(chunk)
                write(chunk)
            metadata = {
                "inputs_sha256": digest.hexdigest(),
                "schema_version": "1.0",
                "state": "incomplete",
                "suite_version": __version__,
            }
            write(b"," + _encode(metadata)[1:])
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        cleanup_directory(recovery)
        raise
    try:
        yield
    except BaseException as exc:
        exc.add_note(
            f"Completed scan inputs retained for pysec recover-report: {recovery}"
        )
        raise
    else:
        cleanup_directory(recovery)


def load_report_inputs(recovery: Path) -> ReportInputs:
    root = resolve_regular_directory(recovery, "report recovery directory")
    _, payload = read_regular_file(
        root / "inputs.json",
        "report recovery inputs",
        maximum_bytes=_MAX_BYTES,
        boundary=root,
    )
    envelope = _load(payload)
    if (
        not isinstance(envelope, dict)
        or set(envelope)
        != {"schema_version", "suite_version", "state", "inputs", "inputs_sha256"}
        or envelope["schema_version"] != "1.0"
        or envelope["suite_version"] != __version__
        or envelope["state"] != "incomplete"
    ):
        raise ValueError("unsupported report recovery checkpoint")
    if (
        hashlib.sha256(_encode(envelope["inputs"])).hexdigest()
        != envelope["inputs_sha256"]
    ):
        raise ValueError("report recovery input checksum mismatch")
    return cast(ReportInputs, _decode(ReportInputs, envelope["inputs"]))


def _decode(expected: Any, value: Any) -> Any:
    """Rehydrate only statically declared model types, rejecting shape mismatches."""
    if expected is Any:
        return value
    origin = get_origin(expected)
    args = get_args(expected)
    if origin is types.UnionType:
        for member in args:
            try:
                return _decode(member, value)
            except (TypeError, ValueError):
                continue
        raise ValueError("invalid optional report recovery field")
    if origin is list and isinstance(value, list):
        return [_decode(args[0], item) for item in value]
    if origin is dict and isinstance(value, dict):
        return {
            _decode(args[0], key): _decode(args[1], item) for key, item in value.items()
        }
    if isinstance(expected, type) and issubclass(expected, StrEnum):
        return expected(value)
    if (
        isinstance(expected, type)
        and is_dataclass(expected)
        and isinstance(value, dict)
    ):
        hints = get_type_hints(expected)
        if set(value) != {field.name for field in fields(expected)}:
            raise ValueError("report recovery model fields do not match")
        return expected(
            **{name: _decode(hints[name], item) for name, item in value.items()}
        )
    if type(value) is expected or (expected is float and type(value) is int):
        return value
    raise ValueError("invalid report recovery field type")
