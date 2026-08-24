from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any

from .execution import (
    CommandEnvironment,
    native_runtime_closure_sha256,
    resolve_executable,
    run_command,
    sha256_file,
)
from .strict_json import canonical_bytes, loads as strict_loads


def run_pinned_json_command(
    prefix: str,
    request: dict[str, Any],
    *,
    timeout_seconds: int = 30,
    maximum_output_bytes: int = 1024 * 1024,
) -> dict[str, Any]:
    """Execute a deployment-pinned argv protocol and return strict JSON."""

    raw_command = os.environ.get(f"{prefix}_COMMAND_JSON", "").strip()
    expected_executable = (
        os.environ.get(f"{prefix}_EXECUTABLE_SHA256", "").strip().casefold()
    )
    try:
        command = strict_loads(raw_command)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{prefix} command is invalid") from exc
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(item, str) or not item for item in command)
        or not _digest(expected_executable)
    ):
        raise ValueError(f"{prefix} command configuration is incomplete")
    resolved = resolve_executable(command[0])
    if resolved is None or sha256_file(Path(resolved)) != expected_executable:
        raise ValueError(f"{prefix} executable does not match its deployment pin")
    _verify_assets(prefix)
    runtime_pin = os.environ.get(f"{prefix}_RUNTIME_SHA256", "").strip().casefold()
    if runtime_pin and (
        not _digest(runtime_pin)
        or native_runtime_closure_sha256(Path(resolved)) != runtime_pin
    ):
        raise ValueError(f"{prefix} runtime closure does not match its deployment pin")
    encoded_request = base64.b64encode(canonical_bytes(request)).decode("ascii")
    result = run_command(
        [str(resolved), *command[1:], encoded_request],
        cwd=Path(resolved).parent,
        timeout_seconds=timeout_seconds,
        max_output_bytes=maximum_output_bytes,
        environment=CommandEnvironment(max_scratch_bytes=16 * 1024 * 1024),
    )
    if sha256_file(Path(resolved)) != expected_executable:
        raise ValueError(f"{prefix} executable changed during governed execution")
    _verify_assets(prefix)
    if (
        result.exit_code != 0
        or result.timed_out
        or result.output_limit_exceeded
        or result.resource_limit_errors
        or result.stderr.strip()
    ):
        raise ValueError(f"{prefix} command failed its governed execution contract")
    try:
        value = strict_loads(result.stdout)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{prefix} command returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{prefix} command response must be an object")
    return value


def command_configured(prefix: str) -> bool:
    return bool(os.environ.get(f"{prefix}_COMMAND_JSON", "").strip())


def _verify_assets(prefix: str) -> None:
    raw = os.environ.get(f"{prefix}_ASSETS_JSON", "[]").strip()
    try:
        assets = strict_loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{prefix} command assets are invalid") from exc
    if not isinstance(assets, list) or len(assets) > 100:
        raise ValueError(f"{prefix} command assets are invalid")
    paths: set[Path] = set()
    for item in assets:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ValueError(f"{prefix} command asset fields do not match")
        path = Path(str(item["path"])).expanduser().resolve()
        digest = str(item["sha256"]).casefold()
        if path in paths or not _digest(digest) or sha256_file(path) != digest:
            raise ValueError(f"{prefix} command asset does not match its pin")
        paths.add(path)


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
