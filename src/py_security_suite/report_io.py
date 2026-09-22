"""Private report file writes with streamed JSON encoding."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .models import json_ready


def write_json(path: Path, value: Any) -> None:
    encoder = json.JSONEncoder(
        indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False
    )
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600
    )
    with os.fdopen(descriptor, "wb") as handle:
        for chunk in encoder.iterencode(json_ready(value)):
            handle.write(chunk.encode("utf-8"))
        handle.write(b"\n")
    os.chmod(path, 0o600)


def write_text(path: Path, value: str) -> None:
    payload = value.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)  # noqa: S103 - private report artifact
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)  # noqa: S103 - repair pre-existing staged permissions
