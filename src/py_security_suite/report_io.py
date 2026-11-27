"""Private report file writes with streamed JSON encoding.

Files are opened without following a final symbolic link (``O_NOFOLLOW``
where the platform provides it; a link check elsewhere) and are flushed to
stable storage before the staging directory is published, so a crash after
the atomic rename cannot expose truncated evidence under the trusted name.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .models import json_ready
from .path_safety import is_link_like

_WRITE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_TRUNC
    | getattr(os, "O_BINARY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


def _open_private(path: Path) -> int:
    if not hasattr(os, "O_NOFOLLOW") and is_link_like(path):
        raise OSError(f"report file must not be a link: {path}")
    return os.open(path, _WRITE_FLAGS, 0o600)  # noqa: S103 - private report artifact


def write_json(path: Path, value: Any) -> None:
    encoder = json.JSONEncoder(
        indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False
    )
    descriptor = _open_private(path)
    with os.fdopen(descriptor, "wb") as handle:
        for chunk in encoder.iterencode(json_ready(value)):
            handle.write(chunk.encode("utf-8"))
        handle.write(b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)


def write_text(path: Path, value: str) -> None:
    payload = value.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    descriptor = _open_private(path)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)  # noqa: S103 - repair pre-existing staged permissions
