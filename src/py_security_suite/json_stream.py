"""Serialize model trees without materializing a second complete object graph."""

from __future__ import annotations

import json
import math
from collections.abc import Iterator
from dataclasses import fields, is_dataclass
from pathlib import Path
from typing import Any


def model_object(value: Any) -> Any:
    if value is None or type(value) in (str, int, float, bool, dict, list, tuple):
        return value
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: getattr(value, field.name) for field in fields(value)}
    if isinstance(value, Path):
        return value.as_posix()
    return value


def iter_model_json(value: Any) -> Iterator[bytes]:
    """Compact sorted JSON with the recovery reader's shape limits applied inline."""
    nodes = 0

    def encode(item: Any, depth: int) -> Iterator[bytes]:
        nonlocal nodes
        nodes += 1
        if nodes > 4_999_980 or depth > 64:
            raise ValueError("report recovery JSON exceeds its structure limits")
        item = model_object(item)
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                item = {str(key): child for key, child in item.items()}
            yield b"{"
            for index, key in enumerate(sorted(item)):
                if index:
                    yield b","
                yield from encode(key, depth + 1)
                yield b":"
                yield from encode(item[key], depth + 1)
            yield b"}"
        elif isinstance(item, (list, tuple)):
            yield b"["
            for index, child in enumerate(item):
                if index:
                    yield b","
                yield from encode(child, depth + 1)
            yield b"]"
        else:
            if isinstance(item, str) and len(item) > 16 * 1024**2:
                raise ValueError("report recovery JSON string exceeds its length limit")
            if isinstance(item, int) and not -(2**53 - 1) <= item <= 2**53 - 1:
                raise ValueError("report recovery JSON integer exceeds the safe range")
            if isinstance(item, float) and not math.isfinite(item):
                raise ValueError("report recovery JSON number must be finite")
            if isinstance(item, str):
                yield json.encoder.encode_basestring_ascii(item).encode("utf-8")
            elif item is None:
                yield b"null"
            elif isinstance(item, bool):
                yield b"true" if item else b"false"
            elif isinstance(item, int):
                yield str(item).encode("ascii")
            else:
                yield json.dumps(item, allow_nan=False, separators=(",", ":")).encode(
                    "utf-8"
                )

    yield from encode(value, 2)  # Inputs live one level inside the envelope.
