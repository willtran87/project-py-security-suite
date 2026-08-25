from __future__ import annotations

import json
import math
from typing import Any, cast

import rfc8785


_MAX_SAFE_INTEGER = (1 << 53) - 1


def loads(payload: str | bytes) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ValueError(f"JSON contains a duplicate property: {key!r}")
            result[key] = value
        return result

    def constant(value: str) -> None:
        raise ValueError(f"JSON contains a non-finite number: {value}")

    def integer(value: str) -> int:
        result = int(value)
        if not -_MAX_SAFE_INTEGER <= result <= _MAX_SAFE_INTEGER:
            raise ValueError("JSON integer exceeds the I-JSON interoperable range")
        return result

    def real(value: str) -> float:
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("JSON number is not finite")
        return result

    document = json.loads(
        payload,
        object_pairs_hook=pairs,
        parse_constant=constant,
        parse_int=integer,
        parse_float=real,
    )
    _validate(document)
    return document


def canonical_bytes(value: object) -> bytes:
    _validate(value)
    try:
        return rfc8785.dumps(cast(Any, value))
    except rfc8785.CanonicalizationError as exc:
        raise ValueError("value cannot be represented as RFC 8785 JSON") from exc


def dumps(value: object, *, indent: int | None = None) -> str:
    _validate(value)
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        indent=indent,
        separators=(",", ":") if indent is None else None,
        sort_keys=True,
    )


def _validate(value: object) -> None:
    pending: list[tuple[object, int]] = [(value, 1)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > 250_000 or depth > 64:
            raise ValueError("JSON structure exceeds safety limits")
        if isinstance(current, str):
            if len(current) > 1_048_576:
                raise ValueError("JSON string exceeds the length limit")
        elif current is None or isinstance(current, bool):
            continue
        elif isinstance(current, int):
            if not -_MAX_SAFE_INTEGER <= current <= _MAX_SAFE_INTEGER:
                raise ValueError("JSON integer exceeds the I-JSON interoperable range")
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise ValueError("JSON number is not finite")
        elif isinstance(current, dict):
            if any(not isinstance(key, str) for key in current):
                raise ValueError("JSON object keys must be strings")
            pending.extend(
                (item, depth + 1) for pair in current.items() for item in pair
            )
        elif isinstance(current, (list, tuple)):
            pending.extend((item, depth + 1) for item in current)
        else:
            raise ValueError(f"unsupported JSON value type: {type(current).__name__}")
