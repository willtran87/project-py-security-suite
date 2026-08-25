from __future__ import annotations

import json
import math
from collections.abc import Iterable
from typing import Any, cast

import rfc8785


_MAX_SAFE_INTEGER = (1 << 53) - 1


def loads(
    payload: str | bytes,
    *,
    maximum_depth: int = 64,
    maximum_nodes: int = 250_000,
    maximum_string_length: int = 1_048_576,
) -> Any:
    """Decode bounded I-JSON, rejecting ambiguous or non-interoperable input."""

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
    _validate_shape(
        document,
        maximum_depth=maximum_depth,
        maximum_nodes=maximum_nodes,
        maximum_string_length=maximum_string_length,
    )
    return document


def canonical_bytes(value: object) -> bytes:
    """Serialize an already parsed value with RFC 8785 JCS."""

    _validate_shape(value)
    try:
        return rfc8785.dumps(cast(Any, value))
    except rfc8785.CanonicalizationError as exc:
        raise ValueError("value cannot be represented as RFC 8785 JSON") from exc


def dumps(value: object, *, indent: int | None = None) -> str:
    """Serialize strict JSON for human or machine output."""

    _validate_shape(value)
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        indent=indent,
        separators=(",", ":") if indent is None else None,
        sort_keys=True,
    )


def _validate_shape(
    value: object,
    *,
    maximum_depth: int = 64,
    maximum_nodes: int = 250_000,
    maximum_string_length: int = 1_048_576,
) -> None:
    if maximum_depth < 1 or maximum_nodes < 1 or maximum_string_length < 1:
        raise ValueError("strict JSON limits must be positive")
    pending: list[tuple[object, int]] = [(value, 1)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > maximum_nodes:
            raise ValueError("JSON structure exceeds the node limit")
        if depth > maximum_depth:
            raise ValueError("JSON structure exceeds the nesting limit")
        if isinstance(current, str):
            if len(current) > maximum_string_length:
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
            pending.extend((item, depth + 1) for item in _items(current))
        elif isinstance(current, (list, tuple)):
            pending.extend((item, depth + 1) for item in current)
        else:
            raise ValueError(f"unsupported JSON value type: {type(current).__name__}")


def _items(value: dict[str, object]) -> Iterable[object]:
    for key, item in value.items():
        yield key
        yield item
