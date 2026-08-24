from __future__ import annotations

import sys
import os
from pathlib import Path
from typing import Any, cast

import atheris  # type: ignore[import-untyped]

with atheris.instrument_imports():
    from py_security_suite.adapters import ADAPTER_TYPES
    from py_security_suite.adapters.sarif import parse_sarif_findings
    from py_security_suite.config import ToolConfig
    from py_security_suite.strict_json import loads as strict_loads


_TARGET = Path("/fuzz-target")
_NAMED_ADAPTERS: tuple[tuple[str, Any], ...] = tuple(
    (name, cast(Any, adapter_type)(ToolConfig(), 1024 * 1024))
    for name, adapter_type in sorted(ADAPTER_TYPES.items())
)
_TARGET_NAME = os.environ.get("PYSEC_FUZZ_TARGET", "strict-json")
_ADAPTER_SHARDS = 8


def test_one_input(data: bytes) -> None:
    if not data or len(data) > 1024 * 1024:
        return
    payload = data
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return
    if _TARGET_NAME == "strict-json":
        try:
            strict_loads(
                payload,
                maximum_nodes=100_000,
                maximum_string_length=1024 * 1024,
            )
        except (TypeError, ValueError):
            pass
        return
    if _TARGET_NAME == "sarif":
        try:
            parse_sarif_findings(
                text,
                _TARGET,
                tool_name="fuzz",
                default_area="parser-fuzzing",
                default_impact="fuzz",
                default_remediation="fuzz",
            )
        except (TypeError, ValueError):
            pass
        return
    selected = _selected_adapters(_TARGET_NAME)
    selector = data[0] % len(selected)
    try:
        selected[selector][1].parse(text, _TARGET)
    except (OSError, TypeError, ValueError):
        pass


def _selected_adapters(target: str) -> tuple[tuple[str, Any], ...]:
    if target.startswith("adapter:"):
        name = target.partition(":")[2]
        selected = tuple(item for item in _NAMED_ADAPTERS if item[0] == name)
    elif target.startswith("adapter-"):
        try:
            shard = int(target.partition("-")[2])
        except ValueError as exc:
            raise ValueError("invalid adapter fuzz shard") from exc
        if not 0 <= shard < _ADAPTER_SHARDS:
            raise ValueError("invalid adapter fuzz shard")
        selected = tuple(
            item
            for index, item in enumerate(_NAMED_ADAPTERS)
            if index % _ADAPTER_SHARDS == shard
        )
    else:
        raise ValueError(f"unsupported fuzz target: {target}")
    if not selected:
        raise ValueError(f"fuzz target selects no adapters: {target}")
    return selected


def main() -> None:
    global _TARGET_NAME
    target_arguments = [item for item in sys.argv[1:] if item.startswith("--target=")]
    if len(target_arguments) > 1:
        raise ValueError("fuzzer accepts one --target argument")
    if target_arguments:
        _TARGET_NAME = target_arguments[0].partition("=")[2]
        sys.argv.remove(target_arguments[0])
    if _TARGET_NAME not in {"strict-json", "sarif"}:
        _selected_adapters(_TARGET_NAME)
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
