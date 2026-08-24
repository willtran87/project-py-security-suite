from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, cast

import atheris  # type: ignore[import-untyped]

with atheris.instrument_imports():
    from py_security_suite.adapters import ADAPTER_TYPES
    from py_security_suite.adapters.sarif import parse_sarif_findings
    from py_security_suite.config import ToolConfig
    from py_security_suite.strict_json import loads as strict_loads


_TARGET = Path("/fuzz-target")
_ADAPTERS: tuple[Any, ...] = tuple(
    cast(Any, adapter_type)(ToolConfig(), 1024 * 1024)
    for _, adapter_type in sorted(ADAPTER_TYPES.items())
)


def test_one_input(data: bytes) -> None:
    if not data or len(data) > 1024 * 1024:
        return
    selector = data[0] % (len(_ADAPTERS) + 2)
    payload = data[1:]
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return
    if selector == 0:
        try:
            strict_loads(
                payload,
                maximum_nodes=100_000,
                maximum_string_length=1024 * 1024,
            )
        except (TypeError, ValueError):
            pass
        return
    if selector == 1:
        try:
            parse_sarif_findings(
                text,
                _TARGET,
                tool_name="fuzz",
                default_area="parser-fuzzing",
                default_impact="fuzz",
                default_remediation="fuzz",
            )
        except (AttributeError, KeyError, TypeError, ValueError):
            pass
        return
    try:
        _ADAPTERS[selector - 2].parse(text, _TARGET)
    except (AttributeError, IndexError, KeyError, OSError, TypeError, ValueError):
        pass


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
