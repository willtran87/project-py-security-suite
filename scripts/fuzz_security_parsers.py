from __future__ import annotations

import sys
from pathlib import Path

import atheris

with atheris.instrument_imports():
    from py_security_suite.adapters.sarif import parse_sarif_findings
    from py_security_suite.strict_json import loads as strict_loads


_TARGET = Path("/fuzz-target")


def test_one_input(data: bytes) -> None:
    if len(data) > 1024 * 1024:
        return
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    try:
        strict_loads(
            data,
            maximum_nodes=100_000,
            maximum_string_length=1024 * 1024,
        )
    except (TypeError, ValueError):
        pass
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


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
