from __future__ import annotations

import base64
import importlib.util
import marshal

import pytest

from py_security_suite.bytecode_analysis import analyze_python_bytecode


def _pyc(source: str) -> bytes:
    return (
        importlib.util.MAGIC_NUMBER
        + b"\0" * 12
        + marshal.dumps(compile(source, "fixture.py", "exec"))
    )


def test_bytecode_analysis_retains_nested_import_and_dynamic_dispatch() -> None:
    payload = _pyc(
        "import json\ndef nested():\n    import pathlib\n    return eval('1')\n"
    )

    result = analyze_python_bytecode(payload)

    assert [1, "module-import", "json"] in result
    assert any(edge[1:] == ["module-import", "pathlib"] for edge in result)
    assert any(edge[1:] == ["dynamic-dispatch", "eval"] for edge in result)
    assert result == analyze_python_bytecode(payload)


@pytest.mark.parametrize(
    "payload, message",
    (
        (b"", "magic or header"),
        (importlib.util.MAGIC_NUMBER + b"\0" * 12, "marshal payload"),
        (
            importlib.util.MAGIC_NUMBER + b"\0" * 12 + marshal.dumps("not-code"),
            "not a code object",
        ),
    ),
)
def test_bytecode_analysis_rejects_malformed_payloads(
    payload: bytes, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        analyze_python_bytecode(payload)


def test_bytecode_analysis_normalizes_malformed_code_object_system_errors() -> None:
    payload = base64.b64decode(
        "8w0NCgAAAAAAAAAAAAAAAOMAAAAAAAAAbG9jYXRpb25zAAAAAfMcAAAAlQBTAFMBSwBy"
        "J1wBIgBTAjUBAAAAAAAAIABnASkD6QAAAABO2gExKQLaBGpzb27aBGV2YWypAPMAAAAA"
        "2gxmdXp6X3NlZWQucHnaCDxtb2R1bGU+cgkAAAABAAAAcw8AAADwAwEBAdsAC9kABIBT"
        "hQlyBwAAAA=="
    )
    payload = importlib.util.MAGIC_NUMBER + payload[4:]

    with pytest.raises(ValueError, match="marshal payload is invalid"):
        analyze_python_bytecode(payload)
