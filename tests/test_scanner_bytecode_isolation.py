"""Existing bytecode must not override verified scanner source."""

import importlib.util
import json
import marshal
import py_compile
import sys
from pathlib import Path

import pytest

from py_security_suite.execution import CommandEnvironment, run_command


@pytest.mark.parametrize("flags", [[], ["-I"], ["-E"]])
def test_scanner_ignores_modified_bytecode(tmp_path, flags):
    source = tmp_path / "cache_fixture.py"
    source.write_text('MARKER = "source"\n', encoding="utf-8")
    py_compile.compile(str(source), doraise=True)
    cache = Path(importlib.util.cache_from_source(str(source)))
    poisoned = cache.read_bytes()[:16] + marshal.dumps(
        compile('MARKER = "cached"\n', str(source), "exec")
    )
    cache.write_bytes(poisoned)
    result = run_command(
        [
            sys.executable,
            *flags,
            "-c",
            "import sys,json; sys.path.insert(0,sys.argv[1]); import cache_fixture; "
            "print(json.dumps([cache_fixture.MARKER,sys.pycache_prefix,sys.dont_write_bytecode]))",
            str(tmp_path),
        ],
        cwd=tmp_path,
        timeout_seconds=30,
        max_output_bytes=4096,
    )
    assert result.exit_code == 0, result.stderr
    marker, private_cache, writes_disabled = json.loads(result.stdout)
    assert marker == "source"
    assert writes_disabled is True
    assert not Path(private_cache).exists()
    assert cache.read_bytes() == poisoned


@pytest.mark.parametrize(
    "key", ["PYTHONPYCACHEPREFIX", "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE"]
)
def test_scanner_rejects_cache_policy_overrides(tmp_path, key):
    with pytest.raises(ValueError, match="cannot override"):
        run_command(
            [sys.executable, "-c", "pass"],
            cwd=tmp_path,
            timeout_seconds=30,
            max_output_bytes=4096,
            environment=CommandEnvironment(extra={key: "untrusted"}),
        )
