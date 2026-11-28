"""Fail-closed contracts of native runtime manifests and scanner lifecycle helpers."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from py_security_suite.execution import (
    _apply_process_resource_limits,
    _declared_native_plugins,
    _observed_native_components,
    _resolve_native_names,
)
from py_security_suite.scanner_launch import (
    descendant_snapshot,
    directory_size_exceeds,
    kill_descendants,
    kill_then_wait,
    launch_failure,
)

_DIGEST = "a" * 64


def _write_manifest(executable: Path, value: object) -> None:
    executable.with_name(f"{executable.name}.runtime-closure.json").write_text(
        json.dumps(value), encoding="utf-8"
    )


@pytest.fixture
def executable(tmp_path: Path) -> Path:
    path = tmp_path / "scanner"
    path.write_bytes(b"scanner")
    return path


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize(
    ("manifest", "message"),
    [
        ([], "fields do not match"),
        ({"schema_version": "1.0"}, "fields do not match"),
        ({"schema_version": "9", "plugins": []}, "is invalid"),
        ({"schema_version": "1.0", "plugins": {}}, "is invalid"),
        (
            {"schema_version": "1.1", "plugins": []},
            "observation contract is inconsistent",
        ),
        (
            {"schema_version": "1.0", "plugins": [], "observation": {}},
            "observation contract is inconsistent",
        ),
        (
            {
                "schema_version": "1.1",
                "plugins": [],
                "observation": {},
                "minimum_authority_signatures": 2,
                "authorities": [],
            },
            "authority contract is inconsistent",
        ),
        ({"schema_version": "1.0", "plugins": [{"path": "x"}]}, "entry fields"),
        (
            {"schema_version": "1.0", "plugins": [{"path": "", "sha256": _DIGEST}]},
            "identity is invalid",
        ),
        (
            {
                "schema_version": "1.0",
                "plugins": [{"path": "../escape", "sha256": _DIGEST}],
            },
            "identity is invalid",
        ),
        (
            {"schema_version": "1.0", "plugins": [{"path": "p", "sha256": "XYZ"}]},
            "identity is invalid",
        ),
        (
            {"schema_version": "1.0", "plugins": [{"path": "p", "sha256": _DIGEST}]},
            "SHA-256 does not match",
        ),
    ],
)
def test_native_plugin_manifest_rejects_malformed_declarations(
    executable: Path, manifest: object, message: str
) -> None:
    (executable.parent / "p").write_bytes(b"plugin")
    _write_manifest(executable, manifest)
    with pytest.raises(ValueError, match=message):
        _declared_native_plugins(executable)


def test_native_plugin_manifest_requirements(executable: Path) -> None:
    assert _declared_native_plugins(executable) == set()
    with pytest.raises(ValueError, match="explicit runtime-plugin manifest"):
        _declared_native_plugins(executable, required=True)
    plugin = executable.parent / "p"
    plugin.write_bytes(b"plugin")
    entry = {"path": "p", "sha256": _sha(b"plugin")}
    _write_manifest(executable, {"schema_version": "1.0", "plugins": [entry]})
    assert plugin.resolve() in _declared_native_plugins(executable)
    with pytest.raises(ValueError, match="independently authenticated"):
        _declared_native_plugins(executable, required=True)
    _write_manifest(executable, {"schema_version": "1.0", "plugins": [entry, entry]})
    with pytest.raises(ValueError, match="duplicated"):
        _declared_native_plugins(executable)
    _write_manifest(executable, {"schema_version": "1.0", "plugins": [entry] * 2049})
    with pytest.raises(ValueError, match="exceeds 2048"):
        _declared_native_plugins(executable)


def _observation(collector: Path, components: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "collector": collector.name,
        "collector_sha256": _sha(collector.read_bytes()),
        "platform": sys.platform,
        "observed_components": components,
    }


def test_loader_observation_binds_collector_and_declared_plugins(
    executable: Path,
) -> None:
    root = executable.parent
    collector = root / "collector"
    collector.write_bytes(b"collector")
    plugin = root / "plugin.so"
    plugin.write_bytes(b"plugin")
    library = root / "libc.so"
    library.write_bytes(b"libc")
    components = [
        {"path": "plugin.so", "sha256": _sha(b"plugin"), "scope": "plugin"},
        {"path": "libc.so", "sha256": _sha(b"libc"), "scope": "os-tcb"},
    ]
    declared = {str(plugin.resolve()): _sha(b"plugin")}
    observed = _observed_native_components(
        executable, _observation(collector, components), declared
    )
    assert observed == {collector.resolve(), plugin.resolve(), library.resolve()}

    with pytest.raises(ValueError, match="does not match the declared"):
        _observed_native_components(
            executable, _observation(collector, components[1:]), declared
        )
    for invalid, message in (
        ({}, "fields do not match"),
        ({**_observation(collector, []), "platform": "other"}, "is invalid"),
        ({**_observation(collector, []), "collector_sha256": "0" * 64}, "collector"),
        (_observation(collector, [{"path": "x"}]), "component fields"),
        (
            _observation(
                collector, [{"path": "x", "sha256": _DIGEST, "scope": "kernel"}]
            ),
            "identity is invalid",
        ),
        (_observation(collector, [components[1], components[1]]), "duplicated"),
        (
            _observation(
                collector, [{"path": "libc.so", "sha256": _DIGEST, "scope": "os-tcb"}]
            ),
            "SHA-256 does not match",
        ),
    ):
        with pytest.raises(ValueError, match=message):
            _observed_native_components(executable, invalid, declared)


def test_native_name_resolution_is_exact_and_fail_closed(tmp_path: Path) -> None:
    library = tmp_path / "libdemo.so"
    library.write_bytes(b"lib")
    assert _resolve_native_names(
        {"libdemo.so", "api-ms-win-core.dll", str(library)},
        (tmp_path,),
        api_set_prefixes=("api-ms-",),
    ) == {library.resolve()}
    with pytest.raises(ValueError, match="unresolved native dependencies"):
        _resolve_native_names({"missing.so"}, (tmp_path,))
    assert _resolve_native_names({"missing.so"}, (tmp_path,), allow_missing=True) == (
        set()
    )


def test_posix_limit_report_contract(tmp_path: Path) -> None:
    process = MagicMock()
    process.pid = 1234
    process.poll.return_value = 0
    report = tmp_path / "limits-applied.json"
    with patch("py_security_suite.execution.os.name", "posix"):
        assert _apply_process_resource_limits(
            process,
            max_output_bytes=1,
            timeout_seconds=1,
            max_scratch_bytes=1,
            limit_report=report,
        ) == ((), ("posix-child-limits:unavailable",), None)
        report.write_text('{"enforced": ["cpu-time"], "errors": [1]}', "utf-8")
        assert _apply_process_resource_limits(
            process,
            max_output_bytes=1,
            timeout_seconds=1,
            max_scratch_bytes=1,
            limit_report=report,
        ) == ((), ("posix-child-limits:invalid-report",), None)
        report.write_text(
            '{"enforced": ["cpu-time"], "errors": ["file-size:denied"]}', "utf-8"
        )
        assert _apply_process_resource_limits(
            process,
            max_output_bytes=1,
            timeout_seconds=1,
            max_scratch_bytes=1,
            limit_report=report,
        ) == (("cpu-time",), ("file-size:denied",), None)
    invalid = MagicMock()
    invalid.pid = None
    assert _apply_process_resource_limits(
        invalid,
        max_output_bytes=1,
        timeout_seconds=1,
        max_scratch_bytes=1,
        limit_report=report,
    ) == ((), (), None)


def test_launch_failure_marker_must_be_an_object(tmp_path: Path) -> None:
    (tmp_path / "launch-failure.json").write_text("[]", encoding="utf-8")
    assert "invalid launch-failure marker" in launch_failure(tmp_path)


def test_scratch_accounting_bounds(tmp_path: Path) -> None:
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "data").write_bytes(b"x" * 64)
    assert directory_size_exceeds(tmp_path, 64)
    assert not directory_size_exceeds(tmp_path, 65)
    assert not directory_size_exceeds(tmp_path / "missing", 1)
    try:
        (tmp_path / "link").symlink_to(tmp_path / "nested" / "data")
    except OSError:
        pass
    assert not directory_size_exceeds(tmp_path, 65)

    class _Link:
        @staticmethod
        def is_symlink() -> bool:
            return True

    with patch(
        "py_security_suite.scanner_launch.os.scandir",
        return_value=[_Link()] * 100_001,
    ):
        assert directory_size_exceeds(tmp_path, 1 << 40)
    broken = MagicMock()
    broken.is_symlink.side_effect = OSError("vanished")
    with patch("py_security_suite.scanner_launch.os.scandir", return_value=[broken]):
        assert not directory_size_exceeds(tmp_path, 1)


def test_descendant_cleanup_helpers_are_best_effort() -> None:
    assert descendant_snapshot(-1) == []
    killed: list[str] = []
    alive = MagicMock()
    alive.kill.side_effect = lambda: killed.append("alive")
    gone = MagicMock()
    gone.kill.side_effect = ProcessLookupError()
    kill_descendants([object(), gone, alive])
    assert killed == ["alive"]

    child = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", "import time; time.sleep(30)"]
    )
    try:
        snapshot = descendant_snapshot(os.getpid())
        assert any(getattr(item, "pid", None) == child.pid for item in snapshot)
    finally:
        child.kill()
        child.wait(timeout=10)

    unkillable = MagicMock()
    unkillable.wait.side_effect = subprocess.TimeoutExpired("x", 1)
    unkillable.kill.side_effect = OSError("denied")
    assert kill_then_wait(unkillable, 0.01) is False
