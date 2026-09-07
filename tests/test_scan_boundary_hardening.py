from __future__ import annotations

import hashlib
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest
from jsonschema import ValidationError

from py_security_suite.artifact_validation import validate_governed_artifacts
from py_security_suite.config import load_config
from py_security_suite.dependency_surface import dependency_surface_artifact
from py_security_suite.diagnostic_safety import sanitize_terminal_text
from py_security_suite.inventory import (
    inventory_target_with_evidence,
    sealed_source_snapshot,
    source_snapshot,
)
from py_security_suite.orchestrator import scan_project
from py_security_suite.path_safety import open_regular_file
from py_security_suite.passport import verify_report
from py_security_suite.scan_control import ScanControl, ScanInterrupted, controlled_scan
from py_security_suite.scan_progress import ProgressDispatcher
from py_security_suite.source_stream import stream_source


@pytest.mark.parametrize("cause", ["cancel", "deadline", "memory"])
def test_stopped_scan_does_not_begin_inventory(tmp_path: Path, cause: str) -> None:
    control = ScanControl()
    if cause == "cancel":
        control.cancel()
    elif cause == "deadline":
        control.timeout_seconds = 1
        control.started = time.monotonic() - 2
    else:
        control.max_memory_bytes = 1
    with (
        controlled_scan(control),
        patch(
            "py_security_suite.scan_control._process_tree_resident_bytes",
            return_value=2,
        ),
        patch(
            "py_security_suite.orchestrator.inventory_target_with_evidence"
        ) as inventory,
        pytest.raises(ScanInterrupted),
    ):
        scan_project(
            target=tmp_path,
            output=tmp_path / "report",
            config=load_config(profile_override="quick"),
            network_isolation_attested=False,
        )
    inventory.assert_not_called()
    assert not (tmp_path / "report").exists()


def test_snapshot_streams_large_members_and_preserves_digest(tmp_path: Path) -> None:
    payload = b"x" * (3 * 1024**2 + 17)
    (tmp_path / "large.bin").write_bytes(payload)
    reads = []

    @contextmanager
    def bounded_open(*args, **kwargs):
        with open_regular_file(*args, **kwargs) as (path, handle, size):

            class Reader:
                def read(self, count):
                    assert 0 < count <= 1024**2
                    reads.append(count)
                    return handle.read(count)

            yield path, Reader(), size

    with patch("py_security_suite.source_stream.open_regular_file", bounded_open):
        _, inventory = inventory_target_with_evidence(tmp_path)
        with sealed_source_snapshot(tmp_path, inventory) as snapshot:
            assert (snapshot / "large.bin").read_bytes() == payload
            assert source_snapshot(snapshot)[0] == inventory["source_sha256"]
    assert len(reads) >= 12
    assert inventory["files"][0]["sha256"] == hashlib.sha256(payload).hexdigest()
    assert not snapshot.exists()


def test_cancel_during_copy_cleans_partial_snapshot(tmp_path: Path) -> None:
    (tmp_path / "large.bin").write_bytes(b"x" * (3 * 1024**2))
    _, inventory = inventory_target_with_evidence(tmp_path)
    control = ScanControl()
    destinations = []

    @contextmanager
    def cancel_after_read(*args, **kwargs):
        with open_regular_file(*args, **kwargs) as (path, handle, size):

            class Reader:
                def read(self, count):
                    payload = handle.read(count)
                    control.cancel()
                    return payload

            yield path, Reader(), size

    def copy(*args, **kwargs):
        destinations.append(Path(kwargs["destination"].name))
        return stream_source(*args, **kwargs)

    with (
        controlled_scan(control),
        patch("py_security_suite.source_stream.open_regular_file", cancel_after_read),
        patch("py_security_suite.inventory.stream_source", side_effect=copy),
        pytest.raises(ScanInterrupted, match="cancelled"),
        sealed_source_snapshot(tmp_path, inventory),
    ):
        pytest.fail("cancelled snapshot was yielded")
    assert destinations
    assert not destinations[0].parent.parent.exists()


def test_final_integrity_hash_can_finish_after_stop(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    expected = source_snapshot(tmp_path)
    control = ScanControl()
    control.cancel()
    with controlled_scan(control):
        with pytest.raises(ScanInterrupted):
            source_snapshot(tmp_path)
        assert source_snapshot(tmp_path, cancellable=False) == expected


@pytest.mark.parametrize("field", ["complete", "manifests", "coverage"])
def test_validation_diagnostics_exclude_values_and_instance_keys(
    tmp_path: Path, field: str
) -> None:
    canary = "REVIEW_CANARY_987654"
    artifact = dependency_surface_artifact(tmp_path, [])
    artifact[field] = {canary: canary}
    with pytest.raises(ValueError) as caught:
        validate_governed_artifacts({"dependency-surface.json": artifact})
    message = str(caught.value)
    assert canary not in message
    assert canary not in sanitize_terminal_text(message)
    assert "at schema /properties/" in message
    assert "failed type validation" in message
    assert len(message) < 1024


def test_validation_stops_after_first_error(tmp_path: Path) -> None:
    def errors(*args, **kwargs):
        yield ValidationError("private value", validator="type", schema_path=["type"])
        pytest.fail("enumerated additional validation failures")

    with patch(
        "py_security_suite.artifact_validation.Draft202012Validator.iter_errors", errors
    ):
        with pytest.raises(ValueError, match="failed type validation"):
            validate_governed_artifacts(
                {"dependency-surface.json": dependency_surface_artifact(tmp_path, [])}
            )


def test_progress_failure_after_publication_preserves_result(tmp_path: Path) -> None:
    target = tmp_path / "project"
    target.mkdir()
    completed = threading.Event()

    def broken_sink(event):
        if event.stage == "report" and event.state == "completed":
            completed.set()
            raise RuntimeError("private telemetry failure")

    with controlled_scan(ScanControl(progress=broken_sink)):
        result = scan_project(
            target=target,
            output=tmp_path / "report",
            config=load_config(profile_override="quick"),
            network_isolation_attested=False,
        )
    assert completed.is_set()
    assert result.manifest
    verify_report(tmp_path / "report")


def test_slow_progress_is_bounded_and_retains_latest_event() -> None:
    entered, release = threading.Event(), threading.Event()
    delivered = []

    def sink(event):
        entered.set()
        assert release.wait(5)
        delivered.append(event)

    dispatcher = ProgressDispatcher(sink)
    try:
        dispatcher.submit(0)
        assert entered.wait(2)
        for index in range(1, 10001):
            dispatcher.submit(index)
        release.set()
        dispatcher.finish()
        assert len(delivered) == 65
        assert delivered == [0, *range(9937, 10001)]
    finally:
        release.set()
        dispatcher.finish()


def test_blocked_progress_cannot_delay_shutdown() -> None:
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()

    def sink(event):
        entered.set()
        release.wait(5)
        finished.set()

    dispatcher = ProgressDispatcher(sink)
    try:
        dispatcher.submit(0)
        assert entered.wait(2)
        dispatcher.submit(1)
        start = time.monotonic()
        dispatcher.finish()
        assert time.monotonic() - start < 1.0
    finally:
        release.set()
        assert finished.wait(2)
        dispatcher.finish()
