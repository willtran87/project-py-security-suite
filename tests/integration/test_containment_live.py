from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from py_security_suite.evidence_ingest import _advance_replay_receipt_state
from py_security_suite.execution import CommandEnvironment, run_command
from py_security_suite.strict_json import loads as strict_loads


pytestmark = pytest.mark.integration


def test_real_process_tree_is_killed_after_scanner_leader_exits(tmp_path: Path) -> None:
    marker = tmp_path / "descendant-survived"
    descendant = (
        "import pathlib,sys,time; time.sleep(2); "
        "pathlib.Path(sys.argv[1]).write_text('survived', encoding='utf-8')"
    )
    scanner = (
        "import subprocess,sys; "
        "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]]); "
        "print('leader-exited')"
    )
    result = run_command(
        [sys.executable, "-c", scanner, descendant, str(marker)],
        cwd=tmp_path,
        timeout_seconds=10,
        max_output_bytes=4096,
    )
    time.sleep(2.5)
    assert result.exit_code == 0
    assert not marker.exists()


def test_real_private_scratch_quota_terminates_writer(tmp_path: Path) -> None:
    scanner = (
        "import pathlib,tempfile,time; "
        "p=pathlib.Path(tempfile.gettempdir())/'fill'; "
        "p.write_bytes(b'x'*(2*1024*1024)); time.sleep(5)"
    )
    result = run_command(
        [sys.executable, "-c", scanner],
        cwd=tmp_path,
        timeout_seconds=10,
        max_output_bytes=4096,
        environment=CommandEnvironment(max_scratch_bytes=1024 * 1024),
    )
    assert result.scratch_limit_exceeded
    assert result.process_tree_terminated


def test_replay_checkpoint_rejects_gap_without_mutating_state(tmp_path: Path) -> None:
    state = tmp_path / "replay-state.json"
    first = {
        "sequence": 1,
        "receipt_sha256": "a" * 64,
        "previous_receipt_sha256": "",
        "key_id": "b" * 64,
    }
    _advance_replay_receipt_state(state, first)
    before = state.read_bytes()
    with pytest.raises(ValueError, match="monotonic"):
        _advance_replay_receipt_state(
            state,
            {
                "sequence": 3,
                "receipt_sha256": "c" * 64,
                "previous_receipt_sha256": "a" * 64,
                "key_id": "b" * 64,
            },
        )
    assert state.read_bytes() == before
    assert strict_loads(before)["sequence"] == 1
