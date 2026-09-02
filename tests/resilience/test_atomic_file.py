from __future__ import annotations

from pathlib import Path
from contextlib import nullcontext
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from py_security_suite.atomic_file import atomic_write_bytes
from py_security_suite.path_safety import HeldParentDirectory


pytestmark = pytest.mark.resilience


def test_atomic_write_preserves_previous_value_when_replace_fails(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "state.json"
    destination.write_bytes(b"previous\n")

    with (
        patch(
            "py_security_suite.path_safety.HeldParentDirectory.replace",
            side_effect=OSError("simulated disk failure"),
        ),
        pytest.raises(OSError, match="simulated disk failure"),
    ):
        atomic_write_bytes(destination, b"new\n", label="test state")

    assert destination.read_bytes() == b"previous\n"
    assert list(tmp_path.glob(".state.json.*.tmp")) == []


def test_atomic_write_rejects_link_destination(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"protected")
    link = tmp_path / "state"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable")

    with pytest.raises(ValueError, match="symbolic link"):
        atomic_write_bytes(link, b"new", label="test state")
    assert target.read_bytes() == b"protected"


def test_atomic_write_syncs_file_and_parent_on_posix(tmp_path: Path) -> None:
    destination = tmp_path / "state"
    held = MagicMock(descriptor=41)
    held.replace.side_effect = lambda source, target: source.replace(target)
    with (
        patch("py_security_suite.atomic_file._POSIX_DURABILITY", True),
        patch(
            "py_security_suite.atomic_file.hold_parent_directory",
            return_value=nullcontext(held),
        ),
        patch("py_security_suite.atomic_file.os.chmod") as chmod,
        patch("py_security_suite.atomic_file.os.fsync") as sync,
    ):
        atomic_write_bytes(destination, b"durable", label="test state")

    assert destination.read_bytes() == b"durable"
    chmod.assert_called_once()
    sync.assert_called_once()
    held.replace.assert_called_once()


def test_atomic_write_portable_mode_skips_posix_chmod(tmp_path: Path) -> None:
    destination = tmp_path / "portable-state"
    with (
        patch("py_security_suite.atomic_file._POSIX_DURABILITY", False),
        patch("py_security_suite.atomic_file.os.chmod") as chmod,
    ):
        atomic_write_bytes(destination, b"portable", label="portable state")

    assert destination.read_bytes() == b"portable"
    chmod.assert_not_called()


def test_held_parent_syncs_directory_metadata_on_posix(tmp_path: Path) -> None:
    held = HeldParentDirectory(tmp_path, 41)
    with (
        patch("py_security_suite.path_safety.os.name", "posix"),
        patch("py_security_suite.path_safety.os.fsync") as sync,
    ):
        held.sync()
    sync.assert_called_once_with(41)
