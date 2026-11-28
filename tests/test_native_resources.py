import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.native_resources import native_resources, scratch_bytes


def test_native_resource_sample_records_scratch_and_restores_after_failure():
    previous = tempfile.tempdir
    with patch(
        "scripts.native_resources.process_tree_resident_bytes", return_value=4096
    ):
        with pytest.raises(RuntimeError), native_resources() as report:
            root = Path(tempfile.gettempdir())
            assert str(root) != previous
            (root / "native-output").write_bytes(b"x" * 1234)
            deadline = time.monotonic() + 3
            while report["peak_scratch_bytes"] < 1234 and time.monotonic() < deadline:
                time.sleep(0.02)
            raise RuntimeError("fixture invocation failed")
    assert tempfile.tempdir == previous
    assert not root.exists()
    assert report["measurement_complete"]
    assert report["peak_scratch_bytes"] == 1234
    assert report["peak_rss_bytes"] == 4096


def test_resource_measurement_failure_is_explicit():
    with patch(
        "scripts.native_resources.process_tree_resident_bytes", side_effect=OSError
    ):
        with native_resources() as report:
            pass
    assert not report["measurement_complete"]
    assert report["error_category"] == "OSError"


def test_scratch_measurement_counts_files_once(tmp_path):
    (tmp_path / "nested").mkdir()
    (tmp_path / "a").write_bytes(b"abc")
    (tmp_path / "nested/b").write_bytes(b"de")
    assert scratch_bytes(tmp_path) == 5
