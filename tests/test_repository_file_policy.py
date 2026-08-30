from __future__ import annotations

from pathlib import Path

from py_security_suite.repository_file_policy import maintained_repository_files


def test_maintained_repository_files_prunes_generated_and_linked_content(
    tmp_path: Path,
) -> None:
    maintained = tmp_path / "src" / "module.py"
    maintained.parent.mkdir()
    maintained.write_text("value = 1\n", encoding="utf-8")
    generated = tmp_path / ".artifacts" / "result.json"
    generated.parent.mkdir()
    generated.write_text("{}\n", encoding="utf-8")
    linked = tmp_path / "linked.py"
    try:
        linked.symlink_to(maintained)
    except OSError:
        linked = None

    observed = maintained_repository_files(tmp_path)

    assert observed == [maintained]
    assert generated not in observed
    if linked is not None:
        assert linked not in observed
