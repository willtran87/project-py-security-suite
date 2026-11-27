import json

import pytest

from py_security_suite.adapters.bandit import BanditAdapter
from py_security_suite.adapters.base import AdapterResult
from py_security_suite.adapters.literal_sql import refine_literal_sql
from py_security_suite.adapters.staging import python_scan_tree
from py_security_suite.config import ToolConfig
from py_security_suite.execution import sha256_file
from py_security_suite.models import ToolRun, ToolStatus


@pytest.mark.parametrize(
    "source,excluded",
    [
        ('sql = f"SELECT name FROM users WHERE id = ?"\n', True),
        ('sql = f"SELECT name FROM users WHERE id = {user}"\n', False),
        ('sql = "SELECT name FROM users WHERE id = " + user\n', False),
        ('sql = f"SELECT name FROM users"; other = f"SELECT {user}"\n', False),
        ('cursor.execute(f"SELECT name FROM users")\n', False),
    ],
)
def test_only_intrinsic_literal_assignments_receive_a_proof(tmp_path, source, excluded):
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    payload = json.dumps(
        {
            "results": [
                {
                    "filename": str(path),
                    "line_number": 1,
                    "end_line_number": 1,
                    "test_id": "B608",
                    "issue_text": "Possible SQL injection",
                }
            ]
        }
    )
    findings = BanditAdapter(ToolConfig(), 4096).parse(payload, tmp_path)
    # Parsing an imported report retains the native finding.
    assert len(findings) == 1
    result = AdapterResult(
        findings, ToolRun("bandit", ToolStatus.COMPLETED, [], 0, finding_count=1), {}
    )
    refine_literal_sql(result, tmp_path, {"app.py": sha256_file(path)})
    assert len(result.findings) == int(not excluded)
    assert result.tool_run.finding_count == len(result.findings)
    if excluded:
        proof = result.diagnostic["literal_sql_refinement"]["exclusions"][0]
        assert proof["native_finding"]["sources"][0]["rule_id"] == "B608"
        assert proof["source_sha256"] == sha256_file(path)
        json.dumps(result.diagnostic)


def test_changed_source_cannot_remove_a_native_sql_finding(tmp_path):
    path = tmp_path / "app.py"
    path.write_text('sql = f"SELECT {user}"\n', encoding="utf-8")
    before = {"app.py": sha256_file(path)}
    findings = BanditAdapter(ToolConfig(), 4096).parse(
        json.dumps(
            {"results": [{"filename": str(path), "line_number": 1, "test_id": "B608"}]}
        ),
        tmp_path,
    )
    path.write_text('sql = f"SELECT fixed"\n', encoding="utf-8")
    result = AdapterResult(findings, ToolRun("bandit", ToolStatus.COMPLETED, [], 0), {})
    refine_literal_sql(result, tmp_path, before)
    assert len(result.findings) == 1


def test_python_inventory_includes_tests_and_ignores_scanner_exclusions(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "app.py").write_text("pass", encoding="utf-8")
    (tmp_path / ".semgrepignore").write_text("tests/\n", encoding="utf-8")
    (tmp_path / "tests" / ".gitignore").write_text("app.py\n", encoding="utf-8")
    with python_scan_tree(tmp_path) as mirror:
        assert (mirror / "tests" / "app.py").read_text() == "pass"
        assert (mirror / ".semgrepignore").read_text() == ""
        assert not (mirror / "tests" / ".gitignore").exists()
    assert not mirror.exists()
    assert (tmp_path / ".semgrepignore").read_text() == "tests/\n"


def test_python_mirror_canonicalizes_temporary_directory_alias(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from py_security_suite.adapters import staging

    source, destination, alias = (
        tmp_path / name for name in ("source", "real", "alias")
    )
    source.mkdir()
    destination.mkdir()
    (source / "app.py").write_bytes(b"pass\n")
    alias.mkdir()
    alias = alias / ".." / destination.name

    @contextmanager
    def temporary(**_):
        yield str(alias)

    monkeypatch.setattr(staging.tempfile, "TemporaryDirectory", temporary)
    with python_scan_tree(source) as mirror:
        assert mirror == destination.resolve()
        assert [
            path.relative_to(mirror).as_posix()
            for path in staging.maintained_files(mirror, frozenset({".py"}))
        ] == ["app.py"]
