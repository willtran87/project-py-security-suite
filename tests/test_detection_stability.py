import json
from copy import deepcopy

import pytest

from scripts.detection_stability import repeated_semgrep


def document():
    return {
        "version": "test",
        "errors": [],
        "paths": {"scanned": ["app.py"]},
        "results": [
            {
                "check_id": "python.test",
                "path": "app.py",
                "start": {"line": 1},
                "extra": {"message": "test", "metadata": {"cwe": ["CWE-22"]}},
            }
        ],
    }


def measure(tmp_path, documents):
    (tmp_path / "app.py").write_text("pass\n")
    values = iter(documents)
    return repeated_semgrep(lambda: next(values), tmp_path, len(documents))


def test_identical_runs_are_stable(tmp_path):
    first, report = measure(tmp_path, [document(), document(), document()])
    assert first == document()
    assert report["passed"] and report["stable_findings"]
    assert len(report["attempts"]) == 3
    assert "app.py" not in json.dumps(report)


@pytest.mark.parametrize("failure", ["timeout", "missing-file", "malformed"])
def test_later_success_cannot_hide_an_incomplete_first_attempt(tmp_path, failure):
    broken = document()
    if failure == "timeout":
        broken["time"] = {"fixpoint_timeouts": [{"message": "PRIVATE_NATIVE_DETAIL"}]}
    elif failure == "missing-file":
        broken["paths"]["scanned"] = []
    else:
        broken["time"] = None
    _, report = measure(tmp_path, [broken, document(), document()])
    assert not report["passed"]
    assert len(report["attempts"]) == 3
    assert not report["attempts"][0]["complete"]
    assert report["attempts"][2]["complete"]
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize(
    "change", ["version", "line", "classification", "dropped", "duplicate"]
)
def test_semantic_or_detection_drift_fails_stability(tmp_path, change):
    changed = deepcopy(document())
    if change == "version":
        changed["version"] = "other"
    elif change == "line":
        changed["results"][0]["start"]["line"] = 2
    elif change == "classification":
        changed["results"][0]["extra"]["metadata"]["cwe"] = ["CWE-89"]
    elif change == "dropped":
        changed["results"] = []
    else:
        changed["results"] *= 2
    _, report = measure(tmp_path, [document(), changed, document()])
    assert not report["passed"] and not report["stable_findings"]


def test_execution_failures_are_retained_without_native_contents(tmp_path):
    (tmp_path / "app.py").write_text("pass\n")
    calls = 0

    def execute():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ValueError("PRIVATE_NATIVE_DETAIL")
        return document()

    first, report = repeated_semgrep(execute, tmp_path, 3)
    assert first == {}
    assert calls == 3
    assert not report["passed"]
    assert report["attempts"][0]["error_category"] == "ValueError"
    assert "PRIVATE" not in json.dumps(report)


@pytest.mark.parametrize("count", [0, 6, True, None])
def test_repetition_count_is_bounded(tmp_path, count):
    with pytest.raises(ValueError):
        repeated_semgrep(document, tmp_path, count)


@pytest.mark.parametrize("mutation", ["contents", "added", "deleted"])
def test_identical_native_findings_cannot_hide_source_mutation(tmp_path, mutation):
    source = tmp_path / "app.py"
    source.write_text("pass\n")
    calls = 0

    def execute():
        nonlocal calls
        calls += 1
        if calls == 1:
            if mutation == "contents":
                source.write_text("changed = True\n")
            elif mutation == "added":
                (tmp_path / "added.py").write_text("pass\n")
            else:
                source.unlink()
        return document()

    _, report = repeated_semgrep(execute, tmp_path, 3)
    assert not report["passed"]
    assert len(report["attempts"]) == 3
    assert not any(attempt["complete"] for attempt in report["attempts"])
    assert "changed = True" not in json.dumps(report)


def test_changed_then_restored_source_keeps_the_failed_attempt(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("pass\n")
    calls = 0

    def execute():
        nonlocal calls
        calls += 1
        source.write_text("changed = True\n" if calls == 1 else "pass\n")
        return document()

    _, report = repeated_semgrep(execute, tmp_path, 3)
    assert not report["passed"]
    assert not report["attempts"][0]["complete"]
    assert report["attempts"][2]["complete"]


def test_oversized_source_fails_before_native_execution(tmp_path):
    (tmp_path / "app.py").write_bytes(b"x" * (1024**2 + 1))

    def execute():
        pytest.fail("oversized source must not execute")

    _, report = repeated_semgrep(execute, tmp_path, 2)
    assert not report["passed"]
    assert len(report["attempts"]) == 2
