from copy import deepcopy

import pytest

from scripts.benchmark_external import regressions


def fixture():
    baseline = {
        "source_sha256": "source",
        "labels_sha256": "labels",
        "engines": {"semgrep": {"CWE-328": {"fp": 0, "fn": 1}}},
        "protected_detections": {"semgrep": {"CWE-328": ["old"]}},
    }
    result = {
        "upstream": {"source_sha256": "source", "labels_sha256": "labels"},
        "engines": {"semgrep": {"by_cwe": {"CWE-328": {"fp": 0, "fn": 1}}}},
        "cases": [
            {
                "case": "old",
                "expected_cwe": "CWE-328",
                "expected_positive": True,
                "evidence": [{"engine": "semgrep", "cwes": ["CWE-328"]}],
            },
            {
                "case": "new",
                "expected_cwe": "CWE-328",
                "expected_positive": True,
                "evidence": [],
            },
        ],
    }
    return result, baseline


def test_equal_aggregate_counts_cannot_hide_lost_detection():
    result, baseline = fixture()
    assert regressions(result, baseline) == []
    result["cases"][1]["evidence"] = result["cases"][0]["evidence"]
    result["cases"][0]["evidence"] = []
    assert regressions(result, baseline) == ["semgrep:CWE-328:lost-detection:old"]


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "duplicate",
        "relabeled",
        "no-evidence",
        "invalid-engine",
        "invalid-category",
        "duplicate-protection",
    ],
)
def test_invalid_protection_cannot_pass(change):
    result, baseline = fixture()
    if change == "missing":
        result["cases"].pop(0)
    elif change == "duplicate":
        result["cases"].append(deepcopy(result["cases"][0]))
    elif change == "relabeled":
        result["cases"][0]["expected_positive"] = False
    elif change == "no-evidence":
        del result["cases"]
    elif change == "invalid-engine":
        baseline["protected_detections"]["other"] = {}
    elif change == "invalid-category":
        baseline["protected_detections"]["semgrep"]["CWE-89"] = ["old"]
    else:
        baseline["protected_detections"]["semgrep"]["CWE-328"].append("old")
    with pytest.raises(ValueError):
        regressions(result, baseline)


def test_old_baseline_remains_compatible():
    result, baseline = fixture()
    del baseline["protected_detections"]
    del result["cases"]
    assert regressions(result, baseline) == []


def test_wrong_engine_or_classification_does_not_preserve_detection():
    result, baseline = fixture()
    result["cases"][0]["evidence"] = [
        {"engine": "bandit", "cwes": ["CWE-328"]},
        {"engine": "semgrep", "cwes": ["CWE-327"]},
    ]
    assert regressions(result, baseline) == ["semgrep:CWE-328:lost-detection:old"]
