from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from py_security_suite.benchmark_semantic_evidence import (
    BenchmarkSemanticEvidenceError,
    CANONICALIZATION,
    SIMILARITY_ALGORITHM,
    canonicalizer_identity,
    semantic_fingerprint,
    verify_semantic_records,
)
from py_security_suite.benchmark_statistical_evidence import (
    BenchmarkStatisticalEvidenceError,
    _exact_binomial_power,
    compute_protocol_power,
    compute_standardized_mean_power,
    verify_leakage_analysis,
    verify_power_analysis,
)


def _record(workspace: Path, name: str, payload: bytes) -> dict[str, str]:
    path = workspace / name
    path.write_bytes(payload)
    return {
        "path": name,
        "language": "python",
        "subject_sha256": hashlib.sha256(payload).hexdigest(),
        "semantic_sha256": semantic_fingerprint(payload, language="python"),
    }


def test_semantic_records_are_rederived_from_held_artifacts(tmp_path: Path) -> None:
    record = _record(tmp_path, "case.py", b"answer = transform(value)\n")
    identity = canonicalizer_identity({"python"})["identity_sha256"]

    subjects, semantics = verify_semantic_records(
        [record],
        workspace=tmp_path,
        expected_canonicalizer_sha256=identity,
        label="case",
    )

    assert subjects == [record["subject_sha256"]]
    assert semantics == [record["semantic_sha256"]]


def test_semantic_records_reject_post_claim_artifact_tampering(tmp_path: Path) -> None:
    record = _record(tmp_path, "case.py", b"answer = transform(value)\n")
    (tmp_path / "case.py").write_bytes(b"answer = dangerous(value)\n")

    with pytest.raises(BenchmarkSemanticEvidenceError, match="does not reproduce"):
        verify_semantic_records(
            [record],
            workspace=tmp_path,
            expected_canonicalizer_sha256=canonicalizer_identity({"python"})[
                "identity_sha256"
            ],
            label="case",
        )


def test_semantic_fingerprint_is_identifier_insensitive_but_control_sensitive() -> None:
    left = semantic_fingerprint(
        b"def allow(value):\n    if value > 0:\n        return value + 1\n    return 0\n",
        language="python",
    )
    renamed = semantic_fingerprint(
        b"def permit(item):\n    if item > 0:\n        return item + 1\n    return 0\n",
        language="python",
    )
    weakened = semantic_fingerprint(
        b"def permit(item):\n    return item + 1\n",
        language="python",
    )

    assert left == renamed
    assert left != weakened


def test_semantic_fingerprint_normalizes_invalid_python_encoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malformed = b"B\ri\r\xc7\xb3x\rixs\rrxs\ri\r"
    try:
        semantic_fingerprint(malformed, language="python")
    except BenchmarkSemanticEvidenceError:
        pass

    def invalid_tokens(_readline: object) -> object:
        raise UnicodeDecodeError("utf-8", b"\xc7", 0, 1, "invalid start byte")

    monkeypatch.setattr(
        "py_security_suite.benchmark_semantic_evidence.tokenize.tokenize",
        invalid_tokens,
    )

    with pytest.raises(BenchmarkSemanticEvidenceError, match="cannot be tokenized"):
        semantic_fingerprint(b"value = 1\n", language="python")


@pytest.mark.parametrize(
    ("language", "suffix", "payload"),
    [
        (
            "javascript",
            "js",
            b"function allow(v) { if (v > 0) return v + 1; return 0; }",
        ),
        (
            "typescript",
            "ts",
            b"function allow(v: number): number { return v > 0 ? v : 0; }",
        ),
        (
            "go",
            "go",
            b"package p\nfunc allow(v int) int { if v > 0 { return v }; return 0 }\n",
        ),
        (
            "java",
            "java",
            b"class A { int allow(int v) { if (v > 0) return v; return 0; } }",
        ),
        ("rust", "rs", b"fn allow(v: i32) -> i32 { if v > 0 { v } else { 0 } }"),
    ],
)
def test_tree_sitter_languages_reproduce_multisignal_records(
    tmp_path: Path, language: str, suffix: str, payload: bytes
) -> None:
    path = tmp_path / f"case.{suffix}"
    path.write_bytes(payload)
    record = {
        "path": path.name,
        "language": language,
        "subject_sha256": hashlib.sha256(payload).hexdigest(),
        "semantic_sha256": semantic_fingerprint(payload, language=language),
    }

    subjects, semantics = verify_semantic_records(
        [record],
        workspace=tmp_path,
        expected_canonicalizer_sha256=canonicalizer_identity({language})[
            "identity_sha256"
        ],
        label="polyglot-case",
    )

    assert subjects == [record["subject_sha256"]]
    assert semantics == [record["semantic_sha256"]]


def test_derived_leakage_detects_same_shape_with_different_names(
    tmp_path: Path,
) -> None:
    training = _record(tmp_path, "training.py", b"answer = transform(value)\n")
    holdout = _record(tmp_path, "holdout.py", b"result = convert(source)\n")
    value = {
        "schema_version": "1.2",
        "algorithm": "parser-derived-sha256-set-intersection",
        "canonicalization": CANONICALIZATION,
        "canonicalizer_sha256": canonicalizer_identity({"python"})["identity_sha256"],
        "training_records": [training],
        "holdout_records": [holdout],
        "overlap_count": 0,
        "semantic_overlap_count": 0,
        "similarity_algorithm": SIMILARITY_ALGORITHM,
        "similarity_threshold": 0.8,
        "near_duplicate_count": 0,
    }

    with pytest.raises(BenchmarkStatisticalEvidenceError, match="semantic"):
        verify_leakage_analysis(
            value,
            require_semantic=True,
            require_derived_semantic=True,
            workspace=tmp_path,
        )


def test_derived_leakage_detects_high_similarity_near_duplicates(
    tmp_path: Path,
) -> None:
    training = _record(
        tmp_path,
        "training.py",
        b"def transform(value):\n    result = value + 1\n    return result\n",
    )
    holdout = _record(
        tmp_path,
        "holdout.py",
        b"def convert(source):\n    result = source - 1\n    return result\n",
    )
    value = {
        "schema_version": "1.2",
        "algorithm": "parser-derived-sha256-set-intersection",
        "canonicalization": CANONICALIZATION,
        "canonicalizer_sha256": canonicalizer_identity({"python"})["identity_sha256"],
        "training_records": [training],
        "holdout_records": [holdout],
        "overlap_count": 0,
        "semantic_overlap_count": 0,
        "similarity_algorithm": SIMILARITY_ALGORITHM,
        "similarity_threshold": 0.8,
        "near_duplicate_count": 0,
    }

    with pytest.raises(BenchmarkStatisticalEvidenceError, match="near-duplicate"):
        verify_leakage_analysis(
            value,
            require_semantic=True,
            require_derived_semantic=True,
            workspace=tmp_path,
        )


def test_exact_binomial_power_counts_both_rejection_tails_and_is_bounded() -> None:
    upward = _exact_binomial_power(
        alpha=0.05, null_rate=0.5, alternative_rate=0.7, sample_size=40
    )
    downward = _exact_binomial_power(
        alpha=0.05, null_rate=0.5, alternative_rate=0.3, sample_size=40
    )

    assert upward == pytest.approx(downward)
    assert upward == pytest.approx(0.703250169634515, abs=1e-14)
    with pytest.raises(BenchmarkStatisticalEvidenceError, match="computational bound"):
        _exact_binomial_power(
            alpha=0.05,
            null_rate=0.5,
            alternative_rate=0.7,
            sample_size=10_001,
        )


def test_exact_binomial_power_is_monotone_for_reference_effect_grid() -> None:
    powers = [
        _exact_binomial_power(
            alpha=0.05,
            null_rate=0.5,
            alternative_rate=alternative,
            sample_size=80,
        )
        for alternative in (0.55, 0.6, 0.65, 0.7, 0.75)
    ]

    assert powers == sorted(powers)
    assert all(0 <= value <= 1 for value in powers)


def test_standardized_mean_protocol_replays_its_distinct_analysis_plan(
    tmp_path: Path,
) -> None:
    achieved = compute_standardized_mean_power(
        alpha=0.025, standardized_effect=0.8, sample_size=30
    )
    sensitivity = compute_standardized_mean_power(
        alpha=0.025, standardized_effect=0.64, sample_size=30
    )
    plan = {
        "schema_version": "1.0",
        "protocol": "fuzzing-statistical",
        "method": "normal-standardized-effect-bonferroni",
        "alpha": 0.05,
        "hypothesis_count": 2,
        "adjusted_alpha": 0.025,
        "design_effect": 1.0,
        "sample_size": 30,
        "standardized_effect": 0.8,
        "effect_source_sha256": "7" * 64,
    }
    payload = json.dumps(plan, sort_keys=True).encode()
    (tmp_path / "mean-plan.json").write_bytes(payload)
    evidence = {
        **plan,
        "schema_version": "1.2",
        "achieved_power": achieved,
        "sensitivity_power": sensitivity,
        "analysis_plan_path": "mean-plan.json",
        "analysis_plan_sha256": hashlib.sha256(payload).hexdigest(),
    }

    assert verify_power_analysis(
        evidence,
        minimum_power=0.8,
        minimum_cases=20,
        protocol="fuzzing-statistical",
        require_protocol_specific=True,
        workspace=tmp_path,
    ) == pytest.approx(achieved)


def test_protocol_power_requires_selected_method_and_plan(tmp_path: Path) -> None:
    achieved = compute_protocol_power(
        protocol="classification",
        alpha=0.0125,
        null_rate=0.1,
        alternative_rate=0.9,
        sample_size=20,
    )
    sensitivity = compute_protocol_power(
        protocol="classification",
        alpha=0.0125,
        null_rate=0.1,
        alternative_rate=0.74,
        sample_size=20,
    )
    plan = {
        "schema_version": "1.0",
        "protocol": "classification",
        "method": "exact-binomial-equal-tail-two-sided-bonferroni",
        "alpha": 0.05,
        "hypothesis_count": 4,
        "adjusted_alpha": 0.0125,
        "design_effect": 1.0,
        "sample_size": 20,
        "null_rate": 0.1,
        "alternative_rate": 0.9,
        "effect_source_sha256": "7" * 64,
    }
    plan_payload = json.dumps(plan, sort_keys=True).encode()
    (tmp_path / "analysis-plan.json").write_bytes(plan_payload)
    value = {
        "schema_version": "1.2",
        "method": "exact-binomial-equal-tail-two-sided-bonferroni",
        "protocol": "classification",
        "alpha": 0.05,
        "null_rate": 0.1,
        "alternative_rate": 0.9,
        "sample_size": 20,
        "achieved_power": achieved,
        "sensitivity_power": sensitivity,
        "hypothesis_count": 4,
        "adjusted_alpha": 0.0125,
        "design_effect": 1.0,
        "analysis_plan_path": "analysis-plan.json",
        "analysis_plan_sha256": hashlib.sha256(plan_payload).hexdigest(),
        "effect_source_sha256": "7" * 64,
    }

    assert verify_power_analysis(
        value,
        minimum_power=0.8,
        minimum_cases=20,
        protocol="classification",
        require_protocol_specific=True,
        workspace=tmp_path,
    ) == pytest.approx(achieved)

    value["method"] = "normal-standardized-effect-bonferroni"
    with pytest.raises(BenchmarkStatisticalEvidenceError, match="contract"):
        verify_power_analysis(
            value,
            minimum_power=0.8,
            minimum_cases=20,
            protocol="classification",
            require_protocol_specific=True,
            workspace=tmp_path,
        )
