from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

from py_security_suite.benchmark_semantic_evidence import semantic_similarity
from py_security_suite.strict_json import canonical_bytes


_CORPUS = Path(__file__).parent / "fixtures" / "semantic-calibration-1.1.json"
_CORPUS_DIGEST = _CORPUS.with_suffix(".sha256")


def _wilson_lower_bound(successes: int, total: int, z: float = 1.96) -> float:
    if total <= 0:
        return 0.0
    proportion = successes / total
    denominator = 1 + z**2 / total
    center = proportion + z**2 / (2 * total)
    margin = z * math.sqrt((proportion * (1 - proportion) + z**2 / (4 * total)) / total)
    return (center - margin) / denominator


def _mutation_variants(source: str, language: str, count: int) -> list[str]:
    comment = "#" if language == "python" else "//"
    return [
        f"{comment} governed calibration variant {index:02d}\n{source.rstrip()}\n"
        for index in range(count)
    ]


def test_versioned_multilingual_semantic_calibration_meets_quality_floor() -> None:
    value = json.loads(_CORPUS.read_text(encoding="utf-8"))
    threshold = float(value["threshold"])
    variants = int(value["mutation_variants_per_case"])
    predictions: dict[str, list[tuple[bool, bool]]] = {}
    languages: set[str] = set()
    for case in value["cases"]:
        language = case["language"]
        languages.add(language)
        pairs = zip(
            _mutation_variants(case["left"], language, variants),
            _mutation_variants(case["right"], language, variants),
            strict=True,
        )
        for left, right in pairs:
            similarity = semantic_similarity(
                left.encode(), right.encode(), language=language
            )
            predictions.setdefault(language, []).append(
                (case["expected_duplicate"], similarity >= threshold)
            )

    assert value["schema_version"] == "1.1"
    assert languages == {"python", "javascript", "typescript", "go", "java", "rust"}
    assert hashlib.sha256(canonical_bytes(value)).hexdigest() == (
        _CORPUS_DIGEST.read_text(encoding="ascii").strip()
    )
    for language, outcomes in predictions.items():
        true_positive = sum(expected and observed for expected, observed in outcomes)
        true_negative = sum(
            not expected and not observed for expected, observed in outcomes
        )
        false_positive = sum(
            not expected and observed for expected, observed in outcomes
        )
        false_negative = sum(
            expected and not observed for expected, observed in outcomes
        )
        positive_total = true_positive + false_negative
        negative_total = true_negative + false_positive
        assert positive_total >= value["minimum_observations_per_class_per_language"]
        assert negative_total >= value["minimum_observations_per_class_per_language"]
        precision = true_positive / (true_positive + false_positive)
        recall = true_positive / positive_total
        specificity = true_negative / negative_total
        assert precision >= value["minimum_precision"], language
        assert recall >= value["minimum_recall"], language
        assert (
            _wilson_lower_bound(true_positive, positive_total)
            >= value["minimum_wilson_lower_bound"]
        ), language
        assert (
            _wilson_lower_bound(true_negative, negative_total)
            >= value["minimum_wilson_lower_bound"]
        ), language
        assert specificity >= value["minimum_precision"], language
