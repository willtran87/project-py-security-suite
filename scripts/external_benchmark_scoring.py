"""Auditable case attribution and fail-closed project accuracy targets."""

from __future__ import annotations

import math


def protected_detection_regressions(result: dict, baseline: dict) -> list[str]:
    """Do not let new true positives conceal the loss of previously detected cases."""
    protected = baseline.get("protected_detections", {})
    if not isinstance(protected, dict) or not set(protected) <= set(result["engines"]):
        raise ValueError("protected detections name invalid engines")
    if not protected:
        return []
    cases = result.get("cases")
    if not isinstance(cases, list):
        raise ValueError("protected detections require case evidence")
    indexed = {row["case"]: row for row in cases}
    if len(indexed) != len(cases):
        raise ValueError("duplicate benchmark case evidence")
    failures = []
    for engine, categories in protected.items():
        if not isinstance(categories, dict) or not set(categories) <= set(
            baseline["engines"][engine]
        ):
            raise ValueError("protected detections name invalid categories")
        for cwe, names in categories.items():
            if (
                not isinstance(names, list)
                or any(not isinstance(name, str) for name in names)
                or len(names) != len(set(names))
            ):
                raise ValueError("protected detections require distinct case names")
            for name in names:
                case = indexed.get(name)
                if (
                    case is None
                    or case["expected_cwe"] != cwe
                    or case["expected_positive"] is not True
                ):
                    raise ValueError(
                        "protected detection is missing or has changed labels"
                    )
                if not any(
                    item["engine"] == engine and cwe in item["cwes"]
                    for item in case["evidence"]
                ):
                    failures.append(f"{engine}:{cwe}:lost-detection:{name}")
    return failures


def case_outcomes(
    expected: list[dict], observations: dict[str, list[dict]]
) -> list[dict]:
    """Keep only reviewed case IDs and structured detector evidence, never source text."""
    outcomes = []
    for row in sorted(expected, key=lambda item: item["id"]):
        evidence = sorted(
            observations.get(row["id"], []),
            key=lambda item: (
                item["engine"],
                item["rule"],
                item["path"],
                item["line"] or 0,
            ),
        )
        reported = sorted({cwe for item in evidence for cwe in item["cwes"]})
        detected = row["cwe"] in reported
        outcomes.append(
            {
                "case": row["id"],
                "expected_cwe": row["cwe"],
                "expected_positive": row["positive"],
                "detected": detected,
                "outcome": ("tp" if detected else "fn")
                if row["positive"]
                else ("fp" if detected else "tn"),
                "reported_cwes": reported,
                "classification_review_needed": bool(reported) and not detected,
                "evidence": evidence,
            }
        )
    return outcomes


def accuracy_gate(result: dict, policy: dict) -> dict:
    """These are project targets, not certification or a production approval."""
    if policy.get("schema_version") != "1.0":
        raise ValueError("unsupported accuracy policy schema")
    required = policy.get("required_engines")
    if (
        not isinstance(required, list)
        or not required
        or any(not isinstance(name, str) or not name for name in required)
        or len(set(required)) != len(required)
    ):
        raise ValueError("accuracy policy requires distinct engine names")
    categories = policy.get("by_cwe")
    if not isinstance(categories, dict) or set(categories) != set(
        result["combined_by_cwe"]
    ):
        raise ValueError("accuracy policy must cover every measured CWE")
    failures = []
    if not result["measurement_complete"]:
        failures.append("measurement-incomplete")
    if set(required) != set(result["engines"]):
        failures.append("engine-set-mismatch")
    for cwe, targets in sorted(categories.items()):
        if not isinstance(targets, dict) or set(targets) != {
            "minimum_precision",
            "minimum_recall",
            "maximum_false_positive_rate",
            "minimum_positive_cases",
            "minimum_negative_cases",
        }:
            raise ValueError("accuracy targets must specify rates and sample minimums")
        for name in (
            "minimum_precision",
            "minimum_recall",
            "maximum_false_positive_rate",
        ):
            value = targets[name]
            if (
                type(value) not in (int, float)
                or not math.isfinite(value)
                or not 0 <= value <= 1
            ):
                raise ValueError(
                    "accuracy rates must be finite numbers between zero and one"
                )
        for name in ("minimum_positive_cases", "minimum_negative_cases"):
            if type(targets[name]) is not int or targets[name] < 1:
                raise ValueError("accuracy sample minimums must be positive integers")
        measured = result["combined_by_cwe"][cwe]
        for name, total in (
            ("positive", measured["tp"] + measured["fn"]),
            ("negative", measured["fp"] + measured["tn"]),
        ):
            if total < targets[f"minimum_{name}_cases"]:
                failures.append(f"{cwe}:insufficient-{name}-cases")
        for metric in ("precision", "recall", "false_positive_rate"):
            value = measured[metric]
            target = targets[
                ("maximum_" if metric == "false_positive_rate" else "minimum_") + metric
            ]
            if (
                value is None
                or not math.isfinite(value)
                or (
                    value > target
                    if metric == "false_positive_rate"
                    else value < target
                )
            ):
                failures.append(f"{cwe}:{metric}")
    return {
        "passed": not failures,
        "failures": failures,
        "scope": "project accuracy targets on this public corpus; not production approval",
        "policy": policy,
    }
