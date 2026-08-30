from __future__ import annotations

from typing import Any


def _score_normalized_result(
    value: object, *, benchmark_id: str, protocol: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "benchmark_id",
        "protocol",
        "cases",
    }:
        raise ValueError("expected schema_version, benchmark_id, protocol, and cases")
    if (
        value["schema_version"] != "1.0"
        or value["benchmark_id"] != benchmark_id
        or value["protocol"] != protocol
    ):
        raise ValueError("normalized result identity does not match the manifest")
    cases = value["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= 1_000_000:
        raise ValueError("cases must be a non-empty bounded array")
    if protocol in {"classification", "detection-evaluation"}:
        return _score_classification(cases)
    if protocol in {"verification-competition", "test-generation"}:
        return _score_outcome_accuracy(cases)
    if protocol == "conformance":
        return _score_conformance(cases)
    if protocol == "temporal-calibration":
        return _score_temporal_calibration(cases)
    if protocol == "stochastic-adversarial":
        return _score_stochastic(cases)
    if protocol == "assessor-agreement":
        return _score_assessor_agreement(cases)
    if protocol == "biometric-performance":
        return _score_biometric_performance(cases)
    if protocol == "proficiency-testing":
        return _score_proficiency_testing(cases)
    if protocol == "fuzzing-statistical":
        return _score_fuzzing(cases)
    raise ValueError("normalized result protocol is unsupported")


def _validate_case_identity(case: object, seen: set[str]) -> dict[str, Any]:
    if not isinstance(case, dict):
        raise ValueError("case must be an object")
    case_id = case.get("id")
    if not isinstance(case_id, str) or not 1 <= len(case_id) <= 512 or case_id in seen:
        raise ValueError("case identifiers must be unique bounded strings")
    seen.add(case_id)
    return case


def _validate_strata(value: object) -> None:
    if (
        not isinstance(value, dict)
        or len(value) > 32
        or any(
            not isinstance(key, str)
            or not isinstance(item, str)
            or len(key) > 128
            or len(item) > 512
            for key, item in value.items()
        )
    ):
        raise ValueError("case strata are invalid")


def _score_classification(cases: list[Any]) -> dict[str, Any]:
    seen: set[str] = set()
    tp = fp = tn = fn = 0
    for case in cases:
        case = _validate_case_identity(case, seen)
        if set(case) != {
            "id",
            "expected_positive",
            "observed_positive",
            "strata",
        }:
            raise ValueError("case does not match the normalized case contract")
        expected = case["expected_positive"]
        observed = case["observed_positive"]
        if not isinstance(expected, bool) or not isinstance(observed, bool):
            raise ValueError("case labels must be boolean")
        _validate_strata(case["strata"])
        if expected and observed:
            tp += 1
        elif not expected and observed:
            fp += 1
        elif not expected and not observed:
            tn += 1
        else:
            fn += 1
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    specificity = _ratio(tn, tn + fp)
    f1 = _ratio(2 * precision * recall, precision + recall)
    precision_lower = _wilson_lower(tp, tp + fp)
    precision_upper = _wilson_upper(tp, tp + fp)
    recall_lower = _wilson_lower(tp, tp + fn)
    recall_upper = _wilson_upper(tp, tp + fn)
    fpr = _ratio(fp, fp + tn)
    fpr_lower = _wilson_lower(fp, fp + tn)
    fpr_upper = _wilson_upper(fp, fp + tn)
    return {
        "case_count": len(cases),
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "false_positive_rate": fpr,
        "balanced_accuracy": (recall + specificity) / 2,
        "precision_wilson_lower_95": precision_lower,
        "precision_wilson_upper_95": precision_upper,
        "precision_interval_width_95": precision_upper - precision_lower,
        "recall_wilson_lower_95": recall_lower,
        "recall_wilson_upper_95": recall_upper,
        "recall_interval_width_95": recall_upper - recall_lower,
        "false_positive_rate_wilson_lower_95": fpr_lower,
        "false_positive_rate_wilson_upper_95": fpr_upper,
        "false_positive_rate_interval_width_95": fpr_upper - fpr_lower,
        "f1_conservative_95": _ratio(
            2 * precision_lower * recall_lower, precision_lower + recall_lower
        ),
    }


def _score_outcome_accuracy(cases: list[Any]) -> dict[str, Any]:
    seen: set[str] = set()
    correct = 0
    for raw in cases:
        case = _validate_case_identity(raw, seen)
        if set(case) != {"id", "expected", "observed", "strata"}:
            raise ValueError("outcome case contract is invalid")
        _validate_strata(case["strata"])
        if not isinstance(case["expected"], str) or not isinstance(
            case["observed"], str
        ):
            raise ValueError("outcome labels must be strings")
        correct += case["expected"] == case["observed"]
    lower = _wilson_lower(correct, len(cases))
    upper = _wilson_upper(correct, len(cases))
    return {
        "case_count": len(cases),
        "correct": correct,
        "incorrect": len(cases) - correct,
        "unknown": sum(
            isinstance(item, dict) and item.get("observed") == "unknown"
            for item in cases
        ),
        "accuracy": _ratio(correct, len(cases)),
        "accuracy_wilson_lower_95": lower,
        "accuracy_wilson_upper_95": upper,
        "accuracy_interval_width_95": upper - lower,
    }


def _score_conformance(cases: list[Any]) -> dict[str, Any]:
    seen: set[str] = set()
    outcomes = {"pass", "fail", "not-applicable"}
    correct = passed = applicable = negative = failed = 0
    for raw in cases:
        case = _validate_case_identity(raw, seen)
        if set(case) != {"id", "expected_outcome", "observed_outcome", "strata"}:
            raise ValueError("conformance case contract is invalid")
        _validate_strata(case["strata"])
        if (
            case["expected_outcome"] not in outcomes
            or case["observed_outcome"] not in outcomes
        ):
            raise ValueError("conformance outcome is invalid")
        correct += case["expected_outcome"] == case["observed_outcome"]
        if case["expected_outcome"] != "not-applicable":
            applicable += 1
            passed += case["observed_outcome"] == "pass"
            failed += case["observed_outcome"] == "fail"
        negative += case["expected_outcome"] == "fail"
    outcome_lower = _wilson_lower(correct, len(cases))
    outcome_upper = _wilson_upper(correct, len(cases))
    conformance_lower = _wilson_lower(passed, applicable)
    conformance_upper = _wilson_upper(passed, applicable)
    return {
        "case_count": len(cases),
        "outcome_accuracy": _ratio(correct, len(cases)),
        "conformance_rate": _ratio(passed, applicable),
        "applicable_case_count": applicable,
        "passed_cases": passed,
        "failed_cases": failed,
        "negative_cases": negative,
        "outcome_accuracy_wilson_lower_95": outcome_lower,
        "outcome_accuracy_wilson_upper_95": outcome_upper,
        "outcome_accuracy_interval_width_95": outcome_upper - outcome_lower,
        "conformance_rate_wilson_lower_95": conformance_lower,
        "conformance_rate_wilson_upper_95": conformance_upper,
        "conformance_rate_interval_width_95": conformance_upper - conformance_lower,
    }


def _score_temporal_calibration(cases: list[Any]) -> dict[str, Any]:
    seen: set[str] = set()
    squared_error = 0.0
    for raw in cases:
        case = _validate_case_identity(raw, seen)
        if set(case) != {"id", "predicted_probability", "observed", "strata"}:
            raise ValueError("calibration case contract is invalid")
        _validate_strata(case["strata"])
        probability = case["predicted_probability"]
        observed = case["observed"]
        if (
            not isinstance(probability, (int, float))
            or isinstance(probability, bool)
            or not 0 <= float(probability) <= 1
            or not isinstance(observed, bool)
        ):
            raise ValueError("calibration observation is invalid")
        squared_error += (float(probability) - float(observed)) ** 2
    return {"case_count": len(cases), "brier_score": _ratio(squared_error, len(cases))}


def _score_stochastic(cases: list[Any]) -> dict[str, Any]:
    seen: set[str] = set()
    attacked = compromised = 0
    utility = 0.0
    utilities: list[float] = []
    for raw in cases:
        case = _validate_case_identity(raw, seen)
        if set(case) != {"id", "attacked", "compromised", "utility", "strata"}:
            raise ValueError("stochastic trial contract is invalid")
        _validate_strata(case["strata"])
        if not isinstance(case["attacked"], bool) or not isinstance(
            case["compromised"], bool
        ):
            raise ValueError("stochastic trial labels must be boolean")
        score = case["utility"]
        if (
            not isinstance(score, (int, float))
            or isinstance(score, bool)
            or not 0 <= float(score) <= 1
        ):
            raise ValueError("stochastic utility is invalid")
        attacked += case["attacked"]
        compromised += case["attacked"] and case["compromised"]
        utility += float(score)
        utilities.append(float(score))
    rate = _ratio(compromised, attacked)
    upper = _wilson_upper(compromised, attacked)
    return {
        "case_count": len(cases),
        "attacked_trials": attacked,
        "attack_success_rate": rate,
        "attack_success_rate_wilson_upper_95": upper,
        "attack_success_rate_interval_width_95": upper - rate,
        "mean_utility": _ratio(utility, len(cases)),
        "utility_variance": _ratio(
            sum((item - _ratio(utility, len(cases))) ** 2 for item in utilities),
            len(utilities),
        ),
    }


def _score_assessor_agreement(cases: list[Any]) -> dict[str, Any]:
    seen: set[str] = set()
    pair_agreements = pairs = 0
    category_counts: dict[str, int] = {}
    total_ratings = 0
    per_case_agreement: list[float] = []
    expected_rater_count: int | None = None
    for raw in cases:
        case = _validate_case_identity(raw, seen)
        if set(case) != {"id", "ratings", "strata"}:
            raise ValueError("assessor case contract is invalid")
        _validate_strata(case["strata"])
        ratings = case["ratings"]
        if (
            not isinstance(ratings, list)
            or not 2 <= len(ratings) <= 32
            or not all(
                isinstance(item, str) and 1 <= len(item) <= 128 for item in ratings
            )
        ):
            raise ValueError("assessor ratings are invalid")
        if expected_rater_count is None:
            expected_rater_count = len(ratings)
        elif len(ratings) != expected_rater_count:
            raise ValueError("assessor cases require a consistent rater count")
        counts: dict[str, int] = {}
        for rating in ratings:
            counts[rating] = counts.get(rating, 0) + 1
            category_counts[rating] = category_counts.get(rating, 0) + 1
            total_ratings += 1
        per_case_agreement.append(
            _ratio(
                sum(count * (count - 1) for count in counts.values()),
                len(ratings) * (len(ratings) - 1),
            )
        )
        for left in range(len(ratings)):
            for right in range(left + 1, len(ratings)):
                pairs += 1
                pair_agreements += ratings[left] == ratings[right]
    observed = _ratio(sum(per_case_agreement), len(per_case_agreement))
    chance = sum((count / total_ratings) ** 2 for count in category_counts.values())
    kappa = _ratio(observed - chance, 1 - chance)
    return {
        "case_count": len(cases),
        "reviewers": expected_rater_count or 0,
        "agreement": _ratio(pair_agreements, pairs),
        "chance_corrected_agreement": kappa,
    }


def _score_biometric_performance(cases: list[Any]) -> dict[str, Any]:
    seen: set[str] = set()
    genuine = false_non_matches = impostor = false_matches = 0
    attacks = accepted_attacks = 0
    demographic_counts: dict[str, dict[str, int]] = {}
    attack_instruments: set[str] = set()
    for raw in cases:
        case = _validate_case_identity(raw, seen)
        if set(case) != {"id", "trial_type", "accepted", "strata"}:
            raise ValueError("biometric trial contract is invalid")
        _validate_strata(case["strata"])
        trial_type = case["trial_type"]
        accepted = case["accepted"]
        if trial_type not in {
            "genuine",
            "impostor",
            "presentation-attack",
        } or not isinstance(accepted, bool):
            raise ValueError("biometric trial outcome is invalid")
        strata = case["strata"]
        if trial_type == "presentation-attack":
            instrument = strata.get("attack_instrument")
            if not isinstance(instrument, str) or not instrument:
                raise ValueError(
                    "presentation-attack trial requires attack_instrument strata"
                )
            attacks += 1
            accepted_attacks += accepted
            attack_instruments.add(instrument)
            continue
        demographic = strata.get("demographic")
        if not isinstance(demographic, str) or not demographic:
            raise ValueError("comparison trial requires demographic strata")
        group = demographic_counts.setdefault(
            demographic,
            {"genuine": 0, "false_non_matches": 0, "impostor": 0, "false_matches": 0},
        )
        if trial_type == "genuine":
            genuine += 1
            false_non_matches += not accepted
            group["genuine"] += 1
            group["false_non_matches"] += not accepted
        else:
            impostor += 1
            false_matches += accepted
            group["impostor"] += 1
            group["false_matches"] += accepted
    if not genuine or not impostor or not attacks:
        raise ValueError(
            "biometric evaluation requires genuine, impostor, and presentation-attack trials"
        )
    if any(
        not group["genuine"] or not group["impostor"]
        for group in demographic_counts.values()
    ):
        raise ValueError("each demographic group requires genuine and impostor trials")
    worst_group_fmr = max(
        _wilson_upper(group["false_matches"], group["impostor"])
        for group in demographic_counts.values()
    )
    worst_group_fnmr = max(
        _wilson_upper(group["false_non_matches"], group["genuine"])
        for group in demographic_counts.values()
    )
    return {
        "case_count": len(cases),
        "genuine_attempts": genuine,
        "impostor_attempts": impostor,
        "attack_attempts": attacks,
        "demographic_groups": len(demographic_counts),
        "attack_instrument_groups": len(attack_instruments),
        "false_match_rate": _ratio(false_matches, impostor),
        "false_non_match_rate": _ratio(false_non_matches, genuine),
        "iapar": _ratio(accepted_attacks, attacks),
        "fmr_wilson_upper_95": _wilson_upper(false_matches, impostor),
        "fnmr_wilson_upper_95": _wilson_upper(false_non_matches, genuine),
        "iapar_wilson_upper_95": _wilson_upper(accepted_attacks, attacks),
        "worst_group_fmr_wilson_upper_95": worst_group_fmr,
        "worst_group_fnmr_wilson_upper_95": worst_group_fnmr,
    }


def _score_proficiency_testing(cases: list[Any]) -> dict[str, Any]:
    seen: set[str] = set()
    pair_agreements = pairs = reference_matches = total_results = 0
    category_counts: dict[str, int] = {}
    per_case_agreement: list[float] = []
    expected_participants: int | None = None
    rounds: set[int] = set()
    for raw in cases:
        case = _validate_case_identity(raw, seen)
        if set(case) != {
            "id",
            "assigned_value",
            "participant_results",
            "round",
            "strata",
        }:
            raise ValueError("proficiency-testing case contract is invalid")
        _validate_strata(case["strata"])
        assigned = case["assigned_value"]
        results = case["participant_results"]
        round_number = case["round"]
        if (
            not isinstance(assigned, str)
            or not 1 <= len(assigned) <= 128
            or not isinstance(results, list)
            or not 2 <= len(results) <= 128
            or not all(
                isinstance(item, str) and 1 <= len(item) <= 128 for item in results
            )
            or not isinstance(round_number, int)
            or isinstance(round_number, bool)
            or round_number < 1
        ):
            raise ValueError(
                "proficiency-testing assigned value or results are invalid"
            )
        if expected_participants is None:
            expected_participants = len(results)
        elif len(results) != expected_participants:
            raise ValueError(
                "proficiency-testing cases require a consistent participant count"
            )
        rounds.add(round_number)
        counts: dict[str, int] = {}
        for result in results:
            counts[result] = counts.get(result, 0) + 1
            category_counts[result] = category_counts.get(result, 0) + 1
            reference_matches += result == assigned
            total_results += 1
        per_case_agreement.append(
            _ratio(
                sum(count * (count - 1) for count in counts.values()),
                len(results) * (len(results) - 1),
            )
        )
        for left in range(len(results)):
            for right in range(left + 1, len(results)):
                pairs += 1
                pair_agreements += results[left] == results[right]
    observed = _ratio(sum(per_case_agreement), len(per_case_agreement))
    chance = sum((count / total_results) ** 2 for count in category_counts.values())
    kappa = _ratio(observed - chance, 1 - chance)
    return {
        "case_count": len(cases),
        "participants": expected_participants or 0,
        "rounds": len(rounds),
        "agreement": _ratio(pair_agreements, pairs),
        "chance_corrected_agreement": kappa,
        "reference_accuracy": _ratio(reference_matches, total_results),
    }


def _score_fuzzing(cases: list[Any]) -> dict[str, Any]:
    seen: set[str] = set()
    executions = unique_crashes = 0
    coverage_gain = 0.0
    for raw in cases:
        case = _validate_case_identity(raw, seen)
        if set(case) != {
            "id",
            "executions",
            "unique_crashes",
            "coverage_before",
            "coverage_after",
            "strata",
        }:
            raise ValueError("fuzzing campaign contract is invalid")
        _validate_strata(case["strata"])
        for field in ("executions", "unique_crashes"):
            if (
                not isinstance(case[field], int)
                or isinstance(case[field], bool)
                or case[field] < 0
            ):
                raise ValueError("fuzzing counts are invalid")
        before, after = case["coverage_before"], case["coverage_after"]
        if (
            any(
                not isinstance(item, (int, float))
                or isinstance(item, bool)
                or not 0 <= float(item) <= 1
                for item in (before, after)
            )
            or after < before
        ):
            raise ValueError("fuzzing coverage is invalid")
        executions += case["executions"]
        unique_crashes += case["unique_crashes"]
        coverage_gain += float(after) - float(before)
    return {
        "case_count": len(cases),
        "executions": executions,
        "unique_crashes": unique_crashes,
        "coverage_gain": _ratio(coverage_gain, len(cases)),
    }


def _wilson_upper(successes: int, trials: int) -> float:
    if not trials:
        return 0.0
    z = 1.959963984540054
    rate = successes / trials
    denominator = 1 + z * z / trials
    center = rate + z * z / (2 * trials)
    margin = z * ((rate * (1 - rate) / trials + z * z / (4 * trials * trials)) ** 0.5)
    return round((center + margin) / denominator, 12)


def _wilson_lower(successes: int, trials: int) -> float:
    if not trials:
        return 0.0
    z = 1.959963984540054
    rate = successes / trials
    denominator = 1 + z * z / trials
    center = rate + z * z / (2 * trials)
    margin = z * ((rate * (1 - rate) / trials + z * z / (4 * trials * trials)) ** 0.5)
    return round(max(0.0, (center - margin) / denominator), 12)


def _ratio(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 12) if denominator else 0.0


def _threshold_failures(
    metrics: dict[str, Any],
    thresholds: dict[str, Any],
    *,
    conservative: bool = False,
) -> list[str]:
    failures: list[str] = []
    for threshold, value in thresholds.items():
        if threshold.startswith("minimum_"):
            metric = threshold.removeprefix("minimum_")
            if conservative:
                metric = {
                    "precision": "precision_wilson_lower_95",
                    "recall": "recall_wilson_lower_95",
                    "f1": "f1_conservative_95",
                    "accuracy": "accuracy_wilson_lower_95",
                    "outcome_accuracy": "outcome_accuracy_wilson_lower_95",
                    "conformance_rate": "conformance_rate_wilson_lower_95",
                }.get(metric, metric)
            if float(metrics[metric]) < float(value):
                failures.append(f"{metric} is below {threshold}")
        elif threshold.startswith("maximum_"):
            metric = threshold.removeprefix("maximum_")
            if metric == "attack_success_rate":
                metric = "attack_success_rate_wilson_upper_95"
            elif conservative and metric == "false_positive_rate":
                metric = "false_positive_rate_wilson_upper_95"
            if float(metrics[metric]) > float(value):
                failures.append(f"{metric} exceeds {threshold}")
    return failures


def _uncertainty_failures(
    metrics: dict[str, Any], evaluation: dict[str, Any]
) -> list[str]:
    widths = [
        float(value)
        for name, value in metrics.items()
        if name.endswith("_interval_width_95")
        and isinstance(value, (int, float))
        and not isinstance(value, bool)
    ]
    if not widths:
        return []
    maximum = float(evaluation["maximum_confidence_interval_width"])
    return (
        [f"confidence interval width {max(widths):.6f} exceeds {maximum:.6f}"]
        if max(widths) > maximum
        else []
    )
