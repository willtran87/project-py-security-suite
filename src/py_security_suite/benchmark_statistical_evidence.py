from __future__ import annotations

import hashlib
import math
from pathlib import Path
from statistics import NormalDist
from typing import Any

from .benchmark_semantic_evidence import (
    CANONICALIZATION,
    SIMILARITY_ALGORITHM,
    BenchmarkSemanticEvidenceError,
    near_duplicate_count,
    verify_semantic_record_features,
)
from .path_safety import read_regular_file
from .strict_json import loads as strict_loads


_MAX_EXACT_BINOMIAL_CASES = 10_000
_MAX_ANALYSIS_PLAN_BYTES = 256 * 1024


class BenchmarkStatisticalEvidenceError(ValueError):
    """Raised when raw benchmark design evidence cannot reproduce its claims."""


def verify_power_analysis(
    value: dict[str, Any],
    *,
    minimum_power: float,
    minimum_cases: int,
    protocol: str | None = None,
    require_adjusted_design: bool = False,
    require_protocol_specific: bool = False,
    workspace: Path | None = None,
) -> float:
    if value.get("schema_version") == "1.2":
        return _verify_protocol_power_analysis(
            value,
            minimum_power=minimum_power,
            minimum_cases=minimum_cases,
            protocol=protocol,
            workspace=workspace,
        )
    if require_protocol_specific:
        raise BenchmarkStatisticalEvidenceError(
            "protocol-specific power analysis evidence is required"
        )
    required = {
        "schema_version",
        "method",
        "alpha",
        "null_rate",
        "alternative_rate",
        "sample_size",
        "achieved_power",
    }
    if require_adjusted_design:
        required |= {
            "protocol",
            "hypothesis_count",
            "adjusted_alpha",
            "design_effect",
        }
    if (
        set(value) != required
        or value.get("schema_version") != ("1.1" if require_adjusted_design else "1.0")
        or value.get("method")
        != (
            "two-proportion-score-bonferroni"
            if require_adjusted_design
            else "normal-two-proportion-two-sided"
        )
    ):
        raise BenchmarkStatisticalEvidenceError("power analysis contract is invalid")
    family_alpha = _finite_float(value["alpha"], "power alpha")
    alpha = family_alpha
    null_rate = _probability(value["null_rate"], "power null rate")
    alternative_rate = _probability(value["alternative_rate"], "power alternative rate")
    sample_size = value["sample_size"]
    effective_sample_size = sample_size
    if require_adjusted_design:
        hypothesis_count = value["hypothesis_count"]
        design_effect = _finite_float(value["design_effect"], "power design effect")
        adjusted_alpha = _finite_float(value["adjusted_alpha"], "adjusted alpha")
        if (
            value.get("protocol") != protocol
            or not isinstance(hypothesis_count, int)
            or isinstance(hypothesis_count, bool)
            or not 1 <= hypothesis_count <= 128
            or not 1 <= design_effect <= 100
            or not math.isclose(
                adjusted_alpha,
                family_alpha / hypothesis_count,
                rel_tol=0,
                abs_tol=1e-12,
            )
        ):
            raise BenchmarkStatisticalEvidenceError(
                "power multiplicity or design-effect inputs are invalid"
            )
        alpha = adjusted_alpha
        effective_sample_size = math.floor(sample_size / design_effect)
    if (
        family_alpha != 0.05
        or not isinstance(sample_size, int)
        or isinstance(sample_size, bool)
        or sample_size < minimum_cases
        or effective_sample_size < 2
        or null_rate == alternative_rate
    ):
        raise BenchmarkStatisticalEvidenceError("power analysis inputs are invalid")
    pooled = (null_rate + alternative_rate) / 2
    standard_null = math.sqrt(2 * pooled * (1 - pooled))
    standard_alternative = math.sqrt(
        null_rate * (1 - null_rate) + alternative_rate * (1 - alternative_rate)
    )
    if standard_null == 0 or standard_alternative == 0:
        raise BenchmarkStatisticalEvidenceError("power analysis variance is invalid")
    z_alpha = NormalDist().inv_cdf(1 - alpha / 2)
    z_power = (
        math.sqrt(effective_sample_size) * abs(alternative_rate - null_rate)
        - z_alpha * standard_null
    ) / standard_alternative
    computed = NormalDist().cdf(z_power)
    claimed = _probability(value["achieved_power"], "achieved power")
    if not math.isclose(claimed, computed, rel_tol=0, abs_tol=1e-9):
        raise BenchmarkStatisticalEvidenceError(
            "power analysis does not reproduce achieved power"
        )
    if computed < minimum_power:
        raise BenchmarkStatisticalEvidenceError(
            "power analysis does not meet the minimum power"
        )
    return computed


def verify_leakage_analysis(
    value: dict[str, Any],
    *,
    require_semantic: bool = False,
    require_derived_semantic: bool = False,
    workspace: Path | None = None,
) -> int:
    if value.get("schema_version") == "1.2":
        if workspace is None:
            raise BenchmarkStatisticalEvidenceError(
                "derived semantic leakage analysis requires its governed workspace"
            )
        return _verify_derived_overlap(
            value,
            workspace=workspace,
            left_name="training",
            right_name="holdout",
            label="training/holdout leakage",
        )
    if require_derived_semantic:
        raise BenchmarkStatisticalEvidenceError(
            "derived semantic training/holdout leakage evidence is required"
        )
    required = {
        "schema_version",
        "algorithm",
        "training_subject_sha256",
        "holdout_subject_sha256",
        "overlap_count",
    }
    if require_semantic:
        required |= {
            "canonicalization",
            "training_semantic_sha256",
            "holdout_semantic_sha256",
            "semantic_overlap_count",
        }
    if (
        set(value) != required
        or value.get("schema_version") != ("1.1" if require_semantic else "1.0")
        or value.get("algorithm") != "sha256-set-intersection"
    ):
        raise BenchmarkStatisticalEvidenceError("leakage analysis contract is invalid")
    training = _digest_set(value["training_subject_sha256"], "training subjects")
    holdout = _digest_set(value["holdout_subject_sha256"], "holdout subjects")
    overlap = len(training & holdout)
    if value.get("overlap_count") != overlap or overlap != 0:
        raise BenchmarkStatisticalEvidenceError("training/holdout leakage is detected")
    if require_semantic:
        semantic_overlap = len(
            _digest_set(value["training_semantic_sha256"], "training semantics")
            & _digest_set(value["holdout_semantic_sha256"], "holdout semantics")
        )
        if (
            value.get("canonicalization") != "ast-token-shape-v1"
            or value.get("semantic_overlap_count") != semantic_overlap
            or semantic_overlap != 0
        ):
            raise BenchmarkStatisticalEvidenceError(
                "semantic training/holdout leakage is detected"
            )
    return overlap


def verify_duplicate_analysis(
    value: dict[str, Any],
    *,
    minimum_cases: int,
    require_semantic: bool = False,
    require_derived_semantic: bool = False,
    workspace: Path | None = None,
) -> int:
    if value.get("schema_version") == "1.2":
        if workspace is None:
            raise BenchmarkStatisticalEvidenceError(
                "derived semantic duplicate analysis requires its governed workspace"
            )
        required = {
            "schema_version",
            "algorithm",
            "canonicalization",
            "canonicalizer_sha256",
            "case_records",
            "duplicate_count",
            "semantic_duplicate_count",
            "similarity_algorithm",
            "similarity_threshold",
            "near_duplicate_count",
        }
        if (
            set(value) != required
            or value.get("algorithm") != "parser-derived-sha256"
            or value.get("canonicalization") != CANONICALIZATION
            or value.get("similarity_algorithm") != SIMILARITY_ALGORITHM
            or value.get("similarity_threshold") != 0.8
        ):
            raise BenchmarkStatisticalEvidenceError(
                "derived duplicate analysis contract is invalid"
            )
        try:
            subjects, semantics, features = verify_semantic_record_features(
                value["case_records"],
                workspace=workspace,
                expected_canonicalizer_sha256=str(value["canonicalizer_sha256"]),
                label="benchmark case",
            )
        except BenchmarkSemanticEvidenceError as exc:
            raise BenchmarkStatisticalEvidenceError(str(exc)) from exc
        if len(subjects) < minimum_cases:
            raise BenchmarkStatisticalEvidenceError(
                "duplicate analysis has insufficient cases"
            )
        duplicates = len(subjects) - len(set(subjects))
        semantic_duplicates = len(semantics) - len(set(semantics))
        near_duplicates = near_duplicate_count(features, threshold=0.8)
        if value["duplicate_count"] != duplicates or duplicates != 0:
            raise BenchmarkStatisticalEvidenceError(
                "duplicate benchmark cases are detected"
            )
        if (
            value["semantic_duplicate_count"] != semantic_duplicates
            or semantic_duplicates != 0
        ):
            raise BenchmarkStatisticalEvidenceError(
                "semantic duplicate benchmark cases are detected"
            )
        if value["near_duplicate_count"] != near_duplicates or near_duplicates != 0:
            raise BenchmarkStatisticalEvidenceError(
                "near-duplicate benchmark cases are detected"
            )
        return duplicates
    if require_derived_semantic:
        raise BenchmarkStatisticalEvidenceError(
            "derived semantic duplicate evidence is required"
        )
    required = {"schema_version", "algorithm", "case_sha256", "duplicate_count"}
    if require_semantic:
        required |= {
            "canonicalization",
            "case_semantic_sha256",
            "semantic_duplicate_count",
        }
    if (
        set(value) != required
        or value.get("schema_version") != ("1.1" if require_semantic else "1.0")
        or value.get("algorithm") != "sha256"
    ):
        raise BenchmarkStatisticalEvidenceError(
            "duplicate analysis contract is invalid"
        )
    case_values = value["case_sha256"]
    if not isinstance(case_values, list) or len(case_values) < minimum_cases:
        raise BenchmarkStatisticalEvidenceError(
            "duplicate analysis has insufficient cases"
        )
    digests = [_digest(item, "case digest") for item in case_values]
    duplicates = len(digests) - len(set(digests))
    if value.get("duplicate_count") != duplicates or duplicates != 0:
        raise BenchmarkStatisticalEvidenceError(
            "duplicate benchmark cases are detected"
        )
    if require_semantic:
        semantic_values = value["case_semantic_sha256"]
        if not isinstance(semantic_values, list) or len(semantic_values) != len(
            digests
        ):
            raise BenchmarkStatisticalEvidenceError(
                "semantic duplicate analysis has incomplete cases"
            )
        semantic_digests = [
            _digest(item, "case semantic digest") for item in semantic_values
        ]
        semantic_duplicates = len(semantic_digests) - len(set(semantic_digests))
        if (
            value.get("canonicalization") != "ast-token-shape-v1"
            or value.get("semantic_duplicate_count") != semantic_duplicates
            or semantic_duplicates != 0
        ):
            raise BenchmarkStatisticalEvidenceError(
                "semantic duplicate benchmark cases are detected"
            )
    return duplicates


def verify_contamination_analysis(
    value: dict[str, Any],
    *,
    require_semantic: bool = False,
    require_derived_semantic: bool = False,
    workspace: Path | None = None,
) -> int:
    if value.get("schema_version") == "1.2":
        if workspace is None:
            raise BenchmarkStatisticalEvidenceError(
                "derived semantic contamination analysis requires its governed workspace"
            )
        return _verify_derived_overlap(
            value,
            workspace=workspace,
            left_name="training",
            right_name="benchmark",
            label="benchmark contamination",
        )
    if require_derived_semantic:
        raise BenchmarkStatisticalEvidenceError(
            "derived semantic contamination evidence is required"
        )
    required = {
        "schema_version",
        "algorithm",
        "training_artifact_sha256",
        "benchmark_artifact_sha256",
        "overlap_count",
    }
    if require_semantic:
        required |= {
            "canonicalization",
            "training_semantic_sha256",
            "benchmark_semantic_sha256",
            "semantic_overlap_count",
        }
    if (
        set(value) != required
        or value.get("schema_version") != ("1.1" if require_semantic else "1.0")
        or value.get("algorithm") != "sha256-set-intersection"
    ):
        raise BenchmarkStatisticalEvidenceError(
            "contamination analysis contract is invalid"
        )
    training = _digest_set(value["training_artifact_sha256"], "training artifacts")
    benchmark = _digest_set(value["benchmark_artifact_sha256"], "benchmark artifacts")
    overlap = len(training & benchmark)
    if value.get("overlap_count") != overlap or overlap != 0:
        raise BenchmarkStatisticalEvidenceError("benchmark contamination is detected")
    if require_semantic:
        semantic_overlap = len(
            _digest_set(value["training_semantic_sha256"], "training semantics")
            & _digest_set(value["benchmark_semantic_sha256"], "benchmark semantics")
        )
        if (
            value.get("canonicalization") != "ast-token-shape-v1"
            or value.get("semantic_overlap_count") != semantic_overlap
            or semantic_overlap != 0
        ):
            raise BenchmarkStatisticalEvidenceError(
                "semantic benchmark contamination is detected"
            )
    return overlap


def verify_environment_capture(value: dict[str, Any]) -> bool:
    required = {
        "schema_version",
        "runtime",
        "runtime_version",
        "platform_sha256",
        "toolset_sha256",
        "network_policy_sha256",
        "hermetic",
    }
    if set(value) != required or value.get("schema_version") != "1.0":
        raise BenchmarkStatisticalEvidenceError(
            "environment capture contract is invalid"
        )
    for field in ("platform_sha256", "toolset_sha256", "network_policy_sha256"):
        _digest(value[field], field)
    for field in ("runtime", "runtime_version"):
        item = value[field]
        if not isinstance(item, str) or not 1 <= len(item) <= 256:
            raise BenchmarkStatisticalEvidenceError(f"environment {field} is invalid")
    if not isinstance(value["hermetic"], bool):
        raise BenchmarkStatisticalEvidenceError("environment hermetic flag is invalid")
    return bool(value["hermetic"])


def compute_power(
    *, alpha: float, null_rate: float, alternative_rate: float, sample_size: int
) -> float:
    """Return the same deterministic approximation required by evidence replay."""
    pooled = (null_rate + alternative_rate) / 2
    return NormalDist().cdf(
        (
            math.sqrt(sample_size) * abs(alternative_rate - null_rate)
            - NormalDist().inv_cdf(1 - alpha / 2) * math.sqrt(2 * pooled * (1 - pooled))
        )
        / math.sqrt(
            null_rate * (1 - null_rate) + alternative_rate * (1 - alternative_rate)
        )
    )


def compute_protocol_power(
    *,
    protocol: str,
    alpha: float,
    null_rate: float,
    alternative_rate: float,
    sample_size: int,
) -> float:
    """Compute the protocol-selected power model used by evidence schema 1.2."""
    if protocol in {
        "classification",
        "detection-evaluation",
        "verification-competition",
        "test-generation",
        "conformance",
        "assessor-agreement",
        "biometric-performance",
        "proficiency-testing",
    }:
        return _exact_binomial_power(
            alpha=alpha,
            null_rate=null_rate,
            alternative_rate=alternative_rate,
            sample_size=sample_size,
        )
    raise BenchmarkStatisticalEvidenceError(
        f"benchmark protocol requires a non-rate power model: {protocol}"
    )


def compute_standardized_mean_power(
    *, alpha: float, standardized_effect: float, sample_size: int
) -> float:
    """Power for a two-sided standardized mean effect under a normal model."""
    if not 0 < alpha < 1 or not 0 < standardized_effect <= 10 or sample_size < 2:
        raise BenchmarkStatisticalEvidenceError(
            "standardized mean power inputs are invalid"
        )
    z_alpha = NormalDist().inv_cdf(1 - alpha / 2)
    shift = math.sqrt(sample_size) * standardized_effect
    return NormalDist().cdf(-z_alpha - shift) + 1 - NormalDist().cdf(z_alpha - shift)


def _verify_protocol_power_analysis(
    value: dict[str, Any],
    *,
    minimum_power: float,
    minimum_cases: int,
    protocol: str | None,
    workspace: Path | None,
) -> float:
    rate_protocols = {
        "classification",
        "detection-evaluation",
        "verification-competition",
        "test-generation",
        "conformance",
        "assessor-agreement",
        "biometric-performance",
        "proficiency-testing",
    }
    mean_protocols = {
        "temporal-calibration",
        "stochastic-adversarial",
        "fuzzing-statistical",
    }
    common = {
        "schema_version",
        "method",
        "protocol",
        "alpha",
        "sample_size",
        "achieved_power",
        "hypothesis_count",
        "adjusted_alpha",
        "design_effect",
        "analysis_plan_path",
        "analysis_plan_sha256",
        "effect_source_sha256",
        "sensitivity_power",
    }
    required = common | (
        {"null_rate", "alternative_rate"}
        if protocol in rate_protocols
        else {"standardized_effect"}
    )
    expected_method = (
        "exact-binomial-equal-tail-two-sided-bonferroni"
        if protocol in rate_protocols
        else "normal-standardized-effect-bonferroni"
    )
    if (
        set(value) != required
        or protocol not in rate_protocols | mean_protocols
        or value.get("protocol") != protocol
        or value.get("method") != expected_method
        or not _is_digest(value.get("analysis_plan_sha256"))
        or not _is_digest(value.get("effect_source_sha256"))
    ):
        raise BenchmarkStatisticalEvidenceError(
            "protocol-specific power analysis contract is invalid"
        )
    family_alpha = _finite_float(value["alpha"], "power alpha")
    hypothesis_count = value["hypothesis_count"]
    adjusted_alpha = _finite_float(value["adjusted_alpha"], "adjusted alpha")
    design_effect = _finite_float(value["design_effect"], "power design effect")
    sample_size = value["sample_size"]
    if (
        family_alpha != 0.05
        or not isinstance(hypothesis_count, int)
        or isinstance(hypothesis_count, bool)
        or not 1 <= hypothesis_count <= 128
        or not math.isclose(
            adjusted_alpha, family_alpha / hypothesis_count, rel_tol=0, abs_tol=1e-12
        )
        or not 1 <= design_effect <= 100
        or not isinstance(sample_size, int)
        or isinstance(sample_size, bool)
        or sample_size < minimum_cases
        or sample_size > _MAX_EXACT_BINOMIAL_CASES
    ):
        raise BenchmarkStatisticalEvidenceError(
            "protocol-specific power analysis inputs are invalid"
        )
    effective = math.floor(sample_size / design_effect)
    if effective < 2 or protocol is None:
        raise BenchmarkStatisticalEvidenceError(
            "protocol-specific effective sample is invalid"
        )
    plan_inputs: dict[str, Any] = {
        "schema_version": "1.0",
        "protocol": protocol,
        "method": expected_method,
        "alpha": family_alpha,
        "hypothesis_count": hypothesis_count,
        "adjusted_alpha": adjusted_alpha,
        "design_effect": design_effect,
        "sample_size": sample_size,
        "effect_source_sha256": value["effect_source_sha256"],
    }
    if protocol in rate_protocols:
        null_rate = _probability(value["null_rate"], "power null rate")
        alternative_rate = _probability(
            value["alternative_rate"], "power alternative rate"
        )
        if null_rate == alternative_rate:
            raise BenchmarkStatisticalEvidenceError(
                "protocol-specific power analysis inputs are invalid"
            )
        plan_inputs.update(
            {"null_rate": null_rate, "alternative_rate": alternative_rate}
        )
        computed = compute_protocol_power(
            protocol=protocol,
            alpha=adjusted_alpha,
            null_rate=null_rate,
            alternative_rate=alternative_rate,
            sample_size=effective,
        )
        sensitivity = compute_protocol_power(
            protocol=protocol,
            alpha=adjusted_alpha,
            null_rate=null_rate,
            alternative_rate=null_rate + (alternative_rate - null_rate) * 0.8,
            sample_size=effective,
        )
    else:
        standardized_effect = _finite_float(
            value["standardized_effect"], "standardized effect"
        )
        if not 0 < standardized_effect <= 10:
            raise BenchmarkStatisticalEvidenceError(
                "protocol-specific standardized effect is invalid"
            )
        plan_inputs["standardized_effect"] = standardized_effect
        computed = compute_standardized_mean_power(
            alpha=adjusted_alpha,
            standardized_effect=standardized_effect,
            sample_size=effective,
        )
        sensitivity = compute_standardized_mean_power(
            alpha=adjusted_alpha,
            standardized_effect=standardized_effect * 0.8,
            sample_size=effective,
        )
    _verify_analysis_plan(value, workspace=workspace, expected=plan_inputs)
    claimed = _probability(value["achieved_power"], "achieved power")
    claimed_sensitivity = _probability(value["sensitivity_power"], "sensitivity power")
    if not math.isclose(claimed, computed, rel_tol=0, abs_tol=1e-9):
        raise BenchmarkStatisticalEvidenceError(
            "power analysis does not reproduce achieved power"
        )
    if not math.isclose(claimed_sensitivity, sensitivity, rel_tol=0, abs_tol=1e-9):
        raise BenchmarkStatisticalEvidenceError(
            "power analysis does not reproduce sensitivity power"
        )
    if computed < minimum_power:
        raise BenchmarkStatisticalEvidenceError(
            "power analysis does not meet the minimum power"
        )
    return computed


def _exact_binomial_power(
    *,
    alpha: float,
    null_rate: float,
    alternative_rate: float,
    sample_size: int,
) -> float:
    if not 2 <= sample_size <= _MAX_EXACT_BINOMIAL_CASES:
        raise BenchmarkStatisticalEvidenceError(
            "exact-binomial sample size exceeds the verified computational bound"
        )
    null_probabilities = _binomial_probabilities(sample_size, null_rate)
    alternative_probabilities = _binomial_probabilities(sample_size, alternative_rate)
    tail_alpha = alpha / 2
    running = 0.0
    lower_critical = -1
    for successes in range(sample_size + 1):
        candidate = running + null_probabilities[successes]
        if candidate > tail_alpha + 1e-15:
            break
        running = candidate
        lower_critical = successes
    running = 0.0
    upper_critical = sample_size + 1
    for successes in range(sample_size, -1, -1):
        candidate = running + null_probabilities[successes]
        if candidate > tail_alpha + 1e-15:
            break
        running = candidate
        upper_critical = successes
    lower_power = math.fsum(alternative_probabilities[: lower_critical + 1])
    upper_power = math.fsum(alternative_probabilities[upper_critical:])
    return lower_power + upper_power


def _binomial_probabilities(sample_size: int, probability: float) -> list[float]:
    if probability == 0:
        return [1.0, *([0.0] * sample_size)]
    if probability == 1:
        return [*([0.0] * sample_size), 1.0]
    values = [
        math.exp(
            math.lgamma(sample_size + 1)
            - math.lgamma(successes + 1)
            - math.lgamma(sample_size - successes + 1)
            + successes * math.log(probability)
            + (sample_size - successes) * math.log1p(-probability)
        )
        for successes in range(sample_size + 1)
    ]
    total = math.fsum(values)
    if total <= 0 or not math.isfinite(total):
        raise BenchmarkStatisticalEvidenceError(
            "exact-binomial probability calculation is unstable"
        )
    return [item / total for item in values]


def _verify_analysis_plan(
    value: dict[str, Any], *, workspace: Path | None, expected: dict[str, Any]
) -> None:
    path = value.get("analysis_plan_path")
    digest = value.get("analysis_plan_sha256")
    if (
        workspace is None
        or not isinstance(path, str)
        or not path
        or Path(path).is_absolute()
        or not _is_digest(digest)
    ):
        raise BenchmarkStatisticalEvidenceError(
            "power analysis plan binding is invalid"
        )
    boundary = workspace.expanduser().absolute().resolve()
    try:
        _, payload = read_regular_file(
            boundary / path,
            "benchmark analysis plan",
            maximum_bytes=_MAX_ANALYSIS_PLAN_BYTES,
            boundary=boundary,
        )
        plan = strict_loads(payload)
    except (OSError, TypeError, ValueError) as exc:
        raise BenchmarkStatisticalEvidenceError(
            "benchmark analysis plan is not a safe canonical document"
        ) from exc
    if hashlib.sha256(payload).hexdigest() != digest or plan != expected:
        raise BenchmarkStatisticalEvidenceError(
            "benchmark analysis plan does not reproduce power inputs"
        )


def _verify_derived_overlap(
    value: dict[str, Any],
    *,
    workspace: Path,
    left_name: str,
    right_name: str,
    label: str,
) -> int:
    required = {
        "schema_version",
        "algorithm",
        "canonicalization",
        "canonicalizer_sha256",
        f"{left_name}_records",
        f"{right_name}_records",
        "overlap_count",
        "semantic_overlap_count",
        "similarity_algorithm",
        "similarity_threshold",
        "near_duplicate_count",
    }
    if (
        set(value) != required
        or value.get("algorithm") != "parser-derived-sha256-set-intersection"
        or value.get("canonicalization") != CANONICALIZATION
        or value.get("similarity_algorithm") != SIMILARITY_ALGORITHM
        or value.get("similarity_threshold") != 0.8
    ):
        raise BenchmarkStatisticalEvidenceError(
            f"derived {label} analysis contract is invalid"
        )
    canonicalizer = str(value["canonicalizer_sha256"])
    try:
        left_subjects, left_semantics, left_features = verify_semantic_record_features(
            value[f"{left_name}_records"],
            workspace=workspace,
            expected_canonicalizer_sha256=canonicalizer,
            label=left_name,
        )
        right_subjects, right_semantics, right_features = (
            verify_semantic_record_features(
                value[f"{right_name}_records"],
                workspace=workspace,
                expected_canonicalizer_sha256=canonicalizer,
                label=right_name,
            )
        )
    except BenchmarkSemanticEvidenceError as exc:
        raise BenchmarkStatisticalEvidenceError(str(exc)) from exc
    overlap = len(set(left_subjects) & set(right_subjects))
    semantic_overlap = len(set(left_semantics) & set(right_semantics))
    near_duplicates = near_duplicate_count(left_features, right_features, threshold=0.8)
    if value["overlap_count"] != overlap or overlap != 0:
        raise BenchmarkStatisticalEvidenceError(f"{label} is detected")
    if value["semantic_overlap_count"] != semantic_overlap or semantic_overlap != 0:
        raise BenchmarkStatisticalEvidenceError(f"semantic {label} is detected")
    if value["near_duplicate_count"] != near_duplicates or near_duplicates != 0:
        raise BenchmarkStatisticalEvidenceError(f"near-duplicate {label} is detected")
    return overlap


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _digest_set(value: object, label: str) -> set[str]:
    if not isinstance(value, list) or not value:
        raise BenchmarkStatisticalEvidenceError(f"{label} are invalid")
    digests = [_digest(item, label) for item in value]
    if len(digests) != len(set(digests)):
        raise BenchmarkStatisticalEvidenceError(f"{label} contain duplicates")
    return set(digests)


def _digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise BenchmarkStatisticalEvidenceError(f"{label} is invalid")
    return value


def _probability(value: object, label: str) -> float:
    result = _finite_float(value, label)
    if not 0 <= result <= 1:
        raise BenchmarkStatisticalEvidenceError(f"{label} is invalid")
    return result


def _finite_float(value: object, label: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise BenchmarkStatisticalEvidenceError(f"{label} is invalid")
    result = float(value)
    if not math.isfinite(result):
        raise BenchmarkStatisticalEvidenceError(f"{label} is invalid")
    return result
