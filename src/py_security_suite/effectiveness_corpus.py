from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .execution import sha256_file
from .passport import verify_report
from .path_safety import resolve_regular_file
from .source_inventory import verify_source_inventory_file


_MAX_CORPUS_BYTES = 16 * 1024 * 1024
_MAX_LABELS = 10_000
_MAX_MATCHES_PER_LABEL = 20
_DIGEST_LENGTH = 64


def evaluate_report_corpus(
    report: Path,
    corpus: Path,
    *,
    corpus_sha256: str,
) -> dict[str, Any]:
    """Measure a verified report against a digest-bound labeled corpus."""
    verification = verify_report(report)
    report_root = report.expanduser().resolve()
    findings_document = _read_object(report_root / "findings.json", 128 * 1024 * 1024)
    findings = findings_document.get("findings")
    if not isinstance(findings, list) or any(
        not isinstance(finding, dict) for finding in findings
    ):
        raise TypeError("verified report findings must be an array of objects")

    expected_digest = corpus_sha256.strip().casefold()
    if len(expected_digest) != _DIGEST_LENGTH or any(
        character not in "0123456789abcdef" for character in expected_digest
    ):
        raise ValueError("corpus SHA-256 must be exactly 64 hexadecimal characters")
    corpus_path = resolve_regular_file(corpus, "effectiveness corpus")
    observed_digest = sha256_file(corpus_path)
    if observed_digest != expected_digest:
        raise ValueError(
            "effectiveness corpus digest does not match the approved SHA-256"
        )
    document = _read_object(corpus_path, _MAX_CORPUS_BYTES)
    labels = _labels(document)
    _validate_clean_paths(labels, report_root)
    outcomes = [_evaluate_label(label, findings) for label in labels]
    counts = {
        name: sum(outcome["outcome"] == name for outcome in outcomes)
        for name in (
            "true_positive",
            "true_negative",
            "false_positive",
            "false_negative",
        )
    }
    true_positive = counts["true_positive"]
    false_positive = counts["false_positive"]
    false_negative = counts["false_negative"]
    true_negative = counts["true_negative"]
    return {
        "schema_version": "1.0",
        "verdict": "pass" if not false_positive and not false_negative else "fail",
        "report": {
            "scan_id": verification["scan_id"],
            "outcome": verification["outcome"],
            "checksums_sha256": verification["checksums_sha256"],
            "files_verified": verification["file_count"],
        },
        "corpus": {
            "id": str(document.get("corpus_id") or "unnamed"),
            "revision": str(document.get("revision") or ""),
            "sha256": observed_digest,
            "labels": len(labels),
        },
        "confusion_matrix": counts,
        "metrics": {
            "precision": _ratio(true_positive, true_positive + false_positive),
            "recall": _ratio(true_positive, true_positive + false_negative),
            "specificity": _ratio(true_negative, true_negative + false_positive),
            "f1": _f1(true_positive, false_positive, false_negative),
        },
        "failures": [
            outcome
            for outcome in outcomes
            if outcome["outcome"] in {"false_positive", "false_negative"}
        ],
        "label_outcomes": outcomes,
    }


def _read_object(path: Path, maximum: int) -> dict[str, Any]:
    source = resolve_regular_file(path, "JSON evidence")
    if source.stat().st_size > maximum:
        raise ValueError(f"JSON evidence exceeds {maximum} bytes")
    try:
        value = json.loads(source.read_bytes())
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON evidence is invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise TypeError("JSON evidence root must be an object")
    return value


def _labels(document: dict[str, Any]) -> list[dict[str, Any]]:
    if document.get("schema_version") != "1.0":
        raise ValueError("effectiveness corpus schema_version must be '1.0'")
    values = document.get("labels")
    if not isinstance(values, list) or not values:
        raise TypeError("effectiveness corpus requires a non-empty labels array")
    if len(values) > _MAX_LABELS:
        raise ValueError(f"effectiveness corpus exceeds {_MAX_LABELS} labels")
    labels: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for value in values:
        if not isinstance(value, dict):
            raise TypeError("effectiveness corpus labels must be objects")
        identifier = str(value.get("id") or "").strip()
        expectation = str(value.get("expected") or "").strip()
        if not identifier or len(identifier) > 200 or identifier in identifiers:
            raise ValueError(
                "effectiveness corpus label IDs must be unique and bounded"
            )
        if expectation not in {"finding", "clean"}:
            raise ValueError(
                "effectiveness corpus expected must be 'finding' or 'clean'"
            )
        match = value.get("match")
        if not isinstance(match, dict):
            raise TypeError("effectiveness corpus label match must be an object")
        normalized = {
            key: str(match.get(key) or "").strip()
            for key in ("tool", "rule_id", "path", "classification")
        }
        if not any(normalized.values()):
            raise ValueError(
                "effectiveness corpus labels require a match discriminator"
            )
        if any(len(item) > 500 for item in normalized.values()):
            raise ValueError("effectiveness corpus match values must be bounded")
        if normalized["path"] and (
            Path(normalized["path"]).is_absolute()
            or ".." in Path(normalized["path"]).parts
        ):
            raise ValueError("effectiveness corpus paths must be repository-relative")
        identifiers.add(identifier)
        labels.append({"id": identifier, "expected": expectation, "match": normalized})
    return labels


def _validate_clean_paths(labels: list[dict[str, Any]], report: Path) -> None:
    required = _required_clean_paths(labels)
    if not required:
        return
    manifest = _read_object(report / "scan-manifest.json", 128 * 1024 * 1024)
    inventory = manifest.get("inventory")
    if not isinstance(inventory, dict):
        raise TypeError("scan manifest inventory must be an object")
    identity = verify_source_inventory_file(
        report / "source-inventory.json",
        inventory,
        require_unchanged=True,
    )
    missing = sorted(required - identity.paths)
    if missing:
        raise ValueError(
            "clean effectiveness label path is absent from the sealed source inventory: "
            + ", ".join(missing)
        )


def _required_clean_paths(labels: list[dict[str, Any]]) -> set[str]:
    return {
        str(label["match"]["path"])
        for label in labels
        if label["expected"] == "clean" and label["match"]["path"]
    }


def _evaluate_label(
    label: dict[str, Any], findings: list[dict[str, Any]]
) -> dict[str, Any]:
    matching = [
        str(finding.get("finding_id") or "unknown")
        for finding in findings
        if _finding_matches(finding, label["match"])
    ]
    detected = bool(matching)
    expected = label["expected"] == "finding"
    outcome = {
        (True, True): "true_positive",
        (True, False): "false_negative",
        (False, True): "false_positive",
        (False, False): "true_negative",
    }[(expected, detected)]
    return {
        "id": label["id"],
        "expected": label["expected"],
        "match": label["match"],
        "outcome": outcome,
        "matching_finding_ids": matching[:_MAX_MATCHES_PER_LABEL],
        "matching_findings_omitted": max(0, len(matching) - _MAX_MATCHES_PER_LABEL),
    }


def _finding_matches(finding: dict[str, Any], match: dict[str, str]) -> bool:
    sources = finding.get("sources")
    locations = finding.get("locations")
    classifications = finding.get("classifications")
    if not isinstance(sources, list):
        sources = []
    if not isinstance(locations, list):
        locations = []
    if not isinstance(classifications, list):
        classifications = []
    source_match = any(
        isinstance(source, dict)
        and (not match["tool"] or source.get("tool") == match["tool"])
        and (not match["rule_id"] or source.get("rule_id") == match["rule_id"])
        for source in sources
    )
    if (match["tool"] or match["rule_id"]) and not source_match:
        return False
    if match["path"] and not any(
        isinstance(location, dict) and location.get("path") == match["path"]
        for location in locations
    ):
        return False
    return not match["classification"] or match["classification"] in classifications


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _f1(true_positive: int, false_positive: int, false_negative: int) -> float | None:
    denominator = 2 * true_positive + false_positive + false_negative
    return round(2 * true_positive / denominator, 6) if denominator else None
