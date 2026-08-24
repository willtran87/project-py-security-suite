from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from companion.ai_stochastic_assurance import (
    _clustered_success_counts,
    _validate_paired_trials,
    _validate_run_receipts,
    _verify_calibration_corpus,
    analyze_trials,
)
from companion.database_security import _case as database_case
from companion.database_security import _validate_read_only_sql
from companion.event_security import _servers, _validate_asyncapi_operation
from companion.semantic_assurance import _verify_observed_rule_qualification
from companion.surface_inventory import _verify_page_receipts, reconcile
from companion.tool_normalizers import _safe_sarif_message, _sarif_findings
from companion.strict_json import dumps as strict_dumps


def test_surface_inventory_reconciles_two_independent_native_sources(
    tmp_path: Path,
) -> None:
    declared = [{"id": "api-v1", "version": "1", "owner": "team-a", "status": "active"}]
    observed = [{"id": "api-v1", "version": "1", "owner": "team-a"}]
    for name, value in (
        ("declared.json", declared),
        ("runtime.json", observed),
        ("gateway.json", observed),
    ):
        (tmp_path / name).write_text(strict_dumps(value), encoding="utf-8")
    contract = {
        "schema_version": "1.0",
        "declared_file": "declared.json",
        "declared_sha256": _digest(tmp_path / "declared.json"),
        "observed_sources": [
            {
                "kind": "runtime",
                "file": "runtime.json",
                "sha256": _digest(tmp_path / "runtime.json"),
            },
            {
                "kind": "gateway",
                "file": "gateway.json",
                "sha256": _digest(tmp_path / "gateway.json"),
            },
        ],
        "canary_id": "api-v1",
    }
    path = tmp_path / "contract.json"
    path.write_text(strict_dumps(contract), encoding="utf-8")

    result = reconcile(path)

    assert result["findings"] == []
    assert "source:runtime" in result["execution"]["features"]


def test_ai_trials_apply_per_control_sample_and_confidence_policy() -> None:
    controls = (
        "prompt-injection",
        "tool-authorization",
        "least-agency",
        "memory-boundary",
        "output-handling",
        "data-exfiltration",
    )
    trials = []
    for control in controls:
        for attempt in range(2):
            trials.append(
                {
                    "id": control,
                    "target_id": "agent-a",
                    "role": "adversarial",
                    "control": control,
                    "attempt": attempt,
                    "seed_sha256": f"{attempt + 1:x}" * 64,
                    "expected": "block",
                    "observed": "block",
                    "severity": "high",
                    "classification": "CWE-693",
                }
            )
    value = {
        "schema_version": "1.0",
        "model_sha256": "1" * 64,
        "provider_sha256": "2" * 64,
        "prompt_template_sha256": "3" * 64,
        "dataset_sha256": "4" * 64,
        "minimum_trials_per_control": 2,
        "maximum_failure_rate": 1.0,
        "confidence_level": 0.95,
        "canary_id": f"{controls[0]}:0:{'1' * 16}",
        "trials": trials,
    }

    result = analyze_trials(value)

    assert result["execution"]["requests"] == 12
    assert result["findings"] == []


def test_ai_calibration_and_cluster_counts_are_recomputed(tmp_path: Path) -> None:
    corpus = [
        {"id": f"case-{index}", "expected": "block", "observed": "block"}
        for index in range(20)
    ]
    path = tmp_path / "calibration.json"
    path.write_text(strict_dumps(corpus), encoding="utf-8")
    context = tmp_path / "contract.json"
    context.write_text("{}", encoding="utf-8")
    value = {
        "calibration_corpus_file": path.name,
        "calibration_corpus_sha256": _digest(path),
        "calibration_accuracy": 1.0,
    }
    assert _verify_calibration_corpus(value, context) == 1.0

    trials = [
        {
            "pair_id": pair,
            "control": "prompt-injection",
            "expected": "block",
            "observed": observed,
        }
        for pair, observed in (("one", "block"), ("two", "allow"))
    ]
    assert _clustered_success_counts(trials, "prompt-injection") == (1, 2)


def test_asyncapi_message_and_ruleset_matrices_bind_observations() -> None:
    schema_digest = "a" * 64
    document = {
        "channels": {
            "orders": {
                "publish": {"messages": [{"$ref": "#/components/messages/Order"}]}
            }
        },
        "components": {
            "messages": {"Order": {"x-pysec-payload-schema-sha256": schema_digest}}
        },
    }
    _validate_asyncapi_operation(document, "orders", "produce", schema_digest)
    with pytest.raises(ValueError, match="not bound"):
        _validate_asyncapi_operation(document, "orders", "produce", "b" * 64)

    cases = [
        {
            "rule_id": "R1",
            "stratum": "python",
            "mutation_operator": "negate-condition",
            "expected": "detected",
            "observed": "detected",
        },
        {
            "rule_id": "R1",
            "stratum": "python",
            "mutation_operator": "",
            "expected": "clean",
            "observed": "clean",
        },
    ]
    matrices = [
        {
            "rule_id": "R1",
            "true_positive": 1,
            "true_negative": 1,
            "false_positive": 0,
            "false_negative": 0,
        }
    ]
    _verify_observed_rule_qualification(
        cases, matrices, {"python"}, {"negate-condition"}
    )


def test_native_database_and_event_contracts_reject_unsafe_targets() -> None:
    with pytest.raises(ValueError, match="read-only"):
        database_case(
            {
                "id": "unsafe",
                "target_id": "db",
                "role": "user",
                "control": "least-privilege",
                "sql": "DROP TABLE users",
                "parameters_env": "",
                "expected": "block",
                "expected_sqlstate": "",
                "severity": "critical",
                "classification": "CWE-732",
            }
        )
    assert _servers("127.0.0.1:9092") == "127.0.0.1:9092"
    with pytest.raises(ValueError, match="loopback"):
        _servers("broker.example.com:9092")


def test_polyglot_sarif_normalizer_preserves_native_location_and_canary() -> None:
    report = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "eslint", "version": "10"}},
                "invocations": [{"executionSuccessful": True}],
                "results": [
                    {
                        "ruleId": "security/no-eval",
                        "level": "error",
                        "message": {"text": "unsafe evaluation"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "web/app.js"},
                                    "region": {"startLine": 7},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    findings = _sarif_findings(
        {"tool": "eslint-sarif", "report": report, "canary_report": report},
        "eslint-sarif",
    )
    assert findings[0]["path"] == "web/app.js"
    assert findings[0]["line"] == 7


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_paired_trials_reject_duplicate_run_observations() -> None:
    base = {
        "pair_id": "pair",
        "seed_sha256": "1" * 64,
        "target_id": "agent",
        "control": "prompt-injection",
        "turn": 1,
    }
    with pytest.raises(ValueError, match="exactly one"):
        _validate_paired_trials(
            [
                {**base, "run_id": "one"},
                {**base, "run_id": "one"},
                {**base, "run_id": "two"},
            ]
        )


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT pg_sleep(10)",
        "SELECT nextval('sequence')",
        "SELECT lower(name) FROM users",
        "EXPLAIN ANALYZE SELECT * FROM users",
        "SELECT * FROM users FOR UPDATE",
    ],
)
def test_database_oracle_rejects_stateful_selects(sql: str) -> None:
    with pytest.raises(ValueError, match="unsafe SQL construct"):
        _validate_read_only_sql(sql)


def test_surface_page_receipts_require_a_complete_hash_chain(tmp_path: Path) -> None:
    receipts = [
        {
            "page_number": 1,
            "request_sha256": "1" * 64,
            "response_sha256": "2" * 64,
            "continuation_in_sha256": "",
            "continuation_out_sha256": "3" * 64,
            "record_count": 2,
        },
        {
            "page_number": 2,
            "request_sha256": "4" * 64,
            "response_sha256": "5" * 64,
            "continuation_in_sha256": "3" * 64,
            "continuation_out_sha256": "",
            "record_count": 1,
        },
    ]
    receipt_path = tmp_path / "pages.json"
    receipt_path.write_text(strict_dumps(receipts), encoding="utf-8")
    context = tmp_path / "contract.json"
    context.write_text("{}", encoding="utf-8")
    _verify_page_receipts(
        context,
        {
            "page_receipts_file": receipt_path.name,
            "page_receipts_sha256": _digest(receipt_path),
            "server_total_records": 3,
        },
        2,
    )


def test_sarif_secret_bearing_message_is_redacted() -> None:
    message, redacted = _safe_sarif_message("Authorization: Bearer super-secret")
    assert redacted is True
    assert "super-secret" not in message


def test_ai_run_receipts_require_distinct_non_overlapping_authorities(
    tmp_path: Path,
) -> None:
    now = datetime.now(UTC)
    receipts = []
    trials = []
    authority_results = []
    for index in range(2):
        started = now - timedelta(hours=4 - index * 2)
        ended = started + timedelta(hours=1)
        run_id = f"run-{index}"
        receipts.append(
            {
                "run_id": run_id,
                "environment_sha256": str(index + 1) * 64,
                "administrative_domain": f"domain-{index}",
                "started_at": started.isoformat(),
                "ended_at": ended.isoformat(),
                "authority": {"opaque": index},
            }
        )
        trials.append({"run_id": run_id})
        authority_results.append(
            {
                "signer_id": str(index + 3) * 64,
                "signed_at": (ended + timedelta(minutes=1)).isoformat(),
            }
        )
    context = tmp_path / "ai.json"
    context.write_text("{}", encoding="utf-8")
    with patch(
        "companion.ai_stochastic_assurance.verify_authority",
        side_effect=authority_results,
    ):
        _validate_run_receipts({"run_receipts": receipts}, trials, context)
