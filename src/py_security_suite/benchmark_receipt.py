from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def build_benchmark_execution_receipt(
    *,
    manifest: dict[str, Any],
    execution_id: str,
    manifest_sha256: str,
    manifest_path: str,
    corpus_sha256: str,
    normalized_result_sha256: str | None,
    started_at: str,
    case_count: int,
    metrics: dict[str, Any] | None,
    statistical_sufficiency: dict[str, Any],
    input_integrity_gaps: list[str],
    subject_sha256: str,
    attestations: dict[str, Any],
    evidence_documents: dict[str, Any] | None,
    replay_receipt: dict[str, Any] | None,
    replay_checkpoint_state: dict[str, Any] | None,
    trust_policy: dict[str, Any] | None,
    trusted_time_proof: dict[str, str] | None,
    stages: list[dict[str, Any]],
    isolation_runtime_proof: dict[str, Any] | None,
    decision: str,
    failure_reason: str | None,
) -> dict[str, Any]:
    """Assemble the stable schema 1.x receipt before industry evidence and signing."""
    return {
        "schema_version": str(manifest["schema_version"]),
        "analysis": "benchmark-adapter-execution",
        "execution_id": execution_id,
        "benchmark_id": manifest["benchmark_id"],
        "protocol": manifest["protocol"],
        "benchmark_version": manifest["benchmark_version"],
        "adapter_version": manifest["adapter_version"],
        "manifest_sha256": manifest_sha256,
        "manifest_path": manifest_path,
        "corpus_sha256": corpus_sha256,
        "corpus": {
            "sha256": corpus_sha256,
            "revision": manifest["benchmark_version"],
            "authority": {
                "organization_approved": manifest["corpus"]["organization_approved"],
                "license_sha256": manifest["corpus"]["license_sha256"],
                "label_authority_sha256": manifest["corpus"]["label_authority_sha256"],
            },
        },
        "normalized_result_sha256": normalized_result_sha256,
        "started_at": started_at,
        "completed_at": datetime.now(UTC).isoformat(),
        "case_count": case_count,
        "metrics": metrics,
        "statistical_sufficiency": statistical_sufficiency,
        "input_integrity": {
            "verified_after_execution": not input_integrity_gaps,
            "gaps": input_integrity_gaps,
        },
        "thresholds": manifest["thresholds"],
        "benchmark_subject_sha256": subject_sha256,
        "attestations": attestations,
        "evidence_documents": evidence_documents,
        "replay_protected": attestations["replay_protection"]["replay_protected"],
        "replay_receipt": replay_receipt,
        "replay_checkpoint_state": replay_checkpoint_state,
        "authority_trust_policy": (
            {
                "policy_id": trust_policy["policy_id"],
                "sha256": trust_policy["sha256"],
                "minimum_distinct_signers": trust_policy["minimum_distinct_signers"],
                "minimum_distinct_organizations": trust_policy[
                    "minimum_distinct_organizations"
                ],
                "trust_root_key_id": trust_policy["trust_root_key_id"],
            }
            if trust_policy is not None
            else None
        ),
        "trusted_time_proof": trusted_time_proof,
        "stages": stages,
        "isolation": manifest["isolation"],
        "isolation_runtime_proof": isolation_runtime_proof,
        "decision": decision,
        "verdict": decision,
        "failure_reason": failure_reason,
        "claim_boundary": (
            "This receipt proves execution of the digest-pinned adapter and corpus. "
            "Process mode does not prove network isolation. OCI mode enforces the "
            "recorded runtime controls; external-sandbox claims remain dependent on "
            "their separately verified isolation evidence."
        ),
    }
