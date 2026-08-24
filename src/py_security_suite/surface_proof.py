from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any

from .strict_json import canonical_bytes


_DIGEST = re.compile(r"[0-9a-f]{64}")
_SOURCE_FIELDS = {
    "kind",
    "snapshot_sha256",
    "collector_id",
    "collector_signer_id",
    "collector_organization",
    "adapter_sha256",
    "endpoint_identity_sha256",
    "query_sha256",
    "pages_expected",
    "pages_observed",
    "page_receipts_sha256",
    "server_total_records",
    "records_observed",
    "liveness_probes",
    "server_collector_id",
    "server_signer_id",
    "server_organization",
    "collected_at",
}


def verify_surface_proof(execution: object) -> dict[str, Any]:
    """Verify the structured, evidence-signed surface reconciliation proof."""

    proof = execution.get("surface_proof") if isinstance(execution, dict) else None
    fields = {
        "schema_version",
        "declared_sha256",
        "history_sha256",
        "trusted_time_sha256",
        "sources",
        "proof_sha256",
    }
    if not isinstance(proof, dict) or set(proof) != fields:
        raise TypeError("surface inventory lacks a structured reconciliation proof")
    subject = {name: proof[name] for name in fields - {"proof_sha256"}}
    if (
        proof.get("schema_version") != "1.0"
        or any(
            _DIGEST.fullmatch(str(proof.get(name) or "")) is None
            for name in (
                "declared_sha256",
                "history_sha256",
                "trusted_time_sha256",
                "proof_sha256",
            )
        )
        or proof["proof_sha256"] != hashlib.sha256(canonical_bytes(subject)).hexdigest()
    ):
        raise TypeError("surface reconciliation proof binding is invalid")
    sources = proof.get("sources")
    if not isinstance(sources, list) or not 2 <= len(sources) <= 16:
        raise TypeError("surface reconciliation proof has an invalid source count")
    kinds: set[str] = set()
    collectors: set[str] = set()
    signers: set[str] = set()
    organizations: set[str] = set()
    for source in sources:
        if not isinstance(source, dict) or set(source) != _SOURCE_FIELDS:
            raise TypeError("surface reconciliation source proof is malformed")
        kind = str(source.get("kind") or "")
        collector = str(source.get("collector_id") or "")
        server_collector = str(source.get("server_collector_id") or "")
        collector_signer = str(source.get("collector_signer_id") or "")
        server_signer = str(source.get("server_signer_id") or "")
        collector_org = str(source.get("collector_organization") or "").strip()
        server_org = str(source.get("server_organization") or "").strip()
        digest_names = (
            "snapshot_sha256",
            "adapter_sha256",
            "endpoint_identity_sha256",
            "query_sha256",
            "page_receipts_sha256",
        )
        integers = (
            source.get("pages_expected"),
            source.get("pages_observed"),
            source.get("server_total_records"),
            source.get("records_observed"),
            source.get("liveness_probes"),
        )
        try:
            datetime.fromisoformat(str(source.get("collected_at"))).astimezone(UTC)
        except (TypeError, ValueError) as exc:
            raise TypeError(
                "surface reconciliation collection time is invalid"
            ) from exc
        if (
            kind not in {"runtime", "gateway", "service-mesh", "cloud-control-plane"}
            or kind in kinds
            or not collector
            or not server_collector
            or collector == server_collector
            or collector in collectors
            or server_collector in collectors
            or not collector_signer
            or not server_signer
            or collector_signer == server_signer
            or collector_signer in signers
            or server_signer in signers
            or not collector_org
            or not server_org
            or collector_org == server_org
            or collector_org in organizations
            or server_org in organizations
            or any(
                _DIGEST.fullmatch(str(source.get(name) or "")) is None
                for name in digest_names
            )
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 1
                for value in integers
            )
            or source["pages_expected"] != source["pages_observed"]
            or source["server_total_records"] != source["records_observed"]
        ):
            raise TypeError("surface reconciliation source proof is invalid")
        kinds.add(kind)
        collectors.update((collector, server_collector))
        signers.update((collector_signer, server_signer))
        organizations.update((collector_org, server_org))
    return proof
