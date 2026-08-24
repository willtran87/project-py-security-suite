from __future__ import annotations

import base64
import hashlib
import re
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .strict_json import canonical_bytes, loads as strict_loads


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
    "page_receipts_base64",
    "server_total_records",
    "records_observed",
    "liveness_probes",
    "server_collector_id",
    "server_signer_id",
    "server_organization",
    "collected_at",
    "collector_subject",
    "collector_receipt",
    "server_subject",
    "server_receipt",
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
            collected_at = datetime.fromisoformat(str(source.get("collected_at")))
        except (TypeError, ValueError) as exc:
            raise TypeError(
                "surface reconciliation collection time is invalid"
            ) from exc
        if collected_at.tzinfo is None:
            raise TypeError("surface reconciliation collection time lacks a timezone")
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
        _verify_page_receipts(source)
        collector_subject = {
            "kind": kind,
            "sha256": source["snapshot_sha256"],
            "collector_organization": collector_org,
            "adapter_sha256": source["adapter_sha256"],
            "endpoint_identity_sha256": source["endpoint_identity_sha256"],
            "query_sha256": source["query_sha256"],
            "pages_expected": source["pages_expected"],
            "pages_observed": source["pages_observed"],
            "collection_complete": True,
            "collected_at": source["collected_at"],
            "page_receipts_sha256": source["page_receipts_sha256"],
            "server_total_records": source["server_total_records"],
        }
        server_subject = {
            **collector_subject,
            "liveness_probes": source["liveness_probes"],
            "server_organization": server_org,
        }
        if (
            source["collector_subject"] != collector_subject
            or source["server_subject"] != server_subject
        ):
            raise TypeError("surface reconciliation authority subject is detached")
        observed_at = collected_at.astimezone(UTC)
        collector_receipt = _verify_portable_authority(
            source["collector_receipt"],
            purpose=f"surface-inventory:{kind}",
            subject=source["collector_subject"],
            at=observed_at,
        )
        server_receipt = _verify_portable_authority(
            source["server_receipt"],
            purpose=f"surface-server-response:{kind}",
            subject=source["server_subject"],
            at=observed_at,
        )
        if (
            collector_receipt["signer_id"] != collector_signer
            or collector_receipt["collector_id"] != collector
            or server_receipt["signer_id"] != server_signer
            or server_receipt["collector_id"] != server_collector
        ):
            raise TypeError("surface reconciliation authority receipt is detached")
        kinds.add(kind)
        collectors.update((collector, server_collector))
        signers.update((collector_signer, server_signer))
        organizations.update((collector_org, server_org))
    return proof


def _verify_page_receipts(source: dict[str, Any]) -> None:
    try:
        raw = base64.b64decode(str(source["page_receipts_base64"]), validate=True)
    except (TypeError, ValueError) as exc:
        raise TypeError("surface page receipts encoding is invalid") from exc
    if (
        not raw
        or len(raw) > 64 * 1024 * 1024
        or hashlib.sha256(raw).hexdigest() != source["page_receipts_sha256"]
    ):
        raise TypeError("surface page receipts commitment does not match")
    try:
        receipts = strict_loads(raw)
    except (TypeError, ValueError) as exc:
        raise TypeError("surface page receipts are not strict JSON") from exc
    if not isinstance(receipts, list) or len(receipts) != source["pages_expected"]:
        raise TypeError("surface page receipt count does not match")
    previous = ""
    total = 0
    required = {
        "page_number",
        "request_sha256",
        "response_sha256",
        "continuation_in_sha256",
        "continuation_out_sha256",
        "record_count",
    }
    for index, item in enumerate(receipts, start=1):
        if not isinstance(item, dict) or set(item) != required:
            raise TypeError("surface page receipt is invalid")
        incoming = str(item.get("continuation_in_sha256") or "")
        outgoing = str(item.get("continuation_out_sha256") or "")
        count = item.get("record_count")
        if (
            item.get("page_number") != index
            or incoming != previous
            or _DIGEST.fullmatch(str(item.get("request_sha256") or "")) is None
            or _DIGEST.fullmatch(str(item.get("response_sha256") or "")) is None
            or (outgoing and _DIGEST.fullmatch(outgoing) is None)
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
        ):
            raise TypeError("surface page receipt chain is invalid")
        total += count
        previous = outgoing
    if previous or total != source["server_total_records"]:
        raise TypeError("surface page receipt chain is incomplete")


def _verify_portable_authority(
    value: object, *, purpose: str, subject: object, at: datetime
) -> dict[str, str]:
    fields = {
        "schema_version",
        "statement",
        "public_key_pem_base64",
        "public_key_sha256",
        "signature_base64",
        "signature_sha256",
        "receipt_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise TypeError("surface authority receipt fields do not match")
    receipt_subject = {name: value[name] for name in fields - {"receipt_sha256"}}
    if (
        value.get("schema_version") != "1.0"
        or value.get("receipt_sha256")
        != hashlib.sha256(canonical_bytes(receipt_subject)).hexdigest()
    ):
        raise TypeError("surface authority receipt commitment does not match")
    try:
        public_bytes = base64.b64decode(
            str(value["public_key_pem_base64"]), validate=True
        )
        signature = base64.b64decode(str(value["signature_base64"]), validate=True)
        public = serialization.load_pem_public_key(public_bytes)
    except (TypeError, ValueError) as exc:
        raise TypeError("surface authority receipt encoding is invalid") from exc
    statement = value.get("statement")
    base_fields = {
        "schema_version",
        "purpose",
        "subject_sha256",
        "signer_id",
        "collector_id",
        "signed_at",
        "expires_at",
    }
    if (
        not isinstance(statement, dict)
        or set(statement)
        not in {frozenset(base_fields), frozenset(base_fields | {"algorithm"})}
        or statement.get("purpose") != purpose
        or statement.get("subject_sha256")
        != hashlib.sha256(canonical_bytes(subject)).hexdigest()
        or not 1 <= len(public_bytes) <= 1024 * 1024
        or not 1 <= len(signature) <= 4096
        or hashlib.sha256(public_bytes).hexdigest() != value.get("public_key_sha256")
        or hashlib.sha256(signature).hexdigest() != value.get("signature_sha256")
    ):
        raise TypeError("surface authority receipt binding is invalid")
    try:
        signed_at = datetime.fromisoformat(str(statement["signed_at"]))
        expires_at = datetime.fromisoformat(str(statement["expires_at"]))
    except (TypeError, ValueError) as exc:
        raise TypeError("surface authority receipt time is invalid") from exc
    if signed_at.tzinfo is None or expires_at.tzinfo is None:
        raise TypeError("surface authority receipt time lacks a timezone")
    signed_at = signed_at.astimezone(UTC)
    expires_at = expires_at.astimezone(UTC)
    if not signed_at <= at <= expires_at or expires_at <= signed_at:
        raise TypeError("surface authority receipt is outside its validity window")
    algorithm = (
        "ed25519"
        if statement.get("schema_version") == "1.0"
        else str(statement.get("algorithm") or "")
    )
    try:
        if algorithm == "ed25519" and isinstance(public, Ed25519PublicKey):
            public.verify(signature, canonical_bytes(statement))
        elif (
            algorithm == "ecdsa-p256-sha256"
            and isinstance(public, ec.EllipticCurvePublicKey)
            and isinstance(public.curve, ec.SECP256R1)
        ):
            public.verify(
                signature, canonical_bytes(statement), ec.ECDSA(hashes.SHA256())
            )
        else:
            raise TypeError("surface authority receipt algorithm is unsupported")
    except Exception as exc:
        raise TypeError("surface authority receipt signature is invalid") from exc
    if isinstance(public, Ed25519PublicKey):
        identity_bytes = public.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    else:
        identity_bytes = public.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    signer_id = hashlib.sha256(identity_bytes).hexdigest()
    if statement.get("signer_id") != signer_id:
        raise TypeError("surface authority receipt signer identity is invalid")
    return {
        "signer_id": signer_id,
        "collector_id": str(statement.get("collector_id") or ""),
    }
