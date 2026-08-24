from __future__ import annotations

import argparse
import hashlib
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    from companion.evidence_authority import verify_authority
    from companion.semantic_assurance import analyze
    from companion.strict_json import dumps as strict_dumps
    from companion.strict_json import loads as strict_loads
    from companion.trusted_time import verify_rfc3161
except ModuleNotFoundError:  # Direct script execution.
    from evidence_authority import verify_authority  # type: ignore[import-not-found,no-redef]
    from semantic_assurance import analyze  # type: ignore[import-not-found,no-redef]
    from strict_json import dumps as strict_dumps  # type: ignore[import-not-found,no-redef]
    from strict_json import loads as strict_loads  # type: ignore[import-not-found,no-redef]
    from trusted_time import verify_rfc3161  # type: ignore[import-not-found,no-redef]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reconcile a declared surface against independent native inventories."
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = reconcile(args.input)
    _write(args.output, result)
    return 0


def reconcile(path: Path) -> dict[str, Any]:
    root = _object(_read(path), "surface inventory root")
    v1_fields = {
        "schema_version",
        "declared_file",
        "declared_sha256",
        "observed_sources",
        "canary_id",
    }
    v2_fields = v1_fields | {"observed_at"}
    v4_fields = v2_fields | {
        "history_file",
        "history_sha256",
        "trusted_time",
    }
    version = root.get("schema_version")
    if (
        (version == "1.0" and set(root) != v1_fields)
        or (version == "2.0" and set(root) != v2_fields)
        or (version == "3.0" and set(root) != v2_fields)
        or (version == "4.0" and set(root) != v4_fields)
        or version not in {"1.0", "2.0", "3.0", "4.0"}
    ):
        raise ValueError("surface inventory fields do not match a supported contract")
    observed_at = (
        _timestamp(
            root.get("observed_at"),
            "surface observed_at",
            enforce_fresh=version != "4.0",
        )
        if version in {"2.0", "3.0", "4.0"}
        else None
    )
    history: list[dict[str, Any]] | None = None
    trusted_time: dict[str, str] | None = None
    if version == "4.0":
        history_digest = str(root.get("history_sha256") or "")
        history_path = _pinned_sibling(path, root.get("history_file"), history_digest)
        history = _verify_history(_read(history_path))
        trusted_time = verify_rfc3161(path, root.get("trusted_time"), history_digest)
        if observed_at != _timestamp(
            trusted_time["trusted_time_observed_at"],
            "surface trusted time",
            enforce_fresh=False,
        ):
            raise ValueError("surface observed_at is detached from trusted time")
    declared = _records(
        _pinned_sibling(path, root.get("declared_file"), root.get("declared_sha256")),
        declared=True,
    )
    sources = root.get("observed_sources")
    if not isinstance(sources, list) or not 2 <= len(sources) <= 16:
        raise ValueError("surface inventory requires 2 to 16 independent sources")
    source_kinds: set[str] = set()
    collector_ids: set[str] = set()
    signer_ids: set[str] = set()
    organizations: set[str] = set()
    source_digests: set[str] = set()
    source_proofs: list[dict[str, object]] = []
    observed: dict[str, list[dict[str, str]]] = {}
    for source in sources:
        value = _object(source, "observed source")
        expected_source = {"kind", "file", "sha256"}
        if version in {"2.0", "3.0", "4.0"}:
            expected_source.add("authority")
        if version in {"3.0", "4.0"}:
            expected_source |= {
                "collector_organization",
                "adapter_sha256",
                "endpoint_identity_sha256",
                "query_sha256",
                "pages_expected",
                "pages_observed",
                "collection_complete",
                "collected_at",
                "page_receipts_file",
                "page_receipts_sha256",
                "server_total_records",
            }
        if version == "4.0":
            expected_source |= {"server_authority", "liveness_probes"}
        if set(value) != expected_source:
            raise ValueError("observed source fields do not match the contract")
        kind = _label(value.get("kind"), "source kind")
        if kind not in {"runtime", "gateway", "service-mesh", "cloud-control-plane"}:
            raise ValueError("observed source kind is unsupported")
        if kind in source_kinds:
            raise ValueError("observed source kinds must be independent")
        source_kinds.add(kind)
        digest = str(value.get("sha256") or "")
        if version in {"2.0", "3.0", "4.0"} and digest in source_digests:
            raise ValueError("observed sources must not reuse identical snapshots")
        source_digests.add(digest)
        if version in {"2.0", "3.0", "4.0"}:
            authority_subject: dict[str, object] = {"kind": kind, "sha256": digest}
            if version in {"3.0", "4.0"}:
                expected_pages = _positive_integer(
                    value.get("pages_expected"), "expected page count"
                )
                observed_pages = _positive_integer(
                    value.get("pages_observed"), "observed page count"
                )
                if value.get("collection_complete") is not True or (
                    observed_pages != expected_pages
                ):
                    raise ValueError("surface inventory pagination is incomplete")
                collected_at = _timestamp(
                    value.get("collected_at"),
                    "collected_at",
                    reference=observed_at,
                )
                organization = _label(
                    value.get("collector_organization"), "collector organization"
                )
                if organization in organizations:
                    raise ValueError(
                        "surface inventory requires distinct collector organizations"
                    )
                organizations.add(organization)
                for name in (
                    "adapter_sha256",
                    "endpoint_identity_sha256",
                    "query_sha256",
                ):
                    if not _digest(str(value.get(name) or "")):
                        raise ValueError(f"surface inventory {name} is invalid")
                authority_subject.update(
                    {
                        "collector_organization": organization,
                        "adapter_sha256": value["adapter_sha256"],
                        "endpoint_identity_sha256": value["endpoint_identity_sha256"],
                        "query_sha256": value["query_sha256"],
                        "pages_expected": expected_pages,
                        "pages_observed": observed_pages,
                        "collection_complete": True,
                        "collected_at": collected_at.isoformat(),
                        "page_receipts_sha256": value["page_receipts_sha256"],
                        "server_total_records": _positive_integer(
                            value.get("server_total_records"), "server total records"
                        ),
                    }
                )
                _verify_page_receipts(path, value, expected_pages)
            authority = verify_authority(
                path,
                value.get("authority"),
                purpose=f"surface-inventory:{kind}",
                subject=authority_subject,
                at=observed_at,
            )
            collector_subject = dict(authority_subject)
            if version in {"3.0", "4.0"}:
                _verify_collector_organization(
                    authority["signer_id"],
                    str(value["collector_organization"]),
                )
            if authority["collector_id"] in collector_ids:
                raise ValueError("observed sources require distinct collectors")
            if authority["signer_id"] in signer_ids:
                raise ValueError(
                    "observed sources require distinct signing authorities"
                )
            collector_ids.add(authority["collector_id"])
            signer_ids.add(authority["signer_id"])
            if version == "4.0":
                liveness = _positive_integer(
                    value.get("liveness_probes"), "surface liveness probes"
                )
                authority_subject["liveness_probes"] = liveness
                if liveness < 1:
                    raise ValueError("surface inventory requires liveness probes")
                server = verify_authority(
                    path,
                    value.get("server_authority"),
                    purpose=f"surface-server-response:{kind}",
                    subject=authority_subject,
                    at=observed_at,
                )
                server_subject = dict(authority_subject)
                if (
                    server["signer_id"] == authority["signer_id"]
                    or server["collector_id"] == authority["collector_id"]
                    or server["signer_id"] in signer_ids
                ):
                    raise ValueError(
                        "surface server receipts require an independent authority"
                    )
                if server["organization"] == organization:
                    raise ValueError(
                        "surface server and collector require distinct organizations"
                    )
                signer_ids.add(server["signer_id"])
        source_records = _records(
            _pinned_sibling(path, value.get("file"), value.get("sha256")),
            declared=False,
        )
        if (
            version in {"3.0", "4.0"}
            and len(source_records) != value["server_total_records"]
        ):
            raise ValueError("surface inventory server total does not match records")
        if version == "4.0":
            source_proofs.append(
                {
                    "kind": kind,
                    "snapshot_sha256": digest,
                    "collector_id": authority["collector_id"],
                    "collector_signer_id": authority["signer_id"],
                    "collector_organization": value["collector_organization"],
                    "adapter_sha256": value["adapter_sha256"],
                    "endpoint_identity_sha256": value["endpoint_identity_sha256"],
                    "query_sha256": value["query_sha256"],
                    "pages_expected": value["pages_expected"],
                    "pages_observed": value["pages_observed"],
                    "page_receipts_sha256": value["page_receipts_sha256"],
                    "server_total_records": value["server_total_records"],
                    "records_observed": len(source_records),
                    "liveness_probes": value["liveness_probes"],
                    "server_collector_id": server["collector_id"],
                    "server_signer_id": server["signer_id"],
                    "server_organization": server["organization"],
                    "collected_at": value["collected_at"],
                    "collector_subject": collector_subject,
                    "collector_receipt": authority["portable_receipt"],
                    "server_subject": server_subject,
                    "server_receipt": server["portable_receipt"],
                }
            )
        for record in source_records:
            observed.setdefault(record["id"], []).append(record)
    declared_by_id = {record["id"]: record for record in declared}
    if version == "4.0" and history is not None:
        current_ids = set(observed)
        last = history[-1]
        if set(last["record_ids"]) != current_ids or observed_at != _timestamp(
            last["observed_at"], "history observed_at", enforce_fresh=False
        ):
            raise ValueError("surface history is detached from the current inventory")
    cases: list[dict[str, str]] = []
    canary_id = _label(root.get("canary_id"), "canary ID")
    if (
        canary_id not in declared_by_id
        or declared_by_id[canary_id]["status"] != "active"
    ):
        raise ValueError("surface inventory canary must identify an active declaration")
    for identifier, declaration in declared_by_id.items():
        matches = observed.get(identifier, [])
        control = (
            "declared-observed"
            if declaration["status"] == "active"
            else "retired-absence"
        )
        expected = "present" if declaration["status"] == "active" else "absent"
        cases.append(
            _case(
                f"presence:{identifier}",
                identifier,
                control,
                expected,
                "present" if matches else "absent",
            )
        )
        metadata_matches = (
            not matches
            if declaration["status"] == "retired"
            else bool(matches)
            and all(
                record["version"] == declaration["version"]
                and record["owner"] == declaration["owner"]
                for record in matches
            )
        )
        cases.append(
            _case(
                f"metadata:{identifier}",
                identifier,
                "version-ownership",
                "pass",
                "pass" if metadata_matches else "detected",
            )
        )
    for identifier in sorted(set(observed) - set(declared_by_id)):
        cases.append(
            _case(
                f"shadow:{identifier}",
                identifier,
                "shadow-surface",
                "clean",
                "detected",
            )
        )
    if not any(case["control"] == "retired-absence" for case in cases):
        cases.append(
            _case(
                "retired:none",
                "surface-inventory",
                "retired-absence",
                "absent",
                "absent",
            )
        )
    if not any(case["control"] == "shadow-surface" for case in cases):
        cases.append(
            _case(
                "shadow:none", "surface-inventory", "shadow-surface", "clean", "clean"
            )
        )
    result = analyze(
        {
            "schema_version": "1.0",
            "kind": "surface-inventory",
            "cases": cases,
            "canary_id": f"presence:{canary_id}",
        },
        "surface-inventory",
    )
    result["execution"]["coverage_metric"] = (
        "independent-native-inventory-reconciliation"
    )
    result["execution"]["features"].extend(
        sorted(f"source:{kind}" for kind in source_kinds)
    )
    if version in {"2.0", "3.0", "4.0"}:
        result["execution"]["features"].extend(
            ["independent-collectors", "independent-signers", "signed-freshness"]
        )
    if version in {"3.0", "4.0"}:
        result["execution"]["features"].extend(
            [
                "collector-organization-bound",
                "adapter-attestation",
                "endpoint-and-query-bound",
                "pagination-completeness",
            ]
        )
    if version == "4.0":
        if trusted_time is None:  # Defensive invariant for type narrowing.
            raise ValueError("surface trusted time verification is unavailable")
        proof_subject = {
            "schema_version": "1.0",
            "declared_sha256": root["declared_sha256"],
            "history_sha256": root["history_sha256"],
            "trusted_time_sha256": trusted_time["trusted_time_sha256"],
            "sources": sorted(source_proofs, key=lambda item: str(item["kind"])),
        }
        result["execution"]["surface_proof"] = {
            **proof_subject,
            "proof_sha256": hashlib.sha256(
                strict_dumps(proof_subject).encode("utf-8")
            ).hexdigest(),
        }
        result["execution"]["features"].extend(
            [
                "server-signed-page-chain",
                "rfc3161-collection-history",
                "tombstone-history",
                "signed-total-count",
                "liveness-probes",
            ]
        )
    return result


def _case(
    identifier: str, target: str, control: str, expected: str, observed: str
) -> dict[str, str]:
    return {
        "id": identifier,
        "target_id": target,
        "role": "inventory",
        "control": control,
        "expected": expected,
        "observed": observed,
        "severity": "high",
        "classification": "CWE-1059",
    }


def _records(path: Path, *, declared: bool) -> list[dict[str, str]]:
    value = _read(path)
    if not isinstance(value, list) or not 1 <= len(value) <= 100_000:
        raise ValueError("surface records must be a bounded non-empty list")
    records: list[dict[str, str]] = []
    expected = (
        {"id", "version", "owner", "status"} if declared else {"id", "version", "owner"}
    )
    for item in value:
        record = _object(item, "surface record")
        if set(record) != expected:
            raise ValueError("surface record fields do not match the contract")
        normalized = {
            "id": _label(record.get("id"), "surface ID"),
            "version": _label(record.get("version"), "surface version"),
            "owner": _label(record.get("owner"), "surface owner"),
        }
        if declared:
            status = str(record.get("status") or "")
            if status not in {"active", "retired"}:
                raise ValueError("declared surface status is invalid")
            normalized["status"] = status
        records.append(normalized)
    if len({record["id"] for record in records}) != len(records):
        raise ValueError("surface record IDs must be unique per source")
    return records


def _pinned_sibling(context: Path, name: object, digest: object) -> Path:
    filename = str(name or "")
    expected = str(digest or "")
    if not filename or Path(filename).name != filename:
        raise ValueError("surface source must be a sibling file")
    path = context.resolve().parent / filename
    raw = _raw(path)
    if len(expected) != 64 or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("surface source SHA-256 does not match")
    return path


def _read(path: Path) -> object:
    return strict_loads(_raw(path))


def _raw(path: Path) -> bytes:
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > 64 * 1024 * 1024
    ):
        raise ValueError("surface source must be a bounded regular file")
    return path.read_bytes()


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be an object")
    return value


def _label(value: object, label: str) -> str:
    result = str(value or "").strip()
    if (
        not result
        or len(result) > 200
        or any(ord(character) < 32 for character in result)
    ):
        raise ValueError(f"{label} is invalid")
    return result


def _timestamp(
    value: object,
    label: str,
    *,
    reference: datetime | None = None,
    enforce_fresh: bool = True,
) -> datetime:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    if result.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    normalized = result.astimezone(UTC)
    if (
        enforce_fresh
        and abs(((reference or datetime.now(UTC)) - normalized).total_seconds())
        > 24 * 60 * 60
    ):
        raise ValueError(f"{label} is stale or in the future")
    return normalized


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be positive")
    return value


def _verify_page_receipts(context: Path, source: dict[str, Any], pages: int) -> None:
    receipt_path = _pinned_sibling(
        context,
        source.get("page_receipts_file"),
        source.get("page_receipts_sha256"),
    )
    value = _read(receipt_path)
    if not isinstance(value, list) or len(value) != pages:
        raise ValueError("surface inventory page receipt count does not match")
    previous = ""
    total = 0
    for index, item in enumerate(value, start=1):
        required = {
            "page_number",
            "request_sha256",
            "response_sha256",
            "continuation_in_sha256",
            "continuation_out_sha256",
            "record_count",
        }
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError("surface inventory page receipt is invalid")
        incoming = str(item.get("continuation_in_sha256") or "")
        outgoing = str(item.get("continuation_out_sha256") or "")
        if (
            item.get("page_number") != index
            or incoming != previous
            or not _digest(str(item.get("request_sha256") or ""))
            or not _digest(str(item.get("response_sha256") or ""))
            or (outgoing and not _digest(outgoing))
        ):
            raise ValueError("surface inventory page receipt chain is invalid")
        count = item.get("record_count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("surface inventory page record count is invalid")
        total += count
        previous = outgoing
    if previous or total != source.get("server_total_records"):
        raise ValueError("surface inventory page chain is incomplete")


def _verify_collector_organization(signer_id: str, organization: str) -> None:
    try:
        policy = strict_loads(os.environ.get("PYSEC_AUTHORITY_ORGANIZATIONS", ""))
    except (TypeError, ValueError) as exc:
        raise ValueError("surface organization policy is invalid") from exc
    if not isinstance(policy, dict) or policy.get(signer_id) != organization:
        raise ValueError(
            "surface collector organization is not deployment-bound to its signer"
        )


def _verify_history(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 2 <= len(value) <= 10_000:
        raise ValueError("surface history requires 2 to 10000 windows")
    previous: datetime | None = None
    snapshots: set[str] = set()
    previous_item: dict[str, Any] | None = None
    normalized: list[dict[str, Any]] = []
    for item in value:
        required = {
            "observed_at",
            "snapshot_sha256",
            "record_ids",
            "tombstone_ids",
            "total_records",
            "previous_window_sha256",
        }
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError("surface history window fields do not match")
        observed = _history_timestamp(item.get("observed_at"))
        snapshot = str(item.get("snapshot_sha256") or "")
        record_ids = item.get("record_ids")
        tombstones = item.get("tombstone_ids")
        total = item.get("total_records")
        previous_digest = str(item.get("previous_window_sha256") or "")
        if (
            (previous is not None and observed <= previous)
            or not _digest(snapshot)
            or snapshot in snapshots
            or not isinstance(record_ids, list)
            or len(record_ids) != len(set(record_ids))
            or any(
                not isinstance(record_id, str) or not record_id
                for record_id in record_ids
            )
            or not isinstance(tombstones, list)
            or len(tombstones) != len(set(tombstones))
            or any(
                not isinstance(record_id, str) or not record_id
                for record_id in tombstones
            )
            or isinstance(total, bool)
            or not isinstance(total, int)
            or total < 0
            or total != len(record_ids)
            or snapshot
            != hashlib.sha256(strict_dumps(sorted(record_ids)).encode()).hexdigest()
        ):
            raise ValueError("surface history continuity is invalid")
        expected_previous = (
            "0" * 64
            if previous_item is None
            else hashlib.sha256(strict_dumps(previous_item).encode()).hexdigest()
        )
        if previous_digest != expected_previous:
            raise ValueError("surface history hash chain is invalid")
        if previous_item is not None:
            expected_tombstones = set(previous_item["record_ids"]) - set(record_ids)
            if set(tombstones) != expected_tombstones:
                raise ValueError(
                    "surface history tombstones do not match removed records"
                )
        elif tombstones:
            raise ValueError("surface history genesis cannot contain tombstones")
        previous = observed
        snapshots.add(snapshot)
        previous_item = dict(item)
        normalized.append(dict(item))
    return normalized


def _history_timestamp(value: object) -> datetime:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("surface history timestamp is invalid") from exc
    if result.tzinfo is None:
        raise ValueError("surface history timestamp requires a timezone")
    return result.astimezone(UTC)


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (strict_dumps(value, indent=2) + "\n").encode()
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


if __name__ == "__main__":
    raise SystemExit(main())
