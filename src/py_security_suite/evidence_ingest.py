from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import hashlib
import math
import os
import ssl
import sqlite3
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from defusedxml import ElementTree as DefusedET  # type: ignore[import-untyped]
from defusedxml.common import DefusedXmlException  # type: ignore[import-untyped]

from .version import __version__
from .assurance_profile import enforce_assurance_profile, load_assurance_profile
from .control_proof import verify_control_proof
from .inventory import source_snapshot
from .strict_json import canonical_bytes, dumps as strict_dumps, loads as strict_loads
from .trusted_time import verify_rfc3161
from .trusted_observation import governed_now

_MAX_REPORT_BYTES = 64 * 1024 * 1024
_MAX_JUNIT_REPORTS = 128
_MAX_JUNIT_TEST_CASES = 100_000
_ASSURANCE_KINDS = frozenset(
    {
        "atheris",
        "authorization-security",
        "ai-security",
        "browser-security",
        "check-manifest",
        "clamav",
        "cloud-attack-path",
        "database-security",
        "event-security",
        "clusterfuzzlite",
        "crosshair",
        "falco",
        "fuzz-introspector",
        "github-attestation",
        "iast",
        "in-toto",
        "kubescape",
        "llm-adversarial",
        "mobsf",
        "mutmut",
        "native-sanitizers",
        "nuclei",
        "oast",
        "oci-image",
        "polyglot",
        "prowler",
        "protocol-security",
        "pytm",
        "rasp",
        "reproducible-build",
        "ruleset-regression",
        "restler",
        "secret-verification",
        "tls-scan",
        "surface-inventory",
        "yara",
        "zap",
    }
)
_MAX_ASSURANCE_FINDINGS = 10_000
_BINDING_SUFFIX = ".pysec-binding.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pysec-evidence",
        description="Validate pre-generated test evidence without executing target code.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="kind", required=True)
    coverage = subparsers.add_parser("coverage")
    coverage.add_argument("path", type=Path)
    junit = subparsers.add_parser("junit")
    junit.add_argument("path", type=Path)
    bind = subparsers.add_parser(
        "bind",
        help="bind pre-generated evidence to the current non-evidence source snapshot",
    )
    bind.add_argument("paths", type=Path, nargs="+")
    bind.add_argument("--source-root", type=Path, required=True)
    bind.add_argument("--overwrite", action="store_true")
    bind.add_argument("--signing-key", type=Path)
    bind.add_argument(
        "--additional-signing-key", type=Path, action="append", default=[]
    )
    bind.add_argument("--key-id", default="")
    bind.add_argument("--valid-for-hours", type=float, default=24.0)
    bind.add_argument("--run-id", default="")
    bind.add_argument(
        "--external-envelope-dir",
        type=Path,
        help="directory containing externally signed <evidence>.dsse.json envelopes",
    )
    scorecard = subparsers.add_parser("scorecard")
    scorecard.add_argument("path", type=Path)
    assurance = subparsers.add_parser("assurance")
    assurance.add_argument("evidence_kind", choices=sorted(_ASSURANCE_KINDS))
    assurance.add_argument("path", type=Path)
    assurance.add_argument("--maximum-age-days", type=float, default=7.0)
    assurance.add_argument("--minimum-coverage-percent", type=float, default=80.0)
    assurance.add_argument("--require-contract-v2", action="store_true")
    assurance.add_argument("--public-key", type=Path)
    assurance.add_argument("--public-keyring", type=Path)
    assurance.add_argument("--require-signature", action="store_true")
    assurance.add_argument("--expected-run-id", default="")
    assurance.add_argument("--expected-environment-sha256", default="")
    assurance.add_argument("--expected-context", type=Path)
    assurance.add_argument("--consume-replay-ledger", type=Path)
    assurance.add_argument("--consume-replay-service")
    assurance.add_argument("--replay-service-token-env", default="")
    assurance.add_argument("--replay-service-ca", type=Path)
    assurance.add_argument("--replay-service-receipt-key", type=Path)
    assurance.add_argument("--replay-service-client-cert", type=Path)
    assurance.add_argument("--replay-service-client-key", type=Path)
    assurance.add_argument("--allowed-builder-id", action="append", default=[])
    assurance.add_argument("--expected-build-type", default="")
    assurance.add_argument("--expected-source-repository", default="")
    assurance.add_argument(
        "--assurance-profile",
        type=Path,
        help="threshold-signed deployment profile that sets minimum contracts and features",
    )
    assurance.add_argument(
        "--require-assurance-profile",
        action="store_true",
        help="fail closed unless a checkpointed v2 assurance profile is supplied",
    )
    args = parser.parse_args(argv)
    try:
        if args.kind == "bind":
            document = _bind_evidence(
                args.paths,
                source_root=args.source_root,
                overwrite=args.overwrite,
                signing_key=args.signing_key,
                additional_signing_keys=args.additional_signing_key,
                key_id=args.key_id,
                valid_for_hours=args.valid_for_hours,
                run_id=args.run_id,
                external_envelope_dir=args.external_envelope_dir,
            )
        elif args.kind == "coverage":
            document = _coverage_document(args.path)
        elif args.kind == "junit":
            document = _junit_document(args.path)
        elif args.kind == "scorecard":
            document = _scorecard_document(args.path)
        else:
            document = _assurance_document(
                args.path,
                args.evidence_kind,
                maximum_age_days=args.maximum_age_days,
                minimum_coverage_percent=args.minimum_coverage_percent,
                require_contract_v2=args.require_contract_v2,
                public_key=args.public_key,
                public_keyring=args.public_keyring,
                require_signature=args.require_signature,
                expected_run_id=args.expected_run_id,
                expected_environment_sha256=args.expected_environment_sha256,
                expected_context=args.expected_context,
                replay_ledger=args.consume_replay_ledger,
                replay_service=args.consume_replay_service,
                replay_service_token_env=args.replay_service_token_env,
                replay_service_ca=args.replay_service_ca,
                replay_service_receipt_key=args.replay_service_receipt_key,
                replay_service_client_cert=args.replay_service_client_cert,
                replay_service_client_key=args.replay_service_client_key,
                allowed_builder_ids=tuple(args.allowed_builder_id),
                expected_build_type=args.expected_build_type,
                expected_source_repository=args.expected_source_repository,
                assurance_profile=args.assurance_profile,
                require_assurance_profile=args.require_assurance_profile,
            )
    except (OSError, TypeError, ValueError, DefusedXmlException) as exc:
        print(f"invalid {args.kind} evidence: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(strict_dumps(document) + "\n")
    return 0


def _read_bounded(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"report is not a regular file: {path}")
    size = path.stat().st_size
    if size > _MAX_REPORT_BYTES:
        raise ValueError(f"report exceeds {_MAX_REPORT_BYTES} bytes: {path}")
    return path.read_bytes()


def _bind_evidence(
    paths: list[Path],
    *,
    source_root: Path,
    overwrite: bool,
    signing_key: Path | None = None,
    additional_signing_keys: list[Path] | None = None,
    key_id: str = "",
    valid_for_hours: float = 24.0,
    run_id: str = "",
    external_envelope_dir: Path | None = None,
) -> dict[str, Any]:
    if source_root.is_symlink() or not source_root.is_dir():
        raise ValueError(f"source root is not a regular directory: {source_root}")
    if len(paths) > 16:
        raise ValueError("at most 16 evidence paths may be bound together")
    if not 0.01 <= valid_for_hours <= 24.0 * 365.0:
        raise ValueError("valid_for_hours must be between 0.01 and 8760")
    signing_paths = ([signing_key] if signing_key else []) + list(
        additional_signing_keys or []
    )
    if len(signing_paths) > 16:
        raise ValueError("at most 16 evidence signing keys may be configured")
    private_keys = [_load_private_key(path) for path in signing_paths]
    if private_keys and external_envelope_dir is not None:
        raise ValueError(
            "local signing keys and external envelopes are mutually exclusive"
        )
    if external_envelope_dir is not None and (
        external_envelope_dir.is_symlink() or not external_envelope_dir.is_dir()
    ):
        raise ValueError("external envelope directory is not a regular directory")
    effective_run_id = _run_identifier(run_id) if private_keys else ""
    resolved_paths: list[Path] = []
    for path in paths:
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError(f"evidence path does not exist or is linked: {path}")
        resolved_paths.append(path.resolve())
    sidecars = [_binding_path(path) for path in resolved_paths]
    digest, files, total_bytes = source_snapshot(
        source_root.resolve(),
        excluded_paths=tuple(
            [
                *resolved_paths,
                *sidecars,
                *([external_envelope_dir.resolve()] if external_envelope_dir else []),
            ]
        ),
    )
    bindings: list[dict[str, Any]] = []
    for path, sidecar in zip(resolved_paths, sidecars, strict=True):
        evidence_sha256 = _evidence_sha256(path)
        if external_envelope_dir is not None:
            binding = _external_binding(
                external_envelope_dir / f"{path.name}.dsse.json",
                evidence_path=path,
                evidence_sha256=evidence_sha256,
                source_sha256=digest,
            )
            envelope_payload = base64.b64decode(
                binding["envelope"]["payload"], validate=True
            )
            external_statement = strict_loads(envelope_payload)
            effective_run_id = str(external_statement["predicate"]["run_id"])
        elif not private_keys:
            binding = {
                "schema_version": "1.0",
                "source_sha256": digest,
                "evidence_sha256": evidence_sha256,
            }
        else:
            binding = _signed_binding(
                private_keys,
                evidence_name=path.name,
                evidence_sha256=evidence_sha256,
                source_sha256=digest,
                key_id=key_id,
                valid_for_hours=valid_for_hours,
                run_id=effective_run_id,
            )
        _write_binding(sidecar, binding, overwrite=overwrite)
        bindings.append(
            {
                "evidence_path": str(path),
                "binding_path": str(sidecar),
                "evidence_sha256": evidence_sha256,
                "authenticated": bool(private_keys),
                "externally_signed": external_envelope_dir is not None,
            }
        )
    return {
        "schema_version": "1.0",
        "kind": "evidence-binding",
        "source_root": str(source_root.resolve()),
        "source_sha256": digest,
        "source_files": files,
        "source_bytes": total_bytes,
        "bindings": bindings,
        "authenticated": bool(private_keys),
        "externally_signed": external_envelope_dir is not None,
        "run_id": effective_run_id,
    }


def _external_binding(
    envelope_path: Path,
    *,
    evidence_path: Path,
    evidence_sha256: str,
    source_sha256: str,
) -> dict[str, Any]:
    if envelope_path.is_symlink() or not envelope_path.is_file():
        raise ValueError(f"external DSSE envelope is missing: {envelope_path.name}")
    external = strict_loads(_read_bounded(envelope_path))
    timestamp_records: list[object] | None = None
    if isinstance(external, dict) and set(external) == {
        "schema_version",
        "envelope",
        "signature_timestamps",
    }:
        if external.get("schema_version") != "1.0":
            raise ValueError("external countersignature wrapper version is invalid")
        envelope = external.get("envelope")
        raw_records = external.get("signature_timestamps")
        if not isinstance(raw_records, list) or not raw_records:
            raise ValueError("external countersignature wrapper requires timestamps")
        timestamp_records = raw_records
    else:
        envelope = external
    if not isinstance(envelope, dict) or set(envelope) != {
        "payloadType",
        "payload",
        "signatures",
    }:
        raise ValueError("external DSSE envelope fields do not match the contract")
    binding: dict[str, Any] = {
        "schema_version": "3.0" if timestamp_records is not None else "2.0",
        "source_sha256": source_sha256,
        "evidence_sha256": evidence_sha256,
        "envelope": envelope,
    }
    if timestamp_records is not None:
        binding["signature_timestamps"] = timestamp_records
    try:
        statement = strict_loads(
            base64.b64decode(str(envelope["payload"]), validate=True)
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("external DSSE envelope payload is invalid") from exc
    _validate_attestation_statement(statement, binding, evidence_path)
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise ValueError("external DSSE envelope has no signatures")
    return binding


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"signing key is not a regular file: {path}")
    key = serialization.load_pem_private_key(_read_bounded(path), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("signing key must be an unencrypted Ed25519 PEM key")
    return key


def _load_public_key(path: Path) -> Ed25519PublicKey:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"public key is not a regular file: {path}")
    key = serialization.load_pem_public_key(_read_bounded(path))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key must be an Ed25519 PEM key")
    return key


def _run_identifier(value: str) -> str:
    candidate = value.strip() or str(uuid.uuid4())
    if len(candidate) > 200 or not all(
        character.isalnum() or character in "._:-" for character in candidate
    ):
        raise ValueError("run_id contains unsupported characters")
    return candidate


def _canonical_json(value: object) -> bytes:
    return canonical_bytes(value)


def _dsse_pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    return b" ".join(
        (
            b"DSSEv1",
            str(len(type_bytes)).encode("ascii"),
            type_bytes,
            str(len(payload)).encode("ascii"),
            payload,
        )
    )


def _signed_binding(
    private_keys: list[Ed25519PrivateKey],
    *,
    evidence_name: str,
    evidence_sha256: str,
    source_sha256: str,
    key_id: str,
    valid_for_hours: float,
    run_id: str,
) -> dict[str, Any]:
    created = governed_now()
    expires = created + timedelta(hours=valid_for_hours)
    requested_key_id = key_id.strip()
    if requested_key_id and len(private_keys) != 1:
        raise ValueError("key_id may only be used with one signing key")
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": evidence_name, "digest": {"sha256": evidence_sha256}}],
        "predicateType": (
            "https://willtran87.github.io/project-py-security-suite/"
            "attestation/companion-evidence/v2"
        ),
        "predicate": {
            "source_sha256": source_sha256,
            "run_id": run_id,
            "created_at": created.isoformat(),
            "expires_at": expires.isoformat(),
        },
    }
    payload_type = "application/vnd.in-toto+json"
    payload = _canonical_json(statement)
    signatures = []
    for private_key in private_keys:
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        derived_key_id = hashlib.sha256(public_bytes).hexdigest()
        if requested_key_id and requested_key_id != derived_key_id:
            raise ValueError("key_id must equal the signing public key SHA-256")
        signatures.append(
            {
                "keyid": derived_key_id,
                "sig": base64.b64encode(
                    private_key.sign(_dsse_pae(payload_type, payload))
                ).decode("ascii"),
            }
        )
    if len({value["keyid"] for value in signatures}) != len(signatures):
        raise ValueError("evidence signing keys must be distinct")
    return {
        "schema_version": "2.0",
        "source_sha256": source_sha256,
        "evidence_sha256": evidence_sha256,
        "envelope": {
            "payloadType": payload_type,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": signatures,
        },
    }


def _apply_source_binding(
    document: dict[str, Any],
    path: Path,
    *,
    public_key: Path | None = None,
    public_keyring: Path | None = None,
    require_signature: bool = False,
) -> dict[str, Any]:
    sidecar = _binding_path(path.resolve())
    if not sidecar.exists():
        return document
    binding = strict_loads(_read_bounded(sidecar))
    if not isinstance(binding, dict):
        raise ValueError("evidence source binding fields do not match the contract")
    binding_version = binding.get("schema_version")
    expected_fields = {
        "1.0": {"schema_version", "source_sha256", "evidence_sha256"},
        "2.0": {
            "schema_version",
            "source_sha256",
            "evidence_sha256",
            "envelope",
        },
        "3.0": {
            "schema_version",
            "source_sha256",
            "evidence_sha256",
            "envelope",
            "signature_timestamps",
        },
    }.get(str(binding_version))
    if expected_fields is None or set(binding) != expected_fields:
        raise ValueError("evidence source binding fields do not match the contract")
    source_sha256 = binding.get("source_sha256")
    evidence_sha256 = binding.get("evidence_sha256")
    if not _digest(source_sha256) or not _digest(evidence_sha256):
        raise ValueError("evidence source binding contains an invalid digest")
    observed = _evidence_sha256(path.resolve())
    if observed != evidence_sha256:
        raise ValueError("evidence source binding does not match the evidence payload")
    authenticated = False
    attestation: dict[str, Any] | None = None
    if binding_version in {"2.0", "3.0"}:
        attestation = _verify_signed_binding(binding, path, public_key, public_keyring)
        authenticated = attestation["verified"] is True
        if authenticated and document.get("schema_version") == "2.0":
            if attestation.get("run_id") != document.get("run_id"):
                raise ValueError(
                    "evidence run_id does not match its signed attestation"
                )
            evidence_expiry = _timestamp(document.get("expires_at"), "expires_at")
            attestation_expiry = _timestamp(
                attestation.get("expires_at"), "attestation expires_at"
            )
            if attestation_expiry > evidence_expiry + timedelta(minutes=5):
                raise ValueError(
                    "signed attestation validity exceeds the evidence validity window"
                )
    if require_signature and not authenticated:
        raise ValueError("evidence requires a verified Ed25519 DSSE/in-toto signature")
    document["source_sha256"] = source_sha256
    document["evidence_binding"] = {
        "schema_version": str(binding_version),
        "evidence_sha256": evidence_sha256,
        "binding_file": sidecar.name,
        "verified": True,
        "authenticated": authenticated,
    }
    if attestation is not None:
        document["evidence_binding"]["attestation"] = attestation
    return document


def _verify_signed_binding(
    binding: dict[str, Any],
    evidence_path: Path,
    public_key_path: Path | None,
    public_keyring_path: Path | None,
) -> dict[str, Any]:
    if public_key_path is None and public_keyring_path is None:
        return {"verified": False, "reason": "trusted public key was not configured"}
    if public_key_path is not None and public_keyring_path is not None:
        raise ValueError("configure a public key or public keyring, not both")
    envelope = binding.get("envelope")
    if not isinstance(envelope, dict) or set(envelope) != {
        "payloadType",
        "payload",
        "signatures",
    }:
        raise ValueError("signed evidence binding has an invalid DSSE envelope")
    payload_type = envelope.get("payloadType")
    signatures = envelope.get("signatures")
    if payload_type != "application/vnd.in-toto+json":
        raise ValueError("signed evidence binding has an invalid payload type")
    if not isinstance(signatures, list) or not 1 <= len(signatures) <= 16:
        raise ValueError("signed evidence binding must contain 1 to 16 signatures")
    try:
        payload = base64.b64decode(str(envelope.get("payload")), validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("signed evidence binding is not valid base64") from exc
    try:
        statement = strict_loads(payload)
    except (TypeError, ValueError) as exc:
        raise ValueError("signed evidence binding statement is invalid JSON") from exc
    _validate_attestation_statement(statement, binding, evidence_path)
    predicate = statement["predicate"]
    created = _timestamp(predicate["created_at"], "attestation created_at")
    trusted, threshold = _trusted_public_keys(
        public_key_path, public_keyring_path, created
    )
    verified_ids: list[str] = []
    for signature_entry in signatures:
        if not isinstance(signature_entry, dict) or set(signature_entry) != {
            "keyid",
            "sig",
        }:
            raise ValueError("signed evidence binding signature is invalid")
        declared_key_id = str(signature_entry.get("keyid") or "")
        if declared_key_id in verified_ids or declared_key_id not in trusted:
            continue
        try:
            signature = base64.b64decode(str(signature_entry.get("sig")), validate=True)
            trusted[declared_key_id].verify(signature, _dsse_pae(payload_type, payload))
        except (InvalidSignature, ValueError, TypeError):
            continue
        verified_ids.append(declared_key_id)
    if len(verified_ids) < threshold:
        raise ValueError(
            "signed evidence binding did not meet its trusted signature threshold"
        )
    timestamp_receipts: list[str] = []
    if binding.get("schema_version") == "3.0":
        timestamp_receipts = _verify_signature_timestamps(
            binding.get("signature_timestamps"),
            signatures,
            verified_ids,
            evidence_path,
        )
    return {
        "verified": True,
        "key_id": verified_ids[0],
        "key_ids": sorted(verified_ids),
        "signature_count": len(verified_ids),
        "run_id": predicate["run_id"],
        "created_at": predicate["created_at"],
        "expires_at": predicate["expires_at"],
        "predicate_type": statement["predicateType"],
        "signature_timestamp_count": len(timestamp_receipts),
        "signature_timestamp_receipts": timestamp_receipts,
    }


def _verify_signature_timestamps(
    value: object,
    signatures: list[object],
    verified_ids: list[str],
    evidence_path: Path,
) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        raise ValueError("signature timestamps must contain 1 to 16 records")
    signature_by_key: dict[str, bytes] = {}
    for item in signatures:
        if isinstance(item, dict):
            try:
                signature_by_key[str(item.get("keyid") or "")] = base64.b64decode(
                    str(item.get("sig") or ""), validate=True
                )
            except (TypeError, ValueError):
                continue
    receipts: list[str] = []
    seen: set[str] = set()
    for record in value:
        if not isinstance(record, dict) or set(record) != {"keyid", "trusted_time"}:
            raise ValueError("signature timestamp fields do not match the contract")
        key_id = str(record.get("keyid") or "")
        if key_id in seen or key_id not in verified_ids:
            raise ValueError("signature timestamp identifies an untrusted signer")
        seen.add(key_id)
        signature = signature_by_key.get(key_id)
        if signature is None:
            raise ValueError("signature timestamp has no matching DSSE signature")
        result = verify_rfc3161(
            evidence_path,
            record.get("trusted_time"),
            hashlib.sha256(signature).hexdigest(),
        )
        receipts.append(result["trusted_time_receipt_sha256"])
    if seen != set(verified_ids):
        raise ValueError(
            "every trusted DSSE signature requires a countersigned timestamp"
        )
    return sorted(receipts)


def _trusted_public_keys(
    public_key_path: Path | None,
    keyring_path: Path | None,
    created: datetime,
) -> tuple[dict[str, Ed25519PublicKey], int]:
    if public_key_path is not None:
        key = _load_public_key(public_key_path)
        key_id = _public_key_id(key)
        return {key_id: key}, 1
    if keyring_path is None:  # Defensive narrowing for static analysis.
        raise ValueError("public keyring was not configured")
    payload = strict_loads(_read_bounded(keyring_path))
    v1_fields = {
        "schema_version",
        "threshold",
        "keys",
    }
    v2_extra = {
        "generation",
        "previous_keyring_sha256",
        "compromised_key_ids",
        "root_key_file",
        "root_key_sha256",
        "root_signature_file",
        "root_signature_sha256",
    }
    if not isinstance(payload, dict):
        raise TypeError("public keyring must be an object")
    version = payload.get("schema_version")
    if (
        (version == "1.0" and set(payload) != v1_fields)
        or (version == "2.0" and set(payload) != v1_fields | v2_extra)
        or (version == "3.0" and set(payload) != v1_fields | v2_extra)
        or version not in {"1.0", "2.0", "3.0"}
    ):
        raise ValueError("public keyring fields do not match a supported contract")
    compromised: dict[str, datetime | None] = {}
    if version in {"2.0", "3.0"}:
        compromised = _verify_keyring_root(payload, keyring_path)
    threshold = _nonnegative_integer(payload.get("threshold"))
    records = payload.get("keys")
    if not isinstance(records, list) or not 1 <= len(records) <= 32:
        raise ValueError("public keyring must contain 1 to 32 keys")
    trusted: dict[str, Ed25519PublicKey] = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "file",
            "sha256",
            "not_before",
            "not_after",
            "status",
        }:
            raise ValueError("public keyring key fields do not match the contract")
        name = str(record.get("file") or "")
        if not name or Path(name).name != name:
            raise ValueError("public keyring files must be sibling filenames")
        path = keyring_path.resolve().parent / name
        raw = _read_bounded(path)
        if hashlib.sha256(raw).hexdigest() != record.get("sha256"):
            raise ValueError("public keyring key SHA-256 does not match")
        not_before = _timestamp(record.get("not_before"), "key not_before")
        not_after = _timestamp(record.get("not_after"), "key not_after")
        status = str(record.get("status") or "")
        if status not in {"active", "retired", "revoked"}:
            raise ValueError("public keyring key status is invalid")
        key = _load_public_key(path)
        key_identity = _public_key_id(key)
        compromised_at = compromised.get(key_identity)
        if (
            status == "revoked"
            or (
                key_identity in compromised
                and (compromised_at is None or created >= compromised_at)
            )
            or not not_before <= created <= not_after
        ):
            continue
        trusted[key_identity] = key
    if threshold < 1 or threshold > len(trusted):
        raise ValueError("public keyring threshold cannot be met")
    return trusted, threshold


def _verify_keyring_root(
    payload: dict[str, Any], keyring_path: Path
) -> dict[str, datetime | None]:
    generation = _nonnegative_integer(payload.get("generation"))
    if generation < 1:
        raise ValueError("public keyring generation must be positive")
    previous = str(payload.get("previous_keyring_sha256") or "")
    if (generation == 1 and previous) or (generation > 1 and not _digest(previous)):
        raise ValueError("public keyring rotation predecessor is invalid")
    compromised_value = payload.get("compromised_key_ids")
    if not isinstance(compromised_value, list) or len(compromised_value) > 32:
        raise ValueError("public keyring compromised key list is invalid")
    version = str(payload.get("schema_version"))
    compromised: dict[str, datetime | None] = {}
    if version == "2.0":
        identities = [str(value or "") for value in compromised_value]
        if len(set(identities)) != len(identities) or not all(
            _digest(value) for value in identities
        ):
            raise ValueError("public keyring compromised key identities are invalid")
        compromised = dict.fromkeys(identities)
    else:
        for record in compromised_value:
            if not isinstance(record, dict) or set(record) != {
                "key_id",
                "compromised_at",
            }:
                raise ValueError("public keyring compromise records are invalid")
            key_id = str(record.get("key_id") or "")
            if not _digest(key_id) or key_id in compromised:
                raise ValueError(
                    "public keyring compromised key identities are invalid"
                )
            compromised[key_id] = _timestamp(
                record.get("compromised_at"), "key compromised_at"
            )
    root_key_path = _keyring_sibling(
        keyring_path,
        payload.get("root_key_file"),
        payload.get("root_key_sha256"),
        "root key",
    )
    signature_path = _keyring_sibling(
        keyring_path,
        payload.get("root_signature_file"),
        payload.get("root_signature_sha256"),
        "root signature",
    )
    root_key = _load_public_key(root_key_path)
    pinned_root = os.environ.get("PYSEC_KEYRING_ROOT_SHA256", "")
    if not _digest(pinned_root) or pinned_root != payload.get("root_key_sha256"):
        raise ValueError("public keyring root is not deployment-pinned")
    signed = {
        "schema_version": version,
        "generation": generation,
        "previous_keyring_sha256": previous,
        "threshold": payload["threshold"],
        "keys": payload["keys"],
        "compromised_key_ids": compromised_value,
    }
    try:
        root_key.verify(_read_bounded(signature_path), canonical_bytes(signed))
    except InvalidSignature as exc:
        raise ValueError("public keyring root signature verification failed") from exc
    _advance_keyring_state(keyring_path, generation, previous, payload)
    return compromised


def _advance_keyring_state(
    keyring_path: Path,
    generation: int,
    predecessor: str,
    payload: dict[str, Any],
) -> None:
    configured = os.environ.get("PYSEC_KEYRING_STATE_FILE", "")
    state_path = (
        Path(configured).expanduser().resolve()
        if configured
        else keyring_path.with_name(f"{keyring_path.name}.accepted-state.json")
    )
    minimum = _policy_integer("PYSEC_KEYRING_MIN_GENERATION", default=1)
    if generation < minimum:
        raise ValueError("public keyring generation is below deployment policy")
    with _exclusive_state_lock(state_path):
        _advance_keyring_state_unlocked(state_path, generation, predecessor, payload)


def _advance_keyring_state_unlocked(
    state_path: Path,
    generation: int,
    predecessor: str,
    payload: dict[str, Any],
) -> None:
    current_digest = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    previous_state: object | None = None
    if state_path.exists():
        if state_path.is_symlink() or not state_path.is_file():
            raise ValueError("public keyring accepted state must be a regular file")
        previous_state = strict_loads(_read_bounded(state_path))
    if previous_state is not None:
        required = {"schema_version", "generation", "keyring_sha256"}
        if not isinstance(previous_state, dict) or set(previous_state) != required:
            raise ValueError("public keyring accepted state is invalid")
        accepted_generation = _nonnegative_integer(previous_state.get("generation"))
        if generation < accepted_generation:
            raise ValueError("public keyring rollback was detected")
        if generation == accepted_generation:
            if current_digest != previous_state.get("keyring_sha256"):
                raise ValueError("public keyring generation was equivocated")
            return
        if generation != accepted_generation + 1:
            raise ValueError("public keyring generation is not contiguous")
        if predecessor != previous_state.get("keyring_sha256"):
            raise ValueError("public keyring predecessor does not match accepted state")
    state = {
        "schema_version": "1.0",
        "generation": generation,
        "keyring_sha256": current_digest,
    }
    data = (strict_dumps(state, indent=2) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{state_path.name}.", suffix=".tmp", dir=state_path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, state_path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _keyring_sibling(
    keyring_path: Path, name: object, digest: object, label: str
) -> Path:
    filename = str(name or "")
    expected = str(digest or "")
    if not filename or Path(filename).name != filename or not _digest(expected):
        raise ValueError(f"public keyring {label} record is invalid")
    path = keyring_path.resolve().parent / filename
    raw = _read_bounded(path)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError(f"public keyring {label} SHA-256 does not match")
    return path


def _public_key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def _validate_attestation_statement(
    statement: object, binding: dict[str, Any], evidence_path: Path
) -> None:
    if (
        not isinstance(statement, dict)
        or set(statement) != {"_type", "subject", "predicateType", "predicate"}
        or statement.get("_type") != "https://in-toto.io/Statement/v1"
    ):
        raise ValueError("signed evidence binding is not an in-toto Statement v1")
    if statement.get("predicateType") != (
        "https://willtran87.github.io/project-py-security-suite/"
        "attestation/companion-evidence/v2"
    ):
        raise ValueError("signed evidence binding predicate type is invalid")
    subjects = statement.get("subject")
    predicate = statement.get("predicate")
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise ValueError("signed evidence binding must identify one subject")
    subject = subjects[0]
    if (
        not isinstance(subject, dict)
        or subject.get("name") != evidence_path.name
        or subject.get("digest") != {"sha256": binding.get("evidence_sha256")}
    ):
        raise ValueError("signed evidence binding subject does not match the evidence")
    if (
        not isinstance(predicate, dict)
        or set(predicate) != {"source_sha256", "run_id", "created_at", "expires_at"}
        or predicate.get("source_sha256") != binding.get("source_sha256")
    ):
        raise ValueError("signed evidence binding source identity does not match")
    created = _timestamp(predicate.get("created_at"), "attestation created_at")
    expires = _timestamp(predicate.get("expires_at"), "attestation expires_at")
    now = governed_now()
    if created > now + timedelta(minutes=5):
        raise ValueError("signed evidence binding was created in the future")
    if expires <= created or expires < now:
        raise ValueError("signed evidence binding has expired")
    _run_identifier(str(predicate.get("run_id") or ""))


def _binding_path(path: Path) -> Path:
    return path.with_name(path.name + _BINDING_SUFFIX)


def _evidence_sha256(path: Path) -> str:
    if path.is_file() and not path.is_symlink():
        return hashlib.sha256(_read_bounded(path)).hexdigest()
    reports = _junit_paths(path)
    aggregate = hashlib.sha256()
    resolved = path.resolve()
    for report in reports:
        payload = _read_bounded(report)
        relative = report.resolve().relative_to(resolved).as_posix().encode("utf-8")
        aggregate.update(len(relative).to_bytes(8, "big"))
        aggregate.update(relative)
        aggregate.update(len(payload).to_bytes(8, "big"))
        aggregate.update(hashlib.sha256(payload).digest())
    return aggregate.hexdigest()


def _write_binding(path: Path, document: dict[str, Any], *, overwrite: bool) -> None:
    if path.exists() and (path.is_symlink() or not overwrite):
        raise ValueError(f"binding output already exists: {path}")
    payload = (strict_dumps(document) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _coverage_document(path: Path) -> dict[str, Any]:
    payload = strict_loads(_read_bounded(path))
    if not isinstance(payload, dict):
        raise TypeError("coverage JSON root must be an object")
    meta = payload.get("meta")
    totals = payload.get("totals")
    files = payload.get("files")
    if not isinstance(meta, dict) or not isinstance(totals, dict):
        raise TypeError("coverage JSON requires meta and totals objects")
    if not isinstance(files, dict):
        raise TypeError("coverage JSON requires a files object")
    normalized_files: list[dict[str, Any]] = []
    for name, value in sorted(files.items()):
        if not isinstance(value, dict) or not isinstance(value.get("summary"), dict):
            raise TypeError(f"coverage file entry is invalid: {name}")
        summary = value["summary"]
        normalized_files.append(
            {
                "path": str(name),
                "summary": _coverage_summary(summary),
                "missing_lines": _integer_list(value.get("missing_lines")),
                "missing_branches": _branch_list(value.get("missing_branches")),
            }
        )
    return _apply_source_binding(
        {
            "schema_version": "1.0",
            "kind": "coverage",
            "report": str(path.resolve()),
            "meta": {
                "format": _integer(meta.get("format")),
                "branch_coverage": bool(meta.get("branch_coverage", False)),
                "timestamp": str(meta.get("timestamp") or ""),
            },
            "totals": _coverage_summary(totals),
            "files": normalized_files,
        },
        path,
    )


def _coverage_summary(value: dict[str, Any]) -> dict[str, int | float]:
    return {
        "covered_lines": _integer(value.get("covered_lines")),
        "num_statements": _integer(value.get("num_statements")),
        "percent_covered": _number(value.get("percent_covered")),
        "missing_lines": _integer(value.get("missing_lines")),
        "num_branches": _integer(value.get("num_branches")),
        "covered_branches": _integer(value.get("covered_branches")),
        "missing_branches": _integer(value.get("missing_branches")),
        "num_partial_branches": _integer(value.get("num_partial_branches")),
    }


def _junit_document(path: Path) -> dict[str, Any]:
    reports = _junit_paths(path)
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0, "time": 0.0}
    failures: list[dict[str, Any]] = []
    test_cases: list[dict[str, Any]] = []
    for report in reports:
        data = _read_bounded(report)
        lowered = data[:4096].lower()
        if b"<!doctype" in lowered or b"<!entity" in lowered:
            raise ValueError(f"DTD and entity declarations are not allowed: {report}")
        root = DefusedET.fromstring(
            data,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
        for case in (
            node for node in root.iter() if _local_name(node.tag) == "testcase"
        ):
            totals["tests"] += 1
            totals["time"] += _number(case.attrib.get("time"))
            result = next(
                (
                    child
                    for child in case
                    if _local_name(child.tag) in {"failure", "error", "skipped"}
                ),
                None,
            )
            result_type = "passed" if result is None else _local_name(result.tag)
            if result_type != "passed":
                total_key = "skipped" if result_type == "skipped" else f"{result_type}s"
                totals[total_key] += 1
            case_record = {
                "name": _bounded_text(case.attrib.get("name") or "unnamed test", 500),
                "classname": _bounded_text(case.attrib.get("classname"), 500),
                "file": _bounded_text(case.attrib.get("file"), 4096),
                "line": _optional_integer(case.attrib.get("line")),
                "time": _number(case.attrib.get("time")),
                "result": result_type,
                "file_attribution": (
                    "producer" if case.attrib.get("file") else "unavailable"
                ),
            }
            if len(test_cases) < _MAX_JUNIT_TEST_CASES:
                test_cases.append(case_record)
            if result is not None and result_type != "skipped":
                failures.append(
                    {
                        "report": str(report.resolve()),
                        **case_record,
                        "message": _bounded_text(result.attrib.get("message")),
                        "type": _bounded_text(result.attrib.get("type")),
                    }
                )
    return _apply_source_binding(
        {
            "schema_version": "1.0",
            "kind": "junit",
            "report_count": len(reports),
            "totals": totals,
            "failures": failures,
            "test_cases": test_cases,
            "test_case_inventory_complete": totals["tests"] <= _MAX_JUNIT_TEST_CASES,
        },
        path,
    )


def _scorecard_document(path: Path) -> dict[str, Any]:
    payload = strict_loads(_read_bounded(path))
    if not isinstance(payload, dict):
        raise TypeError("Scorecard JSON root must be an object")
    checks = payload.get("checks")
    if not isinstance(checks, list):
        raise TypeError("Scorecard JSON requires a checks list")
    normalized: list[dict[str, Any]] = []
    for check in checks:
        if not isinstance(check, dict):
            raise TypeError("Scorecard checks must be objects")
        details = check.get("details", [])
        if not isinstance(details, list):
            details = []
        documentation = check.get("documentation", {})
        if not isinstance(documentation, dict):
            documentation = {}
        normalized.append(
            {
                "name": _bounded_text(check.get("name"), 100),
                "score": _number(check.get("score")),
                "reason": _bounded_text(check.get("reason"), 500),
                "details": [_bounded_text(value, 300) for value in details[:50]],
                "documentation": {
                    "url": _https_url(documentation.get("url")),
                    "short": _bounded_text(documentation.get("short"), 300),
                },
            }
        )
    return {
        "schema_version": "1.0",
        "kind": "scorecard",
        "repository": _bounded_text(
            payload.get("repo") or payload.get("repository"), 300
        ),
        "score": _number(payload.get("score")),
        "date": _bounded_text(payload.get("date"), 100),
        "checks": normalized,
    }


def _assurance_document(
    path: Path,
    kind: str,
    *,
    maximum_age_days: float = 7.0,
    minimum_coverage_percent: float = 0.0,
    require_contract_v2: bool = False,
    public_key: Path | None = None,
    public_keyring: Path | None = None,
    require_signature: bool = False,
    expected_run_id: str = "",
    expected_environment_sha256: str = "",
    expected_context: Path | None = None,
    replay_ledger: Path | None = None,
    replay_service: str | None = None,
    replay_service_token_env: str = "",
    replay_service_ca: Path | None = None,
    replay_service_receipt_key: Path | None = None,
    replay_service_client_cert: Path | None = None,
    replay_service_client_key: Path | None = None,
    allowed_builder_ids: tuple[str, ...] = (),
    expected_build_type: str = "",
    expected_source_repository: str = "",
    assurance_profile: Path | None = None,
    require_assurance_profile: bool = False,
) -> dict[str, Any]:
    payload = strict_loads(_read_bounded(path))
    if not isinstance(payload, dict):
        raise TypeError("assurance JSON root must be an object")
    if payload.get("kind") != kind:
        raise ValueError(f"assurance evidence kind must be {kind!r}")
    contract_version = str(payload.get("schema_version") or "1.0")
    if contract_version not in {"1.0", "2.0"}:
        raise ValueError("assurance evidence schema_version must be '1.0' or '2.0'")
    if require_contract_v2 and contract_version != "2.0":
        raise ValueError("assurance evidence contract v2 is required")
    if require_contract_v2 and expected_context is None:
        raise ValueError("assurance evidence contract v2 requires expected context")
    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        raise TypeError("assurance evidence requires a findings list")
    if len(findings) > _MAX_ASSURANCE_FINDINGS:
        raise ValueError(
            f"assurance evidence exceeds {_MAX_ASSURANCE_FINDINGS} findings"
        )
    normalized: list[dict[str, Any]] = []
    for value in findings:
        if not isinstance(value, dict):
            raise TypeError("assurance findings must be objects")
        evidence = value.get("evidence", {})
        if not isinstance(evidence, dict):
            evidence = {}
        normalized.append(
            {
                "rule_id": _bounded_text(value.get("rule_id"), 160),
                "title": _bounded_text(value.get("title"), 300),
                "message": _bounded_text(
                    value.get("message") or value.get("description"), 1_000
                ),
                "path": _bounded_text(value.get("path"), 500),
                "line": _optional_integer(value.get("line")),
                "severity": _assurance_severity(value.get("severity")),
                "classification": _bounded_text(value.get("classification"), 160),
                "citation": _https_url(value.get("citation")),
                "impact": _bounded_text(value.get("impact"), 1_000),
                "remediation": _bounded_text(value.get("remediation"), 1_000),
                "area": _bounded_text(value.get("area"), 100),
                "domain": _bounded_text(value.get("domain"), 100),
                "fingerprint": _bounded_text(value.get("fingerprint"), 200),
                "evidence": {
                    _bounded_text(key, 100): _bounded_scalar(item)
                    for key, item in list(evidence.items())[:50]
                },
            }
        )
    artifact_sha256 = _bounded_text(payload.get("artifact_sha256"), 64)
    if artifact_sha256 and not _digest(artifact_sha256):
        raise ValueError("assurance artifact_sha256 must be a SHA-256 digest")
    common: dict[str, Any] = {
        "schema_version": contract_version,
        "kind": kind,
        "producer": _bounded_text(payload.get("producer"), 200),
        "revision": _bounded_text(payload.get("revision"), 200),
        "generated_at": _bounded_text(payload.get("generated_at"), 100),
        "artifact_sha256": artifact_sha256,
        "environment": _bounded_text(payload.get("environment"), 200),
        "findings": normalized,
    }
    if contract_version == "2.0":
        common.update(
            _assurance_v2_metadata(
                payload,
                kind=kind,
                maximum_age_days=maximum_age_days,
                minimum_coverage_percent=minimum_coverage_percent,
                allowed_builder_ids=allowed_builder_ids,
                expected_build_type=expected_build_type,
                expected_source_repository=expected_source_repository,
            )
        )
    if require_assurance_profile and assurance_profile is None:
        raise ValueError("checkpointed assurance profile is required")
    profile_metadata: dict[str, Any] | None = None
    if assurance_profile is not None:
        profile = load_assurance_profile(
            assurance_profile, require_checkpoint=require_assurance_profile
        )
        profile_metadata = enforce_assurance_profile(profile, common, kind=kind)
        common["assurance_profile"] = profile_metadata
    document = _apply_source_binding(
        common,
        path,
        public_key=public_key,
        public_keyring=public_keyring,
        require_signature=require_signature,
    )
    if profile_metadata is not None:
        binding = document.get("evidence_binding")
        if not isinstance(binding, dict):
            raise ValueError("profile-governed evidence requires a source binding")
        document["governed_evidence_sha256"] = hashlib.sha256(
            canonical_bytes(
                {
                    "evidence_sha256": binding.get("evidence_sha256"),
                    "source_sha256": document.get("source_sha256"),
                    "assurance_profile_sha256": profile_metadata["profile_sha256"],
                }
            )
        ).hexdigest()
    if expected_run_id:
        normalized_run_id = _run_identifier(expected_run_id)
        if document.get("run_id") != normalized_run_id:
            raise ValueError("assurance evidence run_id is not the expected run")
    if expected_environment_sha256:
        if not _digest(expected_environment_sha256):
            raise ValueError("expected environment SHA-256 is invalid")
        if document.get("environment_sha256") != expected_environment_sha256:
            raise ValueError(
                "assurance evidence environment is not the expected target"
            )
    if expected_context is not None:
        expected_run, expected = _expected_assurance_context(expected_context)
        if (
            document.get("run_id") != expected_run
            or document.get("context") != expected
        ):
            raise ValueError(
                "assurance evidence does not match the expected run context"
            )
    if replay_ledger is not None:
        if replay_service:
            raise ValueError("configure only one replay consumption backend")
        _consume_replay_token(document, replay_ledger)
    elif replay_service:
        _consume_replay_service(
            document,
            replay_service,
            token_env=replay_service_token_env,
            ca_path=replay_service_ca,
            receipt_public_key=replay_service_receipt_key,
            client_cert=replay_service_client_cert,
            client_key=replay_service_client_key,
        )
    return document


def _expected_assurance_context(path: Path) -> tuple[str, dict[str, str]]:
    value = strict_loads(_read_bounded(path))
    required = {
        "schema_version",
        "run_id",
        "target_manifest_sha256",
        "exercised_targets_sha256",
        "deployment_sha256",
        "surface_sha256",
        "challenge_sha256",
        "trusted_time",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != "1.0"
    ):
        raise ValueError("expected assurance context does not match the v1 contract")
    run_id = _run_identifier(str(value.get("run_id") or ""))
    context: dict[str, str] = {}
    for name in required - {"schema_version", "run_id", "trusted_time"}:
        digest = _bounded_text(value.get(name), 64)
        if not _digest(digest):
            raise ValueError(f"expected assurance context requires a valid {name}")
        context[name] = digest
    context.update(
        verify_rfc3161(path, value.get("trusted_time"), context["challenge_sha256"])
    )
    return run_id, context


def _consume_replay_token(document: dict[str, Any], ledger: Path) -> None:
    identity, token = _replay_identity(document)
    if ledger.is_symlink() or (ledger.exists() and not ledger.is_file()):
        raise ValueError("replay ledger is not a regular file")
    parent = ledger.parent.resolve()
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("replay ledger parent must be an existing regular directory")
    try:
        connection = sqlite3.connect(ledger, timeout=10.0)
        with connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS consumed_evidence ("
                "token TEXT PRIMARY KEY, run_id TEXT NOT NULL, kind TEXT NOT NULL, "
                "consumed_at TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO consumed_evidence(token, run_id, kind, consumed_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    token,
                    str(document["run_id"]),
                    str(document["kind"]),
                    governed_now().isoformat(),
                ),
            )
    except sqlite3.IntegrityError as exc:
        raise ValueError("assurance evidence replay was detected") from exc
    except sqlite3.Error as exc:
        raise ValueError("replay ledger could not be updated") from exc
    finally:
        if "connection" in locals():
            connection.close()


def _consume_replay_service(
    document: dict[str, Any],
    service: str,
    *,
    token_env: str,
    ca_path: Path | None,
    receipt_public_key: Path | None = None,
    client_cert: Path | None = None,
    client_key: Path | None = None,
    receipt_state_path: Path | None = None,
) -> dict[str, object]:
    identity, token = _replay_identity(document)
    target = urlsplit(service)
    if (
        target.scheme != "https"
        or not target.hostname
        or target.username
        or target.password
        or target.query
        or target.fragment
    ):
        raise ValueError("replay service must be a credential-free HTTPS URL")
    if (
        not token_env
        or len(token_env) > 100
        or token_env.upper() != token_env
        or not token_env.replace("_", "").isalnum()
    ):
        raise ValueError("replay service token environment name is invalid")
    bearer = os.environ.get(token_env)
    if not bearer or len(bearer) > 8192 or any(ord(value) < 33 for value in bearer):
        raise ValueError("replay service authentication token is unavailable")
    if receipt_public_key is None:
        raise ValueError("replay service requires a deployment-pinned receipt key")
    if ca_path is None:
        raise ValueError("replay service requires an explicitly pinned CA bundle")
    if client_cert is None or client_key is None:
        raise ValueError("replay service requires mutual TLS credentials")
    context = ssl.create_default_context(cafile=str(_regular_ca(ca_path)))
    if bool(client_cert) != bool(client_key):
        raise ValueError(
            "replay service client certificate and key are required together"
        )
    if client_cert is not None and client_key is not None:
        context.load_cert_chain(
            certfile=str(_regular_credential(client_cert, "client certificate")),
            keyfile=str(_regular_credential(client_key, "client key")),
        )
    payload = canonical_bytes(
        {
            "schema_version": "1.0",
            "token": token,
            "identity": identity,
        }
    )
    request = Request(  # noqa: S310 - the URL is restricted to HTTPS above.
        service,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {bearer}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Idempotency-Key": token,
        },
    )
    try:
        with _open_replay_request(request, context) as response:
            if response.status != 201:
                raise ValueError("replay service rejected evidence consumption")
            content_type = str(response.headers.get("Content-Type", ""))
            if not content_type.casefold().startswith("application/json"):
                raise ValueError("replay service receipt has an invalid content type")
            if int(response.headers.get("Content-Length", "0") or "0") > 4096:
                raise ValueError("replay service returned an oversized response")
            raw_receipt = response.read(4097)
            if len(raw_receipt) > 4096:
                raise ValueError("replay service returned an oversized response")
            receipt = _verify_replay_receipt(raw_receipt, token, receipt_public_key)
            configured_state = os.environ.get("PYSEC_REPLAY_STATE_FILE", "")
            state_path = receipt_state_path or (
                Path(configured_state).expanduser().resolve()
                if configured_state
                else receipt_public_key.with_name(
                    f"{receipt_public_key.name}.receipt-state.json"
                )
            )
            _advance_replay_receipt_state(state_path, receipt)
            return receipt
    except HTTPError as exc:
        if exc.code == 409:
            raise ValueError("assurance evidence replay was detected") from exc
        raise ValueError("replay service rejected evidence consumption") from exc
    except (OSError, URLError) as exc:
        raise ValueError("replay service could not be reached") from exc


def _open_replay_request(request: Request, context: ssl.SSLContext) -> Any:
    """Retry the idempotent consume request on transient transport failures."""
    failure: OSError | URLError | None = None
    for attempt in range(3):
        try:
            return urlopen(  # noqa: S310 - caller restricts the URL to HTTPS.
                request, timeout=10.0, context=context
            )
        except HTTPError:
            raise
        except (OSError, URLError) as exc:
            failure = exc
            if attempt < 2:
                time.sleep(0.1 * (2**attempt))
    if failure is None:  # Defensive: the loop above always executes.
        raise ValueError("replay service retry state is invalid")
    raise failure


def _replay_identity(document: dict[str, Any]) -> tuple[dict[str, object], str]:
    binding = document.get("evidence_binding")
    attestation = binding.get("attestation") if isinstance(binding, dict) else None
    if (
        not isinstance(binding, dict)
        or binding.get("authenticated") is not True
        or not isinstance(attestation, dict)
    ):
        raise ValueError("replay protection requires authenticated v2 evidence")
    identity: dict[str, object] = {
        "key_id": attestation.get("key_id"),
        "run_id": document.get("run_id"),
        "kind": document.get("kind"),
        "evidence_sha256": binding.get("evidence_sha256"),
        "source_sha256": document.get("source_sha256"),
        "environment_sha256": document.get("environment_sha256"),
        "context": document.get("context"),
        "provenance": document.get("provenance"),
    }
    if not all(str(value or "") for value in identity.values()):
        raise ValueError("replay identity is incomplete")
    token = hashlib.sha256(canonical_bytes(identity)).hexdigest()
    return identity, token


def _regular_ca(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError("replay service CA is not a bounded regular file")
    resolved = path.expanduser().resolve()
    if (
        resolved.is_symlink()
        or not resolved.is_file()
        or resolved.stat().st_size > 1024 * 1024
    ):
        raise ValueError("replay service CA is not a bounded regular file")
    return resolved


def _regular_credential(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    if (
        path.is_symlink()
        or resolved.is_symlink()
        or not resolved.is_file()
        or resolved.stat().st_size > 1024 * 1024
    ):
        raise ValueError(f"replay service {label} is not a bounded regular file")
    return resolved


def _verify_replay_receipt(
    raw: bytes, token: str, public_key_path: Path
) -> dict[str, object]:
    try:
        value = strict_loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("replay service receipt is invalid JSON") from exc
    required = {
        "schema_version",
        "token",
        "sequence",
        "consumed_at",
        "previous_receipt_sha256",
        "key_id",
        "signature",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("replay service receipt fields do not match the contract")
    if value.get("schema_version") != "1.0" or value.get("token") != token:
        raise ValueError("replay service receipt identity does not match")
    sequence = value.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise ValueError("replay service receipt sequence is invalid")
    consumed_at = _timestamp(value.get("consumed_at"), "replay receipt consumed_at")
    if abs((governed_now() - consumed_at).total_seconds()) > 5 * 60:
        raise ValueError("replay service receipt is stale or in the future")
    previous = str(value.get("previous_receipt_sha256") or "")
    if previous and not _digest(previous):
        raise ValueError("replay service previous receipt digest is invalid")
    public_key_bytes = _read_bounded(public_key_path)
    try:
        public_key = serialization.load_pem_public_key(public_key_bytes)
    except (TypeError, ValueError) as exc:
        raise ValueError("replay service receipt public key is invalid") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("replay service receipt key must use Ed25519")
    key_id = _public_key_id(public_key)
    pinned_key = os.environ.get("PYSEC_REPLAY_RECEIPT_KEY_SHA256", "")
    if pinned_key != key_id:
        raise ValueError("replay service receipt key is not deployment-pinned")
    if value.get("key_id") != key_id:
        raise ValueError("replay service receipt key identity does not match")
    try:
        signature = base64.b64decode(str(value.get("signature") or ""), validate=True)
        public_key.verify(
            signature,
            canonical_bytes({name: value[name] for name in required - {"signature"}}),
        )
    except Exception as exc:
        raise ValueError(
            "replay service receipt signature verification failed"
        ) from exc
    return {
        "schema_version": "1.0",
        "sequence": sequence,
        "receipt_sha256": hashlib.sha256(canonical_bytes(value)).hexdigest(),
        "previous_receipt_sha256": previous,
        "consumed_at": consumed_at.isoformat(),
        "key_id": key_id,
    }


def _advance_replay_receipt_state(path: Path, receipt: dict[str, object]) -> None:
    """Persist and enforce a monotonic, hash-linked replay-service checkpoint."""
    resolved = path.expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    minimum = _policy_integer("PYSEC_REPLAY_MIN_SEQUENCE", default=1)
    sequence = _nonnegative_integer(receipt.get("sequence"))
    if sequence < minimum:
        raise ValueError("replay receipt sequence is below deployment policy")
    with _exclusive_state_lock(resolved):
        _advance_replay_receipt_state_unlocked(resolved, receipt)


def _advance_replay_receipt_state_unlocked(
    resolved: Path, receipt: dict[str, object]
) -> None:
    previous_state: object | None = None
    if resolved.exists():
        if resolved.is_symlink() or not resolved.is_file():
            raise ValueError("replay receipt state must be a regular file")
        previous_state = strict_loads(_read_bounded(resolved))
    if previous_state is not None:
        required = {
            "schema_version",
            "sequence",
            "receipt_sha256",
            "key_id",
        }
        if not isinstance(previous_state, dict) or set(previous_state) != required:
            raise ValueError("replay receipt state is invalid")
        previous_sequence = _nonnegative_integer(previous_state.get("sequence"))
        if receipt["sequence"] != previous_sequence + 1:
            raise ValueError("replay receipt sequence is not monotonic")
        if receipt["previous_receipt_sha256"] != previous_state["receipt_sha256"]:
            raise ValueError("replay receipt hash chain does not match local state")
        if receipt["key_id"] != previous_state["key_id"]:
            raise ValueError("replay receipt signer changed without state migration")
    state = {
        "schema_version": "1.0",
        "sequence": receipt["sequence"],
        "receipt_sha256": receipt["receipt_sha256"],
        "key_id": receipt["key_id"],
    }
    payload = (strict_dumps(state, indent=2) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{resolved.name}.", suffix=".tmp", dir=resolved.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)  # noqa: S103 - private replay checkpoint
        os.replace(temporary, resolved)
        os.chmod(resolved, 0o600)  # noqa: S103 - private replay checkpoint
    finally:
        if temporary.exists():
            temporary.unlink()


@contextmanager
def _exclusive_state_lock(path: Path) -> Any:
    """Hold an advisory cross-process lock while checking and advancing state."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f".{path.name}.lock")
    handle = lock_path.open("a+b")
    os.chmod(lock_path, 0o600)  # noqa: S103 - private replay checkpoint lock
    if lock_path.stat().st_size == 0:
        handle.write(b"0")
        handle.flush()
    deadline = time.monotonic() + 10.0
    acquired = False
    try:
        while not acquired:
            try:
                if os.name == "nt":
                    import msvcrt

                    msvcrt_module: Any = msvcrt
                    handle.seek(0)
                    msvcrt_module.locking(handle.fileno(), msvcrt_module.LK_NBLCK, 1)
                else:
                    fcntl_module: Any = __import__("fcntl")
                    fcntl_module.flock(
                        handle.fileno(), fcntl_module.LOCK_EX | fcntl_module.LOCK_NB
                    )
                acquired = True
            except OSError:
                if time.monotonic() >= deadline:
                    raise ValueError(
                        "security state lock could not be acquired"
                    ) from None
                time.sleep(0.02)
        yield
    finally:
        if acquired:
            if os.name == "nt":
                import msvcrt

                msvcrt_module = msvcrt
                handle.seek(0)
                msvcrt_module.locking(handle.fileno(), msvcrt_module.LK_UNLCK, 1)
            else:
                fcntl_module = __import__("fcntl")
                fcntl_module.flock(handle.fileno(), fcntl_module.LOCK_UN)
        handle.close()


def _policy_integer(name: str, *, default: int) -> int:
    raw = os.environ.get(name, str(default))
    if not raw.isdigit() or int(raw) < 1:
        raise ValueError(f"{name} deployment policy is invalid")
    return int(raw)


def _assurance_v2_metadata(
    payload: dict[str, Any],
    *,
    kind: str,
    maximum_age_days: float,
    minimum_coverage_percent: float,
    allowed_builder_ids: tuple[str, ...] = (),
    expected_build_type: str = "",
    expected_source_repository: str = "",
) -> dict[str, Any]:
    if not 0.01 <= maximum_age_days <= 3650.0:
        raise ValueError("maximum assurance evidence age is invalid")
    if not 0.0 <= minimum_coverage_percent <= 100.0:
        raise ValueError("minimum assurance coverage is invalid")
    required_text = (
        "producer",
        "producer_version",
        "revision",
        "generated_at",
        "expires_at",
        "run_id",
        "environment",
    )
    for name in required_text:
        if not _bounded_text(payload.get(name), 200 if name != "run_id" else 100):
            raise ValueError(f"assurance evidence v2 requires {name}")
    generated = _timestamp(payload.get("generated_at"), "generated_at")
    expires = _timestamp(payload.get("expires_at"), "expires_at")
    now = governed_now()
    if generated > now + timedelta(minutes=5):
        raise ValueError("assurance evidence generated_at is in the future")
    if now - generated > timedelta(days=maximum_age_days):
        raise ValueError("assurance evidence is stale")
    if expires <= generated or expires < now:
        raise ValueError("assurance evidence has expired")
    _run_identifier(str(payload.get("run_id")))
    digests: dict[str, str] = {}
    for name in (
        "producer_sha256",
        "ruleset_sha256",
        "config_sha256",
        "environment_sha256",
    ):
        value = _bounded_text(payload.get(name), 64)
        if not _digest(value):
            raise ValueError(f"assurance evidence v2 requires a valid {name}")
        digests[name] = value
    execution = _assurance_execution(payload.get("execution"), minimum_coverage_percent)
    context = _assurance_context(payload.get("context"), generated)
    provenance = _assurance_provenance(payload.get("provenance"))
    if allowed_builder_ids:
        if len(allowed_builder_ids) > 32 or provenance["builder_id"] not in set(
            allowed_builder_ids
        ):
            raise ValueError(
                "assurance provenance builder is not organization-approved"
            )
    if expected_build_type or expected_source_repository:
        if provenance.get("schema_version") != "2.0":
            raise ValueError("SLSA provenance v2 is required by organization policy")
        if expected_build_type and provenance.get("build_type") != expected_build_type:
            raise ValueError("assurance provenance build type is not approved")
        if (
            expected_source_repository
            and provenance.get("source_repository") != expected_source_repository
        ):
            raise ValueError("assurance provenance source repository is not approved")
    _assurance_kind_requirements(kind, execution)
    return {
        "producer_version": _bounded_text(payload.get("producer_version"), 100),
        **digests,
        "expires_at": expires.isoformat(),
        "run_id": _bounded_text(payload.get("run_id"), 100),
        "generated_at": generated.isoformat(),
        "execution": execution,
        "context": context,
        "provenance": provenance,
    }


def _assurance_provenance(value: object) -> dict[str, Any]:
    v1_required = {
        "schema_version",
        "builder_id",
        "builder_sha256",
        "native_report_sha256",
        "normalizer_sha256",
        "invocation_sha256",
        "materials_sha256",
    }
    v2_extra = {
        "builder_environment_sha256",
        "build_type",
        "source_repository",
        "source_revision",
        "external_parameters_sha256",
        "byproducts_sha256",
    }
    v3_extra = {
        "artifact_sha256",
        "slsa_level",
        "verified_by",
        "slsa_envelope_sha256",
        "resolved_dependencies_sha256",
        "sigstore_bundle_sha256",
        "sigstore_trusted_root_sha256",
        "vsa_sha256",
        "vsa_policy_sha256",
    }
    if not isinstance(value, dict):
        raise TypeError("assurance provenance must be an object")
    version = value.get("schema_version")
    required = (
        v1_required
        if version == "1.0"
        else v1_required | v2_extra | (v3_extra if version == "3.0" else set())
    )
    if version not in {"1.0", "2.0", "3.0"} or set(value) != required:
        raise ValueError("assurance provenance fields do not match the v2 contract")
    builder_id = _bounded_text(value.get("builder_id"), 200)
    if not builder_id:
        raise ValueError("assurance provenance requires builder_id")
    result: dict[str, Any] = {"schema_version": str(version), "builder_id": builder_id}
    text_fields = {
        "build_type",
        "source_repository",
        "source_revision",
        "slsa_level",
        "verified_by",
    }
    for name in required - {"schema_version", "builder_id"} - text_fields:
        digest = _bounded_text(value.get(name), 64)
        if not _digest(digest):
            raise ValueError(f"assurance provenance requires a valid {name}")
        result[name] = digest
    if version in {"2.0", "3.0"}:
        build_type = _bounded_text(value.get("build_type"), 500)
        repository = _bounded_text(value.get("source_repository"), 500)
        revision = _bounded_text(value.get("source_revision"), 64)
        if not build_type.startswith("https://") or not repository.startswith(
            "https://"
        ):
            raise ValueError(
                "SLSA build type and source repository must use HTTPS URIs"
            )
        if len(revision) not in {40, 64} or not all(
            character in "0123456789abcdef" for character in revision
        ):
            raise ValueError("SLSA source revision must be a full hexadecimal digest")
        result.update(
            {
                "build_type": build_type,
                "source_repository": repository,
                "source_revision": revision,
            }
        )
    if version == "3.0":
        level = value.get("slsa_level")
        if (
            isinstance(level, bool)
            or not isinstance(level, (int, str))
            or not str(level).isdigit()
            or int(level) not in {1, 2, 3, 4}
        ):
            raise ValueError("assurance provenance SLSA level is invalid")
        verifiers = value.get("verified_by")
        allowed = {"slsa", "sigstore", "vsa", "dependency-closure"}
        if (
            not isinstance(verifiers, list)
            or len(verifiers) != len(set(verifiers))
            or not set(verifiers).issubset(allowed)
        ):
            raise ValueError("assurance provenance verification receipt is invalid")
        result["slsa_level"] = str(level)
        result["verified_by"] = sorted(verifiers)
    return result


def _assurance_context(value: object, generated_at: datetime) -> dict[str, str]:
    required = {
        "target_manifest_sha256",
        "exercised_targets_sha256",
        "deployment_sha256",
        "surface_sha256",
        "challenge_sha256",
        "trusted_time_sha256",
        "trusted_time_observed_at",
        "trusted_time_receipt_sha256",
        "trusted_time_signer_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError(
            "assurance evidence context fields do not match the v2 contract"
        )
    result: dict[str, str] = {}
    for name in required - {"trusted_time_observed_at"}:
        digest = _bounded_text(value.get(name), 64)
        if not _digest(digest):
            raise ValueError(f"assurance evidence context requires a valid {name}")
        result[name] = digest
    observed = _timestamp(
        value.get("trusted_time_observed_at"), "trusted_time_observed_at"
    )
    if abs((generated_at - observed).total_seconds()) > 24 * 60 * 60:
        raise ValueError("assurance evidence trusted time is not contemporaneous")
    result["trusted_time_observed_at"] = observed.isoformat()
    return result


def _assurance_execution(
    value: object, minimum_coverage_percent: float
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError("assurance evidence v2 requires an execution object")
    allowed = {
        "status",
        "targets_discovered",
        "targets_exercised",
        "requests",
        "coverage_percent",
        "coverage_metric",
        "roles",
        "features",
        "skipped_checks",
        "canaries_expected",
        "canaries_observed",
        "language_matrix",
        "cross_language_matrix",
        "control_proof",
    }
    required = allowed - {"language_matrix", "cross_language_matrix", "control_proof"}
    if set(value) - allowed or not required.issubset(value):
        raise ValueError("assurance execution fields do not match the v2 contract")
    if value.get("status") != "completed":
        raise ValueError("assurance execution did not complete")
    discovered = _nonnegative_integer(value.get("targets_discovered"))
    exercised = _nonnegative_integer(value.get("targets_exercised"))
    requests = _nonnegative_integer(value.get("requests"))
    expected = _nonnegative_integer(value.get("canaries_expected"))
    observed = _nonnegative_integer(value.get("canaries_observed"))
    coverage = _number(value.get("coverage_percent"))
    if discovered < 1 or exercised < 1 or exercised > discovered:
        raise ValueError("assurance execution target coverage is invalid")
    if coverage < minimum_coverage_percent or coverage > 100.0:
        raise ValueError("assurance execution coverage is below policy")
    if expected < 1 or observed != expected:
        raise ValueError("assurance execution canary coverage is incomplete")
    roles = _bounded_string_list(value.get("roles"), "roles", 64)
    features = _bounded_string_list(value.get("features"), "features", 256)
    control_proof = value.get("control_proof")
    skipped = _bounded_string_list(value.get("skipped_checks"), "skipped_checks", 256)
    if skipped:
        raise ValueError("assurance execution contains skipped checks")
    metric = _bounded_text(value.get("coverage_metric"), 100)
    if not metric:
        raise ValueError("assurance execution requires a coverage metric")
    language_matrix = _assurance_language_matrix(value.get("language_matrix", []))
    cross_language_matrix = _assurance_cross_language_matrix(
        value.get("cross_language_matrix", [])
    )
    return {
        "status": "completed",
        "targets_discovered": discovered,
        "targets_exercised": exercised,
        "requests": requests,
        "coverage_percent": coverage,
        "coverage_metric": metric,
        "roles": roles,
        "features": features,
        **({"control_proof": control_proof} if control_proof is not None else {}),
        "skipped_checks": skipped,
        "canaries_expected": expected,
        "canaries_observed": observed,
        **({"language_matrix": language_matrix} if language_matrix else {}),
        **(
            {"cross_language_matrix": cross_language_matrix}
            if cross_language_matrix
            else {}
        ),
    }


def _assurance_language_matrix(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError("assurance language matrix must be a bounded list")
    result: list[dict[str, Any]] = []
    languages: set[str] = set()
    for item in value:
        required = {
            "language",
            "engine",
            "engine_version",
            "query_pack_sha256",
            "source_files_sha256",
            "files_discovered",
            "files_analyzed",
            "exclusions",
            "analysis_modes",
            "files",
        }
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError("assurance language matrix entry fields do not match")
        language = _bounded_text(item["language"], 50).casefold()
        if language in languages:
            raise ValueError("assurance language matrix languages are duplicated")
        discovered = _nonnegative_integer(item["files_discovered"])
        analyzed = _nonnegative_integer(item["files_analyzed"])
        exclusions = item["exclusions"]
        if not isinstance(exclusions, list) or len(exclusions) > 10_000:
            raise ValueError("assurance language exclusions are invalid")
        normalized_exclusions: list[dict[str, str]] = []
        for exclusion in exclusions:
            if not isinstance(exclusion, dict) or set(exclusion) != {"path", "reason"}:
                raise ValueError("assurance language exclusion fields do not match")
            normalized_exclusions.append(
                {
                    "path": _bounded_text(exclusion["path"], 1000),
                    "reason": _bounded_text(exclusion["reason"], 200),
                }
            )
        if discovered < 1 or analyzed < 1 or analyzed + len(exclusions) != discovered:
            raise ValueError("assurance language file accounting is incomplete")
        modes = _bounded_string_list(item["analysis_modes"], "analysis_modes", 32)
        if "semantic-dataflow" not in modes:
            raise ValueError("assurance language matrix lacks semantic dataflow")
        for name in ("query_pack_sha256", "source_files_sha256"):
            if not _digest(str(item[name])):
                raise ValueError(f"assurance language matrix {name} is invalid")
        files = _assurance_language_files(item["files"])
        if (
            len(files) != analyzed
            or hashlib.sha256(canonical_bytes(files)).hexdigest()
            != item["source_files_sha256"]
        ):
            raise ValueError("assurance language exact file ledger does not match")
        languages.add(language)
        result.append(
            {
                "language": language,
                "engine": _bounded_text(item["engine"], 100),
                "engine_version": _bounded_text(item["engine_version"], 100),
                "query_pack_sha256": item["query_pack_sha256"],
                "source_files_sha256": item["source_files_sha256"],
                "files_discovered": discovered,
                "files_analyzed": analyzed,
                "exclusions": normalized_exclusions,
                "analysis_modes": modes,
                "files": files,
            }
        )
    return sorted(result, key=lambda item: str(item["language"]))


def _assurance_language_files(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 50_000:
        raise ValueError("assurance language files must be a bounded non-empty list")
    result: list[dict[str, Any]] = []
    paths: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "size_bytes",
            "sha256",
            "line_count",
        }:
            raise ValueError("assurance language file fields do not match")
        path = _bounded_text(item["path"], 1000)
        size = _nonnegative_integer(item["size_bytes"])
        digest = str(item["sha256"])
        line_count = _nonnegative_integer(item["line_count"])
        if (
            not path
            or path.startswith(("/", "\\"))
            or ".." in Path(path).parts
            or path in paths
            or not _digest(digest)
        ):
            raise ValueError("assurance language file identity is invalid")
        paths.add(path)
        result.append(
            {
                "path": path,
                "size_bytes": size,
                "sha256": digest,
                "line_count": line_count,
            }
        )
    if result != sorted(result, key=lambda item: str(item["path"])):
        raise ValueError("assurance language files must use canonical path order")
    return result


def _assurance_cross_language_matrix(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 2_016:
        raise ValueError("assurance cross-language matrix must be bounded")
    result: list[dict[str, Any]] = []
    pairs: set[tuple[str, str]] = set()
    required = {
        "languages",
        "engine",
        "engine_version",
        "query_pack_sha256",
        "source_file_sets_sha256",
        "boundaries_analyzed",
        "flows_found",
        "boundaries",
        "boundaries_sha256",
        "flows",
        "flows_sha256",
        "analysis_modes",
        "independent_validation",
    }
    for item in value:
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError("assurance cross-language entry fields do not match")
        raw = item["languages"]
        if not isinstance(raw, list) or len(raw) != 2:
            raise ValueError("assurance cross-language entry requires two languages")
        names = sorted(_bounded_text(language, 50).casefold() for language in raw)
        pair = (names[0], names[1])
        modes = _bounded_string_list(item["analysis_modes"], "analysis_modes", 32)
        boundaries = _assurance_cross_records(item["boundaries"], pair, boundary=True)
        flows = _assurance_cross_records(item["flows"], pair, boundary=False)
        independent = _assurance_independent_validation(item["independent_validation"])
        if (
            not pair[0]
            or pair[0] == pair[1]
            or pair in pairs
            or not {"semantic-dataflow", "cross-language-boundary"}.issubset(modes)
            or not _digest(str(item["query_pack_sha256"]))
            or not _digest(str(item["source_file_sets_sha256"]))
            or not _digest(str(item["boundaries_sha256"]))
            or not _digest(str(item["flows_sha256"]))
            or item["boundaries_sha256"]
            != hashlib.sha256(canonical_bytes(boundaries)).hexdigest()
            or item["flows_sha256"]
            != hashlib.sha256(canonical_bytes(flows)).hexdigest()
        ):
            raise ValueError("assurance cross-language entry is invalid")
        boundaries_analyzed = _nonnegative_integer(item["boundaries_analyzed"])
        flows_found = _nonnegative_integer(item["flows_found"])
        if boundaries_analyzed != len(boundaries) or flows_found != len(flows):
            raise ValueError("assurance cross-language ledger count does not match")
        pairs.add(pair)
        result.append(
            {
                "languages": list(pair),
                "engine": _bounded_text(item["engine"], 100),
                "engine_version": _bounded_text(item["engine_version"], 100),
                "query_pack_sha256": item["query_pack_sha256"],
                "source_file_sets_sha256": item["source_file_sets_sha256"],
                "boundaries_analyzed": boundaries_analyzed,
                "flows_found": flows_found,
                "boundaries": boundaries,
                "boundaries_sha256": item["boundaries_sha256"],
                "flows": flows,
                "flows_sha256": item["flows_sha256"],
                "analysis_modes": modes,
                "independent_validation": independent,
            }
        )
    return sorted(result, key=lambda item: tuple(item["languages"]))


def _assurance_independent_validation(value: object) -> dict[str, str]:
    required = {"engine", "query_pack_sha256", "boundaries_sha256", "flows_sha256"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError(
            "assurance independent semantic validation fields do not match"
        )
    result = {name: str(value[name]) for name in required}
    result["engine"] = _bounded_text(value["engine"], 100)
    if not result["engine"] or any(
        not _digest(result[name]) for name in required - {"engine"}
    ):
        raise ValueError("assurance independent semantic validation is invalid")
    return result


def _assurance_cross_records(
    value: object, pair: tuple[str, str], *, boundary: bool
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 100_000:
        raise ValueError("assurance cross-language ledger must be bounded")
    fields = (
        {"path", "line", "language", "kind", "target"}
        if boundary
        else {
            "source_path",
            "source_line",
            "source_language",
            "sink_path",
            "sink_line",
            "sink_language",
            "source_kind",
            "sink_kind",
        }
    )
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError("assurance cross-language ledger fields do not match")
        record: dict[str, Any] = {}
        for name in sorted(fields):
            raw = item[name]
            if name.endswith("line") or name == "line":
                integer = _nonnegative_integer(raw)
                if integer < 1:
                    raise ValueError("assurance cross-language ledger line is invalid")
                record[name] = integer
            else:
                text = _bounded_text(raw, 1000)
                if name.endswith("path") or name == "path":
                    if (
                        text.startswith(("/", "\\"))
                        or (len(text) >= 2 and text[1] == ":")
                        or ".." in Path(text).parts
                    ):
                        raise ValueError(
                            "assurance cross-language ledger path is unsafe"
                        )
                if name.endswith("language") or name == "language":
                    text = text.casefold()
                    if text not in pair:
                        raise ValueError(
                            "assurance cross-language ledger language is invalid"
                        )
                record[name] = text
        result.append(record)
    ordered = sorted(result, key=canonical_bytes)
    if result != ordered or len({canonical_bytes(item) for item in result}) != len(
        result
    ):
        raise ValueError("assurance cross-language ledger is not canonical and unique")
    return result


def _assurance_kind_requirements(kind: str, execution: dict[str, Any]) -> None:
    required_features = {
        "surface-inventory": {
            "declared-observed",
            "retired-absence",
            "version-ownership",
            "shadow-surface",
        },
        "event-security": {
            "producer-authorization",
            "consumer-authorization",
            "message-signing",
            "replay-resistance",
            "idempotency",
            "schema-enforcement",
            "dead-letter-isolation",
            "poison-message-containment",
        },
        "database-security": {
            "least-privilege",
            "row-level-security",
            "migration-safety",
            "query-boundary",
            "backup-restore",
            "audit-trail",
        },
        "ruleset-regression": {
            "true-positive",
            "true-negative",
            "mutation",
            "parser-variant",
            "false-positive-budget",
        },
        "ai-security": {
            "prompt-injection",
            "tool-authorization",
            "least-agency",
            "memory-boundary",
            "output-handling",
            "data-exfiltration",
        },
        "llm-adversarial": {
            "schema-constrained-proposal",
            "prompt-injection-resistance",
            "disposable-worktree",
            "network-deny",
            "command-allowlist",
            "deterministic-oracle",
            "negative-control",
            "mutation-validation",
            "source-bound-evidence",
        },
        "browser-security": {
            "security-headers",
            "csp-quality",
            "browser-isolation",
            "authenticated-cache-control",
            "cookie-attributes",
            "egress-denial",
        },
        "authorization-security": {
            "BOLA",
            "IDOR",
            "tenant-isolation",
            "unauthenticated-access",
            "state-transitions",
            "replay-resistance",
            "concurrency",
            "approval-limits",
            "sequence-enforcement",
            "idempotency",
            "atomicity",
            "business-logic-state-machine",
        },
        "cloud-attack-path": {
            "identity-edges",
            "network-edges",
            "sensitive-assets",
            "iac-live-drift",
        },
        "clusterfuzzlite": {"coverage-guided", "crash-reproducer"},
        "falco": {"rule-canary", "workload-coverage"},
        "fuzz-introspector": {
            "static-reachability",
            "dynamic-coverage",
            "corpus-health",
        },
        "iast": {"instrumentation-health", "route-coverage"},
        "kubescape": {"deployed-inventory", "control-coverage"},
        "mobsf": {"static-analysis", "dynamic-analysis"},
        "native-sanitizers": {"asan", "ubsan", "fuzz-canary"},
        "nuclei": {"signed-templates", "approved-workflow"},
        "oast": {"self-hosted-oast", "callback-correlation", "egress-scope"},
        "polyglot": {"semantic-dataflow", "language-matrix"},
        "prowler": {"read-only-identity", "deployed-inventory", "iac-drift"},
        "protocol-security": {
            "protocol-inventory",
            "contract-cases",
            "fault-injection",
        },
        "rasp": {"block-mode-canary", "observe-mode"},
        "restler": {"stateful-sequences", "producer-consumer", "replay"},
        "secret-verification": {
            "provider-receipts",
            "value-redaction",
            "revocation-state",
        },
        "tls-scan": {"certificate", "protocols", "ciphers"},
        "zap": {"client-spider", "active-scan", "authentication-health"},
    }.get(kind, set())
    observed_features = set(execution["features"])
    missing = sorted(required_features - observed_features)
    if missing:
        raise ValueError(
            f"{kind} evidence is missing required execution features: "
            + ", ".join(missing)
        )
    if kind in {
        "surface-inventory",
        "event-security",
        "database-security",
        "ruleset-regression",
        "ai-security",
        "browser-security",
        "authorization-security",
        "cloud-attack-path",
        "protocol-security",
        "llm-adversarial",
    }:
        verify_control_proof(execution.get("control_proof"), required_features)
    if kind == "polyglot" and not execution.get("language_matrix"):
        raise ValueError("polyglot evidence requires an explicit language matrix")
    if (
        kind in {"authorization-security", "browser-security", "zap"}
        and len(execution["roles"]) < 2
    ):
        raise ValueError(f"{kind} evidence requires at least two exercised roles")


def _timestamp(value: object, label: str) -> datetime:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _nonnegative_integer(value: object) -> int:
    result = _integer(value)
    if result < 0:
        raise ValueError("assurance execution counts cannot be negative")
    return result


def _bounded_string_list(value: object, label: str, maximum: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise TypeError(f"assurance execution {label} must be a bounded list")
    result = [_bounded_text(item, 160) for item in value]
    if any(not item for item in result):
        raise ValueError(f"assurance execution {label} contains an empty value")
    return result


def _junit_paths(path: Path) -> list[Path]:
    if path.is_file() and not path.is_symlink():
        return [path]
    if not path.is_dir() or path.is_symlink():
        raise ValueError(f"JUnit evidence path does not exist: {path}")
    reports = sorted(
        candidate
        for candidate in path.rglob("*.xml")
        if candidate.is_file() and not candidate.is_symlink()
    )
    if not reports:
        raise ValueError(f"no JUnit XML reports were found under: {path}")
    if len(reports) > _MAX_JUNIT_REPORTS:
        raise ValueError(f"more than {_MAX_JUNIT_REPORTS} JUnit reports were found")
    return reports


def _integer(value: object) -> int:
    try:
        return int(str(value or 0))
    except (TypeError, ValueError) as exc:
        raise TypeError(f"expected an integer, received {value!r}") from exc


def _optional_integer(value: object) -> int | None:
    return None if value in (None, "") else _integer(value)


def _number(value: object) -> float:
    try:
        result = round(float(str(value or 0.0)), 6)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"expected a number, received {value!r}") from exc
    if not math.isfinite(result):
        raise TypeError(f"expected a finite number, received {value!r}")
    return result


def _integer_list(value: object) -> list[int]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise TypeError("expected a list of line numbers")
    return [_integer(item) for item in value]


def _branch_list(value: object) -> list[list[int]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise TypeError("expected a list of branch pairs")
    branches: list[list[int]] = []
    for item in value:
        if not isinstance(item, list) or len(item) != 2:
            raise TypeError("coverage branch entries must be two-item lists")
        branches.append([_integer(item[0]), _integer(item[1])])
    return branches


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _bounded_text(value: object, maximum: int = 300) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= maximum else text[: maximum - 3] + "..."


def _https_url(value: object) -> str:
    text = _bounded_text(value, 500)
    return text if text.startswith("https://") else ""


def _assurance_severity(value: object) -> str:
    normalized = _bounded_text(value, 30).casefold() or "medium"
    if normalized not in {"critical", "high", "medium", "low", "informational", "info"}:
        raise ValueError(f"unsupported assurance severity: {normalized!r}")
    return normalized


def _bounded_scalar(value: object) -> str | int | float | bool | None:
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return _bounded_text(value, 500)


if __name__ == "__main__":
    raise SystemExit(main())
