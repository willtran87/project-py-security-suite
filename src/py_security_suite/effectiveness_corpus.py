from __future__ import annotations

import hashlib
import base64
import os
import ssl
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .assurance_profile import verify_governance_quorum
from .execution import sha256_file
from .passport import verify_report
from .path_safety import read_regular_file, resolve_regular_file
from .source_inventory import verify_source_inventory_file
from .strict_json import canonical_bytes, loads as strict_loads
from .trusted_observation import governed_now
from .trusted_time import verify_rfc3161


_MAX_CORPUS_BYTES = 16 * 1024 * 1024
_MAX_LABELS = 10_000
_MAX_MATCHES_PER_LABEL = 20
_DIGEST_LENGTH = 64


def evaluate_report_corpus(
    report: Path,
    corpus: Path,
    *,
    corpus_sha256: str,
    trusted_time: Path | None = None,
    trusted_time_sha256: str = "",
    replay_ledger: Path | None = None,
    replay_service_url: str = "",
    replay_service_token_env: str = "",
    replay_service_receipt_key: Path | None = None,
    replay_service_receipt_key_sha256: str = "",
    replay_query_budget: int = 1,
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
    time_authority = _effectiveness_time(
        document,
        corpus_path,
        verification,
        observed_digest,
        trusted_time,
        trusted_time_sha256,
    )
    authority_time = (
        datetime.fromisoformat(time_authority["observed_at"])
        if time_authority["validated"]
        else governed_now()
    )
    authority = _corpus_authority(document, corpus_path, authority_time)
    replay_receipt = _consume_effectiveness_replay(
        document,
        verification,
        observed_digest,
        time_authority,
        replay_ledger,
        replay_service_url,
        replay_service_token_env,
        replay_service_receipt_key,
        replay_service_receipt_key_sha256,
        replay_query_budget,
    )
    _validate_fixture_paths(labels, report_root)
    _validate_unique_finding_assignments(labels, findings)
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
        "schema_version": str(document["schema_version"]),
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
            "authority": authority,
            "diversity": _diversity(labels),
        },
        "time_authority": time_authority,
        "replay_protected": bool(replay_receipt),
        "replay_receipt": replay_receipt,
        "confusion_matrix": counts,
        "metrics": {
            "precision": _ratio(true_positive, true_positive + false_positive),
            "recall": _ratio(true_positive, true_positive + false_negative),
            "specificity": _ratio(true_negative, true_negative + false_positive),
            "f1": _f1(true_positive, false_positive, false_negative),
        },
        "feedback_policy": (
            "aggregate-only" if document.get("schema_version") == "2.0" else "detailed"
        ),
        "failures": []
        if document.get("schema_version") == "2.0"
        else [
            outcome
            for outcome in outcomes
            if outcome["outcome"] in {"false_positive", "false_negative"}
        ],
        "label_outcomes": [] if document.get("schema_version") == "2.0" else outcomes,
    }


def _read_object(path: Path, maximum: int) -> dict[str, Any]:
    _, payload = read_regular_file(
        path,
        "JSON evidence",
        maximum_bytes=maximum,
    )
    try:
        value = strict_loads(payload)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"JSON evidence is invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise TypeError("JSON evidence root must be an object")
    return value


def _labels(document: dict[str, Any]) -> list[dict[str, Any]]:
    version = document.get("schema_version")
    if version not in {"1.0", "2.0"}:
        raise ValueError("effectiveness corpus schema_version must be '1.0' or '2.0'")
    values = document.get("labels")
    if not isinstance(values, list) or not values:
        raise TypeError("effectiveness corpus requires a non-empty labels array")
    if len(values) > _MAX_LABELS:
        raise ValueError(f"effectiveness corpus exceeds {_MAX_LABELS} labels")
    labels: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    match_identities: set[bytes] = set()
    fixture_identities: set[str] = set()
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
        match_identity = canonical_bytes(normalized)
        if match_identity in match_identities:
            raise ValueError("effectiveness corpus match predicates must be unique")
        match_identities.add(match_identity)
        identifiers.add(identifier)
        label = {"id": identifier, "expected": expectation, "match": normalized}
        if version == "2.0":
            required = {
                "id",
                "expected",
                "match",
                "cwe",
                "language",
                "parser_variant",
                "boundary_type",
                "severity",
                "mutation_operator",
                "fixture_sha256",
                "fixture_path",
            }
            if set(value) != required:
                raise ValueError("governed effectiveness label fields do not match")
            strata = {
                name: str(value.get(name) or "").strip().casefold()
                for name in (
                    "cwe",
                    "language",
                    "parser_variant",
                    "boundary_type",
                    "severity",
                    "mutation_operator",
                )
            }
            if any(not item or len(item) > 160 for item in strata.values()):
                raise ValueError("governed effectiveness label strata are invalid")
            fixture_sha256 = str(value.get("fixture_sha256") or "").casefold()
            if not _digest(fixture_sha256) or fixture_sha256 in fixture_identities:
                raise ValueError(
                    "governed effectiveness fixture identities must be unique digests"
                )
            fixture_identities.add(fixture_sha256)
            fixture_path = str(value.get("fixture_path") or "").strip()
            if (
                not fixture_path
                or len(fixture_path) > 500
                or Path(fixture_path).is_absolute()
                or ".." in Path(fixture_path).parts
                or "\\" in fixture_path
            ):
                raise ValueError(
                    "governed effectiveness fixture paths must be repository-relative"
                )
            label["strata"] = strata
            label["fixture_sha256"] = fixture_sha256
            label["fixture_path"] = fixture_path
        labels.append(label)
    return labels


def _corpus_authority(
    document: dict[str, Any], path: Path, authority_time: datetime
) -> dict[str, Any]:
    if document.get("schema_version") != "2.0":
        return {"validated": False, "organization_approved": False}
    required = {
        "schema_version",
        "corpus_id",
        "revision",
        "training_corpus_sha256",
        "holdout_labels_sha256",
        "minimum_authority_signatures",
        "authorities",
        "labels",
    }
    if set(document) != required:
        raise ValueError("governed effectiveness corpus fields do not match")
    label_digest = hashlib.sha256(canonical_bytes(document["labels"])).hexdigest()
    training = str(document.get("training_corpus_sha256") or "")
    holdout = str(document.get("holdout_labels_sha256") or "")
    if (
        holdout != label_digest
        or training == holdout
        or any(
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            for digest in (training, holdout)
        )
    ):
        raise ValueError("effectiveness training/holdout identity is invalid")
    threshold = document.get("minimum_authority_signatures")
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, int)
        or not 2 <= threshold <= 16
    ):
        raise ValueError("effectiveness authority threshold is invalid")
    subject = {
        "schema_version": "2.0",
        "corpus_id": document["corpus_id"],
        "revision": document["revision"],
        "training_corpus_sha256": training,
        "holdout_labels_sha256": holdout,
    }
    verified = verify_governance_quorum(
        path,
        document["authorities"],
        subject,
        threshold,
        authority_time,
        purpose="effectiveness-corpus",
    )
    return {
        "validated": True,
        "organization_approved": True,
        "minimum_authority_signatures": threshold,
        "authority_signers": sorted({item[0] for item in verified}),
        "authority_collectors": sorted({item[1] for item in verified}),
        "authority_organizations": sorted({item[2] for item in verified}),
        "holdout_labels_sha256": holdout,
        "training_corpus_sha256": training,
    }


def _effectiveness_time(
    document: dict[str, Any],
    corpus_path: Path,
    verification: dict[str, Any],
    corpus_sha256: str,
    trusted_time: Path | None,
    trusted_time_sha256: str,
) -> dict[str, Any]:
    governed = document.get("schema_version") == "2.0"
    if trusted_time is None:
        if governed:
            raise ValueError("governed effectiveness evaluation requires trusted time")
        return {
            "validated": False,
            "observed_at": "",
            "trusted_time_sha256": "",
            "receipt_sha256": "",
        }
    expected = trusted_time_sha256.strip().casefold()
    if len(expected) != 64 or any(
        character not in "0123456789abcdef" for character in expected
    ):
        raise ValueError(
            "trusted-time SHA-256 must be exactly 64 hexadecimal characters"
        )
    path = resolve_regular_file(trusted_time, "effectiveness trusted-time context")
    if sha256_file(path) != expected:
        raise ValueError("effectiveness trusted-time context digest does not match")
    context = _read_object(path, 8 * 1024 * 1024)
    if (
        set(context) != {"schema_version", "trusted_time"}
        or context.get("schema_version") != "1.0"
    ):
        raise ValueError("effectiveness trusted-time context fields do not match")
    challenge = hashlib.sha256(
        canonical_bytes(
            {
                "purpose": "effectiveness-holdout-evaluation",
                "report_checksums_sha256": verification["checksums_sha256"],
                "corpus_sha256": corpus_sha256,
                "holdout_labels_sha256": document.get("holdout_labels_sha256", ""),
            }
        )
    ).hexdigest()
    receipt = verify_rfc3161(
        path,
        context["trusted_time"],
        challenge,
        require_advanced=governed,
    )
    return {
        "validated": True,
        "observed_at": receipt["trusted_time_observed_at"],
        "trusted_time_sha256": receipt["trusted_time_sha256"],
        "receipt_sha256": receipt["trusted_time_receipt_sha256"],
    }


def _consume_effectiveness_replay(
    document: dict[str, Any],
    verification: dict[str, Any],
    corpus_sha256: str,
    time_authority: dict[str, Any],
    replay_ledger: Path | None,
    replay_service_url: str,
    replay_service_token_env: str,
    replay_service_receipt_key: Path | None,
    replay_service_receipt_key_sha256: str,
    replay_query_budget: int,
) -> dict[str, Any] | None:
    governed = document.get("schema_version") == "2.0"
    replay_key = hashlib.sha256(
        canonical_bytes(
            {
                "purpose": "effectiveness-holdout-evaluation",
                "report_checksums_sha256": verification["checksums_sha256"],
                "corpus_sha256": corpus_sha256,
                "trusted_time_sha256": time_authority["trusted_time_sha256"],
            }
        )
    ).hexdigest()
    if governed:
        if replay_ledger is not None:
            raise ValueError(
                "governed effectiveness evaluation cannot use a rollbackable local ledger"
            )
        return _consume_remote_effectiveness_replay(
            replay_key,
            corpus_id=str(document.get("corpus_id") or ""),
            holdout_sha256=str(document.get("holdout_labels_sha256") or ""),
            observed_at=str(time_authority["observed_at"]),
            service_url=replay_service_url,
            token_env=replay_service_token_env,
            receipt_key=replay_service_receipt_key,
            receipt_key_sha256=replay_service_receipt_key_sha256,
            query_budget=replay_query_budget,
        )
    if replay_ledger is None:
        return None
    ledger = replay_ledger.expanduser().resolve()
    ledger.parent.mkdir(parents=True, exist_ok=True)
    if ledger.is_symlink():
        raise ValueError("effectiveness replay ledger must not be a symbolic link")
    connection = sqlite3.connect(ledger, timeout=30, isolation_level=None)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS effectiveness_replay "
            "(replay_key TEXT PRIMARY KEY, observed_at TEXT NOT NULL)"
        )
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "INSERT INTO effectiveness_replay(replay_key, observed_at) VALUES (?, ?)",
                (replay_key, str(time_authority["observed_at"])),
            )
        except sqlite3.IntegrityError as exc:
            connection.execute("ROLLBACK")
            raise ValueError(
                "effectiveness evaluation replay was already consumed"
            ) from exc
        connection.execute("COMMIT")
    finally:
        connection.close()
    return {
        "mode": "local-ledger",
        "replay_key": replay_key,
        "request_sha256": replay_key,
        "service_key_sha256": "",
        "sequence": 0,
        "holdout_uses": 1,
        "checkpoint_size": 0,
        "checkpoint_root_sha256": "",
        "signature_base64": "",
        "signed_statement": None,
        "public_key_pem_base64": "",
        "leaf_sha256": "",
        "leaf_index": 0,
        "inclusion_proof_sha256": [],
        "previous_checkpoint_size": 0,
        "previous_checkpoint_root_sha256": "",
        "consistency_proof_sha256": [],
        "witnesses": [],
    }


def _consume_remote_effectiveness_replay(
    replay_key: str,
    *,
    corpus_id: str,
    holdout_sha256: str,
    observed_at: str,
    service_url: str,
    token_env: str,
    receipt_key: Path | None,
    receipt_key_sha256: str,
    query_budget: int,
) -> dict[str, Any]:
    target = urlsplit(service_url)
    if (
        target.scheme != "https"
        or not target.hostname
        or target.username
        or target.password
        or target.query
        or target.fragment
    ):
        raise ValueError(
            "governed effectiveness replay service must be credential-free HTTPS"
        )
    if (
        not token_env
        or token_env.upper() != token_env
        or not token_env.replace("_", "").isalnum()
        or not os.environ.get(token_env)
    ):
        raise ValueError("governed effectiveness replay authentication is unavailable")
    if (
        receipt_key is None
        or not _digest(receipt_key_sha256)
        or not 1 <= query_budget <= 100
    ):
        raise ValueError("governed effectiveness replay receipt policy is incomplete")
    _, public_bytes = read_regular_file(
        receipt_key,
        "effectiveness replay receipt key",
        maximum_bytes=64 * 1024,
    )
    if hashlib.sha256(public_bytes).hexdigest() != receipt_key_sha256:
        raise ValueError("effectiveness replay receipt key SHA-256 does not match")
    public_key = serialization.load_pem_public_key(public_bytes)
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("effectiveness replay receipt key must use Ed25519")
    request_subject = {
        "schema_version": "1.0",
        "replay_key": replay_key,
        "corpus_id": corpus_id,
        "holdout_labels_sha256": holdout_sha256,
        "observed_at": observed_at,
        "query_budget": query_budget,
    }
    request = Request(  # noqa: S310
        service_url,
        data=canonical_bytes(request_subject),
        headers={
            "Authorization": f"Bearer {os.environ[token_env]}",
            "Content-Type": "application/json",
            "User-Agent": "py-security-suite-effectiveness-replay/1",
        },
        method="POST",
    )
    try:
        with urlopen(  # noqa: S310
            request, timeout=10, context=ssl.create_default_context()
        ) as response:
            payload = response.read(64 * 1024 + 1)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise ValueError(
            "governed effectiveness replay service rejected consumption"
        ) from exc
    if len(payload) > 64 * 1024:
        raise ValueError("governed effectiveness replay receipt is oversized")
    try:
        receipt = strict_loads(payload)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "governed effectiveness replay receipt is invalid JSON"
        ) from exc
    fields = {
        "schema_version",
        "status",
        "replay_key",
        "sequence",
        "holdout_uses",
        "request_sha256",
        "checkpoint_size",
        "checkpoint_root_sha256",
        "log_identity_sha256",
        "leaf_index",
        "leaf_sha256",
        "inclusion_proof_sha256",
        "previous_checkpoint_size",
        "previous_checkpoint_root_sha256",
        "consistency_proof_sha256",
        "witnesses",
        "signature_base64",
    }
    if not isinstance(receipt, dict) or set(receipt) != fields:
        raise ValueError("governed effectiveness replay receipt fields do not match")
    signed = {
        name: receipt[name] for name in fields - {"signature_base64", "witnesses"}
    }
    if (
        receipt["schema_version"] != "1.0"
        or receipt["status"] != "consumed"
        or receipt["replay_key"] != replay_key
        or receipt["request_sha256"]
        != hashlib.sha256(canonical_bytes(request_subject)).hexdigest()
        or isinstance(receipt["sequence"], bool)
        or not isinstance(receipt["sequence"], int)
        or receipt["sequence"] < 1
        or isinstance(receipt["holdout_uses"], bool)
        or not isinstance(receipt["holdout_uses"], int)
        or not 1 <= receipt["holdout_uses"] <= query_budget
        or isinstance(receipt["checkpoint_size"], bool)
        or not isinstance(receipt["checkpoint_size"], int)
        or receipt["checkpoint_size"] < receipt["sequence"]
        or not _digest(str(receipt["checkpoint_root_sha256"]))
        or not _digest(str(receipt["log_identity_sha256"]))
        or receipt["leaf_sha256"]
        != hashlib.sha256(b"\x00" + canonical_bytes(request_subject)).hexdigest()
        or receipt["leaf_index"] != receipt["sequence"] - 1
        or not _proof(receipt["inclusion_proof_sha256"])
        or not _checkpoint(receipt)
    ):
        raise ValueError("governed effectiveness replay receipt policy failed")
    checkpoint_state = os.environ.get(
        "PYSEC_EFFECTIVENESS_CHECKPOINT_STATE_PATH", ""
    ).strip()
    if not checkpoint_state:
        raise ValueError("effectiveness checkpoint state is unavailable")
    state_path = Path(checkpoint_state).expanduser().resolve()
    configured_previous_size, configured_previous_root = _checkpoint_state(state_path)
    if (
        receipt["previous_checkpoint_size"] != configured_previous_size
        or receipt["previous_checkpoint_root_sha256"] != configured_previous_root
        or not _verify_inclusion(
            str(receipt["leaf_sha256"]),
            int(receipt["leaf_index"]),
            int(receipt["checkpoint_size"]),
            receipt["inclusion_proof_sha256"],
            str(receipt["checkpoint_root_sha256"]),
        )
        or not _verify_consistency(
            int(receipt["previous_checkpoint_size"]),
            int(receipt["checkpoint_size"]),
            str(receipt["previous_checkpoint_root_sha256"]),
            str(receipt["checkpoint_root_sha256"]),
            receipt["consistency_proof_sha256"],
        )
    ):
        raise ValueError("governed effectiveness transparency proof failed")
    try:
        signature = base64.b64decode(str(receipt["signature_base64"]), validate=True)
        public_key.verify(signature, canonical_bytes(signed))
    except Exception as exc:
        raise ValueError(
            "governed effectiveness replay receipt signature failed"
        ) from exc
    _verify_checkpoint_witnesses(
        receipt["witnesses"], signed, _receipt_time(request_subject["observed_at"])
    )
    _verify_gossip_checkpoint(signed, _receipt_time(request_subject["observed_at"]))
    _advance_checkpoint_state(
        state_path,
        expected_size=configured_previous_size,
        expected_root=configured_previous_root,
        new_size=int(receipt["checkpoint_size"]),
        new_root=str(receipt["checkpoint_root_sha256"]),
    )
    return {
        "mode": "remote-signed-checkpoint",
        "replay_key": replay_key,
        "request_sha256": str(receipt["request_sha256"]),
        "service_key_sha256": receipt_key_sha256,
        "sequence": int(receipt["sequence"]),
        "holdout_uses": int(receipt["holdout_uses"]),
        "checkpoint_size": int(receipt["checkpoint_size"]),
        "checkpoint_root_sha256": str(receipt["checkpoint_root_sha256"]),
        "signature_base64": str(receipt["signature_base64"]),
        "signed_statement": signed,
        "public_key_pem_base64": base64.b64encode(public_bytes).decode("ascii"),
        "leaf_sha256": str(receipt["leaf_sha256"]),
        "leaf_index": int(receipt["leaf_index"]),
        "inclusion_proof_sha256": list(receipt["inclusion_proof_sha256"]),
        "previous_checkpoint_size": int(receipt["previous_checkpoint_size"]),
        "previous_checkpoint_root_sha256": str(
            receipt["previous_checkpoint_root_sha256"]
        ),
        "consistency_proof_sha256": list(receipt["consistency_proof_sha256"]),
        "witnesses": list(receipt["witnesses"]),
    }


def _verify_checkpoint_witnesses(
    value: object, statement: dict[str, Any], observed_at: datetime
) -> None:
    raw_policy = os.environ.get("PYSEC_EFFECTIVENESS_WITNESS_KEYS_JSON", "").strip()
    try:
        policy = strict_loads(raw_policy)
    except (TypeError, ValueError) as exc:
        raise ValueError("effectiveness witness policy is invalid") from exc
    if (
        not isinstance(policy, dict)
        or len(policy) < 2
        or not isinstance(value, list)
        or len(value) < 2
    ):
        raise ValueError("effectiveness checkpoint witness quorum is unavailable")
    approved: dict[str, tuple[Ed25519PublicKey, str]] = {}
    for digest, configuration in policy.items():
        if (
            not isinstance(digest, str)
            or not _digest(digest)
            or not isinstance(configuration, dict)
            or set(configuration) != {"path", "organization", "not_before", "not_after"}
        ):
            raise ValueError("effectiveness witness policy is invalid")
        path = Path(str(configuration["path"])).expanduser().resolve()
        _, payload = read_regular_file(
            path, "effectiveness witness key", maximum_bytes=16 * 1024
        )
        if hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError("effectiveness witness key does not match its pin")
        loaded_key = serialization.load_pem_public_key(payload)
        if not isinstance(loaded_key, Ed25519PublicKey):
            raise ValueError("effectiveness witness key is not Ed25519")
        not_before = _receipt_time(configuration["not_before"])
        not_after = _receipt_time(configuration["not_after"])
        organization = str(configuration["organization"]).strip()
        if not organization or not_before > observed_at or observed_at > not_after:
            raise ValueError("effectiveness witness lifecycle is invalid")
        approved[digest] = loaded_key, organization
    observed: set[str] = set()
    organizations: set[str] = set()
    for witness in value:
        if not isinstance(witness, dict) or set(witness) != {
            "key_sha256",
            "signature_base64",
        }:
            raise ValueError("effectiveness checkpoint witness is invalid")
        digest = str(witness["key_sha256"])
        approved_witness = approved.get(digest)
        if approved_witness is None or digest in observed:
            raise ValueError("effectiveness checkpoint witness is not approved")
        witness_key, organization = approved_witness
        try:
            signature = base64.b64decode(
                str(witness["signature_base64"]), validate=True
            )
            witness_key.verify(signature, canonical_bytes(statement))
        except Exception as exc:
            raise ValueError(
                "effectiveness checkpoint witness signature failed"
            ) from exc
        observed.add(digest)
        organizations.add(organization)
    if len(observed) < 2 or len(organizations) < 2:
        raise ValueError("effectiveness checkpoint witness quorum was not met")


def _verify_gossip_checkpoint(statement: dict[str, Any], observed_at: datetime) -> None:
    raw_path = os.environ.get("PYSEC_EFFECTIVENESS_GOSSIP_CHECKPOINT_PATH", "").strip()
    expected_digest = (
        os.environ.get("PYSEC_EFFECTIVENESS_GOSSIP_CHECKPOINT_SHA256", "")
        .strip()
        .casefold()
    )
    if not raw_path or not _digest(expected_digest):
        raise ValueError("effectiveness gossip checkpoint policy is invalid")
    path = Path(raw_path).expanduser().resolve()
    _, payload = read_regular_file(
        path, "effectiveness gossip checkpoint", maximum_bytes=1024 * 1024
    )
    if hashlib.sha256(payload).hexdigest() != expected_digest:
        raise ValueError("effectiveness gossip checkpoint does not match its pin")
    expected = strict_loads(payload)
    if (
        not isinstance(expected, dict)
        or set(expected)
        != {
            "schema_version",
            "log_identity_sha256",
            "checkpoint_size",
            "checkpoint_root_sha256",
            "observed_at",
            "minimum_authority_signatures",
            "authorities",
        }
        or expected.get("schema_version") != "1.0"
        or expected.get("log_identity_sha256") != statement["log_identity_sha256"]
        or expected["checkpoint_size"] != statement["checkpoint_size"]
        or expected["checkpoint_root_sha256"] != statement["checkpoint_root_sha256"]
        or _receipt_time(expected["observed_at"]) > observed_at
        or observed_at - _receipt_time(expected["observed_at"]) > timedelta(hours=24)
        or isinstance(expected["minimum_authority_signatures"], bool)
        or not isinstance(expected["minimum_authority_signatures"], int)
        or expected["minimum_authority_signatures"] < 2
    ):
        raise ValueError(
            "effectiveness checkpoint is absent from external gossip state"
        )
    subject = {name: value for name, value in expected.items() if name != "authorities"}
    verify_governance_quorum(
        path,
        expected["authorities"],
        subject,
        expected["minimum_authority_signatures"],
        observed_at,
        purpose="effectiveness-gossip-checkpoint",
    )


def _receipt_time(value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("effectiveness receipt time is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError("effectiveness receipt time must include a timezone")
    return parsed.astimezone(UTC)


def _proof(value: object) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= 256
        and all(isinstance(item, str) and _digest(item) for item in value)
    )


def _checkpoint_state(path: Path) -> tuple[int, str]:
    if path.is_symlink():
        raise ValueError("effectiveness checkpoint state must not be a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30, isolation_level=None)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS checkpoint "
            "(identity INTEGER PRIMARY KEY CHECK(identity=1), size INTEGER NOT NULL, root TEXT NOT NULL)"
        )
        row = connection.execute(
            "SELECT size, root FROM checkpoint WHERE identity=1"
        ).fetchone()
        return (0, "") if row is None else (int(row[0]), str(row[1]))
    finally:
        connection.close()


def _advance_checkpoint_state(
    path: Path,
    *,
    expected_size: int,
    expected_root: str,
    new_size: int,
    new_root: str,
) -> None:
    connection = sqlite3.connect(path, timeout=30, isolation_level=None)
    try:
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT size, root FROM checkpoint WHERE identity=1"
        ).fetchone()
        current = (0, "") if row is None else (int(row[0]), str(row[1]))
        if current != (expected_size, expected_root):
            connection.execute("ROLLBACK")
            raise ValueError("effectiveness checkpoint advanced concurrently")
        connection.execute(
            "INSERT INTO checkpoint(identity, size, root) VALUES (1, ?, ?) "
            "ON CONFLICT(identity) DO UPDATE SET size=excluded.size, root=excluded.root",
            (new_size, new_root),
        )
        connection.execute("COMMIT")
    finally:
        connection.close()
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _checkpoint(receipt: dict[str, Any]) -> bool:
    old = receipt.get("previous_checkpoint_size")
    old_root = receipt.get("previous_checkpoint_root_sha256")
    return bool(
        isinstance(receipt.get("leaf_index"), int)
        and not isinstance(receipt.get("leaf_index"), bool)
        and isinstance(old, int)
        and not isinstance(old, bool)
        and 0 <= old <= receipt["checkpoint_size"]
        and ((old == 0 and old_root == "") or (old > 0 and _digest(str(old_root))))
        and _proof(receipt.get("consistency_proof_sha256"))
    )


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _verify_inclusion(
    leaf: str, index: int, size: int, proof: list[str], root: str
) -> bool:
    if not 0 <= index < size:
        return False
    value = bytes.fromhex(leaf)
    node_index, last = index, size - 1
    for sibling_hex in proof:
        sibling = bytes.fromhex(sibling_hex)
        if node_index & 1 or node_index == last:
            value = _node(sibling, value)
            while node_index and not node_index & 1:
                node_index >>= 1
                last >>= 1
        else:
            value = _node(value, sibling)
        node_index >>= 1
        last >>= 1
    return last == 0 and value.hex() == root


def _verify_consistency(
    old_size: int, new_size: int, old_root: str, new_root: str, proof: list[str]
) -> bool:
    if old_size == 0:
        return not proof
    if old_size == new_size:
        return old_root == new_root and not proof
    if not 0 < old_size < new_size or not proof:
        return False
    first, *remaining = [bytes.fromhex(item) for item in proof]
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if fn == 0:
        old_hash = bytes.fromhex(old_root)
        new_hash = bytes.fromhex(old_root)
        remaining = [first, *remaining]
    else:
        old_hash = new_hash = first
    for sibling in remaining:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            old_hash = _node(sibling, old_hash)
            new_hash = _node(sibling, new_hash)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        elif fn < sn:
            new_hash = _node(new_hash, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and old_hash.hex() == old_root and new_hash.hex() == new_root


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _diversity(labels: list[dict[str, Any]]) -> dict[str, int]:
    names = ("cwe", "language", "parser_variant", "boundary_type", "severity")
    result = {
        name: len(
            {
                str(label.get("strata", {}).get(name) or "")
                for label in labels
                if label.get("strata", {}).get(name)
            }
        )
        for name in names
    }
    result["mutation_operator"] = len(
        {
            str(label.get("strata", {}).get("mutation_operator") or "")
            for label in labels
            if label.get("strata", {}).get("mutation_operator")
            not in {None, "", "none"}
        }
    )
    return result


def _validate_fixture_paths(labels: list[dict[str, Any]], report: Path) -> None:
    clean_paths = _required_clean_paths(labels)
    governed_paths = {
        str(label["fixture_path"]) for label in labels if "fixture_path" in label
    }
    required = clean_paths | governed_paths
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
    file_sha256 = dict(identity.file_sha256)
    detached = sorted(
        str(label["id"])
        for label in labels
        if "fixture_path" in label
        and file_sha256.get(str(label["fixture_path"])) != label["fixture_sha256"]
    )
    if detached:
        raise ValueError(
            "governed effectiveness fixture digest is detached from the sealed "
            "source inventory: " + ", ".join(detached[:20])
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
        **({"strata": label["strata"]} if "strata" in label else {}),
    }


def _validate_unique_finding_assignments(
    labels: list[dict[str, Any]], findings: list[dict[str, Any]]
) -> None:
    assignments: dict[str, list[str]] = {}
    for finding in findings:
        finding_id = str(finding.get("finding_id") or "unknown")
        matched = [
            str(label["id"])
            for label in labels
            if _finding_matches(finding, label["match"])
        ]
        if len(matched) > 1:
            assignments[finding_id] = matched
    if assignments:
        detail = ", ".join(
            f"{finding_id}: {labels}"
            for finding_id, labels in sorted(assignments.items())[:10]
        )
        raise ValueError(
            "effectiveness findings must map to exactly one label; overlaps: " + detail
        )


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
