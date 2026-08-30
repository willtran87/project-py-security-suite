from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from py_security_suite.governance import consume_governance_replay


class RemoteGovernanceReplayTests(unittest.TestCase):
    def test_local_replay_is_atomic_and_rejects_duplicate_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "replay.sqlite3"
            document = {"generation": 3, "nonce": "governance-nonce-0003"}
            first = consume_governance_replay(
                document, "e" * 64, ledger, "organization-policy"
            )
            self.assertEqual(first["replay_backend"], "local-sqlite")
            self.assertEqual(len(first["replay_token_sha256"]), 64)
            with self.assertRaisesRegex(ValueError, "replay was detected"):
                consume_governance_replay(
                    document, "e" * 64, ledger, "organization-policy"
                )

    def test_local_replay_rejects_missing_and_unsafe_ledgers(self) -> None:
        document = {"generation": 3, "nonce": "governance-nonce-0003"}
        with self.assertRaisesRegex(ValueError, "requires a replay ledger"):
            consume_governance_replay(document, "e" * 64, None, "policy")
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "directory-ledger"
            ledger.mkdir()
            with self.assertRaisesRegex(ValueError, "not a regular file"):
                consume_governance_replay(document, "e" * 64, ledger, "policy")

    def test_remote_receipt_supplies_monotonic_replay_and_trusted_time(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            credential = root / "credential.pem"
            credential.write_bytes(b"deployment-pinned-material")
            digest = hashlib.sha256(credential.read_bytes()).hexdigest()
            environment = {
                "PYSEC_GOVERNANCE_REPLAY_SERVICE_URL": "https://replay.example/consume",
                "PYSEC_GOVERNANCE_REPLAY_SERVICE_TOKEN_ENV": "PYSEC_TEST_TOKEN",
                "PYSEC_GOVERNANCE_REPLAY_SERVICE_CA": str(credential),
                "PYSEC_GOVERNANCE_REPLAY_SERVICE_CA_SHA256": digest,
                "PYSEC_GOVERNANCE_REPLAY_SERVICE_RECEIPT_KEY": str(credential),
                "PYSEC_GOVERNANCE_REPLAY_SERVICE_RECEIPT_KEY_SHA256": digest,
                "PYSEC_GOVERNANCE_REPLAY_SERVICE_CLIENT_CERT": str(credential),
                "PYSEC_GOVERNANCE_REPLAY_SERVICE_CLIENT_CERT_SHA256": digest,
                "PYSEC_GOVERNANCE_REPLAY_SERVICE_CLIENT_KEY": str(credential),
                "PYSEC_GOVERNANCE_REPLAY_SERVICE_CLIENT_KEY_SHA256": digest,
                "PYSEC_GOVERNANCE_REPLAY_SERVICE_STATE_FILE": str(
                    root / "replay-state.json"
                ),
            }
            document = {
                "generation": 4,
                "nonce": "governance-nonce-0004",
                "valid_from": "2026-08-22T00:00:00Z",
                "valid_until": "2026-08-24T00:00:00Z",
                "trust_root_sha256": "a" * 64,
            }
            receipt = {
                "schema_version": "1.0",
                "sequence": 41,
                "receipt_sha256": "b" * 64,
                "previous_receipt_sha256": "c" * 64,
                "consumed_at": "2026-08-23T12:00:00+00:00",
                "key_id": "d" * 64,
            }
            with (
                patch.dict(os.environ, {"PYSEC_TEST_TOKEN": "opaque"}),
                patch(
                    "py_security_suite.evidence_ingest._consume_replay_service",
                    return_value=receipt,
                ),
            ):
                result = consume_governance_replay(
                    document,
                    "e" * 64,
                    None,
                    "isolation-evidence",
                    trust_environment=environment,
                )
        self.assertEqual(result["replay_backend"], "remote-mtls-monotonic")
        self.assertEqual(result["replay_receipt_sequence"], 41)
        self.assertEqual(result["trusted_consumed_at"], receipt["consumed_at"])

    def test_remote_policy_cannot_silently_fall_back_to_local_ledger(self) -> None:
        with self.assertRaisesRegex(ValueError, "remote monotonic"):
            consume_governance_replay(
                {"generation": 1, "nonce": "governance-nonce-0001"},
                "e" * 64,
                Path("unused.sqlite3"),
                "isolation-evidence",
                trust_environment={"PYSEC_GOVERNANCE_REPLAY_REQUIRE_REMOTE": "true"},
            )
