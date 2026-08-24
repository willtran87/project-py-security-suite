from __future__ import annotations

import json
import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from companion.assurance_context import target_set_sha256
from companion.authorization_security import (
    _loopback_url,
    _oracle,
    _recovery_checks,
    _verify_recovery_receipt,
    main,
)
from companion.strict_json import canonical_bytes


def _context(path: Path, target_ids: list[str]) -> None:
    from datetime import UTC, datetime

    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "run_id": "run-1",
                "target_manifest_sha256": "1" * 64,
                "exercised_targets_sha256": target_set_sha256(target_ids),
                "deployment_sha256": "2" * 64,
                "surface_sha256": "3" * 64,
                "challenge_sha256": "4" * 64,
                "trusted_time": {
                    "authority": "test-authority",
                    "observed_at": datetime.now(UTC).isoformat(),
                    "receipt_sha256": "5" * 64,
                },
            }
        ),
        encoding="utf-8",
    )


def _verified_context() -> dict[str, str]:
    from datetime import UTC, datetime

    return {
        "run_id": "run-1",
        "target_manifest_sha256": "1" * 64,
        "exercised_targets_sha256": "2" * 64,
        "deployment_sha256": "3" * 64,
        "surface_sha256": "4" * 64,
        "challenge_sha256": "5" * 64,
        "trusted_time_sha256": "6" * 64,
        "trusted_time_observed_at": datetime.now(UTC).isoformat(),
        "trusted_time_receipt_sha256": "7" * 64,
        "trusted_time_signer_sha256": "8" * 64,
    }


class CompanionAuthorizationSecurityTests(unittest.TestCase):
    def test_contract_exercises_allow_and_deny_roles_without_retaining_tokens(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract = root / "authorization.json"
            output = root / "browser-security.json"
            context = root / "context.json"
            contract.write_text(
                json.dumps(
                    {
                        "schema_version": "2.0",
                        "base_url": "http://127.0.0.1:8765/",
                        "roles": {"user_a": {}, "user_b": {}},
                        "cases": [
                            {
                                "id": "tenant-record",
                                "path": "/records/tenant-a",
                                "allow": ["user_a"],
                                "deny": ["user_b"],
                                "allowed_status": [200],
                                "denied_status": [403, 404],
                            }
                        ],
                        "state_cases": [
                            {
                                "id": "approval",
                                "steps": [
                                    {
                                        "id": "create",
                                        "path": "/transfers",
                                        "role": "user_a",
                                        "method": "POST",
                                        "body_env": "",
                                        "expected_status": [201],
                                        "control": "state-transition",
                                    },
                                    {
                                        "id": "limit",
                                        "path": "/transfers/approve",
                                        "role": "user_a",
                                        "method": "POST",
                                        "body_env": "",
                                        "expected_status": [403],
                                        "control": "approval-limit",
                                    },
                                ],
                                "replay": {
                                    "step_index": 0,
                                    "expected_status": [409],
                                },
                                "out_of_order": {
                                    "step_index": 1,
                                    "expected_status": [403],
                                },
                                "concurrency": {
                                    "step_index": 1,
                                    "attempts": 2,
                                    "maximum_successes": 0,
                                    "success_status": [200],
                                },
                                "reset": {
                                    "path": "/fixtures/reset",
                                    "role": "user_a",
                                    "method": "POST",
                                    "body_env": "",
                                    "expected_status": [204],
                                },
                                "postconditions": [
                                    {
                                        "id": "atomic-state",
                                        "phase": phase,
                                        "path": "/fixtures/state",
                                        "role": "user_a",
                                        "expected_status": [200],
                                        "assertions": [
                                            {
                                                "pointer": "/approved",
                                                "operator": "equals",
                                                "value": False,
                                            }
                                        ],
                                    }
                                    for phase in (
                                        "after-reset-out-of-order",
                                        "after-out-of-order",
                                        "after-reset-sequence",
                                        "after-sequence",
                                        "after-replay",
                                        "after-reset-concurrency",
                                        "after-concurrency",
                                    )
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            _context(
                context,
                [
                    "auth:tenant-record:allow:user_a",
                    "auth:tenant-record:deny:user_b",
                    "state:approval:create",
                    "state:approval:limit",
                    "out-of-order:approval:limit",
                    "replay:approval:create",
                    "concurrency:approval:limit:0",
                    "concurrency:approval:limit:1",
                    "reset:approval:out-of-order",
                    "reset:approval:sequence",
                    "reset:approval:concurrency",
                    *(
                        f"postcondition:approval:{phase}:atomic-state"
                        for phase in (
                            "after-reset-out-of-order",
                            "after-out-of-order",
                            "after-reset-sequence",
                            "after-sequence",
                            "after-replay",
                            "after-reset-concurrency",
                            "after-concurrency",
                        )
                    ),
                ],
            )
            with (
                patch(
                    "companion.authorization_security._request",
                    side_effect=[
                        200,
                        403,
                        204,
                        403,
                        204,
                        201,
                        403,
                        409,
                        204,
                        403,
                        403,
                    ],
                ),
                patch(
                    "companion.authorization_security._request_observation",
                    return_value=(200, b'{"approved":false}'),
                ),
                patch(
                    "companion.authorization_security.load_context",
                    return_value=_verified_context(),
                ),
            ):
                status = main(
                    [
                        "--contract",
                        str(contract),
                        "--output",
                        str(output),
                        "--revision",
                        "abc123",
                        "--context",
                        str(context),
                        "--run-id",
                        "run-1",
                    ]
                )
            self.assertEqual(status, 0)
            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(document["schema_version"], "2.0")
            self.assertEqual(document["findings"], [])
            self.assertEqual(document["execution"]["targets_exercised"], 18)
            self.assertEqual(document["execution"]["roles"], ["user_a", "user_b"])
            self.assertEqual(document["execution"]["canaries_observed"], 1)
            self.assertIn("approval-limits", document["execution"]["features"])

    def test_contract_rejects_external_or_credential_bearing_targets(self) -> None:
        for value in (
            "https://example.com/",
            "http://user:password@localhost/",
            "file:///tmp/app",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                _loopback_url(value)

    def test_independent_oracle_requires_distinct_origin_and_credentials(self) -> None:
        roles = {"user": {"authorization_env": "PYSEC_USER_TOKEN"}}
        with patch.dict(
            "os.environ", {"PYSEC_AUTHORIZATION_ORACLE_IDENTITY_SHA256": "a" * 64}
        ):
            oracle = _oracle(
                {
                    "base_url": "http://127.0.0.1:8766/",
                    "authorization_env": "PYSEC_ORACLE_TOKEN",
                    "identity_sha256": "a" * 64,
                },
                "http://127.0.0.1:8765/",
                roles,
            )
        self.assertEqual(oracle["role"]["authorization_env"], "PYSEC_ORACLE_TOKEN")
        with (
            patch.dict(
                "os.environ",
                {"PYSEC_AUTHORIZATION_ORACLE_IDENTITY_SHA256": "a" * 64},
            ),
            self.assertRaisesRegex(ValueError, "independent network origin"),
        ):
            _oracle(
                {
                    "base_url": "http://127.0.0.1:8765/observer",
                    "authorization_env": "PYSEC_ORACLE_TOKEN",
                    "identity_sha256": "a" * 64,
                },
                "http://127.0.0.1:8765/",
                roles,
            )
        with (
            patch.dict(
                "os.environ",
                {"PYSEC_AUTHORIZATION_ORACLE_IDENTITY_SHA256": "a" * 64},
            ),
            self.assertRaisesRegex(ValueError, "credentials distinct"),
        ):
            _oracle(
                {
                    "base_url": "http://127.0.0.1:8766/",
                    "authorization_env": "PYSEC_USER_TOKEN",
                    "identity_sha256": "a" * 64,
                },
                "http://127.0.0.1:8765/",
                roles,
            )

    def test_recovery_checks_require_restart_and_replica_failover(self) -> None:
        roles = {"operator": {"authorization_env": "PYSEC_OPERATOR_TOKEN"}}

        def check(phase: str) -> dict[str, object]:
            return {
                "id": phase,
                "phase": phase,
                "trigger": {
                    "path": f"/fixtures/{phase}",
                    "role": "operator",
                    "method": "POST",
                    "body_env": "",
                    "expected_status": [202],
                },
                "postcondition": {
                    "path": "/fixtures/state",
                    "expected_status": [200],
                    "assertions": [
                        {"pointer": "/committed", "operator": "equals", "value": True}
                    ],
                },
            }

        normalized = _recovery_checks(
            [check("process-restart"), check("replica-failover")], roles
        )
        self.assertEqual(
            {item["phase"] for item in normalized},
            {"process-restart", "replica-failover"},
        )
        with self.assertRaisesRegex(ValueError, "restart and replica failover"):
            _recovery_checks(
                [check("process-restart"), check("process-restart") | {"id": "again"}],
                roles,
            )

    def test_recovery_receipt_proves_instance_transition(self) -> None:
        from datetime import UTC, datetime, timedelta

        with tempfile.TemporaryDirectory() as directory:
            key = Ed25519PrivateKey.generate()
            public_path = Path(directory) / "orchestrator.pem"
            public_path.write_bytes(
                key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            identity = hashlib.sha256(public_path.read_bytes()).hexdigest()
            observed = datetime.now(UTC)
            signed = {
                "schema_version": "1.0",
                "check_id": "restart",
                "phase": "process-restart",
                "event_id": "event-1",
                "before_instance_id": "instance-a",
                "after_instance_id": "instance-b",
                "orchestrator_identity_sha256": identity,
                "run_id": "run-1",
                "deployment_sha256": "a" * 64,
                "challenge_sha256": "b" * 64,
                "contract_sha256": "c" * 64,
                "request_sha256": "d" * 64,
                "oracle_identity_sha256": "e" * 64,
                "issued_at": (observed - timedelta(minutes=1)).isoformat(),
                "expires_at": (observed + timedelta(minutes=1)).isoformat(),
            }
            receipt = {
                **signed,
                "signature_base64": base64.b64encode(
                    key.sign(canonical_bytes(signed))
                ).decode(),
            }
            with patch.dict(
                "os.environ",
                {
                    "PYSEC_AUTHORIZATION_ORCHESTRATOR_KEY_PATH": str(public_path),
                    "PYSEC_AUTHORIZATION_ORCHESTRATOR_KEY_SHA256": identity,
                },
            ):
                _verify_recovery_receipt(
                    canonical_bytes(receipt),
                    check_id="restart",
                    phase="process-restart",
                    run_id="run-1",
                    deployment_sha256="a" * 64,
                    challenge_sha256="b" * 64,
                    contract_sha256="c" * 64,
                    request_sha256="d" * 64,
                    oracle_identity_sha256="e" * 64,
                    observed_at=observed.isoformat(),
                )


if __name__ == "__main__":
    unittest.main()
