from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from companion.assurance_context import target_set_sha256
from companion.protocol_security import _cases, _endpoint, main


def _context(path: Path) -> None:
    from datetime import UTC, datetime

    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "run_id": "run-1",
                "target_manifest_sha256": "1" * 64,
                "exercised_targets_sha256": target_set_sha256(
                    ["protocol:grpc-contract", "protocol:websocket-fault"]
                ),
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


class CompanionProtocolSecurityTests(unittest.TestCase):
    def test_contract_covers_normal_and_fault_cases_without_payload_retention(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract = root / "protocol.json"
            output = root / "evidence.json"
            context = root / "context.json"
            contract.write_text(
                json.dumps(
                    {
                        "cases": [
                            {
                                "id": "grpc-contract",
                                "protocol": "grpc",
                                "endpoint": "127.0.0.1:50051",
                                "method": "/demo.Service/Get",
                                "request_env": "PYSEC_GRPC_REQUEST_B64",
                                "role": "user",
                                "control": "contract",
                                "expected_status": ["OK"],
                                "expected_response_sha256": "a" * 64,
                            },
                            {
                                "id": "websocket-fault",
                                "protocol": "websocket",
                                "endpoint": "ws://127.0.0.1:8765/ws",
                                "method": "",
                                "request_env": "PYSEC_WS_FAULT_B64",
                                "role": "anonymous",
                                "control": "fault",
                                "expected_status": ["OK"],
                                "expected_response_sha256": "b" * 64,
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            _context(context)
            with (
                patch(
                    "companion.protocol_security._execute",
                    side_effect=[("OK", "a" * 64), ("OK", "b" * 64)],
                ),
                patch(
                    "companion.protocol_security.load_context",
                    return_value=_verified_context(),
                ),
            ):
                self.assertEqual(
                    main(
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
                    ),
                    0,
                )
            evidence = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(evidence["findings"], [])
            self.assertIn("fault-injection", evidence["execution"]["features"])
            self.assertNotIn("request_env", json.dumps(evidence))

    def test_contract_rejects_external_endpoints_and_missing_fault_cases(self) -> None:
        with self.assertRaises(ValueError):
            _endpoint("example.com:443", "grpc")
        with self.assertRaisesRegex(ValueError, "fault-injection"):
            _cases(
                {
                    "cases": [
                        {
                            "id": "only-normal",
                            "protocol": "tcp",
                            "endpoint": "127.0.0.1:9000",
                            "method": "",
                            "request_env": "PYSEC_REQUEST_B64",
                            "role": "user",
                            "control": "contract",
                            "expected_status": ["OK"],
                            "expected_response_sha256": "",
                        }
                    ]
                }
            )


if __name__ == "__main__":
    unittest.main()
