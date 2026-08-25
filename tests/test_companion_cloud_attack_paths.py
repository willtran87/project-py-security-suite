from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from companion.cloud_attack_paths import _analyze, main


class CompanionCloudAttackPathTests(unittest.TestCase):
    def test_derives_redacted_public_to_sensitive_paths_and_canary(self) -> None:
        document = {
            "schema_version": "1.0",
            "nodes": [
                {
                    "id": "public-load-balancer-account-123",
                    "type": "public-endpoint",
                    "public_entry": True,
                    "sensitive_asset": False,
                },
                {
                    "id": "workload-role-account-123",
                    "type": "workload-identity",
                    "public_entry": False,
                    "sensitive_asset": False,
                },
                {
                    "id": "production-secret-account-123",
                    "type": "secret-store",
                    "public_entry": False,
                    "sensitive_asset": True,
                },
            ],
            "edges": [
                {
                    "source": "public-load-balancer-account-123",
                    "target": "workload-role-account-123",
                    "type": "network-reachability",
                },
                {
                    "source": "workload-role-account-123",
                    "target": "production-secret-account-123",
                    "type": "identity-permission",
                },
            ],
            "canary_path": {
                "source": "public-load-balancer-account-123",
                "target": "production-secret-account-123",
            },
            "drift_checked": True,
        }

        result = _analyze(document)

        rendered = json.dumps(result)
        self.assertEqual(len(result["findings"]), 1)
        self.assertNotIn("account-123", rendered)
        self.assertEqual(result["execution"]["canaries_observed"], 1)

    def test_cli_rejects_unbounded_or_incomplete_graphs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "graph.json"
            output = root / "result.json"
            source.write_text(json.dumps({"nodes": []}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "fields"):
                main(["--input", str(source), "--output", str(output)])


if __name__ == "__main__":
    unittest.main()
