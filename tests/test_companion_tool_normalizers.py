from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from companion.tool_normalizers import (
    _datadog_iast,
    _falco,
    _nuclei,
    _native_independent_validation,
    _oast,
    _polyglot_findings,
    _prowler,
    _receipt_findings,
    _restler,
    _secret_verification,
    _zap,
)


class CompanionToolNormalizerTests(unittest.TestCase):
    def test_independent_semantic_validation_requires_lifecycle_bound_quorum(
        self,
    ) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "companion.tool_normalizers.verify_authority_quorum",
                return_value=[
                    {
                        "schema_version": "2.0",
                        "signer_id": "signer-a",
                        "collector_id": "collector-a",
                        "organization": "org-a",
                    },
                    {
                        "schema_version": "2.0",
                        "signer_id": "signer-b",
                        "collector_id": "collector-b",
                        "organization": "org-b",
                    },
                ],
            ) as verifier,
        ):
            result = _native_independent_validation(
                {
                    "engine": "independent-engine",
                    "query_pack_sha256": "a" * 64,
                    "boundaries_sha256": "b" * 64,
                    "flows_sha256": "c" * 64,
                    "minimum_authority_signatures": 2,
                    "authorities": [{"receipt": "a"}, {"receipt": "b"}],
                },
                context=Path(directory) / "native.json",
                subject_context={
                    "languages": ["python", "typescript"],
                    "primary_engine": "primary-engine",
                    "primary_query_pack_sha256": "d" * 64,
                    "source_file_sets_sha256": "e" * 64,
                },
            )
        verifier.assert_called_once()
        self.assertTrue(result["authority"]["validated"])
        self.assertEqual(result["authority"]["organizations"], ["org-a", "org-b"])

    def test_iast_drops_taint_values_and_absolute_host_paths(self) -> None:
        findings = _datadog_iast(
            {
                "vulnerabilities": [
                    {
                        "type": "SQL_INJECTION",
                        "severity": "critical",
                        "hash": "stable-runtime-hash",
                        "location": {"path": "C:\\agent\\src\\app.py", "line": 7},
                        "evidence": {"valueParts": [{"value": "sensitive-input"}]},
                    }
                ]
            }
        )
        rendered = json.dumps(findings)
        self.assertNotIn("sensitive-input", rendered)
        self.assertNotIn("agent", rendered)
        self.assertEqual(findings[0]["classification"], "CWE-89")

    def test_falco_drops_command_lines_and_retains_bounded_rule_context(self) -> None:
        findings = _falco(
            [
                {
                    "rule": "Terminal shell in container",
                    "priority": "Critical",
                    "source": "syscall",
                    "output": "secret command --token value",
                    "output_fields": {
                        "container.name": "api",
                        "proc.name": "sh",
                        "proc.cmdline": "secret command --token value",
                    },
                }
            ]
        )
        rendered = json.dumps(findings)
        self.assertNotIn("secret command", rendered)
        self.assertEqual(findings[0]["severity"], "critical")

    def test_nuclei_retains_template_identity_without_target_url(self) -> None:
        findings = _nuclei(
            [
                {
                    "template-id": "signed-template",
                    "matched-at": "http://127.0.0.1/private?token=secret",
                    "matcher-name": "header",
                    "type": "http",
                    "info": {
                        "name": "Approved check",
                        "severity": "high",
                        "classification": {"cwe-id": "CWE-200"},
                        "reference": ["https://example.test/rule"],
                    },
                }
            ]
        )
        rendered = json.dumps(findings)
        self.assertNotIn("token=secret", rendered)
        self.assertEqual(findings[0]["rule_id"], "signed-template")
        self.assertEqual(findings[0]["classification"], "CWE-200")

    def test_zap_collapses_instances_without_urls_or_payloads(self) -> None:
        findings = _zap(
            {
                "site": [
                    {
                        "alerts": [
                            {
                                "pluginid": "10001",
                                "name": "Header weakness",
                                "riskdesc": "Medium (High)",
                                "cweid": "693",
                                "instances": [
                                    {
                                        "uri": "http://localhost/private",
                                        "evidence": "secret response",
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        )
        self.assertEqual(findings[0]["evidence"], {"instances": 1})
        self.assertEqual(findings[0]["classification"], "CWE-693")
        self.assertNotIn("secret response", json.dumps(findings))

    def test_prowler_imports_only_failed_checks_without_resource_ids(self) -> None:
        findings = _prowler(
            [
                {"CheckID": "pass-check", "Status": "PASS"},
                {
                    "CheckID": "failed-check",
                    "Status": "FAIL",
                    "Severity": "critical",
                    "StatusExtended": "Public access is enabled",
                    "Provider": "aws",
                    "Region": "us-east-1",
                    "ResourceType": "bucket",
                    "ResourceId": "sensitive-account-resource",
                },
            ]
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "failed-check")
        self.assertNotIn("sensitive-account-resource", json.dumps(findings))

    def test_restler_retains_replayable_bug_identity_without_network_logs(self) -> None:
        findings = _restler(
            {
                "bugs": [
                    {
                        "checker": "NameSpaceRuleChecker",
                        "sequence_length": 4,
                        "replay_succeeded": True,
                    }
                ]
            }
        )
        self.assertEqual(findings[0]["rule_id"], "NameSpaceRuleChecker")
        self.assertTrue(findings[0]["evidence"]["replay_succeeded"])

    def test_oast_drops_health_canary_and_retains_only_correlation_metadata(
        self,
    ) -> None:
        findings = _oast(
            {
                "service_mode": "self-hosted",
                "egress_scope_approved": True,
                "interactions": [
                    {
                        "correlation_id": "health-1",
                        "protocol": "dns",
                        "health_canary": True,
                    },
                    {
                        "correlation_id": "finding-1",
                        "protocol": "http",
                        "template_id": "blind-ssrf",
                    },
                ],
            }
        )
        self.assertEqual([item["rule_id"] for item in findings], ["blind-ssrf"])

        with self.assertRaisesRegex(ValueError, "approved egress"):
            _oast(
                {
                    "service_mode": "self-hosted",
                    "egress_scope_approved": False,
                    "interactions": [],
                }
            )

    def test_restler_rejects_unconfirmed_bug_buckets(self) -> None:
        with self.assertRaisesRegex(ValueError, "replay confirmation"):
            _restler(
                {
                    "bugs": [
                        {
                            "checker": "NameSpaceRuleChecker",
                            "sequence_length": 4,
                            "replay_succeeded": False,
                        }
                    ]
                }
            )

    def test_secret_verification_never_accepts_or_retains_secret_values(self) -> None:
        findings = _secret_verification(
            {
                "health_canary": True,
                "receipts": [
                    {
                        "provider": "example-provider",
                        "fingerprint": "sha256:bounded-fingerprint",
                        "status": "active",
                    }
                ],
            }
        )
        self.assertEqual(findings[0]["severity"], "critical")
        with self.assertRaisesRegex(ValueError, "sensitive"):
            _secret_verification(
                {
                    "receipts": [
                        {
                            "provider": "example-provider",
                            "fingerprint": "fingerprint",
                            "status": "active",
                            "token_value": "must-never-cross",
                        }
                    ]
                }
            )

    def test_native_receipt_requires_explicit_failed_checks(self) -> None:
        findings = _receipt_findings(
            {
                "tool": "native-sanitizers",
                "checks": [
                    {"id": "asan", "status": "pass"},
                    {
                        "id": "ubsan-overflow",
                        "status": "fail",
                        "severity": "high",
                        "classification": "CWE-190",
                    },
                ],
            },
            "native-sanitizers",
        )
        self.assertEqual([item["rule_id"] for item in findings], ["ubsan-overflow"])

    def test_polyglot_normalizers_parse_native_ecosystem_reports(self) -> None:
        gosec = _polyglot_findings(
            {
                "tool": "gosec",
                "report": {
                    "Issues": [
                        {
                            "rule_id": "G201",
                            "details": "SQL query construction",
                            "file": "src/store.go",
                            "line": "12-13",
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "cwe": {"id": "89"},
                        }
                    ]
                },
                "canary_report": {"Issues": [{"rule_id": "G101"}]},
            },
            "gosec",
        )
        cargo = _polyglot_findings(
            {
                "tool": "cargo-audit",
                "report": {
                    "vulnerabilities": {
                        "list": [
                            {
                                "advisory": {
                                    "id": "RUSTSEC-2026-0001",
                                    "title": "Unsafe behavior",
                                    "url": "https://rustsec.org/advisories/RUSTSEC-2026-0001.html",
                                },
                                "package": {"name": "example", "version": "1.0.0"},
                            }
                        ]
                    }
                },
                "canary_report": {"vulnerabilities": {"list": []}},
            },
            "cargo-audit",
        )
        npm = _polyglot_findings(
            {
                "tool": "npm-audit",
                "report": {
                    "vulnerabilities": {
                        "example": {"severity": "critical", "isDirect": True}
                    }
                },
                "canary_report": {"vulnerabilities": {}},
            },
            "npm-audit",
        )

        self.assertEqual(gosec[0]["classification"], "CWE-89")
        self.assertEqual(cargo[0]["rule_id"], "RUSTSEC-2026-0001")
        self.assertEqual(npm[0]["severity"], "critical")


if __name__ == "__main__":
    unittest.main()
