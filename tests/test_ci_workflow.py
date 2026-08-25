from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

# The isolated Pylint lane intentionally omits locked test-only dependencies.
from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.ci_workflow import build_github_workflow, render_workflow_receipt
from py_security_suite.report_inspection import read_bundled_schema


class GitHubWorkflowTests(unittest.TestCase):
    def test_workflow_is_pinned_fail_closed_and_schema_governed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve()
            output = target / ".github/workflows/python-security.yml"
            workflow, receipt = build_github_workflow(
                target=target,
                output=output,
                profile="production",
                config_path="security/pysec.toml",
                checkout_sha="a" * 40,
                upload_artifact_sha="b" * 40,
                upload_sarif_sha="c" * 40,
                policy_variable="PYSEC_ORGANIZATION_POLICY",
                isolation_command="enterprise-verify-pysec-isolation",
                runner_labels=("self-hosted", "pysec-isolated"),
            )

        self.assertIn(f"actions/checkout@{'a' * 40}", workflow)
        self.assertIn(f"actions/upload-artifact@{'b' * 40}", workflow)
        self.assertIn(f"github/codeql-action/upload-sarif@{'c' * 40}", workflow)
        self.assertIn("--network-isolated", workflow)
        self.assertIn("verify-report", workflow)
        self.assertIn('test "${{ steps.pysec.outputs.exit_code }}" -eq 0', workflow)
        self.assertNotIn("pip install", workflow)
        self.assertFalse(receipt["authoritative"])
        self.assertEqual(receipt["output"], ".github/workflows/python-security.yml")
        schema = json.loads(read_bundled_schema("github-workflow-1.0"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(receipt)

    def test_workflow_rejects_floating_actions_and_unsafe_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve()
            common: dict[str, Any] = {
                "target": target,
                "output": target / "workflow.yml",
                "profile": "quick",
                "config_path": "pysec.toml",
                "checkout_sha": "a" * 40,
                "upload_artifact_sha": "b" * 40,
                "upload_sarif_sha": "c" * 40,
                "policy_variable": "PYSEC_ORGANIZATION_POLICY",
                "isolation_command": "verify-isolation",
                "runner_labels": ("self-hosted",),
            }
            for key, value, message in (
                ("profile", "unknown", "unsupported profile"),
                ("checkout_sha", "main", "40 hexadecimal"),
                ("policy_variable", "lower-case", "uppercase GitHub variable"),
                ("config_path", "../outside.toml", "repository-relative"),
                ("config_path", "safe.toml; echo bad", "repository-relative"),
                ("runner_labels", tuple(str(index) for index in range(9)), "1-8"),
                ("runner_labels", ("bad label",), "1-8"),
                ("isolation_command", "", "one non-empty"),
                ("isolation_command", "verify\necho bad", "one non-empty"),
            ):
                with self.subTest(key=key):
                    values = {**common, key: value}
                    with self.assertRaisesRegex(ValueError, message):
                        build_github_workflow(**values)

        self.assertIn(
            "GENERATED:",
            render_workflow_receipt(
                receipt={
                    "output": ".github/workflows/security.yml",
                    "profile": "quick",
                    "runner_labels": ["self-hosted"],
                    "action_pins": {"one": "a" * 40},
                    "scope": "fixture scope",
                }
            ),
        )


if __name__ == "__main__":
    unittest.main()
