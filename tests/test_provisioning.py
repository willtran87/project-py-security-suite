from __future__ import annotations

import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

# The isolated Pylint lane intentionally omits locked test-only dependencies.
from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.config import load_config
from py_security_suite.provisioning import (
    build_provision_plan,
    render_provision_plan,
    render_provision_plan_markdown,
)


class ProvisioningTests(unittest.TestCase):
    def test_plan_is_schema_governed_non_mutating_and_actionable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            config = load_config(profile_override="quick")
            with patch("py_security_suite.doctor.apply_trust_catalog") as trust:
                trust.return_value.errors = []
                trust.return_value.artifact = {}
                plan = build_provision_plan(target=target, config=config)

        schema = json.loads(
            files("py_security_suite")
            .joinpath("schemas", "provision-plan.schema.json")
            .read_text(encoding="utf-8")
        )
        Draft202012Validator(schema).validate(plan)
        self.assertFalse(plan["authoritative"])
        self.assertFalse(plan["bundle"]["network_acquisition_performed"])
        self.assertFalse(plan["bundle"]["filesystem_mutation_performed"])
        self.assertTrue(plan["plan_id"].startswith("plan-"))
        self.assertGreater(len(plan["controls"]), 0)
        self.assertIsInstance(plan["verification"]["scan_argv"], list)
        self.assertNotIn(str(target.resolve()), json.dumps(plan))

    def test_renderers_prioritize_decision_actions_and_boundary(self) -> None:
        document = {
            "plan_id": "plan-" + "a" * 24,
            "profile": "quick",
            "target": "repo",
            "decision": {"disposition": "block"},
            "summary": {"ready": 1, "applicable": 2, "workflow_batches": 1},
            "workflows": [
                {
                    "order": 1,
                    "priority": "P0",
                    "blocking": True,
                    "category": "unavailable",
                    "controls": ["bandit"],
                    "objective": "Install the approved executable.",
                }
            ],
            "verification": {
                "preflight_argv": ["pysec", "doctor", "."],
                "scan_argv": ["pysec", "scan", "."],
            },
            "scope": "No files changed.",
        }
        text = render_provision_plan(document)
        markdown = render_provision_plan_markdown(document)
        self.assertIn("BLOCKED", text)
        self.assertIn("P0 BLOCK", text)
        self.assertIn("# Offline provisioning plan", markdown)
        self.assertIn("## Safety boundary", markdown)


if __name__ == "__main__":
    unittest.main()
