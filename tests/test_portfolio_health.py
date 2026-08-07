from __future__ import annotations

import json
import unittest

# The isolated Pylint lane intentionally omits locked test-only dependencies.
from jsonschema import (  # pylint: disable=import-error
    Draft202012Validator,
    ValidationError,
)

from py_security_suite.models import ToolRun, ToolStatus
from py_security_suite.portfolio_health import portfolio_health_artifact
from py_security_suite.report_inspection import read_bundled_schema


class PortfolioHealthTests(unittest.TestCase):
    def test_grades_applicable_completion_without_treating_na_as_failure(self) -> None:
        runs = [
            ToolRun("bandit", ToolStatus.COMPLETED, [], 0.1),
            ToolRun("semgrep", ToolStatus.UNAVAILABLE, [], 0.0),
            ToolRun(
                "flawfinder",
                ToolStatus.SKIPPED,
                [],
                0.0,
                applicable=False,
            ),
        ]

        artifact = portfolio_health_artifact([], runs)
        source = next(
            row
            for row in artifact["domains"]
            if row["domain"] == "python-source-security"
        )

        self.assertEqual(source["grade"], "C")
        self.assertEqual(source["execution_gaps"], ["semgrep"])
        self.assertEqual(source["applicable_tools"], 2)
        self.assertEqual(source["selected_tools"], 3)

    def test_unselected_domains_are_explicit_and_not_graded(self) -> None:
        artifact = portfolio_health_artifact(
            [], [ToolRun("bandit", ToolStatus.COMPLETED, [], 0.1)]
        )
        dynamic = next(
            row
            for row in artifact["domains"]
            if row["domain"] == "dynamic-threat-modeling"
        )
        self.assertEqual(dynamic["status"], "not_selected")
        self.assertEqual(dynamic["grade"], "N/A")
        schema = json.loads(read_bundled_schema("portfolio-health-1.0"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(artifact)
        artifact["overall"]["unexpected"] = True
        with self.assertRaises(ValidationError):
            Draft202012Validator(schema).validate(artifact)
