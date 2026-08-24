from __future__ import annotations

import json
import unittest

# The isolated Pylint lane intentionally omits locked test-only dependencies.
from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.adapter_conformance import (
    _bounded_environment_contract,
    assess_adapter_conformance,
    render_adapter_conformance,
)
from py_security_suite.report_inspection import read_bundled_schema


class AdapterConformanceTests(unittest.TestCase):
    def test_every_supported_adapter_satisfies_the_static_sdk_contract(self) -> None:
        document = assess_adapter_conformance()

        self.assertEqual(document["status"], "pass")
        self.assertEqual(document["registry"]["missing"], [])
        self.assertEqual(document["registry"]["unexpected"], [])
        self.assertEqual(document["summary"]["adapters"], 88)
        self.assertEqual(document["summary"]["failed"], 0)
        self.assertEqual(document["summary"]["checks"], 440)
        self.assertTrue(all(len(row["checks"]) == 5 for row in document["adapters"]))

        schema = json.loads(read_bundled_schema("adapter-conformance-1.0"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)

    def test_text_is_decision_first_and_scope_bounded(self) -> None:
        rendered = render_adapter_conformance(assess_adapter_conformance())
        self.assertTrue(rendered.startswith("PASS: adapter conformance"))
        self.assertIn("88/88 passed; 440 checks", rendered)
        self.assertIn("does not establish scanner availability", rendered)

    def test_failure_rendering_and_missing_instance_contract(self) -> None:
        document = assess_adapter_conformance()
        document["status"] = "fail"
        document["adapters"][0]["status"] = "fail"
        document["adapters"][0]["checks"][0]["passed"] = False
        self.assertIn(": FAIL (", render_adapter_conformance(document))
        self.assertFalse(_bounded_environment_contract(None))


if __name__ == "__main__":
    unittest.main()
