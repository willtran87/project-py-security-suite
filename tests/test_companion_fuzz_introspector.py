from __future__ import annotations

import unittest

from companion.fuzz_introspector import _analyze


class CompanionFuzzIntrospectorTests(unittest.TestCase):
    def test_combines_static_reachability_dynamic_coverage_and_corpus_health(
        self,
    ) -> None:
        result = _analyze(
            {
                "schema_version": "1.0",
                "fuzzers": [
                    {
                        "name": "request-parser",
                        "statically_reachable_functions": 100,
                        "dynamically_covered_functions": 55,
                        "corpus_files": 0,
                        "blockers": ["unreached-error-handler"],
                    },
                    {
                        "name": "token-parser",
                        "statically_reachable_functions": 20,
                        "dynamically_covered_functions": 20,
                        "corpus_files": 12,
                        "blockers": [],
                    },
                ],
                "health_canary_observed": True,
            },
            70.0,
        )

        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["fingerprint"], "request-parser")
        self.assertEqual(result["execution"]["coverage_percent"], 62.5)
        self.assertEqual(result["execution"]["canaries_observed"], 1)

    def test_rejects_impossible_coverage_and_unbounded_contract_fields(self) -> None:
        document = {
            "schema_version": "1.0",
            "fuzzers": [
                {
                    "name": "parser",
                    "statically_reachable_functions": 2,
                    "dynamically_covered_functions": 3,
                    "corpus_files": 1,
                    "blockers": [],
                }
            ],
            "health_canary_observed": True,
        }
        with self.assertRaisesRegex(ValueError, "coverage"):
            _analyze(document, 70.0)

        document["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "fields"):
            _analyze(document, 70.0)


if __name__ == "__main__":
    unittest.main()
