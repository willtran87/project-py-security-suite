from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from py_security_suite.evidence_ingest import (
    _assurance_document,
    _branch_list,
    _coverage_document,
    _integer,
    _integer_list,
    _junit_document,
    _junit_paths,
    _scorecard_document,
    _binding_path,
    main,
)


class EvidenceIngestCliTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.root = Path(self.enterContext(temporary))

    def _run(self, *arguments: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(list(arguments))
        return status, stdout.getvalue(), stderr.getvalue()

    def test_cli_normalizes_each_supported_evidence_family(self) -> None:
        coverage = self.root / "coverage.json"
        coverage.write_text(
            json.dumps(
                {
                    "meta": {"format": 3, "branch_coverage": True},
                    "totals": {},
                    "files": {},
                }
            ),
            encoding="utf-8",
        )
        junit = self.root / "junit.xml"
        junit.write_text(
            '<testsuite><testcase name="ok" time="0.25" /></testsuite>',
            encoding="utf-8",
        )
        scorecard = self.root / "scorecard.json"
        scorecard.write_text(json.dumps({"checks": [], "score": 10}), encoding="utf-8")
        assurance = self.root / "oci.json"
        assurance.write_text(
            json.dumps({"kind": "oci-image", "findings": []}), encoding="utf-8"
        )

        invocations = (
            (("coverage", str(coverage)), "coverage"),
            (("junit", str(junit)), "junit"),
            (("scorecard", str(scorecard)), "scorecard"),
            (("assurance", "oci-image", str(assurance)), "oci-image"),
        )
        for arguments, expected_kind in invocations:
            with self.subTest(kind=expected_kind):
                status, output, error = self._run(*arguments)
                self.assertEqual(status, 0)
                self.assertEqual(json.loads(output)["kind"], expected_kind)
                self.assertEqual(error, "")

    def test_cli_returns_sanitized_error_for_invalid_evidence(self) -> None:
        malformed = self.root / "coverage.json"
        malformed.write_text("[]", encoding="utf-8")
        status, output, error = self._run("coverage", str(malformed))
        self.assertEqual(status, 2)
        self.assertEqual(output, "")
        self.assertIn("invalid coverage evidence", error)

    def test_bind_command_attaches_verified_source_identity_to_runtime_evidence(
        self,
    ) -> None:
        (self.root / "src").mkdir()
        (self.root / "src" / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
        coverage = self.root / "coverage.json"
        coverage.write_text(
            json.dumps({"meta": {}, "totals": {}, "files": {}}),
            encoding="utf-8",
        )
        junit = self.root / "junit.xml"
        junit.write_text(
            '<testsuite><testcase name="ok" file="tests/test_app.py" /></testsuite>',
            encoding="utf-8",
        )

        status, output, error = self._run(
            "bind",
            "--source-root",
            str(self.root),
            str(coverage),
            str(junit),
        )

        self.assertEqual(status, 0)
        self.assertEqual(error, "")
        receipt = json.loads(output)
        self.assertEqual(receipt["kind"], "evidence-binding")
        self.assertEqual(len(receipt["bindings"]), 2)
        normalized_coverage = _coverage_document(coverage)
        normalized_junit = _junit_document(junit)
        self.assertEqual(normalized_coverage["source_sha256"], receipt["source_sha256"])
        self.assertEqual(normalized_junit["source_sha256"], receipt["source_sha256"])
        self.assertTrue(normalized_coverage["evidence_binding"]["verified"])
        self.assertTrue(normalized_junit["evidence_binding"]["verified"])
        self.assertTrue(_binding_path(coverage.resolve()).is_file())

        coverage.write_text(
            json.dumps({"meta": {}, "totals": {}, "files": {}, "changed": True}),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "does not match"):
            _coverage_document(coverage)
        second_status, _, second_error = self._run(
            "bind",
            "--source-root",
            str(self.root),
            str(coverage),
            str(junit),
        )
        self.assertEqual(second_status, 2)
        self.assertIn("already exists", second_error)

    def test_coverage_rejects_invalid_shapes_and_values(self) -> None:
        path = self.root / "coverage.json"
        invalid_documents: tuple[object, ...] = (
            [],
            {"meta": {}, "totals": {}},
            {"meta": {}, "totals": {}, "files": {"x.py": []}},
            {
                "meta": {},
                "totals": {},
                "files": {"x.py": {"summary": {}, "missing_lines": "1"}},
            },
            {
                "meta": {},
                "totals": {},
                "files": {"x.py": {"summary": {}, "missing_branches": [[1, 2, 3]]}},
            },
        )
        for document in invalid_documents:
            with self.subTest(document=document):
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises((TypeError, ValueError)):
                    _coverage_document(path)
        with self.assertRaises(TypeError):
            _integer("not-an-integer")
        with self.assertRaises(TypeError):
            _integer_list("1")
        with self.assertRaises(TypeError):
            _branch_list([[1]])

    def test_junit_directory_aggregates_failures_errors_and_skips(self) -> None:
        reports = self.root / "reports"
        reports.mkdir()
        (reports / "one.xml").write_text(
            '<testsuite><testcase name="failed" classname="C" file="t.py" '
            'line="7" time="0.1"><failure message="no" type="AssertionError" />'
            "</testcase></testsuite>",
            encoding="utf-8",
        )
        (reports / "two.xml").write_text(
            '<testsuite><testcase name="errored"><error message="boom" /></testcase>'
            '<testcase name="skipped"><skipped /></testcase></testsuite>',
            encoding="utf-8",
        )
        document = _junit_document(reports)
        self.assertEqual(document["report_count"], 2)
        self.assertEqual(document["totals"]["tests"], 3)
        self.assertEqual(document["totals"]["failures"], 1)
        self.assertEqual(document["totals"]["errors"], 1)
        self.assertEqual(document["totals"]["skipped"], 1)
        self.assertEqual(len(document["failures"]), 2)
        self.assertTrue(document["test_case_inventory_complete"])
        self.assertEqual(
            [item["result"] for item in document["test_cases"]],
            ["failure", "error", "skipped"],
        )
        self.assertEqual(document["test_cases"][0]["file"], "t.py")

    def test_junit_rejects_missing_empty_and_symlink_paths(self) -> None:
        missing = self.root / "missing"
        with self.assertRaisesRegex(ValueError, "does not exist"):
            _junit_paths(missing)
        empty = self.root / "empty"
        empty.mkdir()
        with self.assertRaisesRegex(ValueError, "no JUnit"):
            _junit_paths(empty)

    def test_scorecard_and_assurance_reject_untrusted_shapes(self) -> None:
        path = self.root / "evidence.json"
        invalid_scorecards: tuple[object, ...] = ([], {}, {"checks": ["invalid"]})
        for document in invalid_scorecards:
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises((TypeError, ValueError)):
                _scorecard_document(path)

        path.write_text(json.dumps({"kind": "yara", "findings": []}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "kind"):
            _assurance_document(path, "clamav")
        path.write_text(
            json.dumps({"kind": "clamav", "findings": ["invalid"]}),
            encoding="utf-8",
        )
        with self.assertRaises(TypeError):
            _assurance_document(path, "clamav")
        path.write_text(
            json.dumps(
                {
                    "kind": "clamav",
                    "findings": [{"severity": "catastrophic"}],
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "severity"):
            _assurance_document(path, "clamav")


if __name__ == "__main__":
    unittest.main()
