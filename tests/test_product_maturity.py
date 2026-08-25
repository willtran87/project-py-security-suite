from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from py_security_suite import audit_package, release_manifest
from py_security_suite.audit_package import create_audit_package, verify_audit_package
from py_security_suite.audience_report import (
    build_audience_report,
    render_audience_markdown,
)
from py_security_suite.coverage_merge import merge_coverage_scenarios
from py_security_suite.config_provenance import build_config_provenance
from py_security_suite.finding_register import build_finding_register
from py_security_suite.github_annotations import (
    build_github_annotations,
    render_github_commands,
)
from py_security_suite.portfolio_dashboard import build_portfolio_dashboard


class ProductMaturityTests(unittest.TestCase):
    def test_bounded_helpers_reject_malformed_security_evidence(self) -> None:
        self.assertFalse(audit_package._safe_archive_name("../escape"))
        self.assertFalse(audit_package._safe_archive_name("bad\\path"))
        with self.assertRaisesRegex(ValueError, "manifest contract"):
            audit_package._validate_manifest({})
        with self.assertRaisesRegex(ValueError, "report or files"):
            audit_package._validate_manifest(
                {
                    "schema_version": "1.0",
                    "closed_set": True,
                    "authoritative": False,
                    "report": None,
                    "files": [],
                }
            )
        base_manifest = {
            "schema_version": "1.0",
            "closed_set": True,
            "authoritative": False,
            "report": {"checksums_sha256": "a" * 64},
            "files": [],
        }
        malformed = base_manifest | {"files": [{"path": "report/file"}]}
        with self.assertRaisesRegex(ValueError, "invalid file record"):
            audit_package._validate_manifest(malformed)
        bad_metadata = base_manifest | {
            "files": [
                {
                    "path": "report/file",
                    "sha256": "a" * 64,
                    "size_bytes": -1,
                    "kind": "report",
                }
            ]
        }
        with self.assertRaisesRegex(ValueError, "invalid file metadata"):
            audit_package._validate_manifest(bad_metadata)
        with self.assertRaisesRegex(ValueError, "lowercase digest"):
            audit_package._digest("bad", "test digest")

    def test_release_manifest_shape_guards_and_portable_paths(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported shape"):
            release_manifest._validate_manifest_shape({})
        valid = {
            "schema_version": "1.0",
            "status": "candidate",
            "authoritative": False,
            "closed_set": True,
            "scope": "closed evidence",
            "manifest_id": "a" * 64,
            "report": {"scan_id": "scan-1", "checksums_sha256": "b" * 64},
            "evidence": [
                {
                    "name": "readiness",
                    "path": "readiness.json",
                    "sha256": "c" * 64,
                    "schema_version": "1.0",
                }
            ],
            "required_authorities": ["release-approver"],
        }
        release_manifest._validate_manifest_shape(valid)
        for key, value, message in (
            ("schema_version", "2.0", "schema_version"),
            ("status", "approved", "non-authoritative"),
            ("closed_set", False, "closed evidence set"),
            ("scope", "", "scope"),
            ("evidence", [], "1-100 evidence"),
            ("required_authorities", ["unknown"], "authorities"),
        ):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, message):
                release_manifest._validate_manifest_shape(valid | {key: value})
        for report, message in (
            (None, "report identity"),
            ({"scan_id": "", "checksums_sha256": "b" * 64}, "scan ID"),
        ):
            with (
                self.subTest(report=report),
                self.assertRaisesRegex(ValueError, message),
            ):
                release_manifest._validate_manifest_shape(valid | {"report": report})
        for record, message in (
            ({"name": "readiness"}, "invalid evidence record"),
            (
                {
                    "name": "",
                    "path": "readiness.json",
                    "sha256": "c" * 64,
                    "schema_version": "1.0",
                },
                "evidence identity",
            ),
        ):
            with (
                self.subTest(record=record),
                self.assertRaisesRegex(ValueError, message),
            ):
                release_manifest._validate_manifest_shape(
                    valid | {"evidence": [record]}
                )
        with self.assertRaisesRegex(ValueError, "lowercase SHA-256"):
            release_manifest._validated_digest("bad", "test")
        self.assertEqual(
            release_manifest.bound_report_digest(
                {"report": {"report_checksums_sha256": "d" * 64}}
            ),
            "d" * 64,
        )
        self.assertEqual(
            release_manifest.bound_report_digest({"report_checksums_sha256": "e" * 64}),
            "e" * 64,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / "evidence.json"
            child.touch()
            self.assertEqual(
                release_manifest._portable_path(child, root), "evidence.json"
            )

    def test_coverage_merge_rejects_untrusted_inputs(self) -> None:
        with self.assertRaisesRegex(ValueError, "1-100"):
            merge_coverage_scenarios(())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "coverage.json"
            cases: tuple[tuple[dict[str, object], str | None, str], ...] = (
                ({"files": {}}, "bad", "SHA-256"),
                ({"files": []}, None, "files object"),
                ({"files": {"src/app.py": {}}}, None, "executed_lines"),
                (
                    {"files": {"src/app.py": {"executed_lines": [False]}}},
                    None,
                    "invalid line",
                ),
                (
                    {"files": {"../escape.py": {"executed_lines": [1]}}},
                    None,
                    "safe and relative",
                ),
            )
            for document, digest, message in cases:
                _write(source, document)
                expected = digest or _sha(source)
                with (
                    self.subTest(message=message),
                    self.assertRaisesRegex((TypeError, ValueError), message),
                ):
                    merge_coverage_scenarios((("scenario", source, expected),))
            _write(source, {"files": {}})
            with self.assertRaisesRegex(ValueError, "unique"):
                merge_coverage_scenarios(
                    (("same", source, _sha(source)), ("same", source, _sha(source)))
                )

    @patch("py_security_suite.audience_report.verify_report")
    def test_audience_report_rejects_bad_bindings(self, verify_mock) -> None:
        verify_mock.return_value = _verification("scan-1", "a")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan.json"
            _write(plan, {"schema_version": "1.0"})
            with self.assertRaisesRegex(ValueError, "schema_version"):
                build_audience_report(
                    plan, plan_sha256=_sha(plan), report=root, audience="executive"
                )
            with self.assertRaisesRegex(ValueError, "audience must"):
                build_audience_report(
                    plan, plan_sha256=_sha(plan), report=root, audience="unknown"
                )
            with self.assertRaisesRegex(ValueError, "does not match"):
                build_audience_report(
                    plan, plan_sha256="b" * 64, report=root, audience="executive"
                )
            _write(
                plan,
                {
                    "schema_version": "1.1",
                    "report": {"checksums_sha256": "b" * 64},
                    "audiences": {},
                },
            )
            with self.assertRaisesRegex(ValueError, "not bound"):
                build_audience_report(
                    plan, plan_sha256=_sha(plan), report=root, audience="executive"
                )

    @patch("py_security_suite.github_annotations.verify_report")
    def test_github_annotations_reject_malformed_records(self, verify_mock) -> None:
        verify_mock.return_value = _verification("scan-1", "a")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan.json"
            for annotation, message in (
                ("bad", "must be an object"),
                ({"level": "invalid", "line": 1, "file": "x"}, "invalid level"),
                ({"level": "error", "line": 0, "file": "x"}, "invalid line"),
                ({"level": "error", "line": 1, "file": "../x"}, "unsafe file"),
            ):
                _write(
                    plan,
                    {
                        "schema_version": "1.1",
                        "report": {"checksums_sha256": "a" * 64},
                        "github_annotations": [annotation],
                    },
                )
                with (
                    self.subTest(message=message),
                    self.assertRaisesRegex((TypeError, ValueError), message),
                ):
                    build_github_annotations(plan, plan_sha256=_sha(plan), report=root)

    @patch("py_security_suite.audience_report.verify_report")
    def test_audience_report_is_digest_and_report_bound(self, verify_mock) -> None:
        verify_mock.return_value = _verification("scan-1", "f")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan.json"
            _write(
                plan,
                {
                    "schema_version": "1.2",
                    "status": "blocked",
                    "report": {"checksums_sha256": "f" * 64},
                    "audiences": {
                        "executive": {
                            "message": "Review required",
                            "actions": ["Fix **unsafe** <script>"],
                        }
                    },
                },
            )
            result = build_audience_report(
                plan,
                plan_sha256=_sha(plan),
                report=root,
                audience="executive",
            )
        rendered = render_audience_markdown(result)
        self.assertIn("Review required", rendered)
        self.assertIn("  - Fix \\*\\*unsafe\\*\\* &lt;script&gt;", rendered)
        self.assertNotIn("<script>", rendered)
        self.assertFalse(result["authoritative"])

    def test_config_provenance_reports_origins_without_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "policy.toml"
            repository = root / "pysec.toml"
            policy.write_text(
                'profile = "production"\n[policy]\nrequired_scanners = ["bandit"]\n',
                encoding="utf-8",
            )
            repository.write_text('profile = "quick"\n', encoding="utf-8")
            result = build_config_provenance(
                organization_policy=policy,
                repository_config=repository,
                profile_override="standard",
            )
        self.assertEqual(result["effective"]["profile"], "standard")
        self.assertTrue(
            any(
                item["key"] == "profile" and item["origin"] == "cli"
                for item in result["facts"]
            )
        )
        self.assertNotIn("bandit", json.dumps(result["facts"]))

    @patch("py_security_suite.finding_register.verify_report")
    def test_finding_register_tracks_resolution_and_reopen(self, verify_mock) -> None:
        verify_mock.return_value = _verification("scan-1", "a")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            report.mkdir()
            _report_inputs(
                report, [_finding("F-1", "fingerprint-1")], "2026-01-01T00:00:00Z"
            )
            first = build_finding_register(report)
            self.assertEqual(first["summary"]["open"], 1)
            previous = root / "register.json"
            _write(previous, first)
            digest = _sha(previous)
            _report_inputs(report, [], "2026-01-02T00:00:00Z")
            resolved = build_finding_register(
                report, previous=previous, previous_sha256=digest
            )
            self.assertEqual(resolved["summary"]["resolved"], 1)

    @patch("py_security_suite.github_annotations.verify_report")
    def test_github_annotations_are_bound_and_escaped(self, verify_mock) -> None:
        verify_mock.return_value = _verification("scan-1", "b")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "plan.json"
            _write(
                plan,
                {
                    "schema_version": "1.1",
                    "report": {"checksums_sha256": "b" * 64},
                    "github_annotations": [
                        {
                            "level": "error",
                            "title": "Bad, title",
                            "message": "line%one\nline two",
                            "file": "src/app.py",
                            "line": 7,
                            "finding_id": "F-1",
                        }
                    ],
                },
            )
            result = build_github_annotations(plan, plan_sha256=_sha(plan), report=root)
        rendered = render_github_commands(result)
        self.assertIn("title=Bad%2C title", rendered)
        self.assertIn("line%25one%0Aline two", rendered)

    @patch("py_security_suite.audit_package.verify_report")
    def test_audit_package_round_trip_is_closed_and_portable(self, verify_mock) -> None:
        verify_mock.return_value = _verification("scan-1", "c") | {"outcome": "pass"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            report.mkdir()
            (report / "checksums.sha256").write_text("placeholder", encoding="utf-8")
            (report / "findings.json").write_text("{}", encoding="utf-8")
            evidence = root / "evidence.json"
            _write(
                evidence,
                {"schema_version": "1.0", "report": {"checksums_sha256": "c" * 64}},
            )
            package = root / "audit.zip"
            created = create_audit_package(
                report, package, evidence=(("readiness", evidence, _sha(evidence)),)
            )
            receipt = verify_audit_package(
                package, package_sha256=created["package"]["sha256"]
            )
        self.assertTrue(receipt["verified"])
        self.assertEqual(receipt["evidence_names"], ["readiness"])

    def test_coverage_merge_unions_scenarios(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "first.json", root / "second.json"
            _write(first, {"files": {"src/app.py": {"executed_lines": [1, 2]}}})
            _write(
                second,
                {
                    "files": {
                        "src/app.py": {"executed_lines": [2, 3]},
                        "src/worker.py": {"executed_lines": [5]},
                    }
                },
            )
            merged = merge_coverage_scenarios(
                (("api", first, _sha(first)), ("worker", second, _sha(second)))
            )
        self.assertEqual(merged["files"]["src/app.py"]["executed_lines"], [1, 2, 3])
        self.assertEqual(merged["pysec_merge"]["scenario_count"], 2)

    @patch("py_security_suite.portfolio_dashboard.verify_report")
    def test_portfolio_aggregates_distinct_sealed_reports(self, verify_mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "one", root / "two"
            first.mkdir()
            second.mkdir()
            _portfolio_inputs(first, "one", findings=1)
            _portfolio_inputs(second, "two", findings=0)
            verify_mock.side_effect = lambda path: (
                _verification(Path(path).name, "d" if Path(path).name == "one" else "e")
                | {"outcome": "fail" if Path(path).name == "one" else "pass"}
            )
            result = build_portfolio_dashboard([first, second])
        self.assertEqual(result["summary"]["reports"], 2)
        self.assertEqual(result["summary"]["blocking_findings"], 1)
        self.assertEqual(len(result["attention"]), 1)


def _verification(scan_id: str, character: str) -> dict[str, object]:
    return {
        "scan_id": scan_id,
        "checksums_sha256": character * 64,
        "outcome": "pass",
        "file_count": 2,
    }


def _finding(finding_id: str, fingerprint: str) -> dict[str, object]:
    return {
        "finding_id": finding_id,
        "fingerprint": fingerprint,
        "title": "Finding",
        "severity": "high",
        "blocking": True,
        "status": "new",
        "evidence": {"owners": ["team"]},
    }


def _report_inputs(
    report: Path, findings: list[dict[str, object]], timestamp: str
) -> None:
    _write(report / "scan-manifest.json", {"finished_at": timestamp})
    _write(report / "findings.json", {"findings": findings})


def _portfolio_inputs(report: Path, target: str, *, findings: int) -> None:
    _write(
        report / "scan-manifest.json",
        {
            "profile": "production",
            "finished_at": "2026-01-01T00:00:00Z",
            "inventory": {"target": target},
            "tools": [
                {
                    "tool": "bandit",
                    "applicable": True,
                    "status": "completed",
                    "version": "1",
                }
            ],
        },
    )
    _write(
        report / "findings.json",
        {
            "vcs_revision": "a" * 40,
            "findings": [{"status": "new", "blocking": True}] * findings,
        },
    )
    _write(
        report / "portfolio-health.json",
        {"overall": {"domains_with_execution_gaps": 0}},
    )


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
