from __future__ import annotations

import unittest
import hashlib

from py_security_suite.semantic_coverage import semantic_language_coverage_artifact
from py_security_suite.strict_json import canonical_bytes


class SemanticCoverageTests(unittest.TestCase):
    def test_non_python_language_requires_authenticated_complete_semantics(
        self,
    ) -> None:
        boundary = {
            "languages": {"python": 1, "typescript": 2},
            "heuristic_languages": ["typescript"],
            "graph_sha256": "a" * 64,
            "language_file_sets": {
                "python": {
                    "files": [
                        {
                            "path": "app.py",
                            "size_bytes": 1,
                            "sha256": "1" * 64,
                            "line_count": 1,
                        }
                    ]
                },
                "typescript": {
                    "files": [
                        {
                            "path": "a.ts",
                            "size_bytes": 1,
                            "sha256": "2" * 64,
                            "line_count": 1,
                        },
                        {
                            "path": "b.ts",
                            "size_bytes": 1,
                            "sha256": "3" * 64,
                            "line_count": 1,
                        },
                    ]
                },
            },
        }
        for value in boundary["language_file_sets"].values():
            value["files_sha256"] = hashlib.sha256(
                canonical_bytes(value["files"])
            ).hexdigest()
        pair_digest = hashlib.sha256(
            canonical_bytes(
                {
                    language: boundary["language_file_sets"][language]["files"]
                    for language in ("python", "typescript")
                }
            )
        ).hexdigest()
        boundary_ledger = [
            {
                "kind": "process-execution",
                "language": "python",
                "line": 1,
                "path": "app.py",
                "target": "node",
            }
        ]
        empty_ledger_sha256 = hashlib.sha256(canonical_bytes([])).hexdigest()
        incomplete = semantic_language_coverage_artifact(boundary, {})
        complete = semantic_language_coverage_artifact(
            boundary,
            {
                "polyglot-summary.json": {
                    "schema_version": "2.0",
                    "evidence_binding": {"verified": True, "authenticated": True},
                    "execution": {
                        "status": "completed",
                        "coverage_percent": 100.0,
                        "skipped_checks": [],
                        "features": ["semantic-dataflow", "language-matrix"],
                        "language_matrix": [
                            {
                                "language": "python",
                                "engine": "codeql",
                                "engine_version": "2.20.0",
                                "query_pack_sha256": "a" * 64,
                                "source_files_sha256": boundary["language_file_sets"][
                                    "python"
                                ]["files_sha256"],
                                "files_discovered": 1,
                                "files_analyzed": 1,
                                "exclusions": [],
                                "analysis_modes": ["semantic-dataflow"],
                                "files": boundary["language_file_sets"]["python"][
                                    "files"
                                ],
                            },
                            {
                                "language": "typescript",
                                "engine": "codeql",
                                "engine_version": "2.20.0",
                                "query_pack_sha256": "b" * 64,
                                "source_files_sha256": boundary["language_file_sets"][
                                    "typescript"
                                ]["files_sha256"],
                                "files_discovered": 2,
                                "files_analyzed": 2,
                                "exclusions": [],
                                "analysis_modes": ["semantic-dataflow"],
                                "files": boundary["language_file_sets"]["typescript"][
                                    "files"
                                ],
                            },
                        ],
                        "cross_language_matrix": [
                            {
                                "languages": ["python", "typescript"],
                                "engine": "codeql",
                                "engine_version": "2.20.0",
                                "query_pack_sha256": "d" * 64,
                                "source_file_sets_sha256": pair_digest,
                                "boundaries_analyzed": 1,
                                "flows_found": 0,
                                "boundaries": boundary_ledger,
                                "boundaries_sha256": hashlib.sha256(
                                    canonical_bytes(boundary_ledger)
                                ).hexdigest(),
                                "flows": [],
                                "flows_sha256": empty_ledger_sha256,
                                "analysis_modes": [
                                    "semantic-dataflow",
                                    "cross-language-boundary",
                                ],
                                "independent_validation": {
                                    "engine": "semgrep-pro",
                                    "query_pack_sha256": "e" * 64,
                                    "boundaries_sha256": hashlib.sha256(
                                        canonical_bytes(boundary_ledger)
                                    ).hexdigest(),
                                    "flows_sha256": empty_ledger_sha256,
                                    "authority": {
                                        "validated": True,
                                        "minimum_signatures": 2,
                                        "signers": ["signer-a", "signer-b"],
                                        "collectors": ["collector-a", "collector-b"],
                                        "organizations": ["org-a", "org-b"],
                                        "subject_sha256": "f" * 64,
                                        "observed_at": "2026-08-24T00:00:00+00:00",
                                        "trusted_time_sha256": "a" * 64,
                                        "receipts": [
                                            {"receipt_sha256": "1" * 64},
                                            {"receipt_sha256": "2" * 64},
                                        ],
                                    },
                                },
                            }
                        ],
                    },
                }
            },
        )
        self.assertFalse(incomplete["complete"])
        self.assertEqual(incomplete["uncovered_languages"], ["python", "typescript"])
        self.assertTrue(complete["complete"])

    def test_python_syntax_ast_is_not_mislabeled_as_semantic_dataflow(self) -> None:
        boundary = {
            "languages": {"python": 1},
            "language_file_sets": {
                "python": {
                    "files": [
                        {
                            "path": "app.py",
                            "size_bytes": 1,
                            "sha256": "1" * 64,
                            "line_count": 1,
                        }
                    ],
                    "files_sha256": "2" * 64,
                }
            },
        }
        artifact = semantic_language_coverage_artifact(boundary, {})
        self.assertFalse(artifact["complete"])
        self.assertEqual(artifact["uncovered_languages"], ["python"])
        self.assertFalse(artifact["languages"][0]["semantic"])
        self.assertEqual(
            artifact["languages"][0]["analysis_modes"],
            ["syntax-ast", "control-flow", "call-graph"],
        )

    def test_cross_language_summary_without_exact_ledgers_is_incomplete(self) -> None:
        boundary = {
            "languages": {"python": 1, "typescript": 1},
            "language_file_sets": {
                "python": {"files": [], "files_sha256": "a" * 64},
                "typescript": {"files": [], "files_sha256": "b" * 64},
            },
            "edges": [],
        }
        artifact = semantic_language_coverage_artifact(
            boundary,
            {
                "polyglot-summary.json": {
                    "schema_version": "2.0",
                    "evidence_binding": {"verified": True, "authenticated": True},
                    "execution": {
                        "status": "completed",
                        "coverage_percent": 100.0,
                        "skipped_checks": [],
                        "features": ["semantic-dataflow", "language-matrix"],
                        "language_matrix": [],
                        "cross_language_matrix": [
                            {
                                "languages": ["python", "typescript"],
                                "source_file_sets_sha256": hashlib.sha256(
                                    canonical_bytes({"python": [], "typescript": []})
                                ).hexdigest(),
                                "boundaries_analyzed": 0,
                                "flows_found": 0,
                                "analysis_modes": [
                                    "semantic-dataflow",
                                    "cross-language-boundary",
                                ],
                            }
                        ],
                    },
                }
            },
        )
        self.assertFalse(artifact["cross_language_complete"])
        self.assertFalse(
            artifact["cross_language_pairs"][0]["boundary_ledger_complete"]
        )

    def test_global_coverage_cannot_hide_an_omitted_language(self) -> None:
        boundary = {
            "languages": {"go": 1, "typescript": 1},
            "heuristic_languages": ["go", "typescript"],
            "graph_sha256": "a" * 64,
            "language_file_sets": {
                "go": {
                    "files": [
                        {
                            "path": "main.go",
                            "size_bytes": 1,
                            "sha256": "1" * 64,
                            "line_count": 1,
                        }
                    ]
                },
                "typescript": {
                    "files": [
                        {
                            "path": "app.ts",
                            "size_bytes": 1,
                            "sha256": "2" * 64,
                            "line_count": 1,
                        }
                    ]
                },
            },
        }
        for value in boundary["language_file_sets"].values():
            value["files_sha256"] = hashlib.sha256(
                canonical_bytes(value["files"])
            ).hexdigest()
        artifact = semantic_language_coverage_artifact(
            boundary,
            {
                "polyglot-summary.json": {
                    "schema_version": "2.0",
                    "evidence_binding": {"verified": True, "authenticated": True},
                    "execution": {
                        "status": "completed",
                        "coverage_percent": 100.0,
                        "skipped_checks": [],
                        "features": ["semantic-dataflow", "language-matrix"],
                        "language_matrix": [
                            {
                                "language": "go",
                                "engine": "codeql",
                                "engine_version": "2.20.0",
                                "query_pack_sha256": "b" * 64,
                                "source_files_sha256": boundary["language_file_sets"][
                                    "go"
                                ]["files_sha256"],
                                "files_discovered": 1,
                                "files_analyzed": 1,
                                "exclusions": [],
                                "analysis_modes": ["semantic-dataflow"],
                                "files": boundary["language_file_sets"]["go"]["files"],
                            }
                        ],
                    },
                }
            },
        )
        self.assertFalse(artifact["complete"])
        self.assertEqual(artifact["uncovered_languages"], ["typescript"])
