from __future__ import annotations

import tempfile
import unittest
import base64
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from py_security_suite.boundary_graph import build_boundary_graph
from py_security_suite.strict_json import canonical_bytes
from tests.deployment_authority import authority_environment


class BoundaryGraphTests(unittest.TestCase):
    def test_python_parser_failure_marks_graph_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "broken.py").write_text("def broken(:\n", encoding="utf-8")
            artifact = build_boundary_graph(target)
        self.assertFalse(artifact["complete"])
        self.assertFalse(artifact["semantic_complete"])
        self.assertEqual(artifact["errors"][0]["reason"], "python-syntax-error")

    def test_polyglot_parser_failure_marks_language_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "broken.ts").write_text("function broken( {\n", encoding="utf-8")
            artifact = build_boundary_graph(target)
        self.assertFalse(artifact["complete"])
        self.assertFalse(artifact["semantic_complete"])
        self.assertEqual(artifact["heuristic_languages"], ["typescript"])
        self.assertEqual(
            artifact["errors"][0]["reason"],
            "tree-sitter-typescript-syntax-error",
        )

    def test_unifies_python_javascript_and_native_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "worker.py").write_text(
                "import subprocess\n"
                "import requests\n"
                "subprocess.run(['git', 'status'])\n"
                "requests.get('https://api.example.test/v1/items')\n",
                encoding="utf-8",
            )
            (root / "client.ts").write_text(
                "import x from './bridge';\n"
                "fetch('https://api.example.test/v2/items');\n"
                "child_process.spawn('node');\n",
                encoding="utf-8",
            )
            (root / "native.c").write_text(
                'void f() { dlopen("libcrypto.so"); }\n', encoding="utf-8"
            )

            graph = build_boundary_graph(root)

        self.assertEqual(graph["languages"], {"c": 1, "python": 1, "typescript": 1})
        kinds = {edge["kind"] for edge in graph["edges"]}
        self.assertTrue(
            {
                "module-import",
                "native-ffi",
                "network-endpoint",
                "process-execution",
            }.issubset(kinds)
        )
        self.assertEqual(len(graph["graph_sha256"]), 64)
        self.assertFalse(graph["truncated"])

    def test_generated_dynamic_and_compiled_surfaces_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "generated").mkdir()
            (root / "generated" / "client.ts").write_text(
                "// @generated\neval(message);\n", encoding="utf-8"
            )
            (root / "page.jinja2").write_text("{{ value }}\n", encoding="utf-8")
            (root / "module.wasm").write_bytes(b"\\0asm")

            graph = build_boundary_graph(root)

        kinds = {item["kind"] for item in graph["special_surfaces"]}
        self.assertEqual(
            kinds, {"dynamic-code", "generated-source", "template", "webassembly"}
        )
        self.assertFalse(graph["special_surface_complete"])
        self.assertFalse(graph["complete"])
        self.assertFalse(graph["semantic_complete"])

    def test_notebook_wasm_and_dynamic_imports_are_analyzed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "analysis.ipynb").write_text(
                '{"cells":[{"cell_type":"code","source":["importlib.import_module(\\"plugins.auth\\")\\n"]}]}',
                encoding="utf-8",
            )
            # One function import: module "env", field "clock", type index 0.
            (root / "module.wasm").write_bytes(
                b"\0asm\x01\0\0\0"
                b"\x01\x04\x01\x60\x00\x00"
                b"\x02\x0d\x01\x03env\x05clock\x00\x00"
            )
            graph = build_boundary_graph(root)

        self.assertTrue(graph["special_surface_complete"])
        targets = {(edge["kind"], edge["target"]) for edge in graph["edges"]}
        self.assertIn(("dynamic-dispatch", "plugins.auth"), targets)
        self.assertIn(("binary-import", "env.clock"), targets)

    def test_governed_polyglot_analysis_requires_compiler_semantic_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = b"int main(void) { return 0; }\n"
            (root / "native.c").write_bytes(payload)
            files = [
                {
                    "path": "native.c",
                    "size_bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "line_count": 1,
                }
            ]
            evidence = {
                "schema_version": "1.0",
                "frontends": [
                    {
                        "language": "c",
                        "engine": "clang-static-analyzer",
                        "engine_sha256": "a" * 64,
                        "configuration_sha256": "b" * 64,
                        "files_sha256": hashlib.sha256(
                            canonical_bytes(files)
                        ).hexdigest(),
                        "symbols": 1,
                        "cfg_edges": 1,
                        "dataflow_edges": 0,
                        "interprocedural_edges": 0,
                        "semantic_ledger": {
                            "symbols": [
                                {
                                    "id": "main",
                                    "path": "native.c",
                                    "line": 1,
                                    "kind": "function",
                                }
                            ],
                            "cfg_edges": [{"source": "main", "target": "main"}],
                            "dataflow_edges": [],
                            "interprocedural_edges": [],
                        },
                        "semantic_ledger_sha256": "",
                        "secondary_engine": "codeql",
                        "secondary_engine_sha256": "c" * 64,
                        "secondary_configuration_sha256": "d" * 64,
                        "secondary_semantic_ledger": {},
                        "secondary_semantic_ledger_sha256": "",
                        "primary_analysis_artifact_base64": "",
                        "primary_analysis_artifact_sha256": "",
                        "secondary_analysis_artifact_base64": "",
                        "secondary_analysis_artifact_sha256": "",
                        "taint_paths": [],
                        "taint_paths_sha256": "",
                    }
                ],
            }
            evidence["frontends"][0]["semantic_ledger_sha256"] = hashlib.sha256(
                canonical_bytes(evidence["frontends"][0]["semantic_ledger"])
            ).hexdigest()
            evidence["frontends"][0]["secondary_semantic_ledger"] = evidence[
                "frontends"
            ][0]["semantic_ledger"]
            evidence["frontends"][0]["secondary_semantic_ledger_sha256"] = evidence[
                "frontends"
            ][0]["semantic_ledger_sha256"]
            for prefix, payload in (
                ("primary", b"clang-bqrs"),
                ("secondary", b"codeql-bqrs"),
            ):
                evidence["frontends"][0][f"{prefix}_analysis_artifact_base64"] = (
                    base64.b64encode(payload).decode()
                )
                evidence["frontends"][0][f"{prefix}_analysis_artifact_sha256"] = (
                    hashlib.sha256(payload).hexdigest()
                )
            evidence["frontends"][0]["taint_paths_sha256"] = hashlib.sha256(
                canonical_bytes([])
            ).hexdigest()
            evidence_path = root / "compiler-semantics.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            environment = authority_environment(
                root,
                evidence,
                purpose="compiler-semantic-evidence",
                prefix="PYSEC_COMPILER_SEMANTIC_AUTHORITY",
            )
            environment.update(
                {
                    "PYSEC_COMPILER_SEMANTIC_EVIDENCE_PATH": str(evidence_path),
                    "PYSEC_COMPILER_SEMANTIC_EVIDENCE_SHA256": hashlib.sha256(
                        evidence_path.read_bytes()
                    ).hexdigest(),
                }
            )
            with (
                patch.dict(os.environ, environment),
                patch(
                    "py_security_suite.deployment_receipt._scan_observed_at",
                    return_value=datetime.now(UTC),
                ),
            ):
                graph = build_boundary_graph(root, require_governed_parsers=True)
        self.assertTrue(graph["compiler_semantic_complete"])
        self.assertEqual(
            graph["compiler_semantic_evidence"]["frontends"][0]["engine"],
            "clang-static-analyzer",
        )

    def test_governed_python_analysis_also_requires_compiler_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("print('ok')\n", encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError, "compiler semantic evidence configuration"
            ):
                build_boundary_graph(root, require_governed_parsers=True)


if __name__ == "__main__":
    unittest.main()
