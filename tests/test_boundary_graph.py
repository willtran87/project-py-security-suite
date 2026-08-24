from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from py_security_suite.boundary_graph import build_boundary_graph


class BoundaryGraphTests(unittest.TestCase):
    def test_python_parser_failure_marks_graph_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "broken.py").write_text("def broken(:\n", encoding="utf-8")
            artifact = build_boundary_graph(target)
        self.assertFalse(artifact["complete"])
        self.assertFalse(artifact["semantic_complete"])
        self.assertEqual(artifact["errors"][0]["reason"], "python-syntax-error")

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


if __name__ == "__main__":
    unittest.main()
