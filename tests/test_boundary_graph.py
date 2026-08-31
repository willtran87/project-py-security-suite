from __future__ import annotations

import tempfile
import unittest
import base64
import hashlib
import json
import importlib.util
import marshal
import os
from types import SimpleNamespace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from py_security_suite.boundary_graph import (
    _analyze_special_surface,
    _compiler_semantic_differential,
    _native_imports,
    _parser_environment,
    build_boundary_graph,
)
from py_security_suite.strict_json import canonical_bytes
from tests.deployment_authority import authority_environment, operation_receipt


def _semantic_symbol(
    identity: str,
    path: str,
    line: int,
    kind: str,
    *,
    language: str = "python",
    qualified_name: str | None = None,
) -> dict[str, object]:
    semantic_name = qualified_name or identity
    return {
        "id": identity,
        "path": path,
        "start_line": line,
        "start_column": 0,
        "end_line": line,
        "end_column": 1,
        "kind": kind,
        "qualified_name": semantic_name,
        "signature": f"{semantic_name}()",
        "language": language,
    }


def _semantic_edge(
    source: str, target: str, path: str, *, kind: str = "control-flow"
) -> dict[str, object]:
    return {
        "source": source,
        "target": target,
        "kind": kind,
        "callsite_path": path,
        "callsite_line": 1,
        "callsite_column": 0,
        "context": "root",
    }


class BoundaryGraphTests(unittest.TestCase):
    @staticmethod
    def _parser_result(stdout: str = "[]", **overrides: object) -> SimpleNamespace:
        values: dict[str, object] = {
            "exit_code": 0,
            "timed_out": False,
            "output_limit_exceeded": False,
            "scratch_limit_exceeded": False,
            "resident_memory_limit_exceeded": False,
            "resource_limit_errors": (),
            "stdout": stdout,
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_bytecode_parser_uses_immutable_bounded_snapshot(self) -> None:
        code = compile("import os\n", "target.py", "exec")
        payload = importlib.util.MAGIC_NUMBER + (b"\0" * 12) + marshal.dumps(code)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.pyc"
            target.write_bytes(payload)

            def run(command: list[str], **kwargs: object) -> SimpleNamespace:
                snapshot = Path(command[-1])
                self.assertNotEqual(snapshot, target)
                self.assertEqual(snapshot.read_bytes(), payload)
                self.assertEqual(kwargs["cwd"], snapshot.parent)
                target.write_bytes(b"replaced-after-validation")
                return self._parser_result('[[1,"module-import","os"]]')

            with patch("py_security_suite.boundary_graph.run_command", side_effect=run):
                surface, edges = _analyze_special_surface(
                    payload, "target.pyc", "bytecode", target
                )

        self.assertTrue(surface["covered"])
        self.assertEqual(edges[0]["target"], "os")

    def test_bytecode_parser_rejects_any_containment_failure(self) -> None:
        code = compile("pass\n", "target.py", "exec")
        payload = importlib.util.MAGIC_NUMBER + (b"\0" * 12) + marshal.dumps(code)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.pyc"
            target.write_bytes(payload)
            with (
                patch(
                    "py_security_suite.boundary_graph.run_command",
                    return_value=self._parser_result(
                        resource_limit_errors=("address-space:unavailable",)
                    ),
                ),
                self.assertRaisesRegex(ValueError, "semantic disassembly failed"),
            ):
                _analyze_special_surface(payload, "target.pyc", "bytecode", target)

    def test_bytecode_parser_runs_valid_and_malformed_inputs_out_of_process(
        self,
    ) -> None:
        code = compile("import pathlib\n", "target.py", "exec")
        valid = importlib.util.MAGIC_NUMBER + (b"\0" * 12) + marshal.dumps(code)
        malformed = importlib.util.MAGIC_NUMBER + (b"\0" * 12) + b"not-marshal"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.pyc"
            target.write_bytes(valid)
            surface, edges = _analyze_special_surface(
                valid, "target.pyc", "bytecode", target
            )
            target.write_bytes(malformed)
            with self.assertRaisesRegex(ValueError, "semantic disassembly failed"):
                _analyze_special_surface(malformed, "target.pyc", "bytecode", target)

        self.assertTrue(surface["covered"])
        self.assertIn("pathlib", {edge["target"] for edge in edges})

    def test_bytecode_parser_contains_adversarial_allocation_payload(self) -> None:
        payload = base64.b64decode(
            "8w0NCgAAAHt1iigoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgA"
            "IABnASlmZWF0ZWEoKCh0e3JlcwPpAAROZCgodQ=="
        )
        payload = importlib.util.MAGIC_NUMBER + payload[4:]

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "hostile.pyc"
            target.write_bytes(payload)
            with self.assertRaisesRegex(ValueError, "semantic disassembly failed"):
                _analyze_special_surface(payload, "hostile.pyc", "bytecode", target)

    def test_native_parser_uses_immutable_bounded_snapshot(self) -> None:
        payload = b"MZ" + (b"\0" * 64)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.pyd"
            target.write_bytes(payload)

            def run(command: list[str], **kwargs: object) -> SimpleNamespace:
                snapshot = Path(command[-1])
                self.assertNotEqual(snapshot, target)
                self.assertEqual(snapshot.read_bytes(), payload)
                self.assertEqual(kwargs["cwd"], snapshot.parent)
                return self._parser_result()

            with patch("py_security_suite.boundary_graph.run_command", side_effect=run):
                self.assertEqual(_native_imports(target, payload), [])

    def test_parser_environment_has_bounded_resident_memory(self) -> None:
        self.assertEqual(
            _parser_environment().max_resident_memory_bytes,
            256 * 1024 * 1024,
        )

    def test_direct_graph_construction_requires_governed_hostile_parsers(self) -> None:
        code = compile("pass\n", "target.py", "exec")
        payload = importlib.util.MAGIC_NUMBER + (b"\0" * 12) + marshal.dumps(code)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target.pyc").write_bytes(payload)

            graph = build_boundary_graph(root)

        self.assertFalse(graph["complete"])
        self.assertEqual(graph["special_surfaces"][0]["analysis"], "unsupported")
        self.assertEqual(graph["errors"][0]["reason"], "bytecode-ValueError")

    def test_unrecognized_semantic_language_cannot_silently_disappear(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "agent.dart").write_text(
                "void main() { print('hello'); }\n", encoding="utf-8"
            )
            graph = build_boundary_graph(root)
        self.assertFalse(graph["complete"])
        self.assertFalse(graph["semantic_complete"])
        self.assertEqual(
            graph["special_surfaces"][0]["kind"], "unsupported-semantic-source"
        )

    def test_compiler_differential_preserves_engine_unique_facts(self) -> None:
        evidence = {
            "frontends": [
                {
                    "language": "python",
                    "engine": "engine-a",
                    "secondary_engine": "engine-b",
                    "semantic_ledger_sha256": "a" * 64,
                    "secondary_semantic_ledger_sha256": "b" * 64,
                }
            ]
        }
        primary = {
            "semantic_ledger": {
                "symbols": [
                    _semantic_symbol("shared", "app.py", 1, "function"),
                    _semantic_symbol("primary", "app.py", 2, "call"),
                ],
                "cfg_edges": [],
                "dataflow_edges": [],
                "interprocedural_edges": [],
            },
            "taint_paths": [],
        }
        secondary = {
            "semantic_ledger": {
                "symbols": [
                    _semantic_symbol(
                        "engine-shared",
                        "app.py",
                        1,
                        "function",
                        qualified_name="shared",
                    ),
                    _semantic_symbol("secondary", "app.py", 3, "call"),
                ],
                "cfg_edges": [],
                "dataflow_edges": [],
                "interprocedural_edges": [],
            },
            "taint_paths": [],
        }
        with patch(
            "py_security_suite.boundary_graph._verify_analysis_artifact",
            side_effect=lambda _item, prefix: (
                primary if prefix == "primary" else secondary
            ),
        ):
            differential = _compiler_semantic_differential(evidence)
        assert differential is not None
        self.assertEqual(
            differential["classification"], "engine-disagreement-review-required"
        )
        self.assertEqual(differential["primary_only"], 1)
        self.assertEqual(differential["secondary_only"], 1)
        self.assertEqual(
            differential["normalization"], "qualified-source-symbol-ontology-v2"
        )

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
                "schema_version": "2.0",
                "frontends": [
                    {
                        "language": "c",
                        "engine": "clang-static-analyzer",
                        "engine_sha256": hashlib.sha256(b"primary-engine").hexdigest(),
                        "configuration_sha256": hashlib.sha256(
                            b"primary-configuration"
                        ).hexdigest(),
                        "files_sha256": hashlib.sha256(
                            canonical_bytes(files)
                        ).hexdigest(),
                        "symbols": 1,
                        "cfg_edges": 1,
                        "dataflow_edges": 0,
                        "interprocedural_edges": 0,
                        "semantic_ledger": {
                            "symbols": [
                                _semantic_symbol(
                                    "main", "native.c", 1, "function", language="c"
                                )
                            ],
                            "cfg_edges": [_semantic_edge("main", "main", "native.c")],
                            "dataflow_edges": [],
                            "interprocedural_edges": [],
                        },
                        "semantic_ledger_sha256": "",
                        "secondary_engine": "codeql",
                        "secondary_engine_sha256": hashlib.sha256(
                            b"secondary-engine"
                        ).hexdigest(),
                        "secondary_configuration_sha256": hashlib.sha256(
                            b"secondary-configuration"
                        ).hexdigest(),
                        "secondary_semantic_ledger": {},
                        "secondary_semantic_ledger_sha256": "",
                        "primary_analysis_artifact_base64": "",
                        "primary_analysis_artifact_sha256": "",
                        "secondary_analysis_artifact_base64": "",
                        "secondary_analysis_artifact_sha256": "",
                        "primary_authority_key_sha256": "",
                        "primary_failure_domain": {
                            "organization": "compiler-org-primary",
                            "host_identity_sha256": "1" * 64,
                            "control_plane_sha256": "2" * 64,
                            "implementation_sha256": "3" * 64,
                        },
                        "primary_operation_receipt": {},
                        "secondary_authority_key_sha256": "",
                        "secondary_failure_domain": {
                            "organization": "compiler-org-secondary",
                            "host_identity_sha256": "4" * 64,
                            "control_plane_sha256": "5" * 64,
                            "implementation_sha256": "6" * 64,
                        },
                        "secondary_operation_receipt": {},
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
            for prefix in ("primary", "secondary"):
                engine_prefix = "" if prefix == "primary" else "secondary_"
                replay = {
                    "schema_version": "2.0",
                    "engine": evidence["frontends"][0][f"{engine_prefix}engine"],
                    "engine_sha256": evidence["frontends"][0][
                        f"{engine_prefix}engine_sha256"
                    ],
                    "configuration_sha256": evidence["frontends"][0][
                        f"{engine_prefix}configuration_sha256"
                    ],
                    "files_sha256": evidence["frontends"][0]["files_sha256"],
                    "semantic_ledger": evidence["frontends"][0][
                        f"{engine_prefix}semantic_ledger"
                    ],
                    "taint_paths": [],
                    "engine_base64": base64.b64encode(
                        f"{prefix}-engine".encode()
                    ).decode(),
                    "configuration_base64": base64.b64encode(
                        f"{prefix}-configuration".encode()
                    ).decode(),
                    "runtime_closure": [
                        {
                            "path": "runtime/library.bin",
                            "sha256": hashlib.sha256(b"runtime-library").hexdigest(),
                            "content_base64": base64.b64encode(
                                b"runtime-library"
                            ).decode(),
                        }
                    ],
                    "runtime_closure_sha256": "",
                    "argv": ["analyze", "native.c"],
                    "environment": [],
                    "sandbox_policy": {
                        "network": "deny",
                        "filesystem": "read-only",
                        "process": "confined",
                        "credentials": "isolated",
                    },
                    "canary_results": {
                        "positive_fixture_sha256": "7" * 64,
                        "negative_fixture_sha256": "8" * 64,
                        "positive_detected": True,
                        "negative_clean": True,
                        "cases": [
                            {
                                "id": f"{prefix}-injection-positive",
                                "rule_family": "injection",
                                "fixture_sha256": "7" * 64,
                                "expected_detected": True,
                                "detected": True,
                            },
                            {
                                "id": f"{prefix}-injection-negative",
                                "rule_family": "injection",
                                "fixture_sha256": "8" * 64,
                                "expected_detected": False,
                                "detected": False,
                            },
                            {
                                "id": f"{prefix}-authorization-positive",
                                "rule_family": "authorization",
                                "fixture_sha256": "9" * 64,
                                "expected_detected": True,
                                "detected": True,
                            },
                            {
                                "id": f"{prefix}-authorization-negative",
                                "rule_family": "authorization",
                                "fixture_sha256": "a" * 64,
                                "expected_detected": False,
                                "detected": False,
                            },
                        ],
                    },
                    "analysis_capabilities": {
                        "alias_sensitive": True,
                        "context_sensitive": True,
                        "field_sensitive": True,
                        "path_sensitive": True,
                        "interprocedural": True,
                        "dynamic_dispatch": True,
                        "implicit_flows": True,
                    },
                }
                replay["runtime_closure_sha256"] = hashlib.sha256(
                    canonical_bytes(replay["runtime_closure"])
                ).hexdigest()
                payload = canonical_bytes(replay)
                evidence["frontends"][0][f"{prefix}_analysis_artifact_base64"] = (
                    base64.b64encode(payload).decode()
                )
                evidence["frontends"][0][f"{prefix}_analysis_artifact_sha256"] = (
                    hashlib.sha256(payload).hexdigest()
                )
                engine_subject = {
                    "schema_version": "1.0",
                    "language": "c",
                    "engine": replay["engine"],
                    "engine_sha256": replay["engine_sha256"],
                    "configuration_sha256": replay["configuration_sha256"],
                    "files_sha256": replay["files_sha256"],
                    "analysis_artifact_sha256": hashlib.sha256(payload).hexdigest(),
                    "failure_domain": evidence["frontends"][0][
                        f"{prefix}_failure_domain"
                    ],
                }
                receipt, key = operation_receipt(
                    engine_subject,
                    purpose="compiler-semantic-engine-analysis",
                    operation_id=f"{prefix}-compiler-analysis",
                )
                evidence["frontends"][0][f"{prefix}_operation_receipt"] = receipt
                evidence["frontends"][0][f"{prefix}_authority_key_sha256"] = key
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
                patch(
                    "py_security_suite.boundary_graph._compiler_semantic_reexecution",
                    return_value={"status": "reexecuted-and-matched"},
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
