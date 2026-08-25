from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path

# The isolated Pylint lane intentionally omits locked test-only dependencies.
from jsonschema import Draft202012Validator  # pylint: disable=import-error

from py_security_suite.reachability_delta import compare_reachability


class ReachabilityDeltaTests(unittest.TestCase):
    def test_new_disconnected_code_and_state_regressions_block(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline, baseline_digest = _write_graph(
                root / "baseline.json",
                [
                    _node("app:main", "app.py", "executable", "observed"),
                    _node("app:helper", "app.py", "load-only", "observed"),
                ],
            )
            current, current_digest = _write_graph(
                root / "current.json",
                [
                    _node("app:main", "app.py", "load-only", "not-observed"),
                    _node("app:helper", "app.py", "load-only", "observed"),
                    _node("legacy:unused", "legacy.py", "disconnected"),
                ],
                islands=[{"id": "island:legacy", "reportable": True}],
            )
            result = compare_reachability(
                baseline,
                current,
                baseline_sha256=baseline_digest,
                current_sha256=current_digest,
            )

        self.assertEqual(result["verdict"], "regression")
        self.assertEqual(result["counts"]["state_regressions"], 1)
        self.assertEqual(result["counts"]["new_disconnected_nodes"], 1)
        self.assertEqual(result["counts"]["lost_runtime_observations"], 1)
        _validate_schema(result)

    def test_identical_graphs_pass_and_digest_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, digest = _write_graph(
                Path(directory) / "graph.json",
                [_node("app:main", "app.py", "executable")],
            )
            result = compare_reachability(
                path,
                path,
                baseline_sha256=digest,
                current_sha256=digest,
            )
            with self.assertRaisesRegex(ValueError, "approved SHA-256"):
                compare_reachability(
                    path,
                    path,
                    baseline_sha256="0" * 64,
                    current_sha256=digest,
                )

        self.assertEqual(result["verdict"], "pass")
        _validate_schema(result)


def _node(
    identifier: str,
    path: str,
    state: str,
    observation: str = "not-measured",
) -> dict[str, object]:
    return {
        "id": identifier,
        "path": path,
        "state": state,
        "runtime_observation": observation,
    }


def _write_graph(
    path: Path,
    nodes: list[dict[str, object]],
    *,
    islands: list[dict[str, object]] | None = None,
) -> tuple[Path, str]:
    document = {
        "schema_version": "1.2",
        "analysis": {"graph_sha256": hashlib.sha256(path.name.encode()).hexdigest()},
        "summary": {"nodes": len(nodes)},
        "nodes": nodes,
        "islands": islands or [],
    }
    payload = json.dumps(document, sort_keys=True).encode()
    path.write_bytes(payload)
    return path, hashlib.sha256(payload).hexdigest()


def _validate_schema(document: dict[str, object]) -> None:
    schema = json.loads(
        files("py_security_suite")
        .joinpath("schemas", "reachability-delta.schema.json")
        .read_text("utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)
