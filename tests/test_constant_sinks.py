from __future__ import annotations

import ast
import json
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from py_security_suite.adapters.constant_sinks import (
    constant_argument,
    annotate_constant_sinks,
)
from py_security_suite.adapters.codeql import CodeQlAdapter
from py_security_suite.config import ToolConfig


def proves(body: str, rule: str = "py/xpath-injection") -> bool:
    source = "def route(user):\n" + textwrap.indent(
        textwrap.dedent(body).strip() + "\n", "    "
    )
    line = next(i for i, text in enumerate(source.splitlines(), 1) if "# sink" in text)
    return constant_argument(ast.parse(source), line, rule)


@pytest.mark.parametrize(
    "body",
    [
        "query = '/fixed'\nXPath(query) # sink",
        "query = '/fixed'\nXPath(query) # sink\nfor query in user:\n    print(query)",
        "num = 86\nif 7 * 42 - num > 200:\n    bar = 'fixed'\nelse:\n    bar = user\nquery = f'/item/{bar}'\nXPath(query) # sink",
        "num = 106\nbar = 'fixed' if 7 * 18 + num > 200 else user\nXPath(f'/item/{bar}') # sink",
        "if user:\n    query = '/fixed'\nelse:\n    query = '/fixed'\nXPath(query) # sink",
        "query = '/fixed'\ntry:\n    tree = parse_file()\n    XPath(query) # sink\nexcept Exception:\n    pass",
        "query = '/fixed'\nif user:\n    query = user\n    return\nXPath(query) # sink",
    ],
)
def test_only_complete_constant_arguments_are_proven(body: str) -> None:
    assert proves(body)


@pytest.mark.parametrize(
    "body",
    [
        "query = user\nXPath(query) # sink",
        "num = 0\nquery = 'fixed' if num > 200 else user\nXPath(query) # sink",
        "if user:\n    query = '/fixed'\nelse:\n    query = user\nXPath(query) # sink",
        "query = '/fixed'\nquery = sanitize(user)\nXPath(query) # sink",
        "query = '/fixed'\nfrom dynamic import query\nXPath(query) # sink",
        "query = '/fixed'\nquery += user\nXPath(query) # sink",
        "query = '/fixed'\nfor query in user:\n    XPath(query) # sink",
        "query = '/fixed'\nwith context() as query:\n    XPath(query) # sink",
        "query = '/fixed'\nmatch user:\n    case query:\n        XPath(query) # sink",
        "query = '/fixed'\nqueries = [XPath(query) for query in user] # sink",
        "query = '/fixed'\ncallback = lambda query: XPath(query) # sink",
        "query = '/fixed'\nquery = user; XPath(query) # sink",
        "query = '/fixed'\nXPath(query); XPath(user) # sink",
        "query = '/fixed'\ntry:\n    raise ValueError()\nexcept ValueError as query:\n    XPath(query) # sink",
        "global query\nquery = '/fixed'\nXPath(query) # sink",
        "query = '/fixed'\nexec(user)\nXPath(query) # sink",
        "query = '/fixed'\nbuiltins.exec(user)\nXPath(query) # sink",
        "query = '/fixed'\nframe = sys._getframe()\nXPath(query) # sink",
        "query = '/fixed'\nother = (query := user)\nXPath(query) # sink",
        "query = '/fixed'\nXPath(query, **user) # sink",
        "query = '/fixed'\nXPath(f'{query:{user}}') # sink",
        "query = '/fixed'\nXPath(query + module.value) # sink",
        "query = 'x' * 100000000\nXPath(query) # sink",
    ],
)
def test_unknown_or_ambiguous_execution_keeps_alert(body: str) -> None:
    assert not proves(body)


def test_path_proof_requires_constant_base_too() -> None:
    assert not proves(
        "bar = 'fixed'\nopen(f'{module.ROOT}/{bar}') # sink", "py/path-injection"
    )
    assert proves("bar = 'fixed'\nopen('/tmp/' + bar) # sink", "py/path-injection")


def finding(root: Path, line: int = 3, path: str = "app.py"):
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [
                    {
                        "ruleId": "py/xpath-injection",
                        "message": {"text": "Injection"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": path},
                                    "region": {"startLine": line},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    return CodeQlAdapter(ToolConfig(), 65536).parse(json.dumps(document), root)[0]


def test_refinement_keeps_auditable_identity_without_source_literal(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text(
        "def route():\n    query = 'PRIVATE_LITERAL_CANARY'\n    XPath(query)\n",
        encoding="utf-8",
    )
    original = finding(tmp_path)
    retained, reviews = annotate_constant_sinks(
        [original], tmp_path, check=lambda: None
    )
    assert retained == [original]
    assert original.evidence["constant_sink_review"]["native_finding_retained"] is True
    assert reviews[0]["finding_id"] == original.finding_id
    assert len(reviews[0]["source_sha256"]) == 64
    assert "PRIVATE_LITERAL_CANARY" not in json.dumps(reviews)


@pytest.mark.parametrize(
    "failure",
    [ValueError("budget"), SyntaxError("bad"), OSError("missing"), RecursionError()],
)
def test_source_or_proof_failure_retains_original(
    tmp_path: Path, failure: Exception
) -> None:
    original = finding(tmp_path)
    with patch(
        "py_security_suite.adapters.constant_sinks.read_python_source",
        side_effect=failure,
    ):
        assert annotate_constant_sinks([original], tmp_path, check=lambda: None) == (
            [original],
            [],
        )


def test_refinement_deadline_is_not_swallowed(tmp_path: Path) -> None:
    def expired():
        raise TimeoutError("expired")

    with pytest.raises(TimeoutError):
        annotate_constant_sinks([finding(tmp_path)], tmp_path, check=expired)


def test_evaluation_budget_retains_original(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def route():\n" + "    a = 1\n" * 1100 + "    XPath('/fixed')\n",
        encoding="utf-8",
    )
    original = finding(tmp_path, 1102)
    assert annotate_constant_sinks([original], tmp_path, check=lambda: None) == (
        [original],
        [],
    )
