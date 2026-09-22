"""Isolated worker for native tree-sitter grammar execution."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from typing import Any


def _polyglot_semantic_edges_in_process(
    payload: bytes, source: str, language: str
) -> tuple[list[dict[str, Any]], str | None]:
    """Execute one native grammar; the caller must provide OS containment."""

    from tree_sitter import Language, Parser

    from py_security_suite.boundary_graph import _edge, _text_edges

    module_name = {"csharp": "c_sharp"}.get(language, language)
    function_name = (
        "language_tsx"
        if source.casefold().endswith(".tsx")
        else "language_typescript"
        if language == "typescript"
        else "language_php"
        if language == "php"
        else "language"
    )
    try:
        grammar = importlib.import_module(f"tree_sitter_{module_name}")
        factory = getattr(grammar, function_name)
        tree = Parser(Language(factory())).parse(payload)
    except (AttributeError, ImportError, LookupError, TypeError, ValueError):
        return [], f"tree-sitter-{language}-parser-error"
    if tree.root_node.has_error:
        return [], f"tree-sitter-{language}-syntax-error"
    import_nodes = {
        "import_declaration",
        "import_statement",
        "include_directive",
        "namespace_use_declaration",
        "preproc_include",
        "require_expression",
        "use_declaration",
        "using_directive",
    }
    call_nodes = {
        "call_expression",
        "function_call_expression",
        "invocation_expression",
        "method_invocation",
    }
    edges: list[dict[str, Any]] = []
    stack = [tree.root_node]
    visited = 0
    while stack:
        node = stack.pop()
        visited += 1
        if visited > 2_000_000:
            return [], f"tree-sitter-{language}-node-limit"
        if node.type in import_nodes | call_nodes:
            snippet = payload[node.start_byte : node.end_byte].decode(
                "utf-8", errors="replace"
            )
            extracted = _text_edges(snippet, source, language)
            for edge in extracted:
                edge["line"] = node.start_point.row + int(edge["line"])
            edges.extend(extracted)
            if node.type in import_nodes and not extracted:
                target = " ".join(snippet.split())[:500]
                if target:
                    edges.append(
                        _edge(
                            source,
                            node.start_point.row + 1,
                            "module-import",
                            target,
                            language,
                        )
                    )
        stack.extend(reversed(node.children))
    return edges, None


def main() -> int:
    if len(sys.argv) != 4:
        raise ValueError("polyglot parser worker requires path, source, and language")
    package_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(package_root))
    from py_security_suite.boundary_graph import _LANGUAGES
    from py_security_suite.path_safety import read_regular_file

    source = sys.argv[2]
    language = sys.argv[3]
    if (
        not source
        or len(source) > 1000
        or any(character in source for character in "\r\n\0")
        or language not in set(_LANGUAGES.values())
        or language == "python"
    ):
        raise ValueError("polyglot parser worker identity is invalid")
    _path, payload = read_regular_file(
        Path(sys.argv[1]),
        "polyglot parser input",
        maximum_bytes=1024 * 1024,
    )
    edges, error = _polyglot_semantic_edges_in_process(payload, source, language)
    print(
        json.dumps(
            {"edges": edges, "error": error},
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as an isolated subprocess
    raise SystemExit(main())
