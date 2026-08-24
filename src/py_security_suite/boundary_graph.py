from __future__ import annotations

import ast
import hashlib
import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .path_safety import read_regular_file
from .strict_json import canonical_bytes


_MAX_FILE_BYTES = 1024 * 1024
_MAX_FILES = 50_000
_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_IGNORED_PARTS = frozenset(
    {".git", ".hg", ".mypy_cache", ".pytest_cache", ".tox", ".venv", "node_modules"}
)
_LANGUAGES = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".go": "go",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".kt": "kotlin",
    ".php": "php",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".swift": "swift",
    ".ts": "typescript",
    ".tsx": "typescript",
}
_SPECIAL_SUFFIXES = {
    ".ipynb": "notebook",
    ".j2": "template",
    ".jinja": "template",
    ".jinja2": "template",
    ".twig": "template",
    ".hbs": "template",
    ".pyc": "bytecode",
    ".pyo": "bytecode",
    ".so": "native-extension",
    ".pyd": "native-extension",
    ".dll": "native-extension",
    ".dylib": "native-extension",
    ".wasm": "webassembly",
}
_GENERATED_MARKERS = ("@generated", "code generated", "do not edit")
_DYNAMIC_CODE = re.compile(r"\b(?:eval|exec|compile|new\s+Function)\s*\(")

_TEXT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "module-import",
        re.compile(
            r"(?:\bimport\s+(?:[^'\";]+?\s+from\s+)?|\brequire\s*\()"
            r"['\"]([^'\"]+)['\"]"
        ),
    ),
    (
        "process-execution",
        re.compile(
            r"(?:child_process\.(?:exec|execFile|spawn)|exec\.Command|"
            r"Command::new|ProcessBuilder|Runtime\.getRuntime\(\)\.exec|"
            r"\bsystem|\bpopen)\s*\(?\s*['\"]([^'\"]+)['\"]"
        ),
    ),
    (
        "network-endpoint",
        re.compile(
            r"(?:fetch|axios\.(?:get|post|put|delete)|http\.(?:Get|Post)|"
            r"new\s+URL)\s*\(?\s*['\"](https?://[^'\"]+)['\"]"
        ),
    ),
    (
        "native-ffi",
        re.compile(r"(?:dlopen|LoadLibrary|DllImport)\s*\(?\s*['\"]([^'\"]+)['\"]"),
    ),
)


def build_boundary_graph(target: Path) -> dict[str, Any]:
    """Build a bounded, language-neutral graph of external trust boundaries."""
    root = target.resolve()
    edges: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    languages: Counter[str] = Counter()
    language_files: dict[str, list[dict[str, Any]]] = {}
    special_surfaces: list[dict[str, Any]] = []
    scanned_bytes = 0
    repository_files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and not any(part in _IGNORED_PARTS for part in path.relative_to(root).parts)
    )
    for path in repository_files[:_MAX_FILES]:
        kind = _SPECIAL_SUFFIXES.get(path.suffix.casefold())
        if kind:
            special_surfaces.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "kind": kind,
                    "analysis": "unsupported",
                    "covered": False,
                }
            )
    candidates = [
        path for path in repository_files if path.suffix.casefold() in _LANGUAGES
    ]
    truncated = len(candidates) > _MAX_FILES
    for path in candidates[:_MAX_FILES]:
        if scanned_bytes >= _MAX_TOTAL_BYTES:
            truncated = True
            break
        try:
            _, payload = read_regular_file(
                path,
                "polyglot source",
                maximum_bytes=min(_MAX_FILE_BYTES, _MAX_TOTAL_BYTES - scanned_bytes),
                boundary=root,
            )
        except (OSError, ValueError) as exc:
            errors.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "reason": type(exc).__name__,
                }
            )
            continue
        scanned_bytes += len(payload)
        language = _LANGUAGES[path.suffix.casefold()]
        languages[language] += 1
        text = payload.decode("utf-8", errors="replace")
        relative = path.relative_to(root).as_posix()
        lowered_prefix = text[:4096].casefold()
        generated = any(
            marker in lowered_prefix for marker in _GENERATED_MARKERS
        ) or any(
            part.casefold() in {"gen", "generated"}
            for part in path.relative_to(root).parts
        )
        if generated:
            special_surfaces.append(
                {
                    "path": relative,
                    "kind": "generated-source",
                    "analysis": "semantic" if language == "python" else "heuristic",
                    "covered": language == "python",
                }
            )
        if _DYNAMIC_CODE.search(text):
            special_surfaces.append(
                {
                    "path": relative,
                    "kind": "dynamic-code",
                    "analysis": "inventory-only",
                    "covered": False,
                }
            )
        language_files.setdefault(language, []).append(
            {
                "path": relative,
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "line_count": (
                    0
                    if not payload
                    else text.count("\n") + (0 if text.endswith("\n") else 1)
                ),
            }
        )
        if language == "python":
            python_edges, parse_error = _python_edges(text, relative)
            edges.extend(python_edges)
            if parse_error:
                errors.append({"path": relative, "reason": parse_error})
        else:
            edges.extend(_text_edges(text, relative, language))
    unique = {
        (edge["source"], edge["line"], edge["kind"], edge["target"]): edge
        for edge in edges
    }
    ordered = [unique[key] for key in sorted(unique)]
    heuristic_languages = sorted(set(languages) - {"python"})
    special_surfaces = sorted(
        {(item["path"], item["kind"]): item for item in special_surfaces}.values(),
        key=lambda item: (str(item["path"]), str(item["kind"])),
    )
    special_surface_complete = all(item["covered"] for item in special_surfaces)
    language_file_sets: dict[str, dict[str, Any]] = {}
    for language in sorted(language_files):
        ordered_files = sorted(
            language_files[language], key=lambda item: str(item["path"])
        )
        language_file_sets[language] = {
            "files": ordered_files,
            "files_sha256": hashlib.sha256(canonical_bytes(ordered_files)).hexdigest(),
        }
    subject = {
        "schema_version": "1.0",
        "analysis": "bounded-static-polyglot-boundary-graph",
        "languages": dict(sorted(languages.items())),
        "language_file_sets": language_file_sets,
        "scanned_files": sum(languages.values()),
        "scanned_bytes": scanned_bytes,
        "truncated": truncated,
        "complete": not truncated and not errors and special_surface_complete,
        "semantic_complete": not heuristic_languages
        and not truncated
        and not errors
        and special_surface_complete,
        "semantic_parsers": ["python-ast"] if languages.get("python") else [],
        "heuristic_languages": heuristic_languages,
        "special_surfaces": special_surfaces,
        "special_surface_complete": special_surface_complete,
        "errors": errors[:100],
        "omitted_errors": max(len(errors) - 100, 0),
        "edges": ordered,
        "summary": dict(sorted(Counter(edge["kind"] for edge in ordered).items())),
    }
    return {
        **subject,
        "graph_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
    }


def _python_edges(text: str, source: str) -> tuple[list[dict[str, Any]], str | None]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return [], "python-syntax-error"
    edges: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            edges.extend(
                _edge(source, node.lineno, "module-import", name.name, "python")
                for name in node.names
            )
        elif isinstance(node, ast.ImportFrom) and node.module:
            edges.append(
                _edge(source, node.lineno, "module-import", node.module, "python")
            )
        elif isinstance(node, ast.Call):
            name = _call_name(node.func)
            argument = _literal_argument(node)
            if not argument:
                continue
            if name in {
                "os.popen",
                "os.system",
                "subprocess.call",
                "subprocess.check_call",
                "subprocess.check_output",
                "subprocess.Popen",
                "subprocess.run",
            }:
                edges.append(
                    _edge(source, node.lineno, "process-execution", argument, "python")
                )
            elif name in {"ctypes.CDLL", "ctypes.WinDLL", "cffi.dlopen"}:
                edges.append(
                    _edge(source, node.lineno, "native-ffi", argument, "python")
                )
            elif name in {
                "httpx.get",
                "httpx.post",
                "requests.get",
                "requests.post",
                "urllib.request.urlopen",
            } and _http_origin(argument):
                edges.append(
                    _edge(
                        source,
                        node.lineno,
                        "network-endpoint",
                        _http_origin(argument) or argument,
                        "python",
                    )
                )
    return edges, None


def _text_edges(text: str, source: str, language: str) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for kind, pattern in _TEXT_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(1).strip()
            if kind == "network-endpoint":
                value = _http_origin(value) or value
            edges.append(
                _edge(
                    source,
                    text.count("\n", 0, match.start()) + 1,
                    kind,
                    value,
                    language,
                )
            )
    return edges


def _call_name(node: ast.expr) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _literal_argument(node: ast.Call) -> str:
    if not node.args:
        return ""
    value = node.args[0]
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value[:500]
    if isinstance(value, (ast.List, ast.Tuple)) and value.elts:
        first = value.elts[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value[:500]
    return ""


def _edge(
    source: str, line: int, kind: str, target: str, language: str
) -> dict[str, Any]:
    return {
        "source": source,
        "line": line,
        "kind": kind,
        "target": target[:500],
        "language": language,
    }


def _http_origin(value: str) -> str | None:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{parsed.hostname}{port}"
