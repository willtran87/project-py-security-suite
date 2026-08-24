from __future__ import annotations

import ast
import hashlib
import importlib.util
import importlib.metadata
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .path_safety import read_regular_file
from .execution import CommandEnvironment, run_command
from .strict_json import canonical_bytes
from .deployment_receipt import verify_deployment_receipt


_MAX_FILE_BYTES = 1024 * 1024
_MAX_FILES = 50_000
_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_BYTECODE_ANALYZER = r"""
import dis, json, marshal, sys, types
data = open(sys.argv[1], "rb").read()
root = marshal.loads(data[16:])
if not isinstance(root, types.CodeType): raise ValueError("not a code object")
seen, edges, stack = set(), set(), [root]
while stack:
    code = stack.pop()
    if id(code) in seen: continue
    seen.add(id(code))
    for const in code.co_consts:
        if isinstance(const, types.CodeType): stack.append(const)
    for instruction in dis.get_instructions(code):
        if instruction.opname == "IMPORT_NAME" and isinstance(instruction.argval, str):
            edges.add((max(1, instruction.starts_line or code.co_firstlineno), "module-import", instruction.argval))
        elif instruction.opname in {"LOAD_GLOBAL", "LOAD_NAME"} and instruction.argval in {"eval", "exec", "compile", "__import__"}:
            edges.add((max(1, instruction.starts_line or code.co_firstlineno), "dynamic-dispatch", str(instruction.argval)))
print(json.dumps(sorted(edges)))
"""
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
_GENERATED_MARKERS = (
    "@generated",
    "code generated",
    "do not edit",
    "generated from",
    "automatically generated",
    "sourceMappingURL=",
)
_DYNAMIC_CODE = re.compile(
    r"\b(?:eval|exec|compile|new\s+Function|__import__|importlib\.import_module|"
    r"getattr|setattr|entry_points|load_entry_point|Class\.forName|Assembly\.Load)\s*\("
)

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


def build_boundary_graph(
    target: Path, *, require_governed_parsers: bool = False
) -> dict[str, Any]:
    """Build a bounded, language-neutral graph of external trust boundaries."""
    root = target.resolve()
    edges: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    languages: Counter[str] = Counter()
    language_files: dict[str, list[dict[str, Any]]] = {}
    special_surfaces: list[dict[str, Any]] = []
    semantic_failed_languages: set[str] = set()
    scanned_bytes = 0
    repository_files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and not any(part in _IGNORED_PARTS for part in path.relative_to(root).parts)
    )
    for path in repository_files[:_MAX_FILES]:
        kind = _SPECIAL_SUFFIXES.get(path.suffix.casefold())
        if not kind:
            continue
        relative = path.relative_to(root).as_posix()
        try:
            if (
                require_governed_parsers
                and kind in {"bytecode", "native-extension"}
                and not os.environ.get("PYSEC_PARSER_SANDBOX_PREFIX_JSON", "").strip()
            ):
                raise ValueError("governed parser sandbox is required")
            _, payload = read_regular_file(
                path,
                f"{kind} surface",
                maximum_bytes=_MAX_FILE_BYTES,
                boundary=root,
            )
            surface, surface_edges = _analyze_special_surface(
                payload, relative, kind, path
            )
            special_surfaces.append(surface)
            edges.extend(surface_edges)
        except (
            OSError,
            TypeError,
            ValueError,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            special_surfaces.append(
                {
                    "path": relative,
                    "kind": kind,
                    "analysis": "unsupported",
                    "covered": False,
                }
            )
            errors.append({"path": relative, "reason": f"{kind}-{type(exc).__name__}"})
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
                    "analysis": "semantic" if language == "python" else "heuristic",
                    "covered": True,
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
                semantic_failed_languages.add(language)
        else:
            semantic_edges, parse_error = _polyglot_semantic_edges(
                payload, relative, language
            )
            edges.extend(semantic_edges)
            if parse_error:
                errors.append({"path": relative, "reason": parse_error})
                semantic_failed_languages.add(language)
    unique = {
        (edge["source"], edge["line"], edge["kind"], edge["target"]): edge
        for edge in edges
    }
    ordered = [unique[key] for key in sorted(unique)]
    heuristic_languages = sorted(semantic_failed_languages)
    special_surfaces = sorted(
        {(item["path"], item["kind"]): item for item in special_surfaces}.values(),
        key=lambda item: (str(item["path"]), str(item["kind"])),
    )
    special_surface_complete = all(item["covered"] for item in special_surfaces)
    heuristic_surfaces = any(
        item["analysis"] in {"heuristic", "inventory-only", "unsupported"}
        for item in special_surfaces
    )
    language_file_sets: dict[str, dict[str, Any]] = {}
    for language in sorted(language_files):
        ordered_files = sorted(
            language_files[language], key=lambda item: str(item["path"])
        )
        language_file_sets[language] = {
            "files": ordered_files,
            "files_sha256": hashlib.sha256(canonical_bytes(ordered_files)).hexdigest(),
        }
    parser_provenance = _semantic_parser_provenance(languages)
    compiler_evidence, compiler_authority = _compiler_semantic_evidence(
        language_file_sets,
        required=require_governed_parsers and bool(set(languages) - {"python"}),
    )
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
        and not heuristic_surfaces
        and not truncated
        and not errors
        and special_surface_complete,
        "semantic_parsers": (
            (["python-ast"] if languages.get("python") else [])
            + [
                f"tree-sitter-{language}"
                for language in sorted(set(languages) - {"python"})
            ]
        ),
        "semantic_parser_provenance": parser_provenance,
        "compiler_semantic_complete": compiler_evidence is not None
        or not bool(set(languages) - {"python"}),
        "compiler_semantic_evidence": compiler_evidence,
        "compiler_semantic_authority_receipt": compiler_authority,
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


def _semantic_parser_provenance(languages: Counter[str]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    if languages.get("python"):
        result.append(
            {
                "language": "python",
                "engine": "python-ast",
                "version": sys.version.split()[0],
                "module_sha256": hashlib.sha256(
                    Path(ast.__file__).read_bytes()
                ).hexdigest(),
            }
        )
    for language in sorted(set(languages) - {"python"}):
        module_name = {"csharp": "c_sharp"}.get(language, language)
        package_name = {
            "csharp": "tree-sitter-c-sharp",
        }.get(language, f"tree-sitter-{language.replace('_', '-')}")
        module = importlib.import_module(f"tree_sitter_{module_name}")
        module_path = Path(str(module.__file__)).resolve()
        result.append(
            {
                "language": language,
                "engine": "tree-sitter",
                "version": importlib.metadata.version(package_name),
                "module_sha256": hashlib.sha256(module_path.read_bytes()).hexdigest(),
            }
        )
    return result


def _compiler_semantic_evidence(
    language_file_sets: dict[str, dict[str, Any]], *, required: bool
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if not required:
        return None, None
    raw_path = os.environ.get("PYSEC_COMPILER_SEMANTIC_EVIDENCE_PATH", "").strip()
    expected = (
        os.environ.get("PYSEC_COMPILER_SEMANTIC_EVIDENCE_SHA256", "").strip().casefold()
    )
    if not raw_path or len(expected) != 64:
        raise ValueError("compiler semantic evidence configuration is incomplete")
    path = Path(raw_path).expanduser().resolve()
    _, payload = read_regular_file(
        path, "compiler semantic evidence", maximum_bytes=16 * 1024 * 1024
    )
    if hashlib.sha256(payload).hexdigest() != expected:
        raise ValueError("compiler semantic evidence does not match its pin")
    from .strict_json import loads as strict_loads

    value = strict_loads(payload)
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "frontends"}
        or value.get("schema_version") != "1.0"
        or not isinstance(value.get("frontends"), list)
    ):
        raise ValueError("compiler semantic evidence fields do not match")
    expected_languages = set(language_file_sets) - {"python"}
    observed: set[str] = set()
    for item in value.get("frontends", []):
        fields = {
            "language",
            "engine",
            "engine_sha256",
            "configuration_sha256",
            "files_sha256",
            "symbols",
            "cfg_edges",
            "dataflow_edges",
            "interprocedural_edges",
        }
        language = str(item.get("language") or "") if isinstance(item, dict) else ""
        counts = ("symbols", "cfg_edges", "dataflow_edges", "interprocedural_edges")
        if (
            not isinstance(item, dict)
            or set(item) != fields
            or language not in expected_languages
            or language in observed
            or str(item["engine"]).casefold().startswith("tree-sitter")
            or any(
                len(str(item[name])) != 64
                or any(
                    character not in "0123456789abcdef" for character in str(item[name])
                )
                for name in ("engine_sha256", "configuration_sha256")
            )
            or item["files_sha256"] != language_file_sets[language]["files_sha256"]
            or any(
                isinstance(item[name], bool)
                or not isinstance(item[name], int)
                or item[name] < 0
                for name in counts
            )
            or item["symbols"] < 1
            or sum(item[name] for name in counts[1:]) < 1
        ):
            raise ValueError("compiler semantic frontend evidence is invalid")
        observed.add(language)
    if observed != expected_languages:
        raise ValueError("compiler semantic evidence omits a source language")
    authority = verify_deployment_receipt(
        value,
        purpose="compiler-semantic-evidence",
        environment_prefix="PYSEC_COMPILER_SEMANTIC_AUTHORITY",
    )
    return value, authority


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
            if argument and name in {
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
            elif argument and name in {"ctypes.CDLL", "ctypes.WinDLL", "cffi.dlopen"}:
                edges.append(
                    _edge(source, node.lineno, "native-ffi", argument, "python")
                )
            elif (
                argument
                and name
                in {
                    "httpx.get",
                    "httpx.post",
                    "requests.get",
                    "requests.post",
                    "urllib.request.urlopen",
                }
                and _http_origin(argument)
            ):
                edges.append(
                    _edge(
                        source,
                        node.lineno,
                        "network-endpoint",
                        _http_origin(argument) or argument,
                        "python",
                    )
                )
            elif name in {
                "__import__",
                "importlib.import_module",
                "importlib.metadata.entry_points",
                "pkg_resources.iter_entry_points",
                "pkg_resources.load_entry_point",
                "getattr",
                "setattr",
            }:
                edges.append(
                    _edge(
                        source,
                        node.lineno,
                        "dynamic-dispatch",
                        argument or "<computed>",
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


def _polyglot_semantic_edges(
    payload: bytes, source: str, language: str
) -> tuple[list[dict[str, Any]], str | None]:
    """Parse supported non-Python languages before extracting boundary nodes."""

    from tree_sitter import Language, Parser

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


def _analyze_special_surface(
    payload: bytes, source: str, kind: str, path: Path
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if kind == "notebook":
        value = json.loads(payload.decode("utf-8"))
        cells = value.get("cells") if isinstance(value, dict) else None
        if not isinstance(cells, list):
            raise ValueError("notebook cells are invalid")
        edges: list[dict[str, Any]] = []
        for index, cell in enumerate(cells):
            if not isinstance(cell, dict) or cell.get("cell_type") != "code":
                continue
            raw = cell.get("source")
            text = "".join(raw) if isinstance(raw, list) else str(raw or "")
            transformed: list[str] = []
            for line_number, line in enumerate(text.splitlines(), start=1):
                stripped = line.lstrip()
                if stripped.startswith(("%", "!")):
                    edges.append(
                        _edge(
                            f"{source}#cell-{index + 1}",
                            line_number,
                            "dynamic-dispatch",
                            stripped[:200],
                            "notebook-magic",
                        )
                    )
                    transformed.append("pass")
                else:
                    transformed.append(line)
            cell_edges, error = _python_edges(
                "\n".join(transformed), f"{source}#cell-{index + 1}"
            )
            if error:
                raise ValueError("notebook code cell is not valid Python")
            edges.extend(cell_edges)
        return _surface(source, kind, "semantic", True), edges
    if kind == "template":
        text = payload.decode("utf-8")
        return _surface(source, kind, "semantic", True), _template_edges(
            text, source, path.suffix.casefold()
        )
    if kind == "bytecode":
        if len(payload) < 16 or payload[:4] != importlib.util.MAGIC_NUMBER:
            raise ValueError("Python bytecode magic or header is invalid")
        result = run_command(
            [sys.executable, "-I", "-S", "-c", _BYTECODE_ANALYZER, str(path)],
            cwd=path.parent,
            timeout_seconds=10,
            max_output_bytes=1024 * 1024,
            environment=_parser_environment(),
        )
        if result.exit_code != 0 or result.timed_out or result.output_limit_exceeded:
            raise ValueError("Python bytecode semantic disassembly failed")
        decoded = json.loads(result.stdout)
        if not isinstance(decoded, list) or len(decoded) > 10_000:
            raise ValueError("Python bytecode semantic output is invalid")
        edges = []
        for item in decoded:
            if (
                not isinstance(item, list)
                or len(item) != 3
                or item[1] not in {"module-import", "dynamic-dispatch"}
            ):
                raise ValueError("Python bytecode semantic edge is invalid")
            edges.append(
                _edge(
                    source, int(item[0]), str(item[1]), str(item[2]), "python-bytecode"
                )
            )
        return _surface(source, kind, "semantic", True), edges
    if kind == "webassembly":
        imports = _wasm_imports(payload)
        return _surface(source, kind, "semantic", True), [
            _edge(
                source,
                1,
                "binary-hardening"
                if name.startswith("hardening:")
                else "binary-import",
                name,
                "webassembly",
            )
            for name in imports
        ]
    if kind == "native-extension":
        imports = _native_imports(path, payload)
        return _surface(source, kind, "semantic", True), [
            _edge(
                source,
                1,
                "binary-hardening"
                if name.startswith("hardening:")
                else "binary-import",
                name,
                "native",
            )
            for name in imports
        ]
    raise ValueError("special surface kind is unsupported")


def _surface(path: str, kind: str, analysis: str, covered: bool) -> dict[str, Any]:
    return {"path": path, "kind": kind, "analysis": analysis, "covered": covered}


def _template_edges(text: str, source: str, suffix: str) -> list[dict[str, Any]]:
    """Tokenize Jinja/Twig/Handlebars dependency directives without rendering."""

    token = re.compile(r"{#.*?#}|{%.*?%}|{{.*?}}", re.DOTALL)
    matches = list(token.finditer(text))
    remainder = token.sub("", text)
    if any(marker in remainder for marker in ("{#", "{%", "{{")):
        raise ValueError("template directive is unterminated")
    edges = _text_edges(text, source, "template")
    security_patterns = (
        (r"\|\s*safe\b", "escaping-bypass:safe-filter"),
        (r"{%\s*autoescape\s+false\s*%}", "escaping-bypass:autoescape-disabled"),
        (r"{%\s*raw\s*%}", "escaping-bypass:raw-block"),
        (r"{{{", "escaping-bypass:unescaped-handlebars"),
    )
    for pattern, target in security_patterns:
        for finding in re.finditer(pattern, text, re.IGNORECASE):
            edges.append(
                _edge(
                    source,
                    text.count("\n", 0, finding.start()) + 1,
                    "security-control",
                    target,
                    "template",
                )
            )
    for match in matches:
        raw = match.group(0)
        if raw.startswith(("{#", "{{!")):
            continue
        body = raw[2:-2].strip().rstrip("-").strip()
        if suffix == ".hbs":
            if not body.startswith(">"):
                continue
            argument = body[1:].strip().split(maxsplit=1)[0] if body[1:].strip() else ""
            literal = argument if re.fullmatch(r"[A-Za-z0-9_./-]+", argument) else ""
        else:
            parts = body.split(maxsplit=1)
            if not parts or parts[0] not in {"include", "extends", "import", "from"}:
                continue
            argument = parts[1].strip() if len(parts) == 2 else ""
            quoted = re.match(r"(['\"])([^'\"]+)\1(?:\s|$)", argument)
            literal = quoted.group(2) if quoted else ""
        edges.append(
            _edge(
                source,
                text.count("\n", 0, match.start()) + 1,
                "template-include" if literal else "dynamic-dispatch",
                literal or "<computed-template>",
                "handlebars" if suffix == ".hbs" else "jinja-twig",
            )
        )
    return edges


def _wasm_imports(payload: bytes) -> list[str]:
    if not payload.startswith(b"\x00asm\x01\x00\x00\x00"):
        raise ValueError("WebAssembly header is invalid")
    from wasmtime import Engine, Module, WasmtimeError

    try:
        Module.validate(Engine(), payload)
    except WasmtimeError as exc:
        raise ValueError("WebAssembly module failed full validation") from exc
    offset = 8
    imports: list[str] = []
    while offset < len(payload):
        section = payload[offset]
        offset += 1
        size, offset = _leb128(payload, offset)
        end = offset + size
        if end > len(payload):
            raise ValueError("WebAssembly section exceeds the file")
        if section == 2:
            count, cursor = _leb128(payload, offset)
            if count > 10_000:
                raise ValueError("WebAssembly import table is oversized")
            for _ in range(count):
                module, cursor = _wasm_name(payload, cursor, end)
                name, cursor = _wasm_name(payload, cursor, end)
                if cursor >= end:
                    raise ValueError("WebAssembly import descriptor is truncated")
                descriptor = payload[cursor]
                cursor += 1
                cursor = _skip_wasm_descriptor(payload, cursor, end, descriptor)
                imports.append(f"{module}.{name}")
            if cursor != end:
                raise ValueError("WebAssembly import section has trailing data")
        elif section == 5:
            count, cursor = _leb128(payload, offset)
            if count > 100:
                raise ValueError("WebAssembly memory table is oversized")
            for _ in range(count):
                flags = payload[cursor] if cursor < end else 0xFF
                cursor = _skip_wasm_limits(payload, cursor)
                imports.append(
                    "hardening:memory-maximum="
                    + ("enabled" if flags & 1 else "disabled")
                )
                imports.append(
                    "hardening:shared-memory="
                    + ("enabled" if flags & 2 else "disabled")
                )
            if cursor != end:
                raise ValueError("WebAssembly memory section has trailing data")
        elif section == 8:
            _, cursor = _leb128(payload, offset)
            if cursor != end:
                raise ValueError("WebAssembly start section is invalid")
            imports.append("hardening:start-function=present")
        offset = end
    return sorted(set(imports))


def _leb128(payload: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 35, 7):
        if offset >= len(payload):
            raise ValueError("WebAssembly integer is truncated")
        byte = payload[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
    raise ValueError("WebAssembly integer is oversized")


def _wasm_name(payload: bytes, offset: int, end: int) -> tuple[str, int]:
    size, offset = _leb128(payload, offset)
    if size > 4096 or offset + size > end:
        raise ValueError("WebAssembly name is invalid")
    try:
        return payload[offset : offset + size].decode("utf-8"), offset + size
    except UnicodeDecodeError as exc:
        raise ValueError("WebAssembly name is not UTF-8") from exc


def _skip_wasm_descriptor(payload: bytes, offset: int, end: int, kind: int) -> int:
    if kind == 0:
        _, offset = _leb128(payload, offset)
        return offset
    if kind == 1:
        if offset >= end:
            raise ValueError("WebAssembly table descriptor is truncated")
        offset += 1
        return _skip_wasm_limits(payload, offset)
    if kind == 2:
        return _skip_wasm_limits(payload, offset)
    if kind == 3:
        if offset + 2 > end:
            raise ValueError("WebAssembly global descriptor is truncated")
        return offset + 2
    if kind == 4:
        if offset >= end:
            raise ValueError("WebAssembly tag descriptor is truncated")
        _, offset = _leb128(payload, offset + 1)
        return offset
    raise ValueError("WebAssembly import kind is unsupported")


def _skip_wasm_limits(payload: bytes, offset: int) -> int:
    if offset >= len(payload):
        raise ValueError("WebAssembly limits are truncated")
    flags = payload[offset]
    offset += 1
    _, offset = _leb128(payload, offset)
    if flags & 1:
        _, offset = _leb128(payload, offset)
    return offset


def _native_imports(path: Path, payload: bytes) -> list[str]:
    if not (
        payload[:2] == b"MZ"
        or payload.startswith(b"\x7fELF")
        or payload[:4]
        in {
            b"\xca\xfe\xba\xbe",
            b"\xce\xfa\xed\xfe",
            b"\xcf\xfa\xed\xfe",
            b"\xfe\xed\xfa\xce",
            b"\xfe\xed\xfa\xcf",
        }
    ):
        raise ValueError("native extension format is unsupported")
    worker = Path(__file__).with_name("native_parser_worker.py")
    result = run_command(
        [sys.executable, "-I", str(worker), str(path)],
        cwd=path.parent,
        timeout_seconds=15,
        max_output_bytes=4 * 1024 * 1024,
        environment=_parser_environment(),
    )
    if (
        result.exit_code != 0
        or result.timed_out
        or result.output_limit_exceeded
        or result.resource_limit_errors
    ):
        raise ValueError("resource-contained native binary parsing failed")
    value = json.loads(result.stdout)
    if (
        not isinstance(value, list)
        or len(value) > 100_000
        or any(not isinstance(item, str) or not item for item in value)
        or value != sorted(set(value))
    ):
        raise ValueError("native binary parser output is invalid")
    return value


def _parser_environment() -> CommandEnvironment:
    raw_prefix = os.environ.get("PYSEC_PARSER_SANDBOX_PREFIX_JSON", "").strip()
    if not raw_prefix:
        return CommandEnvironment(max_scratch_bytes=16 * 1024 * 1024)
    try:
        prefix = json.loads(raw_prefix)
    except json.JSONDecodeError as exc:
        raise ValueError("parser sandbox prefix is invalid JSON") from exc
    if (
        not isinstance(prefix, list)
        or not prefix
        or any(not isinstance(item, str) or not item for item in prefix)
    ):
        raise ValueError("parser sandbox prefix must be an argument array")
    return CommandEnvironment(
        sandbox_prefix=tuple(prefix),
        sandbox_executable_sha256=os.environ.get("PYSEC_PARSER_SANDBOX_SHA256", "")
        .strip()
        .casefold(),
        sandbox_runtime_closure_sha256=os.environ.get(
            "PYSEC_PARSER_SANDBOX_RUNTIME_SHA256", ""
        )
        .strip()
        .casefold(),
        max_scratch_bytes=16 * 1024 * 1024,
    )


def _native_imports_in_process(path: Path, payload: bytes) -> list[str]:
    if payload[:2] == b"MZ":
        import pefile  # type: ignore[import-untyped]

        try:
            pe = pefile.PE(str(path), fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
            pe_names = {
                f"{entry.dll.decode('utf-8', errors='strict')}!{symbol.name.decode('utf-8', errors='strict') if symbol.name else '#' + str(symbol.ordinal)}"
                for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ())
                for symbol in entry.imports
            }
            characteristics = int(pe.OPTIONAL_HEADER.DllCharacteristics)
            for label, mask in (
                ("aslr", 0x0040),
                ("high-entropy-aslr", 0x0020),
                ("dep", 0x0100),
                ("control-flow-guard", 0x4000),
            ):
                pe_names.add(
                    f"hardening:{label}={'enabled' if characteristics & mask else 'disabled'}"
                )
            return sorted(pe_names)
        except pefile.PEFormatError as exc:
            raise ValueError("PE import table is invalid") from exc
        finally:
            if "pe" in locals():
                pe.close()
    if payload.startswith(b"\x7fELF"):
        from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]

        elf_names: set[str] = set()
        with path.open("rb") as handle:
            elf = ELFFile(handle)
            elf_names.add(
                "hardening:position-independent="
                + ("enabled" if elf.header["e_type"] == "ET_DYN" else "disabled")
            )
            segments = list(elf.iter_segments())
            stack = next(
                (
                    segment
                    for segment in segments
                    if segment.header.p_type == "PT_GNU_STACK"
                ),
                None,
            )
            elf_names.add(
                "hardening:nx-stack="
                + (
                    "enabled"
                    if stack is not None and not int(stack.header.p_flags) & 1
                    else "disabled"
                )
            )
            elf_names.add(
                "hardening:relro="
                + (
                    "enabled"
                    if any(s.header.p_type == "PT_GNU_RELRO" for s in segments)
                    else "disabled"
                )
            )
            bind_now = False
            for segment in segments:
                if segment.header.p_type == "PT_DYNAMIC":
                    for tag in segment.iter_tags():  # type: ignore[attr-defined]
                        if tag.entry.d_tag == "DT_NEEDED":
                            elf_names.add(str(tag.needed))
                        if tag.entry.d_tag == "DT_BIND_NOW":
                            bind_now = True
                        if tag.entry.d_tag == "DT_FLAGS" and int(tag.entry.d_val) & 0x8:
                            bind_now = True
                        if (
                            tag.entry.d_tag == "DT_FLAGS_1"
                            and int(tag.entry.d_val) & 0x1
                        ):
                            bind_now = True
            elf_names.add(f"hardening:bind-now={'enabled' if bind_now else 'disabled'}")
            symbols = elf.get_section_by_name(".dynsym")
            if symbols is not None:
                elf_names.update(
                    f"symbol:{symbol.name}"
                    for symbol in symbols.iter_symbols()  # type: ignore[attr-defined]
                    if symbol.name and symbol["st_shndx"] == "SHN_UNDEF"
                )
        return sorted(elf_names)
    if payload[:4] in {
        b"\xca\xfe\xba\xbe",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
    }:
        from macholib.MachO import MachO  # type: ignore[import-untyped]

        binary = MachO(str(path))
        macho_names = {
            filename
            for header in binary.headers
            for _index, _command, filename in header.walkRelocatables()
        }
        flags = [int(header.header.flags) for header in binary.headers]
        macho_names.add(
            "hardening:pie="
            + (
                "enabled"
                if flags and all(flag & 0x200000 for flag in flags)
                else "disabled"
            )
        )
        macho_names.add(
            "hardening:no-exec-heap="
            + (
                "enabled"
                if flags and all(flag & 0x1000000 for flag in flags)
                else "disabled"
            )
        )
        return sorted(macho_names)
    raise ValueError("native extension format is unsupported")


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
