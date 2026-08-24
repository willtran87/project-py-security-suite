from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
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
        if not kind:
            continue
        relative = path.relative_to(root).as_posix()
        try:
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
        edges = _text_edges(text, source, "template")
        include = re.compile(
            r"{[%{]\s*(?:include|extends|import|from)\s+['\"]([^'\"]+)"
        )
        edges.extend(
            _edge(
                source,
                text.count("\n", 0, match.start()) + 1,
                "template-include",
                match.group(1),
                "template",
            )
            for match in include.finditer(text)
        )
        literal_starts = {match.start() for match in include.finditer(text)}
        directive = re.compile(r"{[%{]\s*(?:include|extends|import|from)\b")
        edges.extend(
            _edge(
                source,
                text.count("\n", 0, match.start()) + 1,
                "dynamic-dispatch",
                "<computed-template>",
                "template",
            )
            for match in directive.finditer(text)
            if match.start() not in literal_starts
        )
        return _surface(source, kind, "heuristic", True), edges
    if kind == "bytecode":
        if len(payload) < 16 or payload[:4] != importlib.util.MAGIC_NUMBER:
            raise ValueError("Python bytecode magic or header is invalid")
        targets = sorted(
            {
                match.decode("ascii")
                for match in re.findall(rb"[A-Za-z_][A-Za-z0-9_.]{2,120}", payload[16:])
                if b"." in match
            }
        )[:1000]
        return _surface(source, kind, "heuristic", True), [
            _edge(source, 1, "dynamic-dispatch", target, "python-bytecode")
            for target in targets
        ]
    if kind == "webassembly":
        imports = _wasm_imports(payload)
        return _surface(source, kind, "semantic", True), [
            _edge(source, 1, "binary-import", name, "webassembly") for name in imports
        ]
    if kind == "native-extension":
        imports = _native_imports(path, payload)
        return _surface(source, kind, "semantic", True), [
            _edge(source, 1, "binary-import", name, "native") for name in imports
        ]
    raise ValueError("special surface kind is unsupported")


def _surface(path: str, kind: str, analysis: str, covered: bool) -> dict[str, Any]:
    return {"path": path, "kind": kind, "analysis": analysis, "covered": covered}


def _wasm_imports(payload: bytes) -> list[str]:
    if not payload.startswith(b"\x00asm\x01\x00\x00\x00"):
        raise ValueError("WebAssembly header is invalid")
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
    if payload[:2] == b"MZ":
        import pefile  # type: ignore[import-untyped]

        try:
            pe = pefile.PE(str(path), fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
            return sorted(
                {
                    f"{entry.dll.decode('utf-8', errors='strict')}!{symbol.name.decode('utf-8', errors='strict') if symbol.name else '#' + str(symbol.ordinal)}"
                    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ())
                    for symbol in entry.imports
                }
            )
        except pefile.PEFormatError as exc:
            raise ValueError("PE import table is invalid") from exc
        finally:
            if "pe" in locals():
                pe.close()
    if payload.startswith(b"\x7fELF"):
        from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]

        names: set[str] = set()
        with path.open("rb") as handle:
            elf = ELFFile(handle)
            for segment in elf.iter_segments():
                if segment.header.p_type == "PT_DYNAMIC":
                    names.update(
                        str(tag.needed)
                        for tag in segment.iter_tags()  # type: ignore[attr-defined]
                        if tag.entry.d_tag == "DT_NEEDED"
                    )
            symbols = elf.get_section_by_name(".dynsym")
            if symbols is not None:
                names.update(
                    f"symbol:{symbol.name}"
                    for symbol in symbols.iter_symbols()  # type: ignore[attr-defined]
                    if symbol.name and symbol["st_shndx"] == "SHN_UNDEF"
                )
        return sorted(names)
    if payload[:4] in {
        b"\xca\xfe\xba\xbe",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
    }:
        from macholib.MachO import MachO  # type: ignore[import-untyped]

        return sorted(
            {
                filename
                for header in MachO(str(path)).headers
                for _index, _command, filename in header.walkRelocatables()
            }
        )
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
