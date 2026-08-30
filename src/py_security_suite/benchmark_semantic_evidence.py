from __future__ import annotations

import ast
import hashlib
import io
import importlib
import importlib.metadata
import keyword
import sys
import tokenize
from functools import lru_cache
from pathlib import Path
from typing import Any

from .path_safety import read_regular_file
from .strict_json import canonical_bytes


CANONICALIZATION = "parser-derived-structural-lexical-control-v4"
SIMILARITY_ALGORITHM = "multi-signal-shingle-jaccard-v2"
_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
_MAX_ARTIFACTS = 10_000
_MAX_TOTAL_ARTIFACT_BYTES = 256 * 1024 * 1024
_MAX_SYNTAX_NODES = 1_000_000
_SHINGLE_WIDTH = 5
_MAX_SIMILARITY_COMPARISONS = 2_000_000
_TREE_SITTER_LANGUAGES = frozenset(
    {
        "c",
        "csharp",
        "cpp",
        "go",
        "java",
        "javascript",
        "kotlin",
        "php",
        "ruby",
        "rust",
        "swift",
        "typescript",
        "tsx",
    }
)
_DISTRIBUTIONS = {
    "c": "tree-sitter-c",
    "csharp": "tree-sitter-c-sharp",
    "cpp": "tree-sitter-cpp",
    "go": "tree-sitter-go",
    "java": "tree-sitter-java",
    "javascript": "tree-sitter-javascript",
    "kotlin": "tree-sitter-kotlin",
    "php": "tree-sitter-php",
    "ruby": "tree-sitter-ruby",
    "rust": "tree-sitter-rust",
    "swift": "tree-sitter-swift",
    "typescript": "tree-sitter-typescript",
    "tsx": "tree-sitter-typescript",
}


class BenchmarkSemanticEvidenceError(ValueError):
    """Raised when semantic evidence cannot be derived from governed artifacts."""


def canonicalizer_identity(languages: set[str] | frozenset[str]) -> dict[str, Any]:
    """Return the locally reproducible parser identity for a language set."""
    normalized = tuple(sorted({_normalized_language(item) for item in languages}))
    return _canonicalizer_identity(normalized)


@lru_cache(maxsize=32)
def _canonicalizer_identity(normalized: tuple[str, ...]) -> dict[str, Any]:
    parsers: list[dict[str, str]] = []
    for language in normalized:
        if language == "python":
            version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            parsers.append(
                {
                    "language": language,
                    "parser": "cpython-ast",
                    "version": version,
                    "material_sha256": _file_digest(Path(sys.executable)),
                }
            )
            continue
        distribution = _DISTRIBUTIONS[language]
        try:
            version = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError as exc:
            raise BenchmarkSemanticEvidenceError(
                f"required semantic parser is unavailable: {distribution}"
            ) from exc
        parsers.append(
            {
                "language": language,
                "parser": distribution,
                "version": version,
                "material_sha256": _parser_material_digest(language),
            }
        )
    identity: dict[str, Any] = {
        "canonicalization": CANONICALIZATION,
        "parsers": parsers,
    }
    identity["identity_sha256"] = hashlib.sha256(canonical_bytes(identity)).hexdigest()
    return identity


def verify_semantic_records(
    records: object,
    *,
    workspace: Path,
    expected_canonicalizer_sha256: str,
    label: str,
) -> tuple[list[str], list[str]]:
    """Re-read governed artifacts and reproduce their byte and semantic digests."""
    subjects, semantics, _ = verify_semantic_record_features(
        records,
        workspace=workspace,
        expected_canonicalizer_sha256=expected_canonicalizer_sha256,
        label=label,
    )
    return subjects, semantics


def verify_semantic_record_features(
    records: object,
    *,
    workspace: Path,
    expected_canonicalizer_sha256: str,
    label: str,
) -> tuple[list[str], list[str], list[frozenset[str]]]:
    """Reproduce semantic records and return bounded structural shingles."""
    if not isinstance(records, list) or not 1 <= len(records) <= _MAX_ARTIFACTS:
        raise BenchmarkSemanticEvidenceError(f"{label} semantic records are invalid")
    paths: set[str] = set()
    subjects: list[str] = []
    semantics: list[str] = []
    features: list[frozenset[str]] = []
    languages: set[str] = set()
    total_bytes = 0
    boundary = workspace.expanduser().absolute().resolve()
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "path",
            "language",
            "subject_sha256",
            "semantic_sha256",
        }:
            raise BenchmarkSemanticEvidenceError(
                f"{label} semantic record contract is invalid"
            )
        relative = record["path"]
        if (
            not isinstance(relative, str)
            or not relative
            or relative in paths
            or Path(relative).is_absolute()
        ):
            raise BenchmarkSemanticEvidenceError(f"{label} semantic path is invalid")
        paths.add(relative)
        language = _normalized_language(record["language"])
        languages.add(language)
        try:
            _, payload = read_regular_file(
                boundary / relative,
                f"{label} semantic artifact",
                maximum_bytes=_MAX_ARTIFACT_BYTES,
                boundary=boundary,
            )
        except (OSError, ValueError) as exc:
            raise BenchmarkSemanticEvidenceError(
                f"{label} semantic artifact is not a safe regular file"
            ) from exc
        total_bytes += len(payload)
        if total_bytes > _MAX_TOTAL_ARTIFACT_BYTES:
            raise BenchmarkSemanticEvidenceError(
                f"{label} semantic artifacts exceed the aggregate byte limit"
            )
        subject = hashlib.sha256(payload).hexdigest()
        shape = _semantic_shape(payload, language)
        semantic = hashlib.sha256(canonical_bytes(shape)).hexdigest()
        if record["subject_sha256"] != subject or record["semantic_sha256"] != semantic:
            raise BenchmarkSemanticEvidenceError(
                f"{label} semantic evidence does not reproduce the governed artifact"
            )
        subjects.append(subject)
        semantics.append(semantic)
        features.append(_shape_shingles(shape))
    identity = canonicalizer_identity(languages)
    if identity["identity_sha256"] != expected_canonicalizer_sha256:
        raise BenchmarkSemanticEvidenceError(
            f"{label} semantic canonicalizer identity does not match"
        )
    return subjects, semantics, features


def semantic_fingerprint(payload: bytes, *, language: str) -> str:
    """Derive a literal- and identifier-insensitive syntax-shape fingerprint."""
    if len(payload) > _MAX_ARTIFACT_BYTES:
        raise BenchmarkSemanticEvidenceError(
            "semantic artifact exceeds the parser byte limit"
        )
    shape = _semantic_shape(payload, language)
    return hashlib.sha256(canonical_bytes(shape)).hexdigest()


def semantic_similarity(left: bytes, right: bytes, *, language: str) -> float:
    """Return exact multi-signal Jaccard similarity for two governed artifacts."""
    left_features = _shape_shingles(_semantic_shape(left, language))
    right_features = _shape_shingles(_semantic_shape(right, language))
    union = left_features | right_features
    return round(
        len(left_features & right_features) / len(union) if union else 1.0,
        12,
    )


def near_duplicate_count(
    left: list[frozenset[str]],
    right: list[frozenset[str]] | None = None,
    *,
    threshold: float = 0.85,
) -> int:
    """Count structurally similar pairs using exact Jaccard on indexed candidates."""
    if not 0.5 <= threshold <= 1:
        raise BenchmarkSemanticEvidenceError("semantic similarity threshold is invalid")
    target = left if right is None else right
    inverted: dict[str, set[int]] = {}
    for index, features in enumerate(target):
        for feature in features:
            inverted.setdefault(feature, set()).add(index)
    comparisons = 0
    matches = 0
    for left_index, features in enumerate(left):
        candidates: set[int] = set()
        for feature in features:
            candidates.update(inverted.get(feature, ()))
        for right_index in candidates:
            if right is None and right_index <= left_index:
                continue
            comparisons += 1
            if comparisons > _MAX_SIMILARITY_COMPARISONS:
                raise BenchmarkSemanticEvidenceError(
                    "semantic similarity candidate budget is exceeded"
                )
            other = target[right_index]
            union = len(features | other)
            similarity = len(features & other) / union if union else 1.0
            if similarity >= threshold:
                matches += 1
    return matches


def _semantic_shape(payload: bytes, language: str) -> list[str]:
    if len(payload) > _MAX_ARTIFACT_BYTES:
        raise BenchmarkSemanticEvidenceError(
            "semantic artifact exceeds the parser byte limit"
        )
    normalized = _normalized_language(language)
    return (
        _python_shape(payload)
        if normalized == "python"
        else _tree_sitter_shape(payload, normalized)
    )


def _shape_shingles(shape: list[str]) -> frozenset[str]:
    groups = {
        "structural": [
            item
            for item in shape
            if item.startswith(("ast:", "ast-field:", "ast-list:", "ast-scalar:"))
        ],
        "lexical": [item for item in shape if item.startswith("lex-")],
        "control": [item for item in shape if item.startswith("cfg-")],
    }
    features: set[str] = set()
    for signal, values in groups.items():
        width = min(_SHINGLE_WIDTH if signal == "structural" else 3, len(values))
        if not width:
            continue
        windows = [
            values[index : index + width] for index in range(len(values) - width + 1)
        ]
        copies = 3 if signal == "structural" else 1
        for window in windows:
            for copy in range(copies):
                features.add(
                    hashlib.sha256(canonical_bytes([signal, copy, *window])).hexdigest()
                )
    return frozenset(features)


def _python_shape(payload: bytes) -> list[str]:
    try:
        text = payload.decode("utf-8")
        tree = ast.parse(text)
    except (SyntaxError, UnicodeDecodeError) as exc:
        raise BenchmarkSemanticEvidenceError(
            "python semantic artifact cannot be parsed"
        ) from exc
    shape: list[str] = ["profile:structural-lexical-control-v1"]
    stack: list[tuple[str, object]] = [("node", tree)]
    nodes = 0
    while stack:
        marker, value = stack.pop()
        if marker != "node":
            shape.append(f"{marker}:{value}")
            continue
        if not isinstance(value, ast.AST):
            continue
        nodes += 1
        if nodes > _MAX_SYNTAX_NODES:
            raise BenchmarkSemanticEvidenceError(
                "python semantic artifact exceeds the syntax-node limit"
            )
        shape.append(f"ast:{type(value).__name__}")
        children: list[tuple[str, object]] = []
        for field, child in ast.iter_fields(value):
            shape.append(f"ast-field:{field}")
            if isinstance(child, ast.AST):
                children.append(("node", child))
            elif isinstance(child, list):
                shape.append(f"ast-list:{field}:{len(child)}")
                children.extend(
                    ("node", item) for item in child if isinstance(item, ast.AST)
                )
            elif child is not None and not isinstance(child, str):
                shape.append(f"ast-scalar:{field}:{type(child).__name__}")
        stack.extend(reversed(children))
    shape.extend(_python_lexical_features(payload))
    shape.extend(_python_control_features(tree))
    return shape


def _python_lexical_features(payload: bytes) -> list[str]:
    features: list[str] = []
    try:
        tokens = tokenize.tokenize(io.BytesIO(payload).readline)
        for token in tokens:
            if token.type == tokenize.NAME:
                features.append(
                    f"lex-keyword:{token.string}"
                    if keyword.iskeyword(token.string)
                    else "lex-name"
                )
            elif token.type == tokenize.OP:
                features.append(f"lex-operator:{token.string}")
            elif token.type == tokenize.NUMBER:
                features.append("lex-number")
            elif token.type == tokenize.STRING:
                features.append("lex-string")
    except (
        IndentationError,
        SyntaxError,
        UnicodeDecodeError,
        tokenize.TokenError,
    ) as exc:
        raise BenchmarkSemanticEvidenceError(
            "python semantic artifact cannot be tokenized"
        ) from exc
    return features


def _python_control_features(tree: ast.AST) -> list[str]:
    controls = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        ast.With,
        ast.AsyncWith,
        ast.Match,
        ast.BoolOp,
        ast.IfExp,
        ast.Raise,
        ast.Return,
        ast.Break,
        ast.Continue,
    )
    features: list[str] = []
    stack: list[tuple[ast.AST, str]] = [(tree, "root")]
    while stack:
        node, parent_control = stack.pop()
        current = type(node).__name__ if isinstance(node, controls) else parent_control
        if isinstance(node, controls):
            features.append(f"cfg-node:{current}")
            features.append(f"cfg-edge:{parent_control}->{current}")
            for field in ("body", "orelse", "finalbody", "handlers", "cases"):
                branch = getattr(node, field, None)
                if isinstance(branch, list) and branch:
                    features.append(f"cfg-branch:{current}:{field}")
        stack.extend(
            (child, current) for child in reversed(list(ast.iter_child_nodes(node)))
        )
    return features


def _tree_sitter_shape(payload: bytes, language: str) -> list[str]:
    from tree_sitter import Language, Parser

    module_name = {"csharp": "c_sharp", "tsx": "typescript"}.get(language, language)
    function_name = (
        "language_tsx"
        if language == "tsx"
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
    except (AttributeError, ImportError, LookupError, TypeError, ValueError) as exc:
        raise BenchmarkSemanticEvidenceError(
            f"{language} semantic parser is unavailable"
        ) from exc
    if tree.root_node.has_error:
        raise BenchmarkSemanticEvidenceError(
            f"{language} semantic artifact contains syntax errors"
        )
    shape: list[str] = ["profile:structural-lexical-control-v1"]
    stack: list[tuple[Any, str | None, int, str]] = [(tree.root_node, None, 0, "root")]
    while stack:
        node, field, depth, parent_control = stack.pop()
        if len(shape) >= _MAX_SYNTAX_NODES:
            raise BenchmarkSemanticEvidenceError(
                f"{language} semantic artifact exceeds the syntax-node limit"
            )
        shape.append(
            f"ast:{field or '-'}:{node.type}:{int(node.is_named)}:d{min(depth, 12)}"
        )
        control = (
            node.type
            if any(
                marker in node.type
                for marker in (
                    "if",
                    "for",
                    "while",
                    "switch",
                    "match",
                    "try",
                    "catch",
                    "return",
                    "break",
                    "continue",
                )
            )
            else parent_control
        )
        if control != parent_control:
            shape.extend(
                (f"cfg-node:{control}", f"cfg-edge:{parent_control}->{control}")
            )
        if not node.is_named:
            shape.append(f"lex-token:{node.type}")
        elif not node.children:
            shape.append(f"lex-leaf:{node.type}")
        children = [
            (child, node.field_name_for_child(index), depth + 1, control)
            for index, child in enumerate(node.children)
        ]
        stack.extend(reversed(children))
    return shape


@lru_cache(maxsize=32)
def _parser_material_digest(language: str) -> str:
    module_name = {"csharp": "c_sharp", "tsx": "typescript"}.get(language, language)
    modules = [
        importlib.import_module("tree_sitter"),
        importlib.import_module(f"tree_sitter_{module_name}"),
    ]
    materials: list[dict[str, str]] = []
    for module in modules:
        module_file = getattr(module, "__file__", None)
        if not module_file:
            raise BenchmarkSemanticEvidenceError(
                f"semantic parser material is unavailable: {module.__name__}"
            )
        path = Path(module_file).resolve()
        candidates = [path]
        if path.name == "__init__.py":
            candidates.extend(
                item
                for item in sorted(path.parent.iterdir())
                if item.is_file()
                and item.suffix.casefold() in {".py", ".pyd", ".so", ".dll"}
            )
        for candidate in candidates:
            materials.append(
                {
                    "name": f"{module.__name__}/{candidate.name}",
                    "sha256": _file_digest(candidate),
                }
            )
    return hashlib.sha256(canonical_bytes(materials)).hexdigest()


@lru_cache(maxsize=128)
def _file_digest(path: Path) -> str:
    try:
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError as exc:
        raise BenchmarkSemanticEvidenceError(
            f"semantic parser material cannot be read: {path.name}"
        ) from exc


def _normalized_language(value: object) -> str:
    if not isinstance(value, str):
        raise BenchmarkSemanticEvidenceError("semantic artifact language is invalid")
    language = {
        "py": "python",
        "js": "javascript",
        "ts": "typescript",
        "cs": "csharp",
    }.get(value.casefold(), value.casefold())
    if language != "python" and language not in _TREE_SITTER_LANGUAGES:
        raise BenchmarkSemanticEvidenceError(
            f"unsupported semantic artifact language: {language}"
        )
    return language
