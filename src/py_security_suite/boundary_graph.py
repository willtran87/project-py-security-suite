from __future__ import annotations

import ast
import base64
import hashlib
import importlib.metadata
import json

from .strict_json import loads as strict_json_loads
import os
import re
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime
from collections import Counter
from itertools import pairwise
from pathlib import Path
from typing import Any
from collections.abc import Iterator
from urllib.parse import urlsplit

from .path_safety import read_regular_file
from .execution import CommandEnvironment, run_command
from .strict_json import canonical_bytes
from .deployment_receipt import verify_deployment_receipt
from .operation_receipt import verify_operation_receipt
from .failure_domain import (
    require_independent_failure_domains,
    verify_failure_domain,
    verify_registered_failure_domain,
)
from .pinned_command import command_configured, run_pinned_json_command
from .strict_json import loads as strict_loads


_MAX_FILE_BYTES = 1024 * 1024
_MAX_FILES = 50_000
_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_PARSER_SNAPSHOT_SUFFIXES = frozenset({".dll", ".dylib", ".pyc", ".pyd", ".pyo", ".so"})


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


@contextmanager
def _parser_snapshot(payload: bytes, suffix: str) -> Iterator[Path]:
    """Retain exact bounded parser input outside the mutable target tree."""

    normalized_suffix = suffix.casefold()
    if normalized_suffix not in _PARSER_SNAPSHOT_SUFFIXES:
        normalized_suffix = ".bin"
    with tempfile.TemporaryDirectory(prefix="pysec-parser-input-") as directory:
        root = Path(directory).resolve()
        snapshot = root / f"input{normalized_suffix}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(snapshot, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        yield snapshot


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
    ".dart": "unsupported-semantic-source",
    ".groovy": "unsupported-semantic-source",
    ".m": "unsupported-semantic-source",
    ".mm": "unsupported-semantic-source",
    ".scala": "unsupported-semantic-source",
    ".svelte": "unsupported-semantic-source",
    ".vue": "unsupported-semantic-source",
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
    target: Path,
    *,
    require_governed_parsers: bool = False,
    allow_ungoverned_binary_parsers: bool = False,
) -> dict[str, Any]:
    """Build a bounded graph; hostile binary parsers require an OS sandbox by default."""
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
                kind in {"bytecode", "native-extension"}
                and not allow_ungoverned_binary_parsers
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
    compiler_evidence, compiler_authority, compiler_reexecution = (
        _compiler_semantic_evidence(
            language_file_sets,
            required=require_governed_parsers and bool(languages),
        )
    )
    compiler_differential = _compiler_semantic_differential(compiler_evidence)
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
        "compiler_semantic_complete": (
            not bool(languages)
            or (
                compiler_differential is not None
                and compiler_differential["classification"] == "consensus"
            )
        ),
        "compiler_semantic_evidence": compiler_evidence,
        "compiler_semantic_differential": compiler_differential,
        "compiler_semantic_authority_receipt": compiler_authority,
        "compiler_semantic_reexecution": compiler_reexecution,
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
                "extractor_sha256": hashlib.sha256(
                    Path(__file__).read_bytes()
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
                "extractor_sha256": hashlib.sha256(
                    Path(__file__).read_bytes()
                ).hexdigest(),
            }
        )
    return result


def _compiler_semantic_evidence(
    language_file_sets: dict[str, dict[str, Any]], *, required: bool
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
    if not required:
        return None, None, None
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
        or value.get("schema_version") != "2.0"
        or not isinstance(value.get("frontends"), list)
    ):
        raise ValueError("compiler semantic evidence fields do not match")
    verify_compiler_semantic_evidence(value, language_file_sets)
    authority = verify_deployment_receipt(
        value,
        purpose="compiler-semantic-evidence",
        environment_prefix="PYSEC_COMPILER_SEMANTIC_AUTHORITY",
    )
    reexecution = _compiler_semantic_reexecution(value, language_file_sets, path)
    return value, authority, reexecution


def _compiler_semantic_reexecution(
    evidence: dict[str, Any],
    language_file_sets: dict[str, dict[str, Any]],
    evidence_path: Path,
) -> dict[str, Any]:
    prefix = "PYSEC_COMPILER_SEMANTIC_REPLAY"
    if not command_configured(prefix):
        raise ValueError("compiler semantic hermetic reexecution is unavailable")
    expected = {
        "schema_version": "1.0",
        "evidence_sha256": hashlib.sha256(canonical_bytes(evidence)).hexdigest(),
        "language_file_sets_sha256": hashlib.sha256(
            canonical_bytes(language_file_sets)
        ).hexdigest(),
        "frontends_sha256": hashlib.sha256(
            canonical_bytes(evidence["frontends"])
        ).hexdigest(),
    }
    request = {
        **expected,
        "operation": "hermetic-compiler-reexecution",
        "evidence_path": str(evidence_path),
    }
    response = run_pinned_json_command(prefix, request)
    attestation = response.pop("_effective_policy_attestation", None)
    response["effective_policy_attestation"] = attestation
    response["reexecution_request"] = request
    verify_compiler_semantic_reexecution(response, evidence, language_file_sets)
    return response


def verify_compiler_semantic_reexecution(
    value: object, evidence: object, language_file_sets: object
) -> None:
    fields = {
        "schema_version",
        "status",
        "evidence_sha256",
        "language_file_sets_sha256",
        "frontends_sha256",
        "authority_key_sha256",
        "request_sha256",
        "execution_nonce",
        "reexecution_request",
        "fresh_evidence",
        "fresh_evidence_sha256",
        "execution_transcript",
        "failure_domain",
        "operation_receipt",
        "effective_policy_attestation",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value.get("schema_version") != "1.0"
        or value.get("status") != "reexecuted-and-matched"
        or not isinstance(evidence, dict)
        or not isinstance(language_file_sets, dict)
        or value.get("evidence_sha256")
        != hashlib.sha256(canonical_bytes(evidence)).hexdigest()
        or value.get("language_file_sets_sha256")
        != hashlib.sha256(canonical_bytes(language_file_sets)).hexdigest()
        or value.get("frontends_sha256")
        != hashlib.sha256(canonical_bytes(evidence.get("frontends"))).hexdigest()
        or value.get("fresh_evidence") != evidence
        or value.get("fresh_evidence_sha256")
        != hashlib.sha256(canonical_bytes(evidence)).hexdigest()
        or not _digest(str(value.get("authority_key_sha256") or ""))
        or not _digest(str(value.get("request_sha256") or ""))
        or not str(value.get("execution_nonce") or "").strip()
        or not isinstance(value.get("reexecution_request"), dict)
    ):
        raise ValueError("compiler semantic hermetic reexecution is invalid")
    domain = verify_failure_domain(
        value["failure_domain"], "compiler reexecution authority"
    )
    verify_registered_failure_domain(
        domain,
        str(value["authority_key_sha256"]),
        "compiler reexecution authority",
    )
    for frontend in evidence["frontends"]:
        require_independent_failure_domains(
            frontend["primary_failure_domain"],
            domain,
            labels=("primary compiler", "reexecution authority"),
        )
        require_independent_failure_domains(
            frontend["secondary_failure_domain"],
            domain,
            labels=("secondary compiler", "reexecution authority"),
        )
    subject = {
        "schema_version": "1.0",
        "status": value["status"],
        "evidence_sha256": value["evidence_sha256"],
        "language_file_sets_sha256": value["language_file_sets_sha256"],
        "frontends_sha256": value["frontends_sha256"],
        "request_sha256": value["request_sha256"],
        "execution_nonce": value["execution_nonce"],
        "fresh_evidence_sha256": value["fresh_evidence_sha256"],
        "execution_transcript": value["execution_transcript"],
        "failure_domain": domain,
    }
    receipt = value["operation_receipt"]
    statement = receipt.get("statement") if isinstance(receipt, dict) else None
    try:
        observed = datetime.fromisoformat(
            str((statement or {})["issued_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("compiler reexecution authority time is invalid") from exc
    verify_operation_receipt(
        subject,
        receipt,
        purpose="compiler-semantic-hermetic-reexecution",
        observed_at=observed,
        challenge_sha256=os.environ.get("PYSEC_SCAN_TIME_CHALLENGE_SHA256", "").strip(),
        expected_key_sha256=str(value["authority_key_sha256"]),
    )
    attestation = value["effective_policy_attestation"]
    attestation_subject = (
        attestation.get("subject") if isinstance(attestation, dict) else None
    )
    if not isinstance(attestation_subject, dict):
        raise ValueError("compiler reexecution policy attestation is invalid")
    transcript = value["execution_transcript"]
    materialized = {
        "evidence_sha256": value["evidence_sha256"],
        "language_file_sets_sha256": value["language_file_sets_sha256"],
    }
    if (
        not isinstance(transcript, dict)
        or set(transcript)
        != {
            "exit_code",
            "stdout_sha256",
            "stderr_sha256",
            "materialized_inputs_sha256",
            "canary_results_sha256",
        }
        or transcript.get("exit_code") != 0
        or not _digest(str(transcript.get("stdout_sha256") or ""))
        or transcript.get("stderr_sha256") != hashlib.sha256(b"").hexdigest()
        or transcript.get("materialized_inputs_sha256")
        != hashlib.sha256(canonical_bytes(materialized)).hexdigest()
        or transcript.get("canary_results_sha256")
        != hashlib.sha256(
            canonical_bytes(_compiler_canary_results(evidence))
        ).hexdigest()
    ):
        raise ValueError("compiler reexecution transcript is invalid")
    if (
        value["request_sha256"] != attestation_subject.get("request_sha256")
        or value["execution_nonce"] != attestation_subject.get("execution_nonce")
        or value["request_sha256"]
        != hashlib.sha256(canonical_bytes(value["reexecution_request"])).hexdigest()
        or value["reexecution_request"].get("evidence_sha256")
        != value["evidence_sha256"]
        or value["reexecution_request"].get("language_file_sets_sha256")
        != value["language_file_sets_sha256"]
        or value["reexecution_request"].get("frontends_sha256")
        != value["frontends_sha256"]
        or value["reexecution_request"].get("operation")
        != "hermetic-compiler-reexecution"
    ):
        raise ValueError("compiler result is not bound to its attested execution")
    from .pinned_command import verify_retained_effective_policy_attestation

    if domain != verify_retained_effective_policy_attestation(attestation):
        raise ValueError("compiler reexecution failure domain is not attested")


def _compiler_canary_results(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for frontend in evidence["frontends"]:
        for prefix in ("primary", "secondary"):
            try:
                payload = base64.b64decode(
                    str(frontend[f"{prefix}_analysis_artifact_base64"]), validate=True
                )
                replay = strict_loads(payload)
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("compiler canary replay material is invalid") from exc
            canaries = (
                replay.get("canary_results") if isinstance(replay, dict) else None
            )
            if not isinstance(canaries, dict) or not _canary_results_valid(canaries):
                raise ValueError("compiler canary replay result is invalid")
            results.append(dict(canaries))
    return results


def verify_compiler_semantic_evidence(
    value: object, language_file_sets: object
) -> None:
    """Recheck retained compiler semantics against the exact source-file ledger."""
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "frontends"}
        or value.get("schema_version") != "2.0"
        or not isinstance(value.get("frontends"), list)
        or not isinstance(language_file_sets, dict)
    ):
        raise ValueError("compiler semantic evidence fields do not match")
    expected_languages = set(language_file_sets)
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
            "semantic_ledger",
            "semantic_ledger_sha256",
            "secondary_engine",
            "secondary_engine_sha256",
            "secondary_configuration_sha256",
            "secondary_semantic_ledger",
            "secondary_semantic_ledger_sha256",
            "primary_analysis_artifact_base64",
            "primary_analysis_artifact_sha256",
            "secondary_analysis_artifact_base64",
            "secondary_analysis_artifact_sha256",
            "primary_authority_key_sha256",
            "primary_failure_domain",
            "primary_operation_receipt",
            "secondary_authority_key_sha256",
            "secondary_failure_domain",
            "secondary_operation_receipt",
            "taint_paths",
            "taint_paths_sha256",
        }
        language = str(item.get("language") or "") if isinstance(item, dict) else ""
        counts = ("symbols", "cfg_edges", "dataflow_edges", "interprocedural_edges")
        if (
            not isinstance(item, dict)
            or set(item) != fields
            or language not in expected_languages
            or language in observed
            or str(item["engine"]).casefold().startswith("tree-sitter")
            or item["secondary_engine"] == item["engine"]
            or str(item["secondary_engine"]).casefold().startswith("tree-sitter")
            or any(
                len(str(item[name])) != 64
                or any(
                    character not in "0123456789abcdef" for character in str(item[name])
                )
                for name in (
                    "engine_sha256",
                    "configuration_sha256",
                    "secondary_engine_sha256",
                    "secondary_configuration_sha256",
                )
            )
            or item["files_sha256"] != language_file_sets[language]["files_sha256"]
            or item["semantic_ledger_sha256"]
            != hashlib.sha256(canonical_bytes(item["semantic_ledger"])).hexdigest()
            or item["secondary_semantic_ledger_sha256"]
            != hashlib.sha256(
                canonical_bytes(item["secondary_semantic_ledger"])
            ).hexdigest()
            or not isinstance(item["secondary_semantic_ledger"], dict)
            or item["taint_paths_sha256"]
            != hashlib.sha256(canonical_bytes(item["taint_paths"])).hexdigest()
            or any(
                isinstance(item[name], bool)
                or not isinstance(item[name], int)
                or item[name] < 0
                for name in counts
            )
            or item["symbols"] < 1
            or sum(item[name] for name in counts[1:]) < 1
            or len(item["secondary_semantic_ledger"].get("symbols", [])) < 1
            or sum(
                len(item["secondary_semantic_ledger"].get(name, []))
                for name in counts[1:]
            )
            < 1
        ):
            raise ValueError("compiler semantic frontend evidence is invalid")
        _verify_semantic_ledger(
            item["semantic_ledger"],
            language_file_sets[language],
            expected_counts={name: item[name] for name in counts},
        )
        _verify_semantic_ledger(
            item["secondary_semantic_ledger"],
            language_file_sets[language],
            expected_counts={
                name: len(item["secondary_semantic_ledger"][name]) for name in counts
            },
        )
        primary_replay = _verify_analysis_artifact(item, "primary")
        secondary_replay = _verify_analysis_artifact(item, "secondary")
        if (
            primary_replay["semantic_ledger"] != item["semantic_ledger"]
            or secondary_replay["semantic_ledger"] != item["secondary_semantic_ledger"]
            or primary_replay["taint_paths"] != item["taint_paths"]
        ):
            raise ValueError(
                "compiler analysis replay disagrees with retained semantics"
            )
        _verify_engine_operation(item, "primary", primary_replay)
        _verify_engine_operation(item, "secondary", secondary_replay)
        if (
            item["primary_authority_key_sha256"]
            == item["secondary_authority_key_sha256"]
        ):
            raise ValueError(
                "compiler analysis engines require independent authorities"
            )
        require_independent_failure_domains(
            item["primary_failure_domain"],
            item["secondary_failure_domain"],
            labels=("primary compiler", "secondary compiler"),
        )
        _verify_taint_paths(item["taint_paths"], item["semantic_ledger"])
        _verify_taint_paths(
            secondary_replay["taint_paths"], item["secondary_semantic_ledger"]
        )
        observed.add(language)
    if observed != expected_languages:
        raise ValueError("compiler semantic evidence omits a source language")


def _compiler_semantic_differential(
    evidence: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Retain consensus and engine-unique semantic facts without hiding drift."""

    if evidence is None:
        return None
    languages: list[dict[str, Any]] = []
    total_primary_only = 0
    total_secondary_only = 0
    for frontend in evidence["frontends"]:
        primary_replay = _verify_analysis_artifact(frontend, "primary")
        secondary_replay = _verify_analysis_artifact(frontend, "secondary")
        primary_facts = _normalized_semantic_facts(primary_replay)
        secondary_facts = _normalized_semantic_facts(secondary_replay)
        categories: dict[str, dict[str, Any]] = {}
        for name in (
            "symbols",
            "cfg_edges",
            "dataflow_edges",
            "interprocedural_edges",
        ):
            primary = {
                hashlib.sha256(canonical_bytes(item)).hexdigest()
                for item in primary_facts[name]
            }
            secondary = {
                hashlib.sha256(canonical_bytes(item)).hexdigest()
                for item in secondary_facts[name]
            }
            primary_only = sorted(primary - secondary)
            secondary_only = sorted(secondary - primary)
            total_primary_only += len(primary_only)
            total_secondary_only += len(secondary_only)
            categories[name] = {
                "consensus": sorted(primary & secondary),
                "primary_only": primary_only,
                "secondary_only": secondary_only,
                "union": sorted(primary | secondary),
            }
        primary_taint = {
            hashlib.sha256(canonical_bytes(item)).hexdigest()
            for item in primary_facts["taint_paths"]
        }
        secondary_taint = {
            hashlib.sha256(canonical_bytes(item)).hexdigest()
            for item in secondary_facts["taint_paths"]
        }
        taint_primary_only = sorted(primary_taint - secondary_taint)
        taint_secondary_only = sorted(secondary_taint - primary_taint)
        total_primary_only += len(taint_primary_only)
        total_secondary_only += len(taint_secondary_only)
        languages.append(
            {
                "language": frontend["language"],
                "primary_engine": frontend["engine"],
                "secondary_engine": frontend["secondary_engine"],
                "primary_ledger_sha256": frontend["semantic_ledger_sha256"],
                "secondary_ledger_sha256": frontend["secondary_semantic_ledger_sha256"],
                "semantic_facts": categories,
                "taint_paths": {
                    "consensus": sorted(primary_taint & secondary_taint),
                    "primary_only": taint_primary_only,
                    "secondary_only": taint_secondary_only,
                    "union": sorted(primary_taint | secondary_taint),
                },
            }
        )
    subject = {
        "schema_version": "1.0",
        "normalization": "qualified-source-symbol-ontology-v2",
        "classification": (
            "consensus"
            if total_primary_only == 0 and total_secondary_only == 0
            else "engine-disagreement-review-required"
        ),
        "primary_only": total_primary_only,
        "secondary_only": total_secondary_only,
        "languages": sorted(languages, key=lambda item: str(item["language"])),
    }
    return {
        **subject,
        "differential_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
    }


def _normalized_semantic_facts(replay: dict[str, Any]) -> dict[str, list[object]]:
    """Map engine-private IDs onto stable source-location semantic identities."""

    ledger = replay["semantic_ledger"]
    symbol_fields = (
        "path",
        "start_line",
        "start_column",
        "end_line",
        "end_column",
        "kind",
        "qualified_name",
        "signature",
        "language",
    )
    symbols = {
        str(item["id"]): {
            name: (
                str(item[name]).casefold()
                if name in {"kind", "language"}
                else item[name]
            )
            for name in symbol_fields
        }
        for item in ledger["symbols"]
    }

    def symbol(identifier: object) -> dict[str, object]:
        return symbols[str(identifier)]

    result: dict[str, list[object]] = {
        "symbols": list(symbols.values()),
        "cfg_edges": [],
        "dataflow_edges": [],
        "interprocedural_edges": [],
        "taint_paths": [],
    }
    for category in ("cfg_edges", "dataflow_edges", "interprocedural_edges"):
        result[category] = [
            {
                "source": symbol(edge["source"]),
                "target": symbol(edge["target"]),
                "kind": str(edge["kind"]).casefold(),
                "callsite_path": str(edge["callsite_path"]),
                "callsite_line": int(edge["callsite_line"]),
                "callsite_column": int(edge["callsite_column"]),
                "context": str(edge["context"]),
            }
            for edge in ledger[category]
        ]
    result["taint_paths"] = [
        {
            "source": symbol(path["source"]),
            "sink": symbol(path["sink"]),
            "path": [symbol(item) for item in path["path"]],
            "sanitizers": [symbol(item) for item in path["sanitizers"]],
            "barriers": [symbol(item) for item in path["barriers"]],
        }
        for path in replay["taint_paths"]
    ]
    return result


def _verify_analysis_artifact(item: dict[str, Any], prefix: str) -> dict[str, Any]:
    try:
        payload = base64.b64decode(
            str(item[f"{prefix}_analysis_artifact_base64"]), validate=True
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("compiler analysis replay artifact is invalid") from exc
    if (
        not payload
        or len(payload) > 16 * 1024 * 1024
        or hashlib.sha256(payload).hexdigest()
        != item[f"{prefix}_analysis_artifact_sha256"]
    ):
        raise ValueError("compiler analysis replay artifact is detached")
    try:
        replay = strict_loads(payload)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "compiler analysis replay artifact is not strict JSON"
        ) from exc
    engine_field = "engine" if prefix == "primary" else "secondary_engine"
    engine_digest_field = (
        "engine_sha256" if prefix == "primary" else "secondary_engine_sha256"
    )
    config_field = (
        "configuration_sha256"
        if prefix == "primary"
        else "secondary_configuration_sha256"
    )
    if (
        not isinstance(replay, dict)
        or set(replay)
        != {
            "schema_version",
            "engine",
            "engine_sha256",
            "configuration_sha256",
            "files_sha256",
            "semantic_ledger",
            "taint_paths",
            "engine_base64",
            "configuration_base64",
            "runtime_closure",
            "runtime_closure_sha256",
            "argv",
            "environment",
            "sandbox_policy",
            "canary_results",
            "analysis_capabilities",
        }
        or replay.get("schema_version") != "2.0"
        or replay.get("engine") != item[engine_field]
        or replay.get("engine_sha256") != item[engine_digest_field]
        or replay.get("configuration_sha256") != item[config_field]
        or replay.get("files_sha256") != item["files_sha256"]
    ):
        raise ValueError("compiler analysis replay artifact contract is invalid")
    try:
        engine_bytes = base64.b64decode(str(replay["engine_base64"]), validate=True)
        configuration_bytes = base64.b64decode(
            str(replay["configuration_base64"]), validate=True
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("compiler replay materials are invalid") from exc
    if (
        not engine_bytes
        or len(engine_bytes) > 16 * 1024 * 1024
        or hashlib.sha256(engine_bytes).hexdigest() != replay["engine_sha256"]
        or not configuration_bytes
        or len(configuration_bytes) > 16 * 1024 * 1024
        or hashlib.sha256(configuration_bytes).hexdigest()
        != replay["configuration_sha256"]
        or not isinstance(replay["runtime_closure"], list)
        or replay["runtime_closure_sha256"]
        != hashlib.sha256(canonical_bytes(replay["runtime_closure"])).hexdigest()
        or not _replay_materials_valid(replay["runtime_closure"])
        or not isinstance(replay["argv"], list)
        or not replay["argv"]
        or any(
            not isinstance(argument, str) or not argument for argument in replay["argv"]
        )
        or not isinstance(replay["environment"], list)
        or replay["sandbox_policy"]
        != {
            "network": "deny",
            "filesystem": "read-only",
            "process": "confined",
            "credentials": "isolated",
        }
        or not _canary_results_valid(replay["canary_results"])
        or replay["analysis_capabilities"]
        != {
            "alias_sensitive": True,
            "context_sensitive": True,
            "field_sensitive": True,
            "path_sensitive": True,
            "interprocedural": True,
            "dynamic_dispatch": True,
            "implicit_flows": True,
        }
    ):
        raise ValueError("compiler hermetic reexecution materials are invalid")
    return replay


def _replay_materials_valid(value: list[object]) -> bool:
    identities: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "sha256",
            "content_base64",
        }:
            return False
        path = str(item["path"])
        try:
            content = base64.b64decode(str(item["content_base64"]), validate=True)
        except (TypeError, ValueError):
            return False
        if (
            not path
            or path.startswith("/")
            or ".." in Path(path).parts
            or path in identities
            or len(content) > 16 * 1024 * 1024
            or hashlib.sha256(content).hexdigest() != item["sha256"]
        ):
            return False
        identities.add(path)
    return bool(identities)


def _canary_results_valid(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "positive_fixture_sha256",
        "negative_fixture_sha256",
        "positive_detected",
        "negative_clean",
        "cases",
    }:
        return False
    cases = value["cases"]
    if not isinstance(cases, list) or len(cases) < 4:
        return False
    identities: set[str] = set()
    families: set[str] = set()
    outcomes: set[bool] = set()
    for case in cases:
        if (
            not isinstance(case, dict)
            or set(case)
            != {
                "id",
                "rule_family",
                "fixture_sha256",
                "expected_detected",
                "detected",
            }
            or not str(case.get("id") or "")
            or case["id"] in identities
            or not str(case.get("rule_family") or "")
            or not _digest(str(case.get("fixture_sha256") or ""))
            or not isinstance(case.get("expected_detected"), bool)
            or case.get("detected") is not case.get("expected_detected")
        ):
            return False
        identities.add(case["id"])
        families.add(case["rule_family"])
        outcomes.add(case["expected_detected"])
    return bool(
        _digest(str(value["positive_fixture_sha256"]))
        and _digest(str(value["negative_fixture_sha256"]))
        and value["positive_detected"] is True
        and value["negative_clean"] is True
        and len(families) >= 2
        and outcomes == {False, True}
    )


def _verify_engine_operation(
    item: dict[str, Any], prefix: str, replay: dict[str, Any]
) -> None:
    artifact_sha256 = str(item[f"{prefix}_analysis_artifact_sha256"])
    subject = {
        "schema_version": "1.0",
        "language": item["language"],
        "engine": replay["engine"],
        "engine_sha256": replay["engine_sha256"],
        "configuration_sha256": replay["configuration_sha256"],
        "files_sha256": replay["files_sha256"],
        "analysis_artifact_sha256": artifact_sha256,
        "failure_domain": item[f"{prefix}_failure_domain"],
    }
    receipt = item[f"{prefix}_operation_receipt"]
    statement = receipt.get("statement") if isinstance(receipt, dict) else None
    if not isinstance(statement, dict):
        raise ValueError("compiler engine operation receipt is missing")
    try:
        observed_at = datetime.fromisoformat(
            str(statement["issued_at"]).replace("Z", "+00:00")
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("compiler engine operation time is invalid") from exc
    verify_operation_receipt(
        subject,
        receipt,
        purpose="compiler-semantic-engine-analysis",
        observed_at=observed_at,
        challenge_sha256=str(statement.get("challenge_sha256") or ""),
        expected_key_sha256=str(item[f"{prefix}_authority_key_sha256"]),
    )


def _verify_taint_paths(value: object, semantic_ledger: object) -> None:
    if not isinstance(value, list) or not isinstance(semantic_ledger, dict):
        raise ValueError("compiler taint paths are invalid")
    symbols = semantic_ledger.get("symbols")
    if not isinstance(symbols, list):
        raise ValueError("compiler taint path symbols are unavailable")
    identities = {str(item["id"]) for item in symbols if isinstance(item, dict)}
    edges = {
        (str(edge["source"]), str(edge["target"]))
        for name in ("cfg_edges", "dataflow_edges", "interprocedural_edges")
        for edge in semantic_ledger.get(name, [])
        if isinstance(edge, dict)
    }
    seen: set[str] = set()
    for path in value:
        if not isinstance(path, dict) or set(path) != {
            "id",
            "source",
            "sink",
            "path",
            "sanitizers",
            "barriers",
        }:
            raise ValueError("compiler taint path fields do not match")
        path_id = str(path["id"])
        nodes = path["path"]
        sanitizers = path["sanitizers"]
        barriers = path["barriers"]
        if (
            not path_id
            or path_id in seen
            or not isinstance(nodes, list)
            or len(nodes) < 2
            or path["source"] != nodes[0]
            or path["sink"] != nodes[-1]
            or any(node not in identities for node in nodes)
            or not isinstance(sanitizers, list)
            or not isinstance(barriers, list)
            or any(node not in nodes for node in [*sanitizers, *barriers])
            or len(set(nodes)) != len(nodes)
            or any(
                (str(source), str(target)) not in edges
                for source, target in pairwise(nodes)
            )
        ):
            raise ValueError("compiler taint path is invalid")
        seen.add(path_id)


def _verify_semantic_ledger(
    value: object,
    file_set: dict[str, Any],
    *,
    expected_counts: dict[str, int],
) -> None:
    if not isinstance(value, dict) or set(value) != {
        "symbols",
        "cfg_edges",
        "dataflow_edges",
        "interprocedural_edges",
    }:
        raise ValueError("compiler semantic ledger fields do not match")
    files = {str(item["path"]) for item in file_set["files"]}
    symbols = value["symbols"]
    if not isinstance(symbols, list) or len(symbols) != expected_counts["symbols"]:
        raise ValueError("compiler semantic symbol ledger does not match")
    identities: set[str] = set()
    for symbol in symbols:
        if (
            not isinstance(symbol, dict)
            or set(symbol)
            != {
                "id",
                "path",
                "start_line",
                "start_column",
                "end_line",
                "end_column",
                "kind",
                "qualified_name",
                "signature",
                "language",
            }
            or not str(symbol["id"])
            or symbol["id"] in identities
            or symbol["path"] not in files
            or any(
                isinstance(symbol[name], bool) or not isinstance(symbol[name], int)
                for name in ("start_line", "start_column", "end_line", "end_column")
            )
            or symbol["start_line"] < 1
            or symbol["start_column"] < 0
            or symbol["end_line"] < symbol["start_line"]
            or symbol["end_column"] < 0
            or (
                symbol["end_line"] == symbol["start_line"]
                and symbol["end_column"] < symbol["start_column"]
            )
            or any(
                not isinstance(symbol[name], str)
                or not symbol[name]
                or len(symbol[name]) > 500
                for name in ("kind", "qualified_name", "signature", "language")
            )
        ):
            raise ValueError("compiler semantic symbol is invalid")
        identities.add(str(symbol["id"]))
    for name in ("cfg_edges", "dataflow_edges", "interprocedural_edges"):
        edges = value[name]
        if not isinstance(edges, list) or len(edges) != expected_counts[name]:
            raise ValueError("compiler semantic edge ledger does not match")
        canonical: set[bytes] = set()
        for edge in edges:
            if (
                not isinstance(edge, dict)
                or set(edge)
                != {
                    "source",
                    "target",
                    "kind",
                    "callsite_path",
                    "callsite_line",
                    "callsite_column",
                    "context",
                }
                or edge["source"] not in identities
                or edge["target"] not in identities
                or edge["callsite_path"] not in files
                or isinstance(edge["callsite_line"], bool)
                or not isinstance(edge["callsite_line"], int)
                or edge["callsite_line"] < 1
                or isinstance(edge["callsite_column"], bool)
                or not isinstance(edge["callsite_column"], int)
                or edge["callsite_column"] < 0
                or not isinstance(edge["kind"], str)
                or not edge["kind"]
                or not isinstance(edge["context"], str)
                or not edge["context"]
                or canonical_bytes(edge) in canonical
            ):
                raise ValueError("compiler semantic edge is invalid")
            canonical.add(canonical_bytes(edge))


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
    """Parse one non-Python file behind a resource-contained native boundary."""

    worker = Path(__file__).with_name("polyglot_parser_worker.py")
    with _parser_snapshot(payload, Path(source).suffix) as snapshot:
        result = run_command(
            [sys.executable, "-I", str(worker), str(snapshot), source, language],
            cwd=snapshot.parent,
            timeout_seconds=15,
            max_output_bytes=4 * 1024 * 1024,
            environment=_parser_environment(),
        )
    if (
        result.exit_code != 0
        or result.timed_out
        or result.output_limit_exceeded
        or result.scratch_limit_exceeded
        or result.resident_memory_limit_exceeded
        or result.resource_limit_errors
    ):
        return [], f"tree-sitter-{language}-worker-failed"
    try:
        value = strict_json_loads(result.stdout)
    except (UnicodeError, json.JSONDecodeError):
        return [], f"tree-sitter-{language}-worker-output-invalid"
    if (
        not isinstance(value, dict)
        or set(value) != {"edges", "error"}
        or not isinstance(value["edges"], list)
        or len(value["edges"]) > 100_000
        or (value["error"] is not None and not isinstance(value["error"], str))
    ):
        return [], f"tree-sitter-{language}-worker-output-invalid"
    edges: list[dict[str, Any]] = []
    for item in value["edges"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"source", "line", "kind", "target", "language"}
            or item["source"] != source
            or item["language"] != language
            or isinstance(item["line"], bool)
            or not isinstance(item["line"], int)
            or not all(isinstance(item[key], str) for key in ("kind", "target"))
        ):
            return [], f"tree-sitter-{language}-worker-output-invalid"
        edges.append(
            _edge(
                source,
                item["line"],
                item["kind"],
                item["target"],
                language,
            )
        )
    return edges, value["error"]


def _analyze_special_surface(
    payload: bytes, source: str, kind: str, path: Path
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if kind == "notebook":
        value = strict_json_loads(payload.decode("utf-8"))
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
        worker = Path(__file__).with_name("bytecode_parser_worker.py")
        with _parser_snapshot(payload, path.suffix) as snapshot:
            result = run_command(
                [
                    sys.executable,
                    "-I",
                    str(worker),
                    str(snapshot),
                ],
                cwd=snapshot.parent,
                timeout_seconds=10,
                max_output_bytes=1024 * 1024,
                environment=_parser_environment(),
            )
        if (
            result.exit_code != 0
            or result.timed_out
            or result.output_limit_exceeded
            or result.scratch_limit_exceeded
            or result.resident_memory_limit_exceeded
            or result.resource_limit_errors
        ):
            raise ValueError("Python bytecode semantic disassembly failed")
        decoded = strict_json_loads(result.stdout)
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
    with _parser_snapshot(payload, path.suffix) as snapshot:
        result = run_command(
            [sys.executable, "-I", str(worker), str(snapshot)],
            cwd=snapshot.parent,
            timeout_seconds=15,
            max_output_bytes=4 * 1024 * 1024,
            environment=_parser_environment(),
        )
    if (
        result.exit_code != 0
        or result.timed_out
        or result.output_limit_exceeded
        or result.scratch_limit_exceeded
        or result.resident_memory_limit_exceeded
        or result.resource_limit_errors
    ):
        raise ValueError("resource-contained native binary parsing failed")
    value = strict_json_loads(result.stdout)
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
        return CommandEnvironment(
            max_scratch_bytes=16 * 1024 * 1024,
            max_resident_memory_bytes=256 * 1024 * 1024,
        )
    try:
        prefix = strict_json_loads(raw_prefix)
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
        max_resident_memory_bytes=256 * 1024 * 1024,
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
    # Some tree-sitter wheels expose integer/string-compatible extension values
    # whose CPython type metadata is not safe to retain beyond the native parse
    # tree. Materialize exact builtins before the tree is released or values are
    # hashed during graph deduplication.
    normalized_source = str(source)
    normalized_line = int(line)
    normalized_kind = str(kind)
    normalized_target = str(target)
    normalized_language = str(language)
    if not normalized_source or normalized_line < 1 or not normalized_kind:
        raise ValueError("boundary edge identity is invalid")
    return {
        "source": normalized_source,
        "line": normalized_line,
        "kind": normalized_kind,
        "target": normalized_target[:500],
        "language": normalized_language,
    }


def _http_origin(value: str) -> str | None:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{parsed.hostname}{port}"
