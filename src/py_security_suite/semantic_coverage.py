from __future__ import annotations

import hashlib
from itertools import combinations
from typing import Any

from .version import __version__
from .strict_json import canonical_bytes


_PYTHON_QUERY_PACK_SHA256 = hashlib.sha256(
    b"py-security-suite:python-ast-semantic-analysis:1.0"
).hexdigest()


def semantic_language_coverage_artifact(
    boundary_graph: dict[str, Any], derived_artifacts: dict[str, Any]
) -> dict[str, Any]:
    """Bind each discovered language to native or authenticated semantic evidence."""
    discovered = {
        str(language).casefold(): int(count)
        for language, count in (boundary_graph.get("languages") or {}).items()
    }
    languages = sorted(discovered)
    raw_file_sets = boundary_graph.get("language_file_sets")
    file_sets = raw_file_sets if isinstance(raw_file_sets, dict) else {}
    polyglot = derived_artifacts.get("polyglot-summary.json")
    execution = polyglot.get("execution") if isinstance(polyglot, dict) else None
    binding = polyglot.get("evidence_binding") if isinstance(polyglot, dict) else None
    features = (
        set(execution.get("features") or []) if isinstance(execution, dict) else set()
    )
    external_authenticated = bool(
        isinstance(polyglot, dict)
        and polyglot.get("schema_version") == "2.0"
        and isinstance(binding, dict)
        and binding.get("verified") is True
        and binding.get("authenticated") is True
        and isinstance(execution, dict)
        and execution.get("status") == "completed"
        and execution.get("coverage_percent") == 100.0
        and not execution.get("skipped_checks")
        and {"semantic-dataflow", "language-matrix"}.issubset(features)
    )
    raw_matrix = (
        execution.get("language_matrix") if isinstance(execution, dict) else None
    )
    matrix = raw_matrix if isinstance(raw_matrix, list) else []
    matrix_by_language = {
        str(item.get("language", "")).casefold(): item
        for item in matrix
        if isinstance(item, dict)
    }
    raw_cross = (
        execution.get("cross_language_matrix") if isinstance(execution, dict) else None
    )
    cross_matrix = raw_cross if isinstance(raw_cross, list) else []
    cross_by_pair = {
        tuple(
            sorted(str(language).casefold() for language in item.get("languages", []))
        ): item
        for item in cross_matrix
        if isinstance(item, dict) and isinstance(item.get("languages"), list)
    }
    coverage: list[dict[str, Any]] = []
    for language in languages:
        native = language == "python"
        row = matrix_by_language.get(language) if external_authenticated else None
        expected_set = file_sets.get(language)
        expected_files = (
            expected_set.get("files") if isinstance(expected_set, dict) else None
        )
        expected_digest = (
            str(expected_set.get("files_sha256") or "")
            if isinstance(expected_set, dict)
            else ""
        )
        exclusions = row.get("exclusions") if isinstance(row, dict) else []
        reported_files = row.get("files") if isinstance(row, dict) else None
        row_complete = bool(
            isinstance(row, dict)
            and row.get("files_discovered") == discovered[language]
            and row.get("files_analyzed") == discovered[language]
            and exclusions == []
            and expected_files is not None
            and reported_files == expected_files
            and row.get("source_files_sha256") == expected_digest
            and "semantic-dataflow" in (row.get("analysis_modes") or [])
        )
        compiler_frontend = _compiler_frontend(boundary_graph, language)
        compiler_semantic = bool(compiler_frontend)
        semantic = row_complete or compiler_semantic
        coverage.append(
            {
                "language": language,
                "engine": (
                    str((compiler_frontend or {}).get("engine") or "")
                    if compiler_semantic
                    else str((row or {}).get("engine") or "")
                    if row_complete
                    else "python-ast-syntax"
                    if native
                    else ""
                ),
                "engine_version": (
                    str((compiler_frontend or {}).get("engine_version") or "")
                    if compiler_semantic
                    else str((row or {}).get("engine_version") or "")
                    if row_complete
                    else __version__
                    if native
                    else ""
                ),
                "query_pack_sha256": (
                    str((compiler_frontend or {}).get("query_pack_sha256") or "")
                    if compiler_semantic
                    else str((row or {}).get("query_pack_sha256") or "")
                    if row_complete
                    else _PYTHON_QUERY_PACK_SHA256
                    if native
                    else ""
                ),
                "source_files_sha256": (
                    expected_digest
                    if compiler_semantic or (native and not row_complete)
                    else str((row or {}).get("source_files_sha256") or "")
                ),
                "files_discovered": discovered[language],
                "files_analyzed": (
                    discovered[language]
                    if compiler_semantic or (native and not row_complete)
                    else int((row or {}).get("files_analyzed") or 0)
                ),
                "exclusions": []
                if compiler_semantic or (native and not row_complete)
                else list(exclusions or []),
                "files": list(expected_files or [])
                if compiler_semantic or (native and not row_complete)
                else list(reported_files or []),
                "analysis_modes": (
                    list((compiler_frontend or {}).get("analysis_modes") or [])
                    if compiler_semantic
                    else list((row or {}).get("analysis_modes") or [])
                    if row_complete
                    else ["syntax-ast", "control-flow", "call-graph"]
                    if native
                    else list((row or {}).get("analysis_modes") or [])
                ),
                "semantic": semantic,
                "source_bound": semantic,
                "cross_language_correlation": (
                    "compiler-ledger"
                    if compiler_semantic
                    else "normalized-finding-fusion"
                    if row_complete
                    else "syntax-graph-only"
                    if native
                    else "not-established"
                ),
            }
        )
    uncovered = sorted(item["language"] for item in coverage if not item["semantic"])
    cross_language_pairs: list[dict[str, Any]] = []
    graph_edges = boundary_graph.get("edges")
    edges = graph_edges if isinstance(graph_edges, list) else []
    path_languages = {
        str(file.get("path")): language
        for language, file_set in file_sets.items()
        if isinstance(file_set, dict)
        for file in (file_set.get("files") or [])
        if isinstance(file, dict)
    }
    path_records = {
        str(file.get("path")): {
            "language": language,
            "line_count": file.get("line_count"),
        }
        for language, file_set in file_sets.items()
        if isinstance(file_set, dict)
        for file in (file_set.get("files") or [])
        if isinstance(file, dict)
    }
    for left, right in combinations(languages, 2):
        pair = (left, right)
        row = cross_by_pair.get(pair) if external_authenticated else None
        row_record = row if isinstance(row, dict) else {}
        file_subject = {
            language: (file_sets.get(language) or {}).get("files") for language in pair
        }
        expected_pair_digest = hashlib.sha256(canonical_bytes(file_subject)).hexdigest()
        modes = row.get("analysis_modes") if isinstance(row, dict) else []
        boundaries_analyzed = (
            row.get("boundaries_analyzed") if isinstance(row, dict) else None
        )
        flows_found = row.get("flows_found") if isinstance(row, dict) else None
        boundaries = row.get("boundaries") if isinstance(row, dict) else None
        flows = row.get("flows") if isinstance(row, dict) else None
        engine = str(row.get("engine") or "") if isinstance(row, dict) else ""
        expected_boundaries = sorted(
            [
                {
                    "kind": str(edge.get("kind") or ""),
                    "language": path_languages.get(str(edge.get("source") or ""), ""),
                    "line": edge.get("line"),
                    "path": str(edge.get("source") or ""),
                    "target": str(edge.get("target") or ""),
                }
                for edge in edges
                if isinstance(edge, dict)
                and edge.get("kind") != "module-import"
                and path_languages.get(str(edge.get("source") or "")) in pair
            ],
            key=canonical_bytes,
        )
        source_bound_boundaries = bool(
            isinstance(boundaries, list)
            and all(_valid_boundary(item, pair, path_records) for item in boundaries)
        )
        source_bound_flows = bool(
            isinstance(flows, list)
            and all(_valid_cross_flow(item, pair, path_records) for item in flows)
        )
        independent = (
            row.get("independent_validation") if isinstance(row, dict) else None
        )
        independent_record = independent if isinstance(independent, dict) else {}
        independent_authority = independent_record.get("authority")
        independently_reproduced = bool(
            independent_record
            and set(independent_record)
            == {
                "engine",
                "query_pack_sha256",
                "boundaries_sha256",
                "flows_sha256",
                "authority",
            }
            and str(independent_record.get("engine") or "")
            and str(independent_record.get("engine") or "") != engine
            and independent_record.get("query_pack_sha256")
            != row_record.get("query_pack_sha256")
            and independent_record.get("boundaries_sha256")
            == row_record.get("boundaries_sha256")
            and independent_record.get("flows_sha256") == row_record.get("flows_sha256")
            and isinstance(independent_authority, dict)
            and independent_authority.get("validated") is True
            and int(independent_authority.get("minimum_signatures") or 0) >= 2
            and len(set(independent_authority.get("signers") or [])) >= 2
            and len(set(independent_authority.get("collectors") or [])) >= 2
            and len(set(independent_authority.get("organizations") or [])) >= 2
            and len(independent_authority.get("receipts") or [])
            >= int(independent_authority.get("minimum_signatures") or 0)
            and len(str(independent_authority.get("trusted_time_sha256") or "")) == 64
        )
        ledgers_valid = bool(
            isinstance(row, dict)
            and isinstance(boundaries, list)
            and isinstance(flows, list)
            and boundaries == sorted(boundaries, key=canonical_bytes)
            and flows == sorted(flows, key=canonical_bytes)
            and len(boundaries) == boundaries_analyzed
            and len(flows) == flows_found
            and row.get("boundaries_sha256")
            == hashlib.sha256(canonical_bytes(boundaries)).hexdigest()
            and row.get("flows_sha256")
            == hashlib.sha256(canonical_bytes(flows)).hexdigest()
            and all(item in boundaries for item in expected_boundaries)
            and source_bound_boundaries
            and source_bound_flows
            and independently_reproduced
        )
        complete = bool(
            isinstance(row, dict)
            and row.get("source_file_sets_sha256") == expected_pair_digest
            and {"semantic-dataflow", "cross-language-boundary"}.issubset(modes or [])
            and not isinstance(boundaries_analyzed, bool)
            and isinstance(boundaries_analyzed, int)
            and boundaries_analyzed >= 0
            and not isinstance(flows_found, bool)
            and isinstance(flows_found, int)
            and flows_found >= 0
            and ledgers_valid
        )
        cross_language_pairs.append(
            {
                "languages": list(pair),
                "engine": str((row or {}).get("engine") or ""),
                "engine_version": str((row or {}).get("engine_version") or ""),
                "query_pack_sha256": str((row or {}).get("query_pack_sha256") or ""),
                "source_file_sets_sha256": (
                    str((row or {}).get("source_file_sets_sha256") or "")
                ),
                "boundaries_analyzed": int(boundaries_analyzed or 0),
                "flows_found": int(flows_found or 0),
                "boundaries_sha256": str((row or {}).get("boundaries_sha256") or ""),
                "flows_sha256": str((row or {}).get("flows_sha256") or ""),
                "independently_detected_boundaries": len(expected_boundaries),
                "boundary_ledger_complete": ledgers_valid,
                "source_locations_validated": source_bound_boundaries
                and source_bound_flows,
                "independently_reproduced": independently_reproduced,
                "analysis_modes": list(modes or []),
                "complete": complete,
            }
        )
    cross_language_complete = all(item["complete"] for item in cross_language_pairs)
    return {
        "schema_version": "1.0",
        "analysis": "source-bound-semantic-language-coverage",
        "languages": coverage,
        "polyglot_evidence_authenticated": external_authenticated,
        "uncovered_languages": uncovered,
        "cross_language_pairs": cross_language_pairs,
        "cross_language_complete": cross_language_complete,
        "limitations": [
            (
                "cross-language boundaries require authenticated contract-level semantic dataflow for every discovered language pair"
            )
        ],
        "complete": not uncovered and cross_language_complete,
    }


def _compiler_frontend(
    boundary_graph: dict[str, Any], language: str
) -> dict[str, Any] | None:
    evidence = boundary_graph.get("compiler_semantic_evidence")
    if boundary_graph.get("compiler_semantic_complete") is not True or not isinstance(
        evidence, dict
    ):
        return None
    frontends = evidence.get("frontends")
    if not isinstance(frontends, list):
        return None
    matches = [
        item
        for item in frontends
        if isinstance(item, dict)
        and str(item.get("language") or "").casefold() == language
        and "semantic-dataflow" in (item.get("analysis_modes") or [])
    ]
    return matches[0] if len(matches) == 1 else None


def _valid_boundary(
    value: object,
    pair: tuple[str, str],
    records: dict[str, dict[str, Any]],
) -> bool:
    if not isinstance(value, dict):
        return False
    path = str(value.get("path") or "")
    language = str(value.get("language") or "")
    line = value.get("line")
    record = records.get(path)
    return bool(
        record
        and language in pair
        and record.get("language") == language
        and not isinstance(line, bool)
        and isinstance(line, int)
        and 1 <= line <= int(record.get("line_count") or 0)
    )


def _valid_cross_flow(
    value: object,
    pair: tuple[str, str],
    records: dict[str, dict[str, Any]],
) -> bool:
    if not isinstance(value, dict):
        return False
    source_path = str(value.get("source_path") or "")
    sink_path = str(value.get("sink_path") or "")
    source_language = str(value.get("source_language") or "")
    sink_language = str(value.get("sink_language") or "")
    source_line = value.get("source_line")
    sink_line = value.get("sink_line")
    source = records.get(source_path)
    sink = records.get(sink_path)
    return bool(
        source
        and sink
        and source_language != sink_language
        and {source_language, sink_language} == set(pair)
        and source.get("language") == source_language
        and sink.get("language") == sink_language
        and not isinstance(source_line, bool)
        and isinstance(source_line, int)
        and 1 <= source_line <= int(source.get("line_count") or 0)
        and not isinstance(sink_line, bool)
        and isinstance(sink_line, int)
        and 1 <= sink_line <= int(sink.get("line_count") or 0)
    )
