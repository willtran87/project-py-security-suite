from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from typing import cast

from .artifact_contracts import (
    FrameworkCoverageArtifact,
    FrameworkImport,
    FrameworkModel,
    FrameworkRecord,
)
from .models import (
    Citation,
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
    ToolRun,
    ToolStatus,
    finding_identity,
)
from .path_safety import read_regular_file
from .strict_json import loads as strict_loads


_FRAMEWORKS = {
    "aiohttp": ("web-framework", "CWE-20"),
    "airflow": ("workflow-orchestration", "CWE-284"),
    "asyncpg": ("database-framework", "CWE-89"),
    "boto3": ("cloud-sdk", "CWE-918"),
    "celery": ("task-processing", "CWE-400"),
    "django": ("web-framework", "CWE-20"),
    "fastapi": ("web-framework", "CWE-20"),
    "flask": ("web-framework", "CWE-20"),
    "graphql": ("api-framework", "CWE-285"),
    "grpc": ("rpc-framework", "CWE-285"),
    "jinja2": ("template-engine", "CWE-79"),
    "litestar": ("web-framework", "CWE-20"),
    "psycopg": ("database-framework", "CWE-89"),
    "psycopg2": ("database-framework", "CWE-89"),
    "redis": ("data-store", "CWE-400"),
    "rest_framework": ("api-framework", "CWE-285"),
    "sqlalchemy": ("database-framework", "CWE-89"),
    "starlette": ("web-framework", "CWE-20"),
    "tornado": ("web-framework", "CWE-20"),
}
_ENGINES = frozenset({"codeql", "pysa", "semgrep"})
_MAX_FILES = 50_000
_SKIP = frozenset(
    {
        ".artifacts",
        ".git",
        ".pysec-tools",
        ".venv",
        "build",
        "dist",
        "node_modules",
        "tests",
    }
)
_CANARY_ROOT = ("security", "framework-canaries")


def framework_model_coverage(
    target: Path, tool_runs: list[ToolRun], scanner_findings: list[Finding]
) -> tuple[list[Finding], FrameworkCoverageArtifact]:
    observations, parse_errors, parse_errors_omitted = _discover_frameworks(target)
    completed = {run.tool for run in tool_runs if run.status is ToolStatus.COMPLETED}
    models, manifest_errors, manifest_present = _load_models(target)
    records: list[FrameworkRecord] = []
    gap_findings: list[Finding] = []
    qualified_bindings: set[tuple[str, str, str]] = set()
    for framework, locations in sorted(observations.items()):
        candidates = [item for item in models if item["framework"] == framework]
        for item in candidates:
            item.update(_canary_outcomes(item, scanner_findings))
        qualified = [
            item
            for item in candidates
            if item["verified"]
            and item["engine"] in completed
            and item["canary_execution_verified"]
        ]
        for item in qualified:
            qualified_bindings.update(
                (str(item["engine"]), rule_id, str(item["positive_canary_path"]))
                for rule_id in item["expected_rule_ids"]
            )
        engines = sorted({str(item["engine"]) for item in qualified})
        gaps: list[str] = []
        if not candidates:
            gaps.append("no source-bound model and canary declaration")
        elif not any(item["verified"] for item in candidates):
            gaps.append("declared model or canary digest verification failed")
        elif not any(item["canary_execution_verified"] for item in candidates):
            gaps.append(
                "positive/negative canary outcomes were not observed for bound rule IDs"
            )
        if candidates and not engines:
            gaps.append("no declared model engine completed this scan")
        complete = bool(engines) and not gaps
        record = FrameworkRecord(
            framework=framework,
            category=_FRAMEWORKS[framework][0],
            imports=locations,
            declared_models=candidates,
            completed_model_engines=engines,
            complete=complete,
            gaps=gaps,
        )
        records.append(record)
        if not complete:
            gap_findings.append(_model_gap_finding(record))
    complete = (
        not parse_errors
        and not manifest_errors
        and all(record["complete"] for record in records)
    )
    qualified_canary_finding_ids = sorted(
        finding.finding_id
        for finding in scanner_findings
        if _is_qualified_canary_finding(finding, qualified_bindings)
    )
    return gap_findings, FrameworkCoverageArtifact(
        schema_version="1.0",
        analysis="framework-specific-semantic-model-coverage",
        manifest_path=".pysec-models.json" if manifest_present else None,
        manifest_present=manifest_present,
        frameworks_detected=len(records),
        frameworks_modeled=sum(record["complete"] for record in records),
        complete=complete,
        frameworks=records,
        parse_errors=parse_errors,
        parse_errors_omitted=parse_errors_omitted,
        manifest_errors=manifest_errors,
        qualified_canary_finding_ids=qualified_canary_finding_ids,
        claim_boundary=(
            "A complete record proves that a digest-bound model was declared, its engine "
            "completed, every expected rule matched the positive canary, and no expected "
            "rule matched the negative canary. It does not prove that every application "
            "wrapper or runtime dispatch path is modeled."
        ),
    )


def _is_qualified_canary_finding(
    finding: Finding, bindings: set[tuple[str, str, str]]
) -> bool:
    if not finding.sources or not finding.locations:
        return False
    paths = {location.path for location in finding.locations}
    if len(paths) != 1:
        return False
    path = next(iter(paths))
    return all(
        (source.tool, source.rule_id, path) in bindings for source in finding.sources
    )


def _discover_frameworks(
    target: Path,
) -> tuple[dict[str, list[FrameworkImport]], list[str], int]:
    observations: dict[str, list[FrameworkImport]] = {}
    errors: list[str] = []
    files_analyzed = 0
    for path in sorted(target.rglob("*.py")):
        relative = path.relative_to(target)
        if (
            any(part in _SKIP for part in relative.parts)
            or relative.parts[: len(_CANARY_ROOT)] == _CANARY_ROOT
        ):
            continue
        if files_analyzed >= _MAX_FILES:
            errors.append(f"framework discovery exceeded {_MAX_FILES} Python files")
            break
        files_analyzed += 1
        try:
            _, payload = read_regular_file(
                path,
                "framework coverage source",
                maximum_bytes=4 * 1024 * 1024,
                boundary=target,
            )
            tree = ast.parse(payload, filename=relative.as_posix())
        except (OSError, SyntaxError, UnicodeError, ValueError) as exc:
            errors.append(f"{relative.as_posix()}: {type(exc).__name__}")
            continue
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name.split(".", 1)[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".", 1)[0]]
            for name in names:
                if name not in _FRAMEWORKS:
                    continue
                item = FrameworkImport(
                    path=relative.as_posix(),
                    line=int(getattr(node, "lineno", 1)),
                )
                bucket = observations.setdefault(name, [])
                if item not in bucket and len(bucket) < 100:
                    bucket.append(item)
    return observations, errors[:100], max(0, len(errors) - 100)


def _load_models(
    target: Path,
) -> tuple[list[FrameworkModel], list[str], bool]:
    path = target / ".pysec-models.json"
    if not path.is_file():
        return [], [], False
    errors: list[str] = []
    try:
        _, payload = read_regular_file(
            path, "framework model manifest", maximum_bytes=1024 * 1024, boundary=target
        )
        document = strict_loads(payload)
    except (OSError, TypeError, ValueError) as exc:
        return [], [f"manifest could not be read: {type(exc).__name__}"], True
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "models"}
        or document.get("schema_version") not in {"1.0", "1.1"}
        or not isinstance(document.get("models"), list)
        or len(document["models"]) > 1000
    ):
        return [], ["manifest fields do not match schema 1.0"], True
    models: list[FrameworkModel] = []
    identities: set[tuple[str, str, str]] = set()
    base_required = {
        "framework",
        "engine",
        "model_path",
        "model_sha256",
        "positive_canary_path",
        "positive_canary_sha256",
        "negative_canary_path",
        "negative_canary_sha256",
    }
    manifest_version = str(document["schema_version"])
    required = base_required | (
        {"expected_rule_ids"} if manifest_version == "1.1" else set()
    )
    for index, raw in enumerate(document["models"]):
        if not isinstance(raw, dict) or set(raw) != required:
            errors.append(f"model {index} fields do not match")
            continue
        framework = str(raw["framework"]).casefold()
        engine = str(raw["engine"]).casefold()
        expected_rule_ids = raw.get("expected_rule_ids", [])
        identity = (framework, engine, str(raw["model_path"]))
        if (
            framework not in _FRAMEWORKS
            or engine not in _ENGINES
            or identity in identities
            or not isinstance(expected_rule_ids, list)
            or len(expected_rule_ids) > 100
            or any(
                not isinstance(value, str) or not value.strip()
                for value in expected_rule_ids
            )
            or len(set(expected_rule_ids)) != len(expected_rule_ids)
        ):
            errors.append(f"model {index} identity is invalid or duplicated")
            continue
        identities.add(identity)
        verified = all(
            _verify_subject(target, str(raw[path_key]), str(raw[digest_key]))
            for path_key, digest_key in (
                ("model_path", "model_sha256"),
                ("positive_canary_path", "positive_canary_sha256"),
                ("negative_canary_path", "negative_canary_sha256"),
            )
        )
        models.append(
            FrameworkModel(
                framework=framework,
                engine=engine,
                model_path=str(raw["model_path"]),
                model_sha256=str(raw["model_sha256"]).casefold(),
                positive_canary_path=str(raw["positive_canary_path"]),
                positive_canary_sha256=str(raw["positive_canary_sha256"]).casefold(),
                negative_canary_path=str(raw["negative_canary_path"]),
                negative_canary_sha256=str(raw["negative_canary_sha256"]).casefold(),
                expected_rule_ids=sorted(cast(list[str], expected_rule_ids)),
                verified=verified,
                canary_execution_verified=False,
                positive_matches=[],
                negative_matches=[],
            )
        )
    return models, errors[:100], True


def _canary_outcomes(model: FrameworkModel, findings: list[Finding]) -> FrameworkModel:
    engine = str(model["engine"])
    expected = {str(value) for value in model.get("expected_rule_ids", [])}
    positive_path = str(model["positive_canary_path"])
    negative_path = str(model["negative_canary_path"])
    positive = sorted(
        {
            source.rule_id
            for finding in findings
            if any(location.path == positive_path for location in finding.locations)
            for source in finding.sources
            if source.tool == engine and source.rule_id in expected
        }
    )
    negative = sorted(
        {
            source.rule_id
            for finding in findings
            if any(location.path == negative_path for location in finding.locations)
            for source in finding.sources
            if source.tool == engine and source.rule_id in expected
        }
    )
    updated = dict(model)
    updated.update(
        positive_matches=positive,
        negative_matches=negative,
        canary_execution_verified=bool(expected)
        and set(positive) == expected
        and not negative,
    )
    return cast(FrameworkModel, updated)


def _verify_subject(target: Path, relative: str, expected: str) -> bool:
    candidate = Path(relative.replace("\\", "/"))
    if (
        not candidate.parts
        or candidate.is_absolute()
        or ".." in candidate.parts
        or len(expected) != 64
        or any(character not in "0123456789abcdef" for character in expected.casefold())
    ):
        return False
    try:
        _, payload = read_regular_file(
            target / candidate,
            "framework model subject",
            maximum_bytes=8 * 1024 * 1024,
            boundary=target,
        )
    except (OSError, ValueError):
        return False
    return hashlib.sha256(payload).hexdigest() == expected.casefold()


def _model_gap_finding(record: FrameworkRecord) -> Finding:
    first = record["imports"][0]
    framework = str(record["framework"])
    rule_id = f"FRAMEWORK-MODEL-{framework.upper().replace('_', '-')}"
    finding_id, fingerprint = finding_identity(
        tool="framework-model-coverage",
        rule_id=rule_id,
        path=str(first["path"]),
        start_line=int(first["line"]),
    )
    gaps = "; ".join(str(value) for value in record["gaps"])
    return Finding(
        finding_id=finding_id,
        fingerprint=fingerprint,
        title=f"Unverified semantic model coverage for {framework}",
        description=f"The project imports {framework}, but {gaps}.",
        impact=(
            "Sources, sinks, sanitizers, guards, callbacks, or dependency-injection "
            "paths supplied by the framework may be missed or misclassified."
        ),
        remediation=(
            "Add a digest-bound .pysec-models.json entry for an applicable CodeQL, "
            "Pysa, or Semgrep model with positive and negative canaries, then run that engine."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        area="analysis-coverage",
        domain="security",
        classifications=[rule_id, _FRAMEWORKS[framework][1]],
        locations=[Location(path=str(first["path"]), start_line=int(first["line"]))],
        sources=[
            Source(
                tool="framework-model-coverage",
                rule_id=rule_id,
                message=gaps,
                native_severity="coverage-gap",
            )
        ],
        citations=[
            Citation(
                kind="tool_rule",
                identifier=rule_id,
                title="CodeQL model packs",
                uri="https://docs.github.com/en/code-security/tutorials/customize-code-scanning/create-and-work-with-codeql-packs",
            )
        ],
        evidence={"framework_model_coverage": record},
    )
