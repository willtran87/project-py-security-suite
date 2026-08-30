from __future__ import annotations

import ast
import json
import re
import tomllib
from pathlib import Path

from .repository_file_policy import maintained_repository_files


_MAX_DESCRIPTOR_BYTES = 4 * 1024 * 1024
_IMPORT_SURFACES = {
    "web": {
        "aiohttp",
        "blacksheep",
        "bottle",
        "django",
        "falcon",
        "fastapi",
        "flask",
        "litestar",
        "ninja",
        "pyramid",
        "quart",
        "robyn",
        "sanic",
        "starlette",
        "tornado",
    },
    "event": {
        "aiokafka",
        "boto3",
        "celery",
        "confluent_kafka",
        "google.cloud.pubsub",
        "kafka",
        "nats",
        "pika",
        "pulsar",
        "redis",
        "rq",
    },
    "database": {
        "alembic",
        "asyncpg",
        "beanie",
        "django",
        "motor",
        "mysql",
        "peewee",
        "psycopg",
        "pymongo",
        "redis",
        "sqlalchemy",
        "sqlite3",
        "tortoise",
    },
    "ai": {
        "anthropic",
        "autogen",
        "crewai",
        "google.generativeai",
        "haystack",
        "langchain",
        "llama_index",
        "openai",
        "semantic_kernel",
        "transformers",
    },
}
_DEPENDENCY_ALIASES = {
    surface: {name.replace("_", "-").casefold() for name in values}
    for surface, values in _IMPORT_SURFACES.items()
}
_NON_PYTHON_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".dart",
    ".fs",
    ".go",
    ".groovy",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".kts",
    ".m",
    ".mm",
    ".php",
    ".rb",
    ".rs",
    ".scala",
    ".svelte",
    ".swift",
    ".ts",
    ".tsx",
    ".vb",
    ".vue",
}


def classify_repository_surfaces(target: Path) -> frozenset[str]:
    """Conservatively identify security-relevant repository runtime surfaces."""

    surfaces: set[str] = set()
    files = maintained_repository_files(target)
    for path in files:
        name = path.name.casefold()
        suffix = path.suffix.casefold()
        relative = path.relative_to(target).as_posix().casefold()
        if name in {
            "openapi.json",
            "openapi.yaml",
            "openapi.yml",
            "swagger.json",
            "swagger.yaml",
            "swagger.yml",
        }:
            surfaces.update({"web", "service", "authorization"})
        if name in {"asyncapi.json", "asyncapi.yaml", "asyncapi.yml"}:
            surfaces.update({"event", "service", "authorization"})
        if suffix == ".proto":
            surfaces.update({"protocol", "service", "authorization"})
        if _container_name(name) or _looks_like_kubernetes(path):
            surfaces.update({"container", "service"})
        if _cloud_name(name, suffix) or _looks_like_cloudformation(path):
            surfaces.update({"cloud", "service"})
        if _mobile_name(name, suffix, relative):
            surfaces.add("mobile")
        if suffix in _NON_PYTHON_SUFFIXES or name in _POLYGLOT_LOCKFILES:
            surfaces.add("polyglot")
        if suffix in {".sql"} or "migrations/" in relative:
            surfaces.add("database")
        if name == "pyproject.toml":
            _classify_pyproject(path, surfaces)
        elif _dependency_descriptor(name):
            _classify_dependency_text(path, surfaces)
        elif suffix == ".py":
            _classify_python_imports(path, surfaces)
    if "web" in surfaces:
        surfaces.update({"service", "authorization"})
    return frozenset(surfaces)


_POLYGLOT_LOCKFILES = {
    "cargo.lock",
    "composer.lock",
    "gemfile.lock",
    "go.sum",
    "gradle.lockfile",
    "npm-shrinkwrap.json",
    "package-lock.json",
    "packages.lock.json",
    "pnpm-lock.yaml",
    "pom.xml",
    "yarn.lock",
}


def _dependency_descriptor(name: str) -> bool:
    return name.startswith("requirements") or name in {
        "poetry.lock",
        "pdm.lock",
        "pipfile",
        "pipfile.lock",
        "uv.lock",
        "setup.cfg",
        "setup.py",
    }


def _container_name(name: str) -> bool:
    return (
        name == "containerfile"
        or name.startswith("containerfile.")
        or name == "dockerfile"
        or name.startswith("dockerfile.")
        or name.endswith(".dockerfile")
        or name
        in {
            "compose.yaml",
            "compose.yml",
            "docker-compose.yaml",
            "docker-compose.yml",
            "chart.yaml",
        }
    )


def _cloud_name(name: str, suffix: str) -> bool:
    return name in {
        "cdk.json",
        "pulumi.yaml",
        "pulumi.yml",
        "serverless.yaml",
        "serverless.yml",
        "template.yaml",
        "template.yml",
    } or suffix in {".bicep", ".tf", ".tfvars"}


def _mobile_name(name: str, suffix: str, relative: str) -> bool:
    return (
        name
        in {
            "androidmanifest.xml",
            "app.json",
            "info.plist",
            "podfile",
            "pubspec.yaml",
            "pubspec.yml",
        }
        or suffix in {".aab", ".apk", ".ipa", ".xcodeproj"}
        or relative.endswith("/build.gradle")
        or relative.endswith("/build.gradle.kts")
    )


def _bounded_text(path: Path) -> str:
    try:
        if path.stat().st_size > _MAX_DESCRIPTOR_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _classify_pyproject(path: Path, surfaces: set[str]) -> None:
    text = _bounded_text(path)
    if not text:
        return
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        _classify_dependency_blob(text, surfaces)
        return
    dependencies: list[str] = []

    def visit(value: object, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                normalized = str(child_key).casefold().replace("_", "-")
                if key in {
                    "dependencies",
                    "optional-dependencies",
                    "dependency-groups",
                }:
                    dependencies.append(normalized)
                visit(child, normalized)
        elif isinstance(value, list):
            for child in value:
                visit(child, key)
        elif isinstance(value, str) and key in {
            "dependencies",
            "optional-dependencies",
            "dependency-groups",
        }:
            dependencies.append(value)

    visit(document)
    _classify_dependency_blob("\n".join(dependencies), surfaces)


def _classify_dependency_text(path: Path, surfaces: set[str]) -> None:
    _classify_dependency_blob(_bounded_text(path), surfaces)


def _classify_dependency_blob(text: str, surfaces: set[str]) -> None:
    normalized = text.casefold().replace("_", "-")
    for surface, names in _DEPENDENCY_ALIASES.items():
        if any(
            re.search(rf"(?<![a-z0-9-]){re.escape(name)}(?![a-z0-9-])", normalized)
            for name in names
        ):
            surfaces.add(surface)


def _classify_python_imports(path: Path, surfaces: set[str]) -> None:
    text = _bounded_text(path)
    if not text:
        return
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.casefold() for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.casefold())
    for surface, names in _IMPORT_SURFACES.items():
        if any(
            any(value == name or value.startswith(name + ".") for name in names)
            for value in imports
        ):
            surfaces.add(surface)


def _looks_like_kubernetes(path: Path) -> bool:
    if path.suffix.casefold() not in {".yaml", ".yml"}:
        return False
    prefix = _bounded_text(path)[: 128 * 1024]
    return bool(
        re.search(r"(?m)^\s*apiVersion\s*:", prefix)
        and re.search(r"(?m)^\s*kind\s*:", prefix)
    )


def _looks_like_cloudformation(path: Path) -> bool:
    if path.suffix.casefold() not in {".json", ".yaml", ".yml"}:
        return False
    text = _bounded_text(path)[: 256 * 1024]
    if not text:
        return False
    if path.suffix.casefold() == ".json":
        try:
            value = json.loads(text)
        except (TypeError, ValueError):
            return False
        return isinstance(value, dict) and isinstance(value.get("Resources"), dict)
    return bool(
        re.search(r"(?m)^\s*(?:AWSTemplateFormatVersion|Transform)\s*:", text)
        or (
            re.search(r"(?m)^\s*Resources\s*:\s*$", text)
            and re.search(r"(?m)^\s+Type\s*:\s*AWS::", text)
        )
    )
