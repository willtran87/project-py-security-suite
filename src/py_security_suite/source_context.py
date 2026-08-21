from __future__ import annotations

import re
from pathlib import Path

from .models import Finding, Location


_SECRET_TOOLS = {"detect-secrets", "gitleaks", "trufflehog"}
_REDACTED_SOURCE = "<redacted: secret-bearing source is not embedded in reports>"
_REDACTED_VALUE = "<redacted>"
_SECRET_NAME = r"(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)"
_SECRET_ASSIGNMENT = re.compile(
    rf"(?ix)"
    rf"(?P<prefix>"
    rf"(?:"
    rf"[\w.-]*{_SECRET_NAME}[\w.-]*"
    rf"|[\"'][^\"'\r\n]*{_SECRET_NAME}[^\"'\r\n]*[\"']\s*\]?"
    rf")"
    rf"\s*(?::|=(?!=))\s*"
    rf")"
    rf"(?P<value>"
    rf'"(?:\\.|[^"\\])*"'
    rf"|'(?:\\.|[^'\\])*'"
    rf"|[^#;,\r\n]*?\S(?=\s*(?:[#;,]|$))"
    rf")"
)
_LANGUAGES = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".dockerfile": "dockerfile",
    ".go": "go",
    ".html": "html",
    ".ini": "ini",
    ".js": "javascript",
    ".json": "json",
    ".md": "markdown",
    ".py": "python",
    ".rs": "rust",
    ".sh": "shell",
    ".toml": "toml",
    ".ts": "typescript",
    ".yaml": "yaml",
    ".yml": "yaml",
}


def attach_source_context(
    target: Path,
    findings: list[Finding],
    *,
    context_lines: int = 2,
    maximum_line_characters: int = 500,
) -> None:
    """Attach bounded, sanitized source excerpts without leaving the target."""
    resolved_target = target.resolve()
    for finding in findings:
        secret_finding = _is_secret_finding(finding)
        for location in finding.locations:
            if location.start_line is None or location.start_line < 1:
                continue
            source_path = _safe_source_path(resolved_target, location.path)
            if source_path is None:
                continue
            if secret_finding:
                location.snippet = _REDACTED_SOURCE
                location.snippet_start_line = location.start_line
                location.snippet_redacted = True
                continue
            excerpt = _read_excerpt(
                source_path,
                location,
                context_lines=context_lines,
                maximum_line_characters=maximum_line_characters,
            )
            if excerpt is not None:
                location.snippet, location.snippet_start_line = excerpt


def redact_sensitive_snippets(findings: list[Finding]) -> None:
    """Fail closed before persistence when a snippet is secret-bearing or redacted."""
    for finding in findings:
        secret_finding = _is_secret_finding(finding)
        for location in finding.locations:
            if location.snippet is None:
                continue
            if secret_finding or location.snippet_redacted:
                location.snippet = _REDACTED_SOURCE
                location.snippet_start_line = location.start_line
                location.snippet_redacted = True


def _is_secret_finding(finding: Finding) -> bool:
    return finding.area.casefold() in {"secrets", "secrets-history"} or any(
        source.tool.casefold() in _SECRET_TOOLS for source in finding.sources
    )


def source_language(path: str) -> str:
    candidate = Path(path)
    if candidate.name.casefold().startswith("dockerfile"):
        return "dockerfile"
    return _LANGUAGES.get(candidate.suffix.casefold(), "text")


def _safe_source_path(target: Path, relative: str) -> Path | None:
    candidate = Path(relative)
    if candidate.is_absolute():
        return None
    unresolved = target / candidate
    if unresolved.is_symlink():
        return None
    resolved = unresolved.resolve()
    try:
        resolved.relative_to(target)
    except ValueError:
        return None
    if not resolved.is_file():
        return None
    return resolved


def _read_excerpt(
    path: Path,
    location: Location,
    *,
    context_lines: int,
    maximum_line_characters: int,
) -> tuple[str, int] | None:
    start_line = location.start_line
    if start_line is None:
        return None
    end_line = max(start_line, location.end_line or start_line)
    excerpt_start = max(1, start_line - context_lines)
    excerpt_end = end_line + context_lines
    selected: list[str] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for number, value in enumerate(handle, start=1):
                if number > excerpt_end:
                    break
                if number >= excerpt_start:
                    line = value.rstrip("\r\n")
                    line = _SECRET_ASSIGNMENT.sub(rf"\g<prefix>{_REDACTED_VALUE}", line)
                    if len(line) > maximum_line_characters:
                        line = line[:maximum_line_characters] + "…"
                    selected.append(line)
    except OSError:
        return None
    if not selected or start_line >= excerpt_start + len(selected):
        return None
    return "\n".join(selected), excerpt_start
