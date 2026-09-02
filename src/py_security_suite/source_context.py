from __future__ import annotations

import re
from pathlib import Path

from .models import Finding, Location


_SECRET_AREAS = {"secrets", "secrets-history"}
_SECRET_TOOLS = {"detect-secrets", "gitleaks", "trufflehog"}
_REDACTED_SOURCE = "<redacted: secret-bearing source is not embedded in reports>"
_REDACTED_SCANNER_TEXT = "<redacted: sensitive scanner text is not retained>"
_REDACTED_VALUE = "<redacted>"
_SECRET_TITLE = "Redacted credential candidate"  # pragma: allowlist secret
_SECRET_IMPACT = (
    "A real credential could permit unauthorized access."  # pragma: allowlist secret
)
_SECRET_REMEDIATION = (
    "Validate in the protected workspace without copying the value; revoke, rotate, "
    "and remove it from maintained source and applicable history if it is real."
)
_SECRET_NAME = (
    r"(?:password|passwd|secret|token|credential|api[_-]?key|access[_-]?key|"
    r"private[_-]?key)"
)
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
_AUTHORIZATION_VALUE = re.compile(
    r"(?i)\b(?P<prefix>(?:proxy-)?authorization\s*[:=]\s*(?:bearer|basic)?\s*)"
    r"[^\s,;]+"
)
_URI_USERINFO = re.compile(r"(?i)(?P<scheme>[a-z][a-z0-9+.-]*://)[^/@\s]+@")
_JWT_VALUE = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."
    r"[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)
_KNOWN_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"(?:AKIA|ASIA)[A-Z0-9]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|sk_(?:live|test)_[A-Za-z0-9]{16,}"
    r")(?![A-Za-z0-9])"
)
_PRIVATE_KEY_MARKER = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", re.IGNORECASE
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


def sanitize_secret_findings(findings: list[Finding]) -> None:
    """Discard scanner-controlled secret text before correlation or persistence."""
    for finding in findings:
        if not _is_secret_finding(finding):
            continue
        finding.title = _SECRET_TITLE
        finding.description = _REDACTED_SCANNER_TEXT
        finding.impact = _SECRET_IMPACT
        finding.remediation = _SECRET_REMEDIATION
        for source in finding.sources:
            source.rule_id = f"{source.tool}.redacted-candidate"
            source.message = _REDACTED_SCANNER_TEXT
        safe_citations = []
        for citation in finding.citations:
            match = re.fullmatch(r"CWE-(\d+)", citation.identifier, re.IGNORECASE)
            if citation.kind != "taxonomy" or match is None:
                continue
            identifier = f"CWE-{match.group(1)}"
            citation.identifier = identifier
            citation.title = f"{identifier} security classification"
            citation.uri = (
                f"https://cwe.mitre.org/data/definitions/{match.group(1)}.html"
            )
            safe_citations.append(citation)
        finding.citations = safe_citations
        finding.evidence = _safe_secret_evidence(finding.evidence)
        for location in finding.locations:
            location.snippet = _REDACTED_SOURCE
            location.snippet_start_line = location.start_line
            location.snippet_redacted = True


def _safe_secret_evidence(evidence: dict[str, object]) -> dict[str, object]:
    safe: dict[str, object] = {"redacted": True}
    for key in ("verified", "verification_enabled"):
        if isinstance(evidence.get(key), bool):
            safe[key] = evidence[key]
    scan_mode = evidence.get("scan_mode")
    if scan_mode in {"dir", "git"}:
        safe["scan_mode"] = scan_mode
    commit = evidence.get("commit")
    if isinstance(commit, str) and re.fullmatch(r"[0-9a-fA-F]{7,64}", commit):
        safe["commit"] = commit
    return safe


def redact_sensitive_text(value: str, *, secret_bearing: bool = False) -> str:
    """Remove concrete credentials from scanner-controlled report text."""
    if not value:
        return ""
    if secret_bearing or _PRIVATE_KEY_MARKER.search(value):
        return _REDACTED_SCANNER_TEXT
    redacted = _SECRET_ASSIGNMENT.sub(rf"\g<prefix>{_REDACTED_VALUE}", value)
    redacted = _AUTHORIZATION_VALUE.sub(rf"\g<prefix>{_REDACTED_VALUE}", redacted)
    redacted = _URI_USERINFO.sub(rf"\g<scheme>{_REDACTED_VALUE}@", redacted)
    redacted = _JWT_VALUE.sub(_REDACTED_VALUE, redacted)
    return _KNOWN_TOKEN.sub(_REDACTED_VALUE, redacted)


def is_secret_bearing_scan(*, area: str, tool_name: str) -> bool:
    """Return whether scanner-controlled text must be discarded fail closed."""
    return area.casefold() in _SECRET_AREAS or tool_name.casefold() in _SECRET_TOOLS


def _is_secret_finding(finding: Finding) -> bool:
    return finding.area.casefold() in _SECRET_AREAS or any(
        is_secret_bearing_scan(area=finding.area, tool_name=source.tool)
        for source in finding.sources
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
