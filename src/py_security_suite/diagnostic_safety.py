from __future__ import annotations

import re


_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|private[_-]?key)"
    r"(\s*[=:]\s*)([^\s,;]+)"
)


def sanitize_diagnostic(value: str, *, maximum: int = 4096) -> str:
    """Redact secret assignments and bound multi-line diagnostic output."""

    cleaned = _CONTROL_CHARACTERS.sub("", value)
    cleaned = _SECRET_ASSIGNMENT.sub(r"\1\2<redacted>", cleaned)
    if len(cleaned) > maximum:
        cleaned = cleaned[:maximum] + "\n<truncated>"
    return cleaned.strip()


def sanitize_terminal_text(value: str, *, maximum: int = 4096) -> str:
    """Return one bounded, redacted string safe for an operator terminal."""

    redacted = _SECRET_ASSIGNMENT.sub(r"\1\2<redacted>", value)
    sanitized = "".join(
        character if character.isprintable() else "�" for character in redacted
    )
    if len(sanitized) <= maximum:
        return sanitized
    return sanitized[: maximum - 1] + "…"
