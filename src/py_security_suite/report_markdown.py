"""Markdown escaping shared by report renderers.

Report Markdown is published as GitHub job summaries and pull-request
comments, where most untrusted scanner text lands inside GFM table cells.
GFM splits table rows on every unescaped ``|`` before inline parsing, even
inside code spans, so both helpers escape it as ``\\|``. Outside a table a
backslash-escaped pipe still renders as a plain ``|`` in ordinary text.
"""


def _markdown_text(value: str) -> str:
    escaped = value.replace("\\", "\\\\")
    for character in ("`", "*", "_", "{", "}", "[", "]", "<", ">", "#", "|"):
        escaped = escaped.replace(character, f"\\{character}")
    return escaped.replace("\r", " ").replace("\n", " ")


def _markdown_code(value: str) -> str:
    return (
        value.replace("`", "'")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )
