"""Publication-only normalization for links outside the MkDocs source tree."""

from __future__ import annotations

import posixpath
import re
from typing import Any

_REPOSITORY_BLOB_ROOT = (
    "https://github.com/willtran87/project-py-security-suite/blob/main/"
)
_PARENT_RELATIVE_LINK = re.compile(
    r"(?P<prefix>!?\[[^\]]*\]\()"
    r"(?P<target>\.\./[^)\s]+)"
    r"(?P<suffix>\))"
)


def on_page_markdown(
    markdown: str,
    *,
    page: Any,
    config: Any,
    files: Any,
) -> str:
    """Point links outside ``docs/`` at the corresponding repository file."""

    del config, files
    source_directory = posixpath.dirname(page.file.src_uri)

    def replace(match: re.Match[str]) -> str:
        target = match.group("target")
        path, separator, fragment = target.partition("#")
        repository_path = posixpath.normpath(
            posixpath.join("docs", source_directory, path)
        )
        if repository_path == ".." or repository_path.startswith("../"):
            return match.group(0)
        if repository_path == "docs" or repository_path.startswith("docs/"):
            return match.group(0)
        published_target = f"{_REPOSITORY_BLOB_ROOT}{repository_path}"
        if separator:
            published_target = f"{published_target}#{fragment}"
        return f"{match.group('prefix')}{published_target}{match.group('suffix')}"

    return _PARENT_RELATIVE_LINK.sub(replace, markdown)
