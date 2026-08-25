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
_TABLE_HEADER_WITHOUT_SCOPE = re.compile(r"<th(?![^>]*\bscope=)(?P<attrs>[^>]*)>")
_MATERIAL_BUNDLE_SCRIPT = re.compile(
    r'<script src="(?P<src>[^\"]*assets/javascripts/bundle\.[^\"]+\.min\.js)"></script>'
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


def on_page_content(
    html: str,
    *,
    page: Any,
    config: Any,
    files: Any,
) -> str:
    """Associate Markdown table headings with their data columns."""

    del page, config, files
    return _TABLE_HEADER_WITHOUT_SCOPE.sub(r'<th scope="col"\g<attrs>>', html)


def on_post_page(
    output: str,
    *,
    page: Any,
    config: Any,
) -> str:
    """Harden pinned-theme markup without copying entire upstream partials."""

    del page, config
    return _harden_theme_markup(output)


def on_post_template(
    output: str,
    *,
    template_name: str,
    config: Any,
) -> str:
    """Apply the page hardening to standalone theme templates such as 404."""

    del template_name, config
    return _harden_theme_markup(output)


def _harden_theme_markup(output: str) -> str:
    output = output.replace(
        '<div class="md-search" data-md-component="search" role="dialog">',
        '<div class="md-search" data-md-component="search" role="dialog" '
        'aria-label="Search documentation">',
    )
    output = output.replace(
        'class="md-source" data-md-component="source"',
        'class="md-source"',
    )
    return _MATERIAL_BUNDLE_SCRIPT.sub(
        r'<script defer src="\g<src>"></script>',
        output,
    )
