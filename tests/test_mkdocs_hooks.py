from __future__ import annotations

from types import SimpleNamespace

from scripts.mkdocs_hooks import on_page_markdown


def test_pages_hook_rewrites_only_links_outside_docs() -> None:
    page = SimpleNamespace(file=SimpleNamespace(src_uri="guides/example.md"))
    markdown = (
        "[Schema](../../src/package/schema.json#record) "
        "[Sibling](../operations.md) "
        "[Web](https://example.com)"
    )

    rendered = on_page_markdown(
        markdown,
        page=page,
        config=None,
        files=None,
    )

    assert (
        "[Schema](https://github.com/willtran87/project-py-security-suite/"
        "blob/main/src/package/schema.json#record)"
    ) in rendered
    assert "[Sibling](../operations.md)" in rendered
    assert "[Web](https://example.com)" in rendered
