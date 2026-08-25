from __future__ import annotations

from types import SimpleNamespace

from scripts.mkdocs_hooks import (
    on_page_content,
    on_page_markdown,
    on_post_page,
    on_post_template,
)


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


def test_pages_hook_adds_table_header_scope_without_replacing_existing_scope() -> None:
    rendered = on_page_content(
        '<table><thead><tr><th>Rule</th><th scope="row">Value</th></tr></thead></table>',
        page=None,
        config=None,
        files=None,
    )

    assert '<th scope="col">Rule</th>' in rendered
    assert '<th scope="row">Value</th>' in rendered


def test_pages_hook_names_search_and_disables_remote_repository_probe() -> None:
    source = (
        '<div class="md-search" data-md-component="search" role="dialog">'
        '<a class="md-source" data-md-component="source">Repository</a>'
        '<script src="assets/javascripts/bundle.1234.min.js"></script>'
    )
    rendered = on_post_page(source, page=None, config=None)
    template_rendered = on_post_template(
        source,
        template_name="404.html",
        config=None,
    )

    assert 'role="dialog" aria-label="Search documentation"' in rendered
    assert 'class="md-source"' in rendered
    assert 'data-md-component="source"' not in rendered
    assert (
        '<script defer src="assets/javascripts/bundle.1234.min.js"></script>'
        in rendered
    )
    assert template_rendered == rendered
