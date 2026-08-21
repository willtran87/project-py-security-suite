from __future__ import annotations

from pathlib import Path

from scripts.audit_pages import audit_site

_VALID_PAGE = """<!doctype html>
<html lang="en">
<head>
  <title>Documentation</title>
  <meta name="description" content="Reference">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="strict-origin-when-cross-origin">
  <meta property="og:type" content="website">
  <meta property="og:site_name" content="Python Security Suite">
  <meta property="og:title" content="Documentation">
  <meta property="og:description" content="Reference">
  <meta property="og:url" content="https://willtran87.github.io/project-py-security-suite/">
  <link rel="canonical" href="https://willtran87.github.io/project-py-security-suite/">
  <script type="module" src="javascripts/mermaid-init.js"></script>
  <script defer src="assets/javascripts/bundle.1234.min.js"></script>
</head>
<body>
  <div role="dialog" aria-label="Search documentation"></div>
  <a href="#start">Start</a>
  <h1 id="start">Documentation</h1>
  <pre class="pysec-mermaid">flowchart LR</pre>
  <table><thead><tr><th scope="col">Rule</th></tr></thead></table>
</body>
</html>
"""


def _write_required_site_files(root: Path) -> None:
    (root / "javascripts").mkdir()
    loader_source = Path("docs/javascripts/mermaid-init.js").read_text(encoding="utf-8")
    (root / "javascripts" / "mermaid-init.js").write_text(
        loader_source, encoding="utf-8"
    )
    (root / "index.html").write_text(_VALID_PAGE, encoding="utf-8")
    (root / "404.html").write_text(_VALID_PAGE, encoding="utf-8")
    (root / "robots.txt").write_text("User-agent: *\n", encoding="utf-8")
    (root / "sitemap.xml").write_text("<urlset/>\n", encoding="utf-8")


def test_pages_audit_accepts_complete_site(tmp_path: Path) -> None:
    _write_required_site_files(tmp_path)

    assert audit_site(tmp_path) == []


def test_pages_audit_reports_security_accessibility_and_link_defects(
    tmp_path: Path,
) -> None:
    _write_required_site_files(tmp_path)
    loader_path = tmp_path / "javascripts" / "mermaid-init.js"
    loader_path.write_text(
        loader_path.read_text(encoding="utf-8").replace(
            "sha384-o+g/BxPwhi0C3RK7oQBxQuNimeafQ3GE/ST4iT2BxVI4Wzt60SH4pq9iXVYujjaS",
            "sha384-invalid",
        ),
        encoding="utf-8",
    )
    broken = _VALID_PAGE.replace('<th scope="col">', "<th>")
    broken = broken.replace('href="#start"', 'href="missing/" target="_blank"')
    broken = broken.replace(' aria-label="Search documentation"', "")
    broken = broken.replace("</body>", '<a data-md-component="source"></a></body>')
    broken = broken.replace("</body>", '<a href="../outside.txt">Outside</a></body>')
    (tmp_path / "index.html").write_text(broken, encoding="utf-8")

    errors = audit_site(tmp_path)

    assert "site: Mermaid loader does not match its reviewed source" in errors
    assert "index.html: table header is missing a valid scope" in errors
    assert "index.html: dialog is missing an accessible name" in errors
    assert "index.html: new-window link lacks noopener noreferrer" in errors
    assert "index.html: repository link enables remote API probes" in errors
    assert "index.html: broken internal link 'missing/'" in errors
    assert "index.html: broken internal link '../outside.txt'" in errors
