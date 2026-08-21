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
  <script src="https://cdn.example/app.js" integrity="sha384-example" crossorigin="anonymous"></script>
</head>
<body>
  <a href="#start">Start</a>
  <h1 id="start">Documentation</h1>
  <table><thead><tr><th scope="col">Rule</th></tr></thead></table>
</body>
</html>
"""


def _write_required_site_files(root: Path) -> None:
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
    broken = _VALID_PAGE.replace(
        ' integrity="sha384-example" crossorigin="anonymous"', ""
    ).replace('<th scope="col">', "<th>")
    broken = broken.replace('href="#start"', 'href="missing/" target="_blank"')
    broken = broken.replace("</body>", '<a href="../outside.txt">Outside</a></body>')
    (tmp_path / "index.html").write_text(broken, encoding="utf-8")

    errors = audit_site(tmp_path)

    assert "index.html: third-party script lacks integrity" in errors
    assert "index.html: third-party script lacks anonymous CORS" in errors
    assert "index.html: table header is missing a valid scope" in errors
    assert "index.html: new-window link lacks noopener noreferrer" in errors
    assert "index.html: broken internal link 'missing/'" in errors
    assert "index.html: broken internal link '../outside.txt'" in errors
