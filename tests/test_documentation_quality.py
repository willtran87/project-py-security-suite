from __future__ import annotations

import re
import unittest
from pathlib import Path
from urllib.parse import unquote

_ROOT = Path(__file__).resolve().parents[1]
_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


class DocumentationQualityTests(unittest.TestCase):
    def test_local_markdown_links_resolve(self) -> None:
        failures: list[str] = []
        for document in _documents():
            text = document.read_text(encoding="utf-8")
            for raw_target in _LINK.findall(text):
                target = raw_target.strip().strip("<>").split("#", 1)[0]
                if (
                    not target
                    or "://" in target
                    or target.startswith(("mailto:", "data:"))
                ):
                    continue
                candidate = (document.parent / unquote(target)).resolve()
                if not candidate.exists():
                    failures.append(f"{document.relative_to(_ROOT)} -> {raw_target}")
        self.assertEqual(
            failures, [], "broken local Markdown links:\n" + "\n".join(failures)
        )

    def test_mermaid_fences_are_balanced_and_nonempty(self) -> None:
        failures: list[str] = []
        for document in _documents():
            text = document.read_text(encoding="utf-8")
            starts = [match.end() for match in re.finditer(r"```mermaid\s*\n", text)]
            for start in starts:
                end = text.find("```", start)
                if end < 0 or not text[start:end].strip():
                    failures.append(str(document.relative_to(_ROOT)))
        self.assertEqual(failures, [], "invalid Mermaid fences: " + ", ".join(failures))


def _documents() -> list[Path]:
    return sorted(
        [path for path in _ROOT.glob("*.md") if path.is_file()]
        + [path for path in (_ROOT / "docs").rglob("*.md") if path.is_file()]
    )
