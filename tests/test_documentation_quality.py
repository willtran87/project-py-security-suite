from __future__ import annotations

import re
import unittest
from pathlib import Path
from urllib.parse import unquote

from py_security_suite.config import PROFILE_TOOLS, SUPPORTED_TOOLS

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

    def test_documented_portfolio_count_matches_registry(self) -> None:
        expected = len(SUPPORTED_TOOLS)
        documents = (_ROOT / "README.md", _ROOT / "docs" / "design.md")
        for document in documents:
            text = document.read_text(encoding="utf-8")
            counts = {
                int(value) for value in re.findall(r"\b(\d+) governed adapters\b", text)
            }
            self.assertEqual(
                counts,
                {expected},
                f"{document.relative_to(_ROOT)} has a stale adapter count",
            )

    def test_documented_profile_snapshot_matches_configuration(self) -> None:
        index = (_ROOT / "docs" / "index.md").read_text(encoding="utf-8")
        self.assertIn(f"{len(PROFILE_TOOLS)} profiles", index)
        for profile in ("comprehensive", "release", "production", "audit"):
            self.assertIn(
                f"`{profile}`"
                if profile not in {"comprehensive", "release"}
                else profile,
                index,
            )
            self.assertIn(str(len(PROFILE_TOOLS[profile])), index)

    def test_new_contextual_artifacts_are_documented(self) -> None:
        readme = (_ROOT / "README.md").read_text(encoding="utf-8")
        accuracy = (_ROOT / "docs" / "analysis-accuracy.md").read_text(encoding="utf-8")
        for artifact in (
            "finding-validation.json",
            "framework-model-coverage.json",
            "application-contract-analysis.json",
            "capability-manifest.json",
            "code-health.json",
            "static-architecture.json",
            "architecture-history.json",
        ):
            self.assertIn(artifact, readme)
            self.assertIn(artifact, accuracy)

    def test_contextual_analysis_diagrams_cover_current_semantics(self) -> None:
        accuracy = (_ROOT / "docs" / "analysis-accuracy.md").read_text(encoding="utf-8")
        design = (_ROOT / "docs" / "design.md").read_text(encoding="utf-8")
        configuration = (_ROOT / "docs" / "configuration.md").read_text(
            encoding="utf-8"
        )
        for phrase in (
            "semantic anchor",
            "native flow sink",
            "Machine-actionable scenarios + argv-safe tasks",
            "architecture-policy.json",
            "tach.toml",
            "code-health-policy.json",
        ):
            self.assertIn(phrase, accuracy)
        for phrase in (
            "Consumer capability",
            "Authorization tasks",
            "Property tasks",
            "Ranked bounded detail",
            "Tach fallback policy",
            "Separate authorized execution lane",
        ):
            self.assertIn(phrase, design)
        self.assertIn("Conservative finding correlation", design)
        self.assertIn("static-architecture.json 1.4", configuration)
        self.assertIn("code-health.json 1.4", configuration)
        self.assertIn("typed/framework semantic graph", configuration)
        self.assertIn("root-cause review queue", design)

    def test_governed_effectiveness_examples_use_production_floors(self) -> None:
        documents = (
            _ROOT / "README.md",
            _ROOT / "docs" / "release-readiness.md",
        )
        for document in documents:
            text = document.read_text(encoding="utf-8")
            for expected in (
                "--minimum-effectiveness-labels 200",
                "--minimum-effectiveness-positive-labels 80",
                "--minimum-effectiveness-negative-labels 80",
                "--minimum-effectiveness-tools 3",
                "--minimum-effectiveness-labels-per-tool 20",
                "--required-effectiveness-tool codeql",
            ):
                self.assertIn(expected, text)


def _documents() -> list[Path]:
    return sorted(
        [path for path in _ROOT.glob("*.md") if path.is_file()]
        + [path for path in (_ROOT / "docs").rglob("*.md") if path.is_file()]
    )
