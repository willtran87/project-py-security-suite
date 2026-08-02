from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import cast

try:
    from hypothesis import given, settings, strategies as st
    from hypothesis_jsonschema import from_schema
except ModuleNotFoundError as exc:  # pragma: no cover - minimal runtime lane
    raise unittest.SkipTest(
        "Hypothesis and hypothesis-jsonschema are installed by the locked dev group"
    ) from exc

from py_security_suite.evidence_ingest import _assurance_document
from py_security_suite.models import finding_identity, normalize_repo_path


_SEGMENTS = st.lists(
    st.text(
        alphabet=st.characters(
            whitelist_categories=("Ll", "Lu", "Nd"),
            whitelist_characters="-_",
        ),
        min_size=1,
        max_size=24,
    ),
    min_size=1,
    max_size=6,
)
_ASSURANCE_SCHEMA = json.loads(
    (
        Path(__file__).parents[1]
        / "docs"
        / "schemas"
        / "assurance-evidence.schema.json"
    ).read_text(encoding="utf-8")
)


class SecurityPropertyTests(unittest.TestCase):
    @settings(deadline=None)
    @given(from_schema(_ASSURANCE_SCHEMA))
    def test_schema_generated_assurance_evidence_is_accepted(
        self, document: dict[str, object]
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "yara.json"
            evidence.write_text(json.dumps(document), encoding="utf-8")
            normalized = _assurance_document(evidence, "yara")
        self.assertEqual(normalized["kind"], "yara")
        self.assertEqual(
            len(normalized["findings"]),
            len(cast(list[object], document["findings"])),
        )

    @given(_SEGMENTS)
    def test_normalize_repo_path_preserves_only_in_target_paths(
        self, segments: list[str]
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            relative = Path(*segments)
            self.assertEqual(normalize_repo_path(target, relative), relative.as_posix())

    @given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=24))
    def test_normalize_repo_path_rejects_relative_traversal(
        self, filename: str
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.mkdir()
            self.assertEqual(
                normalize_repo_path(target, Path("..") / filename),
                "<outside-target>",
            )

    @given(
        tool=st.text(min_size=16, max_size=50),
        rule=st.text(min_size=16, max_size=50),
        path=st.text(min_size=16, max_size=100),
    )
    def test_finding_identity_is_deterministic_and_does_not_disclose_inputs(
        self, tool: str, rule: str, path: str
    ) -> None:
        first = finding_identity(tool=tool, rule_id=rule, path=path)
        second = finding_identity(tool=tool, rule_id=rule, path=path)
        self.assertEqual(first, second)
        self.assertTrue(first[0].startswith("PYSEC-"))
        self.assertTrue(first[1].startswith("sha256:"))
        self.assertNotIn(tool, first[0])
        self.assertNotIn(rule, first[0])
        self.assertNotIn(path, first[0])
