from pathlib import Path
import hashlib
import json
import re

from py_security_suite.adapters.semgrep import SemgrepAdapter
from py_security_suite.config import ToolConfig

ROOT = Path(__file__).resolve().parents[1]


def test_every_bundled_rule_has_its_own_governed_identity() -> None:
    raw = (ROOT / "src/py_security_suite/rules/python-security.yml").read_bytes()
    assert b"\r" not in raw  # Governed bytes must match the repository's LF policy.
    manifest = json.loads((ROOT / ".pysec-models.json").read_text(encoding="utf-8"))
    for model in manifest["models"]:
        if model["model_path"] == "src/py_security_suite/rules/python-security.yml":
            assert model["model_sha256"] == hashlib.sha256(raw).hexdigest()
    text = (ROOT / "src/py_security_suite/rules/python-security.yml").read_text(
        encoding="utf-8"
    )
    blocks = re.split(r"(?m)^  - id: ", text)[1:]
    ids = []
    for block in blocks:
        declared = block.splitlines()[0]
        governed = re.findall(r"(?m)^      pysec_rule_id: (.+)$", block)
        assert governed == [declared]
        ids.append(declared)
    assert len(ids) > 10
    assert len(ids) == len(set(ids))
    command = SemgrepAdapter(ToolConfig(rules_path=ROOT), 4096).build_command(
        "semgrep", ROOT
    )
    # Native prefixes preserve origin information for collision checks; governed
    # metadata supplies stable public identities for the bundled rules.
    assert "--no-rewrite-rule-ids" not in command


def test_release_builders_require_strict_accuracy() -> None:
    release = (ROOT / ".github/workflows/release-assurance.yml").read_text(
        encoding="utf-8"
    )
    accuracy = release.split("  detection-accuracy:\n", 1)[1].split(
        "\n  deep-assurance:", 1
    )[0]
    assert "uses: ./.github/workflows/detection-accuracy.yml" in accuracy
    assert "require_accuracy: true" in accuracy
    builder = release.split("  independent-build:\n", 1)[1].split("    steps:", 1)[0]
    assert "needs: [deep-assurance, detection-accuracy]" in builder
    assert "if:" not in builder
    assert "continue-on-error" not in release
    workflow = (ROOT / ".github/workflows/detection-accuracy.yml").read_text(
        encoding="utf-8"
    )
    assert "${{ inputs.require_accuracy }}" in workflow
    assert "accuracy_args+=(--require-accuracy)" in workflow
    assert '"${accuracy_args[@]}"' in workflow
    assert "continue-on-error" not in workflow
