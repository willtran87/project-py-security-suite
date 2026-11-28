"""Real adapter acceptance for identities across relocated sources and rules."""

from __future__ import annotations

import tempfile
from pathlib import Path

from py_security_suite.adapters.semgrep import SemgrepAdapter
from py_security_suite.config import ToolConfig
from py_security_suite.models import ToolStatus


def validate_semgrep_identity(executable: str, rules: Path) -> dict:
    identities = []
    with tempfile.TemporaryDirectory(prefix="pysec-identity-") as temporary:
        for name in ("first", "relocated/deeper"):
            directory = Path(temporary) / name
            source = directory / "source"
            source.mkdir(parents=True)
            (source / "app.py").write_text(
                "import subprocess\ndef run(command):\n    subprocess.run(command, shell=True)\n",
                encoding="utf-8",
            )
            config = directory / "rules.yml"
            config.write_bytes(rules.read_bytes())
            result = SemgrepAdapter(
                ToolConfig(
                    executable=executable, rules_path=config, timeout_seconds=120
                ),
                8 * 1024**2,
            ).run(source)
            if result.tool_run.status != ToolStatus.COMPLETED:
                raise ValueError("Semgrep identity acceptance did not complete")
            observed = sorted(
                (item.sources[0].rule_id, item.finding_id, item.fingerprint)
                for item in result.findings
            )
            if not any(row[0] == "python.subprocess-shell-true" for row in observed):
                raise ValueError(
                    "Semgrep identity acceptance missed its positive control"
                )
            if any(not row[0].startswith("python.") for row in observed):
                raise ValueError(
                    "Semgrep finding identity contains a configuration prefix"
                )
            identities.append(observed)
        collision_source = Path(temporary) / "collision-source"
        collision_source.mkdir()
        (collision_source / "app.py").write_text(
            "first()\nsecond()\n", encoding="utf-8"
        )
        collision_rules = Path(temporary) / "collision-rules"
        for name in ("first", "second"):
            directory = collision_rules / name
            directory.mkdir(parents=True)
            (directory / "rule.yml").write_text(
                "rules:\n  - id: external.collision\n    languages: [python]\n"
                "    message: collision control\n    severity: WARNING\n"
                "    metadata:\n      pysec_rule_id: external.collision\n"
                f"    pattern: {name}(...)\n",
                encoding="utf-8",
            )
        collision = SemgrepAdapter(
            ToolConfig(
                executable=executable, rules_path=collision_rules, timeout_seconds=120
            ),
            8 * 1024**2,
        ).run(collision_source)
        if (
            collision.tool_run.status != ToolStatus.PARSE_ERROR
            or "multiple native origins" not in (collision.tool_run.error or "")
        ):
            raise ValueError(
                "Semgrep distinct native origins were allowed to share one governed ID"
            )
    if identities[0] != identities[1]:
        raise ValueError("Semgrep identities changed after relocating source and rules")
    return {
        "passed": True,
        "runs": 2,
        "identities": identities[0],
        "distinct_origin_collision_rejected": True,
    }
