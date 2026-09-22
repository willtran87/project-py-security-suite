"""Durable validation checkpoints; raw process output is represented by digests."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
import traceback
import uuid
from pathlib import Path
from typing import Any
from collections.abc import Callable


def atomic_json(path: Path, document: dict) -> None:
    payload = (json.dumps(document, indent=2) + "\n").encode()
    atomic_bytes(path, payload)


def atomic_bytes(path: Path, payload: bytes) -> None:
    if len(payload) > 64 * 1024**2:
        raise ValueError("validation evidence exceeds 64 MiB")
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=".validation-", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        # Windows may briefly deny replacement while another writer closes its
        # rename handle. Retry only sharing/access violations, for at most 0.75 s.
        for attempt in range(6):
            try:
                os.replace(temporary, path)
                break
            except PermissionError as exc:
                if getattr(exc, "winerror", None) not in {5, 32, 33} or attempt == 5:
                    raise
                time.sleep(0.05 * (attempt + 1))
    finally:
        Path(temporary).unlink(missing_ok=True)


def output_identity(value: str | bytes | None) -> dict:
    data = value.encode("utf-8") if isinstance(value, str) else value or b""
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class ValidationEvidence:
    def __init__(self, output: Path, scope: str):
        self.output = output
        run_id = uuid.uuid4().hex
        self.run_directory = output.parent / (output.stem + "-evidence") / run_id
        self.document: dict[str, Any] = {
            "schema_version": "1.1",
            "scope": scope,
            "passed": False,
            "state": "running",
            "stage": "initializing",
            "cases": [],
            "commands": [],
            "run_id": run_id,
        }
        self.save()

    def save(self) -> None:
        atomic_json(self.run_directory / "run.json", self.document)
        atomic_json(self.output, self.document)

    def stage(self, name: str, **details: Any) -> None:
        self.document.update(stage=name, **details)
        self.save()

    def invoke(
        self, stage: str, operation: Callable[[], subprocess.CompletedProcess]
    ) -> subprocess.CompletedProcess:
        self.stage(stage)
        started = time.monotonic()
        record: dict[str, Any] = {"stage": stage}
        try:
            result = operation()
            record.update(
                exit_code=result.returncode,
                stdout=output_identity(result.stdout),
                stderr=output_identity(result.stderr),
            )
            return result
        except subprocess.TimeoutExpired as exc:
            record.update(
                timed_out=True,
                stdout=output_identity(exc.stdout),
                stderr=output_identity(exc.stderr),
            )
            raise
        except OSError as exc:
            record["error_category"] = type(exc).__name__
            raise
        finally:
            record["duration_seconds"] = round(time.monotonic() - started, 3)
            self.document["commands"].append(record)
            self.save()

    def retain_report(self, source: Path, scenario: str, tools: list[str]) -> None:
        """Retain only normalized reports from these generated acceptance fixtures."""
        destination = self.run_directory / scenario
        records = []
        total = 0
        for name in [
            "scan-manifest.json",
            "findings.json",
            *[f"evidence/{tool}.json" for tool in tools],
        ]:
            path = source / name
            if not path.exists():
                continue
            if path.is_symlink() or not path.resolve().is_relative_to(source.resolve()):
                raise ValueError("acceptance evidence escapes generated report")
            if path.stat().st_size > 16 * 1024**2:
                raise ValueError("acceptance evidence file exceeds 16 MiB")
            data = path.read_bytes()
            total += len(data)
            if total > 64 * 1024**2:
                raise ValueError("acceptance evidence scenario exceeds 64 MiB")
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            records.append(
                {
                    "path": target.relative_to(self.output.parent).as_posix(),
                    **output_identity(data),
                }
            )
        self.document.setdefault("artifacts", {})[scenario] = records
        self.save()

    def complete_case(self, result: dict) -> None:
        self.document["cases"].append(result)
        self.save()

    def fail(self, exc: BaseException) -> dict:
        # Exception messages and native output can contain source or credentials.
        self.document.update(
            state="failed",
            passed=False,
            error_category=type(exc).__name__,
            failed_stage=self.document["stage"],
            failure_sites=[
                {
                    "file": Path(frame.filename).name,
                    "line": frame.lineno,
                    "function": frame.name,
                }
                for frame in traceback.extract_tb(exc.__traceback__)[-6:]
            ],
        )
        self.save()
        return self.document

    def finish(self, result: dict) -> dict:
        self.document.update(
            result, state="passed" if result["passed"] else "failed", stage="finished"
        )
        self.save()
        return self.document
