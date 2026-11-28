"""Genesis checkpoint digest for benchmark replay ledgers."""

from __future__ import annotations

import hashlib


BENCHMARK_REPLAY_GENESIS_SHA256 = hashlib.sha256(
    b"pysec-benchmark-replay-genesis-v1"
).hexdigest()
