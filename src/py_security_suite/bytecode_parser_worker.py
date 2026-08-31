from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        raise ValueError("bytecode parser worker requires one path")
    package_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(package_root))
    from py_security_suite.bytecode_analysis import analyze_python_bytecode
    from py_security_suite.path_safety import read_regular_file

    _path, payload = read_regular_file(
        Path(sys.argv[1]),
        "bytecode parser input",
        maximum_bytes=1024 * 1024,
    )
    print(json.dumps(analyze_python_bytecode(payload), separators=(",", ":")))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as an isolated subprocess
    raise SystemExit(main())
