from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        raise ValueError("native parser worker requires one path")
    package_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(package_root))
    from py_security_suite.boundary_graph import _native_imports_in_process

    path = Path(sys.argv[1]).resolve()
    payload = path.read_bytes()
    if len(payload) > 1024 * 1024:
        raise ValueError("native parser input exceeds the bounded surface limit")
    print(json.dumps(_native_imports_in_process(path, payload), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
