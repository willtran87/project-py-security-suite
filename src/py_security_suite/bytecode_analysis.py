from __future__ import annotations

import dis
import importlib.util
import marshal
import types


_MAX_CODE_OBJECTS = 10_000
_MAX_INSTRUCTIONS = 100_000
_MAX_EDGES = 10_000
_DYNAMIC_NAMES = frozenset({"eval", "exec", "compile", "__import__"})


def analyze_python_bytecode(payload: bytes) -> list[list[int | str]]:
    """Return bounded import and dynamic-dispatch edges without executing code."""

    if len(payload) < 16 or payload[:4] != importlib.util.MAGIC_NUMBER:
        raise ValueError("Python bytecode magic or header is invalid")
    try:
        # Parsing is invoked in a resource- and OS-contained worker for production;
        # the function is separately exposed for the dedicated fuzzing process.
        root = marshal.loads(payload[16:])  # noqa: S302
    except (EOFError, TypeError, ValueError) as exc:
        raise ValueError("Python bytecode marshal payload is invalid") from exc
    if not isinstance(root, types.CodeType):
        raise ValueError("Python bytecode payload is not a code object")

    seen: set[int] = set()
    edges: set[tuple[int, str, str]] = set()
    stack = [root]
    instruction_count = 0
    while stack:
        code = stack.pop()
        identity = id(code)
        if identity in seen:
            continue
        seen.add(identity)
        if len(seen) > _MAX_CODE_OBJECTS:
            raise ValueError("Python bytecode code-object limit exceeded")
        stack.extend(
            constant
            for constant in code.co_consts
            if isinstance(constant, types.CodeType)
        )
        try:
            instructions = dis.get_instructions(code)
            for instruction in instructions:
                instruction_count += 1
                if instruction_count > _MAX_INSTRUCTIONS:
                    raise ValueError("Python bytecode instruction limit exceeded")
                line = max(1, instruction.starts_line or code.co_firstlineno)
                if instruction.opname == "IMPORT_NAME" and isinstance(
                    instruction.argval, str
                ):
                    edges.add((line, "module-import", instruction.argval))
                elif (
                    instruction.opname in {"LOAD_GLOBAL", "LOAD_NAME"}
                    and instruction.argval in _DYNAMIC_NAMES
                ):
                    edges.add((line, "dynamic-dispatch", str(instruction.argval)))
                if len(edges) > _MAX_EDGES:
                    raise ValueError("Python bytecode semantic edge limit exceeded")
        except (IndexError, KeyError, TypeError) as exc:
            raise ValueError("Python bytecode instruction stream is invalid") from exc
    return [list(edge) for edge in sorted(edges)]
