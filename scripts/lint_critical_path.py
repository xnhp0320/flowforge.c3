#!/usr/bin/env python3
"""Find repeated temporary allocations without a per-iteration pool.

Follow calls from packet processing loops. A temporary list is fine when a
surrounding @pool() is entered for each packet or batch, even if that pool is
in a caller. @pool_init() sets up the worker's long-lived arena and does not
count as a reset boundary.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "src"
CRITICAL_ROOTS = (
    "runtime_live:run_worker_impl",
    "runtime_live:run_worker_once_impl",
    "runtime_live:run_capture",
    "runtime_tap:tap_tx_worker_impl",
    "runtime_tap:tap_rx_worker",
    "main:run_file_mode",
)

CALL = re.compile(r"(?<![\w:])([A-Za-z_]\w*(?:(?:::|\.)[A-Za-z_]\w*)*)\s*\(")
TEMP_ALLOC = re.compile(
    r"\.tinit\s*\(|\.init\s*\(\s*tmem\b|"
    r"\bmem::(?:temp_array|tnew)\s*\(|\b(?:tmalloc|tcalloc|trealloc)\s*\("
)
POOL = re.compile(r"@pool\s*\([^)]*\)\s*\{")
ERROR_ONLY_COMMENT = "// critical-path-lint: error-only"
CONTROL_LOOP = re.compile(r"\b(while|for|foreach|do)\b")
FUNCTION = re.compile(r"\bfn\s+")
NAME = re.compile(r"([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*$")


@dataclass(frozen=True)
class Function:
    key: str
    file: Path
    body_start: int
    body_end: int
    source: str
    masked: str
    body_pool: bool = False


def mask_non_code(source: str) -> str:
    """Replace comments and literals with spaces, retaining offsets/newlines."""
    result = list(source)
    i = 0
    while i < len(source):
        start = i
        if source.startswith("//", i):
            end = source.find("\n", i)
            i = len(source) if end < 0 else end
        elif source.startswith("/*", i) or source.startswith("<*", i):
            closing = "*/" if source.startswith("/*", i) else "*>"
            end = source.find(closing, i + 2)
            i = len(source) if end < 0 else end + 2
        elif source[i] in ('"', "'", "`"):
            quote = source[i]
            i += 1
            while i < len(source):
                if source[i] == "\\":
                    i += 2
                elif source[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
        else:
            i += 1
            continue
        for j in range(start, min(i, len(source))):
            if result[j] != "\n":
                result[j] = " "
    return "".join(result)


def closing_brace(masked: str, opening: int) -> int:
    depth = 0
    for i in range(opening, len(masked)):
        if masked[i] == "{":
            depth += 1
        elif masked[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    raise ValueError(f"unclosed block at offset {opening}")


def functions_in(path: Path) -> list[Function]:
    source = path.read_text()
    masked = mask_non_code(source)
    functions = []
    for match in FUNCTION.finditer(masked):
        paren = masked.find("(", match.end())
        if paren < 0:
            continue
        name_match = NAME.search(masked[match.end():paren])
        if not name_match:
            continue
        name = name_match.group(1)
        depth = 1
        i = paren + 1
        while i < len(masked) and depth:
            depth += (masked[i] == "(") - (masked[i] == ")")
            i += 1
        tail = masked[i:]
        body = re.match(r"\s*(?:@[A-Za-z_]\w*\s*)*(=>\s*@pool\s*\([^)]*\)\s*)?\{", tail)
        if not body:
            continue
        opening = i + body.end() - 1
        end = closing_brace(masked, opening)
        functions.append(Function(f"{path.stem}:{name}", path, opening + 1, end, source, masked, body.group(1) is not None))
    return functions


def enclosing_blocks(function: Function, pattern: re.Pattern[str], offset: int) -> list[int]:
    body = function.masked[function.body_start:function.body_end]
    openings = []
    for match in pattern.finditer(body, 0, offset - function.body_start):
        opening = function.body_start + match.end() - 1
        if opening < offset < closing_brace(function.masked, opening):
            openings.append(opening)
    return openings


def enclosing_loops(function: Function, offset: int, while_only: bool = False) -> list[int]:
    masked = function.masked
    openings = []
    for match in CONTROL_LOOP.finditer(masked, function.body_start, offset):
        if while_only and match.group(1) != "while":
            continue
        i = match.end()
        while i < offset and masked[i].isspace():
            i += 1
        if match.group(1) != "do":
            if i >= offset or masked[i] != "(":
                continue
            depth = 1
            i += 1
            while i < offset and depth:
                depth += (masked[i] == "(") - (masked[i] == ")")
                i += 1
            if depth:
                continue
            while i < offset and masked[i].isspace():
                i += 1
        if i < offset and masked[i] == "{" and i < offset < closing_brace(masked, i):
            openings.append(i)
    return openings


def site_state(function: Function, offset: int, repeated: bool, bounded: bool, is_root: bool) -> tuple[bool, bool]:
    loops = enclosing_loops(function, offset)
    whiles = enclosing_loops(function, offset, while_only=True)
    pools = enclosing_blocks(function, POOL, offset)
    if function.body_pool:
        pools.insert(0, function.body_start - 1)
    # Only designated processing loops turn a one-time call into a repeated
    # path. A helper's foreach over a short result list does not do that.
    called_repeatedly = repeated
    repeated = repeated or (is_root and bool(loops))
    # A pool entered after the outer loop begins is reset on every outer
    # iteration. Inner bounded batch loops can share that pool.
    for pool in reversed(pools):
        if not any(loop > pool for loop in whiles) and (not loops or pool > loops[0] or called_repeatedly):
            return repeated, True
    # A while loop inside an inherited pool may run indefinitely before that
    # pool is popped. A new inner pool is needed for repeated allocations.
    if whiles:
        return repeated, False
    return repeated, bounded


def resolve_call(caller: Function, name: str, by_key: dict[str, Function], by_simple: dict[str, list[str]]) -> list[str]:
    parts = name.split("::")
    if len(parts) > 1:
        key = f"{parts[-2]}:{parts[-1]}"
        if key in by_key:
            return [key]
    simple = parts[-1].split(".")[-1]
    module = caller.key.split(":", 1)[0]
    local = [key for key in by_simple.get(simple, ()) if key.startswith(module + ":")]
    if local:
        return local
    # Without type information, Atomic.load() must not be mistaken for an
    # unrelated free function such as header_file::load(). Follow actual
    # project methods (e.g. PayloadFieldModifier.apply) across modules.
    if "." in name and "::" not in name and len(simple) < 10:
        return [key for key in by_simple.get(simple, ()) if "." in key.split(":", 1)[1]]
    return by_simple.get(simple, [])


def marked_error_only(function: Function, offset: int) -> bool:
    """An explicit, locally reviewable exception for a failure-only allocation."""
    line_start = function.source.rfind("\n", 0, offset)
    if line_start < 0:
        return False
    previous_start = function.source.rfind("\n", 0, line_start)
    return function.source[previous_start + 1 : line_start].strip() == ERROR_ONLY_COMMENT


def lint(paths: list[Path], roots: tuple[str, ...] = CRITICAL_ROOTS, root: Path = ROOT) -> list[str]:
    functions = [function for path in paths for function in functions_in(path)]
    by_key = {function.key: function for function in functions}
    by_simple: dict[str, list[str]] = defaultdict(list)
    for function in functions:
        by_simple[function.key.rsplit(".", 1)[-1].split(":")[-1]].append(function.key)

    missing = [critical_root for critical_root in roots if critical_root not in by_key]
    if missing:
        return [f"critical-path root missing: {critical_root}" for critical_root in missing]

    queue = deque((critical_root, False, False, (critical_root,)) for critical_root in roots)
    seen = set()
    problems = []
    while queue:
        key, repeated, bounded, route = queue.popleft()
        if (key, repeated, bounded) in seen:
            continue
        seen.add((key, repeated, bounded))
        function = by_key[key]
        body = function.masked[function.body_start:function.body_end]
        for match in TEMP_ALLOC.finditer(body):
            offset = function.body_start + match.start()
            site_repeated, site_bounded = site_state(function, offset, repeated, bounded, key in roots)
            if site_repeated and not site_bounded and not marked_error_only(function, offset):
                line = function.source.count("\n", 0, offset) + 1
                path = function.file.relative_to(root)
                problems.append(f"{path}:{line}: repeated temp allocation has no per-iteration @pool() ({' -> '.join(route)})")
        for match in CALL.finditer(body):
            offset = function.body_start + match.start()
            if match.group(1).split(".")[-1] in {"init", "tinit"}:
                continue
            site_repeated, site_bounded = site_state(function, offset, repeated, bounded, key in roots)
            for callee in resolve_call(function, match.group(1), by_key, by_simple):
                if (callee, site_repeated, site_bounded) not in seen:
                    queue.append((callee, site_repeated, site_bounded, (*route, callee)))
    return sorted(set(problems))


def main() -> int:
    problems = lint(sorted(SOURCES.glob("*.c3")))
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        print("Put repeated temp allocation inside a per-packet or per-batch @pool() and keep escaping data in an outer allocator.", file=sys.stderr)
        return 1
    print("critical-path pool-lifetime lint: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
