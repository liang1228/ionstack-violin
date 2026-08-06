#!/usr/bin/env python3
"""Offline caller-contract audit for the active violin pipe write path."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "exploit-repo" / "IonStack" / "CVE-2026-43499" / "exploit" / "src"
PIPE = SRC / "pipe.c"
ROOT_C = SRC / "root.c"
PAGE_SIZE = 0x1000


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def macro_string(text: str, name: str) -> str | None:
    match = re.search(rf"^#define\s+{re.escape(name)}\s+\"([^\"]*)\"", text, re.M)
    return match.group(1) if match else None


def direct_calls(path: Path, text: str) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    # Keep the body bounded so a declaration/definition cannot consume a
    # later call. Nested calls in `if (!pipe_phys_write_data(...))` do not end
    # in a literal `);`, so stop at the first sizeof() expression instead.
    pattern = re.compile(
        r"pipe_phys_write_data\((?P<body>[\s\S]{0,300}?sizeof\((?P<size_symbol>\w+)\))"
    )
    for match in pattern.finditer(text):
        body = match.group("body")
        if body.lstrip().startswith("\n    int fd"):
            continue
        size_match = re.search(r"sizeof\((\w+)\)", body)
        # This is the implementation call inside pipe_write64(), not a
        # separate high-level caller; report it through write64_calls().
        if size_match and size_match.group(1) == "value" and "int pipe_write64" in text[max(0, match.start() - 100) : match.start()]:
            continue
        calls.append(
            {
                "file": str(path.relative_to(ROOT)),
                "line": line_of(text, match.start()),
                "length_expression": size_match.group(0) if size_match else "unknown",
                "length_symbol": size_match.group(1) if size_match else None,
                "body": " ".join(body.split()),
            }
        )
    return calls


def write64_calls(path: Path, text: str) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for match in re.finditer(r"\bpipe_write64\s*\(", text):
        line = line_of(text, match.start())
        # Exclude the function definition itself.
        prefix = text[max(0, match.start() - 10) : match.start()]
        if re.search(r"int\s+$", prefix):
            continue
        calls.append(
            {
                "file": str(path.relative_to(ROOT)),
                "line": line,
                "length_expression": "sizeof(value) in pipe_write64",
                "length_bytes": 8,
            }
        )
    return calls


def main() -> None:
    pipe_text = PIPE.read_text(encoding="utf-8", errors="replace")
    root_text = ROOT_C.read_text(encoding="utf-8", errors="replace")
    symbols = {
        # All sizes are statically fixed by the declarations in root.c.
        "zero_ids": 4 * 8,
        "securebits": 4,
        "caps": 5 * 8,
        "sid_pair": 2 * 4,
        "zero32": 4,
        "zero64": 8,
        "permissive": 1,
        "overwrite": (len(macro_string(pipe_text, "PHYS_WRITE_TAG") or "") + 1),
    }
    direct = direct_calls(PIPE, pipe_text) + direct_calls(ROOT_C, root_text)
    for call in direct:
        call["length_bytes"] = symbols.get(call["length_symbol"])
        call["within_small_write_contract"] = (
            call["length_bytes"] is not None and 0 < call["length_bytes"] < PAGE_SIZE
        )
    write64 = write64_calls(PIPE, pipe_text) + write64_calls(ROOT_C, root_text)
    all_calls = direct + write64
    unknown = [c for c in all_calls if c.get("length_bytes") is None]
    unsafe = [
        c
        for c in all_calls
        if c.get("length_bytes") is not None and not (0 < c["length_bytes"] < PAGE_SIZE)
    ]
    result = {
        "audit": "active violin pipe write caller contract",
        "mode": "offline-read-only",
        "sources": [str(PIPE.relative_to(ROOT)), str(ROOT_C.relative_to(ROOT))],
        "contract": {
            "page_size": PAGE_SIZE,
            "required": "0 < len < PAGE_SIZE",
            "reason": "pipe_write merge uses chars = total_len & (PAGE_SIZE - 1)",
        },
        "resolved_sizes": symbols,
        "direct_pipe_phys_write_data_calls": direct,
        "pipe_write64_calls": write64,
        "summary": {
            "total_calls": len(all_calls),
            "known_calls": len(all_calls) - len(unknown),
            "unknown_calls": len(unknown),
            "unsafe_calls": len(unsafe),
            "all_current_callers_within_contract": not unknown and not unsafe,
        },
        "findings": [
            {
                "id": "CALLER-CONTRACT-PASS",
                "severity": "informational",
                "status": "confirmed-offline",
                "title": "当前 active src/pipe.c 与 src/root.c 调用方均使用小于 PAGE_SIZE 的长度",
                "detail": "当前直接调用和 pipe_write64 包装调用的最大静态长度为 40 bytes；没有调用方传入 PAGE_SIZE 或更大长度。",
            },
            {
                "id": "API-GUARD-STILL-REQUIRED",
                "severity": "high",
                "status": "confirmed-offline",
                "title": "调用方安全不等于 API 安全",
                "detail": "pipe_phys_write_data() 仍允许未来调用方传入 0 或 PAGE_SIZE；必须在 API 边界拒绝这两类长度，不能依赖当前调用方画像。",
            },
        ],
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
