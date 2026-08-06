#!/usr/bin/env python3
"""Offline verifier for the Violin sched_blocked_reason KASLR evidence.

This verifier never opens ADB, tracefs, or a device.  It checks the capture
hash, the event/caller field, the same-build symbol delta, and the derived
canonical text base against a local raw capture and kallsyms file.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import struct
import sys
from pathlib import Path

EVENT_ID = 109
CALLER_INSN_DELTA = 0x9C


def parse_symbol(path: Path, name: str) -> int:
    pattern = re.compile(r"^([0-9a-fA-F]+)\s+\S\s+" + re.escape(name) + r"$")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = pattern.match(line.strip())
        if match:
            return int(match.group(1), 16)
    raise ValueError(f"symbol not found: {name}")


def find_records(data: bytes) -> list[tuple[int, int]]:
    records: list[tuple[int, int]] = []
    seen: set[tuple[int, int]] = set()
    for pos in range(0, len(data) - 25, 4):
        if struct.unpack_from("<H", data, pos)[0] != EVENT_ID:
            continue
        pid = struct.unpack_from("<i", data, pos + 8)[0]
        caller = struct.unpack_from("<Q", data, pos + 16)[0]
        if not (0 < pid < 1_000_000 and (caller >> 48) == 0xFFFF):
            continue
        item = (pid, caller)
        if item not in seen:
            seen.add(item)
            records.append(item)
    return records


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("raw", type=Path)
    ap.add_argument("kallsyms", type=Path)
    ap.add_argument("--expected-sha256", required=True)
    ap.add_argument("--expected-caller", type=lambda value: int(value, 0),
                    default=0xFFFFFFD30A6D797C)
    ap.add_argument("--expected-text", type=lambda value: int(value, 0),
                    default=0xFFFFFFD30A600000)
    ns = ap.parse_args()

    data = ns.raw.read_bytes()
    digest = hashlib.sha256(data).hexdigest().upper()
    worker = parse_symbol(ns.kallsyms, "worker_thread")
    text = parse_symbol(ns.kallsyms, "_text")
    image_delta = worker - text
    caller_offset = image_delta + CALLER_INSN_DELTA
    records = find_records(data)

    checks = [
        ("raw_sha256", digest == ns.expected_sha256.upper(),
         f"actual={digest}"),
        ("event_109_caller_offset_16", bool(records),
         f"records={len(records)}"),
        ("same_build_symbol_delta", image_delta == 0xD78E0,
         f"worker_thread-_text=0x{image_delta:x}"),
    ]
    if records:
        pid, caller = records[0]
        derived_text = caller - caller_offset
        checks.extend([
            ("caller_value", caller == ns.expected_caller,
             f"pid={pid} caller=0x{caller:016x}"),
            ("derived_canonical_text", derived_text == ns.expected_text and
             (derived_text >> 48) == 0xFFFF,
             f"kernel_text=0x{derived_text:016x}"),
        ])

    failed = False
    for name, passed, detail in checks:
        print(f"{'PASS' if passed else 'FAIL'} {name}: {detail}")
        failed |= not passed
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
