#!/usr/bin/env python3
"""Extract sched_blocked_reason caller values from a trace_pipe_raw capture.

Event payload layout is taken from tracefs event format: common header (8),
pid (4), padding (4), caller (8), io_wait (1).  A raw ring-buffer record
precedes this payload; scanning for the event common_type makes the parser
robust to record-header variants.
"""
from __future__ import annotations
import argparse, struct
from pathlib import Path

EVENT_ID = 109

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('raw', type=Path)
    ap.add_argument('--symbol-offset', type=lambda x: int(x, 0), required=True,
                    help='image-relative offset of the formatted caller instruction')
    ns = ap.parse_args()
    data = ns.raw.read_bytes()
    seen: set[tuple[int, int]] = set()
    for pos in range(0, len(data) - 25, 4):
        common_type = struct.unpack_from('<H', data, pos)[0]
        if common_type != EVENT_ID:
            continue
        pid = struct.unpack_from('<i', data, pos + 8)[0]
        caller = struct.unpack_from('<Q', data, pos + 16)[0]
        if not (0 < pid < 1_000_000 and (caller >> 48) == 0xffff):
            continue
        item = (pid, caller)
        if item in seen:
            continue
        seen.add(item)
        print(f'pid={pid} caller=0x{caller:016x} kernel_text=0x{caller - ns.symbol_offset:016x}')
    return 0 if seen else 1

if __name__ == '__main__':
    raise SystemExit(main())
