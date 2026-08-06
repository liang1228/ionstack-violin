#!/usr/bin/env python3
"""Offline fd-mask/readiness state machine for the nfds=256 candidate.

This consumes the 12-word waiter map from audit_violin_pselect256_kernel_lock.py
and follows the current open_selected_fds() behavior: fd 3..255 are rebound to
the non-ready read_fd, while fd 0..2 are left untouched.  It intentionally
stops before any kernel PI/rbtree claim.
"""

from __future__ import annotations

import json


NFDS = 256


def bits(value: int) -> list[int]:
    return [i for i in range(64) if (value >> i) & 1]


def build_profile(prio: int, deadline: int) -> dict:
    # Representative addresses preserve the alignment/high-bit shape of the
    # same-build page and KASLR data.  The exact runtime page is not required
    # for the fd-range/readiness check.
    page = 0xFFFFFF81E7998000
    values = {
        "in": [0, 0, 0, 0x42424240 if prio != 130 else 0x42424242],
        "out": [deadline, page + 0x180, 0, 0xFFFFFFD5EFC3B5E0],
        "ex": [prio, 0, page + 0x2380, page + 0x4D0],
    }
    per_set = {}
    for set_name, words in values.items():
        rows = []
        for word, value in enumerate(words):
            fds = [word * 64 + bit for bit in bits(value)]
            rows.append({
                "word": word,
                "value": f"0x{value:016x}",
                "set_bits": fds,
                "reserved_fd_bits": [fd for fd in fds if fd < 3],
                "rebound_by_helper": [fd for fd in fds if fd >= 3],
            })
        per_set[set_name] = rows

    reserved = {
        name: sorted({fd for row in rows for fd in row["reserved_fd_bits"]})
        for name, rows in per_set.items()
    }
    # Baseline descriptor behavior is deliberately conservative: fd 1/2 are
    # commonly writable, while exceptfds rarely reports a normal pipe/tty.
    write_ready_candidates = sorted(set(reserved["out"]) & {1, 2})
    return {
        "prio": prio,
        "deadline": f"0x{deadline:08x}",
        "sets": per_set,
        "reserved_fd_bits": reserved,
        "readiness": {
            "writefds_reserved_fd1_or_2": write_ready_candidates,
            "potential_early_return_with_unmodified_helper": bool(write_ready_candidates),
            "reason": "open_selected_fds skips fd 0..2; a writable baseline fd in writefds can make pselect return before timeout",
        },
        "fd_range_ok": all(
            0 <= fd < NFDS
            for rows in per_set.values()
            for row in rows
            for fd in row["set_bits"]
        ),
    }


def main() -> None:
    result = {
        "scope": "offline pselect nfds=256 fd-mask and readiness only",
        "helper_model": {
            "PSELECT_ROUTE_NFDS": 256,
            "words_per_set": 4,
            "rebind_range": "fd 3..255",
            "rebind_source": "read_fd (pipe read end/timerfd), non-ready baseline",
            "fd0_to_2": "left unchanged by current open_selected_fds",
        },
        "profiles": {
            "original_constants": build_profile(130, 0x43434343),
            "lowbit_cleared_candidate": build_profile(128, 0x43434340),
        },
        "decision": {
            "result": "copy range and fd upper range are feasible; original constants have a reserved writefds bit risk",
            "best_offline_fix": "either rebind fd0..2 to the non-ready descriptor or choose low-bit-cleared diagnostic constants, then re-check PI priority semantics",
            "not_proven": [
                "stale waiter/task identity",
                "kernel PI lock consumption",
                "rb_erase/rb_insert target write",
                "CFI or privilege transition",
            ],
        },
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
