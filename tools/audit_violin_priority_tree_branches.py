#!/usr/bin/env python3
"""Offline branch table for the active Violin FOPS payload.

This models only the first rb_add_cached comparison against fake_w0.  It does
not open a device, build/install a payload, or claim that the stale waiter
pointer reaches this tree in the default poll route.
"""

from __future__ import annotations

import json


ROOT = "fake_w0"
STALE = "stale_waiter"
TARGET = "ashmem_misc+0x10"
FAKE_FOPS = "fake_fops"
FAKE_PRIO = 130


def branch(prio: int) -> dict[str, object]:
    goes_left = prio < FAKE_PRIO
    return {
        "new_prio": prio,
        "root": ROOT,
        "root_prio": FAKE_PRIO,
        "comparison": f"{prio} < {FAKE_PRIO}",
        "selected_link": f"{ROOT}.rb_left" if goes_left else f"{ROOT}.rb_right",
        "link_value": f"&{STALE}",
        "cached_leftmost_after_link": STALE if goes_left else ROOT,
        "target_slot_written": False,
        "write_value_semantics": "rb_link_node writes &new_node, not fake_fops",
        "requires_runtime": [
            "stale waiter identity reaches fake_lock.waiters",
            "fake_w0 remains the first tree root",
            "vendor waiter-prio hook does not override the comparison",
        ],
    }


def main() -> None:
    print(json.dumps({
        "active_defaults": {
            "custom_write": False,
            "write_target": TARGET,
            "write_value": FAKE_FOPS,
            "write_shape": 0,
            "fake_w0_pi_tree_parent_color": FAKE_FOPS,
            "fake_w0_pi_tree_left": f"{TARGET}-8",
            "fake_w0_pi_tree_right": "NULL",
            "fake_w0_pi_tree_prio": FAKE_PRIO,
        },
        "branches": {
            "nice19_candidate": branch(139),
            "nice0_candidate": branch(120),
        },
        "limitations": [
            "default active route is poll(fd=-1,nfds=1), not W=5 pselect",
            "stale waiter tree fields and owner/task identity are not proven",
            "rb_insert_color rotations are not modeled",
        ],
    }, indent=2))


if __name__ == "__main__":
    main()

