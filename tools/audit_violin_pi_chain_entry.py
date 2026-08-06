#!/usr/bin/env python3
"""Offline gate audit for the first rt_mutex PI-chain transition.

This pass intentionally stops before rbtree modelling.  The matching 6.6
source only calls rt_mutex_adjust_prio_chain() after task_blocks_on_rt_mutex()
has both (a) owner->pi_blocked_on and (b) a non-NULL next_lock.  The Violin
worktree has changed those fields relative to git HEAD, so a deeper transition
model must not silently mix the two states.

No device, payload, build, adb, or kernel-facing operation is performed.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT / "exploit-repo"
UTIL_REL = "IonStack/CVE-2026-43499/exploit/src/util.c"
FOPS_REL = "IonStack/CVE-2026-43499/exploit/src/fops.c"


def read_current(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def read_head(rel: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(REPO), "show", f"HEAD:{rel}"],
        text=True,
        encoding="utf-8",
    )


def find_line(text: str, needle: str) -> str | None:
    for line in text.splitlines():
        if needle in line:
            return line.strip()
    return None


def owner_pi_blocked_on_state(util: str) -> str:
    # The write is deliberately classified from the payload source, not from
    # a prose assumption.  The current branch writes fake_w0; HEAD writes 0
    # for PAGE_PAYLOAD_FOPS and therefore cannot enter the chain walk.
    lines = util.splitlines()
    for i, line in enumerate(lines):
        if "FAKE_TASK_OFF + pi_blocked_on_off" in line:
            window = " ".join(lines[i : i + 2])
            if re.search(r"pi_blocked_on_off\s*,\s*fake_w0", window):
                return "fake_w0"
            if re.search(r"pi_blocked_on_off\s*,\s*0", window):
                return "NULL"
    # HEAD uses the named macro rather than the current split-offset form.
    if "FAKE_TASK_PI_BLOCKED_ON_OFF, 0" in util:
        return "NULL"
    if "FAKE_TASK_PI_BLOCKED_ON_OFF, fake_w0" in util:
        return "fake_w0"
    return "UNKNOWN"


def waiter_lock_state(util: str) -> str:
    if "FAKE_WAITER_LOCK_OFF, (uint64_t)(uintptr_t)pselect_user_lock" in util:
        return "pselect_user_lock (user VA)"
    if "FAKE_WAITER_LOCK_OFF, fake_lock" in util:
        return "fake_lock (kernel page)"
    return "UNKNOWN"


def state(label: str, util: str, fops: str) -> dict:
    owner_blocked = owner_pi_blocked_on_state(util)
    lock_state = waiter_lock_state(util)
    root_state = (
        "fake_w0.pi_tree"
        if "FAKE_TASK_OFF + pi_waiters_off" in util
        else "UNKNOWN"
    )
    # For HEAD the PAGE_PAYLOAD_FOPS branch explicitly zeros pi_waiters and
    # later leaves pi_blocked_on NULL.  The current branch overwrites both
    # fields with the forged node/task route.
    if "put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0);" in util:
        root_state = "NULL (PAGE_PAYLOAD_FOPS branch)"
    elif "put64(p, FAKE_TASK_OFF + pi_waiters_off,\n            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);" in util:
        root_state = "fake_w0.pi_tree"

    chain_walk = owner_blocked != "NULL"
    next_lock = lock_state != "UNKNOWN"
    adjust_call_reachable = chain_walk and next_lock

    return {
        "label": label,
        "owner": "fake_task (fake_lock.owner = fake_task|1)",
        "owner_pi_blocked_on": owner_blocked,
        "owner_pi_waiters_root": root_state,
        "forged_waiter_lock": lock_state,
        "task_blocks_on_chain_walk": chain_walk,
        "next_lock_nonnull_static": next_lock,
        "rt_mutex_adjust_prio_chain_reachable": adjust_call_reachable,
        "source_evidence": {
            "blocked_on_line": find_line(util, "FAKE_TASK_OFF + pi_blocked_on_off")
            or find_line(util, "FAKE_TASK_PI_BLOCKED_ON_OFF"),
            "lock_line": find_line(util, "FAKE_WAITER_LOCK_OFF"),
            "pi_waiters_line": find_line(util, "FAKE_TASK_OFF + pi_waiters_off")
            or find_line(util, "FAKE_TASK_PI_WAITERS_OFF"),
            "fops_route_line": find_line(fops, "pselect(PSELECT_ROUTE_NFDS")
            or find_line(fops, "poll((struct pollfd *)pselect_user_lock"),
        },
        "interpretation": (
            "gate open only conditionally: the next-lock value is a user VA; "
            "kernel dereference/identity alignment is not established offline"
            if adjust_call_reachable
            else "gate closed: task_blocks_on_rt_mutex() returns before "
            "rt_mutex_adjust_prio_chain()"
        ),
    }


def main() -> None:
    current_util = read_current(UTIL_REL)
    current_fops = read_current(FOPS_REL)
    head_util = read_head(UTIL_REL)
    head_fops = read_head(FOPS_REL)

    result = {
        "scope": "offline PI-chain entry gate; no rbtree transition claimed",
        "source": {
            "rtmutex": "kernel-src-wsl/common-gki/kernel/locking/rtmutex.c:1212-1290",
            "condition": "chain_walk && next_lock before rt_mutex_adjust_prio_chain",
        },
        "states": [
            state("HEAD", head_util, head_fops),
            state("current_worktree", current_util, current_fops),
        ],
        "hard_limitations": [
            "current default route is poll(fd=-1,nfds=1), not the HEAD pselect route",
            "a user VA in waiter->lock is not proof that kernel rt_mutex dereference is valid",
            "no rbtree write, fops hijack, CFI, credential, or target-slot result is inferred",
        ],
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
