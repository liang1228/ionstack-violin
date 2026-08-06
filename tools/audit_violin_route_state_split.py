#!/usr/bin/env python3
"""Offline split of the Violin HEAD candidate and active worktree state.

This audit exists to prevent mixing the HEAD W=5 pselect layout with the
current poll/nfds=64 worktree.  It also models the first safe part of the HEAD
second chain when fake_w0->lock is the kernel fake_lock, not a user VA.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT / "exploit-repo"
REL_COMMON = "IonStack/CVE-2026-43499/exploit/src/common.h"
REL_UTIL = "IonStack/CVE-2026-43499/exploit/src/util.c"
REL_FOPS = "IonStack/CVE-2026-43499/exploit/src/fops.c"


def read_current(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8", errors="replace")


def read_head(rel: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(REPO), "show", f"HEAD:{rel}"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout


def define(text: str, name: str) -> int | None:
    match = re.search(rf"^#define\s+{re.escape(name)}\s+(\d+)", text, re.M)
    return int(match.group(1)) if match else None


def lock_assignment(text: str) -> str:
    if re.search(r"FAKE_WAITER_LOCK_OFF,\s*fake_lock", text):
        return "fake_lock"
    if re.search(r"FAKE_WAITER_LOCK_OFF,\s*\(uint64_t\)\(uintptr_t\)pselect_user_lock", text):
        return "pselect_user_lock"
    return "unknown"


def default_route(text: str) -> str:
    # The final non-probe route is the only route relevant to active defaults.
    poll = re.search(r"int\s+ret\s*=\s*poll\s*\(", text)
    pselect = re.search(r"int\s+ret\s*=\s*pselect\s*\(", text)
    if poll and (not pselect or poll.start() > pselect.start()):
        return "poll"
    if pselect:
        return "pselect"
    return "unknown"


def state(label: str, common: str, util: str, fops: str) -> dict:
    nfds = define(common, "PSELECT_ROUTE_NFDS")
    calls = define(common, "CONSUMER_MAX_CALLS")
    return {
        "label": label,
        "PSELECT_ROUTE_NFDS": nfds,
        "words_per_set_at_64bit": (nfds + 63) // 64 if nfds else None,
        "CONSUMER_MAX_CALLS": calls,
        "fake_w0_lock": lock_assignment(util),
        "default_route_source": default_route(fops),
        "pselect_w5_stale_lock_source": (
            "ex[1]=fake_lock" if nfds == 320 else "not applicable to active poll route"
        ),
    }


def head_second_chain_model() -> dict:
    return {
        "scope": "conditional HEAD W=5 pselect model after first owner PI enqueue is made valid",
        "first_iteration_lock": "fake_lock (kernel page)",
        "fake_w0_lock": "fake_lock (kernel page)",
        "next_lock_equals_waiter_lock": True,
        "user_va_lock_blocker": False,
        "before_second_requeue": {
            "fake_lock.waiters.root": "stale_waiter",
            "fake_lock.waiters.leftmost": "stale_waiter",
            "fake_w0.tree.__rb_parent_color": "0x1",
            "fake_w0.tree.left": "NULL",
            "fake_w0.tree.right": "NULL",
            "fake_w0.tree.prio": 130,
            "fake_task.prio": 120,
        },
        "second_iteration": [
            "raw_spin_trylock(fake_lock.wait_lock): kernel-page object is at least type-consistent",
            "rt_mutex_owner(fake_lock)=fake_task; orig_lock=NULL and top_task is real scheduler target",
            "rb_erase_cached(fake_lock.waiters, fake_w0): parent from 0x1 is NULL, child NULL, root becomes NULL",
            "waiter_update_prio(fake_w0, fake_task): tree.prio becomes 120",
            "rt_mutex_enqueue(fake_lock, fake_w0): root/leftmost become fake_w0",
            "owner PI replacement is conditional on a valid stale pi-tree state",
            "next_lock remains fake_lock; next iteration sees fake_w0.tree.prio == fake_task.prio and stops with detect_deadlock=false",
        ],
        "target_slot_written_by_second_chain": False,
        "remaining_unknown": [
            "whether the first owner pi enqueue can be made valid after the raw-text traversal",
            "exact rb color/parent writes if the conditional stale pi-tree state is supplied",
        ],
    }


def active_route_model() -> dict:
    return {
        "scope": "current worktree defaults",
        "route": "poll(fd=-1,nfds=1)",
        "stale_lock_source": "poll_wqueues+0x198 stack scratch (same-build prior stack audit)",
        "fake_w0_lock": "pselect_user_lock (user VA)",
        "first_chain_lock_identity": "not established as fake_lock or pselect_user_lock",
        "second_chain": "not reachable from this state; do not apply HEAD W=5 second-chain result",
    }


def main() -> None:
    current = state("current worktree", read_current(REL_COMMON), read_current(REL_UTIL), read_current(REL_FOPS))
    head = state("HEAD baseline", read_head(REL_COMMON), read_head(REL_UTIL), read_head(REL_FOPS))
    out = {
        "scope": "offline state separation; no payload execution",
        "states": {"head": head, "current": current},
        "mismatch_detected": head["fake_w0_lock"] != current["fake_w0_lock"]
        or head["PSELECT_ROUTE_NFDS"] != current["PSELECT_ROUTE_NFDS"],
        "head_second_chain": head_second_chain_model(),
        "active_route": active_route_model(),
        "supersedes": [
            "violin-second-chain-user-lock-audit-20260719.md was labeled HEAD W=5 but used the current-worktree user-lock field; it must not be used as a HEAD conclusion",
        ],
        "next_action": "keep HEAD W=5 and active poll analyses separate; only after this split model the conditional fake_lock second-chain rbtree writes",
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
