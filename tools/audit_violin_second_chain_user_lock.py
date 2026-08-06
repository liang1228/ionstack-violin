#!/usr/bin/env python3
"""Historical offline audit of the second rt_mutex chain iteration.

This is a source/raw-layout state model only.  It does not open a device,
invoke adb, build/install a payload, or dereference the user pointer.

Scope (superseded for HEAD):
  * current-worktree user-lock field only;
  * matching 6.6 rt_mutex_adjust_prio_chain()/rt_mutex_setprio() source;
  * Violin init_task priority from both source and the extracted same-build
    kernel image.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_KERNEL = PROJECT_ROOT / "analysis_outputs" / "ota_full" / "boot_parse" / "boot.img.kernel"
INIT_TASK_OFF = 0x20DE280
INIT_TASK_PRIO_OFF = 0x84
INIT_TASK_STATIC_PRIO_OFF = 0x88
INIT_TASK_NORMAL_PRIO_OFF = 0x8C

FAKE_TASK = "fake_task"
FAKE_W0 = "fake_w0"
STALE = "stale_waiter"
INIT_TASK = "init_task"
PSELECT_USER_LOCK = "pselect_user_lock (user VA)"

FAKE_TASK_PRIO = 120
FAKE_TASK_NORMAL_PRIO = 120
FAKE_W0_TREE_PRIO = 130


def read_u32(offset: int) -> int:
    data = RAW_KERNEL.read_bytes()[offset : offset + 4]
    if len(data) != 4:
        raise ValueError(f"short read at 0x{offset:x}")
    return struct.unpack("<I", data)[0]


def init_task_audit() -> dict:
    source = {
        "prio": 120,
        "static_prio": 120,
        "normal_prio": 120,
        "source": "init/init_task.c:80-82; DEFAULT_PRIO=120",
    }
    raw = {
        "image": str(RAW_KERNEL.relative_to(PROJECT_ROOT)),
        "init_task_offset": hex(INIT_TASK_OFF),
        "prio": read_u32(INIT_TASK_OFF + INIT_TASK_PRIO_OFF),
        "static_prio": read_u32(INIT_TASK_OFF + INIT_TASK_STATIC_PRIO_OFF),
        "normal_prio": read_u32(INIT_TASK_OFF + INIT_TASK_NORMAL_PRIO_OFF),
        "fields": {
            "prio": hex(INIT_TASK_PRIO_OFF),
            "static_prio": hex(INIT_TASK_STATIC_PRIO_OFF),
            "normal_prio": hex(INIT_TASK_NORMAL_PRIO_OFF),
        },
    }
    return {
        "source": source,
        "raw": raw,
        "match": all(
            source[k] == raw[k] for k in ("prio", "static_prio", "normal_prio")
        ),
    }


def scheduler_owner_step(init_prio: int) -> dict:
    effective = min(FAKE_TASK_NORMAL_PRIO, init_prio)
    pi_top_task_before = INIT_TASK
    base_early_return = (
        pi_top_task_before == INIT_TASK
        and effective == FAKE_TASK_PRIO
        and FAKE_TASK_PRIO >= 100  # dl_prio(120) is false on this kernel
    )
    return {
        "call": "rt_mutex_adjust_prio(lock=fake_lock, p=fake_task)",
        "task_has_pi_waiters": True,
        "task_top_pi_waiter": STALE,
        "pi_task_donor": INIT_TASK,
        "p_normal_prio": FAKE_TASK_NORMAL_PRIO,
        "pi_task_prio": init_prio,
        "effective_prio=min(p.normal_prio, pi_task.prio)": effective,
        "p_prio_before": FAKE_TASK_PRIO,
        "p_pi_top_task_before": INIT_TASK,
        "rt_mutex_setprio_base_early_return": base_early_return,
        "vendor_force_update": (
            "unknown restricted hook; if update=1, fake_task rq path is entered"
        ),
        "scheduler_state_mutation_without_force_update": not base_early_return,
        "chain_walk_continues_after_setprio": True,
        "source": [
            "kernel/locking/rtmutex.c:rt_mutex_adjust_prio",
            "kernel/sched/core.c:7187-7210",
        ],
    }


def conditional_second_round(init_prio: int) -> dict:
    owner_step = scheduler_owner_step(init_prio)
    events = [
        "owner branch supplies next_lock=task_blocked_on_lock(fake_task)",
        "fake_task.pi_blocked_on=fake_w0, so next_lock=fake_w0.lock",
        "fake_w0.lock=pselect_user_lock (user VA)",
        "top_waiter from first iteration remains stale_waiter",
        "second iteration compares next_lock == waiter->lock: true",
        "conditional pi enqueue makes task_top_pi_waiter(fake_task)=stale_waiter",
        "fake_w0.tree.prio=130 != fake_task.prio=120",
        "chain reaches lock=waiter->lock=pselect_user_lock",
        "raw_spin_trylock(&lock->wait_lock) would directly access user VA + 0",
    ]
    return {
        "assumption": (
            "first-transition owner pi enqueue somehow bypasses the prior "
            "noop_llseek non-canonical child"
        ),
        "owner_scheduler_step": owner_step,
        "chain_arguments": {
            "chwalk": "RT_MUTEX_MIN_CHAINWALK",
            "orig_lock": "NULL",
            "orig_waiter": "NULL",
            "detect_deadlock": False,
            "second_iteration_task": FAKE_TASK,
            "second_iteration_waiter": FAKE_W0,
            "second_iteration_top_waiter": STALE,
            "next_lock": PSELECT_USER_LOCK,
            "waiter_lock": PSELECT_USER_LOCK,
        },
        "pre_trylock_checks": {
            "next_lock_equals_waiter_lock": True,
            "top_waiter_equals_task_top_pi_waiter": True,
            "waiter_node_equal": False,
        },
        "hard_blocker": {
            "operation": "raw_spin_trylock(&pselect_user_lock->wait_lock)",
            "address": PSELECT_USER_LOCK,
            "kernel_object_proven": False,
            "result": (
                "direct kernel dereference of a user VA; no valid rt_mutex "
                "wait_lock/owner/waiters object is established"
            ),
        },
        "events": events,
        "status": "user_va_lock_dereference_before_second_requeue",
    }


def strict_path() -> dict:
    return {
        "upstream": "violin-rtmutex-full-transition-audit-20260719",
        "owner_pi_enqueue_reached": False,
        "second_chain_reached": False,
        "status": "not_reached_strict_upstream_noncanonical",
        "reason": (
            "pi rb_add traversal reaches noop_llseek raw +0x08 "
            "0xd503233fe61887de before rb_link_node/rb_insert_color"
        ),
    }


def main() -> None:
    init = init_task_audit()
    init_prio = init["raw"]["prio"]
    output = {
        "scope": {
            "candidate": "current-worktree user-lock field only (historical; not HEAD)",
            "active_worktree": "poll(fd=-1,nfds=1), not this pselect candidate",
            "mode": "offline source/raw state model; no payload execution",
        },
        "status": "superseded_by_violin_route_state_split_audit",
        "superseded_by": "analysis_outputs/violin-route-state-split-audit-20260719.md",
        "init_task_priority": init,
        "strict_path": strict_path(),
        "conditional_second_round": conditional_second_round(init_prio),
        "conclusions": [
            "init_task and fake_task both use prio/normal_prio 120",
            "rt_mutex_setprio base path early-returns when the vendor force-update hook leaves update=0",
            "that early return does not stop rt_mutex_adjust_prio_chain from reading fake_task.pi_blocked_on",
            "the second iteration therefore reaches fake_w0.lock only if the first owner pi enqueue was already made valid",
            "fake_w0.lock is a user VA, so the next lock operation is not a valid kernel rt_mutex consumption",
        ],
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
