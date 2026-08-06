#!/usr/bin/env python3
"""Offline second-lock transition matrix for the Violin pselect-256 candidate."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UTIL = ROOT / "exploit-repo/IonStack/CVE-2026-43499/exploit/src/util.c"

FAKE_LOCK = 0xFFFFFF81E79984D0
USER_LOCK = 0x0000007FFF001000
SECOND_LOCK = 0xFFFFFF81E7998C00


def is_kernel(value: int) -> bool:
    return (value >> 48) == 0xFFFF


def evaluate(name: str, next_lock: int, owner_present: bool) -> dict:
    addressable = is_kernel(next_lock)
    same_orig = next_lock == FAKE_LOCK
    if not addressable:
        result = "BLOCKED_[5]_USER_VA_LOCK"
    elif same_orig:
        # rt_mutex_adjust_pi() passes orig_lock=NULL.  Keep the owner/top-task
        # gate conditional instead of treating same fake_lock as an automatic
        # lock==orig_lock deadlock.
        result = "CHECK_[6]_OWNER_TOP_TASK; ORIG_LOCK_NULL"
    elif not owner_present:
        result = "STOP_[9]_SECOND_LOCK_OWNER_MISSING"
    else:
        result = "SECOND_LOCK_MODEL_REQUIRED"
    return {
        "case": name,
        "next_lock": f"0x{next_lock:016x}",
        "canonical_kernel": addressable,
        "same_as_orig_lock": same_orig,
        "owner_present_assumption": owner_present,
        "result": result,
    }


def main() -> None:
    util = UTIL.read_text(encoding="utf-8")
    result = {
        "scope": "offline rt_mutex_adjust_prio_chain second-lock matrix only",
        "source_fact": {
            "fake_w0_lock_is_user_va": "FAKE_WAITER_LOCK_OFF, (uint64_t)(uintptr_t)pselect_user_lock" in util,
            "stale_lock_candidate": "256-fd ex[3] -> fake_lock",
        },
        "source_points": {
            "step_5": "raw_spin_trylock(&lock->wait_lock)",
            "step_6": "lock == orig_lock || rt_mutex_owner(lock) == top_task",
            "step_9": "!rt_mutex_owner(lock) -> chain end",
        },
        "cases": [
            evaluate("current_payload_user_lock", USER_LOCK, False),
            evaluate("hypothetical_same_fake_lock", FAKE_LOCK, True),
            evaluate("hypothetical_distinct_kernel_lock_without_owner", SECOND_LOCK, False),
            evaluate("hypothetical_distinct_kernel_lock_with_owner_model", SECOND_LOCK, True),
        ],
        "decision": "No case currently reaches a write claim: current payload stops at user VA; same fake_lock requires the owner/top-task gate because orig_lock is NULL; distinct lock needs a complete owner/waiters lifetime model.",
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
