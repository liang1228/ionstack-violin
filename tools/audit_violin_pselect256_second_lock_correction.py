#!/usr/bin/env python3
"""Corrected offline matrix for the Violin pselect-256 second-lock model.

The older 2026-07-19 report treated ``fake_lock`` as ``orig_lock``.  The
same-build ``rt_mutex_adjust_pi()`` call passes ``orig_lock = NULL``; this
script keeps that historical report immutable and records the corrected
decision boundary in a dated artifact.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "analysis_outputs"
UTIL = ROOT / "exploit-repo/IonStack/CVE-2026-43499/exploit/src/util.c"
API = ROOT / "kernel-src-wsl/common-gki/kernel/locking/rtmutex_api.c"
COMMON = ROOT / "kernel-src-wsl/common-gki/kernel/locking/rtmutex_common.h"
RT = ROOT / "kernel-src-wsl/common-gki/kernel/locking/rtmutex.c"

FAKE_LOCK = 0xFFFFFF81E79984D0
USER_LOCK = 0x0000007FFF001000
SECOND_LOCK = 0xFFFFFF81E7998C00


def is_kernel(value: int) -> bool:
    return (value >> 48) == 0xFFFF


def evaluate(name: str, next_lock: int, owner_present: bool) -> dict:
    addressable = is_kernel(next_lock)
    same_fake_lock = next_lock == FAKE_LOCK
    if not addressable:
        result = "BLOCKED_[5]_USER_VA_LOCK"
    elif not owner_present:
        result = "STOP_[9]_SECOND_LOCK_OWNER_MISSING"
    elif same_fake_lock:
        # orig_lock is NULL in rt_mutex_adjust_pi(), so the old [6] claim is
        # inapplicable.  The owner/top_task test at [6] still needs closure.
        result = "CHECK_[6]_OWNER_TOP_TASK; ORIG_LOCK_NULL"
    else:
        result = "SECOND_LOCK_MODEL_REQUIRED"
    return {
        "case": name,
        "next_lock": f"0x{next_lock:016x}",
        "canonical_kernel": addressable,
        "same_as_fake_lock": same_fake_lock,
        "owner_present_assumption": owner_present,
        "result": result,
    }


def main() -> None:
    util = UTIL.read_text(encoding="utf-8")
    api = API.read_text(encoding="utf-8")
    common = COMMON.read_text(encoding="utf-8")
    rt = RT.read_text(encoding="utf-8")
    result = {
        "scope": "offline correction of the Violin pselect-256 rt_mutex second-lock matrix",
        "status": "historical_same_orig_lock_claim_revoked",
        "runtime_allowed": False,
        "source_fact": {
            "fake_w0_lock_is_user_va": "FAKE_WAITER_LOCK_OFF, (uint64_t)(uintptr_t)pselect_user_lock" in util,
            "adjust_pi_passes_orig_lock_null": bool(re.search(r"rt_mutex_adjust_prio_chain\(task,\s*RT_MUTEX_MIN_CHAINWALK,\s*NULL,", api)),
            "rt_mutex_adjust_prio_chain_has_owner_top_task_gate": "lock == orig_lock || rt_mutex_owner(lock) == top_task" in rt,
            "stale_lock_candidate": "256-fd ex[3] -> fake_lock",
        },
        "source_points": {
            "step_5": "raw_spin_trylock(&lock->wait_lock)",
            "step_6": "lock == orig_lock || rt_mutex_owner(lock) == top_task",
            "step_9": "!rt_mutex_owner(lock) -> chain end",
            "orig_lock": "NULL from rt_mutex_adjust_pi()",
        },
        "cases": [
            evaluate("current_payload_user_lock", USER_LOCK, False),
            evaluate("hypothetical_same_fake_lock_with_owner", FAKE_LOCK, True),
            evaluate("hypothetical_distinct_kernel_lock_without_owner", SECOND_LOCK, False),
            evaluate("hypothetical_distinct_kernel_lock_with_owner_model", SECOND_LOCK, True),
        ],
        "decision": (
            "The historical same-orig-lock deadlock claim is invalid because orig_lock is NULL. "
            "A same fake_lock candidate still requires the owner==top_task gate and a complete "
            "post-requeue tree/lifetime model; it does not establish a write. A distinct lock "
            "still requires owner, waiters, lifetime, and consumer closure."
        ),
        "next_gate": (
            "Do not treat same_fake_lock as an automatic [6] stop. Keep the active poll route "
            "offline-only and either close the distinct-lock model from same-build evidence or "
            "archive the rb/PI branch and search a different write sink."
        ),
    }
    OUT.mkdir(exist_ok=True)
    (OUT / "violin-pselect256-second-lock-correction-20260722.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    lines = [
        "# Violin pselect-256 second-lock correction (2026-07-22)",
        "",
        "## Verdict",
        "",
        "- Historical `same_fake_lock -> STOP_[6]_SAME_ORIG_LOCK_DEADLOCK` is revoked.",
        "- Same-build `rt_mutex_adjust_pi()` passes `orig_lock = NULL`; the [6] owner/top-task gate remains conditional.",
        "- The current payload still uses a user VA for `fake_w0->lock`, so it remains blocked at [5].",
        "- No distinct kernel lock has a closed owner/waiters/lifetime/consumer model.",
        "- This is an offline correction only; no payload or device action was run.",
        "",
        "## Cases",
        "",
        "| Case | Result |",
        "|---|---|",
    ]
    for case in result["cases"]:
        lines.append(f"| `{case['case']}` | `{case['result']}` |")
    lines += [
        "",
        "## Decision",
        "",
        result["decision"],
        "",
        "## Next gate",
        "",
        result["next_gate"],
        "",
        "## Evidence anchors",
        "",
        "- `kernel-src-wsl/common-gki/kernel/locking/rtmutex_api.c`: `rt_mutex_adjust_pi()` calls `rt_mutex_adjust_prio_chain(..., NULL, ...)`.",
        "- `kernel-src-wsl/common-gki/kernel/locking/rtmutex.c`: chain walk condition includes `lock == orig_lock || rt_mutex_owner(lock) == top_task`.",
        "- `exploit-repo/IonStack/CVE-2026-43499/exploit/src/util.c`: current fake waiter lock is `pselect_user_lock`.",
    ]
    (OUT / "violin-pselect256-second-lock-correction-20260722.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
