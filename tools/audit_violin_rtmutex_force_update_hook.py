#!/usr/bin/env python3
"""Offline audit of the rt_mutex_setprio vendor-hook fork.

The matching GKI source contains restricted Android scheduler hooks but not
their vendor callback bodies.  This script records that boundary and models
both possible values of the force-update flag.  It performs no device I/O,
payload build, installation, or execution.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "kernel-src-wsl" / "common-gki"
KALLSYMS = ROOT / "kallsyms.txt"

HOOK_FORCE = "android_rvh_rtmutex_force_update"
HOOK_PREPARE = "android_rvh_rtmutex_prepare_setprio"
USER_LOCK = "pselect_user_lock (user VA)"


def line_hits(path: Path, patterns: list[str]) -> dict[str, list[int]]:
    text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    result: dict[str, list[int]] = {}
    for pattern in patterns:
        rx = re.compile(pattern)
        result[pattern] = [i + 1 for i, line in enumerate(text) if rx.search(line)]
    return result


def source_boundary() -> dict:
    paths = {
        "hook_declarations": KERNEL / "include" / "trace" / "hooks" / "sched.h",
        "hook_exports": KERNEL / "kernel" / "sched" / "vendor_hooks.c",
        "setprio_callsite": KERNEL / "kernel" / "sched" / "core.c",
    }
    hits = {
        key: line_hits(path, [HOOK_FORCE, HOOK_PREPARE])
        for key, path in paths.items()
    }

    # The source snapshot has no callback registration body.  Keep this
    # explicit instead of treating an absent grep hit as proof about vendor
    # modules, which are outside the common-GKI tree.
    registration_patterns = [
        rf"register_trace_.*{HOOK_FORCE}",
        rf"register_trace_.*{HOOK_PREPARE}",
        rf"trace_android_rvh_.*{HOOK_FORCE}",
        rf"trace_android_rvh_.*{HOOK_PREPARE}",
    ]
    registration_hits: dict[str, list[str]] = {}
    for path in [KERNEL / "kernel", KERNEL / "include"]:
        for file in path.rglob("*"):
            if not file.is_file() or "scripts" in file.parts or "tools" in file.parts:
                continue
            text = file.read_text(encoding="utf-8", errors="replace")
            for pattern in registration_patterns[:2]:
                if re.search(pattern, text):
                    registration_hits.setdefault(pattern, []).append(
                        str(file.relative_to(ROOT))
                    )

    symbols = {}
    if KALLSYMS.exists():
        lines = KALLSYMS.read_text(encoding="utf-8", errors="replace").splitlines()
        for name in [
            "__traceiter_android_rvh_rtmutex_force_update",
            "__traceiter_android_rvh_rtmutex_prepare_setprio",
            "__tracepoint_android_rvh_rtmutex_force_update",
            "__tracepoint_android_rvh_rtmutex_prepare_setprio",
        ]:
            symbols[name] = [line for line in lines if re.search(rf"\s{name}$", line)]

    return {
        "files": {key: str(path.relative_to(ROOT)) for key, path in paths.items()},
        "hook_hits": hits,
        "callback_registration_hits_in_common_gki": registration_hits,
        "same_build_kallsyms": symbols,
        "boundary": (
            "common-GKI declares/exports/calls the hooks, but vendor callback bodies "
            "are outside this source snapshot; update cannot be fixed to 0 from source alone"
        ),
    }


def fork_model() -> dict:
    common = {
        "call": "rt_mutex_setprio(fake_task, INIT_TASK)",
        "p_normal_prio": 120,
        "pi_task_prio": 120,
        "effective_prio": 120,
        "p_prio": 120,
        "p_pi_top_task": "INIT_TASK",
    }
    return {
        "update_0": {
            **common,
            "early_return": True,
            "chain_walk": "continues",
            "next_lock": USER_LOCK,
            "next_operation": "raw_spin_trylock(&pselect_user_lock->wait_lock)",
            "status": "user_va_lock_dereference",
        },
        "update_1": {
            **common,
            "early_return": False,
            "chain_walk": "not reached until rt_mutex_setprio finishes",
            "entered_operations": [
                "__task_rq_lock(fake_task, &rf)",
                "update_rq_clock(rq)",
                "task_on_rq_queued(fake_task)",
                "task_current(rq, fake_task)",
                "fake_task sched_class/dequeue/enqueue/check_class_changed path",
            ],
            "payload_fields_proven": [
                "prio/normal_prio",
                "pi_top_task",
                "pi_blocked_on",
                "sched_class pointer",
            ],
            "payload_fields_not_proven": [
                "task CPU / rq association",
                "on_rq / state / scheduling entity",
                "dl and rt scheduler substructures",
                "valid rq lock and task lifetime invariants",
            ],
            "status": "fake_task_rq_path_unproven_before_chain_second_round",
        },
    }


def main() -> None:
    out = {
        "scope": {
            "build": "Violin GKI 6.6.77",
            "candidate": "current-worktree user-lock field only (historical; not HEAD)",
            "active_route": "poll(fd=-1,nfds=1), not this pselect candidate",
            "execution": "offline only",
        },
        "status": "superseded_for_HEAD_by_route_state_split",
        "superseded_by": "analysis_outputs/violin-route-state-split-audit-20260719.md",
        "source_boundary": source_boundary(),
        "fork_model": fork_model(),
        "conclusion": [
            "The GKI source cannot establish vendor force_update=0 because restricted hook callbacks may live in vendor modules.",
            "If update=0, the previous second-chain user-VA lock blocker remains unchanged.",
            "If update=1, rt_mutex_setprio first consumes fake_task as a scheduler task; required rq/task fields are not forged or verified, so no valid route to the second lock iteration is established.",
        ],
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
