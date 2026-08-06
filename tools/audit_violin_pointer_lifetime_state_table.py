#!/usr/bin/env python3
"""Build one explicit offline state table for the Violin synthetic chain.

This audit reconciles the active worktree route with the existing PI, second-
lock, rb-postwrite, owner, and pipe reports.  It deliberately does not build,
install, connect to a device, change fd-set parameters, or execute a payload.
Conditional pointer equations remain conditional; they are never promoted to
runtime success.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPLOIT = ROOT / "exploit-repo/IonStack/CVE-2026-43499/exploit"
SRC = EXPLOIT / "src"
KERNEL = ROOT / "kernel-src-wsl/common-gki"
OUT = ROOT / "analysis_outputs"
OUT_JSON = OUT / "violin-pointer-lifetime-state-table-20260722.json"
OUT_MD = OUT / "violin-pointer-lifetime-state-table-20260722.md"

ARTIFACTS = {
    "pi_identity": OUT / "violin-pi-dequeue-identity-20260722.json",
    "second_lock": OUT / "violin-second-kernel-lock-inventory-20260722.json",
    "rb_postwrite": OUT / "violin-rb-erase-postwrite-state-20260722.json",
    "owner": OUT / "violin-fake-fops-owner-module-shape-20260722.json",
    "pipe_first_stage": OUT / "violin-pipe-first-stage-circularity-20260722.json",
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def line(text: str, needle: str) -> int | None:
    for number, value in enumerate(text.splitlines(), 1):
        if needle in value:
            return number
    return None


def has(text: str, *needles: str) -> bool:
    return all(needle in text for needle in needles)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    main_c = (SRC / "main.c").read_text(encoding="utf-8")
    fops_c = (SRC / "fops.c").read_text(encoding="utf-8")
    util_c = (SRC / "util.c").read_text(encoding="utf-8")
    rtmutex_c = (KERNEL / "kernel/locking/rtmutex.c").read_text(encoding="utf-8")
    rtmutex_api_c = (KERNEL / "kernel/locking/rtmutex_api.c").read_text(encoding="utf-8")
    requeue_c = (KERNEL / "kernel/futex/requeue.c").read_text(encoding="utf-8")
    artifacts = {name: load(path) for name, path in ARTIFACTS.items()}
    second_lock_verdict = artifacts["second_lock"].get("verdict", {})
    second_lock_closed = bool(second_lock_verdict.get("closed_distinct_second_lock"))
    second_lock_surface = artifacts["second_lock"].get("evidence", {}).get("named_mutex_surface", {})

    source = {
        "payload_shape": has(
            util_c,
            "put64(p, LOCK_OFF + 0x18, fake_task | 1)",
            "put64(p, LOCK_OFF + 0x08, fake_w0)",
            "put64(p, FAKE_TASK_OFF + pi_blocked_on_off, fake_w0)",
            "FAKE_WAITER_LOCK_OFF, (uint64_t)(uintptr_t)pselect_user_lock",
        ),
        "active_poll_route": has(
            fops_c,
            "poll((struct pollfd *)pselect_user_lock, 1",
            "pfd[0] = -1",
        ),
        "main_requeue": has(main_c, "FUTEX_CMP_REQUEUE_PI", "run_main_route_threads();"),
        "real_requeue_waiter_stack": has(
            requeue_c,
            "struct rt_mutex_waiter rt_waiter;",
            "q.rt_waiter = &rt_waiter;",
            "rt_mutex_start_proxy_lock(&pi_state->pi_mutex",
        ),
        "adjust_pi_reads_next_lock": has(
            rtmutex_api_c,
            "waiter = task->pi_blocked_on;",
            "next_lock = waiter->lock;",
        ),
        "chain_trylocks_wait_lock": has(rtmutex_c, "raw_spin_trylock(&lock->wait_lock)"),
        "first_stage_uses_configfs_write": has(
            fops_c,
            "int fd = open_ashmem_device();",
            "configfs_write_once(fd, binwrite_target, payload, sizeof(payload));",
        ),
        "second_lock_inventory_closed": second_lock_closed,
        "second_lock_named_mutex_surface": second_lock_surface,
    }

    states = [
        {
            "id": "S0",
            "state": "payload-shape",
            "precondition": "fake page is reclaimed and the forged lock/task/waiter fields are read by PI code",
            "evidence": "util.c writes fake_lock.owner=fake_task|1, fake_task.pi_blocked_on=fake_w0, and fake_w0.lock=pselect_user_lock",
            "status": "SHAPE_PRESENT_NOT_ENTRY_PROOF",
            "blocker": "field layout does not establish that the real chain walker enters these addresses",
        },
        {
            "id": "S1",
            "state": "futex-requeue",
            "precondition": "the real futex requeue path creates and consumes its stack waiter",
            "evidence": "FUTEX_CMP_REQUEUE_PI is active; kernel requeue.c uses local rt_waiter and proxy-lock handoff",
            "status": "TRANSPORT_CONFIRMED_ONLY",
            "blocker": "the real waiter identity is not the forged fake_w0 identity",
        },
        {
            "id": "S2",
            "state": "PI-chain entry",
            "precondition": "task/lock/waiter become fake_task/fake_lock/fake_w0 before prerequeue_top_waiter is captured",
            "evidence": "active route is poll(fd=-1,nfds=1); no source edge maps pselect_user_lock to fake_lock",
            "status": "NOT_CLOSED",
            "blocker": "prerequeue_top_waiter remains the real lock-tree waiter, not proven fake_w0",
        },
        {
            "id": "S3",
            "state": "second-lock consumption",
            "precondition": "rt_mutex_adjust_prio_chain reaches fake_w0 and treats fake_w0.lock as rt_mutex",
            "evidence": "kernel reads waiter->lock and raw_spin_trylock(&lock->wait_lock); payload stores a user VA; expanded same-build scan finds 212 named mutex data symbols, all ordinary struct mutex shape",
            "status": "BLOCKED_USER_VA",
            "blocker": "no canonical kernel second-lock with owner, wait_lock, lifetime, and release model; expanded inventory closed_distinct_second_lock=false",
        },
        {
            "id": "S4",
            "state": "shape-1 rb erase",
            "precondition": "synthetic chain reaches fake_w0 and N.rb_left != W at rb_erase",
            "evidence": "existing predecessor report makes N.rb_right (=T) -> fake_fops only conditionally",
            "status": "CONDITIONAL_TARGET_ONLY",
            "blocker": "PI identity and second-lock gates are not closed",
        },
        {
            "id": "S5",
            "state": "post-erase rb_add",
            "precondition": "same waiter is enqueued again into stale fake_task.pi_waiters root",
            "evidence": "existing postwrite model follows W -> F -> W without reaching NULL",
            "status": "NON_TERMINATING_CONDITIONAL",
            "blocker": "no safe userspace return; the target write cannot be treated as usable",
        },
        {
            "id": "S6",
            "state": "fops owner/transport",
            "precondition": "T is actually changed to fake_fops and fd is opened through that table",
            "evidence": "initial owner/read_iter/write_iter are prepared, but shape-1 owner=N is not a valid module pointer and first write is downstream",
            "status": "NOT_CLOSED",
            "blocker": "no independent first-stage pipe sink or validated owner repair sequence",
        },
    ]

    verdict = {
        "complete": False,
        "name": "FULL_SYNTHETIC_CHAIN_NOT_CLOSED",
        "decision": "Do not enable shape-1 or rerun full-route until S2-S6 are simultaneously closed.",
        "runtime_allowed": False,
    }
    result = {
        "audit": "Violin pointer/lifetime synthetic-chain state table",
        "date": "2026-07-22",
        "mode": "offline-source-and-existing-artifacts-only",
        "runtime_allowed": False,
        "sources": {
            "main_c": str(SRC / "main.c"),
            "fops_c": str(SRC / "fops.c"),
            "util_c": str(SRC / "util.c"),
            "rtmutex_c": str(KERNEL / "kernel/locking/rtmutex.c"),
            "rtmutex_api_c": str(KERNEL / "kernel/locking/rtmutex_api.c"),
            "requeue_c": str(KERNEL / "kernel/futex/requeue.c"),
        },
        "source_checks": source,
        "evidence_lines": {
            "main_requeue": line(main_c, "int requeue_ret = futex_op"),
            "active_poll": line(fops_c, "poll((struct pollfd *)pselect_user_lock, 1"),
            "poll_fd_minus_one": line(fops_c, "pfd[0] = -1"),
            "fake_w0_lock": line(util_c, "FAKE_WAITER_LOCK_OFF, (uint64_t)(uintptr_t)pselect_user_lock"),
            "adjust_pi_next_lock": line(rtmutex_api_c, "next_lock = waiter->lock;"),
            "chain_trylock": line(rtmutex_c, "raw_spin_trylock(&lock->wait_lock)"),
            "stack_waiter": line(requeue_c, "struct rt_mutex_waiter rt_waiter;"),
        },
        "artifacts": {
            name: {"path": str(path), "sha256": sha256(path), "verdict": artifacts[name].get("verdict")}
            for name, path in ARTIFACTS.items()
        },
        "states": states,
        "verdict": verdict,
        "next_gate": "S3's expanded second-lock inventory is negative; do not substitute ordinary mutexes. Close S2, S4-S6 in one pointer/lifetime/termination table, or archive the fops anchor and search for a different independent first-stage sink.",
    }
    OUT.mkdir(exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md = [
        "# Violin pointer/lifetime synthetic-chain state table (2026-07-22)",
        "",
        "**Mode:** offline source/kernel/artifact reconciliation only; no build, install, device run, fd-set change, or payload execution.",
        "",
        "## State table",
        "",
        "| State | Precondition | Observed evidence | Status | Blocker |",
        "| --- | --- | --- | --- | --- |",
    ]
    for state in states:
        md.append(
            f"| `{state['id']} {state['state']}` | {state['precondition']} | {state['evidence']} | **{state['status']}** | {state['blocker']} |"
        )
    md += [
        "",
        "## Verdict",
        "",
        "**FULL_SYNTHETIC_CHAIN_NOT_CLOSED**. S0/S1 only describe payload shape and ordinary requeue transport. S2 has no active fake-lock edge; S3 consumes a user VA as a kernel rt_mutex and the expanded same-build inventory found no distinct second lock (212 named mutex objects all matched ordinary struct mutex layout); S4 is conditional; S5 is non-terminating under the same-waiter model; S6 has no independent first-stage transport.",
        "",
        "## Next gate",
        "",
        result["next_gate"],
    ]
    OUT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps({"json": str(OUT_JSON), "markdown": str(OUT_MD), "verdict": verdict}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
