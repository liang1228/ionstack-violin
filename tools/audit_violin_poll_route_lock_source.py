#!/usr/bin/env python3
"""Offline closure audit for the active Violin poll-route lock source.

The active worktree calls poll() with a one-entry pollfd whose fd is -1.  This
script checks the same-build select/poll source and records whether the user
pointer can reach poll_wqueues or a wait-queue entry.  It never builds, runs,
or changes the exploit.
"""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPLOIT = ROOT / "exploit-repo" / "IonStack" / "CVE-2026-43499" / "exploit"
SRC = EXPLOIT / "src"
FOPS_C = SRC / "fops.c"
SELECT_C = ROOT / "kernel-src-wsl" / "common-gki" / "fs" / "select.c"
POLL_H = ROOT / "kernel-src-wsl" / "common-gki" / "include" / "linux" / "poll.h"
OUT_DIR = ROOT / "analysis_outputs"
OUT_JSON = OUT_DIR / "violin-poll-route-lock-source-audit-20260722.json"
OUT_MD = OUT_DIR / "violin-poll-route-lock-source-audit-20260722.md"


def lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def line_of(path: Path, needle: str) -> int | None:
    for number, line in enumerate(lines(path), 1):
        if needle in line:
            return number
    return None


def line_after(path: Path, start_needle: str, target_needle: str) -> int | None:
    active = False
    for number, line in enumerate(lines(path), 1):
        if start_needle in line:
            active = True
        if active and target_needle in line:
            return number
    return None


def main() -> int:
    evidence = {
        "active_route": {
            "poll_call": line_of(FOPS_C, "int ret = poll((struct pollfd *)pselect_user_lock, 1"),
            "fd_minus_one": line_of(FOPS_C, "pfd[0] = -1"),
            "user_pointer_role_comment": line_of(FOPS_C, "pselect_user_lock, nfds=1"),
        },
        "poll_source": {
            "negative_fd_skip": line_of(SELECT_C, "if (fd < 0)"),
            "negative_fd_goto_out": line_after(SELECT_C, "if (fd < 0)", "goto out;"),
            "vfs_poll": line_of(SELECT_C, "mask = vfs_poll(f.file, pwait)"),
            "poll_initwait": line_of(SELECT_C, "void poll_initwait(struct poll_wqueues *pwq)"),
            "init_inline_index_zero": line_of(SELECT_C, "pwq->inline_index = 0"),
            "do_poll_schedule": line_of(SELECT_C, "if (!poll_schedule_timeout(wait, TASK_INTERRUPTIBLE, to, slack))"),
            "poll_freewait": line_of(SELECT_C, "poll_freewait(&table)"),
        },
        "poll_layout": {
            "poll_wqueues_struct": line_of(POLL_H, "struct poll_wqueues {"),
            "poll_table": line_of(POLL_H, "poll_table pt;"),
            "table": line_of(POLL_H, "struct poll_table_page *table;"),
            "polling_task": line_of(POLL_H, "struct task_struct *polling_task;"),
            "inline_index": line_of(POLL_H, "int inline_index;"),
            "inline_entries": line_of(POLL_H, "struct poll_table_entry inline_entries"),
        },
    }

    result = {
        "audit": "Violin active poll route lock source",
        "date": "2026-07-22",
        "mode": "offline-source-only",
        "sources": {"fops_c": str(FOPS_C), "select_c": str(SELECT_C), "poll_h": str(POLL_H)},
        "evidence": evidence,
        "state_model": {
            "user_pointer_role": "pselect_user_lock is used only as the userspace pollfd array; fd=-1 is copied into the kernel pollfd and exits do_pollfd before fdget/vfs_poll",
            "wait_registration": "no fd reaches vfs_poll, so no f_op->poll/poll_wait path and no poll_table_entry is registered; poll_initwait sets inline_index=0 and table=NULL",
            "sleep": "do_poll may still call poll_schedule_timeout, but that consumes poll_wqueues state and schedule_hrtimeout; it does not copy pselect_user_lock into a rt_mutex_waiter.lock field",
            "pi_mapping": "fake_w0->lock=pselect_user_lock is not established by the active poll route; any PI chain using that value remains an unproven independent condition",
        },
        "verdict": {
            "active_poll_user_lock_overlay": "NOT-CLOSED",
            "active_poll_fd_minus_one_wait_registration": "CLOSED-NO-WAIT-ENTRY",
            "active_poll_to_fake_w0_lock": "NO-SOURCE-EDGE",
            "pselect_model": "separate conditional model; do not mix with active poll evidence",
            "runtime_allowed": False,
            "next_gate": "keep the active route at offline-only; either prove a distinct poll stack/UAF edge from same-build disassembly or archive the current pselect_user_lock PI mapping and search another sink",
        },
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md = """# Violin active poll-route lock-source audit (2026-07-22)\n\n"""
    md += "**Mode:** same-build source/layout only; no payload build, device connection, fd-set change, or route execution.\n\n"
    md += "## Result\n\n"
    md += "The active worktree passes `pselect_user_lock` only as the userspace `pollfd` array and sets its first `fd` to `-1`. Same-build `do_pollfd()` takes `if (fd < 0) goto out` before `fdget()` and `vfs_poll()`. Therefore this route registers no file poll waiter and has no source edge from the user pointer into `poll_wqueues`, `poll_table_entry`, or a `rt_mutex_waiter.lock` field.\n\n"
    md += "`poll_initwait()` initializes the poll callback/task/error/table state and sets `inline_index=0`; the route may still sleep in `poll_schedule_timeout()`, but that consumes the `poll_wqueues` state and `schedule_hrtimeout()` rather than copying the user pointer into a PI waiter. Thus the active payload assignment `fake_w0->lock=pselect_user_lock` is not established by the active poll route.\n\n"
    md += "## Verdict / next gate\n\n"
    md += "Active poll route: **NO-SOURCE-EDGE** from `pselect_user_lock` to `fake_w0->lock`; fd=-1 wait registration is **CLOSED-NO-WAIT-ENTRY**. The pselect overlay remains a separate conditional model and must not be combined with the poll runtime log. The optimal next move is an offline same-build disassembly check for a distinct poll-stack/UAF edge; if none exists, archive this PI mapping and search a different write sink.\n"
    OUT_MD.write_text(md, encoding="utf-8")
    print(json.dumps({"json": str(OUT_JSON), "markdown": str(OUT_MD), "verdict": result["verdict"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
