#!/usr/bin/env python3
"""Audit PI dequeue/top-waiter identity for the Violin shape-1 branch.

This is an offline source/layout reconciliation only.  It does not build,
install, connect to a device, change fd-set parameters, or execute a payload.

The important distinction in this pass is between:

* ``task->pi_blocked_on`` (the waiter used by the chain walker), and
* ``prerequeue_top_waiter`` (captured from ``rt_mutex_top_waiter(lock)``
  immediately before the lock waiter-tree requeue).

The latter is not implied by the former.  Shape-1 reaches the fops slot only
if the synthetic ``fake_lock``/``fake_task``/``fake_w0`` identity is actually
entered by the PI chain.
"""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPLOIT = ROOT / "exploit-repo/IonStack/CVE-2026-43499/exploit"
KERNEL = ROOT / "kernel-src-wsl/common-gki"
SRC_MAIN = EXPLOIT / "src/main.c"
SRC_FOPS = EXPLOIT / "src/fops.c"
SRC_UTIL = EXPLOIT / "src/util.c"
RTMUTEX_C = KERNEL / "kernel/locking/rtmutex.c"
RTMUTEX_API_C = KERNEL / "kernel/locking/rtmutex_api.c"
FUTEX_REQUEUE_C = KERNEL / "kernel/futex/requeue.c"
PI_ENTRY = ROOT / "tools/audit_violin_pi_chain_entry.py"
PI256 = ROOT / "analysis_outputs/violin-pselect256-pi-identity-20260719.json"
SHAPE = ROOT / "analysis_outputs/violin-pselect-custom-shape-state-20260722.json"
LIST_GATE = ROOT / "analysis_outputs/violin-misc-list-predecessor-20260722.json"
OUT = ROOT / "analysis_outputs"


def line_number(text: str, needle: str) -> int | None:
    for number, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return number
    return None


def require_tokens(text: str, tokens: tuple[str, ...]) -> bool:
    return all(token in text for token in tokens)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    main_c = SRC_MAIN.read_text(encoding="utf-8")
    fops_c = SRC_FOPS.read_text(encoding="utf-8")
    util_c = SRC_UTIL.read_text(encoding="utf-8")
    rtmutex_c = RTMUTEX_C.read_text(encoding="utf-8")
    rtmutex_api_c = RTMUTEX_API_C.read_text(encoding="utf-8")
    requeue_c = FUTEX_REQUEUE_C.read_text(encoding="utf-8")
    pi256 = load(PI256)
    shape = load(SHAPE)
    list_gate = load(LIST_GATE)

    source_checks = {
        # User route and operation selected by the current worktree.
        "active_route_is_poll": "poll((struct pollfd *)pselect_user_lock, 1" in fops_c,
        "active_poll_fd_is_minus_one": "pfd[0] = -1" in fops_c,
        "active_main_calls_route_threads": "run_main_route_threads();" in main_c,
        "main_uses_cmp_requeue_pi": "FUTEX_CMP_REQUEUE_PI" in main_c,
        # The payload fields that are relevant to the synthetic branch.
        "fake_lock_owner_is_fake_task_pi": "put64(p, LOCK_OFF + 0x18, fake_task | 1)" in util_c,
        "fake_lock_waiters_root_is_fake_w0": "put64(p, LOCK_OFF + 0x08, fake_w0)" in util_c,
        "fake_lock_waiters_leftmost_is_fake_w0": "put64(p, LOCK_OFF + 0x10, fake_w0)" in util_c,
        "fake_task_blocked_on_is_fake_w0": "put64(p, FAKE_TASK_OFF + pi_blocked_on_off, fake_w0)" in util_c,
        "fake_w0_task_is_fake_or_init_task_source_present": "FAKE_WAITER_TASK_OFF, waiter_task" in util_c,
        "fake_w0_lock_is_user_va": "FAKE_WAITER_LOCK_OFF, (uint64_t)(uintptr_t)pselect_user_lock" in util_c,
        "shape1_parent_is_predecessor": "fake_parent = write_target - 8" in util_c,
        "shape1_right_child_is_write_value": "fake_right = write_value" in util_c,
        "shape1_left_child_is_null": "fake_left = 0" in util_c,
        # futex_wait_requeue_pi() supplies a real stack waiter to requeue.
        "futex_waiter_is_stack_object": require_tokens(
            requeue_c,
            (
                "struct rt_mutex_waiter rt_waiter;",
                "q.rt_waiter = &rt_waiter;",
                "rt_mutex_wait_proxy_lock(pi_mutex, to, &rt_waiter);",
            ),
        ),
        "requeue_passes_rt_waiter_to_proxy_lock": "this->rt_waiter" in requeue_c
        and "rt_mutex_start_proxy_lock(&pi_state->pi_mutex" in requeue_c,
        # task_blocks_on_rt_mutex() establishes the real waiter identity.
        "task_blocks_on_sets_waiter_task_and_lock": require_tokens(
            rtmutex_c,
            (
                "waiter->task = task;",
                "waiter->lock = lock;",
                "task->pi_blocked_on = waiter;",
            ),
        ),
        "task_blocks_enqueues_waiter_on_lock": "rt_mutex_enqueue(lock, waiter);" in rtmutex_c,
        # Exact source of prerequeue_top_waiter and the two dequeue branches.
        "prerequeue_captured_from_lock_top": "prerequeue_top_waiter = rt_mutex_top_waiter(lock);" in rtmutex_c,
        "prerequeue_dequeued_from_task_pi_tree": "rt_mutex_dequeue_pi(task, prerequeue_top_waiter);" in rtmutex_c,
        "same_waiter_branch_gate": "if (waiter == rt_mutex_top_waiter(lock))" in rtmutex_c,
        "old_top_branch_gate": "else if (prerequeue_top_waiter == waiter)" in rtmutex_c,
        "sched_adjust_pi_reads_blocked_on": require_tokens(
            rtmutex_api_c,
            (
                "waiter = task->pi_blocked_on;",
                "next_lock = waiter->lock;",
                "rt_mutex_adjust_prio_chain(task, RT_MUTEX_MIN_CHAINWALK, NULL,",
            ),
        ),
    }

    evidence_lines = {
        "main_requeue": line_number(main_c, "int requeue_ret = futex_op"),
        "active_poll": line_number(fops_c, "poll((struct pollfd *)pselect_user_lock, 1"),
        "active_poll_fd_minus_one": line_number(fops_c, "pfd[0] = -1"),
        "fake_lock_owner": line_number(util_c, "put64(p, LOCK_OFF + 0x18, fake_task | 1)"),
        "fake_lock_root": line_number(util_c, "put64(p, LOCK_OFF + 0x08, fake_w0)"),
        "fake_task_blocked_on": line_number(util_c, "FAKE_TASK_OFF + pi_blocked_on_off, fake_w0"),
        "fake_w0_lock": line_number(util_c, "FAKE_WAITER_LOCK_OFF, (uint64_t)(uintptr_t)pselect_user_lock"),
        "stack_rt_waiter": line_number(requeue_c, "struct rt_mutex_waiter rt_waiter;"),
        "q_rt_waiter": line_number(requeue_c, "q.rt_waiter = &rt_waiter;"),
        "proxy_start": line_number(requeue_c, "rt_mutex_start_proxy_lock(&pi_state->pi_mutex"),
        "waiter_task_assignment": line_number(rtmutex_c, "waiter->task = task;"),
        "waiter_lock_assignment": line_number(rtmutex_c, "waiter->lock = lock;"),
        "blocked_on_assignment": line_number(rtmutex_c, "task->pi_blocked_on = waiter;"),
        "prerequeue_capture": line_number(rtmutex_c, "prerequeue_top_waiter = rt_mutex_top_waiter(lock);"),
        "prerequeue_dequeue": line_number(rtmutex_c, "rt_mutex_dequeue_pi(task, prerequeue_top_waiter);"),
        "adjust_pi_blocked_on": line_number(rtmutex_api_c, "waiter = task->pi_blocked_on;"),
        "adjust_pi_next_lock": line_number(rtmutex_api_c, "next_lock = waiter->lock;"),
    }

    # These are identity equations, not claims that the equations are reached.
    # The first synthetic hop needs the real chain walker to have entered the
    # forged lock/task.  The current poll route supplies no such edge.
    identity_conditions = {
        "prerequeue_top_waiter_source": "rt_mutex_top_waiter(lock) captured before rt_mutex_dequeue(lock, waiter)",
        "not_derived_from": "task->pi_blocked_on alone",
        "real_futex_waiter_identity": "&rt_waiter stack object from futex_wait_requeue_pi()",
        "shape1_target_identity": {
            "chain_task": "fake_task",
            "chain_lock": "fake_lock",
            "chain_waiter": "fake_w0",
            "prerequeue_top_waiter": "fake_w0",
            "pi_tree_node": "fake_w0.pi_tree.entry",
            "required_branch": "waiter == rt_mutex_top_waiter(lock) OR prerequeue_top_waiter == waiter",
        },
        "current_active_poll": {
            "route_lock_source": "zeroed kernel poll_wqueues; fd=-1 skips do_pollfd/vfs_poll/poll_wait",
            "chain_lock_equals_fake_lock": "NO-SOURCE-EDGE",
            "prerequeue_top_equals_fake_w0": "NOT_CLOSED",
            "target_T_equals_fake_fops": "NOT_CLOSED",
        },
        "hypothetical_pselect257_shape1": {
            "stale_original_lock": "CONDITIONAL fake_lock (existing mapping only)",
            "fake_lock_top_waiter": "payload-shaped as fake_w0 if fake_lock is actually consumed",
            "target_T_equals_fake_fops": "CONDITIONAL_ON_SYNTHETIC_CHAIN_ENTRY",
            "second_lock": "fake_w0->lock remains pselect_user_lock (user VA)",
            "raw_spin_trylock_second_lock": "BLOCKED_TYPE_AND_LIFETIME",
        },
    }

    cases = [
        {
            "case": "active_poll_shape0",
            "route": "current default run_main_route_threads -> poll(fd=-1,nfds=1)",
            "prerequeue_top_waiter": "real rt_mutex waiter from the requeue lock; no source edge to fake_w0",
            "shape1_erase": "not reached (shape0 is active and writes F.rb_right/N.parent state instead)",
            "verdict": "PI_IDENTITY_NOT_CLOSED_ACTIVE_POLL",
        },
        {
            "case": "hypothetical_pselect257_shape1",
            "route": "inactive synthetic field table; requires stale waiter->lock=fake_lock",
            "prerequeue_top_waiter": "fake_w0 only if chain task/lock identity is already fake_task/fake_lock",
            "shape1_erase": "then N.rb_left!=W selects N.rb_right (=T), so T:=fake_fops",
            "verdict": "CONDITIONAL_TARGET_BUT_SECOND_LOCK_INVALID",
        },
    ]

    result = {
        "audit": "Violin PI dequeue/top-waiter identity",
        "date": "2026-07-22",
        "mode": "offline-kernel-source-and-existing-artifacts-only",
        "runtime_allowed": False,
        "sources": {
            "main_c": str(SRC_MAIN),
            "fops_c": str(SRC_FOPS),
            "util_c": str(SRC_UTIL),
            "rtmutex_c": str(RTMUTEX_C),
            "rtmutex_api_c": str(RTMUTEX_API_C),
            "futex_requeue_c": str(FUTEX_REQUEUE_C),
            "pi_chain_entry_tool": str(PI_ENTRY),
            "pi256_identity": str(PI256),
            "custom_shape_state": str(SHAPE),
            "misc_list_gate": str(LIST_GATE),
        },
        "evidence_lines": evidence_lines,
        "source_checks": source_checks,
        "prior_artifact_cross_checks": {
            "pi_chain_entry_tool": "source-only gate tool; no runtime result imported",
            "pselect256_second_lock": pi256["decision"],
            "shape_state_verdict": shape["cross_case_conclusion"],
            "misc_list_verdict": list_gate["verdict"],
        },
        "identity_conditions": identity_conditions,
        "cases": cases,
        "verdict": {
            "active_route": "PI_IDENTITY_NOT_CLOSED_ACTIVE_POLL",
            "shape1_target_equation": "CONDITIONAL_ON_SYNTHETIC_CHAIN_ENTRY",
            "second_lock": "FAKE_W0_LOCK_USER_VA",
            "full_chain": "NOT_CLOSED",
        },
        "next_gate": (
            "Do not change nfds, enable shape1, rebuild, or run a device test.  The only useful "
            "next offline proof is a complete pointer-identity/lifetime chain that makes the "
            "actual rt_mutex_adjust_prio_chain task/lock/waiter equal fake_task/fake_lock/fake_w0 "
            "and then supplies a canonical kernel fake_w0->lock plus a terminating post-erase "
            "rb_add and owner/transport repair."
        ),
    }

    OUT.mkdir(exist_ok=True)
    out_json = OUT / "violin-pi-dequeue-identity-20260722.json"
    out_md = OUT / "violin-pi-dequeue-identity-20260722.md"
    out_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md = [
        "# Violin PI dequeue/top-waiter identity audit (2026-07-22)",
        "",
        "离线 kernel-source / exploit-source / 已有报告对账；不构建、不安装、不改 fd-set、不联机、不运行 payload。",
        "",
        "## 关键更正",
        "",
        "`prerequeue_top_waiter` 不是从 `task->pi_blocked_on` 直接取得，而是先由 `rt_mutex_top_waiter(lock)` 捕获，再在 `rt_mutex_dequeue_pi(task, prerequeue_top_waiter)` 中消费。futex requeue 路径传入的初始 waiter 是 `futex_wait_requeue_pi()` 的栈对象 `&rt_waiter`。因此，`fake_task.pi_blocked_on=fake_w0` 和 `fake_lock.waiters.leftmost=fake_w0` 只能构成候选形状，不能单独证明身份已经到达。",
        "",
        "## 当前 route",
        "",
        "- 当前主路径是 `run_main_route_threads()` → `FUTEX_CMP_REQUEUE_PI` → `poll(fd=-1,nfds=1)`。",
        "- `poll` 的 fd=-1 会跳过 `do_pollfd/vfs_poll/poll_wait`；stale `waiter->lock` 来自清零的 kernel `poll_wqueues`，没有 `pselect_user_lock → fake_lock` 的 source edge。",
        "- 因此当前 active route 不能证明 chain task/lock/waiter 分别为 `fake_task/fake_lock/fake_w0`，shape-1 的 `T:=fake_fops` 不可达。",
        "",
        "## 条件性 shape-1",
        "",
        "若另一个离线模型先证明链已经进入 `fake_lock`（owner=`fake_task|1`、top waiter=`fake_w0`），则 `N.rb_left!=W` 的 predecessor 分支会到达 `rt_mutex_dequeue_pi(fake_task,fake_w0)`，并把 `N.rb_right`（即 `T=ashmem_misc+0x10`）改成 `fake_fops`。但现有 payload 的 `fake_w0->lock` 仍是用户态 `pselect_user_lock`，下一轮 `rt_mutex_adjust_prio_chain()` 的 `raw_spin_trylock()` 不能获得一个已证实的 kernel `rt_mutex`。",
        "",
        "## 状态表",
        "",
        "| Case | `prerequeue_top_waiter` | shape-1 target | 结论 |",
        "| --- | --- | --- | --- |",
    ]
    for case in cases:
        md.append(
            f"| `{case['case']}` | {case['prerequeue_top_waiter']} | "
            f"{case['shape1_erase']} | **{case['verdict']}** |"
        )
    md += [
        "",
        "## Verdict",
        "",
        "**PI_IDENTITY_NOT_CLOSED_ACTIVE_POLL**；shape-1 仅为 synthetic-chain-entry 条件成立时的目标等式，完整链仍未闭合。",
        "",
        "## 下一道门",
        "",
        result["next_gate"],
    ]
    out_md.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
