#!/usr/bin/env python3
"""Close the four remaining Violin synthetic-chain gates offline.

This is a source/raw-image/report reconciliation only.  It does not build,
install, connect to a device, change fd-set/nfds values, or execute a payload.

The four gates are kept separate on purpose:

* payload fields can describe a synthetic ``fake_task/fake_lock/fake_w0``
  shape without proving that the real PI chain ever enters those objects;
* a second ``rt_mutex`` must be a canonical kernel object with a closed
  lifetime, not merely a user pointer stored in ``fake_w0->lock``;
* the post-erase ``rb_add`` must terminate and return to userspace;
* the forged fops owner and the ConfigFS/pipe transport must be repaired in an
  order that is reachable from the first write.

The result intentionally records missing evidence as a verdict.  A conditional
equation is not promoted to a successful exploit chain.
"""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPLOIT = ROOT / "exploit-repo/IonStack/CVE-2026-43499/exploit"
SRC = EXPLOIT / "src"
KERNEL = ROOT / "kernel-src-wsl/common-gki"
OUT = ROOT / "analysis_outputs"
OUT_JSON = OUT / "violin-full-synthetic-chain-closure-20260722.json"
OUT_MD = OUT / "violin-full-synthetic-chain-closure-20260722.md"

ARTIFACTS = {
    "pi_dequeue": OUT / "violin-pi-dequeue-identity-20260722.json",
    "rb_postwrite": OUT / "violin-rb-erase-postwrite-state-20260722.json",
    "second_lock": OUT / "violin-second-kernel-lock-inventory-20260722.json",
    "owner_module": OUT / "violin-fake-fops-owner-module-shape-20260722.json",
    "pipe_first_stage": OUT / "violin-pipe-first-stage-circularity-20260722.json",
    "misc_predecessor": OUT / "violin-misc-list-predecessor-20260722.json",
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def line_of(text: str, needle: str) -> int | None:
    for number, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return number
    return None


def line_of_last(text: str, needle: str) -> int | None:
    found = None
    for number, line in enumerate(text.splitlines(), 1):
        if needle in line:
            found = number
    return found


def has(text: str, needle: str) -> bool:
    return needle in text


def require(text: str, *needles: str) -> bool:
    return all(has(text, needle) for needle in needles)


def main() -> int:
    main_c = (SRC / "main.c").read_text(encoding="utf-8")
    fops_c = (SRC / "fops.c").read_text(encoding="utf-8")
    util_c = (SRC / "util.c").read_text(encoding="utf-8")
    pipe_c = (SRC / "pipe.c").read_text(encoding="utf-8")
    rtmutex_c = (KERNEL / "kernel/locking/rtmutex.c").read_text(encoding="utf-8")
    rtmutex_api_c = (KERNEL / "kernel/locking/rtmutex_api.c").read_text(encoding="utf-8")
    rbtree_aug_c = (KERNEL / "include/linux/rbtree_augmented.h").read_text(encoding="utf-8")
    rbtree_c = (KERNEL / "include/linux/rbtree.h").read_text(encoding="utf-8")

    artifacts = {name: load(path) for name, path in ARTIFACTS.items()}

    # Gate 1: synthetic payload shape versus actual PI-chain entry.
    synthetic_shape = {
        "fake_lock_owner_fake_task_pi": has(util_c, "put64(p, LOCK_OFF + 0x18, fake_task | 1)"),
        "fake_lock_waiters_root_fake_w0": has(util_c, "put64(p, LOCK_OFF + 0x08, fake_w0)"),
        "fake_lock_waiters_leftmost_fake_w0": has(util_c, "put64(p, LOCK_OFF + 0x10, fake_w0)"),
        "fake_task_pi_waiters_fake_w0": require(
            util_c,
            "put64(p, FAKE_TASK_OFF + pi_waiters_off,",
            "fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF",
        ),
        "fake_task_pi_blocked_on_fake_w0": has(
            util_c, "put64(p, FAKE_TASK_OFF + pi_blocked_on_off, fake_w0)"
        ),
        "fake_w0_lock_is_pselect_user_lock": has(
            util_c,
            "FAKE_WAITER_LOCK_OFF, (uint64_t)(uintptr_t)pselect_user_lock",
        ),
        "shape1_predecessor_equation_present": require(
            util_c,
            "fake_parent = write_target - 8",
            "fake_right = write_value",
            "fake_left = 0",
        ),
    }
    synthetic_shape_ok = all(synthetic_shape.values())
    active_route = {
        "main_uses_cmp_requeue_pi": has(main_c, "FUTEX_CMP_REQUEUE_PI"),
        "main_calls_route_threads": has(main_c, "run_main_route_threads();"),
        "route_enters_poll": has(fops_c, "poll((struct pollfd *)pselect_user_lock, 1"),
        "poll_fd_is_minus_one": has(fops_c, "pfd[0] = -1"),
        "source_comment_says_no_pselect_edge": has(
            fops_c,
            "poll_wqueues",
        ) and has(fops_c, "不会被 pselect_user_lock"),
    }
    active_route_ok = all(active_route.values())
    synthetic_entry_closed = (
        artifacts["pi_dequeue"]["verdict"]["active_route"]
        == "PI_IDENTITY_CLOSED_ACTIVE_POLL"
    )

    # Gate 2: the second iteration reads waiter->lock and immediately treats it
    # as a kernel rt_mutex_base.  The current value is explicitly a user VA.
    second_lock_source = {
        "adjust_pi_reads_pi_blocked_on": has(rtmutex_api_c, "waiter = task->pi_blocked_on;"),
        "adjust_pi_loads_next_lock": has(rtmutex_api_c, "next_lock = waiter->lock;"),
        "adjust_pi_calls_chain_with_orig_null": has(
            rtmutex_api_c,
            "rt_mutex_adjust_prio_chain(task, RT_MUTEX_MIN_CHAINWALK, NULL,",
        ),
        "chain_uses_waiter_lock": has(rtmutex_c, "lock = waiter->lock;"),
        "chain_trylocks_wait_lock": has(rtmutex_c, "raw_spin_trylock(&lock->wait_lock)"),
        "payload_second_lock_is_user_va": synthetic_shape["fake_w0_lock_is_pselect_user_lock"],
    }
    second_lock_closed = artifacts["second_lock"]["verdict"]["closed_distinct_second_lock"]

    # Gate 3: use the already reconciled post-erase state and anchor it back to
    # the same-build rb_add implementation.  This avoids treating a symbolic
    # target equation as a proof of a returning call path.
    rb_state = artifacts["rb_postwrite"]
    post_enqueue = rb_state["states"]["custom_followup_enqueue"]
    termination = {
        "rb_add_cached_present": has(rbtree_c, "rb_add_cached"),
        "shape1_target_equation": rb_state["verdict"]["custom_shape1_target_equation"],
        "post_erase_root_is_stale_W": rb_state["states"]["custom_shape1"]["post_state"].startswith(
            "rb_root remains W"
        ),
        "post_erase_leftmost_is_F": "leftmost is F" in rb_state["states"]["custom_shape1"]["post_state"],
        "same_waiter_cycle": (
            "W→F→W" in post_enqueue["same_waiter_cycle"]
            or "W -> F -> W" in post_enqueue["same_waiter_cycle"]
            or "W.rb_right=F" in post_enqueue["same_waiter_cycle"]
            and "F.rb_right=W" in post_enqueue["same_waiter_cycle"]
        ),
        "rb_add_reaches_null": "without finding NULL" not in post_enqueue["same_waiter_cycle"],
        "safe_userspace_return": "No safe userspace return" not in post_enqueue["closure"],
    }
    termination_closed = (
        termination["rb_add_cached_present"]
        and not termination["same_waiter_cycle"]
        and termination["rb_add_reaches_null"]
        and termination["safe_userspace_return"]
    )

    # Gate 4: distinguish an initially usable ConfigFS transport from a later
    # owner/text refresh.  The latter is downstream of the first CFI write.
    owner_transport_source = {
        "initial_owner_zero": has(util_c, "put64(p, off + FOPS_OWNER_OFF, 0)"),
        "initial_read_iter_configfs": has(util_c, "put64(p, off + FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER))"),
        "initial_write_iter_configfs": has(util_c, "put64(p, off + FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER))"),
        "llseek_repair_uses_configfs": require(
            fops_c,
            "ssize_t wr = configfs_write_once(fd, slot, &llseek, sizeof(llseek));",
            "ssize_t rd = configfs_read_once(fd, slot, &after, sizeof(after));",
        ),
        "text_refresh_uses_kernel_write": has(fops_c, "kernel_write_data(fd, target, &slots[i].value"),
        "leak_calls_text_refresh": has(fops_c, "if (!refresh_fake_fops_text(fd))"),
        "kernel_write_aliases_configfs": has(util_c, "return configfs_write_once(fd, target, data, len);"),
        "first_stage_opens_then_configfs_writes": require(
            fops_c,
            "int fd = open_ashmem_device();",
            "configfs_write_once(fd, binwrite_target, payload, sizeof(payload));",
        ),
        "final_owner_clear_exists": has(fops_c, "configfs_write_once(fd, fake_fops, &null_owner, sizeof(null_owner))"),
        "fail_owner_clear_exists": has(fops_c, "&null_owner_fail, sizeof(null_owner_fail)"),
        "pipe_setup_uses_same_transport": has(pipe_c, "kernel_write_data(fd, buf_addr, &pb, sizeof(pb))"),
    }
    owner_shape1 = artifacts["owner_module"]["alias"]["owner_after_erase"] == "N"
    owner_valid_module = artifacts["owner_module"]["verdict"]["owner_is_valid_module_pointer"]
    owner_transport_closed = (
        all(owner_transport_source.values())
        and not owner_shape1
        and owner_valid_module
        and artifacts["pipe_first_stage"]["verdict"] != "NO_INDEPENDENT_FIRST_STAGE_WRITE"
    )

    evidence_lines = {
        "main_requeue": line_of(main_c, "int requeue_ret = futex_op"),
        "main_route_threads": line_of_last(main_c, "run_main_route_threads();"),
        "active_poll": line_of(fops_c, "poll((struct pollfd *)pselect_user_lock, 1"),
        "active_poll_fd_minus_one": line_of(fops_c, "pfd[0] = -1"),
        "fake_lock_owner": line_of(util_c, "put64(p, LOCK_OFF + 0x18, fake_task | 1)"),
        "fake_task_blocked_on": line_of(util_c, "put64(p, FAKE_TASK_OFF + pi_blocked_on_off, fake_w0)"),
        "fake_w0_lock": line_of(util_c, "FAKE_WAITER_LOCK_OFF, (uint64_t)(uintptr_t)pselect_user_lock"),
        "adjust_pi_next_lock": line_of(rtmutex_api_c, "next_lock = waiter->lock;"),
        "chain_lock_from_waiter": line_of_last(rtmutex_c, "lock = waiter->lock;"),
        "chain_trylock": line_of_last(rtmutex_c, "raw_spin_trylock(&lock->wait_lock)"),
        "prerequeue_top": line_of(rtmutex_c, "prerequeue_top_waiter = rt_mutex_top_waiter(lock);"),
        "post_erase_enqueue": line_of(rtmutex_c, "rt_mutex_enqueue_pi(task, waiter);"),
        "fake_fops_owner": line_of(util_c, "put64(p, off + FOPS_OWNER_OFF, 0)"),
        "fake_fops_read_iter": line_of(util_c, "put64(p, off + FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER))"),
        "repair_llseek": line_of(fops_c, "int repair_fake_fops_llseek(int fd)"),
        "refresh_text": line_of(fops_c, "int refresh_fake_fops_text(int fd)"),
        "refresh_call": line_of(fops_c, "if (!refresh_fake_fops_text(fd))"),
        "cfi_open": line_of(fops_c, "int fd = open_ashmem_device();"),
        "first_configfs_write": line_of(fops_c, "configfs_write_once(fd, binwrite_target, payload, sizeof(payload))"),
        "final_owner_clear": line_of(fops_c, "configfs_write_once(fd, fake_fops, &null_owner, sizeof(null_owner))"),
        "pipe_setup": line_of(pipe_c, "kernel_write_data(fd, buf_addr, &pb, sizeof(pb))"),
    }

    result = {
        "audit": "Violin full synthetic chain closure",
        "date": "2026-07-22",
        "mode": "offline-source-raw-image-existing-artifacts-only",
        "runtime_allowed": False,
        "sources": {
            "main_c": str(SRC / "main.c"),
            "fops_c": str(SRC / "fops.c"),
            "util_c": str(SRC / "util.c"),
            "pipe_c": str(SRC / "pipe.c"),
            "rtmutex_c": str(KERNEL / "kernel/locking/rtmutex.c"),
            "rtmutex_api_c": str(KERNEL / "kernel/locking/rtmutex_api.c"),
            "rbtree_augmented_h": str(KERNEL / "include/linux/rbtree_augmented.h"),
            "artifacts": {name: str(path) for name, path in ARTIFACTS.items()},
        },
        "evidence_lines": evidence_lines,
        "gates": {
            "synthetic_chain": {
                "payload_shape": synthetic_shape,
                "payload_shape_complete": synthetic_shape_ok,
                "active_route": active_route,
                "active_route_complete": active_route_ok,
                "entry_closed": synthetic_entry_closed,
                "required_identity": {
                    "chain_task": "fake_task",
                    "chain_lock": "fake_lock",
                    "chain_waiter": "fake_w0",
                    "prerequeue_top_waiter": "fake_w0",
                },
                "verdict": "SHAPE_PRESENT_ENTRY_NOT_PROVEN" if not synthetic_entry_closed else "CLOSED",
            },
            "kernel_second_lock": {
                "source": second_lock_source,
                "distinct_candidate_closed": second_lock_closed,
                "inventory_verdict": artifacts["second_lock"]["verdict"],
                "verdict": "NO_CANONICAL_KERNEL_SECOND_LOCK" if not second_lock_closed else "CLOSED",
            },
            "termination": {
                "source": termination,
                "post_erase_model": post_enqueue,
                "verdict": "NON_TERMINATING_CONDITIONAL_SHAPE1" if not termination_closed else "CLOSED",
            },
            "owner_transport": {
                "source": owner_transport_source,
                "shape1_owner": "N" if owner_shape1 else "not-N",
                "owner_is_valid_module": owner_valid_module,
                "owner_artifact_verdict": artifacts["owner_module"]["verdict"],
                "pipe_artifact_verdict": artifacts["pipe_first_stage"]["verdict"],
                "verdict": "STRUCTURAL_ONLY_FOPS_GATED" if not owner_transport_closed else "CLOSED",
            },
        },
        "overall": {
            "complete_synthetic_chain": False,
            "all_four_gates_closed": bool(
                synthetic_entry_closed and second_lock_closed and termination_closed and owner_transport_closed
            ),
            "verdict": "FULL_SYNTHETIC_CHAIN_NOT_CLOSED",
            "decision": (
                "The payload contains the intended synthetic fields, but the active poll route does not prove entry into "
                "fake_task/fake_lock/fake_w0. The second iteration still consumes a user VA as waiter->lock. "
                "The shape-1 target equation is only conditional and its same-waiter post-erase rb_add follows W->F->W "
                "without finding NULL. Owner=0 and ConfigFS iter callbacks are prepared before the first write, while "
                "text refresh/pipe setup are downstream; shape-1 owner=N is not a validated module pointer and no independent "
                "first-stage pipe sink exists."
            ),
            "runtime_allowed": False,
        },
        "next_gate": (
            "Keep the rb/PI branch frozen.  Do not change nfds/fd_set, enable shape1, rebuild, connect, or run a payload. "
            "Re-open only if a new offline proof supplies all four: actual synthetic PI identity, a canonical kernel "
            "second rt_mutex with lifetime, a terminating post-erase rb_add, and an owner/transport sequence independent "
            "of the unresolved write."
        ),
    }

    OUT.mkdir(exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md = [
        "# Violin full synthetic-chain closure audit (2026-07-22)",
        "",
        "离线 source / same-build raw image / 已有报告对账；不构建、不安装、不改 `fd_set`/`nfds`、不联机、不运行 payload。",
        "",
        "## 结论",
        "",
        "**FULL_SYNTHETIC_CHAIN_NOT_CLOSED**。四个门没有同时闭合；条件性方程不当作成功证据。",
        "",
        "| Gate | 已找到的证据 | 缺口 | Verdict |",
        "| --- | --- | --- | --- |",
        "| synthetic chain | payload 确实写出 `fake_task/fake_lock/fake_w0` 字段 | active `poll(fd=-1,nfds=1)` 没有进入这些对象的 source edge；真实 `prerequeue_top_waiter` 仍来自实际锁 | **SHAPE_PRESENT_ENTRY_NOT_PROVEN** |",
        "| kernel second-lock | `rt_mutex_adjust_pi()` 读取 `waiter->lock` 并对 `lock->wait_lock` trylock | `fake_w0->lock` 是 `pselect_user_lock` 用户 VA；没有 distinct canonical kernel `rt_mutex` + lifetime | **NO_CANONICAL_KERNEL_SECOND_LOCK** |",
        "| termination | shape-1 的 `N.rb_left!=W` 可条件性把 `T` 改为 `F` | erase 后 stale root/leftmost 与 `W→F→W` same-waiter cycle；找不到 NULL、无安全返回 | **NON_TERMINATING_CONDITIONAL_SHAPE1** |",
        "| owner/transport | 初始 owner=0，read/write_iter 已指向 ConfigFS；llseek/text refresh 和最终 owner clear 都有代码 | refresh/pipe 是首次写入之后的下游；shape-1 owner=N 不是合法 module 指针，pipe 无独立 first-stage sink | **STRUCTURAL_ONLY_FOPS_GATED** |",
        "",
        "## 关键证据",
        "",
        f"- Synthetic payload：`util.c:{evidence_lines['fake_lock_owner']}` 写 `fake_lock.owner=fake_task|1`，`util.c:{evidence_lines['fake_task_blocked_on']}` 写 `fake_task.pi_blocked_on=fake_w0`，`util.c:{evidence_lines['fake_w0_lock']}` 写 `fake_w0->lock=pselect_user_lock`。",
        f"- Active route：`main.c:{evidence_lines['main_requeue']}` 使用 `FUTEX_CMP_REQUEUE_PI`，随后 `main.c:{evidence_lines['main_route_threads']}` 进入 route；`fops.c:{evidence_lines['active_poll']}` 使用 `poll(...,1,...)`，`fops.c:{evidence_lines['active_poll_fd_minus_one']}` 将 fd 设为 -1。既有 PI identity 报告因此判定 active entry 未闭合。",
        f"- Kernel second-lock：`rtmutex_api.c:{evidence_lines['adjust_pi_next_lock']}` 取 `next_lock=waiter->lock`；`rtmutex.c:{evidence_lines['chain_lock_from_waiter']}` 重复取 `lock=waiter->lock`，`rtmutex.c:{evidence_lines['chain_trylock']}` 立即访问 `lock->wait_lock`。",
        f"- Termination：既有 post-write state 报告记录 shape-1 后 root=W、leftmost=F，same-waiter enqueue 沿 `W→F→W`，`rb_add` 不遇到 NULL；该报告同时判定无安全 userspace return。",
        f"- Owner/transport：`util.c:{evidence_lines['fake_fops_owner']}` 初始 owner=0，`util.c:{evidence_lines['fake_fops_read_iter']}` 初始 read_iter=ConfigFS；`fops.c:{evidence_lines['repair_llseek']}` 和 `{evidence_lines['refresh_text']}` 是下游修复，`fops.c:{evidence_lines['refresh_call']}` 只在 leak 阶段调用；`try_cfi_stage` 先在 `fops.c:{evidence_lines['cfi_open']}` open，再于 `fops.c:{evidence_lines['first_configfs_write']}` 做首个 ConfigFS 写入。最终 owner clear 在 `fops.c:{evidence_lines['final_owner_clear']}`。",
        "- Pipe：`pipe.c` 的 pipe-buffer forge/restore 通过 `kernel_write_data()`，而 `kernel_write_data()` 又委托 ConfigFS；已有 circularity 报告判定 `NO_INDEPENDENT_FIRST_STAGE_WRITE`。",
        "",
        "## 操作边界",
        "",
        "本轮只生成 JSON/Markdown 审计产物并更新日志，不修改 payload，不执行设备测试。只有四个 gate 都由新的离线证据闭合，才允许重新评估 frozen rb/PI branch。",
        "",
    ]
    OUT_MD.write_text("\n".join(md), encoding="utf-8")
    print(json.dumps({"json": str(OUT_JSON), "markdown": str(OUT_MD), "verdict": result["overall"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
