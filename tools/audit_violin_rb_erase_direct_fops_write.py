#!/usr/bin/env python3
"""Offline audit of the current Violin PI-tree rb_erase write equation.

This is a source/layout audit only.  It does not build, install, connect to a
device, modify fd sets, or execute a payload.  The audit was added because the
older rb_erase destination report modelled the FOPS node in the opposite
orientation.  The active payload's shape-1 branch is:

    W.__rb_parent_color = N = (ashmem_misc + 0x10) - 0x08
    W.rb_right          = F = fake_fops
    W.rb_left           = NULL

For a one-child erase of W, the kernel therefore calls
``__rb_change_child(W, F, N, root)``.  Since N.rb_left is the live
miscdevice.list.next field rather than W, the helper's ``else`` arm stores
N.rb_right = F.  N.rb_right aliases the actual miscdevice.fops slot T.

This shape-1 equation is a **custom candidate**, not the active default route:
``main.c`` deliberately does not call ``set_pselect_write()``.  The active
default is shape 0, with W.parent=F, W.rb_left=N and W.rb_right=NULL; that
default erase writes fake_fops.rb_right=N and does not reach T.  The report
keeps both states explicit so a conditional symbolic result cannot be mistaken
for a runtime result.

The report intentionally stops before any runtime claim: the write is reached
only if the PI chain reaches rt_mutex_dequeue_pi(fake_task, W), and the tree is
malformed immediately afterwards.  It also records the fops->owner side effect
and the separate owner/open problem.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "kernel-src-wsl" / "common-gki"
EXPLOIT = ROOT / "exploit-repo" / "IonStack" / "CVE-2026-43499" / "exploit"
SRC = EXPLOIT / "src"

UTIL_C = SRC / "util.c"
TARGET_H = SRC / "targets" / "violin-v-oss" / "target.h"
RB_H = KERNEL / "include" / "linux" / "rbtree.h"
RB_AUG = KERNEL / "include" / "linux" / "rbtree_augmented.h"
RTMUTEX_C = KERNEL / "kernel" / "locking" / "rtmutex.c"
RTMUTEX_API_C = KERNEL / "kernel" / "locking" / "rtmutex_api.c"
RTMUTEX_COMMON_H = KERNEL / "kernel" / "locking" / "rtmutex_common.h"
MISC_C = KERNEL / "drivers" / "char" / "misc.c"
FS_H = KERNEL / "include" / "linux" / "fs.h"

OUT_DIR = ROOT / "analysis_outputs"
OUT_JSON = OUT_DIR / "violin-rb-erase-direct-fops-write-20260719.json"
OUT_MD = OUT_DIR / "violin-rb-erase-direct-fops-write-20260719.md"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def line_of(path: Path, needle: str) -> int | None:
    for number, line in enumerate(read(path).splitlines(), 1):
        if needle in line:
            return number
    return None


def constant(path: Path, name: str) -> str | None:
    pattern = re.compile(rf"^\s*#define\s+{re.escape(name)}\s+(.+?)\s*(?:/\*.*)?$")
    for line in read(path).splitlines():
        match = pattern.match(line)
        if match:
            return match.group(1).strip()
    return None


def source_evidence() -> dict:
    return {
        "payload": {
            "shape1_parent_line": line_of(UTIL_C, "fake_parent = write_target - 8"),
            "shape1_right_line": line_of(UTIL_C, "fake_right = write_value"),
            "shape1_left_line": line_of(UTIL_C, "fake_left = 0"),
            "write_pc_line": line_of(UTIL_C, "put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc)"),
            "write_right_line": line_of(UTIL_C, "put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right)"),
            "write_left_line": line_of(UTIL_C, "put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left)"),
            "pi_root_line": line_of(UTIL_C, "fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF"),
            "pi_blocked_on_line": line_of(UTIL_C, "pi_blocked_on_off, fake_w0"),
            "fops_owner_line": line_of(UTIL_C, "put64(p, off + FOPS_OWNER_OFF, 0)"),
            "fops_llseek_line": line_of(UTIL_C, "put64(p, off + FOPS_LLSEEK_OFF"),
            "fops_read_iter_line": line_of(UTIL_C, "FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER)"),
            "fops_write_iter_line": line_of(UTIL_C, "FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER)"),
            "main_no_custom_write_line": line_of(EXPLOIT / "src" / "main.c", "不调用 set_pselect_write"),
        },
        "rbtree": {
            "rb_erase_cached_line": line_of(RB_H, "rb_erase_cached(struct rb_node *node"),
            "cached_rb_next_line": line_of(RB_H, "leftmost = root->rb_leftmost = rb_next(node)"),
            "rb_change_child_definition_line": line_of(RB_AUG, "__rb_change_child(struct rb_node *old"),
            "rb_change_child_left_line": line_of(RB_AUG, "WRITE_ONCE(parent->rb_left, new)"),
            "rb_change_child_right_line": line_of(RB_AUG, "WRITE_ONCE(parent->rb_right, new)"),
            "rb_erase_one_child_line": line_of(RB_AUG, "__rb_change_child(node, child, parent, root)"),
            "rb_child_parent_copy_line": line_of(RB_AUG, "child->__rb_parent_color = pc"),
            "rb_rebalance_line": line_of(RB_AUG, "rebalance = NULL;"),
            "rb_add_cached_loop_line": line_of(RB_H, "while (*link)"),
        },
        "rtmutex": {
            "dequeue_pi_line": line_of(RTMUTEX_C, "rb_erase_cached(&waiter->pi_tree.entry"),
            "clear_pi_node_line": line_of(RTMUTEX_C, "RB_CLEAR_NODE(&waiter->pi_tree.entry)"),
            "enqueue_pi_line": line_of(RTMUTEX_C, "rb_add_cached(&waiter->pi_tree.entry"),
            "orig_lock_check_line": line_of(RTMUTEX_C, "if (lock == orig_lock || rt_mutex_owner(lock) == top_task)"),
            "requeue_pi_line": line_of(RTMUTEX_C, "rt_mutex_dequeue_pi(task, prerequeue_top_waiter)"),
            "requeue_pi_enqueue_line": line_of(RTMUTEX_C, "rt_mutex_enqueue_pi(task, waiter)"),
            "adjust_pi_call_line": line_of(RTMUTEX_API_C, "rt_mutex_adjust_prio_chain(task, RT_MUTEX_MIN_CHAINWALK, NULL,"),
            "waiter_node_entry_line": line_of(RTMUTEX_COMMON_H, "struct rb_node\tentry;"),
            "waiter_node_prio_line": line_of(RTMUTEX_COMMON_H, "int\t\tprio;"),
            "waiter_pi_tree_line": line_of(RTMUTEX_COMMON_H, "struct rt_waiter_node\tpi_tree;"),
        },
        "open_path": {
            "misc_open_line": line_of(MISC_C, "static int misc_open(struct inode *inode, struct file *file)"),
            "misc_fops_get_line": line_of(MISC_C, "new_fops = fops_get(iter->fops)"),
            "fops_get_macro_line": line_of(FS_H, "#define fops_get(fops)"),
            "try_module_get_line": line_of(FS_H, "try_module_get((fops)->owner)"),
        },
    }


def symbolic_state() -> dict:
    return {
        "symbols": {
            "T": "ashmem_misc + 0x10 (miscdevice.fops slot)",
            "N": "T - 0x08 = ashmem_misc + 0x08 (miscdevice.name field; interpreted as rb_node)",
            "W": "fake_w0 + 0x28 (rt_mutex_waiter.pi_tree.entry; rb_node is first member)",
            "F": "fake_fops (fake file_operations blob, interpreted as rb_node)",
        },
        "struct_layout": {
            "rt_waiter_node.entry": "+0x00",
            "rt_waiter_node.prio": "+0x18",
            "rt_waiter_node.deadline": "+0x20",
            "rt_mutex_waiter.pi_tree": "+0x28",
            "rt_mutex_waiter.task": "+0x50",
            "rt_mutex_waiter.lock": "+0x58",
        },
        "active_default_shape0_fields": {
            "activation": "main.c does not call set_pselect_write(); pselect_write_shape() returns 0",
            "W.__rb_parent_color": "F (fake_fops)",
            "W.rb_left": "N",
            "W.rb_right": "NULL",
            "fake_task.pi_waiters.rb_root": "W",
            "fake_task.pi_waiters.rb_leftmost": "W",
            "default_erase": "__rb_change_child(W, N, F, root) => F.rb_right=N; T is unchanged",
        },
        "custom_shape1_fields": {
            "activation": "requires set_pselect_write()/custom DIRECT_WRITE_SHAPE=1 path; not active in main.c",
            "W.__rb_parent_color": "N (aligned, RB_RED color bit 0)",
            "W.rb_left": "NULL",
            "W.rb_right": "F",
            "fake_task.pi_waiters.rb_root": "W",
            "fake_task.pi_waiters.rb_leftmost": "W",
            "fake_task.pi_blocked_on": "fake_w0 (the containing waiter)",
            "F.rb_left": "NULL (fake_fops.read)",
            "F.rb_right": "W (fake_fops.llseek)",
        },
        "dequeue_equation": {
            "gate": "rt_mutex_dequeue_pi(fake_task, fake_w0) must be reached and RB_EMPTY_NODE(W) must be false",
            "default_shape0": "W.parent=F, W.left=N, W.right=NULL => __rb_change_child(W,N,F,root), so fake_fops.rb_right=N and T is not written",
            "custom_shape1": "W.parent=N, W.left=NULL, W.right=F => __rb_change_child(W,F,N,root), so N.rb_right=T is written",
            "cached_step": "rb_erase_cached(W): rb_leftmost=W, rb_next(W)=F, so fake_task.pi_waiters.rb_leftmost becomes F",
            "erase_case": "W.rb_left=NULL, W.rb_right=F => one-child case with child=F and parent=N",
            "helper_call": "__rb_change_child(W, F, N, &fake_task.pi_waiters.rb_root)",
            "branch": "N.rb_left is miscdevice.list.next at runtime, not W; helper takes its else arm",
            "direct_store": "N.rb_right = F",
            "target_alias": "N.rb_right is ashmem_misc + 0x10 = T, therefore T := F",
            "child_parent_store": "F.__rb_parent_color := pc = N",
            "fops_side_effect": "F.owner aliases F.__rb_parent_color, so F.owner := N",
            "rebalance": "none in the child-present case; rebalance=NULL",
            "root_side_effect": "fake_task.pi_waiters.rb_root remains W because N is non-NULL; it is not changed to F",
        },
        "post_write_state": {
            "target": "ashmem_misc.fops == fake_fops",
            "owner": "fake_fops.owner == N (not the initially encoded NULL and not a proven module pointer)",
            "cache": "fake_task.pi_waiters.rb_leftmost == F while rb_root still == W",
            "next_call": "rt_mutex_enqueue_pi(fake_task, waiter) may call rb_add_cached on the stale root W",
            "risk": "F and W are no longer a valid rt_mutex waiter tree; comparator/rotation reachability is unresolved offline",
        },
        "orig_lock_correction": {
            "source": "rt_mutex_adjust_pi() passes orig_lock=NULL to rt_mutex_adjust_prio_chain()",
            "effect": "the lock==orig_lock deadlock check cannot reject fake_lock merely because it is fake_lock; the separate owner==top_task check still applies",
            "status": "corrects the old report that treated fake_w0->lock=fake_lock as automatically blocked by lock==orig_lock",
        },
        "transport_implication": {
            "fresh_open": "misc_open() calls fops_get(iter->fops), and fops_get calls try_module_get(fops->owner)",
            "problem": "after the erase, fake_fops.owner aliases N, so a fresh ashmem open is not closed unless N is a valid module pointer or owner is repaired first",
            "candidate": "pre-open a transport fd before route and use only that existing fd for any owner repair; this is a design candidate, not runtime evidence",
            "current_stage_mismatch": "try_cfi_stage() currently opens ashmem after the route, so the existing order is not closed",
        },
        "route_precondition": {
            "active_mode": "default shape0; custom shape1 is not selected by main.c",
            "default_poll": "current active default route does not prove that the stale kernel waiter->lock points at fake_lock",
            "pselect256": "the 256-fd mapping remains a separate candidate requiring an independent 12-word field table and fd-mask closure",
            "runtime_status": "not tested in this audit",
        },
    }


def main() -> int:
    evidence = source_evidence()
    state = symbolic_state()
    result = {
        "audit": "Violin rb_erase direct fops-slot write equation",
        "date": "2026-07-19",
        "mode": "offline-source-and-symbolic-only",
        "sources": {key: str(value) for key, value in {
            "util_c": UTIL_C,
            "target_h": TARGET_H,
            "rbtree_h": RB_H,
            "rbtree_augmented_h": RB_AUG,
            "rtmutex_c": RTMUTEX_C,
            "rtmutex_api_c": RTMUTEX_API_C,
            "rtmutex_common_h": RTMUTEX_COMMON_H,
            "misc_c": MISC_C,
            "fs_h": FS_H,
        }.items()},
        "target_constants": {
            "ASHMEM_MISC_OFF": constant(TARGET_H, "ASHMEM_MISC_OFF"),
            "ASHMEM_MISC_FOPS_OFF": constant(TARGET_H, "ASHMEM_MISC_FOPS_OFF"),
            "FAKE_WAITER_PI_TREE_ENTRY_OFF": constant(TARGET_H, "FAKE_WAITER_PI_TREE_ENTRY_OFF"),
        },
        "evidence": evidence,
        "state": state,
        "verdict": {
            "active_default_shape0_direct_fops_slot": "not reached: rb_erase_cached(W) stores fake_fops.rb_right := N",
            "custom_shape1_direct_fops_slot_equation": "closed symbolically: rb_erase_cached(W) can store T := F through N.rb_right, but custom shape1 is not active",
            "pi_chain_reachability": "not closed",
            "post_write_tree_validity": "not closed; stale root W and leftmost F remain after non-NULL-parent erase",
            "fresh_open_owner": "not closed; F.owner becomes N before fops_get",
            "current_payload_success": "not established",
            "runtime_allowed": False,
            "next_gate": "offline-model the post-erase rb_add/rotation and define a pre-open transport/owner-repair ordering before considering any runtime work",
        },
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md = """# Violin rb_erase direct fops-slot write audit (2026-07-19)\n\n"""
    md += "**Mode:** offline source/layout/symbolic analysis only. No build, install, device connection, fd-set change, or payload execution.\n\n"
    md += "## Corrected equation\n\n"
    md += "先区分 active/default 与 custom shape-1：`main.c` 明确不调用 `set_pselect_write()`，所以当前默认运行是 shape 0，而不是 shape 1。默认 shape 0 的真实布局为 `T=ashmem_misc+0x10`、`N=T-0x08`、`W=fake_w0+0x28`、`F=fake_fops`；`W.__rb_parent_color=F`、`W.rb_left=N`、`W.rb_right=NULL`。因此默认 erase 调用 `__rb_change_child(W,N,F,root)`，只写 `F.rb_right=N`，**T 不变**。\n\n"
    md += "作为未启用的 custom shape-1 候选，布局才是 `W.parent=N`、`W.left=NULL`、`W.right=F`。若 PI 链确实到达 `rt_mutex_dequeue_pi(fake_task, fake_w0)`，`rb_erase_cached(W)` 先把缓存 leftmost 从 W 更新到 `rb_next(W)=F`；一子节点路径随后执行 `__rb_change_child(W,F,N,root)`。运行时 `N.rb_left` 是 `miscdevice.list.next`，不是 W，因此走 else：`N.rb_right=F`。由于 `N.rb_right` 正好别名 T，custom shape-1 才得到 **`ashmem_misc.fops := fake_fops`**。这里 `pi_tree.entry` 位于 `rt_mutex_waiter` 的 `+0x28`，因为 `struct rt_waiter_node` 的第一个成员就是 `rb_node entry`。\n\n"
    md += "## 必须同时记录的副作用\n\n"
    md += "- `child->__rb_parent_color = pc` 会把 `F.__rb_parent_color` 写成 N；因 fake_fops 的 owner 位于 +0x00，等价于 **`fake_fops.owner := N`**。\n"
    md += "- parent 非 NULL，所以 `fake_task.pi_waiters.rb_root` 仍是 W；cached leftmost 已变成 F。后续 `rt_mutex_enqueue_pi()` 对这个残缺树执行 `rb_add_cached()`，比较、链接和旋转尚未闭合。\n"
    md += "- `rt_mutex_adjust_pi()` 传给 chain walk 的 `orig_lock` 明确是 NULL；旧报告把 `lock==orig_lock` 当成 fake_lock 的必然阻断，这一点应删除。但 `rt_mutex_owner(lock)==top_task` 和其它链路条件仍需满足。\n"
    md += "- `misc_open()` 后续调用 `fops_get()`，而 `fops_get()` 会对 `fake_fops.owner` 执行 `try_module_get()`；因此当前“route 后再 open ashmem”的顺序不闭合。预先打开 transport fd、再通过已有 fd 修复 owner 是候选设计，不是已验证事实。\n\n"
    md += "## 当前门禁与最小下一步\n\n"
    md += "默认 poll 路由没有证明 stale waiter 的 `lock` 指向 `fake_lock`；256-fd pselect 方案还缺独立的 12-word 消费表、fd-mask 就绪状态和 post-erase `rb_add/rotation` 状态表。故本审计只把 **custom shape-1 的目标槽写入方程** 标为 `SYMBOLICALLY-CLOSED`，active default shape-0 仍为 `T-NOT-REACHED`，两者都不等于整条 exploit 链成功。最优下一步是离线完成“erase 后 stale root/leftmost → rb_add_cached → 可能的 rb_insert_color”状态机，并把 pre-open/owner-repair 作为单独传输层约束；在此之前不改 payload、不联机。\n"
    OUT_MD.write_text(md, encoding="utf-8")
    print(json.dumps({"json": str(OUT_JSON), "markdown": str(OUT_MD), "verdict": result["verdict"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
