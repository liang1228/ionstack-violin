#!/usr/bin/env python3
"""Offline post-rb_erase state audit for the Violin FOPS candidate.

This report is deliberately a bounded source/layout model.  It does not
change the payload, compile it, connect to a device, or execute a route.

The important distinction is between the active default (shape 0) and the
custom shape-1 candidate.  ``main.c`` does not call ``set_pselect_write()``,
so the active default has W.parent=F, W.left=N, W.right=NULL and never writes
the real fops slot T.  Shape 1 can write T through N.rb_right, but the erase
leaves a stale cached tree and aliases fake_fops.owner before the fresh open.
Same-build BTF/raw-image evidence makes that owner gate a
likely-pass-with-side-effect prediction, not a hard blocker; the runtime tree
consumer remains unresolved.
"""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "kernel-src-wsl" / "common-gki"
EXPLOIT = ROOT / "exploit-repo" / "IonStack" / "CVE-2026-43499" / "exploit"
SRC = EXPLOIT / "src"

UTIL_C = SRC / "util.c"
MAIN_C = SRC / "main.c"
FOPS_C = SRC / "fops.c"
COMMON_H = SRC / "common.h"
TARGET_H = SRC / "targets" / "violin-v-oss" / "target.h"
RB_H = KERNEL / "include" / "linux" / "rbtree.h"
RB_AUG = KERNEL / "include" / "linux" / "rbtree_augmented.h"
RTMUTEX_C = KERNEL / "kernel" / "locking" / "rtmutex.c"
RTMUTEX_API_C = KERNEL / "kernel" / "locking" / "rtmutex_api.c"
MISC_C = KERNEL / "drivers" / "char" / "misc.c"
FS_H = KERNEL / "include" / "linux" / "fs.h"

OUT_DIR = ROOT / "analysis_outputs"
OUT_JSON = OUT_DIR / "violin-rb-erase-postwrite-state-20260722.json"
OUT_MD = OUT_DIR / "violin-rb-erase-postwrite-state-20260722.md"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def line_of(path: Path, needle: str) -> int | None:
    for number, line in enumerate(read(path).splitlines(), 1):
        if needle in line:
            return number
    return None


def source_evidence() -> dict:
    return {
        "active_selection": {
            "main_prepare_page_line": line_of(MAIN_C, "prepare_good_kernel_page(PAGE_PAYLOAD_FOPS)"),
            "main_no_custom_write_line": line_of(MAIN_C, "不调用 set_pselect_write"),
            "shape_selector_line": line_of(UTIL_C, "int write_shape = pselect_write_shape()"),
            "shape0_parent_line": line_of(UTIL_C, "fake_parent = write_value"),
            "shape0_left_line": line_of(UTIL_C, "fake_left = write_target"),
            "shape1_parent_line": line_of(UTIL_C, "fake_parent = write_target - 8"),
            "shape1_right_line": line_of(UTIL_C, "fake_right = write_value"),
            "shape1_left_line": line_of(UTIL_C, "fake_left = 0"),
        },
        "payload_fields": {
            "pi_parent_write_line": line_of(UTIL_C, "FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc"),
            "pi_right_write_line": line_of(UTIL_C, "FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right"),
            "pi_left_write_line": line_of(UTIL_C, "FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left"),
            "fake_fops_owner_line": line_of(UTIL_C, "put64(p, off + FOPS_OWNER_OFF, 0)"),
            "fake_fops_llseek_line": line_of(UTIL_C, "put64(p, off + FOPS_LLSEEK_OFF"),
            "fake_fops_read_line": line_of(UTIL_C, "put64(p, off + FOPS_READ_OFF, 0)"),
            "fake_fops_write_line": line_of(UTIL_C, "put64(p, off + FOPS_WRITE_OFF, 0)"),
        },
        "erase": {
            "cached_line": line_of(RB_H, "leftmost = root->rb_leftmost = rb_next(node)"),
            "erase_call_line": line_of(RB_H, "rb_erase(node, &root->rb_root)"),
            "change_child_definition_line": line_of(RB_AUG, "__rb_change_child(struct rb_node *old"),
            "change_child_right_line": line_of(RB_AUG, "WRITE_ONCE(parent->rb_right, new)"),
            "one_child_line": line_of(RB_AUG, "__rb_change_child(node, child, parent, root)"),
            "copy_parent_line": line_of(RB_AUG, "child->__rb_parent_color = pc"),
            "dequeue_pi_line": line_of(RTMUTEX_C, "rb_erase_cached(&waiter->pi_tree.entry"),
            "clear_node_line": line_of(RTMUTEX_C, "RB_CLEAR_NODE(&waiter->pi_tree.entry)"),
        },
        "post_erase_consumer": {
            "add_cached_line": line_of(RB_H, "rb_add_cached(struct rb_node *node"),
            "add_loop_line": line_of(RB_H, "while (*link)"),
            "add_link_line": line_of(RB_H, "rb_link_node(node, parent, link)"),
            "add_color_line": line_of(RB_H, "rb_insert_color_cached(node, tree, leftmost)"),
            "enqueue_pi_line": line_of(RTMUTEX_C, "rb_add_cached(&waiter->pi_tree.entry"),
            "clone_prio_line": line_of(RTMUTEX_C, "waiter_clone_prio(waiter, task)"),
            "fake_task_blocked_on_line": line_of(UTIL_C, "FAKE_TASK_OFF + pi_blocked_on_off, fake_w0"),
            "fake_fops_write_zero_line": line_of(UTIL_C, "FOPS_WRITE_OFF, 0"),
            "adjust_pi_orig_lock_line": line_of(RTMUTEX_API_C, "rt_mutex_adjust_prio_chain(task, RT_MUTEX_MIN_CHAINWALK, NULL,"),
        },
        "open_transport": {
            "try_cfi_open_line": line_of(FOPS_C, "int fd = open_ashmem_device()"),
            "try_cfi_write_line": line_of(FOPS_C, "configfs_write_once(fd, binwrite_target"),
            "misc_open_fops_get_line": line_of(MISC_C, "new_fops = fops_get(iter->fops)"),
            "fops_get_line": line_of(FS_H, "try_module_get((fops)->owner)"),
        },
    }


def states() -> dict:
    return {
        "symbols": {
            "T": "ashmem_misc + 0x10 (miscdevice.fops slot)",
            "N": "T - 0x08 (miscdevice.name; interpreted as rb_node)",
            "W": "fake_w0 + 0x28 (pi_tree.entry rb_node)",
            "F": "fake_fops (file_operations blob interpreted as rb_node)",
            "X": "the waiter inserted by rt_mutex_enqueue_pi after prerequeue_top_waiter is dequeued",
        },
        "active_default_shape0": {
            "activation": "main.c does not call set_pselect_write(); pselect_write_shape() returns 0",
            "before_erase": "W.parent=F, W.left=N, W.right=NULL; F.right=W from fake_fops.llseek",
            "cached_update": "rb_next(W) is computed before unlink; with W as F.right and F.parent=NULL, leftmost becomes NULL",
            "unlink": "__rb_change_child(W,N,F,root) writes F.rb_right=N; N.__rb_parent_color=F",
            "target": "T is unchanged; F.rb_right is fake_fops.llseek, not ashmem_misc.fops",
            "post_state": "RB_CLEAR_NODE(W) leaves root stale at W; no direct fops-slot write is established",
            "verdict": "ACTIVE-T-NOT-REACHED",
        },
        "custom_shape1": {
            "activation": "requires custom set_pselect_write()/shape=1 path; not active in main.c",
            "before_erase": "W.parent=N, W.left=NULL, W.right=F; F.left=NULL, F.right=W",
            "cached_update": "rb_next(W)=F, so fake_task.pi_waiters.rb_leftmost becomes F",
            "unlink": "__rb_change_child(W,F,N,root) takes else because N.rb_left is live miscdevice.list.next, not W",
            "target": "N.rb_right aliases T; therefore T := F",
            "side_effect": "F.__rb_parent_color := N, so F.owner := N",
            "post_state": "rb_root remains W (parent N is non-NULL), rb_leftmost is F, and RB_CLEAR_NODE(W) makes W self-parented/empty",
            "verdict": "TARGET-EQUATION-CLOSED-BUT-CONSUMER-STATE-BROKEN",
        },
        "custom_followup_enqueue": {
            "call": "rt_mutex_enqueue_pi(task, waiter) -> rb_add_cached(waiter->pi_tree.entry, &task->pi_waiters, __pi_waiter_less)",
            "root_seen": "rb_add_cached starts from stale rb_root=W; it does not consult rb_leftmost first",
            "identity_gate": "payload sets fake_task.pi_blocked_on=fake_w0; if the consumed lock also reports prerequeue_top_waiter=fake_w0, the post-erase enqueue is W itself. If that identity/top-waiter condition is false, the custom pi-tree erase is not reached and T:=F is not realized.",
            "same_waiter_path": "waiter_clone_prio() changes W.pi_tree.prio to fake_task.prio=120; W.prio=120, F.prio aliases fake_fops.write=0, and both less(W,W) and less(W,F) are false",
            "same_waiter_cycle": "rb_add follows root W -> W.rb_right=F -> F.rb_right=W -> W.rb_right=F without finding NULL; rb_insert_color is not reached",
            "closure": "conditional no-return is closed for the same-waiter identity; otherwise the destination write is not reached. No safe userspace return is established",
        },
        "owner_open_gate": {
            "order": "try_cfi_stage opens ashmem after the route, before configfs_write_once",
            "open_operation": "misc_open -> fops_get(iter->fops) -> try_module_get(fake_fops.owner)",
            "custom_owner": "fake_fops.owner=N after erase; N is not a valid module pointer, but same-build BTF/raw-image bytes are module-shaped",
            "result": "with CONFIG_MODULE_UNLOAD=y, source only checks module_is_live() and atomic_inc_not_zero(); raw image predicts a likely pass and an adjacent refcnt increment at dev_attr_recovery+0x8. Runtime initialization is not proven. Pre-opening an ashmem fd does not change its per-file f_op and therefore does not by itself supply a configfs fops transport",
            "status": "OWNER-OPEN-LIKELY-PASS-WITH-SIDEEFFECT-RUNTIME-UNCLOSED",
        },
        "orig_lock": {
            "source": "rt_mutex_adjust_pi passes orig_lock=NULL",
            "consequence": "lock==orig_lock is not an automatic fake_lock blocker; owner/top-task, route lock mapping and tree state remain independent gates",
        },
    }


def main() -> int:
    result = {
        "audit": "Violin rb_erase post-write state",
        "date": "2026-07-22",
        "mode": "offline-source-and-symbolic-only",
        "sources": {key: str(value) for key, value in {
            "util_c": UTIL_C,
            "main_c": MAIN_C,
            "fops_c": FOPS_C,
            "common_h": COMMON_H,
            "target_h": TARGET_H,
            "rbtree_h": RB_H,
            "rbtree_augmented_h": RB_AUG,
            "rtmutex_c": RTMUTEX_C,
            "rtmutex_api_c": RTMUTEX_API_C,
            "misc_c": MISC_C,
            "fs_h": FS_H,
        }.items()},
        "evidence": source_evidence(),
        "states": states(),
        "verdict": {
            "active_default": "T-NOT-REACHED",
            "custom_shape1_target_equation": "symbolically closed only",
            "custom_shape1_post_erase_enqueue": "conditional cycle closed for same-waiter identity; otherwise target write is not reached",
            "custom_shape1_fresh_open": "likely passes on raw image with adjacent refcnt side effect; runtime bytes and post-erase consumer remain unproven",
            "full_exploit_chain": "not established",
            "runtime_allowed": False,
            "next_gate": "abandon the inactive shape1 branch unless an independent write/owner repair and a valid post-erase tree consumer are proven; otherwise search for a different kernel write sink",
        },
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md = """# Violin rb_erase post-write state audit (2026-07-22)\n\n"""
    md += "**Mode:** offline source/layout/symbolic analysis only. No payload build, install, device connection, fd-set change, or runtime execution.\n\n"
    md += "## 1. Active default is still shape 0\n\n"
    md += "`main.c` explicitly does not call `set_pselect_write()`. Therefore the active payload has `W.parent=F`、`W.left=N`、`W.right=NULL` (with `F.right=W` from fake `llseek`). `rb_erase_cached(W)` computes `rb_next(W)` before unlink, then calls `__rb_change_child(W,N,F,root)`: the stores are `F.rb_right=N` and `N.__rb_parent_color=F`; **the actual slot T is not written**. Result: `ACTIVE-T-NOT-REACHED`.\n\n"
    md += "## 2. Custom shape 1 can write T, but breaks the consumer state\n\n"
    md += "The inactive custom candidate uses `W.parent=N`、`W.left=NULL`、`W.right=F`. The one-child erase calls `__rb_change_child(W,F,N,root)`. Since `N.rb_left` is live `miscdevice.list.next`, the helper takes else and stores `N.rb_right=F`; because `N.rb_right` aliases T, the symbolic target equation is `T := F`. The same child-parent copy sets `F.__rb_parent_color=N`, so `fake_fops.owner := N`.\n\n"
    md += "After that erase, `rb_root` remains W while cached leftmost is F; `RB_CLEAR_NODE(W)` makes W self-parented/empty. The payload also sets `fake_task.pi_blocked_on=fake_w0`. If the consumed lock reports `prerequeue_top_waiter=fake_w0`, the owner branch re-enqueues W itself after `waiter_clone_prio()`: W's priority becomes 120, F's synthetic priority aliases `fake_fops.write=0`, and `less(W,W)` / `less(W,F)` are both false. `rb_add_cached()` therefore follows `W -> F -> W` forever without reaching a NULL link or `rb_insert_color()`. If the top-waiter identity is false, the custom pi-tree erase is not reached and the target equation `T := F` is not realized. Thus the post-erase consumer is conditionally closed as a no-return cycle, while the identity gate remains unproven.\n\n"
    md += "## 3. Fresh-open gate\n\n"
    md += "`try_cfi_stage()` opens ashmem after the route. `misc_open()` calls `fops_get()`, which calls `try_module_get(fake_fops.owner)`. Same-build BTF reports `struct module.state` at `+0x0` and `refcnt` at `+0x5c0`; at N the raw image has `state=0x815eb0c9` and `refcnt=0x1a4`, with `CONFIG_MODULE_UNLOAD=y`. The checked source does not validate module-registry membership, so the raw-image prediction is **likely pass with an adjacent refcnt increment** (the alias is `dev_attr_recovery+0x8`), not a guaranteed fault. Runtime initialization may change those bytes, and the stale-tree consumer is still unresolved. Pre-opening an ashmem fd does not change its per-file `f_op`, so it does not by itself provide a post-hijack ConfigFS transport.\n\n"
    md += "## Verdict / next gate\n\n"
    md += "Active default: **T-NOT-REACHED**. Custom shape1: target equation is symbolically closed, owner/open is likely-pass-with-side-effect on the raw image, but the only same-waiter post-erase consumer is a closed `W↔F` traversal and the top-waiter identity is not proven. The optimal next move is not to enable shape1 or run another payload. Search offline for an independent write/owner-repair sink or a different consumer whose tree remains valid; otherwise archive this rb anchor as non-viable.\n"
    OUT_MD.write_text(md, encoding="utf-8")
    print(json.dumps({"json": str(OUT_JSON), "markdown": str(OUT_MD), "verdict": result["verdict"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
