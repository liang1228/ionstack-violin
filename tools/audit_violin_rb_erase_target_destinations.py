#!/usr/bin/env python3
"""Offline audit of rb_erase/rb_replace target-slot destinations.

This is a bounded source/symbolic audit.  It does not build, install, connect
to a device, or execute a payload.  The purpose is to distinguish a write to
the preceding miscdevice.name field (ashmem_misc + 0x08) from a write to the
actual miscdevice.fops slot (ashmem_misc + 0x10).
"""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "kernel-src-wsl" / "common-gki"
EXPLOIT = ROOT / "exploit-repo" / "IonStack" / "CVE-2026-43499" / "exploit"
SRC = EXPLOIT / "src"
RB_C = KERNEL / "lib" / "rbtree.c"
RB_AUG = KERNEL / "include" / "linux" / "rbtree_augmented.h"
RB_H = KERNEL / "include" / "linux" / "rbtree.h"
RTMUTEX_C = KERNEL / "kernel" / "locking" / "rtmutex.c"
MISC_C = KERNEL / "drivers" / "char" / "misc.c"
UTIL_C = SRC / "util.c"
TARGET_H = SRC / "targets" / "violin-v-oss" / "target.h"

OUT_DIR = ROOT / "analysis_outputs"
OUT_JSON = OUT_DIR / "violin-rb-erase-target-destinations-20260719.json"
OUT_MD = OUT_DIR / "violin-rb-erase-target-destinations-20260719.md"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def line_of(path: Path, needle: str) -> int | None:
    for no, line in enumerate(read(path).splitlines(), 1):
        if needle in line:
            return no
    return None


def source_evidence() -> dict:
    return {
        "rb_change_child": {
            "definition_line": line_of(RB_AUG, "__rb_change_child(struct rb_node *old"),
            "parent_left_store_line": line_of(RB_AUG, "WRITE_ONCE(parent->rb_left, new)"),
            "parent_right_store_line": line_of(RB_AUG, "WRITE_ONCE(parent->rb_right, new)"),
            "root_store_line": line_of(RB_AUG, "WRITE_ONCE(root->rb_node, new)"),
            "semantics": "parent.rb_left/right is selected by old identity; parent=NULL updates root.rb_node",
        },
        "rb_erase_augmented": {
            "definition_line": line_of(RB_AUG, "__rb_erase_augmented(struct rb_node *node"),
            "one_child_change_line": line_of(RB_AUG, "__rb_change_child(node, child, parent, root)"),
            "left_only_change_line": line_of(RB_AUG, "__rb_change_child(node, tmp, parent, root)"),
            "successor_change_line": line_of(RB_AUG, "__rb_change_child(node, successor, tmp, root)"),
            "semantics": "the direct child-link write is through the erased node's rb_parent()",
        },
        "rb_replace_node": {
            "definition_line": line_of(RB_C, "void rb_replace_node(struct rb_node *victim"),
            "change_child_line": line_of(RB_C, "__rb_change_child(victim, new, parent, root)"),
            "semantics": "replacement also writes only the victim parent child link (or root)",
        },
        "rtmutex_callers": {
            "dequeue_tree_erase_line": line_of(RTMUTEX_C, "rb_erase_cached(&waiter->tree.entry"),
            "dequeue_pi_erase_line": line_of(RTMUTEX_C, "rb_erase_cached(&waiter->pi_tree.entry"),
            "replace_node_references": "rb_replace_node is not called by rtmutex.c",
        },
        "misc_registration": {
            "init_list_line": line_of(MISC_C, "INIT_LIST_HEAD(&misc->list)"),
            "list_add_line": line_of(MISC_C, "list_add(&misc->list, &misc_list)"),
            "semantics": "fops slot is adjacent to a live list_head; image-time zero bytes are not post-registration state",
        },
        "payload": {
            "write_target_line": line_of(UTIL_C, "uintptr_t write_left = data_addr(ASHMEM_MISC) + 0x10 - 0x08"),
            "pi_parent_line": line_of(UTIL_C, "put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc)"),
            "pi_right_line": line_of(UTIL_C, "put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right)"),
            "pi_left_line": line_of(UTIL_C, "put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left)"),
            "fake_fops_table_line": line_of(UTIL_C, "put_fake_fops_table(p, FOPS_TABLE_OFF)"),
            "semantics": "current FOPS payload models W.parent=fake_fops, W.rb_right=NULL, W.rb_left=target-8",
        },
        "headers_used": {
            "rb_parent_line": line_of(RB_H, "#define rb_parent(r)"),
            "rb_erase_cached_line": line_of(RB_H, "rb_erase_cached(struct rb_node *node"),
            "rb_next_left_descent_line": line_of(RB_C, "if (node->rb_left)"),
            "rb_next_right_descent_line": line_of(RB_C, "while (node->rb_right)"),
        },
    }


def symbolic_graph() -> dict:
    # Names intentionally describe addresses, not runtime values.  Let T be
    # ashmem_misc + 0x10, the actual miscdevice.fops pointer slot.
    # N=T-8 is ashmem_misc + 0x08, the miscdevice.name pointer field.
    graph = {
        "symbols": {
            "T": "ashmem_misc + 0x10 (miscdevice.fops slot)",
            "N": "T - 0x08 = ashmem_misc + 0x08 (miscdevice.name field)",
            "W": "fake_w0 + 0x28 (fake_w0.pi_tree rb_node)",
            "F": "fake_fops (payload file_operations blob, interpreted as rb_node)",
            "A": "ashmem_fops (static kernel file_operations object)",
        },
        "initial_fields": {
            "W.__rb_parent_color": "F (payload write_pc; color bit is zero)",
            "W.rb_left": "N (payload write_left=T-8)",
            "W.rb_right": "NULL (payload write_right=0)",
            "F.rb_left": "NULL (fake_fops.read=0)",
            "F.rb_right": "W (fake_fops.llseek=W)",
            "N.rb_right": "A (contents of ashmem_misc.fops slot)",
            "N.rb_left": "runtime miscdevice.list.next alias (not image-time zero)",
        },
        "rb_erase_W_one_child": {
            "precondition": "rb_erase(W): W.rb_left=N, W.rb_right=NULL, rb_parent(W)=F",
            "cached_leftmost_update": "if pi_waiters.rb_leftmost==W, rb_erase_cached first sets it to rb_next(W)=A (W.left=N, N.right=A, A.left=NULL)",
            "__rb_change_child": "__rb_change_child(W, N, F, root)",
            "writes": [
                "F.rb_right = N (fake_fops + 0x08)",
                "N.__rb_parent_color = F (N = ashmem_misc + 0x08)",
            ],
            "does_not_write": [
                "T (ashmem_misc + 0x10 fops slot)",
                "root.rb_node (because parent is non-NULL)",
            ],
            "rebalance": "none when W parent/color word is red (payload value F has low color bit 0)",
        },
        "rb_replace_W": {
            "precondition": "rb_replace_node(W, NEW, root): rb_parent(W)=F",
            "writes": [
                "NEW receives W's rb fields",
                "F.rb_right = NEW (victim parent child link)",
            ],
            "does_not_write": ["T (unless a separate, unproven victim/parent state exists)"],
            "reachability": "not a current rtmutex call; retained as a conditional API check",
        },
        "conditional_target_write": {
            "required_parent": "N = T-8",
            "required_branch": "parent.rb_right == victim",
            "known_value": "N.rb_right currently aliases T and contains A",
            "candidate": "an rb_erase/rb_replace of victim A with rb_parent(A)=N could write N.rb_right=T",
            "status": "conditional only",
            "why_not_closed": [
                "current W erase sets N.__rb_parent_color=F, not A.__rb_parent_color=N",
                "A is a static file_operations object, not a proven rt_mutex rb_node",
                "rtmutex.c uses rb_erase_cached, not rb_replace_node",
                "no reachable call state proves victim=A with parent=N",
            ],
        },
        "rb_set_parent_color": {
            "target_condition": "first argument must be exactly T",
            "known_destinations": [
                "W (W.__rb_parent_color)",
                "F (fake_fops.__rb_parent_color)",
                "A+0x10 or another visited rb-node alias, depending on rotation state",
            ],
            "status": "T is not present in the known destination set",
        },
    }
    return graph


def main() -> int:
    evidence = source_evidence()
    graph = symbolic_graph()
    result = {
        "audit": "violin rb_erase/rb_replace target destinations",
        "date": "2026-07-19",
        "mode": "offline-source-and-symbolic-only",
        "sources": {
            "rbtree_augmented_h": str(RB_AUG),
            "rbtree_c": str(RB_C),
            "rbtree_h": str(RB_H),
            "rtmutex_c": str(RTMUTEX_C),
            "misc_c": str(MISC_C),
            "util_c": str(UTIL_C),
            "target_h": str(TARGET_H),
        },
        "evidence": evidence,
        "graph": graph,
        "verdict": {
            "current_rb_erase_target_write": "not established",
            "current_rb_erase_W_direct_destination": "fake_fops + 0x08, plus N.__rb_parent_color",
            "conditional_parent_N_victim_A_path": "possible in abstract, not reachable/proven in current rtmutex graph",
            "rb_replace_relevance": "not in current rtmutex call graph",
            "fops_slot_reached": False,
            "runtime_allowed": False,
            "next_gate": "either prove a concrete victim=A,parent=N rb_erase state, or abandon this anchor and choose a different write primitive/target",
        },
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md = "# Violin rb_erase/rb_replace target-destination audit (2026-07-19)\n\n"
    md += "**Mode:** offline source and symbolic graph only. No payload build, install, device connection, or runtime execution.\n\n"
    md += "## Verdict\n\n"
    md += "当前 FOPS 图中，`rb_erase(W)` 的直接写入目标不是 `ashmem_misc + 0x10`。`W=fake_w0.pi_tree` 的 `rb_parent` 是 `F=fake_fops`，`rb_left=N=(ashmem_misc + 0x10)-0x08`，`rb_right=NULL`；若 cached leftmost 指向 W，`rb_erase_cached` 先把它更新为 `rb_next(W)=A=ashmem_fops`（W.left=N、N.right=A、A.left=NULL）。随后一子节点路径只会执行 `__rb_change_child(W, N, F, root)`，即写 `F.rb_right`，再把 `N.__rb_parent_color` 设为 `F`。因为 parent 非 NULL，`root.rb_node` 也不会被更新。\n\n"
    md += "## Target-slot equation\n\n"
    md += "真实目标槽记为 `T=ashmem_misc+0x10`，其前一个字段 `N=T-0x08` 是 `miscdevice.name`。把 `N` 当作 rb_node 时，`N.rb_right` 恰好别名 `T`，而镜像中的该值是 `ashmem_fops`。因此抽象上只有一种 erase/replace 机会能改写 T：必须出现 `parent=N` 且被移除/替换的 victim 正好是 `N.rb_right=A=ashmem_fops`，使 `__rb_change_child()` 走 `N.rb_right` 分支。当前图没有证明这个 victim/parent 对；相反，W 的 erase 只把 N 的 parent 写成 F。\n\n"
    md += "## API/call-graph checks\n\n"
    md += f"- `rbtree_augmented.h:{evidence['rb_change_child']['parent_right_store_line']}` 的父右链接写是 `WRITE_ONCE(parent->rb_right, new)`；目标 T 需要 parent 恰为 N。\n"
    md += f"- `rbtree_augmented.h:{evidence['rb_erase_augmented']['one_child_change_line']}` 的一子节点 erase 通过 victim 的 `rb_parent()` 选择 parent。\n"
    md += f"- `rtmutex.c:{evidence['rtmutex_callers']['dequeue_pi_erase_line']}` 是当前 owner PI-tree 的实际 `rb_erase_cached()` 调用；当前 rtmutex 没有 `rb_replace_node()` 调用。\n"
    md += f"- `misc.c:{evidence['misc_registration']['init_list_line']}` / `:{evidence['misc_registration']['list_add_line']}` 说明 fops 槽邻接的 list 字段必须按注册后的运行时状态建模，不能把镜像零值当作 live child。\n\n"
    md += "## Conditional path and stop condition\n\n"
    md += "`rb_replace_node()` 也只改 victim 的父链接；它不在当前 rtmutex 路径中。若没有新的离线证据证明 `A` 被当作 rb victim 且 `rb_parent(A)=N`，则该条件路径不能作为成功方案。当前结论为 **RB-ERASE-FOPS-SLOT-NOT-CLOSED**：不改 fd-set，不调整 pselect，不构建、不联机。下一步应在这个条件证明失败后更换写入锚点/原语，而不是继续重复 route 运行。\n"
    OUT_MD.write_text(md, encoding="utf-8")
    print(json.dumps({"json": str(OUT_JSON), "markdown": str(OUT_MD), "verdict": result["verdict"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
