#!/usr/bin/env python3
"""Reconcile the shape-1 predecessor branch with misc_register() list invariants.

This is a source/raw-image audit only.  It does not build, install, connect to
the device, change fd-set parameters, or execute a payload.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPLOIT = ROOT / "exploit-repo/IonStack/CVE-2026-43499/exploit"
KERNEL = ROOT / "kernel-src-wsl/common-gki"
SRC_UTIL = EXPLOIT / "src/util.c"
MISC_C = KERNEL / "drivers/char/misc.c"
MISCDEVICE_H = KERNEL / "include/linux/miscdevice.h"
LIST_H = KERNEL / "include/linux/list.h"
RBTREE_AUG_H = KERNEL / "include/linux/rbtree_augmented.h"
PRIMARY = ROOT / "analysis_outputs/violin-primary-fops-gate-20260722.json"
RB = ROOT / "analysis_outputs/violin-rb-erase-postwrite-state-20260722.json"
IMAGE = ROOT / "analysis_outputs/ota_full/boot_parse/boot.img.kernel"
OUT = ROOT / "analysis_outputs"

IMAGE_BASE = 0xFFFFFFC080000000
ASHMEM_FOPS_OFF = 0x12C9DF0
ASHMEM_MISC_OFF = 0x223B5D8


def qword(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def main() -> None:
    util = SRC_UTIL.read_text(encoding="utf-8")
    misc_c = MISC_C.read_text(encoding="utf-8")
    miscdevice_h = MISCDEVICE_H.read_text(encoding="utf-8")
    list_h = LIST_H.read_text(encoding="utf-8")
    rbtree_aug_h = RBTREE_AUG_H.read_text(encoding="utf-8")
    primary = json.loads(PRIMARY.read_text(encoding="utf-8"))
    rb = json.loads(RB.read_text(encoding="utf-8"))
    image = IMAGE.read_bytes()

    target = IMAGE_BASE + ASHMEM_MISC_OFF + 0x10
    predecessor = target - 8
    ashmem_fops = IMAGE_BASE + ASHMEM_FOPS_OFF
    raw_n_left = qword(image, ASHMEM_MISC_OFF + 0x18)
    raw_n_right = qword(image, ASHMEM_MISC_OFF + 0x10)

    source_checks = {
        "miscdevice_field_order": all(
            token in miscdevice_h
            for token in (
                "int minor;",
                "const char *name;",
                "const struct file_operations *fops;",
                "struct list_head list;",
            )
        ),
        "misc_register_initializes_list": "INIT_LIST_HEAD(&misc->list);" in misc_c,
        "misc_register_adds_to_front": "list_add(&misc->list, &misc_list);" in misc_c,
        "list_add_uses_head_next": "__list_add(new, head, head->next)" in list_h,
        "list_add_writes_new_next_prev": all(
            token in list_h for token in ("new->next = next;", "new->prev = prev;")
        ),
        "rb_change_child_tests_left_then_right": (
            "if (parent->rb_left == old)" in rbtree_aug_h
            and "WRITE_ONCE(parent->rb_left, new);" in rbtree_aug_h
            and "WRITE_ONCE(parent->rb_right, new);" in rbtree_aug_h
        ),
        "shape1_parent_is_predecessor": "fake_parent = write_target - 8" in util,
        "shape1_w_is_right_child_f": (
            "fake_right = write_value" in util and "fake_left = 0" in util
        ),
        "shape1_fake_fops_right_is_w": "FAKE_WAITER_PI_TREE_ENTRY_OFF" in util,
    }

    raw_checks = {
        "raw_target_slot_points_to_ashmem_fops": raw_n_right == ashmem_fops,
        "raw_predecessor_left_is_not_w": raw_n_left == 0,
        "primary_raw_gate_passed": all(primary["raw_checks"].values()),
    }

    # At N = ashmem_misc + 0x08, rb_right aliases misc->fops and rb_left aliases
    # misc->list.next.  misc_register() initializes the list and then inserts it
    # after misc_list, so the child tested by __rb_change_child is the list
    # successor, not the payload-page W node.  Under the current no-prior-list-
    # corruption model it cannot equal W.  This is the inverse of the earlier
    # (incorrect) requirement that N.rb_left must equal W.
    derived = {
        "N_rb_right_before_erase": "T contents = &ashmem_fops (not W)",
        "N_rb_left_after_register": "misc_list.next (empty-head or existing miscdevice.list node)",
        "shape1_change_child_condition": "N.rb_left == W -> writes N.rb_left; N.rb_left != W -> writes N.rb_right",
        "shape1_target_branch": "N.rb_left != W -> N.rb_right := F -> T := F",
        "predecessor_gate": "CLOSED_UNDER_CURRENT_LIST_INVARIANT",
        "remaining_identity_gate": "rt_mutex_dequeue_pi(fake_task, fake_w0) must actually be reached",
        "post_erase_state": "root remains W, cached leftmost becomes F, same-waiter rb_add can cycle W->F->W",
        "owner_side_effect": "F.__rb_parent_color := N, so F.owner := N",
    }

    result = {
        "audit": "Violin misc_register shape-1 predecessor correction",
        "date": "2026-07-22",
        "mode": "offline-kernel-source-and-same-build-image-only",
        "runtime_allowed": False,
        "sources": {
            "util_c": str(SRC_UTIL),
            "misc_c": str(MISC_C),
            "miscdevice_h": str(MISCDEVICE_H),
            "list_h": str(LIST_H),
            "rbtree_augmented_h": str(RBTREE_AUG_H),
            "primary_gate": str(PRIMARY),
            "rb_postwrite": str(RB),
            "raw_image": str(IMAGE),
        },
        "addresses": {
            "T_ashmem_misc_fops_slot": hex(target),
            "N_ashmem_misc_minus_8": hex(predecessor),
            "ashmem_fops": hex(ashmem_fops),
            "raw_N_rb_left": hex(raw_n_left),
            "raw_N_rb_right": hex(raw_n_right),
        },
        "source_checks": source_checks,
        "raw_checks": raw_checks,
        "derived": derived,
        "verdict": {
            "shape1_predecessor_gate": "CLOSED_UNDER_CURRENT_LIST_INVARIANT",
            "shape1_target_equation": "CONDITIONALLY_REACHABLE_ON_PI_DEQUEUE_IDENTITY",
            "shape1_full_chain": "NOT_CLOSED",
            "old_child_equals_W_claim": "SUPERSEDED_INVERSE_BRANCH_CONDITION",
        },
        "next_gate": (
            "Stop treating N.rb_left==W as a prerequisite.  The remaining offline gates are "
            "PI dequeue identity/reachability, terminating post-erase rb_add, and owner/transport "
            "repair; do not change fd-set values or run a payload."
        ),
    }
    OUT.mkdir(exist_ok=True)
    out_json = OUT / "violin-misc-list-predecessor-20260722.json"
    out_md = OUT / "violin-misc-list-predecessor-20260722.md"
    out_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md = [
        "# Violin misc_register predecessor correction (2026-07-22)",
        "",
        "Offline kernel-source/raw-image reconciliation only; no build, install, fd-set change, device connection, or payload execution.",
        "",
        "## Layout",
        "",
        f"- `T=ashmem_misc+0x10` = `{hex(target)}`; `N=T-0x08` = `{hex(predecessor)}`.",
        f"- `N.rb_right` aliases `miscdevice.fops` and is initially `&ashmem_fops` = `{hex(ashmem_fops)}`.",
        "- `N.rb_left` aliases `miscdevice.list.next`.",
        "",
        "## Correct branch condition",
        "",
        "`__rb_change_child()` writes `parent->rb_left` only when `parent->rb_left == old`; otherwise it writes `parent->rb_right`.  For shape-1, `parent=N` and `old=W`, so the target branch is **`N.rb_left != W`**, not `N.rb_left == W`.",
        "",
        "`misc_register()` performs `INIT_LIST_HEAD(&misc->list)` and then `list_add(&misc->list, &misc_list)`.  Therefore `N.rb_left` becomes `misc_list.next` (the list head when empty or an existing miscdevice list node), not the payload-page `W`, assuming no prior independent list corruption.",
        "",
        "## Result",
        "",
        "- Shape-1 predecessor gate: **CLOSED_UNDER_CURRENT_LIST_INVARIANT**.",
        "- If PI dequeue actually consumes `fake_w0`, `__rb_change_child(W,F,N,root)` takes the right-child arm and writes `N.rb_right:=F`, i.e. `T:=F`.",
        "- This does not close the chain: the same-waiter post-erase `rb_add` can still traverse `W→F→W`, and `F.owner:=N` leaves fresh-open/owner repair unresolved.",
        "",
        "## Correction",
        "",
        "The earlier claim that shape-1 requires the predecessor child link to equal `W` is superseded; the branch condition is the inverse.  Do not use that claim as the blocker.",
        "",
        "## Next gate",
        "",
        result["next_gate"],
    ]
    out_md.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
