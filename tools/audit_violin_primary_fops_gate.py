#!/usr/bin/env python3
"""Reconcile the corrected Violin fops/rbtree gate offline.

This is a source + same-build image check only.  It does not build, install, or
execute a payload and does not change fd-set parameters.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC_UTIL = ROOT / "exploit-repo/IonStack/CVE-2026-43499/exploit/src/util.c"
SRC_FOPS = ROOT / "exploit-repo/IonStack/CVE-2026-43499/exploit/src/fops.c"
IMAGE = ROOT / "analysis_outputs/ota_full/boot_parse/boot.img.kernel"
OUT = ROOT / "analysis_outputs"

IMAGE_BASE = 0xFFFFFFC080000000
MISC_FOPS_OFF = 0x1269710
ASHMEM_FOPS_OFF = 0x12C9DF0
ASHMEM_MISC_OFF = 0x223B5D8


def qword(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def main() -> None:
    util = SRC_UTIL.read_text(encoding="utf-8")
    fops = SRC_FOPS.read_text(encoding="utf-8")
    image = IMAGE.read_bytes()

    target_slot = IMAGE_BASE + ASHMEM_MISC_OFF + 0x10
    target_predecessor = target_slot - 8
    # `ASHMEM_FOPS_OFF` is the address of the static table, not a pointer
    # slot.  The pointer stored in `ashmem_misc + 0x10` is therefore compared
    # with the image-base-adjusted table address.  Keep the first qword of the
    # table separately for completeness; it is the `owner` field and is
    # expected to be NULL in this image.
    ashmem_fops_addr = IMAGE_BASE + ASHMEM_FOPS_OFF
    ashmem_fops_first_qword = qword(image, ASHMEM_FOPS_OFF)
    misc_poll = qword(image, MISC_FOPS_OFF + 0x40)
    misc_owner = qword(image, MISC_FOPS_OFF)
    n_rb_left = qword(image, ASHMEM_MISC_OFF + 0x18)
    n_rb_right = qword(image, ASHMEM_MISC_OFF + 0x10)

    source_checks = {
        "default_target_equation": "write_left = data_addr(ASHMEM_MISC) + 0x10 - 0x08"
        in util,
        "default_fake_fops_value": "uintptr_t write_pc = fake_fops;" in util,
        "fake_w0_lock_user_va": "FAKE_WAITER_LOCK_OFF, (uint64_t)(uintptr_t)pselect_user_lock"
        in util,
        "active_poll_fd_minus_one": "pfd[0] = -1" in fops,
        "active_poll_user_pointer": "poll((struct pollfd *)pselect_user_lock, 1" in fops,
    }
    raw_checks = {
        "target_slot_points_to_ashmem_fops": n_rb_right == ashmem_fops_addr,
        "misc_fops_owner_null": misc_owner == 0,
        "misc_fops_poll_null": misc_poll == 0,
    }

    result = {
        "scope": "corrected primary fops/rbtree gate for explicit Violin source",
        "runtime_allowed": False,
        "raw_image": {
            "path": str(IMAGE),
            "image_base": hex(IMAGE_BASE),
            "misc_fops_offset": hex(MISC_FOPS_OFF),
            "ashmem_fops_offset": hex(ASHMEM_FOPS_OFF),
            "ashmem_misc_offset": hex(ASHMEM_MISC_OFF),
            "target_slot": hex(target_slot),
            "target_predecessor": hex(target_predecessor),
            "ashmem_fops_address": hex(ashmem_fops_addr),
            "ashmem_fops_first_qword": hex(ashmem_fops_first_qword),
            "misc_fops_owner": hex(misc_owner),
            "misc_fops_poll": hex(misc_poll),
            "predecessor_as_rb_left": hex(n_rb_left),
            "predecessor_as_rb_right": hex(n_rb_right),
        },
        "source_checks": source_checks,
        "raw_checks": raw_checks,
        "states": {
            "old_no_null_claim": "INVALIDATED_BY_RAW_IMAGE",
            "active_poll_user_lock_edge": "NO_SOURCE_EDGE",
            "default_shape0_direct_target_slot_write": "NOT_REACHED",
            "default_shape0_modeled_writes": [
                "[ashmem_misc+0x08] = fake_fops (rb_set_parent_color child write)",
                "[fake_fops+0x08] = ashmem_misc+0x08 (parent child-link write)",
            ],
            "custom_shape1_target_slot": "CONDITIONAL_ON_PI_DEQUEUE_IDENTITY",
            "custom_shape1_precondition": (
                "parent=N and N.rb_left != W; __rb_change_child then writes N.rb_right (=T)"
            ),
            "custom_shape1_precondition_from_raw": (
                "SUPPORTED_UNDER_MISC_REGISTER_LIST_INVARIANT; N.rb_left aliases misc_list.next, not W"
            ),
        },
        "verdict": "ACTIVE_PRIMARY_FOPS_WRITE_NOT_CLOSED",
        "next_gate": (
            "Keep default poll frozen.  If research continues, use the misc_register/list "
            "invariant and one offline state table for an explicit pselect/custom-shape route "
            "to prove PI dequeue identity, rb_erase/rb_add transitions, and fake_fops owner repair; otherwise "
            "close this anchor and use no historical artifact as runtime evidence."
        ),
    }
    OUT.mkdir(exist_ok=True)
    (OUT / "violin-primary-fops-gate-20260722.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    md = [
        "# Violin corrected primary fops gate (2026-07-22)",
        "",
        "Offline source/raw-image reconciliation only; no build, install, fd-set change, or runtime action.",
        "",
        "## Corrected facts",
        "",
        "- `misc_fops` contains NULL fields, including `poll`; the old no-NULL root-cause claim is invalid.",
        "- The actual fops pointer slot is `ashmem_misc + 0x10`, whose raw value is `&ashmem_fops`.",
        "- Active worktree route is `poll(fd=-1,nfds=1)`; the stale lock source is zeroed kernel `poll_wqueues`, not `pselect_user_lock`.",
        "",
        "## Default shape-0 model",
        "",
        "`T=ashmem_misc+0x10`, `N=T-0x08`, `W=fake_w0.pi_tree.entry`, `F=fake_fops`; source sets `W.parent=F`, `W.left=N`, `W.right=NULL`.",
        "",
        "The modeled erase writes `[N]=F` (the preceding `miscdevice.name` slot) and updates `[F+0x08]`; it does not write `T`. The fops slot remains `&ashmem_fops`.",
        "",
        "## Custom shape-1 condition",
        "",
        "Shape 1 uses `parent=N` and `old=W`. `__rb_change_child()` writes the right child when `N.rb_left != W`, so the target condition is the inverse of the earlier claim: `N.rb_left != W -> N.rb_right:=F -> T:=F`. `misc_register()` initializes `misc->list` and inserts it into `misc_list`; therefore `N.rb_left` aliases `misc_list.next` (the head or another miscdevice list node), not payload-page `W`, assuming no prior list corruption. The target equation is structurally supported once the PI dequeue identity reaches this erase; the remaining chain is still not closed.",
        "",
        "## Verdict",
        "",
        "**ACTIVE_PRIMARY_FOPS_WRITE_NOT_CLOSED**. The NULL fields reopen an anchor search but do not prove fops hijack. Default poll, old no-NULL diagnosis, and unproven custom-shape assumptions must not be mixed.",
        "",
        "## Next gate",
        "",
        result["next_gate"],
    ]
    (OUT / "violin-primary-fops-gate-20260722.md").write_text(
        "\n".join(md) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
