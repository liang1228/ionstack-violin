#!/usr/bin/env python3
"""Offline raw-image/object-graph audit for the Violin rb write route.

This reconciles the same-build image with the current target-slot semantics.
It does not build, install, connect to a device, or execute a payload.
"""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IMAGE = ROOT / "analysis_outputs" / "ota_full" / "boot_parse" / "boot.img.kernel"
TARGET_H = ROOT / "exploit-repo" / "IonStack" / "CVE-2026-43499" / "exploit" / "src" / "targets" / "violin-v-oss" / "target.h"
COMMON_H = ROOT / "exploit-repo" / "IonStack" / "CVE-2026-43499" / "exploit" / "src" / "common.h"
MISC_C = ROOT / "kernel-src-wsl" / "common-gki" / "drivers" / "char" / "misc.c"
OUT_DIR = ROOT / "analysis_outputs"
OUT_JSON = OUT_DIR / "violin-raw-rb-object-graph-20260719.json"
OUT_MD = OUT_DIR / "violin-raw-rb-object-graph-20260719.md"
BASE = 0xFFFFFFC008000000


def define(path: Path, name: str, default: int | None = None) -> int | None:
    m = re.search(rf"^\s*#define\s+{re.escape(name)}\s+([^/\s]+)", path.read_text(encoding="utf-8"), re.M)
    if not m:
        return default
    try:
        return int(m.group(1).rstrip("ULLull"), 0)
    except ValueError:
        return default


def qword(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def image_qwords(buf: bytes, off: int, count: int = 14) -> list[int]:
    return [qword(buf, off + i * 8) for i in range(count)]


def fmt(value: int, base: int) -> str:
    if value == 0:
        return "NULL"
    if BASE <= value < BASE + 0x4000000:
        return f"image+0x{value - BASE:x}"
    return f"0x{value:016x}"


def rb_view(name: str, addr_off: int, words: list[int], labels: dict[int, str]) -> dict:
    parent, right, left = words[0], words[1], words[2]
    return {
        "name": name,
        "image_offset": hex(addr_off),
        "rb_parent_color_raw": hex(parent),
        "rb_parent_color_low_bit": parent & 3,
        "rb_right_raw": hex(right),
        "rb_left_raw": hex(left),
        "rb_right_symbol": labels.get(right, fmt(right, BASE)),
        "rb_left_symbol": labels.get(left, fmt(left, BASE)),
        "rb_right_null_in_image": right == 0,
        "rb_left_null_in_image": left == 0,
    }


def main() -> int:
    image = IMAGE.read_bytes()
    misc_fops_off = define(TARGET_H, "ASHMEM_MISC_FOPS_OFF", 0x1269710)
    ashmem_fops_off = define(TARGET_H, "ASHMEM_FOPS_OFF", 0x12C9DF0)
    ashmem_misc_off = define(TARGET_H, "ASHMEM_MISC_OFF", 0x223B5D8)
    fake_w0_off = define(TARGET_H, "W0_OFF", 0x2220)
    fake_pi_off = define(TARGET_H, "FAKE_WAITER_PI_TREE_ENTRY_OFF", 0x28)
    fake_prio = define(COMMON_H, "FAKE_WAITER_PRIO", 130)
    assert misc_fops_off is not None and ashmem_fops_off is not None and ashmem_misc_off is not None

    addresses = {
        BASE + misc_fops_off: "misc_fops",
        BASE + ashmem_fops_off: "ashmem_fops",
        BASE + ashmem_misc_off: "ashmem_misc",
        BASE + ashmem_misc_off + 0x08: "ashmem_misc+0x08 (name field)",
        BASE + ashmem_misc_off + 0x10: "ashmem_misc+0x10 (fops slot)",
        BASE + ashmem_misc_off + 0x18: "ashmem_misc.list",
        BASE + ashmem_misc_off + 0x20: "ashmem_misc.list+0x08",
    }
    records = {
        "misc_fops": rb_view("misc_fops as rb_node", misc_fops_off,
                              image_qwords(image, misc_fops_off), addresses),
        "ashmem_fops": rb_view("ashmem_fops as rb_node", ashmem_fops_off,
                                image_qwords(image, ashmem_fops_off), addresses),
        "ashmem_misc_plus_8": rb_view("ashmem_misc+0x08 as rb_node", ashmem_misc_off + 8,
                                       image_qwords(image, ashmem_misc_off + 8), addresses),
        "ashmem_misc_fops_slot": rb_view("ashmem_misc+0x10 as rb_node", ashmem_misc_off + 0x10,
                                          image_qwords(image, ashmem_misc_off + 0x10), addresses),
    }

    misc_words = image_qwords(image, misc_fops_off)
    ashmem_words = image_qwords(image, ashmem_fops_off)
    miscdev_words = image_qwords(image, ashmem_misc_off, 8)
    target_slot_value = miscdev_words[2]
    # Current payload graph: fake_w0.pi_tree.parent=fake_fops,
    # right=NULL, left=ashmem_misc+0x08.  In the mirror case a new node linked
    # at right rotates through fake_fops; it does not make the fops slot a node.
    graph = {
        "current_target": "ashmem_misc+0x10",
        "target_slot_initial_raw": hex(target_slot_value),
        "target_slot_initial_symbol": addresses.get(target_slot_value, fmt(target_slot_value, BASE)),
        "target_minus_8": {
            "rb_right": "ashmem_misc+0x10 contents = ashmem_fops (non-NULL)",
            "rb_left": "runtime miscdevice.list.next (non-NULL after INIT_LIST_HEAD/list_add)",
            "direct_link_to_target_slot": False,
        },
        "target_slot_as_rb_node": {
            "rb_right": "runtime miscdevice.list.next",
            "rb_left": "runtime miscdevice.list.prev",
            "post_registration_child_nulls": {
                "rb_right": False,
                "rb_left": False,
            },
            "is_reachable_from_target_minus_8_right": False,
            "reason": "target-8.rb_right loads the fops pointer value (ashmem_fops), not the address of the slot",
        },
        "static_fops_nulls": {
            "misc_fops.rb_left_is_NULL": misc_words[2] == 0,
            "ashmem_fops.rb_left_is_NULL": ashmem_words[2] == 0,
            "interpretation": "NULL insertion points exist in static fops objects, but they are not the ashmem_misc.fops slot",
        },
        "runtime_list": {
            "source": str(MISC_C),
            "init_list_head": "misc_register(): INIT_LIST_HEAD(&misc->list)",
            "add": "misc_register(): list_add(&misc->list, &misc_list)",
            "post_registration": "misc.list.next is misc_list.next (or &misc_list), misc.list.prev is &misc_list; both non-NULL",
            "source_lines": {
                "init": 217,
                "add": 258,
            },
        },
        "fake_payload": {
            "fake_w0_pi_node_offset": hex((fake_w0_off or 0) + (fake_pi_off or 0)),
            "fake_w0_pi_prio": fake_prio,
            "fake_w0_pi_left": "ashmem_misc+0x08",
            "fake_w0_pi_right": "NULL",
            "fake_fops_as_rb_right": "fake_w0.pi_tree (from fake_fops.llseek)",
        },
        "known_destination_set": {
            "rb_link_node": [
                "fake_w0.pi_tree + 0x08 (fake root right, when incoming prio takes right branch)",
                "ashmem_fops + 0x10 (static ashmem_fops.read, if traversal reaches ashmem_fops left NULL)",
            ],
            "rb_set_parent_color": [
                "ashmem_misc + 0x08 (target-8 parent_color, when target-8 is tmp)",
                "fake_fops + 0x00 (fake_fops.owner, rotation old node)",
                "other visited rb_node + 0x00 (only if a separate list node is reached)",
            ],
            "target_slot": "ashmem_misc + 0x10 is absent from the known destination set",
            "status": "TARGET-SLOT-NOT-REACHED-IN-KNOWN-GRAPH",
        },
    }

    verdict = {
        "prior_claim_misc_fops_all_nonzero": "refuted by same-build raw image",
        "prior_claim_target_slot_is_static_misc_fops": "false",
        "rb_insert_target_write": "not established",
        "best_current_explanation": "static fops NULL fields do not place rb_link_node/rb_set_parent_color destination at ashmem_misc+0x10; target-8 dereferences the ashmem_fops pointer value",
        "next_gate": "use misc_register list equations to eliminate the fops-slot-as-rb-node path, then enumerate remaining reachable rb_set_parent_color destinations; prove a first argument equal to the fops slot or select a different anchor",
        "runtime_allowed": False,
    }

    result = {
        "audit": "violin raw rb object graph reconciliation",
        "date": "2026-07-19",
        "mode": "offline-image-only",
        "image": str(IMAGE),
        "image_size": len(image),
        "base": hex(BASE),
        "offsets": {
            "misc_fops": hex(misc_fops_off),
            "ashmem_fops": hex(ashmem_fops_off),
            "ashmem_misc": hex(ashmem_misc_off),
        },
        "rb_views": records,
        "graph": graph,
        "verdict": verdict,
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md = "# Violin raw rb-object graph reconciliation (2026-07-19)\n\n"
    md += "**Mode:** offline same-build image only; no payload/build/device/runtime action.\n\n"
    md += "## Corrected baseline\n\n"
    md += "The same-build image refutes the earlier statement that every `misc_fops` field is non-NULL. `misc_fops` has `llseek` non-NULL but its read/write/read_iter/write_iter and poll-related slots are zero; `ashmem_fops` also has NULL slots.\n\n"
    md += "## Target-slot graph\n\n"
    md += f"- `ashmem_misc + 0x10` contains `ashmem_fops` (`{graph['target_slot_initial_symbol']}` in the image).\n"
    md += "- The current rb anchor `ashmem_misc + 0x08` has `rb_right` equal to the **contents** of the fops slot (`ashmem_fops`), not the slot address itself. Therefore traversal reaches the static `ashmem_fops` object, not `ashmem_misc + 0x10`.\n"
    md += "- Treating the slot itself as an rb_node aliases `rb_right/rb_left` to the live `miscdevice.list.next/prev`. `misc_register()` first initializes the list and then calls `list_add()`, so both child values are non-NULL after registration; the image zeros are only pre-registration bytes.\n\n"
    md += "## Consequence\n\n"
    md += "NULL fields in static fops objects reopen possible insertion anchors, but they do **not** establish a write to `ashmem_misc.fops`. In the known current graph, destinations are fake_w0.pi_tree+0x08, ashmem_fops+0x10, ashmem_misc+0x08, fake_fops+0x00, or another visited list node; `ashmem_misc+0x10` is absent.\n\n"
    md += "## Next offline gate\n\n"
    md += "Use the `misc_register()` list equations to eliminate the fops-slot-as-rb-node path, then enumerate the remaining reachable `rb_set_parent_color` first arguments. The required destination is exactly `ashmem_misc + 0x10`; if no reachable first argument equals that address, stop this anchor and choose a different write target.\n"
    OUT_MD.write_text(md, encoding="utf-8")
    print(json.dumps({"json": str(OUT_JSON), "markdown": str(OUT_MD), "verdict": verdict}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
