#!/usr/bin/env python3
"""Offline inventory of alternate file_operations slots for the rb route.

The inventory asks a narrow question: do any NULL file_operations slots in the
same-build image coincide with a child-link destination reachable from the
known rb graph, and would the write value be callable?  No payload is built or
run by this script.
"""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IMAGE = ROOT / "analysis_outputs" / "ota_full" / "boot_parse" / "boot.img.kernel"
TARGET_H = ROOT / "exploit-repo" / "IonStack" / "CVE-2026-43499" / "exploit" / "src" / "targets" / "violin-v-oss" / "target.h"
OUT_DIR = ROOT / "analysis_outputs"
OUT_JSON = OUT_DIR / "violin-alternate-fops-slot-audit-20260719.json"
OUT_MD = OUT_DIR / "violin-alternate-fops-slot-audit-20260719.md"
BASE = 0xFFFFFFC008000000

FOPS_FIELDS = {
    0x00: "owner",
    0x08: "llseek",
    0x10: "read",
    0x18: "write",
    0x20: "read_iter",
    0x28: "write_iter",
    0x30: "iopoll",
    0x38: "iterate_shared",
    0x40: "poll",
    0x48: "unlocked_ioctl",
    0x50: "compat_ioctl",
    0x58: "mmap",
    0x60: "mmap_supported_flags",
    0x68: "open",
    0x70: "flush",
    0x78: "release",
    0x80: "fsync",
    0x88: "fasync",
    0x90: "lock",
    0x98: "get_unmapped_area",
    0xa0: "check_flags",
    0xa8: "flock",
    0xb0: "splice_write",
    0xb8: "splice_read",
    0xc0: "splice_eof",
    0xc8: "setlease",
    0xd0: "fallocate",
    0xd8: "show_fdinfo",
}


def define(name: str, default: int) -> int:
    src = TARGET_H.read_text(encoding="utf-8")
    m = re.search(rf"^\s*#define\s+{re.escape(name)}\s+([^/\s]+)", src, re.M)
    if not m:
        return default
    return int(m.group(1).rstrip("ULLull"), 0)


def qword(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def fmt(v: int) -> str:
    if v == 0:
        return "NULL"
    if BASE <= v < BASE + 0x4000000:
        return f"image+0x{v - BASE:x}"
    return f"0x{v:016x}"


def fops_slots(image: bytes, name: str, off: int) -> list[dict]:
    rows = []
    for rel, field in FOPS_FIELDS.items():
        value = qword(image, off + rel)
        rows.append({
            "object": name,
            "object_offset": hex(off),
            "field": field,
            "field_offset": hex(rel),
            "address": hex(BASE + off + rel),
            "value": hex(value),
            "value_display": fmt(value),
            "null": value == 0,
        })
    return rows


def main() -> int:
    image = IMAGE.read_bytes()
    misc_off = define("ASHMEM_MISC_FOPS_OFF", 0x1269710)
    ashmem_off = define("ASHMEM_FOPS_OFF", 0x12C9DF0)
    miscdev_off = define("ASHMEM_MISC_OFF", 0x223B5D8)

    all_slots = fops_slots(image, "misc_fops", misc_off) + fops_slots(image, "ashmem_fops", ashmem_off)
    null_slots = [row for row in all_slots if row["null"]]
    null_pointer_or_callback_slots = [
        row for row in null_slots if row["field"] != "mmap_supported_flags"
    ]

    # These are the only static rb-node bases that the reconciled graph can
    # currently reach or intentionally model.  T is the actual fops slot; N
    # is the preceding miscdevice.name field.
    addresses = {
        "N=ashmem_misc+0x08": BASE + miscdev_off + 0x08,
        "T=ashmem_misc+0x10": BASE + miscdev_off + 0x10,
        "A=ashmem_fops": BASE + ashmem_off,
        "M=misc_fops (alternate anchor only)": BASE + misc_off,
    }
    parent_candidates = []
    for label, parent in addresses.items():
        parent_candidates.extend([
            {"parent": label, "parent_address": hex(parent), "child_slot": hex(parent + 0x08), "edge": "rb_right"},
            {"parent": label, "parent_address": hex(parent), "child_slot": hex(parent + 0x10), "edge": "rb_left"},
        ])
    by_address = {int(row["address"], 16): row for row in null_slots}
    intersections = []
    for candidate in parent_candidates:
        slot = int(candidate["child_slot"], 16)
        row = by_address.get(slot)
        if row:
            intersections.append({
                **candidate,
                "object": row["object"],
                "field": row["field"],
                "field_offset": row["field_offset"],
                "write_value_if_rb_link_node": "new_waiter pi_tree address (not a callable fops function)",
                "current_graph_status": (
                    "reachable conditional: A left NULL; current graph reaches A through N.rb_right content"
                    if row["object"] == "ashmem_fops" and row["field"] == "read"
                    else "alternate anchor only or not proven"
                ),
            })

    rb_color_hazards = []
    for name, off in (("misc_fops", misc_off), ("ashmem_fops", ashmem_off)):
        owner = qword(image, off)
        if owner == 0:
            rb_color_hazards.append({
                "object": name,
                "owner_word": "0x0",
                "rb_parent": "NULL",
                "rb_color": "RED (low color bit 0)",
                "insert_consequence": "an insertion below this interpreted rb_node sees red parent with NULL gparent and cannot form a valid rb_insert state",
            })

    # A file_operations callback requires a kernel text/function pointer.  The
    # current rb primitives only produce node/parent/child addresses or NULL;
    # none of the reachable NULL callback slots gets a proven callable value.
    callable_value_paths = []
    for item in intersections:
        callable_value_paths.append({
            "object": item["object"],
            "field": item["field"],
            "callable_value_proven": False,
            "reason": "rb_link_node stores the incoming rb_node address; rb_set_parent_color stores a parent/node address, not CONFIGFS_* function text",
        })

    result = {
        "audit": "violin alternate file_operations slot inventory",
        "date": "2026-07-19",
        "mode": "offline same-build image plus symbolic graph",
        "image": str(IMAGE),
        "offsets": {"misc_fops": hex(misc_off), "ashmem_fops": hex(ashmem_off), "ashmem_misc": hex(miscdev_off)},
        "null_field_count": len(null_slots),
        "null_pointer_or_callback_count": len(null_pointer_or_callback_slots),
        "null_slots": null_slots,
        "parent_candidates": parent_candidates,
        "rb_child_destination_intersections": intersections,
        "rb_color_hazards": rb_color_hazards,
        "callable_value_paths": callable_value_paths,
        "verdict": {
            "ashmem_fops_read_candidate": "reachable as rb_link_node destination but value is new_waiter, not a callable fops function",
            "misc_fops_null_slots": "alternate anchor not reached by current ashmem_misc+0x08 graph",
            "target_slot": "ashmem_misc+0x10 remains non-NULL and not a proven child-link destination",
            "independent_usable_fops_sink": False,
            "next_gate": "stop static-fops-null-slot branch; enumerate a different kernel object whose writable field both reaches the graph and accepts a proven callable/value",
            "runtime_allowed": False,
        },
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md = "# Violin alternate file_operations slot audit (2026-07-19)\n\n"
    md += "**Mode:** offline same-build image and symbolic graph only; no payload build, install, device connection, or runtime execution.\n\n"
    md += "## Result\n\n"
    md += f"Raw image contains {len(null_slots)} NULL qword fields across `misc_fops` and `ashmem_fops` (其中 {len(null_pointer_or_callback_slots)} 个是 pointer/callback 字段，另 2 个是两个对象各自的 scalar `mmap_supported_flags`). The reconciled graph has one meaningful intersection: `ashmem_fops.read` (`A+0x10`), because `N=ashmem_misc+0x08` loads the fops-slot content `A` and `A.rb_left` is NULL.\n\n"
    md += "That intersection is not a usable first-stage fops hijack: `rb_link_node()` stores the incoming waiter `rb_node` address into the NULL field, not `fake_fops` or a CONFIGFS callback. Moreover, `ashmem_fops.owner` is zero; when A is interpreted as an rb_node this is a red node with NULL parent, so insertion below A has no valid gparent state. `rb_set_parent_color()` likewise stores a node/parent address, and no current path proves a callable kernel-text value at a NULL callback slot.\n\n"
    md += "`misc_fops` NULL slots remain an alternate anchor only; no current graph edge reaches their required parent addresses. `ashmem_misc+0x10` remains non-NULL (`ashmem_fops`) and is not a proven child-link destination.\n\n"
    md += "## Verdict\n\n"
    md += "**NO-USABLE-ALTERNATE-FOPS-SLOT**. Stop the static-fops-NULL branch. The next offline task is a broader kernel-object inventory: find a writable field that is both reachable from the actual rb/PI graph and accepts a proven callable or pointer value. Do not change fd-set/payload or run a device test.\n"
    OUT_MD.write_text(md, encoding="utf-8")
    print(json.dumps({"json": str(OUT_JSON), "markdown": str(OUT_MD), "verdict": result["verdict"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
