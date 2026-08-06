#!/usr/bin/env python3
"""Offline inventory of the same-build miscdevice/rbtree object graph.

This is deliberately a static audit.  It parses the shipped kernel image and
the matching kallsyms snapshot, then models the field offsets used by the
existing rb route.  It does not build, install, connect to, or execute a
payload.
"""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IMAGE = ROOT / "analysis_outputs" / "ota_full" / "boot_parse" / "boot.img.kernel"
KALLSYMS = ROOT / "kallsyms.txt"
OUT_DIR = ROOT / "analysis_outputs"
OUT_JSON = OUT_DIR / "violin-miscdevice-graph-audit-20260719.json"
OUT_MD = OUT_DIR / "violin-miscdevice-graph-audit-20260719.md"

# The raw boot image uses the link-time arm64 image base for embedded pointers.
# The symbol offsets are derived from the runtime _text and are what matter for
# the target; normalising both forms avoids comparing C080... raw pointers with
# the C008... compile-time macro directly.
RUNTIME_TEXT = 0xFFFFFFD365E00000
RAW_LINK_BASE = 0xFFFFFFC080000000
RAW_TYPES = set("bBcCdDgGrRsS")
IMAGE_TEXT_LIMIT = 0x4000000

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
    0xA0: "check_flags",
    0xA8: "flock",
    0xB0: "splice_write",
    0xB8: "splice_read",
    0xC0: "splice_eof",
    0xC8: "setlease",
    0xD0: "fallocate",
    0xD8: "show_fdinfo",
}


def qword(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def normalise_raw_ptr(value: int, image_size: int) -> int | None:
    if RAW_LINK_BASE <= value < RAW_LINK_BASE + image_size:
        return value - RAW_LINK_BASE
    return None


def display(value: int, image_size: int) -> str:
    off = normalise_raw_ptr(value, image_size)
    if off is not None:
        return f"image+0x{off:x}"
    return "NULL" if value == 0 else f"0x{value:016x}"


def parse_symbols(image_size: int) -> tuple[dict[int, list[str]], list[dict]]:
    by_off: dict[int, list[str]] = {}
    data = []
    for line in KALLSYMS.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        try:
            addr = int(fields[0], 16)
        except ValueError:
            continue
        typ, name = fields[1], fields[2]
        if not (RUNTIME_TEXT <= addr < RUNTIME_TEXT + image_size):
            continue
        off = addr - RUNTIME_TEXT
        by_off.setdefault(off, []).append(name)
        if typ in RAW_TYPES:
            data.append({"offset": off, "type": typ, "name": name})
    return by_off, data


def likely_miscdevice(row: dict, image: bytes) -> bool:
    # struct miscdevice starts with a 32-bit minor and has fops at +0x10.  The
    # suffix match excludes misc_fops/misc_list/misc_mtx and helper symbols.
    name = row["name"]
    if not re.search(r"(?:^|_)(?:miscdev|miscdevice|misc)$", name, re.I):
        return False
    off = row["offset"]
    if off + 0x20 > len(image):
        return False
    minor = struct.unpack_from("<I", image, off)[0]
    fops = qword(image, off + 0x10)
    fops_off = normalise_raw_ptr(fops, len(image))
    return minor <= 0xFF and fops_off is not None and fops_off + 0xD8 + 8 <= len(image)


def fops_snapshot(image: bytes, fops_off: int, symbol_names: dict[int, list[str]]) -> dict:
    fields = []
    for rel, field in FOPS_FIELDS.items():
        value = qword(image, fops_off + rel)
        fields.append({
            "field": field,
            "offset": hex(rel),
            "value": hex(value),
            "display": display(value, len(image)),
            "null": value == 0,
        })
    owner = qword(image, fops_off)
    null_children = [x["field"] for x in fields if x["field"] in {"llseek", "read"} and x["null"]]
    return {
        "offset": hex(fops_off),
        "symbols": symbol_names.get(fops_off, []),
        "owner": hex(owner),
        "owner_display": display(owner, len(image)),
        # Linux rbtree uses RB_RED == 0 and RB_BLACK == 1.  A built-in fops
        # owner of NULL is therefore a red parent, not a safe black anchor.
        "owner_rb_color": "RED" if (owner & 1) == 0 else "BLACK",
        "null_fops_tree_children": null_children,
        "fields": fields,
    }


def main() -> int:
    image = IMAGE.read_bytes()
    symbol_names, data_symbols = parse_symbols(len(image))
    candidates = [row for row in data_symbols if likely_miscdevice(row, image)]
    # Multiple aliases can point at one object.  Keep each name because it is
    # useful evidence, but report a stable offset/object view as well.
    objects = []
    for row in sorted(candidates, key=lambda item: (item["offset"], item["name"])):
        off = row["offset"]
        minor = struct.unpack_from("<I", image, off)[0]
        name_ptr = qword(image, off + 0x08)
        fops_ptr = qword(image, off + 0x10)
        list_next = qword(image, off + 0x18)
        list_prev = qword(image, off + 0x20)
        parent = qword(image, off + 0x28)
        fops_off = normalise_raw_ptr(fops_ptr, len(image))
        fops = fops_snapshot(image, fops_off, symbol_names) if fops_off is not None else None
        objects.append({
            "name": row["name"],
            "type": row["type"],
            "offset": hex(off),
            "minor": minor,
            "name_ptr": hex(name_ptr),
            "fops_ptr": hex(fops_ptr),
            "fops_display": display(fops_ptr, len(image)),
            "list_next": hex(list_next),
            "list_next_display": display(list_next, len(image)),
            "list_prev": hex(list_prev),
            "list_prev_display": display(list_prev, len(image)),
            "parent": hex(parent),
            "parent_display": display(parent, len(image)),
            "raw_list_fields_zero": list_next == 0 and list_prev == 0,
            "fops": fops,
            "name_node_model": {
                "node_base": "misc+0x08",
                "rb_right": "misc+0x10 (fops pointer)",
                "rb_left": "misc+0x18 (list.next)",
                "reachable_null_child": bool(fops and fops["null_fops_tree_children"]),
                "write_value": "incoming waiter rb_node address",
            },
            "list_node_model": {
                "node_base": "misc+0x18",
                "rb_right": "misc+0x20 (list.prev)",
                "rb_left": "misc+0x28 (parent pointer)",
                "static_image_closed": False,
                "reason": "misc_register() INIT_LIST_HEAD/list_add() rewrites these fields at runtime; raw image is pre-registration",
            },
        })

    fops_with_null_child = [
        {
            "miscdevice": o["name"],
            "misc_offset": o["offset"],
            "fops_offset": o["fops"]["offset"],
            "null_children": o["fops"]["null_fops_tree_children"],
            "owner": o["fops"]["owner_display"],
            "owner_rb_color": o["fops"]["owner_rb_color"],
            "status": "blocked: owner=0 is RB_RED and rb_insert_color would read gparent=NULL"
            if o["fops"]["owner"] == "0x0"
            else "not closed: owner/gparent is not a proven rb node",
        }
        for o in objects
        if o["fops"] and o["fops"]["null_fops_tree_children"]
    ]

    result = {
        "audit": "violin miscdevice object/rbtree graph",
        "date": "2026-07-19",
        "mode": "offline same-build raw image + kallsyms + misc.c source equations",
        "image": str(IMAGE),
        "kallsyms": str(KALLSYMS),
        "runtime_text": hex(RUNTIME_TEXT),
        "raw_link_base": hex(RAW_LINK_BASE),
        "miscdevice_layout": {
            "name": "+0x08",
            "fops": "+0x10",
            "list_next": "+0x18",
            "list_prev": "+0x20",
            "parent": "+0x28",
        },
        "object_count": len(objects),
        "objects": objects,
        "fops_null_child_candidates": fops_with_null_child,
        "runtime_list_closure": False,
        "verdict": {
            "static_miscdevice_fops_sink": False,
            "reason": "All in-image static miscdevice fops owners are NULL/RB_RED; the null llseek/read fields are not a safe rb_insert parent. The list-node fields are runtime-mutated by misc_register and are not closed by the raw image.",
            "best_candidate": "userfaultfd_misc -> userfaultfd_fops.read=NULL, but owner=0/RB_RED; no closed insertion path",
            "target_fops_slot": "ashmem_misc+0x10 remains a non-NULL fops pointer and no list-node model makes it a proven rb child destination",
            "independent_write_primitive": False,
            "next_gate": "stop miscdevice/fops branch; perform one bounded cross-object inventory only if a concrete consumer/value equation is available, otherwise report the rb primitive as not closed on violin",
            "runtime_allowed": False,
        },
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md = [
        "# Violin miscdevice object/rbtree graph audit (2026-07-19)",
        "",
        "**Mode:** offline same-build raw image + kallsyms + `misc_register()` source equations; no payload build, install, device connection, or runtime execution.",
        "",
        f"The image contains **{len(objects)}** in-image static `struct miscdevice` candidates with an in-image `fops` pointer. The raw image is pre-registration: `misc_list` is self-linked while each candidate's `list.next/list.prev` is zero. `misc_register()` later executes `INIT_LIST_HEAD()` and `list_add()`, so the runtime list topology is not recoverable from this raw image alone.",
        "",
        "## Name-node model",
        "",
        "For a candidate `M`, interpreting `M+0x08` (`name`) as an rb_node yields `rb_right=M+0x10` (the fops pointer) and `rb_left=M+0x18` (the list link). Several fops objects therefore expose NULL `llseek`/`read` child fields, but `rb_link_node()` would write the incoming waiter rb_node address there, not a callable fops value.",
        "",
        "All in-image static miscdevice fops owners are `NULL`. Linux rbtree encodes `RB_RED == 0`, so a NULL owner makes the fops object a red parent; `rb_insert_color()` then needs `rb_parent(fops)` as a gparent and reaches NULL. This is a deterministic closure failure, not a viable insertion anchor.",
        "",
        "## List-node model",
        "",
        "Interpreting `M+0x18` as an rb_node would use `list.prev` as `rb_right` and `M+0x28` (`parent`) as `rb_left`. Those values are written by `misc_register()`/`list_add()` at runtime and are zero in the shipped image, so no static parent/child/value/consumer equation is closed. Treating this as a ready-made tree would require a runtime payload change, which is outside the current gate.",
        "",
        "## Verdict",
        "",
        "**NO-CLOSED-MISCDEVICE-SINK**. The best-looking candidate is `userfaultfd_misc -> userfaultfd_fops.read=NULL`, but its owner is NULL/RB_RED and the insertion-color path is not valid. `ashmem_misc+0x10` remains a non-NULL fops pointer and is still not proven to be an rb child destination. Stop this branch; only continue with a different kernel object if a concrete consumer, destination, and write-value equation can be proven offline.",
    ]
    OUT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps({"json": str(OUT_JSON), "markdown": str(OUT_MD), "object_count": len(objects), "null_child_candidates": len(fops_with_null_child), "verdict": result["verdict"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
