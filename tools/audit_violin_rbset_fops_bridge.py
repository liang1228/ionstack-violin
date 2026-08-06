#!/usr/bin/env python3
"""Offline audit of the rb_set_parent_color -> fops bridge hypothesis.

This is deliberately source-only.  It does not build, install, connect to a
device, or execute a payload.  The audit records the argument order of
rb_set_parent_color(), the miscdevice alias at ashmem_misc + 0x10, and the
temporary file_operations view obtained when a waiter pi_tree node is used as
an fops pointer.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "kernel-src-wsl" / "common-gki"
EXPLOIT = ROOT / "exploit-repo" / "IonStack" / "CVE-2026-43499" / "exploit"
SRC = EXPLOIT / "src"
TARGET_H = SRC / "targets" / "violin-v-oss" / "target.h"
COMMON_H = SRC / "common.h"
RB_C = KERNEL / "lib" / "rbtree.c"
RB_AUG = KERNEL / "include" / "linux" / "rbtree_augmented.h"
RB_H = KERNEL / "include" / "linux" / "rbtree.h"
MISC_H = KERNEL / "include" / "linux" / "miscdevice.h"
FS_H = KERNEL / "include" / "linux" / "fs.h"
READ_WRITE_C = KERNEL / "fs" / "read_write.c"
UTIL_C = SRC / "util.c"
FOPS_C = SRC / "fops.c"

OUT_DIR = ROOT / "analysis_outputs"
OUT_JSON = OUT_DIR / "violin-rbset-fops-bridge-audit-20260719.json"
OUT_MD = OUT_DIR / "violin-rbset-fops-bridge-audit-20260719.md"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def line_of(path: Path, needle: str) -> int | None:
    for no, line in enumerate(text(path).splitlines(), 1):
        if needle in line:
            return no
    return None


def define(path: Path, name: str, default: int | None = None) -> int | None:
    m = re.search(rf"^\s*#define\s+{re.escape(name)}\s+([^/\s]+)", text(path), re.M)
    if not m:
        return default
    raw = m.group(1).rstrip("ULLull")
    try:
        return int(raw, 0)
    except ValueError:
        return default


def check_struct_miscdevice() -> dict:
    src = text(MISC_H)
    fields = ["int minor;", "const char *name;", "const struct file_operations *fops;",
              "struct list_head list;", "struct device *parent;",
              "struct device *this_device;", "const struct attribute_group **groups;"]
    present = {field: field in src for field in fields}
    # arm64 LP64: int + 4-byte padding, followed by 8-byte pointers/list_head.
    offsets = {
        "minor": 0x00,
        "name": 0x08,
        "fops": 0x10,
        "list": 0x18,
        "parent": 0x28,
        "this_device": 0x30,
        "groups": 0x38,
    }
    return {
        "header": str(MISC_H),
        "fields_present": present,
        "all_expected_fields_present": all(present.values()),
        "lp64_offsets": offsets,
        "target_slot": "ashmem_misc + 0x10",
        "target_as_rb_node": {
            "__rb_parent_color@+0x00": "miscdevice.fops",
            "rb_right@+0x08": "miscdevice.list.next",
            "rb_left@+0x10": "miscdevice.list.prev",
        },
        "warning": "target is an alias into a live miscdevice/list object, not a standalone rb_node",
    }


def check_rb_semantics() -> dict:
    aug = text(RB_AUG)
    rb_c = text(RB_C)
    rb_h = text(RB_H)
    exact = "rb->__rb_parent_color = (unsigned long)p + color;" in aug
    calls = [
        {"line": 100, "call": "rb_set_parent_color(node, NULL, RB_BLACK)", "destination_arg": "node", "value_arg": "NULL"},
        {"line": 131, "call": "rb_set_parent_color(tmp, gparent, RB_BLACK)", "destination_arg": "tmp", "value_arg": "gparent"},
        {"line": 132, "call": "rb_set_parent_color(parent, gparent, RB_BLACK)", "destination_arg": "parent", "value_arg": "gparent"},
        {"line": 135, "call": "rb_set_parent_color(node, parent, RB_RED)", "destination_arg": "node", "value_arg": "parent"},
        {"line": 158, "call": "rb_set_parent_color(tmp, parent, RB_BLACK)", "destination_arg": "tmp", "value_arg": "parent"},
        {"line": 160, "call": "rb_set_parent_color(parent, node, RB_RED)", "destination_arg": "parent", "value_arg": "node"},
        {"line": 179, "call": "rb_set_parent_color(tmp, gparent, RB_BLACK)", "destination_arg": "tmp", "value_arg": "gparent"},
        {"line": 187, "call": "rb_set_parent_color(tmp, gparent, RB_BLACK)", "destination_arg": "tmp", "value_arg": "gparent"},
        {"line": 188, "call": "rb_set_parent_color(parent, gparent, RB_BLACK)", "destination_arg": "parent", "value_arg": "gparent"},
        {"line": 191, "call": "rb_set_parent_color(node, parent, RB_RED)", "destination_arg": "node", "value_arg": "parent"},
        {"line": 202, "call": "rb_set_parent_color(tmp, parent, RB_BLACK)", "destination_arg": "tmp", "value_arg": "parent"},
        {"line": 204, "call": "rb_set_parent_color(parent, node, RB_RED)", "destination_arg": "parent", "value_arg": "node"},
        {"line": 214, "call": "rb_set_parent_color(tmp, gparent, RB_BLACK)", "destination_arg": "tmp", "value_arg": "gparent"},
    ]
    return {
        "definition_found": exact,
        "definition_line": line_of(RB_AUG, "rb->__rb_parent_color ="),
        "rb_parent_masks_low_bits": "rb_parent(r) masks __rb_parent_color with ~3",
        "rb_parent_line": line_of(RB_H, "#define rb_parent(r)"),
        "insert_calls": calls,
        "rotation_helper_line": line_of(RB_C, "rb_set_parent_color(old, new, color)"),
        "conclusion": "first argument is the write destination; second argument supplies the parent pointer value and color",
    }


def check_interim_fops() -> dict:
    w0 = define(TARGET_H, "W0_OFF", 0x2220)
    pi = define(TARGET_H, "FAKE_WAITER_PI_TREE_ENTRY_OFF", 0x28)
    prio = define(COMMON_H, "FAKE_WAITER_PRIO", 130)
    fops = {
        "owner": 0x00,
        "llseek": 0x08,
        "read": 0x10,
        "write": 0x18,
        "read_iter": 0x20,
        "write_iter": 0x28,
    }
    waiter = {
        "pi_tree.__rb_parent_color": 0x00,
        "pi_tree.rb_right": 0x08,
        "pi_tree.rb_left": 0x10,
        "pi_tree.prio": 0x18,
        "pi_tree.deadline": 0x20,
        "task": 0x28,
        "lock": 0x30,
    }
    fields = {
        name: {
            "fops_offset": off,
            "waiter_relative_offset": off,
            "waiter_field": next((k for k, v in waiter.items() if v == off), "unknown"),
        }
        for name, off in fops.items()
    }
    return {
        "fake_w0_offset": w0,
        "pi_tree_node_offset": pi,
        "interim_fops_base": "new_waiter = fake_w0 + 0x28 (pi_tree rb_node)",
        "field_map_relative_to_new_waiter": fields,
        "payload_values": {
            "pi_tree.__rb_parent_color": "write_pc=fake_fops (current PAGE_PAYLOAD_FOPS path)",
            "pi_tree.rb_right": "write_right=0",
            "pi_tree.rb_left": "write_left=(ashmem_misc + 0x10) - 0x08",
            "pi_tree.prio": prio,
            "pi_tree.deadline": 0,
            "task": "waiter_task (init_task in the default FOPS payload)",
        },
        "invalid_fields": [
            "fops.read resolves to rb_left=(ashmem_misc + 0x10)-0x08, a data address, not a function",
            f"fops.write resolves to pi_tree.prio={prio}, a small non-function value",
            "fops.read_iter resolves to pi_tree.deadline=0, so iter-read dispatch returns -EINVAL",
            "fops.write_iter resolves to waiter_task/init_task, so iter-write dispatch would indirect-call a task address",
        ],
        "verdict": "RBSET-INTERIM-FOPS-INVALID",
    }


def check_dispatch_chain() -> dict:
    return {
        "configfs_write_once_pwrite_line": line_of(UTIL_C, "ssize_t wr = pwrite(fd, data, len, 0);"),
        "configfs_read_once_pread_line": line_of(UTIL_C, "ssize_t rd = pread(fd, data, len, pos);"),
        "pwrite_to_vfs_write": {
            "ksys_pwrite64_line": line_of(READ_WRITE_C, "ret = vfs_write(f.file, buf, count, &pos);"),
            "vfs_write_write_precedence_line": line_of(READ_WRITE_C, "if (file->f_op->write)"),
            "vfs_write_iter_fallback_line": line_of(READ_WRITE_C, "else if (file->f_op->write_iter)"),
        },
        "pread_to_vfs_read": {
            "ksys_pread64_line": line_of(READ_WRITE_C, "ret = vfs_read(f.file, buf, count, &pos);"),
            "vfs_read_read_precedence_line": line_of(READ_WRITE_C, "if (file->f_op->read)"),
            "vfs_read_iter_fallback_line": line_of(READ_WRITE_C, "else if (file->f_op->read_iter)"),
        },
        "llseek_required": False,
        "conclusion": "pread/pwrite dispatch through read/write first; a NULL llseek does not make the interim fops safe",
    }


def main() -> int:
    result = {
        "audit": "violin rb_set_parent_color fops bridge",
        "date": "2026-07-19",
        "mode": "offline-source-only",
        "sources": {
            "rbtree_augmented_h": str(RB_AUG),
            "rbtree_c": str(RB_C),
            "rbtree_h": str(RB_H),
            "miscdevice_h": str(MISC_H),
            "fs_h": str(FS_H),
            "read_write_c": str(READ_WRITE_C),
            "util_c": str(UTIL_C),
            "fops_c": str(FOPS_C),
        },
        "miscdevice": check_struct_miscdevice(),
        "rb_set_parent_color": check_rb_semantics(),
        "interim_fops": check_interim_fops(),
        "dispatch": check_dispatch_chain(),
        "final_verdict": {
            "claim_fake_parent_as_destination": "false",
            "claim_first_write_equals_new_waiter": "not established; value depends on the second argument at the specific call site",
            "bridge_status": "not closed",
            "minimum_next_gate": "prove a concrete __rb_insert state where first argument == ashmem_misc+0x10 and prove list.next/list.prev reads and writes remain safe",
            "runtime_allowed": False,
        },
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md = f"# Violin rb_set_parent_color → fops bridge audit (2026-07-19)\n\n"
    md += "**Mode:** offline source-only. No payload build, install, device connection, or runtime execution.\n\n"
    md += "## Verdict\n\n"
    md += "The proposed bridge is **not closed**. `rb_set_parent_color(rb, p, color)` writes to `rb` (the first argument) and stores `p | color`; assigning `fake_parent = ashmem_misc + 0x10` only changes a value and does not select the destination.\n\n"
    md += "Even if the fops slot temporarily became `new_waiter = fake_w0 + 0x28`, that address is a `rt_mutex_waiter.pi_tree` rb_node, not a file_operations object. With the current payload layout, `.read` aliases `rb_left`, `.write` aliases `pi_tree.prio`, `.read_iter` aliases `pi_tree.deadline`, and `.write_iter` aliases `waiter_task`.\n\n"
    md += "## Evidence\n\n"
    md += f"- `rbtree_augmented.h:{result['rb_set_parent_color']['definition_line']}` assigns `rb->__rb_parent_color = (unsigned long)p + color`; `rbtree.h:{result['rb_set_parent_color']['rb_parent_line']}` masks only the low color bits when reading the parent.\n"
    md += f"- `miscdevice.h` places `fops` at `+0x10` on arm64 LP64; treating that slot as an rb_node aliases `+0x08` to `list.next` and `+0x10` to `list.prev`. This is a live list object, not standalone rb storage.\n"
    md += f"- `util.c:{result['dispatch']['configfs_write_once_pwrite_line']}` uses `pwrite`; `read_write.c:{result['dispatch']['pwrite_to_vfs_write']['vfs_write_write_precedence_line']}` checks `.write` before `.write_iter`. `pread` similarly checks `.read` first. `llseek` is not consulted by these calls.\n"
    md += "- Current waiter offsets: pi_tree rb node `+0x00/+0x08/+0x10`, priority `+0x18`, deadline `+0x20`, task `+0x28`; file_operations offsets: owner `+0x00`, llseek `+0x08`, read `+0x10`, write `+0x18`, read_iter `+0x20`, write_iter `+0x28`.\n\n"
    md += "## Required next offline gate\n\n"
    md += "Construct one concrete `__rb_insert` state table (node/parent/gparent/tmp addresses, colors, and child values) and prove all of the following simultaneously:\n\n"
    md += "1. The first argument of a reachable `rb_set_parent_color()` call is exactly `ashmem_misc + 0x10`;\n"
    md += "2. The value argument yields the desired fops pointer without a color-bit corruption;\n"
    md += "3. Any `rb_left/rb_right` accesses at the target alias the real `miscdevice.list` safely; and\n"
    md += "4. The resulting file_operations pointer is directly usable by `pwrite/pread` (or is immediately repaired by a separate proven write).\n\n"
    md += "Until that table exists, do not change fd-set words or run a new payload.\n"
    OUT_MD.write_text(md, encoding="utf-8")
    print(json.dumps({"json": str(OUT_JSON), "markdown": str(OUT_MD), "verdict": result["interim_fops"]["verdict"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
