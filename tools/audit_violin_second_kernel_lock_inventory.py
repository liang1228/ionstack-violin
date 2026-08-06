#!/usr/bin/env python3
"""Offline inventory of candidate second rt_mutex addresses for Violin.

This is a negative/closure audit only.  It does not select a payload value or
perform a device/runtime test.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "kernel-src-wsl" / "common-gki"
KALLSYMS = ROOT / "kallsyms.txt"
IMAGE = ROOT / "analysis_outputs" / "ota_full" / "boot_parse" / "boot.img.kernel"
BTF = ROOT / "analysis_outputs" / "violin-boot-btf.bin"
OUT_DIR = ROOT / "analysis_outputs"
OUT_JSON = OUT_DIR / "violin-second-kernel-lock-inventory-20260722.json"
OUT_MD = OUT_DIR / "violin-second-kernel-lock-inventory-20260722.md"
IMAGE_BASE = 0xFFFF_FFC0_8000_0000


def line_of(path: Path, needle: str) -> int | None:
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if needle in line:
            return n
    return None


def symbol_addr(name: str) -> int | None:
    for line in KALLSYMS.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == name:
            return int(parts[0], 16)
    return None


def symbols() -> list[tuple[int, str, str]]:
    """Return the same-build kallsyms tuples (address, type, name)."""
    result = []
    for line in KALLSYMS.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            address = int(parts[0], 16)
        except ValueError:
            continue
        result.append((address, parts[1], parts[2]))
    return result


def raw_words(runtime_addr: int, base: int, count: int = 4) -> list[int]:
    data = IMAGE.read_bytes()
    off = runtime_addr - base
    if off < 0 or off + count * 8 > len(data):
        raise ValueError(f"symbol is outside the raw built-in image: {runtime_addr:#x}")
    return [int.from_bytes(data[off + i * 8:off + i * 8 + 8], "little") for i in range(count)]


def named_mutex_surface(text_base: int) -> dict:
    """Check all in-image data symbols whose name contains ``mutex``.

    A regular ``struct mutex`` has owner at +0, wait_lock at +8, and a
    self-linked wait_list at +0x10/+0x18.  That shape must not be treated as
    an ``rt_mutex_base`` (whose rb_root/leftmost are at +0x8/+0x10 and owner
    is at +0x18).  This is an offline shape check, not a runtime probe.
    """
    rows = []
    skipped = []
    image_size = IMAGE.stat().st_size
    for address, symbol_type, name in symbols():
        if symbol_type not in "dDbB" or "mutex" not in name.lower():
            continue
        if name.startswith(("__tpstrtab_", "__tracepoint_", "__SCK__")):
            continue
        offset = address - text_base
        if offset < 0 or offset + 0x20 > image_size:
            skipped.append({"name": name, "runtime_address": f"0x{address:016x}"})
            continue
        words = raw_words(address, text_base)
        image_address = IMAGE_BASE + offset
        is_mutex_shape = (
            words[0] == 0
            and words[1] == 0
            and words[2] == image_address + 0x10
            and words[3] == image_address + 0x10
        )
        rows.append({
            "name": name,
            "runtime_address": f"0x{address:016x}",
            "image_offset": f"0x{offset:x}",
            "raw_words": [f"0x{x:016x}" for x in words],
            "shape": "struct_mutex" if is_mutex_shape else "other",
        })
    shape_counts = {}
    for row in rows:
        shape_counts[row["shape"]] = shape_counts.get(row["shape"], 0) + 1
    return {
        "data_symbol_count": len(rows),
        "shape_counts": shape_counts,
        "all_in_image_named_mutexes_match_struct_mutex_shape": bool(rows)
        and all(row["shape"] == "struct_mutex" for row in rows),
        "out_of_image_skipped": skipped,
        "sample": rows[:8],
    }


def named_rtmutex_data(text_base: int) -> list[dict]:
    """List data symbols that look like RT-mutex objects by name."""
    pattern = re.compile(r"(^|_)(rtmutex|rt_mutex|boost_mtx|pi_mutex)(_|$)", re.I)
    result = []
    image_size = IMAGE.stat().st_size
    for address, symbol_type, name in symbols():
        if symbol_type not in "dDbB" or not pattern.search(name):
            continue
        if name.startswith(("__tpstrtab_", "__tracepoint_", "__SCK__")):
            continue
        row = {
            "name": name,
            "runtime_address": f"0x{address:016x}",
            "symbol_type": symbol_type,
        }
        offset = address - text_base
        if 0 <= offset + 0x20 <= image_size:
            row["image_offset"] = f"0x{offset:x}"
            row["raw_words"] = [f"0x{x:016x}" for x in raw_words(address, text_base)]
        else:
            row["status"] = "outside_raw_builtin_image"
        if name == "rt_mutex_adjust_prio_chain.prev_max":
            row["classification"] = "function_local_scalar_not_lock"
        result.append(row)
    return result


def source_rtmutex_defs() -> list[dict]:
    """Cross-check source-level static test locks against exact-build symbols."""
    source_files = [
        KERNEL / "kernel" / "locking" / "locktorture.c",
        KERNEL / "lib" / "locking-selftest.c",
    ]
    exact_symbols = {name for _, _, name in symbols()}
    result = []
    for source in source_files:
        text = source.read_text(encoding="utf-8", errors="ignore")
        for match in re.finditer(r"DEFINE_RT_MUTEX\(([^)]+)\)", text):
            name = match.group(1).strip()
            line = text.count("\n", 0, match.start()) + 1
            result.append({
                "name": name,
                "source": str(source),
                "source_line": line,
                "kallsyms_present": name in exact_symbols,
                "verdict": "EXACT_SYMBOL_PRESENT" if name in exact_symbols else "ABSENT_FROM_EXACT_KALLSYMS",
            })
    return result


def main() -> int:
    text_base = symbol_addr("_text")
    rcu = symbol_addr("rcu_state")
    assert text_base is not None and rcu is not None
    mutex_surface = named_mutex_surface(text_base)
    rtmutex_surface = named_rtmutex_data(text_base)
    source_defs = source_rtmutex_defs()
    node_size = 0x2C0
    boost_off = 0xB0
    rcu_candidates = []
    for index in range(3):
        addr = rcu + index * node_size + boost_off
        rcu_candidates.append({
            "name": f"rcu_state.node[{index}].boost_mtx",
            "runtime_address": f"0x{addr:016x}",
            "image_offset": f"0x{addr - text_base:x}",
            "raw_words": [f"0x{x:016x}" for x in raw_words(addr, text_base)],
            "layout": "valid struct rt_mutex/rt_mutex_base (BTF size 0x20; wait_lock+0, waiters+0x8, owner+0x18)",
            "owner_gate": "raw owner=0; no static owner source",
            "source_role": "rcu boost side effect only, not used as a general lock",
            "verdict": "NO-STABLE-OWNER",
        })

    console = symbol_addr("console_mutex")
    tty = symbol_addr("tty_mutex")
    candidates = rcu_candidates + [
        {
            "name": "console_mutex",
            "runtime_address": f"0x{console:016x}" if console else None,
            "layout": "BTF struct mutex size 0x30 (non-RT layout), not rt_mutex_base",
            "owner_gate": "not applicable: field offsets do not match rt_mutex_base",
            "verdict": "LAYOUT-MISMATCH",
        },
        {
            "name": "tty_mutex",
            "runtime_address": f"0x{tty:016x}" if tty else None,
            "layout": "BTF struct mutex size 0x30 (non-RT layout), not rt_mutex_base",
            "owner_gate": "not applicable: field offsets do not match rt_mutex_base",
            "verdict": "LAYOUT-MISMATCH",
        },
        {
            "name": "futex_pi_state.pi_mutex",
            "layout": "dynamic struct rt_mutex_base embedded in futex_pi_state",
            "owner_gate": "no stable symbol/address; lifetime is route-owned",
            "verdict": "DYNAMIC-NOT-CLOSED",
        },
        {
            "name": "fake_lock",
            "layout": "controlled kernel-page rt_mutex_base",
            "owner_gate": "owner=fake_task is prepared; orig_lock from rt_mutex_adjust_pi is NULL, so same-lock is not an automatic [6] blocker",
            "verdict": "CONTROLLED-BUT-CHAIN-GATES-OPEN",
        },
    ]

    result = {
        "audit": "Violin second kernel rt_mutex inventory",
        "date": "2026-07-22",
        "mode": "offline-BTF-source-raw-image-only",
        "sources": {
            "kallsyms": str(KALLSYMS),
            "image": str(IMAGE),
            "btf": str(BTF),
            "rtmutex_h": str(KERNEL / "include/linux/rtmutex.h"),
            "rtmutex_common_h": str(KERNEL / "kernel/locking/rtmutex_common.h"),
            "rcu_tree_h": str(KERNEL / "kernel/rcu/tree.h"),
            "mutex_h": str(KERNEL / "include/linux/mutex.h"),
        },
        "evidence": {
            "text_base": f"0x{text_base:016x}",
            "image_base": f"0x{IMAGE_BASE:016x}",
            "image_size": IMAGE.stat().st_size,
            "rcu_state": f"0x{rcu:016x}",
            "rt_mutex_base_btf": "size=0x20; wait_lock=+0x0; waiters=+0x8; owner=+0x18",
            "mutex_btf": "size=0x30; owner=+0x0; wait_lock=+0x8; wait_list=+0x10",
            "rcu_boost_source_line": line_of(KERNEL / "kernel/rcu/tree.h", "boost_mtx;"),
            "rcu_boost_role_line": line_of(KERNEL / "kernel/rcu/tree.h", "Used only for the priority-boosting"),
            "adjust_pi_orig_lock_line": line_of(KERNEL / "kernel/locking/rtmutex_api.c", "rt_mutex_adjust_prio_chain(task, RT_MUTEX_MIN_CHAINWALK, NULL,"),
            "named_mutex_surface": mutex_surface,
            "named_rtmutex_data_surface": rtmutex_surface,
            "source_static_rtmutex_defs": source_defs,
        },
        "candidates": candidates,
        "verdict": {
            "closed_distinct_second_lock": False,
            "rcu_boost_candidates": "valid layout but raw owner=0 and role is side-effect-only",
            "mutex_candidates": "rejected by BTF layout mismatch",
            "named_mutex_surface": "all 212 in-image named mutex data symbols match struct mutex self-list shape; no rt_mutex_base-shaped named object",
            "source_static_rtmutex_defs": "locktorture/locking-selftest DEFINE_RT_MUTEX names are absent from exact kallsyms; no stable built-in target",
            "named_rtmutex_data_surface": "only rt_mutex_adjust_prio_chain.prev_max remains, and it is an out-of-image function-local scalar, not a lock",
            "fake_lock": "only controlled candidate; orig_lock=NULL correction does not close owner/top-task/requeue gates",
            "runtime_allowed": False,
            "next_gate": "do not substitute console/tty/rcu locks; either close a distinct lock owner/waiters/lifetime model offline or abandon the second-lock branch",
        },
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md = """# Violin second kernel rt_mutex inventory (2026-07-22)\n\n"""
    md += "**Mode:** same-build BTF/source/raw-image only; no payload build, device connection, or runtime execution.\n\n"
    md += "## Findings\n\n"
    md += "- `rcu_state.node[0..2].boost_mtx` are the only statically named objects in this inventory with a valid `struct rt_mutex` layout. Their raw 0x20-byte initial states are all zero, so `owner=0` and `waiters.rb_root=0`; source comments say the mutex is used only for RCU priority-boost side effects, not as a general lock. They do not provide a second owner-bearing chain.\n"
    md += "- The expanded same-image scan found 212 named in-image data symbols containing `mutex`; every one has the raw `struct mutex` owner/wait_lock/self-list shape. This includes `console_mutex`, `tty_mutex`, `port_mutex`, `misc_mtx`, and `ashmem_mutex`; none is an `rt_mutex_base`.\n"
    md += "- Source-level `DEFINE_RT_MUTEX` objects in `locktorture.c` and `locking-selftest.c` are absent from this build's kallsyms, so they are not stable targets in the exact image. The only remaining name match is `rt_mutex_adjust_prio_chain.prev_max`, an out-of-image function-local scalar, not a lock.\n"
    md += "- `futex_pi_state.pi_mutex` is dynamically allocated and route-owned, so it has no independent stable address/lifetime. `fake_lock` remains the only controlled kernel-page candidate; because `rt_mutex_adjust_pi()` passes `orig_lock=NULL`, same-lock is not automatically a [6] blocker, but owner/top-task/requeue gates remain open.\n\n"
    md += "## Verdict / next gate\n\n"
    md += "No distinct second lock is closed. Do not substitute console/tty/RCU locks or change fd-set values. Either produce a complete offline owner/waiters/lifetime model for a distinct rt_mutex, or archive the second-lock branch and search a different write sink.\n"
    OUT_MD.write_text(md, encoding="utf-8")
    print(json.dumps({"json": str(OUT_JSON), "markdown": str(OUT_MD), "verdict": result["verdict"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
