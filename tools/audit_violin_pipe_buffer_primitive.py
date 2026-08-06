#!/usr/bin/env python3
"""Offline audit of the violin pipe_buffer/anon_pipe_buf_ops path.

This script only reads source, target metadata, kernel config and existing
analysis notes.  It deliberately does not build, load, execute or connect to
the exploit/payload.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EXPLOIT = ROOT / "exploit-repo" / "IonStack" / "CVE-2026-43499" / "exploit"
SRC = EXPLOIT / "src"
TARGET = SRC / "targets" / "violin-v-oss" / "target.h"
COMMON = SRC / "common.h"
PIPE = SRC / "pipe.c"
UTIL = SRC / "util.c"
KERNEL_PIPE_H = ROOT / "kernel-src-wsl" / "common-gki" / "include" / "linux" / "pipe_fs_i.h"
KERNEL_PIPE_C = ROOT / "kernel-src-wsl" / "common-gki" / "fs" / "pipe.c"
KERNEL_SLAB_H = ROOT / "kernel-src-wsl" / "common-gki" / "include" / "linux" / "slab.h"
CONFIG = ROOT / "analysis_outputs" / "e24" / "target-config.txt"
KALLSYMS_AUDIT = ROOT / "analysis_outputs" / "kallsyms_violin_audit.md"
OFFSET_REPORT = ROOT / "analysis_outputs" / "violin-offset-validation-report-20260714.md"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def line_of(text: str, needle: str) -> int | None:
    for number, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return number
    return None


def defines(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"\s*#define\s+(\w+)\s+(.+?)\s*$", line)
        if match:
            result[match.group(1)] = match.group(2).split("/*", 1)[0].strip()
    return result


def integer(value: str) -> int | None:
    value = value.strip().replace("ULL", "").replace("UL", "").replace("U", "")
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
        return int(value, 16)
    if value.isdigit():
        return int(value, 10)
    return None


def config_state(text: str, name: str) -> bool | None:
    if re.search(rf"^\s*{re.escape(name)}=y\s*$", text, re.M):
        return True
    if re.search(rf"^\s*# {re.escape(name)} is not set\s*$", text, re.M):
        return False
    return None


def evidence(path: Path, text: str, needle: str) -> dict[str, Any]:
    return {"file": str(path.relative_to(ROOT)), "line": line_of(text, needle), "text": needle}


def main() -> None:
    target_text = read(TARGET)
    common_text = read(COMMON)
    pipe_text = read(PIPE)
    util_text = read(UTIL)
    pipe_h_text = read(KERNEL_PIPE_H)
    kernel_pipe_text = read(KERNEL_PIPE_C)
    slab_text = read(KERNEL_SLAB_H)
    config_text = read(CONFIG)
    kallsyms_text = read(KALLSYMS_AUDIT)
    offset_text = read(OFFSET_REPORT)
    target = defines(target_text)
    common = defines(common_text)

    page_shift = integer(common.get("PAGE_SHIFT", "12")) or 12
    page_size = integer(common.get("PAGE_SIZE", "0x1000")) or (1 << page_shift)
    pipe_buffer_size = integer(target.get("PIPE_BUFFER_SIZE", "0x28")) or 0x28
    pipe_slots = integer(target.get("PIPE_BUFFER_SLOTS", "32")) or 32
    object_size = integer(common.get("PIPE_OBJECT_SIZE", "0x800")) or 0x800
    objs_per_slab = integer(common.get("PIPE_OBJS_PER_SLAB", "16")) or 16
    slab_size = object_size * objs_per_slab
    ring_bytes = pipe_buffer_size * pipe_slots
    anon_ops_off = integer(target.get("ANON_PIPE_BUF_OPS_OFF", "0")) or 0
    cache_types = integer(common.get("KMALLOC_CACHE_TYPES", "0")) or 0
    # KMALLOC_BUCKETS is expressed as (KMALLOC_SHIFT_HIGH + 1), and this
    # target is an arm64 4K build: KMALLOC_SHIFT_HIGH = PAGE_SHIFT + 1.
    cache_buckets = (page_shift + 1) + 1
    cgroup_type = integer(common.get("KMALLOC_CGROUP_TYPE", "0")) or 0
    pipe_index = integer(common.get("KMALLOC_PIPE_INDEX", "0")) or 0
    direct_map_base = integer(target.get("DIRECT_MAP_BASE", "0")) or 0
    direct_map_end = integer(target.get("DIRECT_MAP_END", "0")) or 0
    vmemmap_start = integer(target.get("VMEMMAP_START", "0")) or 0
    direct_map_pages = (direct_map_end - direct_map_base) // page_size if direct_map_end > direct_map_base else 0
    vmemmap_end = vmemmap_start + direct_map_pages * (integer(target.get("STRUCT_PAGE_SIZE", "0x40")) or 0x40)

    config = {
        name: config_state(config_text, name)
        for name in (
            "CONFIG_ARM64_4K_PAGES",
            "CONFIG_ZONE_DMA",
            "CONFIG_ZONE_DMA32",
            "CONFIG_MEMCG_KMEM",
            "CONFIG_SLUB",
            "CONFIG_SLUB_TINY",
            "CONFIG_RANDOM_KMALLOC_CACHES",
        )
    }

    # The target's cache-type constant is compared with the source enum under
    # this build configuration.  With no DMA/random caches and MEMCG_KMEM on,
    # the enum is NORMAL=0, RECLAIM=1, CGROUP=2 (three rows, not four).
    expected_cache_types = 3 if config["CONFIG_MEMCG_KMEM"] and not config["CONFIG_ZONE_DMA"] else None
    expected_cgroup_type = 2 if expected_cache_types == 3 else None

    pipe_fields = {
        "page": 0x00,
        "offset": 0x08,
        "len": 0x0C,
        "ops": 0x10,
        "flags": 0x18,
        "private": 0x20,
        "sizeof": 0x28,
    }
    target_user_fields = {
        "page": 0x00,
        "offset": 0x08,
        "len": 0x0C,
        "ops": 0x10,
        "flags": 0x18,
        "pad": 0x1C,
        "private": 0x20,
        "sizeof": 0x28,
    }

    write_lengths = [0, 8, 24, page_size - 1, page_size]
    write_state = []
    for length in write_lengths:
        # The code enters pipe_write with a non-empty pipe after marker writes.
        # It sets the forged last buffer's len to zero and then relies on the
        # small-write merge branch to copy into the forged page.
        chars = length & (page_size - 1)
        merge_candidate = chars != 0 and (0 + chars <= page_size)
        write_state.append(
            {
                "len": length,
                "same_page_guard_at_offset_0": length <= page_size,
                "chars": chars,
                "merge_candidate_nonempty_pipe_offset_0": merge_candidate,
                "targets_forged_buffer": merge_candidate,
                "new_pipe_buffer_allocated": not merge_candidate and length > 0,
            }
        )

    ops_members = re.search(
        r"static const struct pipe_buf_operations anon_pipe_buf_ops\s*=\s*\{(.*?)\n\};",
        kernel_pipe_text,
        re.S,
    )
    ops_body = ops_members.group(1) if ops_members else ""
    ops = [name for name in ("release", "try_steal", "get", "confirm") if re.search(rf"\.\s*{name}\s*=", ops_body)]

    sources = {
        "target_header": str(TARGET.relative_to(ROOT)),
        "common_header": str(COMMON.relative_to(ROOT)),
        "pipe_source": str(PIPE.relative_to(ROOT)),
        "util_source": str(UTIL.relative_to(ROOT)),
        "kernel_pipe_header": str(KERNEL_PIPE_H.relative_to(ROOT)),
        "kernel_pipe_source": str(KERNEL_PIPE_C.relative_to(ROOT)),
        "kernel_slab_header": str(KERNEL_SLAB_H.relative_to(ROOT)),
        "target_config": str(CONFIG.relative_to(ROOT)),
        "kallsyms_audit": str(KALLSYMS_AUDIT.relative_to(ROOT)),
        "offset_report": str(OFFSET_REPORT.relative_to(ROOT)),
    }

    findings = [
        {
            "id": "PBUF-WRITE-PAGE-BOUNDARY",
            "severity": "high",
            "status": "confirmed-offline",
            "title": "pipe_phys_write_data accepts PAGE_SIZE but pipe_write skips the forged-buffer merge",
            "impact": "A write of exactly PAGE_SIZE passes the wrapper guard, but chars=(len & (PAGE_SIZE-1)) is zero; pipe_write allocates a fresh buffer instead of copying to the forged direct-map page.",
            "recommendation": "Treat the arbitrary write contract as 0 < len < PAGE_SIZE, or implement a separately proven multi-buffer/page-sized path.",
            "evidence": [
                evidence(PIPE, pipe_text, "(direct_addr & (PAGE_SIZE - 1)) + len > PAGE_SIZE"),
                evidence(KERNEL_PIPE_C, kernel_pipe_text, "chars = total_len & (PAGE_SIZE-1)"),
                evidence(KERNEL_PIPE_C, kernel_pipe_text, "buf->ops = &anon_pipe_buf_ops"),
            ],
        },
        {
            "id": "PBUF-NOT-INDEPENDENT",
            "severity": "high",
            "status": "confirmed-offline",
            "title": "pipe metadata manipulation still depends on the ConfigFS/ashmem primitive",
            "impact": "Every save/forge/restore operation calls kernel_read_data/kernel_write_data, which are direct wrappers around configfs_read_once/configfs_write_once. The pipe path is not an independent arbitrary-write primitive until the ashmem fops route and ConfigFS iterators are already working.",
            "recommendation": "Describe pipe physrw as a second-stage consumer of the ConfigFS primitive; do not use it as evidence that the first-stage fops/configfs write works.",
            "evidence": [
                evidence(PIPE, pipe_text, "kernel_write_data(fd, buf_addr, &pb, sizeof(pb))"),
                evidence(UTIL, util_text, "ssize_t kernel_write_data(int fd, uintptr_t target, const void *data, size_t len)"),
                evidence(UTIL, util_text, "return configfs_write_once(fd, target, data, len);"),
            ],
        },
        {
            "id": "PBUF-CACHE-GATE-WEAK",
            "severity": "high",
            "status": "confirmed-offline",
            "title": "cache gate accepts kmalloc-normal-2k although pipe->bufs uses GFP_KERNEL_ACCOUNT",
            "impact": "The kernel allocation site uses kcalloc(..., GFP_KERNEL_ACCOUNT); accepting a normal-2k slab can turn a candidate-page match into a false positive and permit writes against an object that is not the pipe ring.",
            "recommendation": "Require the cgroup cache selected by the target build, or prove the normal/cgroup alias from the exact runtime config before accepting both.",
            "evidence": [
                evidence(PIPE, pipe_text, "return slab_cache == kmalloc_normal_2k_cache ||"),
                evidence(KERNEL_PIPE_C, kernel_pipe_text, "bufs = kcalloc(nr_slots, sizeof(*bufs),"),
                evidence(KERNEL_PIPE_C, kernel_pipe_text, "GFP_KERNEL_ACCOUNT | __GFP_NOWARN"),
                evidence(CONFIG, config_text, "CONFIG_MEMCG_KMEM=y"),
            ],
        },
        {
            "id": "PBUF-SLAB-TYPE-NOT-ENFORCED",
            "severity": "medium",
            "status": "confirmed-offline",
            "title": "pipe_reclaim_cache_gate records page_type but never requires PAGE_TYPE_SLAB",
            "impact": "A cache-pointer match alone does not prove that the candidate page is a live SLUB slab page; the diagnostic page_type value is currently non-binding.",
            "recommendation": "Require page_type == PAGE_TYPE_SLAB (and retain the value in evidence) before selecting the page, unless a build-specific exception is proven.",
            "evidence": [
                evidence(PIPE, pipe_text, "uint32_t page_type = (uint32_t)kernel_read64(fd, type_addr);"),
                evidence(PIPE, pipe_text, "if (cache_match) {"),
                evidence(COMMON, common_text, "#define PAGE_TYPE_SLAB 0xf5"),
            ],
        },
        {
            "id": "PBUF-CACHE-SLOT-COUNT",
            "severity": "low",
            "status": "confirmed-offline",
            "title": "KMALLOC_CACHE_TYPES is oversized for the validated target config",
            "impact": "The target config has MEMCG_KMEM=y, ZONE_DMA disabled and RANDOM_KMALLOC_CACHES disabled, giving three kmalloc cache rows (normal/reclaim/cgroup); common.h allocates and reads four rows. Required type-2 entries remain in range, but the read overruns the declared kmalloc_caches array into adjacent read-only data.",
            "recommendation": "Derive the row count from the exact config or read only the required normal/cgroup indices; avoid an oversized bulk read.",
            "evidence": [
                evidence(COMMON, common_text, "#define KMALLOC_CACHE_TYPES 4"),
                evidence(KERNEL_SLAB_H, slab_text, "enum kmalloc_cache_type"),
                evidence(CONFIG, config_text, "# CONFIG_ZONE_DMA is not set"),
                evidence(CONFIG, config_text, "# CONFIG_RANDOM_KMALLOC_CACHES is not set"),
            ],
        },
        {
            "id": "PBUF-ZERO-LENGTH",
            "severity": "medium",
            "status": "confirmed-offline",
            "title": "zero-length write is reported as success without touching the target",
            "impact": "The wrapper allows len==0; write() returns zero and the equality check reports success even though pipe_write takes its null-write path and performs no copy.",
            "recommendation": "Reject len==0 in pipe_phys_write_data (and make the read/write contract explicit).",
            "evidence": [
                evidence(PIPE, pipe_text, "if (!is_direct_ptr(direct_addr) ||"),
                evidence(PIPE, pipe_text, "ssize_t wrote = write(pipe_fds_reclaim[pipebuf_pipe_idx][1], data, len);"),
                evidence(KERNEL_PIPE_C, kernel_pipe_text, "/* Null write succeeds. */"),
            ],
        },
    ]

    validated_anon_ops = bool(
        re.search(r"anon_pipe_buf_ops.*0x0*114a288", kallsyms_text, re.I)
        or re.search(r"ANON_PIPE_BUF_OPS_OFF\s+0x0*114a288", offset_text, re.I)
    )

    result = {
        "audit": "violin pipe_buffer / anon_pipe_buf_ops independent-write primitive",
        "mode": "offline-read-only",
        "generated": "2026-07-19",
        "sources": sources,
        "build_config": config,
        "geometry": {
            "page_size": page_size,
            "pipe_buffer_size_header": pipe_buffer_size,
            "pipe_buffer_size_layout": pipe_fields["sizeof"],
            "pipe_buffer_slots": pipe_slots,
            "ring_bytes": ring_bytes,
            "kmalloc_object_size": object_size,
            "objects_per_order3_slab": objs_per_slab,
            "order3_slab_bytes": slab_size,
            "direct_map_pages": direct_map_pages,
            "vmemmap_start": f"0x{vmemmap_start:x}",
            "vmemmap_end": f"0x{vmemmap_end:x}",
            "vmemmap_range_valid": vmemmap_end > vmemmap_start,
            "kmalloc_pipe_index_header": pipe_index,
            "kmalloc_cache_types_header": cache_types,
            "kmalloc_cache_buckets_header": cache_buckets,
            "kmalloc_cgroup_type_header": cgroup_type,
            "expected_cache_rows_from_config": expected_cache_types,
            "expected_cgroup_type_from_config": expected_cgroup_type,
        },
        "layout": {
            "kernel_struct_pipe_buffer": pipe_fields,
            "user_pipe_buffer": target_user_fields,
            "matches": pipe_fields == {k: target_user_fields[k] for k in pipe_fields},
            "source_evidence": evidence(KERNEL_PIPE_H, pipe_h_text, "struct pipe_buffer {"),
        },
        "anon_pipe_buf_ops": {
            "target_offset": anon_ops_off,
            "target_offset_hex": f"0x{anon_ops_off:x}",
            "validated_offset": "0x114a288" if validated_anon_ops else None,
            "members_found_in_same_build_source": ops,
            "confirm_member_present": "confirm" in ops,
            "confirm_call_null_safe": "confirm" not in ops,
            "source_evidence": evidence(KERNEL_PIPE_C, kernel_pipe_text, "static const struct pipe_buf_operations anon_pipe_buf_ops"),
        },
        "write_state_simulation": {
            "assumptions": ["direct-map offset=0", "forged buffer is the last buffer", "pipe is non-empty after marker writes", "PIPE_BUF_FLAG_CAN_MERGE is set"],
            "cases": write_state,
        },
        "dependency_edges": {
            "pipe_phys_read_write_to_configfs": True,
            "pipe_source_read_calls": [line for line in (line_of(pipe_text, "kernel_read_data(fd, buf_addr"), line_of(pipe_text, "kernel_write_data(fd, buf_addr")) if line],
            "util_kernel_write_delegates_to_configfs": line_of(util_text, "return configfs_write_once(fd, target, data, len);"),
            "util_kernel_read_delegates_to_configfs": line_of(util_text, "return configfs_read_once(fd, target, data, len);"),
        },
        "findings": findings,
        "overall": {
            "layout_and_symbol_offset": "pass-static",
            "anon_ops_confirm_path": "pass-static; confirm is absent and pipe_buf_confirm treats NULL as success",
            "independent_write_claim": "fail; pipe metadata reads/writes require ConfigFS/ashmem primitive",
            "arbitrary_write_contract": "fail for len==0 and len==PAGE_SIZE; bounded small writes remain statically plausible",
            "runtime_evidence": "not collected in this offline audit",
        },
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
