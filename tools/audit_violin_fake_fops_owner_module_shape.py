#!/usr/bin/env python3
"""Offline audit of fake_fops.owner=N through misc_open/fops_get.

The post-erase model showed ``fake_fops.owner`` becoming N (the address of the
ashmem_misc.name field).  That is not a validated ``struct module`` pointer,
but CONFIG_MODULE_UNLOAD's try_module_get() does not perform a membership
check; it reads module->state and module->refcnt.  This bounded audit extracts
the same-build BTF layout from the shipped kernel image and checks the raw
image bytes at the aliased addresses.  It does not build, install, connect,
modify a payload, or execute a route.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IMAGE = ROOT / "analysis_outputs" / "ota_full" / "boot_parse" / "boot.img.kernel"
KALLSYMS = ROOT / "kallsyms.txt"
CONFIG = ROOT / "analysis_outputs" / "share-poc-XRing-O1-20260718" / "refs" / "kernel_config.txt"
TARGET_H = ROOT / "exploit-repo" / "IonStack" / "CVE-2026-43499" / "exploit" / "src" / "targets" / "violin-v-oss" / "target.h"
OUT_DIR = ROOT / "analysis_outputs"
OUT_JSON = OUT_DIR / "violin-fake-fops-owner-module-shape-20260722.json"
OUT_MD = OUT_DIR / "violin-fake-fops-owner-module-shape-20260722.md"


def find_btf(blob: bytes) -> tuple[int, bytes]:
    for pos in range(0, len(blob) - 24):
        if blob[pos:pos + 2] != b"\x9f\xeb":
            continue
        magic, version, flags, hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from("<HBBIIIII", blob, pos)
        end = pos + hdr_len + max(type_off + type_len, str_off + str_len)
        if magic == 0xEB9F and version == 1 and 0 < type_len < 20_000_000 and 0 < str_len < 20_000_000 and end <= len(blob):
            return pos, blob[pos:end]
    raise ValueError("embedded BTF header not found")


def cstr(strings: bytes, offset: int) -> str:
    end = strings.find(b"\0", offset)
    return strings[offset:end].decode("utf-8", "replace") if end >= 0 else ""


def btf_struct_fields(blob: bytes, wanted: str) -> tuple[int, dict[str, int], int]:
    _, btf = find_btf(blob)
    _, _, _, hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from("<HBBIIIII", btf, 0)
    types_blob = btf[hdr_len + type_off:hdr_len + type_off + type_len]
    strings = btf[hdr_len + str_off:hdr_len + str_off + str_len]
    p = 0
    while p < len(types_blob):
        name_off, info, size_type = struct.unpack_from("<III", types_blob, p)
        p += 12
        vlen = info & 0xffff
        kind = (info >> 24) & 0x1f
        if kind in (4, 5):
            extra = types_blob[p:p + 12 * vlen]
            p += 12 * vlen
            name = cstr(strings, name_off)
            if kind == 4 and name == wanted:
                fields: dict[str, int] = {}
                for i in range(vlen):
                    member_name, _, bit_offset = struct.unpack_from("<III", extra, i * 12)
                    fields[cstr(strings, member_name)] = bit_offset // 8
                return size_type, fields, len(btf)
        elif kind == 1:
            p += 4
        elif kind == 3:
            p += 12
        elif kind == 6:
            p += 8 * vlen
        elif kind == 13:
            p += 8 * vlen
        elif kind == 14:
            p += 4
        elif kind == 15:
            p += 12 * vlen
        elif kind == 17:
            p += 4
        elif kind == 19:
            p += 12 * vlen
    raise ValueError(f"BTF struct {wanted!r} not found")


def target_offset() -> int:
    for line in TARGET_H.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("#define ASHMEM_MISC_OFF"):
            return int(line.split()[2].replace("ULL", ""), 16)
    raise ValueError("ASHMEM_MISC_OFF missing")


def symbol_near(offset: int) -> dict:
    base = None
    rows = []
    for line in KALLSYMS.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        try:
            addr = int(fields[0], 16)
        except ValueError:
            continue
        if fields[2] == "_text" and base is None:
            base = addr
        if base is not None:
            rows.append((addr - base, fields[2]))
    prior = sorted((off, name) for off, name in rows if off <= offset)
    if not prior:
        return {"offset": hex(offset), "symbol": None, "delta": None}
    off, name = prior[-1]
    return {"offset": hex(offset), "symbol": name, "symbol_offset": hex(off), "delta": hex(offset - off)}


def main() -> int:
    image = IMAGE.read_bytes()
    module_size, module_fields, btf_size = btf_struct_fields(image, "module")
    state_off = module_fields["state"]
    refcnt_off = module_fields["refcnt"]
    misc_off = target_offset()
    n_off = misc_off + 0x08
    state = struct.unpack_from("<I", image, n_off + state_off)[0]
    refcnt = struct.unpack_from("<I", image, n_off + refcnt_off)[0]
    config = CONFIG.read_text(encoding="utf-8", errors="replace")
    unload = "CONFIG_MODULE_UNLOAD=y" in config
    going = 2
    result = {
        "audit": "fake_fops.owner=N module-shaped open gate",
        "date": "2026-07-22",
        "mode": "offline-raw-image-BTF-source-only",
        "sources": {"image": str(IMAGE), "kallsyms": str(KALLSYMS), "config": str(CONFIG), "target_h": str(TARGET_H)},
        "btf": {"struct_module_size": hex(module_size), "state_offset": hex(state_off), "refcnt_offset": hex(refcnt_off), "blob_size": btf_size},
        "alias": {"T": "ashmem_misc+0x10", "N": "ashmem_misc+0x08", "owner_after_erase": "N"},
        "raw_values": {"N_state": hex(state), "N_refcnt": hex(refcnt), "module_state_going": going,
                       "state_is_live_under_source": state != going, "refcnt_nonzero": refcnt != 0},
        "side_effect_target": symbol_near(n_off + refcnt_off),
        "try_module_get_model": {
            "config_module_unload": unload,
            "source_predicate": "module && module_is_live(module) && atomic_inc_not_zero(&module->refcnt)",
            "raw_image_prediction": "likely returns true and increments the aliased refcnt word" if unload and state != going and refcnt != 0 else "not proven true from raw bytes",
            "membership_validation": "none in try_module_get; N is still not proven to be a real struct module",
            "runtime_caveat": "raw image bytes may be changed by runtime initialization; no runtime claim is made",
        },
        "verdict": {
            "owner_is_valid_module_pointer": False,
            "owner_gate_hard_block": False,
            "owner_gate_raw_image_prediction": "likely-pass-with-adjacent-refcnt-side-effect" if unload and state != going and refcnt != 0 else "unknown",
            "transport_order": "still not closed because post-erase tree consumer and callback sequence remain unresolved",
            "runtime_allowed": False,
            "next_gate": "do not treat owner=N as a guaranteed crash; model the adjacent refcnt side effect together with the stale-tree consumer, or abandon the shape1 anchor if no valid post-erase consumer appears",
        },
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md = "# fake_fops.owner=N module-shaped open-gate audit (2026-07-22)\n\n"
    md += "**Mode:** offline raw image + embedded BTF + source/config only; no build, install, device connection, or route execution.\n\n"
    md += f"BTF reports `struct module` size `{module_size:#x}`, `state` at `{state_off:#x}`, and `refcnt` at `{refcnt_off:#x}`. For custom shape-1, `fake_fops.owner` becomes N=`ashmem_misc+0x08`; raw image bytes at that alias are `state={state:#x}` and `refcnt={refcnt:#x}`.\n\n"
    md += "With `CONFIG_MODULE_UNLOAD=y`, the checked source implements `try_module_get()` as `module_is_live(module) && atomic_inc_not_zero(&module->refcnt)` and does not validate that the pointer belongs to the module registry. The image therefore predicts a likely successful pin and a write-side increment to the aliased refcount word, but N is not a legitimate module object and runtime initialization may change those bytes.\n\n"
    md += "## Corrected conclusion\n\n"
    md += "`fake_fops.owner=N` is **not a proven hard open blocker**; it is a likely-pass-with-adjacent-refcnt-side-effect condition. This removes an overstrong earlier claim, but it does not close the exploit: the custom shape-1 stale-root/leftmost tree still lacks a valid post-erase consumer, and no runtime execution is authorized.\n"
    OUT_MD.write_text(md, encoding="utf-8")
    print(json.dumps({"json": str(OUT_JSON), "markdown": str(OUT_MD), "verdict": result["verdict"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
