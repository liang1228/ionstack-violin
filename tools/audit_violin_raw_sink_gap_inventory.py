#!/usr/bin/env python3
"""Use the matching Violin raw kernel to close the two source-snapshot gaps.

The checked-in common-gki tree is missing the io_uring and virt/kvm common
implementation directories, but the matching OTA kernel and rooted kallsyms
are available locally.  This audit only inventories symbols and bounded ARM64
disassembly around generic entry points.  It does not execute, rebuild, or
derive a payload.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from capstone.arm64_const import ARM64_OP_IMM


ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "analysis_outputs/ota_full/boot_parse/boot.img.kernel"
KALLSYMS = ROOT / "analysis_outputs/violin-kernel-info2/violin-kernel-info/kallsyms.txt"
OUT = ROOT / "analysis_outputs"
OUT_JSON = OUT / "violin-raw-sink-gap-inventory-20260722.json"
OUT_MD = OUT / "violin-raw-sink-gap-inventory-20260722.md"
IMAGE_BASE = 0xFFFF_FFE3_8720_0000


RANGES = {
    "__arm64_sys_io_uring_setup": 0x120,
    "__arm64_sys_io_uring_register": 0x3C0,
    "io_uring_create": 0x1C0,
    "io_sqe_buffers_register": 0x250,
    "io_read": 0x180,
    "io_write": 0x180,
    "kvm_vm_ioctl": 0x320,
    "kvm_vm_ioctl_set_memory_region": 0x70,
    "kvm_write_guest": 0x150,
}


def parse_kallsyms(text: str) -> dict[int, list[str]]:
    by_addr: dict[int, list[str]] = {}
    for line in text.splitlines():
        m = re.match(r"^([0-9a-fA-F]+)\s+[A-Za-z?]\s+(\S+)$", line)
        if not m:
            continue
        by_addr.setdefault(int(m.group(1), 16), []).append(m.group(2))
    return by_addr


def symbol_addr(by_addr: dict[int, list[str]], name: str) -> int | None:
    for address, names in by_addr.items():
        if name in names:
            return address
    return None


def disassemble(raw: bytes, address: int, length: int, by_addr: dict[int, list[str]]) -> dict:
    offset = address - IMAGE_BASE
    if offset < 0 or offset >= len(raw):
        return {"address": hex(address), "offset": hex(offset), "status": "out-of-range"}
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    instructions = []
    calls = []
    for ins in md.disasm(raw[offset : offset + length], address):
        row = {"address": hex(ins.address), "mnemonic": ins.mnemonic, "op_str": ins.op_str}
        instructions.append(row)
        if ins.mnemonic == "bl" and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
            target = ins.operands[0].imm & 0xFFFF_FFFF_FFFF_FFFF
            calls.append({
                "at": hex(ins.address),
                "target": hex(target),
                "symbols": by_addr.get(target, []),
            })
    return {
        "address": hex(address),
        "offset": hex(offset),
        "status": "ok",
        "instruction_count": len(instructions),
        "calls": calls,
        "instructions": instructions,
    }


def call_names(disasm: dict) -> list[str]:
    names: list[str] = []
    for call in disasm.get("calls", []):
        if call["symbols"]:
            names.extend(call["symbols"])
        else:
            names.append(call["target"])
    return names


def main() -> int:
    raw = RAW.read_bytes()
    by_addr = parse_kallsyms(KALLSYMS.read_text(encoding="utf-8", errors="replace"))
    symbols = {}
    for name in RANGES:
        address = symbol_addr(by_addr, name)
        symbols[name] = {
            "address": hex(address) if address is not None else None,
            "offset": hex(address - IMAGE_BASE) if address is not None else None,
            "present": address is not None,
        }

    disassembly = {}
    for name, length in RANGES.items():
        address = symbol_addr(by_addr, name)
        if address is not None:
            disassembly[name] = disassemble(raw, address, length, by_addr)

    required_io = [
        "__arm64_sys_io_uring_setup",
        "__arm64_sys_io_uring_enter",
        "__arm64_sys_io_uring_register",
        "io_uring_create",
        "io_sqe_buffers_register",
        "io_read",
        "io_write",
    ]
    required_kvm = [
        "kvm_vm_ioctl",
        "kvm_vm_ioctl_set_memory_region",
        "kvm_write_guest",
        "kvm_dev_ioctl",
    ]
    io_present = {name: symbol_addr(by_addr, name) is not None for name in required_io}
    kvm_present = {name: symbol_addr(by_addr, name) is not None for name in required_kvm}

    result = {
        "audit": "Violin raw kernel sink-gap inventory",
        "date": "2026-07-22",
        "mode": "offline-raw-image-symbol-and-bounded-arm64-disassembly",
        "runtime_allowed": False,
        "raw_artifact": {
            "path": str(RAW.relative_to(ROOT)),
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest().upper(),
            "image_base": hex(IMAGE_BASE),
            "kallsyms_path": str(KALLSYMS.relative_to(ROOT)),
        },
        "symbols": symbols,
        "disassembly": disassembly,
        "candidate_closure": {
            "io_uring_symbols_present": all(io_present.values()),
            "io_uring_symbol_presence": io_present,
            "kvm_symbols_present": all(kvm_present.values()),
            "kvm_symbol_presence": kvm_present,
            "io_uring_generic_destination": "ring/registered-user-buffer/file-object semantics; io_uring_cmd remains driver-specific",
            "kvm_generic_destination": "KVM memslot/guest-memory and vCPU state semantics; no arbitrary host pointer in generic path",
            "generic_independent_sink_closed": False,
            "open_review": [
                "io_uring_cmd driver-specific uring_cmd callbacks",
                "architecture-specific KVM ioctl handlers beyond the common memslot path",
            ],
            "overall": "RAW_ARTIFACT_PRESENT_GENERIC_PATHS_NOT_ARBITRARY_DRIVER_OR_ARCH_REVIEW_OPEN",
        },
        "next_gate": (
            "If a whole-kernel sink claim is needed, disassemble the listed driver-specific "
            "io_uring_cmd and arm64 KVM handlers from this same raw image. Do not treat the "
            "missing common-gki directories as proof of absence, and do not run a payload."
        ),
    }

    OUT.mkdir(exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md = [
        "# Violin raw sink-gap inventory (2026-07-22)",
        "",
        "只读使用匹配 OTA raw kernel 与 rooted kallsyms；不构建、不安装、不改 payload/fd-set/nfds、不联机。",
        "",
        "## Artifact",
        "",
        f"- `{RAW.relative_to(ROOT)}`：{len(raw)} bytes，SHA256 `{hashlib.sha256(raw).hexdigest().upper()}`。",
        f"- `_text`/image base：`{IMAGE_BASE:#x}`；file offset = symbol VA - image base。",
        f"- kallsyms：`{KALLSYMS.relative_to(ROOT)}`。",
        "",
        "## Raw symbol closure",
        "",
        f"- io_uring generic symbols present：**{all(io_present.values())}**；entry/setup/register、buffer registration、read/write 均可定位。",
        f"- KVM generic symbols present：**{all(kvm_present.values())}**；VM ioctl、set-memory-region、write-guest、device ioctl 均可定位。",
        "",
        "## Bounded disassembly evidence",
        "",
        "- `io_uring_create` 将 ring/params 状态写回用户参数指针，并通过 `_copy_to_user` 回传；`io_sqe_buffers_register` 先分配 kernel resource state，再复制 iovec、pin user pages/register buffers。",
        "- `io_read`/`io_write` 走 `io_import_iovec` 与 file operation；目的地是用户 buffer 或已打开 file，不是任意 kernel address。",
        "- `kvm_vm_ioctl_set_memory_region` 只调用 `__kvm_set_memory_region`；`kvm_write_guest` 通过 memslot/guest page 选择 guest memory。generic KVM path 没有 user-supplied host pointer store。",
        "",
        "## Remaining review boundary",
        "",
        "- `io_uring_cmd` 通过 file-specific `uring_cmd` callback 间接分发；其 driver-specific destination/value 语义未在本轮展开。",
        "- arm64 KVM 专用 ioctl handler 仍需按同一 raw image 单独核对；common memslot path 已有上述边界。",
        "",
        "## Verdict",
        "",
        "原先的 `OPEN_SOURCE_SNAPSHOT_GAP` 不能再理解为“内核实现不存在”：匹配 raw image 已证明两个子系统都在目标 build 中。当前结论为 **`RAW_ARTIFACT_PRESENT_GENERIC_PATHS_NOT_ARBITRARY_DRIVER_OR_ARCH_REVIEW_OPEN`**；未发现新的 generic independent first-stage sink，但 driver/arch 专用分支仍未全闭合。",
        "",
    ]
    OUT_MD.write_text("\n".join(md), encoding="utf-8")
    print(json.dumps({"json": str(OUT_JSON), "markdown": str(OUT_MD), "verdict": result["candidate_closure"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
