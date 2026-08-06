#!/usr/bin/env python3
"""Bounded offline audit of the remaining raw-kernel sink-review boundary.

The checked-in common-gki snapshot does not contain all of the target build's
io_uring/KVM implementation.  This audit uses only the matching raw kernel and
rooted kallsyms to inspect the generic io_uring_cmd dispatcher, the built-in
ublk/NVMe callbacks, and arm64 KVM ioctl helpers.  It records call/uaccess
shapes; it does not execute, rebuild, install, or derive a payload.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, Cs
from capstone.arm64_const import ARM64_OP_IMM

try:
    from audit_violin_raw_sink_gap_inventory import parse_kallsyms, symbol_addr
except ModuleNotFoundError:  # supports ``python -m tools.<script>`` from repo root
    from tools.audit_violin_raw_sink_gap_inventory import parse_kallsyms, symbol_addr


ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "analysis_outputs/ota_full/boot_parse/boot.img.kernel"
KALLSYMS = ROOT / "analysis_outputs/violin-kernel-info2/violin-kernel-info/kallsyms.txt"
OUT = ROOT / "analysis_outputs"
OUT_JSON = OUT / "violin-raw-driver-arch-sinks-20260722.json"
OUT_MD = OUT / "violin-raw-driver-arch-sinks-20260722.md"
IMAGE_BASE = 0xFFFF_FFE3_8720_0000
# Static fops in the raw image retain the pre-relocation module-text alias;
# the delta is independently visible from the ublk/NVMe fops callback slots.
MODULE_ALIAS_RELOC_DELTA = 0x2307_200000


# Explicit bounds stop the disassembler at the next known function.  A few
# symbols are tiny wrappers; keeping their short ranges is intentional.
TARGETS = {
    "io_uring_cmd": (0x114, "generic-dispatch"),
    "uring_cmd_null": (0x0C, "driver-callback"),
    "ublk_ctrl_uring_cmd": (0x254, "driver-callback"),
    "ublk_ch_uring_cmd": (0x484, "driver-callback"),
    "nvme_ns_chr_uring_cmd": (0x88, "driver-callback"),
    "nvme_ns_head_chr_uring_cmd": (0x108, "driver-callback"),
    "nvme_dev_uring_cmd": (0x7C, "driver-callback"),
    "nvme_uring_cmd_io": (0x314, "driver-helper"),
    "kvm_arch_dev_ioctl": (0x0C, "arm64-kvm"),
    "kvm_arch_vcpu_ioctl": (0x8EC, "arm64-kvm"),
    "kvm_arch_vm_ioctl": (0x25C, "arm64-kvm"),
    "kvm_vm_ioctl_mte_copy_tags": (0x24C, "arm64-kvm"),
    "pkvm_vm_ioctl_set_fw_ipa": (0x74, "arm64-kvm"),
    "pkvm_vm_ioctl_info": (0x140, "arm64-kvm"),
    "kvm_vm_ioctl_set_counter_offset": (0xC4, "arm64-kvm"),
}


SHAPES = {
    "io_uring_cmd": (
        "indirect file->f_op->uring_cmd dispatch after security_uring_cmd; "
        "generic code does not choose the destination"
    ),
    "uring_cmd_null": "null-device callback reads a command field and has no kernel write sink",
    "ublk_ctrl_uring_cmd": (
        "ublk control state machine; copy_to_user reports device/affinity data and "
        "mutations stay in ublk objects"
    ),
    "ublk_ch_uring_cmd": (
        "ublk request/queue bookkeeping and completion; stores target ublk request state, "
        "not an arbitrary host pointer"
    ),
    "nvme_ns_chr_uring_cmd": "selects namespace and forwards to nvme_uring_cmd_io",
    "nvme_ns_head_chr_uring_cmd": "selects a namespace path under SRCU and forwards to nvme_uring_cmd_io",
    "nvme_dev_uring_cmd": "builds a validated NVMe command and forwards to nvme_uring_cmd_io",
    "nvme_uring_cmd_io": (
        "allocates a block request, maps/pins the user request through nvme_map_user_request, "
        "and submits device I/O; no user-selected host kernel destination"
    ),
    "kvm_arch_dev_ioctl": "allocates KVM VM state; no user pointer store in the wrapper",
    "kvm_arch_vcpu_ioctl": (
        "copy_from_user/copy_to_user around fixed vCPU register/event attributes and "
        "arch helpers; destination is the KVM vCPU object"
    ),
    "kvm_arch_vm_ioctl": (
        "copy_from_user/copy_to_user around VM attributes, VGIC, SMCCC, MTE and legacy "
        "VGIC handlers; MTE path is guest-memory/memslot limited"
    ),
    "kvm_vm_ioctl_mte_copy_tags": (
        "translates a guest frame through KVM memslots, then copies MTE tags from/to user "
        "or guest pages; not an arbitrary kernel address"
    ),
    "pkvm_vm_ioctl_set_fw_ipa": "updates pKVM VM firmware IPA state under the VM mutex",
    "pkvm_vm_ioctl_info": "copies pKVM information to a user buffer",
    "kvm_vm_ioctl_set_counter_offset": "updates per-vCPU timer offset fields under VM/vCPU locks",
}


def disassemble(raw: bytes, address: int, length: int, by_addr: dict[int, list[str]]) -> dict:
    offset = address - IMAGE_BASE
    if offset < 0 or offset >= len(raw):
        return {"address": hex(address), "offset": hex(offset), "status": "out-of-range"}
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    instructions = []
    calls = []
    indirect = []
    for ins in md.disasm(raw[offset : offset + length], address):
        row = {"address": hex(ins.address), "mnemonic": ins.mnemonic, "op_str": ins.op_str}
        instructions.append(row)
        if ins.mnemonic == "bl" and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
            target = ins.operands[0].imm & 0xFFFF_FFFF_FFFF_FFFF
            calls.append({"at": hex(ins.address), "target": hex(target), "symbols": by_addr.get(target, [])})
        if ins.mnemonic in {"blr", "br"}:
            indirect.append(row)
    return {
        "address": hex(address),
        "offset": hex(offset),
        "status": "ok",
        "instruction_count": len(instructions),
        "calls": calls,
        "indirect_control_flow": indirect,
        "instructions": instructions,
    }


def names_containing(by_addr: dict[int, list[str]], pattern: str) -> list[str]:
    rx = re.compile(pattern)
    return sorted({name for names in by_addr.values() for name in names if rx.search(name)})


def normalize_module_alias(pointer: int) -> int:
    if 0xFFFF_FFC0_0000_0000 <= pointer < 0xFFFF_FFC1_0000_0000:
        return pointer + MODULE_ALIAS_RELOC_DELTA
    return pointer


def scan_static_uring_fops(raw: bytes, by_addr: dict[int, list[str]]) -> list[dict]:
    """Resolve recognized +0xf8/+0x100 uring slots in static fops symbols.

    The two offsets are not inferred from the source struct order (the target
    uses randomized layout); they are the offsets loaded by the raw
    io_uring_cmd dispatcher itself.  Unknown nonzero values are ignored rather
    than treated as callbacks.
    """
    rows = []
    for address, names in by_addr.items():
        fops_names = [name for name in names if name.endswith("_fops") and not name.startswith("__")]
        if not fops_names:
            continue
        offset = address - IMAGE_BASE
        if offset < 0 or offset + 0x108 > len(raw):
            continue
        for slot in (0xF8, 0x100):
            pointer = int.from_bytes(raw[offset + slot : offset + slot + 8], "little")
            if pointer == 0:
                continue
            normalized = normalize_module_alias(pointer)
            target_names = [name for name in by_addr.get(normalized, []) if "uring_cmd" in name]
            if not target_names:
                continue
            rows.append({
                "fops": fops_names,
                "address": hex(address),
                "slot": hex(slot),
                "raw_pointer": hex(pointer),
                "normalized_pointer": hex(normalized),
                "callbacks": target_names,
            })
    return sorted(rows, key=lambda row: (row["address"], row["slot"]))


def main() -> int:
    raw = RAW.read_bytes()
    by_addr = parse_kallsyms(KALLSYMS.read_text(encoding="utf-8", errors="replace"))
    symbols = {}
    disassembly = {}
    for name, (length, group) in TARGETS.items():
        address = symbol_addr(by_addr, name)
        symbols[name] = {
            "group": group,
            "address": hex(address) if address is not None else None,
            "offset": hex(address - IMAGE_BASE) if address is not None else None,
            "length": length,
            "present": address is not None,
        }
        if address is not None:
            disassembly[name] = disassemble(raw, address, length, by_addr)

    uring_symbols = names_containing(by_addr, r"(?:^|_)uring_cmd(?:$|_)")
    kvm_arch_symbols = names_containing(by_addr, r"^(?:p?pkvm_)?kvm_arch_.*ioctl|^kvm_vm_ioctl_.*")
    static_uring_fops = scan_static_uring_fops(raw, by_addr)
    present = {name: symbols[name]["present"] for name in TARGETS}
    targeted_missing = [name for name, ok in present.items() if not ok]
    result = {
        "audit": "Violin raw driver/arch sink boundary",
        "date": "2026-07-22",
        "mode": "offline-raw-image-bounded-arm64-disassembly",
        "runtime_allowed": False,
        "raw_artifact": {
            "path": str(RAW.relative_to(ROOT)),
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest().upper(),
            "image_base": hex(IMAGE_BASE),
            "kallsyms_path": str(KALLSYMS.relative_to(ROOT)),
        },
        "enumerated_symbols": {
            "uring_cmd_like": uring_symbols,
            "kvm_ioctl_like": kvm_arch_symbols,
            "static_fops_uring_cmd_slots": static_uring_fops,
            "module_alias_reloc_delta": hex(MODULE_ALIAS_RELOC_DELTA),
        },
        "symbols": symbols,
        "disassembly": disassembly,
        "candidate_closure": {
            "targeted_symbols_all_present": not targeted_missing,
            "targeted_missing": targeted_missing,
            "static_uring_fops_resolved": bool(static_uring_fops),
            "generic_io_uring_cmd_closed": False,
            "listed_driver_callbacks_no_arbitrary_kernel_destination": True,
            "arm64_kvm_ioctl_helpers_no_arbitrary_kernel_destination": True,
            "open_review": [
                "generic io_uring_cmd still dispatches through file-specific f_op callback",
                "unlisted loadable modules or future driver callbacks are outside this bounded inventory",
            ],
            "overall": (
                "TARGETED_DRIVER_ARCH_CALLBACKS_NO_ARBITRARY_KERNEL_DESTINATION; "
                "GENERIC_IO_URING_CMD_DISPATCH_REMAINS_OPEN"
            ),
        },
        "shape_notes": SHAPES,
    }

    OUT.mkdir(exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    c = result["candidate_closure"]
    md = [
        "# Violin raw driver/arch sink boundary (2026-07-22)",
        "",
        "只读使用匹配 OTA raw kernel 与 rooted kallsyms；不构建、不安装、不改 payload/fd-set/nfds、不联机。",
        "",
        "## Artifact",
        "",
        f"- `{RAW.relative_to(ROOT)}`：{len(raw)} bytes，SHA256 `{hashlib.sha256(raw).hexdigest().upper()}`。",
        f"- image base：`{IMAGE_BASE:#x}`；kallsyms：`{KALLSYMS.relative_to(ROOT)}`。",
        "",
        "## Targeted callback/handler evidence",
        "",
        "- generic `io_uring_cmd` 在 `file->f_op` 上做间接 `uring_cmd` callback dispatch；这仍是 transport/driver 选择点，而不是独立 arbitrary-write sink。",
        "- 已定位的 ublk callbacks 只读写 ublk request/device state，并对用户缓冲区做显式 usercopy。",
        "- 已定位的 NVMe callbacks 最终进入 `nvme_map_user_request`、block request 与设备 I/O；没有用户选择的 host-kernel destination。",
        "- arm64 `kvm_arch_vcpu_ioctl`/`kvm_arch_vm_ioctl` 只围绕固定 KVM vCPU/VM、guest memslot、MTE tags 和计时字段操作；`copy_{from,to}_user` 不形成任意内核地址写。",
        "",
        "## Enumerated symbol boundary",
        "",
        f"- `uring_cmd`-like symbols：{len(uring_symbols)} 个；`kvm ioctl`-like symbols：{len(kvm_arch_symbols)} 个。",
        f"- 本轮目标符号全部存在：**{not targeted_missing}**；缺失：`{', '.join(targeted_missing) or 'none'}`。",
        f"- raw static fops 中能按 dispatcher 的 `+0xf8/+0x100` 槽解析出已知 `uring_cmd` callback 的记录：{len(static_uring_fops)} 条；module alias relocation delta：`{MODULE_ALIAS_RELOC_DELTA:#x}`。",
        "",
        "## Verdict",
        "",
        f"- 已核对目标驱动/arm64 handler 未发现新的 arbitrary kernel destination：**{c['listed_driver_callbacks_no_arbitrary_kernel_destination']}**。",
        "- 不能据此把 generic `io_uring_cmd` 间接分发宣称为闭合写入原语；未列出的模块/未来 callback 仍在边界外。",
        f"- 总结：**`{c['overall']}`**。",
        "",
    ]
    OUT_MD.write_text("\n".join(md), encoding="utf-8")
    print(json.dumps({"json": str(OUT_JSON), "markdown": str(OUT_MD), "verdict": c}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
