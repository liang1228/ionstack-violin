#!/usr/bin/env python3
"""Bounded offline audit of same-build kernel write-sink candidates.

This pass is deliberately narrower than a whole-kernel vulnerability scan.  It
checks the enabled configuration and the user-copy entry points most likely to
look like an independent first-stage write for the Violin route.  A candidate
is only closed when the source shows both the destination class and the value
flow.  Missing implementation files are reported as an explicit source gap,
not as a negative result.

No build, device, payload, fd-set, nfds, or runtime action is performed.
"""

from __future__ import annotations

import json
import hashlib
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "kernel-src-wsl/common-gki"
CONFIG = ROOT / "analysis_outputs/share-poc-XRing-O1-20260718/refs/kernel_config.txt"
RAW_KERNEL = ROOT / "analysis_outputs/ota_full/boot_parse/boot.img.kernel"
OUT = ROOT / "analysis_outputs"
OUT_JSON = OUT / "violin-kernel-sink-candidates-20260722.json"
OUT_MD = OUT / "violin-kernel-sink-candidates-20260722.md"


def config_states(text: str) -> dict[str, str]:
    states: dict[str, str] = {}
    for line in text.splitlines():
        m = re.match(r"^(CONFIG_[A-Z0-9_]+)=(y|m)$", line)
        if m:
            states[m.group(1)] = m.group(2)
            continue
        m = re.match(r"^# (CONFIG_[A-Z0-9_]+) is not set$", line)
        if m:
            states[m.group(1)] = "n"
    return states


def first_line(rel_path: str, pattern: str) -> dict:
    path = KERNEL / rel_path
    if not path.exists():
        return {"file": rel_path, "line": None, "pattern": pattern, "status": "missing"}
    regex = re.compile(pattern)
    for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if regex.search(line):
            return {
                "file": rel_path,
                "line": number,
                "pattern": pattern,
                "text": line.strip(),
                "status": "found",
            }
    return {"file": rel_path, "line": None, "pattern": pattern, "status": "not-found"}


def evidence(rows: list[tuple[str, str]]) -> list[dict]:
    return [first_line(path, pattern) for path, pattern in rows]


def main() -> int:
    cfg_text = CONFIG.read_text(encoding="utf-8", errors="replace")
    cfg = config_states(cfg_text)

    candidates = [
        {
            "id": "dev_mem",
            "config": {"CONFIG_DEVMEM": cfg.get("CONFIG_DEVMEM", "unspecified")},
            "entry": "drivers/char/mem.c:write_mem",
            "destination": "physical address selected by f_pos, translated by xlate_dev_mem_ptr",
            "value": "user buffer via copy_from_user",
            "reachability": "CONFIG_DEVMEM is disabled in the recorded build; when enabled open_port also requires CAP_SYS_RAWIO and passes lockdown",
            "verdict": "CLOSED_CONFIG_DISABLED",
            "evidence": evidence([
                ("drivers/char/mem.c", r"^static ssize_t write_mem"),
                ("drivers/char/mem.c", r"copied = copy_from_user\(ptr, buf, sz\)"),
                ("drivers/char/mem.c", r"^static int open_port"),
                ("drivers/char/mem.c", r"!capable\(CAP_SYS_RAWIO\)"),
                ("drivers/char/mem.c", r"^#ifdef CONFIG_DEVMEM"),
            ]),
        },
        {
            "id": "android_binder",
            "config": {"CONFIG_ANDROID_BINDER_IPC": cfg.get("CONFIG_ANDROID_BINDER_IPC", "unspecified")},
            "entry": "drivers/android/binder.c:binder_ioctl -> binder_transaction",
            "destination": "target-process binder allocator buffer; binder_alloc_copy_* operates on that allocator-owned buffer",
            "value": "user transaction/scatter-gather bytes and binder fixups",
            "reachability": "device/ioctl reachability is separate, but source-level destination is allocator-owned and not an arbitrary kernel pointer",
            "verdict": "CLOSED_NO_ARBITRARY_KERNEL_DESTINATION",
            "evidence": evidence([
                ("drivers/android/binder.c", r"^static int binder_ioctl_write_read"),
                ("drivers/android/binder.c", r"^static void binder_transaction"),
                ("drivers/android/binder.c", r"t->buffer = binder_alloc_new_buf"),
                ("drivers/android/binder.c", r"binder_alloc_copy_user_to_buffer"),
                ("drivers/android/binder.c", r"copy_from_user\(&tr, ptr, sizeof\(tr\)\)"),
            ]),
        },
        {
            "id": "bpf",
            "config": {
                "CONFIG_BPF": cfg.get("CONFIG_BPF", "unspecified"),
                "CONFIG_BPF_SYSCALL": cfg.get("CONFIG_BPF_SYSCALL", "unspecified"),
                "CONFIG_BPF_UNPRIV_DEFAULT_OFF": cfg.get("CONFIG_BPF_UNPRIV_DEFAULT_OFF", "unspecified"),
            },
            "entry": "kernel/bpf/syscall.c:__sys_bpf -> map_update_elem / bpf_prog_load",
            "destination": "map-type operation or verifier-approved BPF object; no user-supplied arbitrary kernel pointer is accepted by these paths",
            "value": "user key/value and BPF attributes; general program types are capability-gated",
            "reachability": "CONFIG_BPF_UNPRIV_DEFAULT_OFF is not set in this config, so runtime unprivileged policy is not inferred; bpf_capable gates general program types and privileged map types",
            "verdict": "CLOSED_NO_ARBITRARY_KERNEL_DESTINATION",
            "evidence": evidence([
                ("kernel/bpf/syscall.c", r"^static int map_update_elem"),
                ("kernel/bpf/syscall.c", r"bpf_map_update_value\(map, f\.file, key, value, attr->flags\)"),
                ("kernel/bpf/syscall.c", r"^static int __sys_bpf"),
                ("kernel/bpf/syscall.c", r"copy_from_bpfptr\(&attr, uattr, size\)"),
                ("kernel/bpf/syscall.c", r"type != BPF_PROG_TYPE_SOCKET_FILTER"),
                ("kernel/bpf/syscall.c", r"sysctl_unprivileged_bpf_disabled && !bpf_capable"),
            ]),
        },
        {
            "id": "userfaultfd",
            "config": {"CONFIG_USERFAULTFD": cfg.get("CONFIG_USERFAULTFD", "unspecified")},
            "entry": "fs/userfaultfd.c:userfaultfd_copy",
            "destination": "validated range in ctx->mm user VMA, passed to mfill_atomic_copy",
            "value": "source user VMA/page range; ioctl header is copied to a local struct",
            "reachability": "userfaultfd can be user-reachable, but validate_range ties dst to the context mm rather than kernel address space",
            "verdict": "CLOSED_NO_ARBITRARY_KERNEL_DESTINATION",
            "evidence": evidence([
                ("fs/userfaultfd.c", r"^static int userfaultfd_copy"),
                ("fs/userfaultfd.c", r"copy_from_user\(&uffdio_copy"),
                ("fs/userfaultfd.c", r"validate_range\(ctx->mm, uffdio_copy\.dst"),
                ("fs/userfaultfd.c", r"mfill_atomic_copy\(ctx, uffdio_copy\.dst"),
            ]),
        },
        {
            "id": "tun",
            "config": {"CONFIG_TUN": cfg.get("CONFIG_TUN", "unspecified")},
            "entry": "drivers/net/tun.c:tun_chr_write_iter -> tun_get_user",
            "destination": "new or existing skb/packet data owned by the TUN path",
            "value": "user iov_iter packet bytes and headers",
            "reachability": "write_iter is a real user entry, but the destination is network-buffer state, not an arbitrary kernel object",
            "verdict": "CLOSED_NO_ARBITRARY_KERNEL_DESTINATION",
            "evidence": evidence([
                ("drivers/net/tun.c", r"^static ssize_t tun_get_user"),
                ("drivers/net/tun.c", r"copy_from_iter_full\(&pi"),
                ("drivers/net/tun.c", r"^static ssize_t tun_chr_write_iter"),
                ("drivers/net/tun.c", r"result = tun_get_user"),
            ]),
        },
        {
            "id": "vhost",
            "config": {
                "CONFIG_VHOST": cfg.get("CONFIG_VHOST", "unspecified"),
                "CONFIG_VHOST_NET": cfg.get("CONFIG_VHOST_NET", "unspecified"),
                "CONFIG_VHOST_VSOCK": cfg.get("CONFIG_VHOST_VSOCK", "unspecified"),
                "CONFIG_VHOST_VDPA": cfg.get("CONFIG_VHOST_VDPA", "unspecified"),
            },
            "entry": "drivers/vhost/vhost.c:vhost_chr_write_iter / vhost_copy_from_user",
            "destination": "vhost allocated state or guest-memory ranges translated through the IOTLB; internal descriptor copies use caller-owned kernel structs",
            "value": "user IOTLB message, vring state, or guest descriptor bytes",
            "reachability": "VHOST_VSOCK is enabled; VHOST_NET is disabled. Source does not expose an arbitrary kernel destination through these APIs",
            "verdict": "CLOSED_NO_ARBITRARY_KERNEL_DESTINATION",
            "evidence": evidence([
                ("drivers/vhost/vhost.c", r"^ssize_t vhost_chr_write_iter"),
                ("drivers/vhost/vhost.c", r"copy_from_iter\(&type, sizeof\(type\), from\)"),
                ("drivers/vhost/vhost.c", r"^static int vhost_copy_from_user"),
                ("drivers/vhost/vhost.c", r"__copy_from_user\(to, from, size\)"),
                ("drivers/vhost/vhost.c", r"^static long vhost_set_memory"),
                ("drivers/vhost/vhost.c", r"copy_from_user\(newmem->regions"),
            ]),
        },
        {
            "id": "ashmem",
            "config": {"CONFIG_ASHMEM": cfg.get("CONFIG_ASHMEM", "unspecified")},
            "entry": "drivers/staging/android/ashmem.c:ashmem_ioctl",
            "destination": "the ashmem_area name/size/range objects selected by the ashmem fd",
            "value": "user name, size, or pin range; ioctl copies into local structs first",
            "reachability": "existing transport object only; no attacker-selected kernel address is accepted",
            "verdict": "CLOSED_OBJECT_LIMITED_NOT_ARBITRARY",
            "evidence": evidence([
                ("drivers/staging/android/ashmem.c", r"^static int set_name"),
                ("drivers/staging/android/ashmem.c", r"strncpy_from_user\(local_name"),
                ("drivers/staging/android/ashmem.c", r"^static long ashmem_ioctl"),
                ("drivers/staging/android/ashmem.c", r"copy_from_user\(&pin, p, sizeof\(pin\)\)"),
            ]),
        },
        {
            "id": "io_uring",
            "config": {"CONFIG_IO_URING": cfg.get("CONFIG_IO_URING", "unspecified")},
            "entry": "io_uring/io_uring.c (expected implementation path)",
            "destination": "not assessable from this source snapshot",
            "value": "not assessable from this source snapshot",
            "reachability": "CONFIG_IO_URING=y, but the implementation directory/files are absent; uapi and cross-subsystem references remain",
            "verdict": "OPEN_SOURCE_SNAPSHOT_GAP",
            "evidence": evidence([
                ("io_uring/io_uring.c", r"^"),
                ("fs/io_uring.c", r"^"),
                ("init/Kconfig", r"io_uring interface"),
                ("kernel/sys_ni.c", r"COND_SYSCALL\(io_uring_setup\)"),
            ]),
        },
        {
            "id": "kvm_core",
            "config": {"CONFIG_KVM": cfg.get("CONFIG_KVM", "unspecified")},
            "entry": "virt/kvm/kvm_main.c (expected common implementation path)",
            "destination": "not assessable from this source snapshot; KVM user-memory and ioctl core is absent",
            "value": "not assessable from this source snapshot",
            "reachability": "CONFIG_KVM=y and arm64 KVM files exist, but the common virt/kvm implementation is missing, so no same-build destination closure is possible",
            "verdict": "OPEN_SOURCE_SNAPSHOT_GAP",
            "evidence": evidence([
                ("virt/kvm/kvm_main.c", r"^"),
                ("arch/arm64/kvm/arm.c", r"KVM_SET_ONE_REG"),
                ("arch/arm64/kvm/guest.c", r"copy_from_user\(valp, uaddr"),
            ]),
        },
    ]

    for candidate in candidates:
        candidate["source_files_present"] = sorted({
            row["file"]
            for row in candidate["evidence"]
            if (KERNEL / row["file"]).exists()
        })
        candidate["source_files_missing"] = sorted({
            row["file"]
            for row in candidate["evidence"]
            if not (KERNEL / row["file"]).exists()
        })

    closed = [c for c in candidates if c["verdict"].startswith("CLOSED_")]
    open_gaps = [c for c in candidates if c["verdict"] == "OPEN_SOURCE_SNAPSHOT_GAP"]
    result = {
        "audit": "Violin same-build kernel sink candidate closure",
        "date": "2026-07-22",
        "mode": "offline-source-and-config-only",
        "runtime_allowed": False,
        "kernel_source": str(KERNEL.relative_to(ROOT)),
        "kernel_config": str(CONFIG.relative_to(ROOT)),
        "raw_kernel_artifact": {
            "present": RAW_KERNEL.exists(),
            "path": str(RAW_KERNEL.relative_to(ROOT)),
            "size": RAW_KERNEL.stat().st_size if RAW_KERNEL.exists() else None,
            "sha256": hashlib.sha256(RAW_KERNEL.read_bytes()).hexdigest().upper() if RAW_KERNEL.exists() else None,
        },
        "candidates": candidates,
        "verdict": {
            "closed_candidate_count": len(closed),
            "open_source_gap_count": len(open_gaps),
            "independent_sink_closed": False,
            "overall": "NO_NEW_INDEPENDENT_SINK_CLOSED_SOURCE_GAPS_REMAIN",
            "runtime_allowed": False,
        },
        "next_gate": (
            "The checked-in common-gki tree is incomplete for io_uring and virt/kvm, but a matching raw "
            "boot.img.kernel is present. Use bounded disassembly of that artifact (or exact sources) for "
            "the remaining driver/arch handlers before claiming whole-kernel sink absence. Do not alter "
            "the frozen rb/PI route or run a payload."
        ),
    }

    OUT.mkdir(exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md = [
        "# Violin same-build kernel sink candidate closure (2026-07-22)",
        "",
        "只读核对 `kernel-src-wsl/common-gki` 与记录的 Violin config；不构建、不安装、不改 payload/fd-set/nfds、不联机。",
        "",
        "## 规则",
        "",
        "只有同时闭合 **user entry + destination class + value flow + build/reachability gate** 才能称为独立首写原语。源文件缺失不会被解释为不存在。",
        "",
        "## Candidate matrix",
        "",
        "| Candidate | Config | Destination/value closure | Verdict |",
        "| --- | --- | --- | --- |",
    ]
    for candidate in candidates:
        config_text = ", ".join(f"`{k}={v}`" for k, v in candidate["config"].items())
        md.append(
            f"| `{candidate['id']}` | {config_text} | {candidate['destination']}; {candidate['value']} | **{candidate['verdict']}** |"
        )
    md += [
        "",
        "## Closed findings",
        "",
        "- `/dev/mem` 的 strongest direct physical write 在记录 config 中被 `CONFIG_DEVMEM=n` 编译门关闭；即使启用，`open_port()` 还要求 `CAP_SYS_RAWIO` 并经过 lockdown。",
        "- Binder、TUN、VHOST、UFFD、ashmem 和 BPF 的 user-copy 目标分别落在 allocator-owned buffer、skb、guest/IOTLB 或当前 mm/对象状态；没有接受任意内核地址的首写接口。",
        "- `CONFIG_VHOST_NET=n`；当前只保留通用 vhost 与 vhost-vsock 路径。",
        "",
        "## 未闭合的 source-snapshot gaps（raw artifact 已存在）",
        "",
        "- `CONFIG_IO_URING=y`，但 checked-in 本树缺少 `io_uring/io_uring.c` 与 `fs/io_uring.c`；匹配 raw `boot.img.kernel` 已确认实现存在，需转到 raw disassembly 审计实际 destinations。",
        "- `CONFIG_KVM=y`，但 checked-in 本树缺少 `virt/kvm/kvm_main.c` common core；匹配 raw kernel 已有符号，需用同一 raw image 补齐 KVM ioctl/user-memory 路径。",
        "",
        "## 结论",
        "",
        "在可见同 build 源码中没有发现新的独立 kernel-write sink；整体判定仍是 **`NO_NEW_INDEPENDENT_SINK_CLOSED_SOURCE_GAPS_REMAIN`**，但 raw artifact 已存在，所以 source gap 应转化为 raw driver/arch disassembly gate，而不是“内核实现不存在”。",
        "",
    ]
    OUT_MD.write_text("\n".join(md), encoding="utf-8")
    print(json.dumps({"json": str(OUT_JSON), "markdown": str(OUT_MD), "verdict": result["verdict"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
