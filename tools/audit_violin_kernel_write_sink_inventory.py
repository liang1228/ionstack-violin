#!/usr/bin/env python3
"""Bounded offline inventory of core Violin write-like interfaces."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "exploit-repo/IonStack/CVE-2026-43499/exploit/src"
OUT = ROOT / "analysis_outputs"


def contains(text: str, needle: str) -> bool:
    return needle in text


def main() -> None:
    files = {
        name: (SRC / name).read_text(encoding="utf-8")
        for name in ("util.c", "pipe.c", "main.c", "root.c", "slide.c", "fops.c", "preload.c", "su_daemon.c")
    }

    candidates = [
        {
            "function": "configfs_write_once",
            "file": "src/util.c:926-943",
            "class": "arbitrary_kernel_write_transport",
            "verdict": "EXISTING_SINK_FOPS_GATED",
            "evidence": {
                "configures_target": contains(files["util.c"], "put64(blob, CFG_BIN_BUFFER_OFF - ASHMEM_NAME_PREFIX_LEN, target)"),
                "uses_pwrite": contains(files["util.c"], "ssize_t wr = pwrite(fd, data, len, 0);"),
            },
            "reason": "The only already-closed target/value transport; it requires the ashmem fops/ConfigFS route to be active.",
        },
        {
            "function": "pipe_phys_write / pipe_phys_write_data",
            "file": "src/pipe.c:517-597",
            "class": "pipe_buffer_direct_write",
            "verdict": "DOWNSTREAM_CIRCULAR",
            "evidence": {
                "direct_write": contains(files["pipe.c"], "ssize_t wrote = write(pipefd[1], data, len);"),
                "setup_uses_kernel_write": contains(files["pipe.c"], "kernel_write_data(fd, buf_addr, &pb, sizeof(pb))"),
                "restore_uses_kernel_write": contains(files["pipe.c"], "kernel_write_data(fd, buf_addr, &saved, sizeof(saved))"),
                "unfound_path_uses_forge": contains(files["pipe.c"], "forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 1);"),
            },
            "reason": "Direct write exists, but both found/unfound buffer setup paths depend on kernel_write_data, which delegates to ConfigFS.",
        },
        {
            "function": "pselect_write_once_child / set_pselect_write",
            "file": "src/util.c:124-128; target pipe variants",
            "class": "rbtree_write_shape",
            "verdict": "SAME_RB_ANCHOR",
            "evidence": {
                "sets_target_value": contains(files["util.c"], "pselect_custom_target = target;") and contains(files["util.c"], "pselect_custom_value = value;"),
                "route_requires_fake_page": contains(files["util.c"], "PAGE_PAYLOAD_FOPS"),
            },
            "reason": "This is the existing fd-set/rbtree shaping branch, not a distinct kernel write sink.",
        },
        {
            "function": "try_put_blob_no_zeros / try_put_blob_zero_at",
            "file": "src/util.c:413-433",
            "class": "ashmem_name_setup",
            "verdict": "SETUP_ONLY",
            "evidence": {
                "ashmem_set_name": contains(files["util.c"], "ioctl(fd, ASHMEM_SET_NAME, name)"),
            },
            "reason": "Only changes the ashmem name buffer used to configure ConfigFS; no arbitrary destination is consumed here.",
        },
        {
            "function": "run_perf_leak",
            "file": "src/main.c:870-978",
            "class": "kernel_address_leak",
            "verdict": "LEAK_ONLY",
            "evidence": {
                "perf_event_open": contains(files["main.c"], "SYS_perf_event_open"),
                "maps_perf_buffer": contains(files["main.c"], "mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)"),
                "reads_samples": contains(files["main.c"], "struct perf_leak_sample"),
            },
            "reason": "Produces KASLR evidence; no attacker-selected kernel destination write is present.",
        },
        {
            "function": "prepare_kernel_page / prepare_pipe_buffer_page_child",
            "file": "src/util.c:723-881; src/pipe.c:118-276",
            "class": "skb_pipe_page_shaping",
            "verdict": "ALLOCATION_SHAPING_ONLY",
            "evidence": {
                "sendmsg": contains(files["util.c"], "sendmsg(pcp_shaping_sv[0], &msg, 0)") and contains(files["pipe.c"], "sendmsg(pcp_sv[0], &msg, 0)"),
                "reclaim_close_sequence": contains(files["util.c"], "close(memfd_leak)") and contains(files["pipe.c"], "close(leak_memfd)"),
            },
            "reason": "Shapes/reclaims kernel objects and pages; no direct arbitrary write callback is exposed.",
        },
        {
            "function": "spawn_root_child",
            "file": "src/root.c:39-111",
            "class": "post_credential_side_effect",
            "verdict": "POST_CRED_ONLY",
            "evidence": {
                "writes_selinux_enforce": contains(files["root.c"], "open(\"/sys/fs/selinux/enforce\", O_WRONLY | O_CLOEXEC)"),
                "gated_by_setuid": contains(files["root.c"], "if (report.setgid_ret == 0 && report.setuid_ret == 0)"),
            },
            "reason": "The write is a user-visible post-privilege side effect, not a pre-privilege kernel-memory primitive.",
        },
        {
            "function": "slide_crash_write_one / crash_debug_write_one / fops_route_log",
            "file": "src/slide.c; src/main.c; src/fops.c",
            "class": "userspace_logging",
            "verdict": "USERSPACE_ONLY",
            "evidence": {
                "slide_opens_path": contains(files["slide.c"], "open(path, O_WRONLY | O_CREAT | O_APPEND, 0644)"),
                "debug_writes_fd": contains(files["main.c"], "ssize_t n = write(fd, msg + off, len - off);"),
                "route_log_writes_fd": contains(files["fops.c"], "ssize_t wr = write(fd, buf + off, len - off);"),
            },
            "reason": "These writes target files/log descriptors and do not write kernel memory.",
        },
    ]

    for candidate in candidates:
        candidate["evidence_ok"] = all(candidate["evidence"].values())

    result = {
        "scope": "core src/ write-like interfaces only; target variants intentionally excluded",
        "runtime_allowed": False,
        "candidate_count": len(candidates),
        "candidates": candidates,
        "verdict": "NO_NEW_INDEPENDENT_KERNEL_WRITE_SINK",
        "decision": (
            "Within the bounded core inventory, ConfigFS/pwrite remains the only arbitrary "
            "target/value transport. Pipe direct writes are downstream of that transport; "
            "pselect is the same rbtree anchor; ashmem-name/ioctl/sendmsg/perf paths are setup, "
            "leak, or allocation mechanisms; root/SELinux and log writes are post-credential or "
            "userspace side effects. No new independent pre-privilege kernel write sink was found."
        ),
        "next_gate": "Archive the known rb/PI, pipe, and core syscall branches; only pursue a new sink if a separate kernel object, callback, destination, and write value can be closed offline.",
    }
    OUT.mkdir(exist_ok=True)
    (OUT / "violin-kernel-write-sink-inventory-20260722.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    md = [
        "# Violin bounded kernel-write sink inventory (2026-07-22)",
        "",
        "## Scope",
        "",
        "Core `src/*.c` only; target variants and already duplicated target files were excluded. This is a static inventory, not a runtime test.",
        "",
        "## Verdict",
        "",
        "- **NO_NEW_INDEPENDENT_KERNEL_WRITE_SINK**",
        "- ConfigFS/`pwrite` remains the only arbitrary target/value transport and is fops-gated.",
        "- Pipe direct writes are downstream/circular; pselect is the same rbtree anchor.",
        "- `ASHMEM_SET_NAME`, perf, `sendmsg`, and page-shaping paths are setup/leak/allocation only.",
        "- SELinux, su, wallpaper, and log writes are post-credential or userspace side effects.",
        "- Offline only; no payload, build, device, or runtime action.",
        "",
        "## Candidate matrix",
        "",
        "| Function | Class | Verdict |",
        "|---|---|---|",
    ]
    for candidate in candidates:
        md.append(f"| `{candidate['function']}` | `{candidate['class']}` | `{candidate['verdict']}` |")
    md += [
        "",
        "## Decision",
        "",
        result["decision"],
        "",
        "## Next gate",
        "",
        result["next_gate"],
        "",
        "## Graph/source anchors",
        "",
        "- Codebase-memory `search_code` found 18 core functions matching write-like syscall patterns.",
        "- `src/util.c:926-943` — ConfigFS target setup followed by `pwrite`.",
        "- `src/pipe.c:517-597` — pipe direct write with kernel-write setup/restore.",
        "- `src/main.c:870-978` — perf sampling/KASLR leak, no arbitrary destination write.",
        "- `src/root.c:39-111` — SELinux write gated after `setgid/setuid`.",
    ]
    (OUT / "violin-kernel-write-sink-inventory-20260722.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
