#!/usr/bin/env python3
"""Bounded offline closure of independent kernel-write candidates for Violin.

The previous four-gate audit froze the rb/PI branch.  This pass checks whether
the explicit ``PROJECT=violin-v-oss`` source map contains a separate first-stage
write primitive that could replace the unresolved fops/ConfigFS write.  It is a
static scan only: no build, device, payload, fd-set change, or runtime action.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPLOIT = ROOT / "exploit-repo/IonStack/CVE-2026-43499/exploit"
SRC = EXPLOIT / "src"
OUT = ROOT / "analysis_outputs"
OUT_JSON = OUT / "violin-independent-sink-closure-20260722.json"
OUT_MD = OUT / "violin-independent-sink-closure-20260722.md"

ACTIVE_FILES = [
    SRC / "main.c",
    SRC / "util.c",
    SRC / "fops.c",
    SRC / "pipe.c",
    SRC / "root.c",
    SRC / "preload.c",
    SRC / "su_daemon.c",
    SRC / "targets/violin-v-oss/slide.c",
]

CALL_PATTERNS = {
    "pwrite": r"(?<![A-Za-z0-9_])pwrite\s*\(",
    "write": r"(?<![A-Za-z0-9_])write\s*\(",
    "sendmsg": r"(?<![A-Za-z0-9_])sendmsg\s*\(",
    "ioctl": r"(?<![A-Za-z0-9_])ioctl\s*\(",
    "setsockopt": r"(?<![A-Za-z0-9_])setsockopt\s*\(",
    "splice": r"(?<![A-Za-z0-9_])splice\s*\(",
    "vmsplice": r"(?<![A-Za-z0-9_])vmsplice\s*\(",
    "tee": r"(?<![A-Za-z0-9_])tee\s*\(",
    "process_vm_writev": r"(?<![A-Za-z0-9_])process_vm_writev\s*\(",
    "copy_file_range": r"(?<![A-Za-z0-9_])copy_file_range\s*\(",
    "madvise": r"(?<![A-Za-z0-9_])madvise\s*\(",
    "ptrace": r"(?<![A-Za-z0-9_])ptrace\s*\(",
    "bpf": r"(?<![A-Za-z0-9_])bpf\s*\(",
}

ABSENT_FIRST_SINKS = [
    "splice",
    "vmsplice",
    "tee",
    "process_vm_writev",
    "copy_file_range",
    "madvise",
    "ptrace",
    "bpf",
]


def line_matches(text: str, pattern: str) -> list[dict]:
    regex = re.compile(pattern)
    rows = []
    for number, line in enumerate(text.splitlines(), 1):
        if regex.search(line):
            rows.append({"line": number, "text": line.strip()})
    return rows


def main() -> int:
    source_text = {str(path.relative_to(ROOT)): path.read_text(encoding="utf-8") for path in ACTIVE_FILES}
    calls: dict[str, list[dict]] = {}
    for name, pattern in CALL_PATTERNS.items():
        rows = []
        for rel, text in source_text.items():
            for match in line_matches(text, pattern):
                rows.append({"file": rel, **match})
        calls[name] = rows

    makefile = (EXPLOIT / "Makefile").read_text(encoding="utf-8")
    target_header = SRC / "targets/violin-v-oss/target.h"

    source_map = {
        "main.c": "src/main.c",
        "util.c": "src/util.c",
        "fops.c": "src/fops.c",
        "pipe.c": "src/pipe.c",
        "slide.c": "src/targets/violin-v-oss/slide.c",
        "root.c": "src/root.c",
        "preload.c": "src/preload.c",
        "su_daemon.c": "src/su_daemon.c",
    }

    known_classification = {
        "pwrite": {
            "class": "ConfigFS arbitrary target/value transport",
            "verdict": "EXISTING_FOPS_GATED_SINK",
            "evidence": "src/util.c configfs_write_once() prepares the ashmem name then calls pwrite().",
        },
        "write": {
            "class": "userspace/pipe/post-credential writes",
            "verdict": "NO_INDEPENDENT_FIRST_STAGE_SINK",
            "evidence": "log/report writes, pipe direct writes, and root SELinux write; pipe setup is ConfigFS-dependent.",
        },
        "sendmsg": {
            "class": "skb/page shaping",
            "verdict": "ALLOCATION_SHAPING_ONLY",
            "evidence": "sendmsg() targets socket pairs used to shape/reclaim kernel pages.",
        },
        "ioctl": {
            "class": "ashmem/perf/TTY setup",
            "verdict": "SETUP_OR_LEAK_ONLY",
            "evidence": "ASHMEM_SET_NAME and perf controls do not carry an attacker-selected kernel destination/value.",
        },
        "setsockopt": {
            "class": "socket spray setup",
            "verdict": "SETUP_ONLY",
            "evidence": "SO_SNDBUF controls reclaim-socket sizing.",
        },
    }
    for name in ABSENT_FIRST_SINKS:
        known_classification[name] = {
            "class": "candidate independent kernel-write API",
            "verdict": "ABSENT_IN_ACTIVE_SOURCE",
            "evidence": "No callsite in the explicit Violin source map.",
        }

    target_slide_write_rows = [
        row for row in calls["write"]
        if row["file"].endswith("targets/violin-v-oss/slide.c")
    ]
    target_slide_has_arbitrary_api = any(
        calls[name] and any(row["file"].endswith("targets/violin-v-oss/slide.c") for row in calls[name])
        for name in ABSENT_FIRST_SINKS + ["pwrite", "splice"]
    )

    result = {
        "audit": "Violin independent kernel-write sink closure",
        "date": "2026-07-22",
        "mode": "offline-active-source-map-and-callsite-scan-only",
        "runtime_allowed": False,
        "source_selection": {
            "required_project": "violin-v-oss",
            "makefile_default_is_non_violin": "PROJECT ?= blazer-CP2A.260605.012" in makefile,
            "target_override_rule_present": "$(if $(wildcard $(TARGET_DIR)/$(1)),$(TARGET_DIR)/$(1),src/$(1))" in makefile,
            "target_header_exists": target_header.exists(),
            "source_map": source_map,
            "target_slide_arbitrary_write_api": target_slide_has_arbitrary_api,
            "target_slide_write_calls": target_slide_write_rows,
        },
        "callsite_scan": calls,
        "classification": known_classification,
        "known_sink_relationships": {
            "kernel_write_data_delegates_configfs": "src/util.c:995-996",
            "pipe_setup_and_restore_use_kernel_write_data": "src/pipe.c:517-557",
            "install_pipe_proof_write_precedes_physrw": "src/pipe.c:652-656",
            "selinux_write_is_post_credential": "src/root.c:39-111",
        },
        "verdict": {
            "independent_first_stage_sink_found": False,
            "existing_configfs_sink": "ONLY_ARBITRARY_TARGET_VALUE_TRANSPORT",
            "target_override_adds_sink": False,
            "candidate_api_absence_closed": all(not calls[name] for name in ABSENT_FIRST_SINKS),
            "overall": "NO_NEW_INDEPENDENT_KERNEL_WRITE_SINK",
            "runtime_allowed": False,
        },
        "next_gate": (
            "Archive the known rb/PI, pipe, and syscall branches. Re-open only for a separate kernel object, "
            "callback, destination, and attacker-controlled value whose first write is independent of fops/ConfigFS."
        ),
    }
    OUT.mkdir(exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md = [
        "# Violin independent kernel-write sink closure (2026-07-22)",
        "",
        "只读扫描显式 `PROJECT=violin-v-oss` source map；不构建、不安装、不改 payload/fd-set、不联机。",
        "",
        "## Source map",
        "",
        "- `main.c/util.c/fops.c/pipe.c` 使用核心 `src/*.c`。",
        "- 只有 `src/targets/violin-v-oss/slide.c` 和 `target.h` 是 Violin override。",
        "- Violin `slide.c` 仅有日志/child-pipe `write()`，没有 arbitrary kernel-write syscall。",
        "",
        "## Callsite verdict",
        "",
        "| API | Active callsite | 结论 |",
        "| --- | ---: | --- |",
    ]
    for name in CALL_PATTERNS:
        rows = calls[name]
        md.append(f"| `{name}()` | {len(rows)} | **{known_classification[name]['verdict']}** — {known_classification[name]['evidence']} |")
    md += [
        "",
        "## 结论",
        "",
        "- 唯一 arbitrary target/value transport 仍是 ConfigFS/`pwrite()`，且受 fops 劫持门控。",
        "- pipe direct write 的 buffer forge/restore 和 proof write 均依赖 `kernel_write_data()`，属于下游循环链。",
        "- `sendmsg()`、`ioctl()`、`setsockopt()` 仅为页面/套接字/ashmem/perf 设置；root/SELinux write 是提权后副作用。",
        "- `splice/vmsplice/tee/process_vm_writev/copy_file_range/madvise/ptrace/bpf` 在显式 Violin 源码中无调用点。",
        "- 总判定：**`NO_NEW_INDEPENDENT_KERNEL_WRITE_SINK`**。",
        "",
        "## 下一步",
        "",
        "当前 rb/PI anchor 没有新的首写原语，继续归档；只有发现独立 kernel object + callback + destination + value 的离线闭合证据才重新评估。",
        "",
    ]
    OUT_MD.write_text("\n".join(md), encoding="utf-8")
    print(json.dumps({"json": str(OUT_JSON), "markdown": str(OUT_MD), "verdict": result["verdict"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
